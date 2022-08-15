package requests

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"go.uber.org/zap"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Request struct {
	httpreq             *http.Request
	header              *http.Header
	Client              *http.Client
	Cookies             []*http.Cookie
	body                []byte
	Trace               *[]TraceInfo
	logger              *zap.Logger
	waitResponseStart   time.Time
	waitResponeDuration time.Duration
}

type TraceInfo struct {
	Request  string
	Response string
	Duration time.Duration
}

type Header map[string]string
type Host string
type Params map[string]string
type Datas map[string]string // for post form
type Files map[string]File   // name ,file-content
type File struct {
	FileName    string
	ContentType string
	Content     []byte
}
type NoRedirect bool
type Timeout time.Duration

// {username,password}
type Auth []string

var titleReg = regexp.MustCompile("(?ims)<title.*?>(.*?)</title>")

func Requests() *Request {

	req := new(Request)

	req.httpreq = &http.Request{
		Method:     "GET",
		Header:     make(http.Header),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	req.header = &req.httpreq.Header
	req.httpreq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36")
	req.httpreq.Header.Set("Accept", "*/*")
	req.httpreq.Header.Set("Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2")
	req.Client = &http.Client{
		Transport: &http.Transport{
			MaxConnsPerHost: 0,
			MaxIdleConns:    0,
			//MaxIdleConnsPerHost: ThreadsNum * 2,
			MaxIdleConnsPerHost: 6,
			IdleConnTimeout:     10 * time.Second,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionSSL30},
			TLSHandshakeTimeout: 5 * time.Second,
			DisableKeepAlives:   true,
		},
		Timeout: 5 * time.Second,
	}

	// auto with Cookies
	// cookiejar.New source code return jar, nil
	req.Client.Jar, _ = cookiejar.New(nil)

	return req
}

//开启trace，非线程安全
func (req *Request) WithTrace(traceInfo *[]TraceInfo) *Request {
	req.httpreq = req.httpreq.WithContext(
		httptrace.WithClientTrace(
			req.httpreq.Context(),
			&httptrace.ClientTrace{
				WroteRequest: func(_ httptrace.WroteRequestInfo) {
					req.waitResponseStart = time.Now()
				},
				GotFirstResponseByte: func() {
					req.waitResponeDuration = time.Since(req.waitResponseStart)
				},
			}))
	req.Trace = traceInfo
	return req
}

//开启debug log
func (req *Request) WithLogger(logger *zap.Logger) *Request {
	req.logger = logger
	return req
}

func (req *Request) EmptyHost() {
	req.httpreq.Host = ""
}

func (req *Request) GetReqText() (reqText string) {
	httpreq := req.httpreq
	path := httpreq.URL.RequestURI()
	if len(path) == 0 {
		path = "/"
	}
	reqText += fmt.Sprintf("%s %s %s\r\n", httpreq.Method, path, httpreq.Proto)
	headers := []string{}
	for k, v := range httpreq.Header {
		headers = append(headers, fmt.Sprintf("%s: %s", k, strings.Join(v, ",")))
	}
	if httpreq.ContentLength > 0 {
		headers = append(headers, fmt.Sprintf("Content-Length: %d", httpreq.ContentLength))
	}
	sort.Strings(headers)
	reqText += fmt.Sprintf("%s\r\n\r\n%s\r\n", strings.Join(headers, "\r\n"), req.body)
	return
}

// Get ,Req.Get
func Get(origurl string, args ...interface{}) (resp *Response, err error) {
	req := Requests()
	req.httpreq.Method = "GET"
	// call request Get
	resp, err = req.do(origurl, args...)
	return resp, err
}

func (req *Request) Get(origurl string, args ...interface{}) (resp *Response, err error) {
	req.httpreq.Method = "GET"
	// call request Get
	resp, err = req.do(origurl, args...)
	return resp, err
}

func Head(origurl string, args ...interface{}) (resp *Response, err error) {
	req := Requests()
	req.httpreq.Method = "HEAD"
	// call request Get
	resp, err = req.do(origurl, args...)
	return resp, err
}

func (req *Request) Head(origurl string, args ...interface{}) (resp *Response, err error) {
	req.httpreq.Method = "HEAD"
	// call request Get
	resp, err = req.do(origurl, args...)
	return resp, err
}

func Delete(origurl string, args ...interface{}) (resp *Response, err error) {
	req := Requests()
	req.httpreq.Method = "DELETE"

	// call request Delete
	resp, err = req.do(origurl, args...)
	return resp, err
}

func (req *Request) Move(origurl string, args ...interface{}) (resp *Response, err error) {
	req.httpreq.Method = "MOVE"
	// call request Get
	resp, err = req.do(origurl, args...)
	return resp, err
}

func Move(origurl string, args ...interface{}) (resp *Response, err error) {
	req := Requests()
	req.httpreq.Method = "MOVE"

	// call request Delete
	resp, err = req.do(origurl, args...)
	return resp, err
}

func (req *Request) do(origurl string, args ...interface{}) (resp *Response, err error) {
	// set params ?a=b&b=c
	//set header
	params := []map[string]string{}
	datas := []map[string]string{} // POST
	files := []map[string]File{}   //post file

	//reset Cookies,
	//Client.Do can copy cookie from client.Jar to Req.header
	delete(req.httpreq.Header, "Cookie")

	req.Client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		l := len(via)
		// 二次及二次以上跳转到另外host则停止跳转
		if (strings.Split(via[l-1].URL.Host, ":")[0] != strings.Split(req.URL.Host, ":")[0] && l > 1) || l > 5 {
			return http.ErrUseLastResponse
		} else {
			return nil
		}
	}

	for _, arg := range args {
		switch a := arg.(type) {
		// arg is header , set to request header
		case Header:
			for k, v := range a {
				(*req.header)[k] = []string{v}
			}
		case Host:
			req.httpreq.Host = string(a)
		case Params:
			params = append(params, a)
		case Auth:
			// a{username,password}
			req.httpreq.SetBasicAuth(a[0], a[1])
		case NoRedirect:
			if a == true {
				req.Client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				}
			}
		case []byte:
			req.httpreq.ContentLength = int64(len(arg.([]byte)))
			if req.httpreq.ContentLength > 0 {
				req.setBodyRawBytes(ioutil.NopCloser(bytes.NewReader(arg.([]byte))))
			}
		case string:
			req.httpreq.ContentLength = int64(len(arg.(string)))
			if req.httpreq.ContentLength > 0 {
				req.setBodyRawBytes(ioutil.NopCloser(strings.NewReader(arg.(string))))
			}
		case Datas: //Post form data,packaged in body.
			datas = append(datas, a)
		case Files:
			files = append(files, a)
		case Timeout:
			req.Client.Timeout = time.Duration(a)
		}
	}

	disturl, _ := buildURLParams(origurl, params...)

	//prepare to Do
	URL, err := url.Parse(disturl)
	if err != nil {
		return nil, err
	}
	req.httpreq.URL = URL
	if len(files) > 0 {
		req.buildFilesAndForms(files, datas)
	} else if req.httpreq.Body == nil {
		Forms := req.buildForms(datas...)
		req.setBodyBytes(Forms) // set forms to body
	}

	if req.httpreq.Body != nil {
		req.body, err = ioutil.ReadAll(req.httpreq.Body)
		req.httpreq.Body = ioutil.NopCloser(bytes.NewBuffer(req.body))
	}
	req.ClientSetCookies()

	var rawRequest string
	if req.Trace != nil {
		rawRequest = req.GetReqText()
		req.logger.Debug("Send Request:\n" + rawRequest)
	}
	res, err := req.Client.Do(req.httpreq)

	if err != nil {
		// Debug
		//fmt.Println(err)
		return nil, err
	}

	resp = &Response{}
	resp.HttpResp = res
	resp.Req = req
	resp.Delay = req.waitResponeDuration

	resp.Content()
	if req.Trace != nil {
		rawResponse := resp.GetRespText()
		req.logger.Debug("Receive response:\n" + rawResponse)
		*req.Trace = append(*req.Trace, TraceInfo{
			Request:  rawRequest,
			Response: rawResponse,
			Duration: resp.Delay,
		})
	}
	defer res.Body.Close()
	return resp, nil
}

// cookies
// cookies only save to Client.Jar
// Req.Cookies is temporary
func (req *Request) SetCookie(cookie *http.Cookie) {
	req.Cookies = append(req.Cookies, cookie)
}

func (req *Request) ClearCookies() {
	req.Client.Jar, _ = cookiejar.New(nil)
}

func (req *Request) ClientSetCookies() {

	if len(req.Cookies) > 0 {
		// 1. Cookies have content, Copy Cookies to Client.jar
		// 2. Clear  Cookies
		req.Client.Jar.SetCookies(req.httpreq.URL, req.Cookies)
		req.Cookies = req.Cookies[0:0]
	}

}

// set timeout s = second
func (req *Request) SetTimeout(n time.Duration) {
	req.Client.Timeout = n
}

func (req *Request) Close() {
	req.httpreq.Close = true
}

func (req *Request) Proxy(proxyurl string) {

	urli := url.URL{}
	urlproxy, err := urli.Parse(proxyurl)
	if err != nil {
		fmt.Println("Set proxy failed")
		return
	}
	req.Client.Transport.(*http.Transport).Proxy = http.ProxyURL(urlproxy)
}

// POST requests
func (req *Request) PostJson(origurl string, args ...interface{}) (resp *Response, err error) {

	req.httpreq.Method = "POST"

	req.header.Set("Content-Type", "application/json")

	return req.do(origurl, args...)
}

func PostJson(origurl string, args ...interface{}) (resp *Response, err error) {
	req := Requests()

	// call request Get
	resp, err = req.PostJson(origurl, args...)
	return resp, err
}

func (req *Request) Post(origurl string, args ...interface{}) (resp *Response, err error) {

	req.httpreq.Method = "POST"

	//set default
	req.header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req.do(origurl, args...)
}

func Post(origurl string, args ...interface{}) (resp *Response, err error) {
	req := Requests()

	// call request Get
	resp, err = req.Post(origurl, args...)
	return resp, err
}

// PUT requests

func (req *Request) Put(origurl string, args ...interface{}) (resp *Response, err error) {

	req.httpreq.Method = "PUT"

	req.header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req.do(origurl, args...)
}

func Put(origurl string, args ...interface{}) (resp *Response, err error) {
	req := Requests()

	// call request Get
	resp, err = req.Put(origurl, args...)
	return resp, err
}

// only set forms
func (req *Request) setBodyBytes(Forms url.Values) {

	// maybe
	data := Forms.Encode()
	if len(data) > 0 {
		req.httpreq.Body = ioutil.NopCloser(strings.NewReader(data))
	}
	req.httpreq.ContentLength = int64(len(data))
}

// only set forms
func (req *Request) setBodyRawBytes(read io.ReadCloser) {
	req.httpreq.Body = read
}

// upload file and form
// build to body format
func (req *Request) buildFilesAndForms(files []map[string]File, datas []map[string]string) {

	//handle file multipart

	var b bytes.Buffer
	w := multipart.NewWriter(&b)

	for _, file := range files {
		for fieldName, f := range file {
			if f.ContentType == "" {
				f.ContentType = "application/octet-stream"
			}
			h := make(textproto.MIMEHeader)
			h.Set("Content-Disposition",
				fmt.Sprintf(`form-data; name="%s"; filename="%s"`,
					escapeQuotes(fieldName), escapeQuotes(f.FileName)))
			h.Set("Content-Type", f.ContentType)
			part, err := w.CreatePart(h)
			//part, err := w.CreateFormFile(fieldName, f.FileName)
			if err != nil {
				fmt.Printf("Upload %s failed!", fieldName)
				panic(err)
			}
			reader := bytes.NewReader(f.Content)
			_, err = io.Copy(part, reader)
			if err != nil {
				panic(err)
			}
		}
	}

	for _, data := range datas {
		for k, v := range data {
			w.WriteField(k, v)
		}
	}

	w.Close()
	// set file header example:
	// "Content-Type": "multipart/form-data; boundary=------------------------7d87eceb5520850c",
	req.httpreq.Body = ioutil.NopCloser(bytes.NewReader(b.Bytes()))
	req.httpreq.ContentLength = int64(b.Len())
	req.header.Set("Content-Type", w.FormDataContentType())
}

// build post Form data
func (req *Request) buildForms(datas ...map[string]string) (Forms url.Values) {
	Forms = url.Values{}
	for _, data := range datas {
		for key, value := range data {
			Forms.Add(key, value)
		}
	}
	return Forms
}
