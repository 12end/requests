package requests

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"golang.org/x/net/html"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

type Request struct {
	httpreq             *http.Request
	header              *http.Header
	Client              *http.Client
	Cookies             []*http.Cookie
	body                []byte
	Trace               *[]TraceInfo
	waitResponseStart   time.Time
	waitResponeDuration time.Duration
}

type Response struct {
	HttpResp *http.Response
	content  []byte
	hasRead  bool
	text     string
	Req      *Request
	header   string
	title    string
	Delay    time.Duration
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

func (req *Request) EmptyHost() {
	req.httpreq.Host = ""
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
		*req.Trace = append(*req.Trace, TraceInfo{
			Request:  req.GetReqText(),
			Response: resp.GetRespText(),
			Duration: resp.Delay,
		})
	}
	defer res.Body.Close()
	return resp, nil
}

// handle URL params
func buildURLParams(userURL string, params ...map[string]string) (string, error) {
	if len(params) == 0 {
		return userURL, nil
	}
	parsedURL, err := url.Parse(userURL)

	if err != nil {
		return "", err
	}

	parsedQuery, err := url.ParseQuery(parsedURL.RawQuery)

	if err != nil {
		return "", nil
	}

	for _, param := range params {
		for key, value := range param {
			parsedQuery.Add(key, value)
		}
	}
	return addQueryParams(parsedURL, parsedQuery), nil
}

func addQueryParams(parsedURL *url.URL, parsedQuery url.Values) string {
	if len(parsedQuery) > 0 {
		return strings.Join([]string{strings.Replace(parsedURL.String(), "?"+parsedURL.RawQuery, "", -1), parsedQuery.Encode()}, "?")
	}
	return strings.Replace(parsedURL.String(), "?"+parsedURL.RawQuery, "", -1)
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

func (resp *Response) Content() []byte {

	if resp.hasRead {
		return resp.content
	}

	var Body = resp.HttpResp.Body
	if resp.HttpResp.Header.Get("Content-Encoding") == "gzip" && resp.Req.header.Get("Accept-Encoding") != "" {
		// fmt.Println("gzip")
		reader, err := gzip.NewReader(Body)
		if err != nil {
			return nil
		}
		Body = reader
	}
	eof := make(chan bool)
	go func() {
		resp.content, _ = ioutil.ReadAll(Body)
		eof <- true
	}()
	select {
	case <-time.After(resp.Req.Client.Timeout):
	case <-eof:
	}
	resp.hasRead = true
	resp.text = string(decodeBody(resp.content))
	return resp.content
}

func (resp *Response) GetRespText() (respText string) {
	httpResp := resp.HttpResp
	respText += fmt.Sprintf("%s %s\r\n", httpResp.Proto, httpResp.Status)
	headers := []string{}
	for k, v := range httpResp.Header {
		headers = append(headers, fmt.Sprintf("%s: %s", k, strings.Join(v, ",")))
	}
	sort.Strings(headers)
	respText += fmt.Sprintf("%s\r\n\r\n%s\r\n", strings.Join(headers, "\r\n"), resp.Text())
	return
}

func (resp *Response) Text() string {
	if !resp.hasRead {
		resp.Content()
	}
	return resp.text
}

func (resp *Response) HeaderString() string {
	if resp.header == "" {
		for k, header := range resp.HttpResp.Header {
			resp.header = resp.header + fmt.Sprintf("%s: %s\n", k, strings.Join(header, ","))
		}
	}
	return resp.header
}

func (resp *Response) Title() string {
	if resp.title == "" {
		find := titleReg.FindSubmatch([]byte(resp.Text()))
		if len(find) > 1 {
			resp.title = string(find[1])
			resp.title = html.UnescapeString(resp.title)
			resp.title = strings.ReplaceAll(resp.title, "\t", "")
			resp.title = strings.ReplaceAll(resp.title, "\n", "")
			resp.title = strings.ReplaceAll(resp.title, "\r", "")
			resp.title = strings.TrimSpace(resp.title)
		}
	}
	return resp.title
}

func decodeBody(s []byte) []byte {
	I := bytes.NewReader(s)
	var O io.Reader
	if utf8.Valid(s) {
		O = transform.NewReader(I, unicode.UTF8.NewDecoder())
	} else {
		O = transform.NewReader(I, simplifiedchinese.GB18030.NewDecoder())
	}
	d, e := ioutil.ReadAll(O)
	if e != nil {
		return s
	} else {
		return d
	}
}

func (resp *Response) BodyContains(arg interface{}) (result bool) {
	switch a := arg.(type) {
	case string:
		result = strings.Contains(strings.ToLower(resp.Text()), strings.ToLower(a))
	case []byte:
		result = bytes.Contains(bytes.ToLower(resp.Content()), bytes.ToLower(a))
	}
	return
}

func (resp *Response) HeaderContains(arg string) (result bool) {
	result = strings.Contains(strings.ToLower(resp.HeaderString()), strings.ToLower(arg))
	return
}

func (resp *Response) Search(reg *regexp.Regexp) map[string]string {
	match := reg.FindStringSubmatch(resp.Text())
	groupNames := reg.SubexpNames()
	result := make(map[string]string)
	if len(match) < len(groupNames) {
		return result
	}
	for i, name := range groupNames {
		if i != 0 && name != "" {
			result[name] = match[i]
		}
	}
	return result
}

func (resp *Response) Json(v interface{}) error {
	if resp.content == nil {
		resp.Content()
	}
	return json.Unmarshal(resp.content, v)
}

func (resp *Response) Cookies() (cookies []*http.Cookie) {
	//httpreq := resp.Req.httpreq
	//client := resp.Req.Client
	//
	//cookies = client.Jar.Cookies(httpreq.URL)

	return resp.HttpResp.Cookies()

}

/**************post*************************/
// call Req.Post ,only for easy
func Post(origurl string, args ...interface{}) (resp *Response, err error) {
	req := Requests()

	// call request Get
	resp, err = req.Post(origurl, args...)
	return resp, err
}

func Put(origurl string, args ...interface{}) (resp *Response, err error) {
	req := Requests()

	// call request Get
	resp, err = req.PUT(origurl, args...)
	return resp, err
}

func PostJson(origurl string, args ...interface{}) (resp *Response, err error) {
	req := Requests()

	// call request Get
	resp, err = req.PostJson(origurl, args...)
	return resp, err
}

// POST requests

func (req *Request) PostJson(origurl string, args ...interface{}) (resp *Response, err error) {

	req.httpreq.Method = "POST"

	req.header.Set("Content-Type", "application/json")

	return req.do(origurl, args...)
}

func (req *Request) Post(origurl string, args ...interface{}) (resp *Response, err error) {

	req.httpreq.Method = "POST"

	//set default
	req.header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req.do(origurl, args...)
}

// PUT requests

func (req *Request) PUT(origurl string, args ...interface{}) (resp *Response, err error) {

	req.httpreq.Method = "PUT"

	req.header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req.do(origurl, args...)
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

var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

func escapeQuotes(s string) string {
	return quoteEscaper.Replace(s)
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

// open file for post upload files

func openFile(filename string) *os.File {
	r, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	return r
}
