package requests

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"golang.org/x/net/html"
	"io/ioutil"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

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

func (resp *Response) getRespText() (respText string) {
	httpResp := resp.HttpResp
	respText += fmt.Sprintf("%s %s\r\n", httpResp.Proto, httpResp.Status)
	headers := []string{}
	for k, v := range httpResp.Header {
		headers = append(headers, fmt.Sprintf("%s: %s", k, strings.Join(v, ",")))
	}
	sort.Strings(headers)
	respText += fmt.Sprintf("%s\r\n\r\n%s", strings.Join(headers, "\r\n"), resp.Text())
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
