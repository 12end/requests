package requests

import (
	"bytes"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
	"io"
	"io/ioutil"
	"net/url"
	"strings"
	"unicode/utf8"
)

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

var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

func escapeQuotes(s string) string {
	return quoteEscaper.Replace(s)
}
