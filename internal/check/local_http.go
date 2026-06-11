package check

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type localHTTPResult struct {
	OK     bool
	Status string
	Error  string
}

func testLocalHTTP(raw string, timeout time.Duration) localHTTPResult {
	if _, err := url.ParseRequestURI(raw); err != nil {
		return localHTTPResult{Error: "invalid URL: " + err.Error()}
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(raw)
	if err != nil {
		return localHTTPResult{Error: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 500 {
		return localHTTPResult{OK: true, Status: fmt.Sprintf("%d", resp.StatusCode)}
	}
	return localHTTPResult{Status: fmt.Sprintf("%d", resp.StatusCode), Error: resp.Status}
}
