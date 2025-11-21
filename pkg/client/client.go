package forticlient

import (
	"crypto/tls"
	"net/http"
	"time"
)

type FortiClient struct {
	httpClient *http.Client
	baseURL    string
	vdom       string
	token      string
}

func NewFortiClient(baseURL, vdom, token string) *FortiClient {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	httpClient := &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
	}

	return &FortiClient{
		httpClient: httpClient,
		baseURL:    baseURL,
		vdom:       vdom,
		token:      token,
	}
}
