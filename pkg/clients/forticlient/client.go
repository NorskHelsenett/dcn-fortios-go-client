package forticlient

import (
	"crypto/tls"
	"net/http"
	"time"
)

// FortiClient is a client for interacting with FortiGate firewalls via the REST API.
type FortiClient struct {
	httpClient *http.Client
	baseURL    string
	vdom       string
	token      string
}

// NewFortiClient creates a new FortiGate client with the specified base URL, VDOM, and API token.
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
