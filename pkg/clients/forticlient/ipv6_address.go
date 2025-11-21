package forticlient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/NorskHelsenett/dcn-fortios-go-client/pkg/types/fortiostypes"
	"github.com/NorskHelsenett/ror/pkg/rlog"
)

// IPv6AddressExists checks if an IPv6 address object exists in FortiGate.
func (c *FortiClient) IPv6AddressExists(name string) (bool, error) {
	rlog.Info(fmt.Sprintf("Checking if IPv6 address '%s' exists on '%s/?vdom=%s'", name, c.baseURL, c.vdom))
	url := fmt.Sprintf("%s/cmdb/firewall/address6/%s?vdom=%s", c.baseURL, url.PathEscape(name), c.vdom)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// If the address does not exist, FortiGate returns 404
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}

	// For other status codes, we expect 200 OK
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("fortigate returned status %d: %v", resp.StatusCode, string(body))
	}

	return true, nil
}

// CreateIPv6Address creates a new IPv6 address object in FortiGate.
func (c *FortiClient) CreateIPv6Address(address fortiostypes.FortigateIPv6Address) error {
	rlog.Info(fmt.Sprintf("Creating IPv6 address '%s' on '%s/?vdom=%s'", address.Name, c.baseURL, c.vdom))
	url := fmt.Sprintf("%s/cmdb/firewall/address6/?vdom=%s", c.baseURL, c.vdom)

	jsonBody, err := json.Marshal(address)
	if err != nil {
		return fmt.Errorf("failed to marshal address: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create ipv6 address: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("fortigate returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// DeleteIPv6Address deletes an IPv6 address object from FortiGate.
func (c *FortiClient) DeleteIPv6Address(name string) error {
	rlog.Info(fmt.Sprintf("Deleting IPv6 address '%s' on '%s/?vdom=%s'", name, c.baseURL, c.vdom))
	url := fmt.Sprintf("%s/cmdb/firewall/address6/%s?vdom=%s", c.baseURL, url.PathEscape(name), c.vdom)

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete ipv6 address: %w", err)
	}
	defer resp.Body.Close()

	// If the address does not exist, consider it deleted
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("fortigate returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
