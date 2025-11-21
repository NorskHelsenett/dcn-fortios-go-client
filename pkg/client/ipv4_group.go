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

func (c *FortiClient) IPv4AddressGroupExists(name string) (bool, error) {
	rlog.Info(fmt.Sprintf("Checking if IPv4 address group '%s' exists on '%s/?vdom=%s'", name, c.baseURL, c.vdom))
	url := fmt.Sprintf("%s/cmdb/firewall/addrgrp/%s?vdom=%s", c.baseURL, url.PathEscape(name), c.vdom)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to check if ipv4 address group exists: %w", err)
	}
	defer resp.Body.Close()

	// If the address does not exist, FortiGate returns 404
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}

	// For other status codes, we expect 200 OK
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("fortigate returned status %d: %s", resp.StatusCode, string(body))
	}

	return true, nil
}

func (c *FortiClient) CreateIPv4AddressGroup(addressGroup fortiostypes.FortigateAddressGroup) error {
	rlog.Info(fmt.Sprintf("Creating IPv4 address group '%s' on '%s/?vdom=%s'", addressGroup.Name, c.baseURL, c.vdom))
	url := fmt.Sprintf("%s/cmdb/firewall/addrgrp/?vdom=%s", c.baseURL, c.vdom)

	jsonBody, err := json.Marshal(addressGroup)
	if err != nil {
		return fmt.Errorf("failed to marshal address group: %w", err)
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
		return fmt.Errorf("failed to create ipv4 address group: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("fortigate returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (c *FortiClient) UpdateIPv4AddressGroup(addressGroup fortiostypes.FortigateAddressGroup) error {
	rlog.Info(fmt.Sprintf("Updating IPv4 address group '%s' on '%s/?vdom=%s'", addressGroup.Name, c.baseURL, c.vdom))
	url := fmt.Sprintf("%s/cmdb/firewall/addrgrp/%s?vdom=%s", c.baseURL, url.PathEscape(addressGroup.Name), c.vdom)

	jsonBody, err := json.Marshal(addressGroup)
	if err != nil {
		return fmt.Errorf("failed to marshal address group: %w", err)
	}

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to update ipv4 address group: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("fortigate returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (c *FortiClient) DeleteIPv4AddressGroup(name string) error {
	rlog.Info(fmt.Sprintf("Deleting IPv4 address group '%s' on '%s/?vdom=%s'", name, c.baseURL, c.vdom))
	url := fmt.Sprintf("%s/cmdb/firewall/addrgrp/%s?vdom=%s", c.baseURL, url.PathEscape(name), c.vdom)

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete ipv4 address group: %w", err)
	}
	defer resp.Body.Close()

	// If the address group does not exist, consider it deleted
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("fortigate returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
