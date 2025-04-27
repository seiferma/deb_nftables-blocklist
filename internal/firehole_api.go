package internal

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type FireholeApi struct {
	UrlPrefix string
}

func (a FireholeApi) getListUrl() string {
	return fmt.Sprintf("%s/all-ipsets.json", a.UrlPrefix)
}

func (a FireholeApi) getDetailsUrl(listName string) string {
	return fmt.Sprintf("%s/%v.json", a.UrlPrefix, listName)
}

type Blocklist struct {
	Category   string    `json:"category"`
	Maintainer string    `json:"maintainer"`
	Started    Timestamp `json:"started"`
	Updated    Timestamp `json:"updated"`
	Checked    Timestamp `json:"checked"`
	Clock_scew int       `json:"clock_scew"`
	Ips        int       `json:"ips"`
	Errors     int       `json:"errors"`
}

type BlocklistShort struct {
	Blocklist
	Name string `json:"ipset"`
}

type BlocklistDetails struct {
	Blocklist
	Name      string `json:"name"`
	IpSetFile string `json:"file_local"`
}

type Timestamp time.Time

func (t *Timestamp) UnmarshalJSON(b []byte) error {
	var unixTime int64
	err := json.Unmarshal(b, &unixTime)
	if err != nil {
		return err
	}
	*t = Timestamp(time.UnixMilli(unixTime))
	return nil
}

func (a FireholeApi) GetBlocklists() ([]BlocklistShort, error) {
	var ipsets []BlocklistShort
	// Make an HTTP GET request to the URL

	resp, err := http.Get(a.getListUrl())
	if err != nil {
		return ipsets, fmt.Errorf("failed to fetch URL: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ipsets, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse the JSON data into a slice of Item structs
	err = json.Unmarshal(body, &ipsets)
	if err != nil {
		return ipsets, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return ipsets, nil
}

func (a FireholeApi) GetBlocklistDetailsByShort(blocklistShort BlocklistShort) (BlocklistDetails, error) {
	return a.GetBlocklistDetailsByName(blocklistShort.Name)
}

func (a FireholeApi) GetBlocklistDetailsByName(blocklistName string) (BlocklistDetails, error) {
	var blocklistDetails BlocklistDetails
	resp, err := http.Get(a.getDetailsUrl(blocklistName))
	if err != nil {
		return blocklistDetails, fmt.Errorf("failed to fetch URL: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return blocklistDetails, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse the JSON data into a slice of Item structs
	err = json.Unmarshal(body, &blocklistDetails)
	if err != nil {
		return blocklistDetails, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return blocklistDetails, nil
}

func (a FireholeApi) GetBlocklistIpsByDetails(blocklistDetails BlocklistDetails) ([]*net.IPNet, error) {
	ipsetUrl := blocklistDetails.IpSetFile
	return a.GetBlocklistIpsByUrl(ipsetUrl)
}

func (a FireholeApi) GetBlocklistIpsByUrl(ipsetUrl string) ([]*net.IPNet, error) {
	resp, err := http.Get(ipsetUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch URL \"%v\": %v", ipsetUrl, err)
	}
	defer resp.Body.Close()

	var ips []*net.IPNet
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed_line := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed_line, "#") {
			parsed_net, err1 := ParseIpNet(trimmed_line)
			if err1 == nil {
				ips = append(ips, parsed_net)
			}

		}
	}
	return ips, nil
}
