package internal

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func assertNil(t *testing.T, actual error) {
	if actual != nil {
		t.Errorf("An error was expected to be nil but got following instead: %v", actual)
	}
}

func assertEquals(t *testing.T, expected, actual interface{}) {
	if expected != actual {
		t.Errorf("Expected \"%v\" but got \"%v\".", expected, actual)
	}
}

func TestGetLists(t *testing.T) {

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertEquals(t, "/all-ipsets.json", r.URL.Path)
		assertEquals(t, http.MethodGet, r.Method)
		w.Write([]byte(`
			[
				{
					"ipset": "anonymous",
					"category": "geolocation",
					"maintainer": "MaxMind.com",
					"started": 1525193298000,
					"updated": 1536699944000,
					"checked": 1536715212000,
					"clock_skew": 0,
					"ips": 5907,
					"errors": 0
				},
				{
					"ipset": "bds_atif",
					"category": "reputation",
					"maintainer": "Binary Defense Systems",
					"started": 1438159314000,
					"updated": 1745686414000,
					"checked": 1745687806000,
					"clock_skew": 0,
					"ips": 4679,
					"errors": 0
				}
			]
		`))
	}))
	api := FireholeApi{
		UrlPrefix: server.URL,
	}

	blocklists, err := api.GetBlocklists()

	assertNil(t, err)
	assertEquals(t, 2, len(blocklists))
}

func TestGetDetails(t *testing.T) {

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertEquals(t, "/tor_exits_1d.json", r.URL.Path)
		assertEquals(t, http.MethodGet, r.Method)
		w.Write([]byte(`
			{
				"name": "tor_exits_1d",
				"entries": 929,
				"entries_min": 852,
				"entries_max": 950,
				"ips": 1280,
				"ips_min": 1170,
				"ips_max": 1312,
				"ipv": "ipv4",
				"hash": "ip",
				"frequency": 5,
				"aggregation": 1440,
				"started": 1440288191000,
				"updated": 1745693001000,
				"processed": 1745696645000,
				"checked": 1528004168000,
				"clock_skew": 0,
				"category": "anonymizers",
				"maintainer": "TorProject.org",
				"maintainer_url": "https://www.torproject.org/",
				"info": "<a href=\"https://www.torproject.org\">TorProject.org</a>  list of all current TOR exit points (TorDNSEL)  ",
				"source": "https://check.torproject.org/exit-addresses",
				"file": "tor_exits_1d.ipset",
				"history": "tor_exits_1d_history.csv",
				"geolite2": "tor_exits_1d_geolite2_country.json",
				"ipdeny": "tor_exits_1d_ipdeny_country.json",
				"ip2location": "tor_exits_1d_ip2location_country.json",
				"ipip": "tor_exits_1d_ipip_country.json",
				"comparison": "tor_exits_1d_comparison.json",
				"file_local": "https://iplists.firehol.org/files/tor_exits_1d.ipset",
				"commit_history": "https://github.com/firehol/blocklist-ipsets/commits/master/tor_exits_1d.ipset",
				"license": "unknown",
				"grade": "unknown",
				"protection": "unknown",
				"intended_use": "unknown",
				"false_positives": "unknown",
				"poisoning": "unknown",
				"services": [ "unknown" ],
				"errors": 0,
				"version": 24272,
				"average_update": 128,
				"min_update": 53,
				"max_update": 1020,
				"downloader": ""
			}
		`))
	}))
	api := FireholeApi{
		UrlPrefix: server.URL,
	}
	blocklistShort := BlocklistShort{Name: "tor_exits_1d"}

	blocklistDetails, err := api.GetBlocklistDetailsByShort(blocklistShort)

	assertNil(t, err)
	assertEquals(t, "tor_exits_1d", blocklistDetails.Name)
	assertEquals(t, "anonymizers", blocklistDetails.Category)

	assertEquals(t, "TorProject.org", blocklistDetails.Maintainer)
	assertEquals(t, time.UnixMilli(1440288191000), time.Time(blocklistDetails.Started))
	assertEquals(t, time.UnixMilli(1745693001000), time.Time(blocklistDetails.Updated))
	assertEquals(t, time.UnixMilli(1528004168000), time.Time(blocklistDetails.Checked))
	assertEquals(t, 0, blocklistDetails.Clock_scew)
	assertEquals(t, 1280, blocklistDetails.Ips)
	assertEquals(t, 0, blocklistDetails.Errors)
	assertEquals(t, "https://iplists.firehol.org/files/tor_exits_1d.ipset", blocklistDetails.IpSetFile)
}

func TestGetIps(t *testing.T) {

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertEquals(t, "/tor_exits_1d.ipset", r.URL.Path)
		assertEquals(t, http.MethodGet, r.Method)
		w.Write([]byte(`
			#
			# tor_exits_1d
			#
			# ipv4 hash:ip ipset
			#
			# [TorProject.org] (https://www.torproject.org) list of all 
			# current TOR exit points (TorDNSEL)
			#
			#
			198.51.100.1
			198.51.100.3
			198.51.100.4/30
			203.0.113.0/24
			233.252.0.0
		`))
	}))
	api := FireholeApi{
		UrlPrefix: server.URL,
	}

	ips, err := api.GetBlocklistIpsByUrl(fmt.Sprintf("%v/tor_exits_1d.ipset", server.URL))

	assertNil(t, err)
	assertEquals(t, len(ips), 5)
}
