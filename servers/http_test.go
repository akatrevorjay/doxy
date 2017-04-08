/* http_test.go
 *
 * Copyright (C) 2016 Alexandre ACEBEDO
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

package servers

import (
	"github.com/akatrevorjay/dnsdock/utils"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestServiceRequests(t *testing.T) {
	const TestAddr = "127.0.0.1:9980"

	config := utils.NewConfig()
	config.HttpAddr = TestAddr

	server := NewHTTPServer(config, NewDNSServer(config))
	go server.Start()

	// Allow some time for server to start
	time.Sleep(250 * time.Millisecond)

	var tests = []struct {
		method, url, body, expected string
		status                      int
	}{
		{"GET", "/services", "", "{}", 200},
		{"GET", "/services/foo", "", "", 404},
		{"PUT", "/services/foo", `{"name": "foo"}`, "", 500},
		{"PUT", "/services/foo", `{"name": "foo", "image": "bar", "ips": ["127.0.0.1"], "aliases": ["foo.docker"]}`, "", 200},
		{"GET", "/services/foo", "", `{"Name":"foo","Image":"bar","IPs":["127.0.0.1"],"TTL":-1,"Aliases":["foo.docker"]}`, 200},
		{"PUT", "/services/boo", `{"name": "baz", "image": "bar", "ips": ["127.0.0.2"]}`, "", 200},
		{"GET", "/services", "", `{"boo":{"Name":"baz","Image":"bar","IPs":["127.0.0.2"],"TTL":-1,"Aliases":null},"foo":{"Name":"foo","Image":"bar","IPs":["127.0.0.1"],"TTL":-1,"Aliases":["foo.docker"]}}`, 200},
		{"PATCH", "/services/boo", `{"name": "bar", "ttl": 20, "image": "bar"}`, "", 200},
		{"GET", "/services/boo", "", `{"Name":"bar","Image":"bar","IPs":["127.0.0.2"],"TTL":20,"Aliases":null}`, 200},
		{"DELETE", "/services/foo", ``, "", 200},
		{"GET", "/services", "", `{"boo":{"Name":"bar","Image":"bar","IPs":["127.0.0.2"],"TTL":20,"Aliases":null}}`, 200},
	}

	for _, input := range tests {
		t.Log(input.method, input.url)
		req, err := http.NewRequest(input.method, "http://"+TestAddr+input.url, strings.NewReader(input.body))
		if err != nil {
			t.Error(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Error(err)
		}
		defer resp.Body.Close()

		if input.status != resp.StatusCode {
			t.Error(input, "Expected status:", input.status, "Got:", resp.StatusCode)
		}

		if input.status != 200 {
			continue
		}

		actual, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Error(err)
		}
		actualStr := strings.Trim(string(actual), " \n")
		if actualStr != input.expected {
			t.Error(input, "Expected:", input.expected, "Got:", actualStr)
		}
	}

	t.Log("Test TTL setter")
	if config.Ttl != 0 {
		t.Error("Default TTL is not 0")
	}
	req, err := http.NewRequest("PUT", "http://"+TestAddr+"/set/ttl", strings.NewReader("12"))
	if err != nil {
		t.Error(err)
	}
	_, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Error(err)
	}
	if config.Ttl != 12 {
		t.Error("TTL not updated. Expected: 12 Got:", config.Ttl)
	}
}
