/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"encoding/json"
	"fmt"
	//"github.com/miekg/dns"
	//"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/services"
	"net"
	"net/http"
	"time"
)

const dohURL = "https://cloudflare-dns.com/dns-query"

type dnsAnswer struct {
	Data string `json:"data"`
	Type int    `json:"type"`
}
type dnsResponse struct {
	Answer []dnsAnswer `json:"Answer"`
}

func resolveHostname(name string, port uint16) (resolvedEndpoint *Endpoint, err error) {
	// 优先判断 name 是否为 IP 地址，若为 IP 则直接返回
	ip := net.ParseIP(name)
	if ip != nil {
		return &Endpoint{Host: ip.String(), Port: port}, nil
	}

	maxTries := 10
	if services.StartedAtBoot() {
		maxTries *= 3
	}
	for i := 0; i < maxTries; i++ {
		if i > 0 {
			time.Sleep(time.Second * 4)
		}
		resolvedEndpoint, err = resolveHostnameOnce(name, port)
		if err == nil {
			return
		}
	}
	return
}

func resolveHostnameOnce(name string, port uint16) (resolvedEndpoint *Endpoint, err error) {
	ip, err := dohResolve(name, "A")
	if err == nil && ip != "" {
		return &Endpoint{Host: ip, Port: port}, nil
	}
	ip6, err := dohResolve(name, "AAAA")
	if err == nil && ip6 != "" {
		return &Endpoint{Host: ip6, Port: port}, nil
	}
	return nil, fmt.Errorf("no A or AAAA records found for %s", name)
}

func dohResolve(name string, qtype string) (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", dohURL, nil)
	if err != nil {
		return "", err
	}
	q := req.URL.Query()
	q.Add("name", name)
	q.Add("type", qtype)
	req.URL.RawQuery = q.Encode()
	req.Header.Set("accept", "application/dns-json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var dr dnsResponse
	if err := json.NewDecoder(resp.Body).Decode(&dr); err != nil {
		return "", err
	}
	for _, ans := range dr.Answer {
		// A=1, AAAA=28
		if (qtype == "A" && ans.Type == 1) || (qtype == "AAAA" && ans.Type == 28) {
			return ans.Data, nil
		}
	}
	return "", fmt.Errorf("no %s record found", qtype)
}

func (config *Config) ResolveEndpoints() error {
	for i := range config.Peers {
		if config.Peers[i].Endpoint.IsEmpty() {
			continue
		}
		var err error
		resolvedEndpoint, err := resolveHostname(config.Peers[i].Endpoint.Host, config.Peers[i].Endpoint.Port)
		if err != nil || resolvedEndpoint == nil {
			return fmt.Errorf("failed to resolve endpoint: %w", err)
		}
		config.Peers[i].Endpoint = *resolvedEndpoint
	}
	return nil
}
