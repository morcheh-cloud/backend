package api

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/morche/backend/internal/dbmon"
)

// ArvanCloud's edge addresses, for a reverse proxy behind its CDN to trust
// (real_ip). Read from arvancloud.ir/en/ips.txt, kept 6 hours; the list
// below stands in when it can't be read.
var arvanRangesFallback = []string{
	"185.143.232.0/22", "188.229.116.16/30", "94.101.182.0/27", "2.144.3.128/28",
	"37.32.16.0/27", "37.32.17.0/27", "37.32.18.0/27", "37.32.19.0/27",
	"185.215.232.0/22", "178.131.120.48/28", "94.101.183.0/28", "78.157.36.112/28",
	"95.38.61.80/28", "193.24.119.0/29",
}

var arvanRanges struct {
	sync.Mutex
	list []string
	at   time.Time
}

func fetchArvanRanges(ctx context.Context) ([]string, error) {
	tr := &http.Transport{Proxy: nil, DialContext: dbmon.DirectDialer(false)}
	cl := &http.Client{Timeout: 10 * time.Second, Transport: tr}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.arvancloud.ir/en/ips.txt", nil)
	if err != nil {
		return nil, err
	}
	res, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, huma.Error502BadGateway("ArvanCloud answered " + res.Status)
	}
	var out []string
	sc := bufio.NewScanner(io.LimitReader(res.Body, 1<<20))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if p, err := netip.ParsePrefix(line); err == nil {
			out = append(out, p.Masked().String())
		} else if a, err := netip.ParseAddr(line); err == nil {
			out = append(out, a.String())
		}
	}
	if len(out) == 0 {
		return nil, huma.Error502BadGateway("ArvanCloud's list was empty")
	}
	return out, nil
}

type CDNRangesOutput struct {
	Body struct {
		Ranges []string `json:"ranges"`
		Header string   `json:"header" doc:"The header the CDN puts the visitor's address in"`
		Live   bool     `json:"live" doc:"false = ArvanCloud's list couldn't be read; this is Morche's built-in copy"`
	}
}

func registerCDNRanges(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "get-arvan-ranges", Method: http.MethodGet, Path: "/cdn-ranges/arvan",
		Summary:     "ArvanCloud CDN's edge addresses",
		Description: "For a reverse proxy behind ArvanCloud: trust these and read the visitor from AR-Real-IP.",
		Tags:        []string{"Proxies"},
	}, func(ctx context.Context, _ *struct{}) (*CDNRangesOutput, error) {
		out := &CDNRangesOutput{}
		out.Body.Header = "AR-Real-IP"
		arvanRanges.Lock()
		defer arvanRanges.Unlock()
		if arvanRanges.list == nil || time.Since(arvanRanges.at) > 6*time.Hour {
			if list, err := fetchArvanRanges(ctx); err == nil {
				arvanRanges.list, arvanRanges.at = list, time.Now()
			}
		}
		if arvanRanges.list != nil {
			out.Body.Ranges, out.Body.Live = arvanRanges.list, true
		} else {
			out.Body.Ranges = arvanRangesFallback
		}
		return out, nil
	})
}
