// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enum

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	client "github.com/owasp-amass/amass/v5/engine/api/client/v1"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

func TestScopeJSON(t *testing.T) {
	token := uuid.New()
	fetch := func(_ context.Context, atype oam.AssetType) ([]oam.Asset, error) {
		switch atype {
		case oam.FQDN:
			return []oam.Asset{&oamdns.FQDN{Name: "crayon.no"}, &oamdns.FQDN{Name: "crayon.co"}}, nil
		case oam.Netblock:
			return []oam.Asset{
				&oamnet.Netblock{CIDR: netip.MustParsePrefix("90.166.17.0/24"), Type: "IPv4"},
				&oamnet.Netblock{CIDR: netip.MustParsePrefix("2001:db8::/32"), Type: "IPv6"},
				&oamnet.Netblock{CIDR: netip.MustParsePrefix("9.0.0.0/24"), Type: "IPv4"},
			}, nil
		case oam.AutonomousSystem:
			// what the engine answers for a type with nothing in scope
			return nil, errors.New("x/scope: status=404 Not Found error=session scope not found for the selected asset type")
		case oam.IPAddress:
			return nil, errors.New("context deadline exceeded")
		}
		t.Fatalf("unexpected scope type %s", atype)
		return nil, nil
	}

	var buf bytes.Buffer
	if err := writeScopeJSON(&buf, buildScopeReport(token, fetch)); err != nil {
		t.Fatal(err)
	}
	line := buf.String()
	if !strings.HasPrefix(line, ScopeJSONMarker) || !strings.HasSuffix(line, "\n") || strings.Count(line, "\n") != 1 {
		t.Fatalf("want one marked line, got %q", line)
	}

	var got ScopeReport
	if err := json.Unmarshal([]byte(strings.TrimPrefix(strings.TrimSpace(line), ScopeJSONMarker)), &got); err != nil {
		t.Fatal(err)
	}
	want := ScopeReport{
		Session:           token.String(),
		FQDNs:             []string{"crayon.co", "crayon.no"},
		Netblocks:         []string{"9.0.0.0/24", "90.166.17.0/24", "2001:db8::/32"},
		AutonomousSystems: []int{},
		IPAddresses:       []string{},
		Errors:            map[string]string{"ipaddress": "context deadline exceeded"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
	// empty lists are [] rather than null, so a reader never sees a missing type
	if !strings.Contains(line, `"autonomoussystem":[]`) {
		t.Fatalf("want an empty ASN list, got %s", line)
	}
}

func TestAddrLess(t *testing.T) {
	in := []string{"10.0.0.10", "10.0.0.9", "::1", "bogus", "9.255.255.255"}
	want := []string{"9.255.255.255", "10.0.0.9", "10.0.0.10", "::1", "bogus"}
	for i := 0; i < len(in); i++ {
		for j := i + 1; j < len(in); j++ {
			if addrLess(in[j], in[i]) {
				in[i], in[j] = in[j], in[i]
			}
		}
	}
	if !reflect.DeepEqual(in, want) {
		t.Fatalf("got %v, want %v", in, want)
	}
}

// printScopeJSON against an HTTP server shaped like the engine's scope
// endpoint: OAM JSON in {"data": [...]}, and 404 with the engine's error body
// for a type with nothing in scope.
func TestPrintScopeJSONOverHTTP(t *testing.T) {
	token := uuid.New()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch strings.TrimPrefix(r.URL.Path, "/api/v1") {
		case "/sessions/" + token.String() + "/scope/fqdn":
			_, _ = w.Write([]byte(`{"data":[{"name":"crayon.com"},{"name":"crayon.co"}]}`))
		case "/sessions/" + token.String() + "/scope/netblock":
			_, _ = w.Write([]byte(`{"data":[{"cidr":"185.20.117.0/24","type":"IPv4"}]}`))
		case "/sessions/" + token.String() + "/scope/autonomoussystem":
			_, _ = w.Write([]byte(`{"data":[{"number":64512},{"number":13335}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"session scope not found for the selected asset type","code":404,"details":"not found"}`))
		}
	}))
	defer srv.Close()

	c, err := client.NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var buf bytes.Buffer
	if err := printScopeJSON(&buf, c, token); err != nil {
		t.Fatal(err)
	}
	var got ScopeReport
	if err := json.Unmarshal([]byte(strings.TrimPrefix(strings.TrimSpace(buf.String()), ScopeJSONMarker)), &got); err != nil {
		t.Fatalf("%v: %q", err, buf.String())
	}
	want := ScopeReport{
		Session:           token.String(),
		FQDNs:             []string{"crayon.co", "crayon.com"},
		Netblocks:         []string{"185.20.117.0/24"},
		AutonomousSystems: []int{13335, 64512},
		IPAddresses:       []string{},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
}
