// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/resolve/conn"
	"github.com/owasp-amass/resolve/pool"
	"github.com/owasp-amass/resolve/selectors"
	"github.com/owasp-amass/resolve/servers"
	"github.com/owasp-amass/resolve/types"
	"github.com/owasp-amass/resolve/utils"
	"github.com/owasp-amass/resolve/wildcards"
	"golang.org/x/net/publicsuffix"
)

// Environment variables that let an operator replace the built-in trusted
// resolver configuration at engine start-up. All are optional; when unset (or
// invalid) the engine uses the built-in defaults, so existing deployments are
// unchanged. See docs for the rationale (AWS VPC resolver, etc.).
const (
	// EnvResolvers is a comma-separated list of resolver IP addresses, or a
	// path to a file with one IP address per line (blank lines and lines
	// starting with '#' are ignored). When it yields at least one valid
	// address, it replaces the built-in baseline list.
	EnvResolvers = "AMASS_ENGINE_RESOLVERS"
	// EnvResolverQPS is an aggregate queries-per-second cap applied across the
	// whole trusted pool (the resolve library's pool-level limiter). 0 or unset
	// means no pool-level cap. Use it to stay under a per-interface ceiling such
	// as the AWS VPC resolver's link-local packet limit.
	EnvResolverQPS = "AMASS_ENGINE_RESOLVER_QPS"
	// EnvWildcardResolver is a single resolver IP used for wildcard detection.
	// Unset means the built-in default. Point it at an in-scope resolver when
	// egress is locked down.
	EnvWildcardResolver = "AMASS_ENGINE_WILDCARD_RESOLVER"

	// defaultWildcardResolver is used for wildcard detection when
	// EnvWildcardResolver is not set.
	defaultWildcardResolver = "8.8.4.4"
)

// resolverStartupSummary is a one-line description of the trusted-resolver
// configuration chosen by trustedResolvers() at start-up. It is set once during
// package initialization and read by the engine for logging via
// ResolverStartupInfo.
var resolverStartupSummary string

// ResolverStartupInfo returns a one-line summary of the trusted-resolver
// configuration selected at start-up (which list, how many resolvers, any pool
// QPS cap, and the wildcard-detection resolver), including a warning when an
// override was requested but could not be used. It is intended to be logged
// once by the engine so operators can confirm an override took effect.
func ResolverStartupInfo() string {
	return resolverStartupSummary
}

// resolverListFromEnv parses EnvResolvers into a deduplicated list of resolver
// IP addresses. The second return value reports whether the variable was set to
// a non-empty value, so the caller can distinguish "no override requested" from
// "override requested but nothing valid was found" and warn on the latter.
func resolverListFromEnv() ([]string, bool) {
	val := strings.TrimSpace(os.Getenv(EnvResolvers))
	if val == "" {
		return nil, false
	}

	var raw []string
	// A readable, non-directory path is treated as a resolver file; anything
	// else is treated as a comma-separated list.
	if info, err := os.Stat(val); err == nil && !info.IsDir() {
		if data, err := os.ReadFile(val); err == nil {
			raw = strings.Split(string(data), "\n")
		}
	} else {
		raw = strings.Split(val, ",")
	}

	seen := make(map[string]struct{})
	var out []string
	for _, r := range raw {
		r = strings.TrimSpace(r)
		if r == "" || strings.HasPrefix(r, "#") {
			continue
		}
		if net.ParseIP(r) == nil {
			continue // skip anything that is not a bare IP address
		}
		if _, dup := seen[r]; dup {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	return out, true
}

// resolverPoolQPS returns the aggregate pool QPS cap from EnvResolverQPS. 0
// means no cap (the default, and also the result of an invalid value).
func resolverPoolQPS() int {
	val := strings.TrimSpace(os.Getenv(EnvResolverQPS))
	if val == "" {
		return 0
	}
	if n, err := strconv.Atoi(val); err == nil && n > 0 {
		return n
	}
	return 0
}

// wildcardResolver returns the resolver IP used for wildcard detection: the
// EnvWildcardResolver override when it is a valid IP, otherwise the default.
func wildcardResolver() string {
	val := strings.TrimSpace(os.Getenv(EnvWildcardResolver))
	if val != "" && net.ParseIP(val) != nil {
		return val
	}
	return defaultWildcardResolver
}

var (
	ErrNameDoesNotExist     = errors.New("name does not exist")
	ErrNoRecordOfThisType   = errors.New("no record of this type")
	ErrFailedMaxDNSAttempts = errors.New("failed the maximum number of DNS attempts")
)

type baseline struct {
	address string
	qps     int
}

// baselineResolvers is a list of trusted public DNS resolvers.
var baselineResolvers = []baseline{
	{"8.8.8.8", 5}, // Google Primary
	//	{"8.8.4.4", 5},         // Google Secondary
	{"95.85.95.85", 2},     // Gcore DNS Primary
	{"2.56.220.2", 2},      // Gcore DNS Secondary
	{"76.76.2.0", 2},       // ControlD Primary
	{"76.76.10.0", 2},      // ControlD Secondary
	{"9.9.9.9", 2},         // Quad9 Primary
	{"149.112.112.112", 2}, // Quad9 Secondary
	{"208.67.222.222", 2},  // Cisco OpenDNS Home Primary
	{"208.67.220.220", 2},  // Cisco OpenDNS Home Secondary
	{"1.1.1.1", 3},         // Cloudflare Primary
	{"1.0.0.1", 3},         // Cloudflare Secondary
	{"185.228.168.9", 1},   // CleanBrowsing Primary
	{"185.228.169.9", 1},   // CleanBrowsing Secondary
	{"76.76.19.19", 1},     // Alternate DNS Primary
	{"76.223.122.150", 1},  // Alternate DNS Secondary
	{"94.140.14.14", 1},    // AdGuard DNS Primary
	{"94.140.15.15", 1},    // AdGuard DNS Secondary
	{"176.103.130.130", 1}, // AdGuard
	{"176.103.130.131", 1}, // AdGuard
	{"8.26.56.26", 1},      // Comodo Secure DNS Primary
	{"8.20.247.20", 1},     // Comodo Secure DNS Secondary
	{"205.171.3.65", 1},    // CenturyLink Level3 Primary
	{"205.171.2.65", 1},    // CenturyLink Level3 Secondary
	{"64.6.64.6", 1},       // Verisign DNS Primary
	{"64.6.65.6", 1},       // Verisign DNS Secondary
	{"209.244.0.3", 1},     // CenturyLink Level3
	{"209.244.0.4", 1},     // CenturyLink Level3
	{"149.112.121.10", 1},  // CIRA Canadian Shield Primary
	{"149.112.122.10", 1},  // CIRA Canadian Shield Secondary
	{"138.197.140.189", 1}, // OpenNIC Primary
	{"162.243.19.47", 1},   // OpenNIC Secondary
	{"216.87.84.211", 1},   // OpenNIC
	{"23.90.4.6", 1},       // OpenNIC
	{"216.146.35.35", 1},   // Oracle Dyn Primary
	{"216.146.36.36", 1},   // Oracle Dyn Secondary
	{"91.239.100.100", 1},  // UncensoredDNS Primary
	{"89.233.43.71", 1},    // UncensoredDNS Secondary
	{"77.88.8.8", 1},       // Yandex.DNS Primary
	{"77.88.8.1", 1},       // Yandex.DNS Secondary
	{"74.82.42.42", 1},     // Hurricane Electric Primary
	{"94.130.180.225", 1},  // DNS for Family Primary
	{"78.47.64.161", 1},    // DNS for Family Secondary
	{"80.80.80.80", 1},     // Freenom World Primary
	{"80.80.81.81", 1},     // Freenom World Secondary
	{"84.200.69.80", 1},    // DNS.WATCH Primary
	{"84.200.70.40", 1},    // DNS.WATCH Secondary
	{"156.154.70.5", 1},    // Neustar Primary
	{"156.157.71.5", 1},    // Neustar Secondary
	{"81.218.119.11", 1},   // GreenTeamDNS Primary
	{"209.88.198.133", 1},  // GreenTeamDNS Secondary
	{"37.235.1.177", 1},    // FreeDNS
	{"38.132.106.139", 1},  // CyberGhost
}

var trusted *pool.Pool
var detector *wildcards.Detector

func PerformQuery(ctx context.Context, name string, qtype uint16) ([]dns.RR, error) {
	for i := 1; i <= 6; i++ {
		msg := utils.QueryMsg(name, qtype)
		if qtype == dns.TypePTR {
			msg = utils.ReverseMsg(name)
		}

		if resp, err := dnsQuery(ctx, msg, trusted); err == nil && resp != nil {
			if wildcardDetected(ctx, resp, detector) {
				return nil, errors.New("wildcard detected")
			}
			if len(resp.Answer) > 0 {
				if rr := utils.AnswersByType(resp, qtype); len(rr) > 0 {
					return rr, nil
				}
			}
		} else if err == ErrNameDoesNotExist || err == ErrNoRecordOfThisType {
			return nil, err
		}
	}
	return nil, ErrFailedMaxDNSAttempts
}

func wildcardDetected(ctx context.Context, resp *dns.Msg, r *wildcards.Detector) bool {
	name := strings.ToLower(utils.RemoveLastDot(resp.Question[0].Name))

	if dom, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil && dom != "" {
		return r.WildcardDetected(ctx, resp, dom)
	}
	return false
}

func dnsQuery(ctx context.Context, msg *dns.Msg, r *pool.Pool) (*dns.Msg, error) {
	if resp, err := r.Exchange(ctx, msg); err != nil {
		return nil, err
	} else if resp.Rcode == dns.RcodeNameError {
		return nil, ErrNameDoesNotExist
	} else if resp.Rcode == dns.RcodeSuccess {
		if len(resp.Answer) == 0 {
			return nil, ErrNoRecordOfThisType
		}
		return resp, nil
	}
	return nil, errors.New("unexpected response")
}

func trustedResolvers() *pool.Pool {
	timeout := 250 * time.Millisecond
	cpus := runtime.NumCPU()

	// wildcard detector (resolver configurable via EnvWildcardResolver)
	wc := wildcardResolver()
	serv := servers.NewNameserver(wc)
	wconns := conn.New(cpus, selectors.NewSingle(timeout, serv))
	detector = wildcards.NewDetector(serv, wconns, nil)

	// Trusted resolver addresses: an operator-supplied override via
	// EnvResolvers, otherwise the built-in baseline list.
	addrs, requested := resolverListFromEnv()
	override := len(addrs) > 0
	var warn string
	if !override {
		if requested {
			warn = fmt.Sprintf("; warning: %s was set but held no valid resolver addresses, using the built-in list", EnvResolvers)
		}
		for _, r := range baselineResolvers {
			addrs = append(addrs, r.address)
		}
	}

	var servs []types.Nameserver
	for _, a := range addrs {
		servs = append(servs, servers.NewNameserver(a))
	}
	sel := selectors.NewRoundRobin(timeout, servs...)
	//sel := selectors.NewAuthoritative(timeout, servers.NewNameserver)
	conns := conn.New(cpus, sel)

	qps := resolverPoolQPS()

	source := "built-in baseline list"
	if override {
		source = EnvResolvers + " override"
	}
	cap := "no pool QPS cap"
	if qps > 0 {
		cap = fmt.Sprintf("pool QPS cap %d", qps)
	}
	resolverStartupSummary = fmt.Sprintf(
		"trusted DNS resolvers: %d from %s; %s; wildcard detector %s%s",
		len(addrs), source, cap, wc, warn)

	return pool.New(qps, sel, conns, nil)
}
