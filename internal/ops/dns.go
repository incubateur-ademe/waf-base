package ops

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/incubateur-ademe/waf-base/internal/inventory"
	"github.com/incubateur-ademe/waf-base/internal/render"
)

// Plages publiées par Cloudflare (www.cloudflare.com/ips-v4 et ips-v6,
// relevées le 2026-11-20). Une liste périmée donne un écart sur une app edge,
// jamais un faux OK.
var cloudflareRanges = prefixes(
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
)

func prefixes(l ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(l))
	for _, s := range l {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// ControleDNS : chaque host de l'app résout vers les IP des VM de son stage.
// Une app en edge: cloudflare peut aussi résoudre vers les plages de
// Cloudflare. Toute autre adresse, IPv6 comprise, envoie des visiteurs hors
// du WAF.
func ControleDNS(ctx context.Context, res Resolver, a inventory.App, vmIPs []string) (ecarts, notes []string) {
	vms := map[netip.Addr]bool{}
	for _, s := range vmIPs {
		if ip, err := netip.ParseAddr(s); err == nil {
			vms[ip] = true
		}
	}
	edge := a.Edge == render.EdgeCloudflare
	for _, h := range a.Hosts {
		addrs, err := res.LookupIPAddr(ctx, h)
		if err != nil {
			var de *net.DNSError
			if errors.As(err, &de) && de.IsNotFound {
				ecarts = append(ecarts, fmt.Sprintf("DNS : %s ne résout pas", h))
			} else {
				ecarts = append(ecarts, fmt.Sprintf("DNS : résolution de %s en échec", h))
				notes = append(notes, fmt.Sprintf("DNS : %s : %v", h, err))
			}
			continue
		}
		var hors []string
		v4 := false
		for _, ad := range addrs {
			ip, ok := netip.AddrFromSlice(ad.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if ip.Is4() {
				v4 = true
			}
			if vms[ip] || (edge && inRanges(ip, cloudflareRanges)) {
				continue
			}
			hors = append(hors, ip.String())
		}
		sort.Strings(hors)
		switch {
		case len(hors) > 0:
			attendu := "les IP des VM du stage " + a.Stage
			if edge {
				attendu += " ou Cloudflare"
			}
			ecarts = append(ecarts, fmt.Sprintf("DNS : %s résout vers %s, hors de %s", h, strings.Join(hors, " "), attendu))
		case !v4:
			ecarts = append(ecarts, fmt.Sprintf("DNS : %s sans adresse IPv4", h))
		}
	}
	return ecarts, notes
}

func inRanges(ip netip.Addr, ranges []netip.Prefix) bool {
	for _, p := range ranges {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
