package main

import "testing"

func TestHostsFromCIDR(t *testing.T) {
	// /30 -> 4 addrs, drop net+broadcast => 2 hosts
	h, err := hostsFromCIDR("192.168.1.0/30")
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 2 || h[0] != "192.168.1.1" || h[1] != "192.168.1.2" {
		t.Fatalf("/30 got %v", h)
	}
	// /31 -> 2 addrs, no drop (point-to-point)
	h, _ = hostsFromCIDR("10.0.0.0/31")
	if len(h) != 2 {
		t.Fatalf("/31 got %v", h)
	}
	// /32 -> single host
	h, _ = hostsFromCIDR("10.0.0.5/32")
	if len(h) != 1 || h[0] != "10.0.0.5" {
		t.Fatalf("/32 got %v", h)
	}
	// /24 -> 254 usable hosts
	h, _ = hostsFromCIDR("172.16.0.0/24")
	if len(h) != 254 {
		t.Fatalf("/24 host count %d", len(h))
	}
	// too large
	if _, err := hostsFromCIDR("10.0.0.0/8"); err == nil {
		t.Fatal("expected error for /8")
	}
}

func TestDashRange(t *testing.T) {
	h, err := hostsFromDashRange("10.0.0.5-10.0.0.8")
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 4 || h[0] != "10.0.0.5" || h[3] != "10.0.0.8" {
		t.Fatalf("range got %v", h)
	}
	// shorthand last octet
	h, _ = hostsFromDashRange("10.0.0.1-3")
	if len(h) != 3 || h[2] != "10.0.0.3" {
		t.Fatalf("shorthand got %v", h)
	}
	// Full address space must be rejected by the size guard, not overflow to 0
	// and attempt to materialize ~4.29B addresses.
	if _, err := hostsFromDashRange("0.0.0.0-255.255.255.255"); err == nil {
		t.Fatal("expected too-large error for full 0.0.0.0-255.255.255.255 range")
	}
	// Reversed range is rejected.
	if _, err := hostsFromDashRange("10.0.0.9-10.0.0.1"); err == nil {
		t.Fatal("expected error for reversed range")
	}
}

func TestExpandTargets(t *testing.T) {
	out, exp := expandTargets([]string{"192.168.1.0/30", "example.com", "8.8.8.8"})
	if !exp {
		t.Fatal("expected didExpand true")
	}
	// 2 hosts + hostname + ip = 4, deduped
	if len(out) != 4 {
		t.Fatalf("expand got %v", out)
	}
	_, exp2 := expandTargets([]string{"example.com", "1.1.1.1"})
	if exp2 {
		t.Fatal("expected didExpand false for plain hosts")
	}
}

func TestNormalizeTarget(t *testing.T) {
	cases := map[string]string{
		"  example.com  ":           "example.com",
		"https://example.com/login": "example.com",
		"http://example.com:8443/x": "example.com",
		"example.com/path":          "example.com", // path stripped in expandTargets default branch
		"10.0.0.0/24":               "10.0.0.0/24", // CIDR untouched by normalizeTarget
		"10.0.0.1-50":               "10.0.0.1-50", // range untouched
		"8.8.8.8":                   "8.8.8.8",
	}
	for in, want := range cases {
		// normalizeTarget handles scheme stripping; the default-branch path
		// strip is exercised via expandTargets for the no-scheme "host/path" case.
		if in == "example.com/path" {
			out, _ := expandTargets([]string{in})
			if len(out) != 1 || out[0] != want {
				t.Fatalf("expandTargets(%q) = %v, want [%q]", in, out, want)
			}
			continue
		}
		if got := normalizeTarget(in); got != want {
			t.Fatalf("normalizeTarget(%q) = %q, want %q", in, got, want)
		}
	}
	// A URL with scheme+path fully resolves through expandTargets to the host.
	out, _ := expandTargets([]string{"https://scanme.example.org/a/b?q=1"})
	if len(out) != 1 || out[0] != "scanme.example.org" {
		t.Fatalf("url expand got %v", out)
	}
}

func TestSanitizePorts(t *testing.T) {
	got := sanitizePorts([]string{"80", " 443 ", "", "80", "abc", "0", "70000", "8080"})
	want := []string{"80", "443", "8080"}
	if len(got) != len(want) {
		t.Fatalf("sanitizePorts got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sanitizePorts got %v, want %v", got, want)
		}
	}
	if len(sanitizePorts([]string{"", "  ", "bad", "99999"})) != 0 {
		t.Fatal("expected empty result for all-invalid ports")
	}
}
