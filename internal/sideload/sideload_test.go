package sideload

import (
	"reflect"
	"testing"
	"time"
)

func TestExtensionID(t *testing.T) {
	cases := map[string]string{
		"com.hammerandchisel.discord.Share":           "dev.example.se.Share",
		"com.hammerandchisel.discord.widgets.Weather": "dev.example.se.widgets.Weather",
		"com.other.vendor.Broadcast":                  "dev.example.se.Broadcast",
	}
	for original, want := range cases {
		if got := ExtensionID("com.hammerandchisel.discord", original, "dev.example.se"); got != want {
			t.Fatalf("ExtensionID(%s) = %s, want %s", original, got, want)
		}
	}
}

func TestMatchProfilePrefersExactUnexpiredProfilesFromTheIdentity(t *testing.T) {
	now := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	identity := "AAAA"
	device := "00008030-0001"
	target := Target{Identity: identity, Device: device, Now: now}
	wildcard := Profile{Path: "wildcard", TeamID: "T", AppID: "T.*", Expires: now.Add(time.Hour * 48), Certificates: []string{identity}, Devices: []string{device}}
	exact := Profile{Path: "exact", TeamID: "T", AppID: "T.dev.example.se", Expires: now.Add(time.Hour), Certificates: []string{identity}, Devices: []string{device}}
	expired := Profile{Path: "expired", TeamID: "T", AppID: "T.dev.example.se", Expires: now.Add(-time.Hour), Certificates: []string{identity}, Devices: []string{device}}
	other := Profile{Path: "other", TeamID: "T", AppID: "T.dev.example.se", Expires: now.Add(time.Hour * 96), Certificates: []string{"BBBB"}, Devices: []string{device}}
	elsewhere := Profile{Path: "elsewhere", TeamID: "T", AppID: "T.dev.example.se.Widget", Expires: now.Add(time.Hour * 96), Certificates: []string{identity}, Devices: []string{"00008130-0002"}}
	profiles := []Profile{wildcard, expired, other, exact, elsewhere}

	if got, ok := MatchProfile(profiles, target, "dev.example.se"); !ok || got.Path != "exact" {
		t.Fatalf("got %s, want the exact profile", got.Path)
	}
	if got, ok := MatchProfile(profiles, target, "dev.example.se.Share"); !ok || got.Path != "wildcard" {
		t.Fatalf("got %s, want the wildcard profile", got.Path)
	}
	if got, ok := MatchProfile(profiles, target, "dev.example.se.Widget"); !ok || got.Path != "wildcard" {
		t.Fatalf("got %s, want the wildcard profile over one for another device", got.Path)
	}
	if _, ok := MatchProfile([]Profile{exact}, target, "dev.example.se.Share"); ok {
		t.Fatal("an exact profile must not cover another id")
	}
}

func TestEntitlementsNameTheBundleAndExpandWildcards(t *testing.T) {
	profile := Profile{TeamID: "T", AppID: "T.*", Entitlements: map[string]any{
		"application-identifier":                "T.*",
		"keychain-access-groups":                []any{"T.*", "com.apple.token"},
		"com.apple.security.application-groups": []any{"group.dev.example.se"},
		"get-task-allow":                        true,
	}}

	got := Entitlements(profile, "dev.example.se.Share")

	want := map[string]any{
		"application-identifier":                "T.dev.example.se.Share",
		"keychain-access-groups":                []any{"T.dev.example.se.Share", "com.apple.token"},
		"com.apple.security.application-groups": []any{"group.dev.example.se"},
		"get-task-allow":                        true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseIdentities(t *testing.T) {
	output := `  1) F745B6CC0706F2C8EAD62C9A1FD1090E52B2B893 "Apple Development: someone (ABCDE12345)"
  2) 0123456789abcdef0123456789abcdef01234567 "Apple Distribution: someone (ABCDE12345)"
     2 valid identities found`

	want := []string{"F745B6CC0706F2C8EAD62C9A1FD1090E52B2B893", "0123456789ABCDEF0123456789ABCDEF01234567"}
	if got := ParseIdentities(output); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
