package sideload

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

type Profile struct {
	Path         string
	Name         string
	TeamID       string
	AppID        string
	Expires      time.Time
	Entitlements map[string]any
	Certificates []string
	Devices      []string
	AllDevices   bool
}

func DefaultProfileDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "Developer", "Xcode", "UserData", "Provisioning Profiles")
}

func (p Profile) Bundle() string {
	return strings.TrimPrefix(p.AppID, p.TeamID+".")
}

func (p Profile) Covers(bundleID string) bool {
	pattern := p.Bundle()
	if prefix, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(bundleID, prefix)
	}
	return pattern == bundleID
}

func (p Profile) Installs(device string) bool {
	if p.AllDevices || device == "" {
		return true
	}
	for _, provisioned := range p.Devices {
		if strings.EqualFold(provisioned, device) {
			return true
		}
	}
	return false
}

func (p Profile) SignedBy(identity string) bool {
	for _, certificate := range p.Certificates {
		if strings.EqualFold(certificate, identity) {
			return true
		}
	}
	return false
}

func LoadProfiles(ctx context.Context, run Runner, dir string) ([]Profile, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.mobileprovision"))
	if err != nil {
		return nil, err
	}
	var profiles []Profile
	for _, path := range paths {
		profile, err := loadProfile(ctx, run, path)
		if err != nil {
			continue
		}
		profiles = append(profiles, profile)
	}
	return profiles, nil
}

func loadProfile(ctx context.Context, run Runner, path string) (Profile, error) {
	decoded, err := run(ctx, "security", "cms", "-D", "-i", path)
	if err != nil {
		return Profile{}, fmt.Errorf("decode %s: %w", path, err)
	}
	plist, err := os.CreateTemp("", "jb-p1lot-profile-*.plist")
	if err != nil {
		return Profile{}, err
	}
	defer os.Remove(plist.Name())
	if _, err := plist.Write(decoded); err != nil {
		plist.Close()
		return Profile{}, err
	}
	plist.Close()
	extract := func(key, format string) (string, error) {
		output, err := run(ctx, "plutil", "-extract", key, format, "-o", "-", plist.Name())
		return strings.TrimSpace(string(output)), err
	}
	entitlementsJSON, err := extract("Entitlements", "json")
	if err != nil {
		return Profile{}, err
	}
	profile := Profile{Path: path}
	if err := json.Unmarshal([]byte(entitlementsJSON), &profile.Entitlements); err != nil {
		return Profile{}, err
	}
	profile.Name, _ = extract("Name", "raw")
	profile.TeamID, _ = extract("TeamIdentifier.0", "raw")
	profile.AppID, _ = profile.Entitlements["application-identifier"].(string)
	if devices, err := extract("ProvisionedDevices", "json"); err == nil {
		_ = json.Unmarshal([]byte(devices), &profile.Devices)
	}
	allDevices, _ := extract("ProvisionsAllDevices", "raw")
	profile.AllDevices = allDevices == "true"
	if expires, err := extract("ExpirationDate", "raw"); err == nil {
		profile.Expires, _ = time.Parse(time.RFC3339, expires)
	}
	for index := 0; ; index++ {
		encoded, err := extract("DeveloperCertificates."+strconv.Itoa(index), "raw")
		if err != nil || encoded == "" {
			break
		}
		certificate, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			break
		}
		sum := sha1.Sum(certificate)
		profile.Certificates = append(profile.Certificates, strings.ToUpper(hex.EncodeToString(sum[:])))
	}
	return profile, nil
}

type Target struct {
	Identity string
	Device   string
	Now      time.Time
}

func MatchProfile(profiles []Profile, target Target, bundleID string) (Profile, bool) {
	var best Profile
	found := false
	for _, profile := range profiles {
		if !profile.Covers(bundleID) || !profile.SignedBy(target.Identity) || !profile.Installs(target.Device) || profile.Expires.Before(target.Now) {
			continue
		}
		exact := !strings.HasSuffix(profile.AppID, "*")
		bestExact := found && !strings.HasSuffix(best.AppID, "*")
		if !found || (exact && !bestExact) || (exact == bestExact && profile.Expires.After(best.Expires)) {
			best, found = profile, true
		}
	}
	return best, found
}

func Entitlements(profile Profile, bundleID string) map[string]any {
	concrete := profile.TeamID + "." + bundleID
	entitlements := make(map[string]any, len(profile.Entitlements))
	for key, value := range profile.Entitlements {
		entitlements[key] = expandWildcards(value, concrete)
	}
	entitlements["application-identifier"] = concrete
	return entitlements
}

func expandWildcards(value any, concrete string) any {
	switch typed := value.(type) {
	case string:
		if strings.HasSuffix(typed, "*") {
			return concrete
		}
		return typed
	case []any:
		expanded := make([]any, len(typed))
		for index, item := range typed {
			expanded[index] = expandWildcards(item, concrete)
		}
		return expanded
	}
	return value
}

func ParseIdentities(output string) []string {
	var identities []string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || !strings.HasSuffix(fields[0], ")") || len(fields[1]) != 40 {
			continue
		}
		identities = append(identities, strings.ToUpper(fields[1]))
	}
	return identities
}
