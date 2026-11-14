package sideload

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Options struct {
	IPA        string
	BundleID   string
	Identity   string
	Device     string
	ProfileDir string
	Work       string
	Install    bool
}

type Bundle struct {
	Path       string `json:"path"`
	OriginalID string `json:"originalId"`
	BundleID   string `json:"bundleId"`
	Profile    string `json:"profile,omitempty"`
}

type Result struct {
	App      string   `json:"app"`
	Identity string   `json:"identity"`
	Signed   []Bundle `json:"signed"`
	Dropped  []Bundle `json:"dropped,omitempty"`
	Groups   []string `json:"appGroups,omitempty"`
	Install  string   `json:"install,omitempty"`
}

func ExtensionID(originalApp, originalExtension, newApp string) string {
	suffix, ok := strings.CutPrefix(originalExtension, originalApp+".")
	if !ok {
		suffix = originalExtension[strings.LastIndex(originalExtension, ".")+1:]
	}
	return newApp + "." + suffix
}

func Sideload(ctx context.Context, run Runner, options Options) (Result, error) {
	if options.IPA == "" || options.BundleID == "" {
		return Result{}, errors.New("ipa and bundleId are required")
	}
	if options.ProfileDir == "" {
		options.ProfileDir = DefaultProfileDir()
	}
	work, err := os.MkdirTemp(options.Work, "jb-p1lot-sideload-*")
	if err != nil {
		return Result{}, err
	}
	if options.Install {
		defer os.RemoveAll(work)
	}
	if _, err := run(ctx, "ditto", "-x", "-k", options.IPA, work); err != nil {
		return Result{}, fmt.Errorf("unpack %s: %w", options.IPA, err)
	}
	apps, _ := filepath.Glob(filepath.Join(work, "Payload", "*.app"))
	if len(apps) != 1 {
		return Result{}, fmt.Errorf("%s holds %d apps, expected one", options.IPA, len(apps))
	}
	app := apps[0]
	profiles, err := LoadProfiles(ctx, run, options.ProfileDir)
	if err != nil {
		return Result{}, err
	}
	identity, err := pickIdentity(ctx, run, options, profiles)
	if err != nil {
		return Result{}, err
	}
	result := Result{App: app, Identity: identity}
	bundles, err := plan(ctx, run, app, options.BundleID)
	if err != nil {
		return Result{}, err
	}
	target := Target{Identity: identity, Device: options.Device, Now: time.Now()}
	for _, bundle := range bundles {
		profile, ok := MatchProfile(profiles, target, bundle.BundleID)
		if !ok && bundle.Path == app {
			return Result{}, fmt.Errorf("no provisioning profile for %s signed by %s and listing device %s in %s; register both in Xcode first", bundle.BundleID, identity, options.Device, options.ProfileDir)
		}
		if !ok {
			if err := os.RemoveAll(bundle.Path); err != nil {
				return Result{}, err
			}
			result.Dropped = append(result.Dropped, bundle)
			continue
		}
		bundle.Profile = profile.Path
		if err := prepare(ctx, run, bundle, profile); err != nil {
			return Result{}, err
		}
		if bundle.Path == app {
			result.Groups = stringList(profile.Entitlements["com.apple.security.application-groups"])
		}
		result.Signed = append(result.Signed, bundle)
	}
	if err := signAll(ctx, run, target, result.Signed, profiles); err != nil {
		return result, err
	}
	if !options.Install {
		return result, nil
	}
	output, err := run(ctx, "xcrun", "devicectl", "device", "install", "app", "--device", options.Device, app)
	result.Install = strings.TrimSpace(string(output))
	if err != nil {
		return result, fmt.Errorf("install: %w", err)
	}
	return result, nil
}

func pickIdentity(ctx context.Context, run Runner, options Options, profiles []Profile) (string, error) {
	if options.Identity != "" {
		return strings.ToUpper(options.Identity), nil
	}
	output, err := run(ctx, "security", "find-identity", "-v", "-p", "codesigning")
	if err != nil {
		return "", fmt.Errorf("list signing identities: %w", err)
	}
	for _, identity := range ParseIdentities(string(output)) {
		target := Target{Identity: identity, Device: options.Device, Now: time.Now()}
		if _, ok := MatchProfile(profiles, target, options.BundleID); ok {
			return identity, nil
		}
	}
	return "", fmt.Errorf("no signing identity has a provisioning profile for %s on device %s", options.BundleID, options.Device)
}

func plistString(ctx context.Context, run Runner, path, key string) (string, error) {
	output, err := run(ctx, "plutil", "-extract", key, "raw", "-o", "-", path)
	return strings.TrimSpace(string(output)), err
}

func plan(ctx context.Context, run Runner, app, bundleID string) ([]Bundle, error) {
	original, err := plistString(ctx, run, filepath.Join(app, "Info.plist"), "CFBundleIdentifier")
	if err != nil {
		return nil, fmt.Errorf("read the app's bundle id: %w", err)
	}
	bundles := []Bundle{{Path: app, OriginalID: original, BundleID: bundleID}}
	extensions, _ := filepath.Glob(filepath.Join(app, "PlugIns", "*.appex"))
	sort.Strings(extensions)
	for _, extension := range extensions {
		id, err := plistString(ctx, run, filepath.Join(extension, "Info.plist"), "CFBundleIdentifier")
		if err != nil {
			return nil, fmt.Errorf("read %s's bundle id: %w", filepath.Base(extension), err)
		}
		bundles = append(bundles, Bundle{Path: extension, OriginalID: id, BundleID: ExtensionID(original, id, bundleID)})
	}
	return bundles, nil
}

func prepare(ctx context.Context, run Runner, bundle Bundle, profile Profile) error {
	if _, err := run(ctx, "plutil", "-replace", "CFBundleIdentifier", "-string", bundle.BundleID, filepath.Join(bundle.Path, "Info.plist")); err != nil {
		return fmt.Errorf("rename %s: %w", filepath.Base(bundle.Path), err)
	}
	data, err := os.ReadFile(profile.Path)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(bundle.Path, "embedded.mobileprovision"), data, 0o644); err != nil {
		return err
	}
	return os.RemoveAll(filepath.Join(bundle.Path, "_CodeSignature"))
}

func nestedCode(root string) []string {
	var code []string
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || path == root {
			return nil
		}
		if entry.IsDir() && strings.HasSuffix(path, ".appex") {
			return filepath.SkipDir
		}
		if (entry.IsDir() && strings.HasSuffix(path, ".framework")) || (!entry.IsDir() && strings.HasSuffix(path, ".dylib")) {
			code = append(code, path)
		}
		return nil
	})
	sort.Slice(code, func(a, b int) bool { return strings.Count(code[a], "/") > strings.Count(code[b], "/") })
	return code
}

func signAll(ctx context.Context, run Runner, target Target, bundles []Bundle, profiles []Profile) error {
	identity := target.Identity
	for index := len(bundles) - 1; index >= 0; index-- {
		bundle := bundles[index]
		for _, code := range nestedCode(bundle.Path) {
			if _, err := run(ctx, "codesign", "-f", "-s", identity, code); err != nil {
				return fmt.Errorf("sign %s: %w", filepath.Base(code), err)
			}
		}
		profile, _ := MatchProfile(profiles, target, bundle.BundleID)
		entitlements, err := writeEntitlements(ctx, run, Entitlements(profile, bundle.BundleID))
		if err != nil {
			return err
		}
		output, err := run(ctx, "codesign", "-f", "-s", identity, "--entitlements", entitlements, bundle.Path)
		os.Remove(entitlements)
		if err != nil {
			return fmt.Errorf("sign %s: %w: %s", filepath.Base(bundle.Path), err, output)
		}
	}
	if output, err := run(ctx, "codesign", "--verify", "--deep", "--strict", bundles[0].Path); err != nil {
		return fmt.Errorf("verify %s: %w: %s", filepath.Base(bundles[0].Path), err, output)
	}
	return nil
}

func writeEntitlements(ctx context.Context, run Runner, entitlements map[string]any) (string, error) {
	data, err := json.Marshal(entitlements)
	if err != nil {
		return "", err
	}
	file, err := os.CreateTemp("", "jb-p1lot-entitlements-*.plist")
	if err != nil {
		return "", err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return "", err
	}
	file.Close()
	if _, err := run(ctx, "plutil", "-convert", "xml1", file.Name()); err != nil {
		os.Remove(file.Name())
		return "", err
	}
	return file.Name(), nil
}

func stringList(value any) []string {
	items, _ := value.([]any)
	var list []string
	for _, item := range items {
		if text, ok := item.(string); ok {
			list = append(list, text)
		}
	}
	return list
}
