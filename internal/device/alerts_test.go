package device

import "testing"

func TestSystemAlertsKeepsOnlyAlertWindows(t *testing.T) {
	windows := []map[string]any{
		{"class": "SBStatusBarWindow", "labels": []any{"No SIM", "04:39"}},
		{"class": "SBAlertItemWindow", "labels": []any{"test@example.invalid", "Cancel", "Call"}},
		{"class": "SSScreenshotsWindow", "labels": []any{}},
	}

	alerts := systemAlerts(windows)

	if len(alerts) != 1 || alerts[0]["class"] != "SBAlertItemWindow" {
		t.Fatalf("expected only the alert window, got %v", alerts)
	}
}

func TestSystemAlertsIsEmptyWithoutAlerts(t *testing.T) {
	if alerts := systemAlerts([]map[string]any{{"class": "SBStatusBarWindow"}}); len(alerts) != 0 {
		t.Fatalf("expected no alerts, got %v", alerts)
	}
}
