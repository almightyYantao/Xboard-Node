package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func resetUpdateNotice() {
	updateNoticeMu.Lock()
	updateNoticeLast = ""
	updateNoticeMu.Unlock()
}

func TestSelfUpdateDisabledByEnv(t *testing.T) {
	for v, want := range map[string]bool{"": false, "1": false, "on": false, "0": true, "off": true, "FALSE": true, " no ": true, "disabled": true} {
		t.Setenv("LB_NODE_SELF_UPDATE", v)
		if got := selfUpdateDisabled(); got != want {
			t.Errorf("LB_NODE_SELF_UPDATE=%q: disabled=%v, want %v", v, got, want)
		}
	}
}

// With self-update disabled the panel target is only recorded (hint file), never
// launched, and the global guard stays free.
func TestTriggerSelfUpdateDisabledWritesHint(t *testing.T) {
	resetUpdateNotice()
	hint := filepath.Join(t.TempDir(), "hint")
	t.Setenv("LB_NODE_SELF_UPDATE", "0")
	t.Setenv("LB_NODE_UPDATE_HINT_FILE", hint)
	TriggerSelfUpdate("v9.9.9")
	b, err := os.ReadFile(hint)
	if err != nil || strings.TrimSpace(string(b)) != "v9.9.9" {
		t.Fatalf("hint file = %q, %v", b, err)
	}
	if globalSelfUpdate.Load() {
		t.Fatal("disabled self-update must not take the update guard")
	}
	// Same target again: no rewrite (noticed once).
	os.Remove(hint)
	TriggerSelfUpdate("v9.9.9")
	if _, err := os.Stat(hint); err == nil {
		t.Fatal("same target should only be noted once")
	}
	TriggerSelfUpdate("v9.9.10")
	if b, _ := os.ReadFile(hint); strings.TrimSpace(string(b)) != "v9.9.10" {
		t.Fatalf("new target not recorded: %q", b)
	}
}

// No systemd-run on PATH (procd systems): skip quietly instead of erroring every cycle.
func TestTriggerSelfUpdateWithoutSystemdRun(t *testing.T) {
	resetUpdateNotice()
	hint := filepath.Join(t.TempDir(), "hint")
	t.Setenv("LB_NODE_SELF_UPDATE", "")
	t.Setenv("LB_NODE_UPDATE_HINT_FILE", hint)
	t.Setenv("PATH", t.TempDir())
	TriggerSelfUpdate("v9.9.9")
	if globalSelfUpdate.Load() {
		t.Fatal("must not start an update without systemd-run")
	}
	if b, _ := os.ReadFile(hint); strings.TrimSpace(string(b)) != "v9.9.9" {
		t.Fatalf("hint file = %q", b)
	}
}
