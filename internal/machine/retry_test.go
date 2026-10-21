package machine

import (
	"testing"
	"time"
)

func TestRetryDelay(t *testing.T) {
	want := []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second,
		160 * time.Second, 5 * time.Minute, 5 * time.Minute}
	for i, w := range want {
		if got := retryDelay(i + 1); got != w {
			t.Errorf("retryDelay(%d) = %v, want %v", i+1, got, w)
		}
	}
	if got := retryDelay(100); got != nodeRetryMax {
		t.Errorf("retryDelay(100) = %v, want cap %v", got, nodeRetryMax)
	}
}
