package limiter

import (
	"sync"
	"sync/atomic"

	"github.com/cedar2025/xboard-node/internal/model"
	"golang.org/x/time/rate"
)

// SpeedTrackerLogCallback is called when bucket updates occur.
type SpeedTrackerLogCallback func(msg string)

// SpeedTracker manages per-user token-bucket rate limiters.
// It does NOT wrap connections itself — instead, ConnTracker consults it
// via GetLimiter to embed rate limiting in the same tracked connection
// wrapper that does byte counting.
type SpeedTracker struct {
	limiter *Limiter
	mu      sync.RWMutex
	buckets map[int]*rate.Limiter // userID → shared rate limiter
	uuidMap map[string]int        // UUID → userID

	// penalized holds userIDs whose bucket is currently held at an auto-throttle
	// penalty rate. UpdateBuckets leaves these alone so a routine user-sync from
	// the panel doesn't lift an active penalty; ClearPenalty restores them.
	penalized map[int]struct{}

	// Fast-path: when no users have a speed limit, GetLimiter returns nil
	// immediately without any map lookup.
	hasLimits atomic.Bool

	// Optional callback for logging
	logFunc SpeedTrackerLogCallback
}

// NewSpeedTracker creates a bucket manager for per-user bandwidth throttling.
func NewSpeedTracker(l *Limiter) *SpeedTracker {
	return &SpeedTracker{
		limiter:   l,
		buckets:   make(map[int]*rate.Limiter),
		uuidMap:   make(map[string]int),
		penalized: make(map[int]struct{}),
	}
}

// SetLogCallback sets the logging callback.
func (t *SpeedTracker) SetLogCallback(f SpeedTrackerLogCallback) {
	t.logFunc = f
}

// UpdateBuckets updates the UUID→userID mapping and syncs existing limiters.
func (t *SpeedTracker) UpdateBuckets() {
	currentUsers := make([]model.UserSpec, 0, 32)
	t.limiter.mu.RLock()
	for _, u := range t.limiter.users {
		currentUsers = append(currentUsers, u)
	}
	t.limiter.mu.RUnlock()

	func() {
		t.mu.Lock()
		defer t.mu.Unlock()

		newUUIDMap := make(map[string]int, len(currentUsers))
		activeIDs := make(map[int]struct{}, len(currentUsers))

		for _, user := range currentUsers {
			activeIDs[user.ID] = struct{}{}
			if user.UUID != "" {
				newUUIDMap[user.UUID] = user.ID
			}

			// Leave penalized users' buckets alone — a routine user-sync must
			// not lift an active auto-throttle penalty.
			if _, pen := t.penalized[user.ID]; pen {
				continue
			}

			// Update existing limiter if speed changed
			if lim, ok := t.buckets[user.ID]; ok {
				if user.SpeedLimit > 0 {
					bytesPerSec := int(user.SpeedLimit) * 1_000_000 / 8
					burst := bytesPerSec
					if burst < 64*1024 {
						burst = 64 * 1024
					}
					lim.SetLimit(rate.Limit(bytesPerSec))
					lim.SetBurst(burst)
				} else {
					delete(t.buckets, user.ID)
				}
			}
		}

		// Clean up buckets for removed users
		for id := range t.buckets {
			if _, ok := activeIDs[id]; !ok {
				delete(t.buckets, id)
				delete(t.penalized, id)
			}
		}

		t.uuidMap = newUUIDMap
		t.hasLimits.Store(len(t.buckets) > 0)
	}()

	if t.logFunc != nil {
		t.logFunc("buckets updated")
	}
}

// GetLimiter returns the rate limiter for the given user UUID, or nil if
// no limit applies. Creates limiter on-demand if not exists.
// Thread-safe.
func (t *SpeedTracker) GetLimiter(user string) *rate.Limiter {
	t.mu.RLock()
	uid, exists := t.uuidMap[user]
	if !exists {
		t.mu.RUnlock()
		return nil
	}
	if lim, ok := t.buckets[uid]; ok {
		t.mu.RUnlock()
		return lim
	}
	t.mu.RUnlock()

	// Get user info from limiter
	t.limiter.mu.RLock()
	u, userExists := t.limiter.users[uid]
	t.limiter.mu.RUnlock()

	if !userExists || u.SpeedLimit <= 0 {
		return nil
	}

	// Create limiter on-demand
	bytesPerSec := int(u.SpeedLimit) * 1_000_000 / 8
	burst := bytesPerSec
	if burst < 64*1024 {
		burst = 64 * 1024
	}
	if cap4s := bytesPerSec * 4; cap4s > 64*1024 && burst > cap4s {
		burst = cap4s
	}

	lim := rate.NewLimiter(rate.Limit(bytesPerSec), burst)

	t.mu.Lock()
	// Double-check after acquiring write lock
	if existing, ok := t.buckets[uid]; ok {
		t.mu.Unlock()
		return existing
	}
	t.buckets[uid] = lim
	t.hasLimits.Store(true)
	t.mu.Unlock()

	return lim
}

// HasLimits returns true if any user currently has a speed limit configured.
func (t *SpeedTracker) HasLimits() bool {
	return t.hasLimits.Load()
}

// LimitedUserCount returns the number of users with active speed limits.
func (t *SpeedTracker) LimitedUserCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.buckets)
}

// penaltyBurst returns a sensible burst for a given bytes/sec rate.
func penaltyBurst(bytesPerSec int) int {
	burst := bytesPerSec
	if burst < 64*1024 {
		burst = 64 * 1024
	}
	return burst
}

// SetPenalty forces a user's shared bucket to the given bytes/sec rate and marks
// them penalized so UpdateBuckets won't lift it. Idempotent: safe to call every
// track cycle to keep the penalty in force. Existing connections of a user who
// already had a bucket (i.e. a configured speed limit) are throttled
// immediately because they share this instance; unlimited users only feel it on
// their next connection (which is why the policy escalates to a kick).
func (t *SpeedTracker) SetPenalty(userID, bytesPerSec int) {
	if bytesPerSec <= 0 {
		bytesPerSec = 1
	}
	burst := penaltyBurst(bytesPerSec)
	t.mu.Lock()
	if lim, ok := t.buckets[userID]; ok {
		lim.SetLimit(rate.Limit(bytesPerSec))
		lim.SetBurst(burst)
	} else {
		t.buckets[userID] = rate.NewLimiter(rate.Limit(bytesPerSec), burst)
	}
	t.penalized[userID] = struct{}{}
	t.hasLimits.Store(true)
	t.mu.Unlock()
}

// ClearPenalty lifts a user's auto-throttle penalty, restoring their configured
// speed limit (or removing the bucket entirely if they have none).
func (t *SpeedTracker) ClearPenalty(userID int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.penalized[userID]; !ok {
		return
	}
	delete(t.penalized, userID)

	t.limiter.mu.RLock()
	u, exists := t.limiter.users[userID]
	t.limiter.mu.RUnlock()

	if exists && u.SpeedLimit > 0 {
		bytesPerSec := u.SpeedLimit * 1_000_000 / 8
		burst := penaltyBurst(bytesPerSec)
		if lim, ok := t.buckets[userID]; ok {
			lim.SetLimit(rate.Limit(bytesPerSec))
			lim.SetBurst(burst)
		} else {
			t.buckets[userID] = rate.NewLimiter(rate.Limit(bytesPerSec), burst)
		}
	} else {
		delete(t.buckets, userID)
	}
	t.hasLimits.Store(len(t.buckets) > 0)
}

// PenalizedCount returns the number of users currently under an auto-throttle penalty.
func (t *SpeedTracker) PenalizedCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.penalized)
}

// PenalizedUserIDs returns the IDs of users currently under an auto-throttle
// penalty, so the panel can show who (not just how many).
func (t *SpeedTracker) PenalizedUserIDs() []int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	ids := make([]int, 0, len(t.penalized))
	for id := range t.penalized {
		ids = append(ids, id)
	}
	return ids
}
