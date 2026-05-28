package runtime

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrLockHeld is returned by AcquireLock when another caller currently
// owns the lock. Worker code uses this to back off and retry.
var ErrLockHeld = errors.New("runtime: lock held")

// ErrLockLost is returned by Lock.Release / Lock.Renew when the lock's
// lease has expired and someone else may have acquired it. Treat as a
// signal to abandon any side-effects guarded by the lock.
var ErrLockLost = errors.New("runtime: lock lease lost")

// Lock represents an acquired distributed lock. Always release it via
// Release(); leaving it un-released is safe (the lease TTL releases it
// eventually) but wastes time.
type Lock struct {
	client *Client
	key    string // already namespaced
	token  string
	lease  time.Duration

	mu       sync.Mutex
	released bool
	stopCh   chan struct{}
}

// AcquireLock attempts to acquire a distributed lock under name. The
// lease determines how long the lock survives a crashed caller.
// AutoRenew can be enabled by calling Lock.StartRenewal — otherwise
// the caller is expected to finish within lease.
func (c *Client) AcquireLock(ctx context.Context, name string, lease time.Duration) (*Lock, error) {
	if lease <= 0 {
		lease = 30 * time.Second
	}
	tok, err := randomToken(16)
	if err != nil {
		return nil, err
	}
	full := c.key("lock", name)
	ok, err := c.rdb.SetNX(ctx, full, tok, lease).Result()
	if err != nil {
		return nil, fmt.Errorf("runtime: lock SETNX: %w", err)
	}
	if !ok {
		return nil, ErrLockHeld
	}
	return &Lock{client: c, key: full, token: tok, lease: lease}, nil
}

// Release returns the lock to the pool. Token-guarded so a caller whose
// lease has expired (and the lock now belongs to someone else) does NOT
// accidentally release the new owner's lock. Returns ErrLockLost when
// the lease has flipped.
func (l *Lock) Release(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released {
		return nil
	}
	l.released = true
	if l.stopCh != nil {
		close(l.stopCh)
		l.stopCh = nil
	}

	script := redis.NewScript(`
		if redis.call("GET", KEYS[1]) == ARGV[1] then
			redis.call("DEL", KEYS[1])
			return 1
		end
		return 0
	`)
	res, err := script.Run(ctx, l.client.rdb, []string{l.key}, l.token).Result()
	if err != nil {
		return fmt.Errorf("runtime: lock release: %w", err)
	}
	if n, _ := res.(int64); n == 0 {
		return ErrLockLost
	}
	return nil
}

// Renew extends the lease by the original duration if (and only if) the
// caller still owns the lock. Returns ErrLockLost when the lease has
// flipped to a new owner.
func (l *Lock) Renew(ctx context.Context) error {
	script := redis.NewScript(`
		if redis.call("GET", KEYS[1]) == ARGV[1] then
			redis.call("PEXPIRE", KEYS[1], ARGV[2])
			return 1
		end
		return 0
	`)
	res, err := script.Run(ctx, l.client.rdb, []string{l.key}, l.token, l.lease.Milliseconds()).Result()
	if err != nil {
		return fmt.Errorf("runtime: lock renew: %w", err)
	}
	if n, _ := res.(int64); n == 0 {
		return ErrLockLost
	}
	return nil
}

// StartRenewal launches a background goroutine that calls Renew every
// lease/3. The returned cancel func stops the renewer; Release does so
// implicitly. Useful for long-running jobs that may exceed the lease.
//
// onLost is invoked once if a Renew call returns ErrLockLost so the
// caller can abandon the work; passing nil treats it as a silent loss.
func (l *Lock) StartRenewal(parent context.Context, onLost func()) (cancel func()) {
	l.mu.Lock()
	if l.released || l.stopCh != nil {
		l.mu.Unlock()
		return func() {}
	}
	stop := make(chan struct{})
	l.stopCh = stop
	interval := l.lease / 3
	if interval < 100*time.Millisecond {
		interval = 100 * time.Millisecond
	}
	l.mu.Unlock()

	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-parent.Done():
				return
			case <-t.C:
				renewCtx, c := context.WithTimeout(parent, interval)
				err := l.Renew(renewCtx)
				c()
				if errors.Is(err, ErrLockLost) {
					if onLost != nil {
						onLost()
					}
					return
				}
			}
		}
	}()

	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.stopCh == stop {
			close(stop)
			l.stopCh = nil
		}
	}
}
