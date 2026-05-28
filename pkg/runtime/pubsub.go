package runtime

import (
	"context"
	"errors"
	"fmt"

	"github.com/redis/go-redis/v9"
)

// Publish sends payload to subscribers of channel. payload is opaque
// bytes; CALLERS MUST NOT publish secret values — Redis pub/sub is
// fanout-only, doesn't persist, and isn't reviewable for compliance.
// Worker-side notifications about state CHANGES (new request, job
// completed) are the intended use case.
func (c *Client) Publish(ctx context.Context, channel string, payload []byte) (int64, error) {
	if c == nil || c.rdb == nil {
		return 0, errors.New("runtime: client not initialized")
	}
	full := c.key("ch", channel)
	delivered, err := c.rdb.Publish(ctx, full, payload).Result()
	if err != nil {
		return 0, fmt.Errorf("runtime: publish: %w", err)
	}
	return delivered, nil
}

// Subscription is the receive side of a pub/sub channel. Always Close
// it; un-closed subscriptions leak the underlying connection.
type Subscription struct {
	ps      *redis.PubSub
	channel string
	closed  bool
}

// Subscribe opens a subscription to channel. The returned Subscription
// must be Close()d when no longer needed.
func (c *Client) Subscribe(ctx context.Context, channel string) (*Subscription, error) {
	if c == nil || c.rdb == nil {
		return nil, errors.New("runtime: client not initialized")
	}
	full := c.key("ch", channel)
	ps := c.rdb.Subscribe(ctx, full)
	// Wait for the subscribe acknowledgement so the caller knows the
	// channel is actively receiving before they kick off whatever
	// publishes into it.
	if _, err := ps.Receive(ctx); err != nil {
		_ = ps.Close()
		return nil, fmt.Errorf("runtime: subscribe: %w", err)
	}
	return &Subscription{ps: ps, channel: full}, nil
}

// Receive blocks until the next message arrives on the subscription
// (or ctx is cancelled). Returns the payload.
func (s *Subscription) Receive(ctx context.Context) ([]byte, error) {
	msg, err := s.ps.ReceiveMessage(ctx)
	if err != nil {
		return nil, fmt.Errorf("runtime: receive: %w", err)
	}
	return []byte(msg.Payload), nil
}

// Close releases the subscription. Idempotent.
func (s *Subscription) Close() error {
	if s == nil || s.closed {
		return nil
	}
	s.closed = true
	return s.ps.Close()
}
