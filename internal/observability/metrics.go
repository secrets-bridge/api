package observability

import (
	"context"
	"errors"
	"net"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// RedisCallTimeouts counts Redis calls that ran out of their deadline, by
// call site. A slow but reachable Redis shows up here before the rate
// limiters start failing open and the reject-audit rollup stops folding
// rows (api#306).
var RedisCallTimeouts = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "redis_call_timeouts_total",
		Help: "Redis calls that hit their deadline, by site. Site set is fixed at {auth_cache, rate_limit}.",
	},
	[]string{"site"},
)

// Redis call sites for RedisCallTimeouts.
const (
	RedisSiteAuthCache = "auth_cache"
	RedisSiteRateLimit = "rate_limit"
)

// CountRedisTimeout adds one to RedisCallTimeouts for site when err is a
// deadline expiry, and returns err unchanged.
func CountRedisTimeout(site string, err error) error {
	if isTimeout(err) {
		RedisCallTimeouts.WithLabelValues(site).Inc()
	}
	return err
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
