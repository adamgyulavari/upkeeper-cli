package cloudclient

import (
	"context"
	"log"
	"math/rand/v2"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

// Loop collects and sends a report every interval, as long as ctx lives.
type Loop struct {
	Client   *Client
	Collect  func(ctx context.Context) protocol.Report
	Interval time.Duration // from the server; default 300 s
	Logf     func(format string, args ...any)

	MinBackoff time.Duration // default 30 s
	MaxBackoff time.Duration // default 15 min
	// Sleep is replaceable in tests; it returns false if ctx ended.
	Sleep func(ctx context.Context, d time.Duration) bool
	// OnInterval is called when the server changes the interval.
	OnInterval func(seconds int)
	// OnAck sees every accepted report's answer.
	OnAck func(protocol.ReportAck)
}

// Report interval limits: the cloud can't make the agent report more often
// than every minute, or less often than hourly.
const (
	MinInterval = 60
	MaxInterval = 3600
)

// ClampInterval keeps a report interval within MinInterval..MaxInterval seconds.
func ClampInterval(s int) int {
	return max(MinInterval, min(MaxInterval, s))
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Jitter spreads d by ±10 % so a fleet doesn't report in lockstep.
func Jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	span := int64(d) / 5
	if span <= 0 {
		return d
	}
	return d - time.Duration(span/2) + time.Duration(rand.Int64N(span+1))
}

// Run never returns an error; it stops when ctx is done.
func (l *Loop) Run(ctx context.Context) {
	if l.Interval <= 0 {
		l.Interval = 300 * time.Second
	}
	l.Interval = time.Duration(ClampInterval(int(l.Interval/time.Second))) * time.Second
	if l.MinBackoff <= 0 {
		l.MinBackoff = 30 * time.Second
	}
	if l.MaxBackoff <= 0 {
		l.MaxBackoff = 15 * time.Minute
	}
	if l.Sleep == nil {
		l.Sleep = sleepCtx
	}
	logf := l.Logf
	if logf == nil {
		logf = log.Printf
	}
	backoff := time.Duration(0)
	for ctx.Err() == nil {
		r := l.Collect(ctx)
		if ctx.Err() != nil {
			return
		}
		ack, err := l.Client.Report(ctx, r)
		var wait time.Duration
		if err != nil {
			if backoff == 0 {
				backoff = l.MinBackoff
			} else {
				backoff = min(backoff*2, l.MaxBackoff)
			}
			if Unauthorized(err) {
				backoff = l.MaxBackoff
				logf("report rejected: the agent token isn't valid any more. Enroll again with `upkeeper enroll <token>`. Retrying in %s.", backoff)
			} else {
				logf("report not sent: %v. Retrying in %s.", err, backoff)
			}
			wait = backoff
		} else {
			backoff = 0
			if l.OnAck != nil {
				l.OnAck(ack)
			}
			if every := ClampInterval(ack.ReportEvery); ack.ReportEvery > 0 && time.Duration(every)*time.Second != l.Interval {
				ack.ReportEvery = every
				l.Interval = time.Duration(every) * time.Second
				if l.OnInterval != nil {
					l.OnInterval(ack.ReportEvery)
				}
			}
			logf("report sent: %d items, %d risks, %d collector errors. Next in about %s.", len(r.Items), len(r.Risks), len(r.Errors), l.Interval)
			wait = l.Interval
		}
		if !l.Sleep(ctx, Jitter(wait)) {
			return
		}
	}
}
