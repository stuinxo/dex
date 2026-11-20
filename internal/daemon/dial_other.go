//go:build !linux

package daemon

import (
	"net"
	"time"
)

func newDirectDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   8 * time.Second,
		KeepAlive: 30 * time.Second,
	}
}
