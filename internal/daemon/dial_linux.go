//go:build linux

package daemon

import (
	"errors"
	"net"
	"syscall"
	"time"

	"github.com/stuinxo/dex/internal/state"
)

func newDirectDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   8 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var sockErr error
			if err := c.Control(func(fd uintptr) {
				sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, state.DirectBypassMark)
				if errors.Is(sockErr, syscall.EPERM) || errors.Is(sockErr, syscall.EACCES) {
					sockErr = nil
				}
			}); err != nil {
				return err
			}
			return sockErr
		},
	}
}
