//go:build linux

package resolve

import (
	"fmt"
	"net"
	"syscall"
)

func bindControl(network string, bindIP net.IP, iface string, c syscall.RawConn) error {
	var opErr error
	err := c.Control(func(fd uintptr) {
		if iface != "" {
			if e := syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface); e != nil {
				opErr = fmt.Errorf("SO_BINDTODEVICE %s: %w", iface, e)
				return
			}
		}
		// Source IP: prefer Dialer.LocalAddr; when only Control runs for UDP, bind sockaddr.
		if bindIP != nil {
			if ip4 := bindIP.To4(); ip4 != nil {
				sa := &syscall.SockaddrInet4{Port: 0}
				copy(sa.Addr[:], ip4)
				if e := syscall.Bind(int(fd), sa); e != nil && e != syscall.EINVAL && e != syscall.EADDRINUSE {
					// EINVAL often means already bound — ignore
					if e != syscall.EINVAL {
						opErr = fmt.Errorf("bind %s: %w", bindIP, e)
					}
				}
			} else {
				sa := &syscall.SockaddrInet6{Port: 0}
				copy(sa.Addr[:], bindIP.To16())
				if e := syscall.Bind(int(fd), sa); e != nil && e != syscall.EINVAL {
					opErr = fmt.Errorf("bind %s: %w", bindIP, e)
				}
			}
		}
		_ = network
	})
	if err != nil {
		return err
	}
	return opErr
}
