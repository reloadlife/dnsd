//go:build !linux

package resolve

import (
	"fmt"
	"net"
	"syscall"
)

func bindControl(network string, bindIP net.IP, iface string, c syscall.RawConn) error {
	if iface != "" {
		return fmt.Errorf("bind_iface %q only supported on linux", iface)
	}
	_ = network
	_ = bindIP
	_ = c
	return nil
}

