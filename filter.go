package socks5

import "net"

type Filter interface {
	Pass(net.Addr) bool
}
