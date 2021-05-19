package socks5

import "net"

type Filter interface {
	Pass(net.Addr) bool
}

type NoFilter struct{}

func (n NoFilter) Pass(net.Addr) bool {
	return true
}
