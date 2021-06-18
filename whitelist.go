package socks5

import (
	log "github.com/sirupsen/logrus"
	"net"
	"regexp"
)

const IPV4Pattern = "((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3}"

type WhiteList struct {
	Map map[string]bool
}

func NewWhiteList(list []net.IP) WhiteList {
	var m = make(map[string]bool)
	ipv4Reg, _ := regexp.Compile(IPV4Pattern)
	for _, v := range list {
		if !ipv4Reg.Match(v) {
			panic("white list ip illegal")
		}
		m[string(v)] = true
	}
	return WhiteList{m}
}

func (w WhiteList) Pass(addr net.Addr) bool {
	var ip string
	var address = addr.String()
	for i := 0; i < len(address); i++ {
		if address[i] == ':' {
			ip = address[:i]
		}
	}
	isPass := w.Map[ip]
	if !isPass {
		log.Info("ip refuse:" + ip)
	} else {
		log.Info("ip accept:" + ip)
		aliveConns++
	}
	return isPass
}
