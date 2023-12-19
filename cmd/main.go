package main

import (
	"socks5"
	_ "net/http/pprof"
)

func main() {
	serv, err := socks5.NewServer(&socks5.Config{
		Port: 11080,
		Auth: socks5.NoAuth,
	})
	if err != nil {
		panic(err)
	}

	if err := serv.Start(); err != nil {
		panic(err)
	}
}
