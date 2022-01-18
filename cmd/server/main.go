package main

import (
	"socks5/filter"
	"socks5/server"
)

func main() {
	flt, err := filter.NewHttpFilter(":80", "icy4ever")
	if err != nil {
		panic(err)
	}
	serve := server.New(server.NoAuth{}, flt)
	if err := serve.ListenAndServe("tcp", ":1080"); err != nil {
		panic(err)
	}
}
