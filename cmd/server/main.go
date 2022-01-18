package main

import (
	"flag"
	"socks5/filter"
	"socks5/server"
)

var (
	name     = flag.String("user_name", "socks5", "socks5 proxy username")
	password = flag.String("password", "20220101", "socks5 proxy password")
)

func main() {
	serve := server.New(server.BasicAuth{
		Username: *name,
		Password: *password,
	}, filter.NoFilter{})
	if err := serve.ListenAndServe("tcp", ":1080"); err != nil {
		panic(err)
	}
}
