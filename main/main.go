package main

import (
	"socks5"
)

func main()  {
	var server = socks5.New(socks5.NoAuth{})
	server.ListenAndServe("tcp",":1080")
}