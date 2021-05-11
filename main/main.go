package main

import (
	"fmt"
	"socks5"
)

func main() {
	var m = make(map[int]int,1)
	fmt.Println(len(m))
	var server = socks5.New(socks5.NoAuth{}, socks5.NoFilter{})
	server.ListenAndServe("tcp", ":1080")
}
