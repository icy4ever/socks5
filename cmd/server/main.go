package main

import (
	"fmt"
	"socks5/filter"
	"socks5/server"
	"socks5/uid"
)

func main() {
	token := uid.NewID().String()
	fmt.Println(fmt.Sprintf("your key is : %s", token))
	httpFilter, err := filter.NewHttpFilter(":80", token)
	if err != nil {
		panic(err)
	}
	serve := server.New(server.NoAuth{}, httpFilter)
	if err := serve.ListenAndServe("tcp", ":1080"); err != nil {
		panic(err)
	}
}
