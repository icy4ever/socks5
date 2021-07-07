# socks5 

**This source code only use for study. Don't use this do sth illegal.**



### Quick Start

#### Read white list ips in code

```go
package main

import (
   "net"
   "socks5"
)

func main() {
   serve := socks5.New(socks5.NoAuth{}, socks5.NewWhiteList([]net.IP{net.IP("127.0.0.1")}))
   if err := serve.ListenAndServe("tcp", ":1080"); err != nil {
      panic(err)
   }
}
```

#### Read white list ips from file

```go
package main

import (
	"bytes"
	"net"
	"os"
	"socks5"
)

func main() {
	content, err := os.ReadFile("./white_list")
	if err != nil {
		panic(err)
	}
	bs := bytes.Split(content, []byte("\n"))
	var ips []net.IP
	for _, v := range bs {
		ips = append(ips, v)
	}
	serve := socks5.New(socks5.NoAuth{}, socks5.NewWhiteList(ips))
	if err := serve.ListenAndServe("tcp", ":1080"); err != nil {
		panic(err)
	}
}
```
