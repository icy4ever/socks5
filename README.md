# socks5

**This source code only use for study. Don't use this do sth illegal.**



### Quick Start

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