package socks5

type NoAuth struct {}

func (n NoAuth) Verify(...interface{}) bool {
	return true
}

func (n NoAuth) GetCode() int {
	return 0
}
