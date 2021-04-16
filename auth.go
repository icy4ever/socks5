package socks5

type Auth interface {
	Verify(...interface{}) bool
	GetCode() int
}
