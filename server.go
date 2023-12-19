package socks5

import (
	"net"
	"fmt"
	log "github.com/sirupsen/logrus"

	"io"
	"errors"
	"strings"
	"context"
	"strconv"
)

type Config struct {
	Port     int
	Auth     AuthMethod
	Username string
	Password string
}

func NewServer(cfg *Config) (*Server, error) {
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Port))
	if err != nil {
		log.Error("%v", err)
		return nil, err
	}

	return &Server{listener: l, cfg: cfg}, nil
}

type Server struct {
	listener net.Listener
	cfg      *Config
}

func (s *Server) Start() error {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			if err := s.handleConn(conn); err != nil {
				log.Error("%v", err)
			}
		}()
	}
}

func (s *Server) handleConn(conn net.Conn) error {
	defer conn.Close()
	// Auth
	authBs := make([]byte, 2)
	if _, err := io.ReadFull(conn, authBs); err != nil {
		return err
	}

	version, methodCnt := authBs[0], authBs[1]
	if version != 0x5 {
		return VersionNotSupportErr
	}

	methods := make([]byte, methodCnt)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	for _, method := range methods {
		if method == byte(s.cfg.Auth) {
			goto authMethodSupport
		}
	}
	return NoAuthMethodSupportErr

authMethodSupport:
	switch s.cfg.Auth {
	case NoAuth:
		if _, err := conn.Write([]byte{0x5, 0x0}); err != nil {
			return err
		}
	case UserNamePasswordAuth:
		if _, err := conn.Write([]byte{0x5, 0x2}); err != nil {
			return err
		}

		versionAndUsernameLenBs := make([]byte, 2)
		if _, err := io.ReadFull(conn, versionAndUsernameLenBs); err != nil {
			return err
		}

		version, usernameLen := versionAndUsernameLenBs[0], versionAndUsernameLenBs[1]
		if version != 0x5 {
			return VersionNotSupportErr
		}

		username := make([]byte, usernameLen)
		if _, err := io.ReadFull(conn, username); err != nil {
			return err
		}

		pwdLenBs := make([]byte, 1)
		if _, err := io.ReadFull(conn, pwdLenBs); err != nil {
			return err
		}

		pwdLen := pwdLenBs[0]
		pwd := make([]byte, pwdLen)
		if _, err := io.ReadFull(conn, pwd); err != nil {
			return err
		}

		if s.cfg.Username != string(username) || s.cfg.Password != string(pwd) {
			if _, err := conn.Write([]byte{0x1, 0x1}); err != nil {
				return err
			}
			return UsernamePasswordIncorrectErr
		}

		if _, err := conn.Write([]byte{0x1, 0x0}); err != nil {
			return err
		}
	}

	addrTypeBs := make([]byte, 4)
	if _, err := io.ReadFull(conn, addrTypeBs); err != nil {
		return err
	}

	version, cmd, _, addrType := addrTypeBs[0], addrTypeBs[1], addrTypeBs[2], addrTypeBs[3]
	if version != 0x5 {
		return VersionNotSupportErr
	}

	if cmd != 1 {
		return CommandNotSupportErr
	}

	var addr string
	addrAllBs := append([]byte{}, addrType)
	switch AddressType(addrType) {
	case IPv4Addr:
		addrBs := make([]byte, 4)
		if _, err := io.ReadFull(conn, addrBs); err != nil {
			return err
		}
		addr = net.IP(addrBs).String()
		addrAllBs = append(addrAllBs, addrBs...)
	case IPv6Addr:
		addrBs := make([]byte, 16)
		if _, err := io.ReadFull(conn, addrBs); err != nil {
			return err
		}
		addr = net.IP(addrBs).String()
		addrAllBs = append(addrAllBs, addrBs...)
	case DomainAddr:
		addrLenBs := make([]byte, 1)
		if _, err := io.ReadFull(conn, addrLenBs); err != nil {
			return err
		}

		addrLen := addrLenBs[0]
		addrBs := make([]byte, addrLen)
		if _, err := io.ReadFull(conn, addrBs); err != nil {
			return err
		}
		addr = string(addrBs)
		addrAllBs = append(append(addrAllBs, addrLen), addrBs...)
	default:
		return AddrTypeNotSupportErr
	}

	portBs := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBs); err != nil {
		return err
	}

	servConn, err := net.Dial("tcp", strings.Join([]string{addr,
		strconv.Itoa(int(portBs[0])*(1<<8) + int(portBs[1]))}, ":"))
	if err != nil {
		return err
	}
	defer servConn.Close()

	if _, err := conn.Write(append([]byte{0x5, 0x0, 0x0}, append(addrAllBs, portBs...)...)); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_, _ = io.Copy(servConn, conn)
		cancel()
	}()

	go func() {
		_, _ = io.Copy(conn, servConn)
		cancel()
	}()

	<-ctx.Done()
	return nil
}

var (
	VersionNotSupportErr         = errors.New("version not support")
	NoAuthMethodSupportErr       = errors.New("no auth method support")
	UsernamePasswordIncorrectErr = errors.New("username or password incorrect")
	CommandNotSupportErr         = errors.New("command not support")
	AddrTypeNotSupportErr        = errors.New("addr type not support")
)

type AuthMethod byte

const (
	NoAuth               AuthMethod = 0x0
	UserNamePasswordAuth AuthMethod = 0x2
)

type AddressType byte

const (
	IPv4Addr   AddressType = 0x1
	DomainAddr AddressType = 0x3
	IPv6Addr   AddressType = 0x4
)
