package server

import (
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"io"
	"math/rand"
	"net"
	"socks5/filter"
	log2 "socks5/log"
	"strconv"
	"sync/atomic"
	"time"
)

type Server struct {
	Auth
	filter.Filter
}

func init() {
	rand.Seed(time.Now().Unix())
}

func New(auth Auth, filter filter.Filter) *Server {
	return &Server{
		auth,
		filter,
	}
}

func (s *Server) ListenAndServe(network, address string) error {
	l, err := net.Listen(network, address)
	if err != nil {
		log.Error(err)
		return err
	}
	log.Info("server start")
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Error(err)
			continue
		}
		if !s.Pass(conn.RemoteAddr()) {
			_ = conn.Close()
			continue
		}
		go func() {
			atomic.AddInt32(&log2.AliveConns, 1)
			defer func() {
				if err := conn.Close(); err != nil {
					log.Error(err)
				}
				atomic.AddInt32(&log2.AliveConns, -1)
			}()
			if err := s.HandleConn(conn); err != nil {
				log.Error(err)
			}
		}()
	}
}

func (s *Server) HandleConn(conn net.Conn) error {
	// read the version number
	if err := s.checkVersion(conn); err != nil {
		return err
	}
	// read the auth methods
	buf, err := s.read(conn)
	if err != nil {
		return err
	}
	var has bool
	for _, v := range buf {
		if int(v) == s.Auth.GetCode() {
			has = true
		}
	}
	if !has {
		return errors.New("client dont support method specified")
	}
	if _, err := conn.Write([]byte{5, byte(s.Auth.GetCode())}); err != nil {
		return err
	}
	switch buf[0] {
	case 2:
		// SubNegotiation Version : abandon
		var subNeg = make([]byte, 1)
		if _, err := conn.Read(subNeg); err != nil {
			return err
		}
		name, err := s.read(conn)
		if err != nil {
			return err
		}
		pwd, err := s.read(conn)
		if err != nil {
			return err
		}
		if !s.Auth.Verify(string(name), string(pwd)) {
			if _, err := conn.Write(append(subNeg, 1)); err != nil {
				return err
			}
			return errors.New(fmt.Sprintf("auth failed, username: %s password: %s", string(name), string(pwd)))
		}
		if _, err := conn.Write(append(subNeg, 0)); err != nil {
			return err
		}
	}

	// read the request
	if err := s.checkVersion(conn); err != nil {
		return err
	}
	// read the CMD
	var cmd = make([]byte, 1)
	if _, err := conn.Read(cmd); err != nil {
		return err
	}
	// todo: handle bind and udp
	switch cmd[0] {
	case 1: // connect cmd
	case 2: // bind
	case 3: // udp
	}
	// read the rsv
	var rsv = make([]byte, 1)
	if _, err := conn.Read(rsv); err != nil {
		return err
	}
	// read the address type
	var addressType = make([]byte, 1)
	if _, err := conn.Read(addressType); err != nil {
		return err
	}
	var addressLen = make([]byte, 1)
	if _, err := conn.Read(addressLen); err != nil {
		return err
	}
	var address = make([]byte, addressLen[0])
	if _, err := conn.Read(address); err != nil {
		return err
	}
	var port = make([]byte, 2)
	if _, err := conn.Read(port); err != nil {
		return err
	}
	var addressInfo []byte
	switch addressType[0] {
	case 1: // ipv4
	case 3: // unix / socket
	case 4: // ipv6
	}
	addressInfo = make([]byte, 0, 4+addressLen[0])
	for _, v := range [][]byte{addressType, addressLen, address, port} {
		for _, val := range v {
			addressInfo = append(addressInfo, val)
		}
	}
	bindConn, err := net.Dial("tcp", string(address)+":"+strconv.Itoa(int(port[0])*256+int(port[1])))
	if err != nil {
		if _, err := conn.Write(append([]byte{5, 1, 0}, addressInfo...)); err != nil {
			return err
		}
		return err
	}
	if _, err := conn.Write(append([]byte{5, 0, 0}, addressInfo...)); err != nil {
		return err
	}
	var errg errgroup.Group
	errg.Go(func() error {
		if _, err := io.Copy(bindConn, conn); err != nil {
			log.Error(err)
			return err
		}
		return nil
	})
	errg.Go(func() error {
		if _, err := io.Copy(conn, bindConn); err != nil {
			log.Error(err)
			return err
		}
		return nil
	})
	return errg.Wait()
}

func (s *Server) checkVersion(conn net.Conn) error {
	var version = make([]byte, 1)
	if _, err := conn.Read(version); err != nil {
		return err
	} else if version[0] != 5 {
		return errors.New("version not supported")
	}
	return nil
}

func (s *Server) read(conn net.Conn) ([]byte, error) {
	var l = make([]byte, 1)
	if _, err := conn.Read(l); err != nil {
		return nil, err
	}
	var str = make([]byte, l[0])
	if _, err := io.ReadAtLeast(conn, str, int(l[0])); err != nil {
		return nil, err
	}
	return str, nil
}
