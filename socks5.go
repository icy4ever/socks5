package socks5

import (
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strconv"
)

type Server struct {
	Auth
}

func New(auth Auth) *Server {
	return &Server{
		auth,
	}
}

func (s *Server) ListenAndServe(network, address string) error {
	l, err := net.Listen(network, address)
	if err != nil {
		log.Printf("Net Listen Failed ! Error Happened : %s", err.Error())
		return err
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("Accept Conn Failed ! Error Happened : %s", err.Error())
			continue
		}
		go func() {
			if err := s.HandleConn(conn); err != nil {
				log.Println(err)
			}
		}()
	}
}

func (s *Server) HandleConn(conn net.Conn) error {
	// read the version number
	if err := s.checkVersion(conn); err != nil {
		return err
	}
	// read the num of auth methods
	var numOfAuth = make([]byte, 1)
	if _, err := conn.Read(numOfAuth); err != nil {
		return err
	}
	// read the auth methods
	var buf = make([]byte, numOfAuth[0])
	if _, err := io.ReadAtLeast(conn, buf, int(numOfAuth[0])); err != nil {
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

	// read the request
	if err := s.checkVersion(conn); err != nil {
		return err
	}
	// read the CMD
	var cmd = make([]byte, 1)
	if _, err := conn.Read(cmd); err != nil {
		return err
	}
	switch cmd[0] {
	// connect cmd
	case 1:
		// bind
	case 2:
		// udp
	case 3:
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
	log.Println(addressType)
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
	log.Println(string(address) + ":" + strconv.Itoa(int(port[0])*256+int(port[1])))
	bindConn, err := net.Dial("tcp", string(address)+":"+strconv.Itoa(int(port[0])*256+int(port[1])))
	if err != nil {
		log.Println(err)
		if _, err := conn.Write(append([]byte{5, 1, 0}, append(addressType, append(address, port...)...)...)); err != nil {
			return err
		}
		return err
	}
	if _, err := conn.Write(append([]byte{5, 0, 0}, append(addressType, append(address, port...)...)...)); err != nil {
		return err
	}
	for {
		req, err := ioutil.ReadAll(conn)
		if err != nil {
			log.Println(err)
			continue
		}
		if _, err := bindConn.Write(req); err != nil {
			log.Println(err)
		}
		resp, err := ioutil.ReadAll(bindConn)
		if err != nil {
			log.Println(err)
			continue
		}
		if _,err:=conn.Write(resp);err!=nil {
			log.Println(err)
		}
	}
	return nil
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
