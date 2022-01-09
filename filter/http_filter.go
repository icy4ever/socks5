package filter

import (
	log "github.com/sirupsen/logrus"
	"net"
	"net/http"
)

type HttpFilter struct {
	whiteList map[string]struct{}
	token     string
}

func NewHttpFilter(addr, token string) (*HttpFilter, error) {
	hf := &HttpFilter{whiteList: make(map[string]struct{}), token: token}
	go func() {
		if err := http.ListenAndServe(addr, hf); err != nil {
			panic(err)
		}
	}()
	return hf, nil
}

func (h *HttpFilter) Pass(addr net.Addr) bool {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		log.Error(err)
		return false
	}
	_, ok := h.whiteList[host]
	return ok
}

func (h *HttpFilter) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	if val := req.FormValue("token"); val != h.token {
		if _, err := resp.Write([]byte("token invalid")); err != nil {
			log.Error(err)
		}
		return
	}
	if _, ok := h.whiteList[req.RemoteAddr]; !ok {
		host, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			log.Error(err)
			return
		}
		h.whiteList[host] = struct{}{}
	}

	if _, err := resp.Write([]byte("ok")); err != nil {
		log.Error(err)
	}
}
