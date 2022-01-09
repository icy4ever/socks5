package filter

import (
	"io/ioutil"
	"net/http"
	"socks5/uid"
	"testing"
)

func TestHttpFilter_ServeHTTP(t *testing.T) {
	token := uid.NewID().String()
	hf, err := NewHttpFilter(":80", token)
	if err != nil {
		t.Error(err)
	}
	resp, err := http.Get("http://127.0.0.1?token=" + token)
	if err != nil {
		t.Error(err)
	}
	bs, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	} else if string(bs) != "ok" {
		t.Error(err)
	}
	if !hf.Pass(TAddr{}) {
		t.Error("filter is not work correctly")
	}
}

type TAddr struct{}

func (t TAddr) String() string {
	return "127.0.0.1"
}
func (t TAddr) Network() string {
	return "tcp"
}
