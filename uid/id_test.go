package uid

import (
	"sync"
	"testing"
)

func BenchmarkID_String(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewID()
	}
}

func TestNew(t *testing.T) {
	var cnt = 1000000
	var res = sync.Map{}
	var wg sync.WaitGroup
	wg.Add(cnt)
	for i := 0; i < cnt; i++ {
		go func() {
			if _, ok := res.Load(NewID().String()); ok {
				t.Error("this func is not safe in parallel calling")
			}
			wg.Done()
		}()
	}
	wg.Wait()
}

func TestNewLen(t *testing.T) {
	var cnt = 100
	for i := 0; i < cnt; i++ {
		var id = NewID()
		if len(id.String()) != 24 {
			t.Errorf("len err, %v", id.String())
		}
	}
}
