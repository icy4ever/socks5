package log

import (
	log "github.com/sirupsen/logrus"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"
)

func init() {
	// Log as JSON instead of the default ASCII formatter.
	log.SetFormatter(&log.JSONFormatter{})

	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example
	log.SetOutput(os.Stdout)

	// Only log the warning severity or above.
	log.SetLevel(log.InfoLevel)

	go stats()
}

var AliveConns int32

func stats() {
	var t = time.NewTicker(10 * time.Second)
	var m runtime.MemStats
	for {
		select {
		case <-t.C:
			ac := atomic.LoadInt32(&AliveConns)
			runtime.ReadMemStats(&m)
			log.WithFields(log.Fields{
				"total alloc": strconv.Itoa(int(m.TotalAlloc/(1024*1024))) + "m",
				"alloc":       strconv.Itoa(int(m.Alloc/(1024*1024))) + "m",
				"gc count":    m.NumGC,
				"alive conns": ac,
			}).Info()
		}
	}
}
