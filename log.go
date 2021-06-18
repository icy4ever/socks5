package socks5

import (
	log "github.com/sirupsen/logrus"
	"os"
	"runtime"
	"strconv"
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

var aliveConns int

func stats() {
	var t = time.NewTicker(5 * time.Second)
	var m runtime.MemStats
	for {
		select {
		case <-t.C:
			runtime.ReadMemStats(&m)
			log.WithFields(log.Fields{
				"total alloc": strconv.Itoa(int(m.TotalAlloc/(1024*1024))) + "m",
				"alloc":       strconv.Itoa(int(m.Alloc/(1024*1024))) + "m",
				"gc count":        m.NumGC,
				"alive conns":     aliveConns,
			}).Info()
		}
	}
}
