package uid

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"
)

// ID combine from 4 digit timestamp, 3 digit rand,2 digit pid and 3 digit number(which is auto increment in process)
type ID [12]byte

var objectIDCounter = readRandomUint32()
var processUnique = processUniqueBytes()

// New new an id, this func is almost same as primitive.NewObjectId().
func NewID() ID {
	var b [12]byte

	binary.BigEndian.PutUint32(b[0:4], uint32(time.Now().Unix()))
	copy(b[4:9], processUnique[:])
	putUint24(b[9:12], atomic.AddUint32(&objectIDCounter, 1))
	return b
}

func readRandomUint32() uint32 {
	var b [4]byte
	_, err := io.ReadFull(rand.Reader, b[:])
	if err != nil {
		panic(fmt.Errorf("cannot initialize commit package with crypto.rand.Reader: %v", err))
	}

	return (uint32(b[0]) << 0) | (uint32(b[1]) << 8) | (uint32(b[2]) << 16) | (uint32(b[3]) << 24)
}

func processUniqueBytes() [5]byte {
	var b [5]byte
	_, err := io.ReadFull(rand.Reader, b[0:3])
	if err != nil {
		panic(fmt.Errorf("cannot initialize commit package with crypto.rand.Reader: %v", err))
	}
	var p = os.Getpid()
	b[3] = byte(p >> 8)
	b[4] = byte(p)

	return b
}

func putUint24(b []byte, v uint32) {
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
}

func (id ID) String() string {
	return fmt.Sprintf(`%s`, hex.EncodeToString(id[:]))
}