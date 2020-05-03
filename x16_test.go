package x11

import (
	"encoding/binary"
	"fmt"
	"testing"
)

func TestHash(t *testing.T) {
	b := []byte("helloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhelloworldhel")
	x17r := New()
	out := make([]byte, 32)
	x17r.Hash(b, out)
	for i := 0; i < 8; i++ {
		a := binary.LittleEndian.Uint32(out[i*4 : 4*(i+1)])
		fmt.Printf("%x", a)
	}
}
