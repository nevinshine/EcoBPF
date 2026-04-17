package collector

import (
	"encoding/binary"
	"unsafe"
)

// nativeEndian is the byte order of the host machine.
// BPF ring buffer records use native endianness.
var nativeEndian binary.ByteOrder

func init() {
	// Detect native byte order at startup
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = 0x0102
	if buf[0] == 0x01 {
		nativeEndian = binary.BigEndian
	} else {
		nativeEndian = binary.LittleEndian
	}
}
