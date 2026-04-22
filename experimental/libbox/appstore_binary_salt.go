package potokcore

import (
	"math/bits"
	"runtime"
)

var appStoreBuildSalt = "veilify-libbox-static-salt"
var appStoreBinaryFingerprint uint64

func init() {
	appStoreBinaryFingerprint = appStoreBinaryMix(appStoreBuildSalt, 0x8f3d7c2a4b91605e)
	runtime.KeepAlive(appStoreBinaryFingerprint)
}

//go:noinline
func appStoreBinaryMix(salt string, state uint64) uint64 {
	for index, value := range []byte(salt) {
		state ^= uint64(value) + uint64(index)*0x9e3779b185ebca87
		state = bits.RotateLeft64(state, int(value&31)+1)
		state *= 0xc2b2ae3d27d4eb4f
	}
	if state == 0 {
		return 0x4d7a1217f82f3b65
	}
	return state
}
