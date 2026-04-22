//go:build !(darwin || linux)

package potokcore

import "os"

func getTunnelName(fd int32) (string, error) {
	return "", os.ErrInvalid
}
