//go:build !windows

package potokcore

import "syscall"

func dup(fd int) (nfd int, err error) {
	return syscall.Dup(fd)
}
