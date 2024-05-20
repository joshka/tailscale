//go:build !linux

package main

import (
	"errors"
	"io"
	"net"
	"time"
)

func getConnKernelTimestamp() (io.Closer, error) {
	return nil, errors.New("unimplemented")
}

func measureRTTKernel(conn io.Closer, dst *net.UDPAddr, req []byte) (resp []byte, rtt time.Duration, err error) {
	return nil, 0, errors.New("unimplemented")
}
