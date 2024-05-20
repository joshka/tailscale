package main

import (
	"errors"
	"net"
	"time"

	"github.com/mdlayher/socket"
	"golang.org/x/sys/unix"
)

const (
	flags = unix.SOF_TIMESTAMPING_TX_SOFTWARE | unix.SOF_TIMESTAMPING_RX_SOFTWARE
)

func getConnKernelTimestamp() (*socket.Conn, error) {
	sconn, err := socket.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP, "udp", nil)
	if err != nil {
		return nil, err
	}
	sa := unix.SockaddrInet4{}
	err = sconn.Bind(&sa)
	if err != nil {
		return nil, err
	}
	err = sconn.SetsockoptInt(unix.SOL_SOCKET, unix.SO_TIMESTAMPING, flags)
	if err != nil {
		return nil, err
	}
	return sconn, nil
}

func measureRTTKernel(conn *socket.Conn, dst *net.UDPAddr, req []byte) (resp []byte, rtt time.Duration, err error) {
	return nil, 0, errors.New("todo")
}
