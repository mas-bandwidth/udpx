package core

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
)

var debugLogs bool

func init() {
	value, ok := os.LookupEnv("NEXT_DEBUG_LOGS")
	if ok && value == "1" {
		debugLogs = true
	}
}

func Error(s string, params ...interface{}) {
	fmt.Printf("error: "+s+"\n", params...)
}

func Debug(s string, params ...interface{}) {
	if debugLogs {
		fmt.Printf(s+"\n", params...)
	}
}

const (
	IPAddressNone = 0
	IPAddressIPv4 = 1
	IPAddressIPv6 = 2
)

func ParseAddress(input string) *net.UDPAddr {
	address := &net.UDPAddr{}
	ip_string, port_string, err := net.SplitHostPort(input)
	if err != nil {
		address.IP = net.ParseIP(input)
		address.Port = 0
		return address
	}
	address.IP = net.ParseIP(ip_string)
	address.Port, _ = strconv.Atoi(port_string)
	return address
}

const (
	ADDRESS_NONE = 0
	ADDRESS_IPV4 = 1
	ADDRESS_IPV6 = 2
)

func WriteAddress(buffer []byte, address *net.UDPAddr) {
	if address == nil {
		buffer[0] = ADDRESS_NONE
		return
	}
	ipv4 := address.IP.To4()
	port := address.Port
	if ipv4 != nil {
		buffer[0] = ADDRESS_IPV4
		buffer[1] = ipv4[0]
		buffer[2] = ipv4[1]
		buffer[3] = ipv4[2]
		buffer[4] = ipv4[3]
		buffer[5] = (byte)(port & 0xFF)
		buffer[6] = (byte)(port >> 8)
	} else {
		buffer[0] = ADDRESS_IPV6
		copy(buffer[1:], address.IP)
		buffer[17] = (byte)(port & 0xFF)
		buffer[18] = (byte)(port >> 8)
	}
}

func ReadAddress(buffer []byte) *net.UDPAddr {
	addressType := buffer[0]
	if addressType == ADDRESS_IPV4 {
		return &net.UDPAddr{IP: net.IPv4(buffer[1], buffer[2], buffer[3], buffer[4]), Port: ((int)(binary.LittleEndian.Uint16(buffer[5:])))}
	} else if addressType == ADDRESS_IPV6 {
		return &net.UDPAddr{IP: buffer[1:17], Port: ((int)(binary.LittleEndian.Uint16(buffer[17:19])))}
	}
	return nil
}
