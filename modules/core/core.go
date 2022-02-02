/*
   Copyright (c) 2022, Network Next, Inc. All rights reserved.

   This is open source software licensed under the BSD 3-Clause License.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:

	1. Redistributions of source code must retain the above copyright notice, this
	   list of conditions and the following disclaimer.

	2. Redistributions in binary form must reproduce the above copyright notice,
	   this list of conditions and the following disclaimer in the documentation
	   and/or other materials provided with the distribution.

	3. Neither the name of the copyright holder nor the names of its
	   contributors may be used to endorse or promote products derived from
	   this software without specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
	AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
	IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
	DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
	FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
	DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
	SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
	CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
	OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
	OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package core

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"math"
	"net"
	"os"
	"strconv"
	"time"
)

const MagicBytes = 8
const VersionBytes = 1
const ChonkleBytes = 15
const SessionIdBytes = 32
const GatewayIdBytes = 32
const ServerIdBytes = 32
const UserIdBytes = 32
const SequenceBytes = 8
const AckBytes = 8
const AckBitsBytes = 32
const PittleBytes = 2
const AddressBytes = 19
const PacketTypeBytes = 1
const FlagsBytes = 1

const PayloadPacket = byte(0)
const ChallengePacket = byte(1)

const PublicKeyBytes_Box = 32
const PrivateKeyBytes_Box = 32
const NonceBytes_Box = 24
const HMACBytes_Box = 16

const PrivateKeyBytes_SecretBox = 32
const NonceBytes_SecretBox = 24
const HMACBytes_SecretBox = 16

const PrefixBytes = VersionBytes + PacketTypeBytes + ChonkleBytes + EncryptedSessionTokenBytes + SequenceBytes
const HeaderBytes = SessionIdBytes + SequenceBytes + AckBytes + AckBitsBytes + GatewayIdBytes + ServerIdBytes + PacketTypeBytes + FlagsBytes
const PostfixBytes = HMACBytes_Box + PittleBytes

const MinPayloadBytes = 1000

const MinPacketSize = PrefixBytes + HeaderBytes + MinPayloadBytes + PostfixBytes

const Flags_ChallengeToken = (1 << 0)

const ChallengePacketBytes = PrefixBytes + NonceBytes_Box + EncryptedChallengeTokenBytes + SequenceBytes + GatewayIdBytes + PostfixBytes

const ConnectTokenExpireSeconds = 20
const SessionTokenExtensionSeconds = 10

const EnvelopeBytes = 8

const SessionTokenBytes = 8 + SessionIdBytes + UserIdBytes + EnvelopeBytes
const EncryptedSessionTokenBytes = NonceBytes_SecretBox + SessionTokenBytes + HMACBytes_SecretBox

const ConnectDataBytes = PublicKeyBytes_Box + PrivateKeyBytes_Box + AddressBytes + PublicKeyBytes_Box + EnvelopeBytes

const EthernetHeaderBytes = 18
const IPv4HeaderBytes = 18
const UDPHeaderBytes = 8

func Keygen_Box() ([]byte, []byte) {
	var publicKey [PublicKeyBytes_Box]byte
	var privateKey [PrivateKeyBytes_Box]byte
	C.crypto_box_keypair((*C.uchar)(&publicKey[0]),
		(*C.uchar)(&privateKey[0]))
	return publicKey[:], privateKey[:]
}

func Encrypt_Box(senderPrivateKey []byte, receiverPublicKey []byte, nonce []byte, buffer []byte, bytes int) int {
	C.crypto_box_easy((*C.uchar)(&buffer[0]),
		(*C.uchar)(&buffer[0]),
		C.ulonglong(bytes),
		(*C.uchar)(&nonce[0]),
		(*C.uchar)(&receiverPublicKey[0]),
		(*C.uchar)(&senderPrivateKey[0]))
	return bytes + HMACBytes_Box
}

func Decrypt_Box(senderPublicKey []byte, receiverPrivateKey []byte, nonce []byte, buffer []byte, bytes int) error {
	result := C.crypto_box_open_easy(
		(*C.uchar)(&buffer[0]),
		(*C.uchar)(&buffer[0]),
		C.ulonglong(bytes),
		(*C.uchar)(&nonce[0]),
		(*C.uchar)(&senderPublicKey[0]),
		(*C.uchar)(&receiverPrivateKey[0]))
	if result != 0 {
		return fmt.Errorf("failed to decrypt: result = %d", result)
	} else {
		return nil
	}
}

func Keygen_SecretBox() []byte {
	key := make([]byte, PrivateKeyBytes_SecretBox)
	C.crypto_secretbox_keygen((*C.uchar)(&key[0]))
	return key
}

func Encrypt_SecretBox(privateKey []byte, nonce []byte, buffer []byte, bytes int) int {
	C.crypto_secretbox_easy((*C.uchar)(&buffer[0]),
		(*C.uchar)(&buffer[0]),
		C.ulonglong(bytes),
		(*C.uchar)(&nonce[0]),
		(*C.uchar)(&privateKey[0]))
	return bytes + HMACBytes_SecretBox
}

func Decrypt_SecretBox(privateKey []byte, nonce []byte, buffer []byte, bytes int) error {
	result := C.crypto_secretbox_open_easy(
		(*C.uchar)(&buffer[0]),
		(*C.uchar)(&buffer[0]),
		C.ulonglong(bytes),
		(*C.uchar)(&nonce[0]),
		(*C.uchar)(&privateKey[0]))
	if result != 0 {
		return fmt.Errorf("failed to decrypt: result = %d", result)
	} else {
		return nil
	}
}

var debugLogs bool

func init() {
	value, ok := os.LookupEnv("UDPX_DEBUG_LOGS")
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

func Info(s string, params ...interface{}) {
	fmt.Printf(s+"\n", params...)
}

const (
	IPAddressNone = 0
	IPAddressIPv4 = 1
	IPAddressIPv6 = 2
	AddressSize   = 19
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

func WriteBool(data []byte, index *int, value bool) {
	if value {
		data[*index] = byte(1)
	} else {
		data[*index] = byte(0)
	}

	*index += 1
}

func WriteUint8(data []byte, index *int, value uint8) {
	data[*index] = byte(value)
	*index += 1
}

func WriteUint16(data []byte, index *int, value uint16) {
	binary.LittleEndian.PutUint16(data[*index:], value)
	*index += 2
}

func WriteUint32(data []byte, index *int, value uint32) {
	binary.LittleEndian.PutUint32(data[*index:], value)
	*index += 4
}

func WriteUint64(data []byte, index *int, value uint64) {
	binary.LittleEndian.PutUint64(data[*index:], value)
	*index += 8
}

func WriteFloat32(data []byte, index *int, value float32) {
	uintValue := math.Float32bits(value)
	WriteUint32(data, index, uintValue)
}

func WriteFloat64(data []byte, index *int, value float64) {
	uintValue := math.Float64bits(value)
	WriteUint64(data, index, uintValue)
}

func WriteString(data []byte, index *int, value string, maxStringLength uint32) {
	stringLength := uint32(len(value))
	if stringLength > maxStringLength {
		panic("string is too long!\n")
	}
	binary.LittleEndian.PutUint32(data[*index:], stringLength)
	*index += 4
	for i := 0; i < int(stringLength); i++ {
		data[*index] = value[i]
		*index++
	}
}

func WriteBytes(data []byte, index *int, value []byte, numBytes int) {
	for i := 0; i < numBytes; i++ {
		data[*index] = value[i]
		*index++
	}
}

func WriteAddress(buffer []byte, index *int, address *net.UDPAddr) {
	if address == nil {
		buffer[*index] = IPAddressNone
		*index += AddressBytes
		return
	}
	ipv4 := address.IP.To4()
	port := address.Port
	if ipv4 != nil {
		buffer[*index] = IPAddressIPv4
		buffer[*index+1] = ipv4[0]
		buffer[*index+2] = ipv4[1]
		buffer[*index+3] = ipv4[2]
		buffer[*index+4] = ipv4[3]
		buffer[*index+5] = (byte)(port & 0xFF)
		buffer[*index+6] = (byte)(port >> 8)
	} else {
		buffer[*index] = IPAddressIPv6
		copy(buffer[*index+1:], address.IP)
		buffer[*index+17] = (byte)(port & 0xFF)
		buffer[*index+18] = (byte)(port >> 8)
	}
	*index += AddressBytes
}

func ReadBool(data []byte, index *int, value *bool) bool {
	if *index+1 > len(data) {
		return false
	}

	if data[*index] > 0 {
		*value = true
	} else {
		*value = false
	}

	*index += 1
	return true
}

func ReadUint8(data []byte, index *int, value *uint8) bool {
	if *index+1 > len(data) {
		return false
	}
	*value = data[*index]
	*index += 1
	return true
}

func ReadUint16(data []byte, index *int, value *uint16) bool {
	if *index+2 > len(data) {
		return false
	}
	*value = binary.LittleEndian.Uint16(data[*index:])
	*index += 2
	return true
}

func ReadUint32(data []byte, index *int, value *uint32) bool {
	if *index+4 > len(data) {
		return false
	}
	*value = binary.LittleEndian.Uint32(data[*index:])
	*index += 4
	return true
}

func ReadUint64(data []byte, index *int, value *uint64) bool {
	if *index+8 > len(data) {
		return false
	}
	*value = binary.LittleEndian.Uint64(data[*index:])
	*index += 8
	return true
}

func ReadFloat32(data []byte, index *int, value *float32) bool {
	var intValue uint32
	if !ReadUint32(data, index, &intValue) {
		return false
	}
	*value = math.Float32frombits(intValue)
	return true
}

func ReadFloat64(data []byte, index *int, value *float64) bool {
	var uintValue uint64
	if !ReadUint64(data, index, &uintValue) {
		return false
	}
	*value = math.Float64frombits(uintValue)
	return true
}

func ReadString(data []byte, index *int, value *string, maxStringLength uint32) bool {
	var stringLength uint32
	if !ReadUint32(data, index, &stringLength) {
		return false
	}
	if stringLength > maxStringLength {
		return false
	}
	if *index+int(stringLength) > len(data) {
		return false
	}
	stringData := make([]byte, stringLength)
	for i := uint32(0); i < stringLength; i++ {
		stringData[i] = data[*index]
		*index++
	}
	*value = string(stringData)
	return true
}

func ReadBytes(data []byte, index *int, value []byte, bytes uint32) bool {
	if *index+int(bytes) > len(data) {
		return false
	}
	for i := uint32(0); i < bytes; i++ {
		value[i] = data[*index]
		*index++
	}
	return true
}

func ReadAddress(buffer []byte, index *int, address *net.UDPAddr) bool {
	addressType := buffer[*index]
	switch addressType {
	case IPAddressIPv4:
		*address = net.UDPAddr{IP: net.IPv4(buffer[*index+1], buffer[*index+2], buffer[*index+3], buffer[*index+4]), Port: ((int)(binary.LittleEndian.Uint16(buffer[*index+5:])))}
		break
	case IPAddressIPv6:
		*address = net.UDPAddr{IP: buffer[*index+1:], Port: ((int)(binary.LittleEndian.Uint16(buffer[*index+17:])))}
		break
	}
	*index += AddressBytes
	return true
}

func RandomBytes(bytes int) []byte {
	buffer := make([]byte, bytes)
	_, _ = rand.Read(buffer)
	return buffer
}

func RandomBytes_InPlace(buffer []byte) {
	_, _ = rand.Read(buffer)
}

func GeneratePittle(output []byte, fromAddress []byte, fromPort uint16, toAddress []byte, toPort uint16, packetLength int) {

	var fromPortData [2]byte
	binary.LittleEndian.PutUint16(fromPortData[:], fromPort)

	var toPortData [2]byte
	binary.LittleEndian.PutUint16(toPortData[:], toPort)

	var packetLengthData [4]byte
	binary.LittleEndian.PutUint32(packetLengthData[:], uint32(packetLength))

	sum := uint16(0)

	for i := 0; i < len(fromAddress); i++ {
		sum += uint16(fromAddress[i])
	}

	sum += uint16(fromPortData[0])
	sum += uint16(fromPortData[1])

	for i := 0; i < len(toAddress); i++ {
		sum += uint16(toAddress[i])
	}

	sum += uint16(toPortData[0])
	sum += uint16(toPortData[1])

	sum += uint16(packetLengthData[0])
	sum += uint16(packetLengthData[1])
	sum += uint16(packetLengthData[2])
	sum += uint16(packetLengthData[3])

	var sumData [2]byte
	binary.LittleEndian.PutUint16(sumData[:], sum)

	output[0] = 1 | (sumData[0] ^ sumData[1] ^ 193)
	output[1] = 1 | ((255 - output[0]) ^ 113)
}

func GenerateChonkle(output []byte, magic []byte, fromAddressData []byte, fromPort uint16, toAddressData []byte, toPort uint16, packetLength int) {

	var fromPortData [2]byte
	binary.LittleEndian.PutUint16(fromPortData[:], fromPort)

	var toPortData [2]byte
	binary.LittleEndian.PutUint16(toPortData[:], toPort)

	var packetLengthData [4]byte
	binary.LittleEndian.PutUint32(packetLengthData[:], uint32(packetLength))

	hash := fnv.New64a()
	hash.Write(magic)
	hash.Write(fromAddressData)
	hash.Write(fromPortData[:])
	hash.Write(toAddressData)
	hash.Write(toPortData[:])
	hash.Write(packetLengthData[:])
	hashValue := hash.Sum64()

	var data [8]byte
	binary.LittleEndian.PutUint64(data[:], uint64(hashValue))

	output[0] = ((data[6] & 0xC0) >> 6) + 42
	output[1] = (data[3] & 0x1F) + 200
	output[2] = ((data[2] & 0xFC) >> 2) + 5
	output[3] = data[0]
	output[4] = (data[2] & 0x03) + 78
	output[5] = (data[4] & 0x7F) + 96
	output[6] = ((data[1] & 0xFC) >> 2) + 100
	if (data[7] & 1) == 0 {
		output[7] = 79
	} else {
		output[7] = 7
	}
	if (data[4] & 0x80) == 0 {
		output[8] = 37
	} else {
		output[8] = 83
	}
	output[9] = (data[5] & 0x07) + 124
	output[10] = ((data[1] & 0xE0) >> 5) + 175
	output[11] = (data[6] & 0x3F) + 33
	value := (data[1] & 0x03)
	if value == 0 {
		output[12] = 97
	} else if value == 1 {
		output[12] = 5
	} else if value == 2 {
		output[12] = 43
	} else {
		output[12] = 13
	}
	output[13] = ((data[5] & 0xF8) >> 3) + 210
	output[14] = ((data[7] & 0xFE) >> 1) + 17
}

func BasicPacketFilter(packetData []byte, packetLength int) bool {

	data := packetData[2:]

	if data[0] < 0x2A || data[0] > 0x2D {
		return false
	}

	if data[1] < 0xC8 || data[1] > 0xE7 {
		return false
	}

	if data[2] < 0x05 || data[2] > 0x44 {
		return false
	}

	if data[4] < 0x4E || data[4] > 0x51 {
		return false
	}

	if data[5] < 0x60 || data[5] > 0xDF {
		return false
	}

	if data[6] < 0x64 || data[6] > 0xE3 {
		return false
	}

	if data[7] != 0x07 && data[7] != 0x4F {
		return false
	}

	if data[8] != 0x25 && data[8] != 0x53 {
		return false
	}

	if data[9] < 0x7C || data[9] > 0x83 {
		return false
	}

	if data[10] < 0xAF || data[10] > 0xB6 {
		return false
	}

	if data[11] < 0x21 || data[11] > 0x60 {
		return false
	}

	if data[12] != 0x61 && data[12] != 0x05 && data[12] != 0x2B && data[12] != 0x0D {
		return false
	}

	if data[13] < 0xD2 || data[13] > 0xF1 {
		return false
	}

	if data[14] < 0x11 || data[14] > 0x90 {
		return false
	}

	return true
}

func AdvancedPacketFilter(data []byte, magic []byte, fromAddress []byte, fromPort uint16, toAddress []byte, toPort uint16, packetLength int) bool {
	var a [15]byte
	var b [2]byte
	GenerateChonkle(a[:], magic, fromAddress, fromPort, toAddress, toPort, packetLength)
	GeneratePittle(b[:], fromAddress, fromPort, toAddress, toPort, packetLength)
	if bytes.Compare(a[0:15], data[2:17]) != 0 {
		return false
	}
	if bytes.Compare(b[0:2], data[packetLength-2:packetLength]) != 0 {
		return false
	}
	return true
}

func GetAddressData(address *net.UDPAddr, addressData []byte, addressPort *uint16) {
	// todo: ipv6 support
	addressData[0] = address.IP[0]
	addressData[1] = address.IP[1]
	addressData[2] = address.IP[2]
	addressData[3] = address.IP[3]
	*addressPort = uint16(address.Port)
}

func IdString(id []byte) string {
	string := ""
	for i := 0; i < len(id); i++ {
		string = string + fmt.Sprintf("%02x", id[i])
	}
	return string
}

func AddressEqual(a *net.UDPAddr, b *net.UDPAddr) bool {
	return net.IP.Equal(a.IP, b.IP) && a.Port == b.Port
}

func IdEqual(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type ChallengeToken struct {
	ExpireTimestamp uint64
	ClientAddress   net.UDPAddr
	GatewayAddress  net.UDPAddr
	Sequence        uint64
}

const ChallengeTokenBytes = 8 + AddressBytes + 8
const EncryptedChallengeTokenBytes = NonceBytes_SecretBox + ChallengeTokenBytes + HMACBytes_SecretBox

func WriteChallengeToken(buffer []byte, index *int, token *ChallengeToken) {
	WriteUint64(buffer, index, token.ExpireTimestamp)
	WriteAddress(buffer, index, &token.ClientAddress)
	WriteUint64(buffer, index, token.Sequence)
}

func ReadChallengeToken(buffer []byte, index *int, token *ChallengeToken) bool {
	if len(buffer)-*index < ChallengeTokenBytes {
		return false
	}
	ReadUint64(buffer, index, &token.ExpireTimestamp)
	ReadAddress(buffer, index, &token.ClientAddress)
	ReadUint64(buffer, index, &token.Sequence)
	return true
}

func WriteEncryptedChallengeToken(buffer []byte, index *int, token *ChallengeToken, privateKey []byte) {
	nonce := buffer[*index : *index+NonceBytes_SecretBox]
	RandomBytes_InPlace(nonce)
	*index += NonceBytes_SecretBox
	tokenData := buffer[*index : *index+ChallengeTokenBytes+HMACBytes_SecretBox]
	WriteChallengeToken(buffer, index, token)
	Encrypt_SecretBox(privateKey, nonce, tokenData, ChallengeTokenBytes)
	*index += HMACBytes_SecretBox
}

func ReadEncryptedChallengeToken(buffer []byte, index *int, token *ChallengeToken, privateKey []byte) bool {
	if len(buffer)-*index < EncryptedChallengeTokenBytes {
		return false
	}
	nonce := buffer[*index : *index+NonceBytes_SecretBox]
	*index += NonceBytes_SecretBox
	tokenData := buffer[*index : *index+ChallengeTokenBytes+HMACBytes_SecretBox]
	err := Decrypt_SecretBox(privateKey, nonce, tokenData, ChallengeTokenBytes+HMACBytes_SecretBox)
	if err != nil {
		return false
	}
	result := ReadChallengeToken(buffer, index, token)
	*index += HMACBytes_SecretBox
	return result
}

func GetAckBits(latestReceivedSequence uint64, receivedPackets []uint64, ack_bits []byte) {
	totalBits := uint64(len(ack_bits) * 8)
	ack := make([]byte, totalBits)
	bufferSize := uint64(len(receivedPackets))
	i := 0
	minSequence := latestReceivedSequence - totalBits
	for sequence := latestReceivedSequence; sequence > minSequence; sequence-- {
		if receivedPackets[sequence%bufferSize] == sequence {
			ack[i] = 1
		}
		i++
	}
	for i := uint64(0); i < totalBits; i++ {
		if ack[i] == 1 {
			byteIndex := i / 8
			bitIndex := i % 8
			ack_bits[byteIndex] |= (1 << bitIndex)
		}
	}
}

func ProcessAcks(ackSequence uint64, ack_bits []byte, ackedPackets []uint64, ackBuffer []uint64) []uint64 {
	totalBits := uint64(len(ack_bits) * 8)
	ack := make([]byte, totalBits)
	for i := uint64(0); i < totalBits; i++ {
		byteIndex := i / 8
		bitIndex := i % 8
		if (ack_bits[byteIndex] & (1 << bitIndex)) != 0 {
			ack[i] = 1
		}
	}
	bufferSize := uint64(len(ackedPackets))
	numAcks := 0
	for i := uint64(0); i < totalBits; i++ {
		sequence := ackSequence - i
		if ack[i] == 1 && ackedPackets[sequence%bufferSize] != sequence {
			ackBuffer[numAcks] = sequence
			numAcks++
		}
	}
	return ackBuffer[:numAcks]
}

type SessionToken struct {
	ExpireTimestamp  uint64
	SessionId        [SessionIdBytes]byte
	UserId           [UserIdBytes]byte
	EnvelopeUpKbps   uint32
	EnvelopeDownKbps uint32
}

func WriteSessionToken(buffer []byte, index *int, token *SessionToken) {
	WriteUint64(buffer, index, token.ExpireTimestamp)
	WriteBytes(buffer, index, token.SessionId[:], SessionIdBytes)
	WriteBytes(buffer, index, token.UserId[:], UserIdBytes)
	WriteUint32(buffer, index, token.EnvelopeUpKbps)
	WriteUint32(buffer, index, token.EnvelopeDownKbps)
}

func ReadSessionToken(buffer []byte, index *int, token *SessionToken) bool {
	if len(buffer)-*index < SessionTokenBytes {
		return false
	}
	ReadUint64(buffer, index, &token.ExpireTimestamp)
	ReadBytes(buffer, index, token.SessionId[:], SessionIdBytes)
	ReadBytes(buffer, index, token.UserId[:], UserIdBytes)
	ReadUint32(buffer, index, &token.EnvelopeUpKbps)
	ReadUint32(buffer, index, &token.EnvelopeDownKbps)
	return true
}

func WriteEncryptedSessionToken(buffer []byte, index *int, token *SessionToken, senderPrivateKey []byte, receiverPublicKey []byte) {
	nonce := buffer[*index : *index+NonceBytes_Box]
	RandomBytes_InPlace(nonce)
	*index += NonceBytes_Box
	tokenData := buffer[*index : *index+SessionTokenBytes+HMACBytes_Box]
	WriteSessionToken(buffer, index, token)
	Encrypt_Box(senderPrivateKey, receiverPublicKey, nonce, tokenData, SessionTokenBytes)
	*index += HMACBytes_Box
}

func ReadEncryptedSessionToken(buffer []byte, index *int, token *SessionToken, senderPublicKey []byte, receiverPrivateKey []byte) bool {
	if len(buffer)-*index < EncryptedSessionTokenBytes {
		return false
	}
	nonce := buffer[*index : *index+NonceBytes_Box]
	*index += NonceBytes_Box
	tokenData := buffer[*index : *index+SessionTokenBytes+HMACBytes_Box]
	err := Decrypt_Box(senderPublicKey, receiverPrivateKey, nonce, tokenData, SessionTokenBytes+HMACBytes_Box)
	if err != nil {
		return false
	}
	result := ReadSessionToken(buffer, index, token)
	*index += HMACBytes_Box
	return result
}

type ConnectData struct {
	ClientPublicKey  [PublicKeyBytes_Box]byte
	ClientPrivateKey [PrivateKeyBytes_Box]byte
	GatewayAddress   net.UDPAddr
	GatewayPublicKey [PublicKeyBytes_Box]byte
	EnvelopeUpKbps   uint32
	EnvelopeDownKbps uint32
}

func WriteConnectData(buffer []byte, index *int, connectData *ConnectData) {
	WriteBytes(buffer, index, connectData.ClientPublicKey[:], PublicKeyBytes_Box)
	WriteBytes(buffer, index, connectData.ClientPrivateKey[:], PrivateKeyBytes_Box)
	WriteAddress(buffer, index, &connectData.GatewayAddress)
	WriteBytes(buffer, index, connectData.GatewayPublicKey[:], UserIdBytes)
	WriteUint32(buffer, index, connectData.EnvelopeUpKbps)
	WriteUint32(buffer, index, connectData.EnvelopeDownKbps)
}

func ReadConnectData(buffer []byte, index *int, connectData *ConnectData) bool {
	if len(buffer)-*index < ConnectDataBytes {
		return false
	}
	ReadBytes(buffer, index, connectData.ClientPublicKey[:], PublicKeyBytes_Box)
	ReadBytes(buffer, index, connectData.ClientPrivateKey[:], PrivateKeyBytes_Box)
	ReadAddress(buffer, index, &connectData.GatewayAddress)
	ReadBytes(buffer, index, connectData.GatewayPublicKey[:], PublicKeyBytes_Box)
	ReadUint32(buffer, index, &connectData.EnvelopeUpKbps)
	ReadUint32(buffer, index, &connectData.EnvelopeDownKbps)
	return true
}

const ConnectTokenBytes = ConnectDataBytes + EncryptedSessionTokenBytes

func GenerateConnectToken(userId []byte, envelopeUpKbps uint32, envelopeDownKbps uint32, gatewayAddress *net.UDPAddr, gatewayPublicKey []byte, senderPrivateKey []byte, receiverPublicKey []byte) []byte {

	publicKey, privateKey := Keygen_Box()

	connectData := ConnectData{}
	copy(connectData.ClientPublicKey[:], publicKey[:])
	copy(connectData.ClientPrivateKey[:], privateKey[:])
	connectData.GatewayAddress = *gatewayAddress
	copy(connectData.GatewayPublicKey[:], gatewayPublicKey[:])
	connectData.EnvelopeUpKbps = envelopeUpKbps
	connectData.EnvelopeDownKbps = envelopeDownKbps

	sessionToken := SessionToken{}
	sessionToken.ExpireTimestamp = uint64(time.Now().Unix()) + ConnectTokenExpireSeconds
	copy(sessionToken.SessionId[:], connectData.ClientPublicKey[:])
	copy(sessionToken.UserId[:], userId[:])
	sessionToken.EnvelopeUpKbps = envelopeUpKbps
	sessionToken.EnvelopeDownKbps = envelopeDownKbps

	buffer := make([]byte, ConnectDataBytes+EncryptedSessionTokenBytes)

	index := 0

	WriteConnectData(buffer, &index, &connectData)

	WriteEncryptedSessionToken(buffer, &index, &sessionToken, senderPrivateKey, receiverPublicKey)

	return buffer
}

func WirePacketBits(packetBytes int) int {
	return (EthernetHeaderBytes + IPv4HeaderBytes + UDPHeaderBytes + packetBytes) * 8
}

func PacketBytesFromPayload(payloadBytes int) int {
	if payloadBytes < MinPayloadBytes {
		payloadBytes = MinPayloadBytes
	}
	return payloadBytes + PrefixBytes + HeaderBytes + PostfixBytes
}
