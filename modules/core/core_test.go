/*
	UDPX

	Copyright (c) 2023 - 2024, Mas Bandwidth LLC, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package core

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"os"
	"testing"
	"time"
)

func FuckOffGolang() {
	fmt.Fprintf(os.Stdout, "I'm sick of adding and removing the fmt and os imports as I work")
}

func randomBytes(buffer []byte) {
	for i := 0; i < len(buffer); i++ {
		buffer[i] = byte(rand.Intn(256))
	}
}

func TestPittle(t *testing.T) {

	t.Parallel()

	rand.Seed(42)
	var output [256]byte
	for i := 0; i < 10000; i++ {
		var fromAddress [4]byte
		var toAddress [4]byte
		randomBytes(fromAddress[:])
		randomBytes(toAddress[:])
		fromPort := uint16(i + 1000000)
		toPort := uint16(i + 5000)
		packetLength := 1 + (i % 1500)
		GeneratePittle(output[:], fromAddress[:], fromPort, toAddress[:], toPort, packetLength)
		assert.NotEqual(t, output[0], 0)
		assert.NotEqual(t, output[1], 0)
	}
}

func TestChonkle(t *testing.T) {

	t.Parallel()

	rand.Seed(42)
	var output [1500]byte
	output[0] = 1
	for i := 0; i < 10000; i++ {
		var magic [8]byte
		var fromAddress [4]byte
		var toAddress [4]byte
		randomBytes(magic[:])
		randomBytes(fromAddress[:])
		randomBytes(toAddress[:])
		fromPort := uint16(i + 1000000)
		toPort := uint16(i + 5000)
		packetLength := 18 + (i % (len(output) - 18))
		GenerateChonkle(output[2:], magic[:], fromAddress[:], fromPort, toAddress[:], toPort, packetLength)
		assert.Equal(t, true, BasicPacketFilter(output[:], packetLength))
	}
}

func TestABI(t *testing.T) {

	t.Parallel()

	var output [1024]byte

	magic := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	fromAddress := [4]byte{1, 2, 3, 4}
	toAddress := [4]byte{4, 3, 2, 1}
	fromPort := uint16(1000)
	toPort := uint16(5000)
	packetLength := 1000

	GeneratePittle(output[:], fromAddress[:], fromPort, toAddress[:], toPort, packetLength)

	assert.Equal(t, output[0], uint8(71))
	assert.Equal(t, output[1], uint8(201))

	GenerateChonkle(output[:], magic[:], fromAddress[:], fromPort, toAddress[:], toPort, packetLength)

	assert.Equal(t, output[0], uint8(45))
	assert.Equal(t, output[1], uint8(203))
	assert.Equal(t, output[2], uint8(67))
	assert.Equal(t, output[3], uint8(96))
	assert.Equal(t, output[4], uint8(78))
	assert.Equal(t, output[5], uint8(180))
	assert.Equal(t, output[6], uint8(127))
	assert.Equal(t, output[7], uint8(7))
}

func TestPittleAndChonkle(t *testing.T) {

	t.Parallel()
	extra := VersionBytes + PacketTypeBytes + ChonkleBytes + PittleBytes
	rand.Seed(42)
	var output [1500]byte
	for i := 0; i < 10000; i++ {
		var magic [8]byte
		var fromAddress [4]byte
		var toAddress [4]byte
		randomBytes(magic[:])
		randomBytes(fromAddress[:])
		randomBytes(toAddress[:])
		fromPort := uint16(i + 1000000)
		toPort := uint16(i + 5000)
		packetLength := extra + (i % (len(output) - extra))
		GenerateChonkle(output[VersionBytes+PacketTypeBytes:], magic[:], fromAddress[:], fromPort, toAddress[:], toPort, packetLength)
		GeneratePittle(output[packetLength-PittleBytes:], fromAddress[:], fromPort, toAddress[:], toPort, packetLength)
		assert.Equal(t, true, BasicPacketFilter(output[:], packetLength))
		assert.Equal(t, true, AdvancedPacketFilter(output[:], magic[:], fromAddress[:], fromPort, toAddress[:], toPort, packetLength))
	}
}

func TestBasicPacketFilter(t *testing.T) {

	t.Parallel()

	rand.Seed(42)
	var output [256]byte
	iterations := 10000
	for i := 0; i < iterations; i++ {
		randomBytes(output[:])
		packetLength := i % len(output)
		assert.Equal(t, false, BasicPacketFilter(output[:], packetLength))
	}
}

func TestAdvancedPacketFilter(t *testing.T) {

	t.Parallel()

	rand.Seed(42)
	var output [1500]byte
	iterations := 10000
	for i := 0; i < iterations; i++ {
		var magic [8]byte
		var fromAddress [4]byte
		var toAddress [4]byte
		randomBytes(magic[:])
		randomBytes(fromAddress[:])
		randomBytes(toAddress[:])
		fromPort := uint16(i + 1000000)
		toPort := uint16(i + 5000)
		randomBytes(output[:])
		packetLength := i % len(output)
		assert.Equal(t, false, BasicPacketFilter(output[:], packetLength))
		assert.Equal(t, false, AdvancedPacketFilter(output[:], magic[:], fromAddress[:], fromPort, toAddress[:], toPort, packetLength))
	}
}

func TestEncryptBox(t *testing.T) {

	t.Parallel()

	senderPublicKey, senderPrivateKey := Keygen_Box()
	receiverPublicKey, receiverPrivateKey := Keygen_Box()

	assert.Equal(t, PrivateKeyBytes_Box, len(senderPrivateKey))
	assert.Equal(t, PublicKeyBytes_Box, len(senderPublicKey))
	assert.Equal(t, PrivateKeyBytes_Box, len(receiverPrivateKey))
	assert.Equal(t, PublicKeyBytes_Box, len(receiverPublicKey))

	// encrypt random data and verify we can decrypt it

	nonce := RandomBytes(NonceBytes_Box)

	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(data[i])
	}

	encryptedData := make([]byte, 256+HMACBytes_Box)

	encryptedBytes := Encrypt_Box(senderPrivateKey[:], receiverPublicKey[:], nonce, encryptedData, len(data))

	assert.Equal(t, 256+HMACBytes_Box, encryptedBytes)

	err := Decrypt_Box(senderPublicKey[:], receiverPrivateKey[:], nonce, encryptedData, encryptedBytes)

	assert.NoError(t, err)

	// decryption should fail with garbage data

	garbageData := RandomBytes(256 + HMACBytes_Box)

	err = Decrypt_Box(senderPublicKey[:], receiverPrivateKey[:], nonce, garbageData, encryptedBytes)

	assert.Error(t, err)

	// decryption should fail with the wrong receiver private key

	for i := 0; i < 32; i++ {
		receiverPrivateKey[i] = byte(i)
	}

	err = Decrypt_Box(senderPublicKey[:], receiverPrivateKey[:], nonce, encryptedData, encryptedBytes)

	assert.Error(t, err)
}

func TestEncryptSecretBox(t *testing.T) {

	t.Parallel()

	privateKey := Keygen_SecretBox()

	assert.Equal(t, PrivateKeyBytes_SecretBox, len(privateKey))

	nonce := RandomBytes(NonceBytes_SecretBox)

	// encrypt random data and verify we can decrypt it

	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(data[i])
	}

	encryptedData := make([]byte, 256+HMACBytes_SecretBox)

	encryptedBytes := Encrypt_SecretBox(privateKey[:], nonce, encryptedData, len(data))

	assert.Equal(t, 256+HMACBytes_SecretBox, encryptedBytes)

	err := Decrypt_SecretBox(privateKey[:], nonce, encryptedData, encryptedBytes)

	assert.NoError(t, err)

	// decryption should fail with garbage data

	garbageData := RandomBytes(256 + HMACBytes_SecretBox)

	err = Decrypt_SecretBox(privateKey[:], nonce, garbageData, encryptedBytes)

	assert.Error(t, err)

	// decryption should fail with the wrong receiver private key

	for i := 0; i < 32; i++ {
		privateKey[i] = byte(i)
	}

	err = Decrypt_SecretBox(privateKey[:], nonce, encryptedData, encryptedBytes)

	assert.Error(t, err)
}

func TestChallengeToken(t *testing.T) {

	t.Parallel()

	privateKey := Keygen_SecretBox()

	assert.Equal(t, PrivateKeyBytes_SecretBox, len(privateKey))

	challengeToken := ChallengeToken{}
	challengeToken.ExpireTimestamp = uint64(time.Now().Unix() + 10)
	challengeToken.ClientAddress = *ParseAddress("127.0.0.1:30000")
	challengeToken.Sequence = 10000

	// write the challenge token to a buffer and read it back in

	buffer := make([]byte, EncryptedChallengeTokenBytes)

	index := 0

	WriteChallengeToken(buffer, &index, &challengeToken)

	assert.Equal(t, index, ChallengeTokenBytes)

	var readChallengeToken ChallengeToken

	index = 0

	result := ReadChallengeToken(buffer, &index, &readChallengeToken)

	assert.True(t, result)
	assert.Equal(t, challengeToken, readChallengeToken)
	assert.Equal(t, index, ChallengeTokenBytes)

	// can't read a token if the buffer is too small

	index = 0

	result = ReadChallengeToken(buffer[:5], &index, &readChallengeToken)

	assert.False(t, result)

	// write an encrypted challenge token and read it back

	index = 0
	WriteEncryptedChallengeToken(buffer, &index, &challengeToken, privateKey)
	assert.Equal(t, index, EncryptedChallengeTokenBytes)

	index = 0
	result = ReadEncryptedChallengeToken(buffer, &index, &readChallengeToken, privateKey)
	assert.Equal(t, index, EncryptedChallengeTokenBytes)

	assert.True(t, result)
	assert.Equal(t, challengeToken, readChallengeToken)

	// can't read an encrypted challenge token if the buffer is too small

	index = 0
	result = ReadEncryptedChallengeToken(buffer[:5], &index, &readChallengeToken, privateKey)
	assert.False(t, result)

	// can't read an encrypted challenge token if the buffer is garbage

	buffer = make([]byte, EncryptedChallengeTokenBytes)
	result = ReadEncryptedChallengeToken(buffer, &index, &readChallengeToken, privateKey)
	assert.False(t, result)
}

func TestAckBits(t *testing.T) {

	t.Parallel()

	// todo

}

func TestProcessAcks(t *testing.T) {

	t.Parallel()

	// todo

}

func TestSessionToken(t *testing.T) {

	t.Parallel()

	senderPublicKey, senderPrivateKey := Keygen_Box()
	receiverPublicKey, receiverPrivateKey := Keygen_Box()

	sessionToken := SessionToken{}
	sessionToken.ExpireTimestamp = uint64(time.Now().Unix() + 20)
	RandomBytes_InPlace(sessionToken.SessionId[:])
	RandomBytes_InPlace(sessionToken.UserId[:])
	sessionToken.EnvelopeUpKbps = 2500
	sessionToken.EnvelopeDownKbps = 10000

	// write the session token to a buffer and read it back in

	buffer := make([]byte, EncryptedSessionTokenBytes)

	index := 0

	WriteSessionToken(buffer, &index, &sessionToken)

	assert.Equal(t, index, SessionTokenBytes)

	var readSessionToken SessionToken

	index = 0

	result := ReadSessionToken(buffer, &index, &readSessionToken)

	assert.True(t, result)
	assert.Equal(t, sessionToken, readSessionToken)
	assert.Equal(t, index, SessionTokenBytes)

	// can't read a token if the buffer is too small

	index = 0

	result = ReadSessionToken(buffer[:5], &index, &readSessionToken)

	assert.False(t, result)

	// write an encrypted session token and read it back

	index = 0
	WriteEncryptedSessionToken(buffer, &index, &sessionToken, senderPrivateKey, receiverPublicKey)
	assert.Equal(t, index, EncryptedSessionTokenBytes)

	index = 0
	result = ReadEncryptedSessionToken(buffer, &index, &readSessionToken, senderPublicKey, receiverPrivateKey)
	assert.Equal(t, index, EncryptedSessionTokenBytes)

	assert.True(t, result)
	assert.Equal(t, sessionToken, readSessionToken)

	// can't read an encrypted session token if the buffer is too small

	index = 0
	result = ReadEncryptedSessionToken(buffer[:5], &index, &readSessionToken, senderPublicKey, receiverPrivateKey)
	assert.False(t, result)

	// can't read an encrypted session token if the buffer is garbage

	buffer = make([]byte, EncryptedSessionTokenBytes)
	result = ReadEncryptedSessionToken(buffer, &index, &readSessionToken, senderPublicKey, receiverPrivateKey)
	assert.False(t, result)
}

func TestConnectData(t *testing.T) {

	t.Parallel()

	publicKey, privateKey := Keygen_Box()

	connectData := ConnectData{}
	copy(connectData.ClientPublicKey[:], publicKey)
	copy(connectData.ClientPrivateKey[:], privateKey)
	connectData.GatewayAddress = *ParseAddress("127.0.0.1:40000")
	RandomBytes_InPlace(connectData.GatewayPublicKey[:])

	// write the connect data to a buffer and read it back in

	buffer := make([]byte, ConnectDataBytes)

	index := 0

	WriteConnectData(buffer, &index, &connectData)

	assert.Equal(t, index, ConnectDataBytes)

	var readConnectData ConnectData

	index = 0

	result := ReadConnectData(buffer, &index, &readConnectData)

	assert.True(t, result)
	assert.Equal(t, connectData, readConnectData)
	assert.Equal(t, index, ConnectDataBytes)

	// can't read connect data if the buffer is too small

	index = 0

	result = ReadConnectData(buffer[:5], &index, &readConnectData)

	assert.False(t, result)
}
