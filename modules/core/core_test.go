/*
   UDPX is Copyright (c) 2022, Network Next, Inc. All rights reserved.

   UDPX is open source software licensed under the BSD 3-Clause License.

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

import (
	"fmt"
	"testing"
	"os"
	"math/rand"
	"crypto/ed25519"
	"github.com/stretchr/testify/assert"
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
	rand.Seed(42)
	var output [256]byte
    for i := 0; i < 10000; i++ {
    	var fromAddress [4]byte
    	var toAddress [4]byte
    	randomBytes(fromAddress[:])
    	randomBytes(toAddress[:])
    	fromPort := uint16(i+1000000)
    	toPort := uint16(i+5000)
    	packetLength := 1 + (i % 1500)
    	GeneratePittle(output[:], fromAddress[:], fromPort, toAddress[:], toPort, packetLength)
    	assert.NotEqual(t, output[0], 0)
    	assert.NotEqual(t, output[1], 0)
    }
}

func TestChonkle(t *testing.T) {
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
    	fromPort := uint16(i+1000000)
    	toPort := uint16(i+5000)
    	packetLength := 18 + ( i % ( len(output) - 18 ) )
    	GenerateChonkle(output[:], magic[:], fromAddress[:], fromPort, toAddress[:], toPort, packetLength)
    	assert.Equal(t, true, BasicPacketFilter(output[:], packetLength))
	}
}
	
func TestABI(t *testing.T) {

	var output [1024]byte
	
	magic := [8]byte{1,2,3,4,5,6,7,8}
	fromAddress := [4]byte{1,2,3,4}
	toAddress := [4]byte{4,3,2,1}
	fromPort := uint16(1000)
	toPort := uint16(5000)
	packetLength := 1000

	GeneratePittle(output[:], fromAddress[:], fromPort, toAddress[:], toPort, packetLength)

	assert.Equal(t, output[0], uint8(71) )
	assert.Equal(t, output[1], uint8(201) )

	GenerateChonkle(output[:], magic[:], fromAddress[:], fromPort, toAddress[:], toPort, packetLength)

	assert.Equal(t, output[0], uint8(45) )
	assert.Equal(t, output[1], uint8(203) )
	assert.Equal(t, output[2], uint8(67) )
	assert.Equal(t, output[3], uint8(96) )
	assert.Equal(t, output[4], uint8(78) )
	assert.Equal(t, output[5], uint8(180) )
	assert.Equal(t, output[6], uint8(127) )
	assert.Equal(t, output[7], uint8(7) )
}

func TestPittleAndChonkle(t *testing.T) {
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
    	fromPort := uint16(i+1000000)
    	toPort := uint16(i+5000)
    	packetLength := 18 + ( i % ( len(output) - 18 ) )
    	GenerateChonkle(output[:], magic[:], fromAddress[:], fromPort, toAddress[:], toPort, packetLength)
    	GeneratePittle(output[packetLength-2:], fromAddress[:], fromPort, toAddress[:], toPort, packetLength)
    	assert.Equal(t, true, BasicPacketFilter(output[:], packetLength))
    	assert.Equal(t, true, AdvancedPacketFilter(output[:], magic[:], fromAddress[:], fromPort, toAddress[:], toPort, packetLength))
	}
}

func TestBasicPacketFilter(t *testing.T) {
	rand.Seed(42)
	var output [256]byte
	iterations := 10000
	for i := 0; i < iterations; i++ {
		randomBytes(output[:])
		packetLength := i % len(output)
    	assert.Equal(t, false, BasicPacketFilter(output[:], packetLength))
	}
}

func TestAdvancedBasicPacketFilter(t *testing.T) {
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
    	fromPort := uint16(i+1000000)
    	toPort := uint16(i+5000)
		randomBytes(output[:])
		packetLength := i % len(output)
    	assert.Equal(t, false, BasicPacketFilter(output[:], packetLength))
    	assert.Equal(t, false, AdvancedPacketFilter(output[:], magic[:], fromAddress[:], fromPort, toAddress[:], toPort, packetLength))
	}
}

func TestEncrypt(t *testing.T) {

	// todo: keygen is at fault
	senderPublicKey, senderPrivateKey, _ := ed25519.GenerateKey(nil)
	receiverPublicKey, receiverPrivateKey, _ := ed25519.GenerateKey(nil)

	// encrypt random data and verify we can decrypt it

	nonce := RandomBytes(24)

	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(data[i])
	}

	encryptedData := make([]byte, 256+16)

	encryptedBytes := Encrypt(senderPrivateKey[:], receiverPublicKey[:], nonce, encryptedData, len(data))

	assert.Equal(t, 256+16, encryptedBytes)

	err := Decrypt(senderPublicKey[:], receiverPrivateKey[:], nonce, encryptedData, encryptedBytes)

	assert.NoError(t, err)

	// decryption should fail with garbage data

	garbageData := RandomBytes(256+16)

	err = Decrypt(senderPublicKey[:], receiverPrivateKey[:], nonce, garbageData, encryptedBytes)

	assert.Error(t, err)

	// decryption should fail with the wrong receiver private key

	for i := 0; i < 32; i++ {
		receiverPrivateKey[i] = byte(i)
	}

	err = Decrypt(senderPublicKey[:], receiverPrivateKey[:], nonce, encryptedData, encryptedBytes)

	assert.Error(t, err)
}
