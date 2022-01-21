package core

import (
	"fmt"
	"testing"
	"os"
	"math/rand"
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
    	GenerateChonkle(output[1:], magic[:], fromAddress[:], fromPort, toAddress[:], toPort, packetLength)
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
    	GenerateChonkle(output[1:], magic[:], fromAddress[:], fromPort, toAddress[:], toPort, packetLength)
    	GeneratePittle(output[packetLength-2:], fromAddress[:], fromPort, toAddress[:], toPort, packetLength)
    	assert.Equal(t, true, BasicPacketFilter(output[:], packetLength))
    	assert.Equal(t, true, AdvancedPacketFilter(output[:], magic[:], fromAddress[:], fromPort, toAddress[:], toPort, packetLength))
	}
}

func TestBasicPacketFilter(t *testing.T) {
	rand.Seed(42)
	var output [256]byte
	pass := 0
	iterations := 10000
	for i := 0; i < iterations; i++ {
		randomBytes(output[:])
		packetLength := i % len(output)
    	assert.Equal(t, false, BasicPacketFilter(output[:], packetLength))
	}
   	assert.Equal(t, 0, pass)
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
