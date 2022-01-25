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

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
	
	"github.com/networknext/udpx/modules/core"
	"github.com/networknext/udpx/modules/envvar"
)

const MaxPacketSize = 1500

func main() {
	os.Exit(mainReturnWithCode())
}

func mainReturnWithCode() int {

	serviceName := "udpx client"

	fmt.Printf("%s\n", serviceName)

	ctx, ctxCancelFunc := context.WithCancel(context.Background())

	readBuffer, err := envvar.GetInt("READ_BUFFER", 100000)
	if err != nil {
		core.Error("invalid READ_BUFFER: %v", err)
		return 1
	}

	writeBuffer, err := envvar.GetInt("WRITE_BUFFER", 100000)
	if err != nil {
		core.Error("invalid WRITE_BUFFER: %v", err)
		return 1
	}

	udpPort := envvar.Get("UDP_PORT", "0")

	clientAddress, err := envvar.GetAddress("CLIENT_ADDRESS", core.ParseAddress("127.0.0.1:30000"))
	if err != nil {
		core.Error("invalid CLIENT_ADDRESS: %v", err)
		return 1
	}

	gatewayAddress, err := envvar.GetAddress("GATEWAY_ADDRESS", core.ParseAddress("127.0.0.1:40000"))
	if err != nil {
		core.Error("invalid GATEWAY_ADDRESS: %v", err)
		return 1
	}

	clientPublicKey, clientPrivateKey := core.Keygen()

	gatewayPublicKey, err := envvar.GetBase64("GATEWAY_PUBLIC_KEY", nil)
	if err != nil || len(gatewayPublicKey) != core.PublicKeyBytes {
		core.Error("missing or invalid GATEWAY_PUBLIC_KEY: %v\n", err)
		return 1
	}

	lc := net.ListenConfig{}

	go func() {

		lp, err := lc.ListenPacket(ctx, "udp", "0.0.0.0:"+udpPort)
		if err != nil {
			panic(fmt.Sprintf("could not bind socket: %v", err))
		}

		conn := lp.(*net.UDPConn)
		defer conn.Close()

		if err := conn.SetReadBuffer(readBuffer); err != nil {
			panic(fmt.Sprintf("could not set connection read buffer size: %v", err))
		}

		if err := conn.SetWriteBuffer(writeBuffer); err != nil {
			panic(fmt.Sprintf("could not set connection write buffer size: %v", err))
		}

		go func() {

			// receive packets

			buffer := [MaxPacketSize]byte{}

			for {

				packetBytes, from, err := conn.ReadFromUDP(buffer[:])
				if err != nil {
					core.Error("failed to read udp packet: %v", err)
					break
				}

				if packetBytes <= 0 {
					continue
				}

				packetData := buffer[:packetBytes]

				fmt.Printf("recv %d byte packet from %s\n", packetBytes, from)

				// todo: queue packet up on channel for main loop to receive
				_ = packetData
			}

		}()

		// main loop

		sessionId := clientPublicKey
		if len(sessionId) != core.SessionIdBytes {
			panic(fmt.Sprintf("public key must be %d bytes", core.SessionIdBytes))
		}

		_ = clientPrivateKey

		sequence := uint64(0)
		ack := uint64(0)
		ack_bits := [32]byte{}

		for {

			packetData := make([]byte, MaxPacketSize)

			payload := make([]byte, core.MinPayloadBytes)
			for i := 0; i < core.MinPayloadBytes; i++ {
				payload[i] = byte(i)
			}
			
			index := core.VersionBytes
			chonkle := packetData[index:index+core.ChonkleBytes]
			index += core.ChonkleBytes
			core.WriteBytes(packetData, &index, sessionId, core.SessionIdBytes)
			sequenceData := packetData[index:index+core.SequenceBytes]
			core.WriteUint64(packetData, &index, sequence)
			encryptStart := index
			core.WriteUint64(packetData, &index, ack)
			core.WriteBytes(packetData, &index, ack_bits[:], len(ack_bits))
			core.WriteUint8(packetData, &index, core.PayloadPacket)
			core.WriteBytes(packetData, &index, payload[:], core.MinPayloadBytes)
			encryptFinish := index
			index += core.HMACBytes
			pittle := packetData[index:index+core.PittleBytes]
			index += core.PittleBytes

			nonce := make([]byte, core.NonceBytes)
			for i := 0; i < core.SequenceBytes; i++ {
				nonce[i] = sequenceData[i]
			}

			core.Encrypt(clientPrivateKey, gatewayPublicKey, nonce, packetData[encryptStart:encryptFinish], encryptFinish - encryptStart)
			
			packetBytes := index
			packetData = packetData[:packetBytes]

			var magic [core.MagicBytes]byte
			
			var fromAddressData [4]byte
			var fromAddressPort uint16
	
			var toAddressData [4]byte
			var toAddressPort uint16
	
			core.GetAddressData(clientAddress, fromAddressData[:], &fromAddressPort)
			core.GetAddressData(gatewayAddress, toAddressData[:], &toAddressPort)

			core.GenerateChonkle(chonkle[:], magic[:], fromAddressData[:], fromAddressPort, toAddressData[:], toAddressPort, packetBytes)

			core.GeneratePittle(pittle[:], fromAddressData[:], fromAddressPort, toAddressData[:], toAddressPort, packetBytes)

			if !core.BasicPacketFilter(packetData, packetBytes) {
				panic("basic packet filter failed")
			}

			if !core.AdvancedPacketFilter(packetData, magic[:], fromAddressData[:], fromAddressPort, toAddressData[:], toAddressPort, packetBytes) {
				panic("advanced packet filter failed")
			}

			if _, err := conn.WriteToUDP(packetData, gatewayAddress); err != nil {
				core.Error("failed to write udp packet: %v", err)
			}

			fmt.Printf("sent %d byte packet to %s\n", len(packetData), gatewayAddress)

			time.Sleep(100 * time.Millisecond)

			sequence++
		}

	}()

	fmt.Printf("started udp client on port %s\n", udpPort)

	fmt.Printf("gateway address is %s\n", gatewayAddress)

	// Wait for shutdown signal
	termChan := make(chan os.Signal, 1)
	signal.Notify(termChan, os.Interrupt, syscall.SIGTERM)
	<-termChan

	fmt.Println("\nshutting down")

	ctxCancelFunc()

	fmt.Println("shutdown completed")

	return 0
}
