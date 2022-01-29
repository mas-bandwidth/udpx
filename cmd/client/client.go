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
	"math/rand"

	"github.com/networknext/udpx/modules/core"
	"github.com/networknext/udpx/modules/envvar"
)

const MaxPacketSize = 1500
const OldSequenceThreshold = 100
const SequenceBufferSize = 1024

func main() {
	os.Exit(mainReturnWithCode())
}

func mainReturnWithCode() int {

	serviceName := "udpx client"

	core.Info("%s", serviceName)

	// configure

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

	gatewayPublicKey, err := envvar.GetBase64("GATEWAY_PUBLIC_KEY", nil)
	if err != nil || len(gatewayPublicKey) != core.PublicKeyBytes_Box {
		core.Error("missing or invalid GATEWAY_PUBLIC_KEY: %v", err)
		return 1
	}

	clientPublicKey, clientPrivateKey := core.Keygen_Box()

	sessionId := clientPublicKey

	if len(sessionId) != core.SessionIdBytes {
		panic(fmt.Sprintf("public key must be %d bytes", core.SessionIdBytes))
	}

	core.Info("session id is %s", core.SessionIdString(sessionId))

	// setup

	connectedToServer := false
	hasChallengeToken := false
	challengeTokenData := [core.EncryptedChallengeTokenBytes]byte{}
	challengeTokenSequence := uint64(0)
	challengeTokenExpireTimestamp := uint64(0)

	sendSequence := uint64(10000) + uint64(rand.Intn(10000))
	receiveSequence := uint64(0)
	
	packetReceiveQueue := make(chan []byte)

	ackBuffer := make([]uint64, SequenceBufferSize)
	ackedPackets := make([]uint64, SequenceBufferSize)
	receivedPackets := make([]uint64, SequenceBufferSize)

    // create client socket

	lc := net.ListenConfig{}

	ctx, ctxCancelFunc := context.WithCancel(context.Background())

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

			for {

				packetData := make([]byte, MaxPacketSize)

				packetBytes, from, err := conn.ReadFromUDP(packetData)
				if err != nil {
					core.Debug("failed to read udp packet: %v", err)
					break
				}

				if !core.AddressEqual(from, gatewayAddress) {
					core.Debug("packet is not from gateway")
					continue
				}

				if packetBytes < core.PrefixBytes {
					core.Debug("packet is too small")
					continue
				}

				if packetData[0] != 0 {
					core.Debug("unknown packet version: %d", packetData[0])
					continue
				}

				if packetData[1] != core.PayloadPacket && packetData[1] != core.ChallengePacket {
					core.Debug("unknown packet type %d", packetData[1])
					continue
				}

				// packet filter

				if !core.BasicPacketFilter(packetData, packetBytes) {
					core.Debug("basic packet filter failed")
					continue
				}

				var magic [8]byte

				var fromAddressData [4]byte
				var fromAddressPort uint16

				var toAddressData [4]byte
				var toAddressPort uint16

				core.GetAddressData(from, fromAddressData[:], &fromAddressPort)
				core.GetAddressData(clientAddress, toAddressData[:], &toAddressPort)

				if !core.AdvancedPacketFilter(packetData, magic[:], fromAddressData[:], fromAddressPort, toAddressData[:], toAddressPort, packetBytes) {
					core.Debug("advanced packet filter failed")
					continue
				}

				packetData = packetData[:packetBytes]

				packetReceiveQueue <- packetData
			}

		}()

		// main loop

		for {

			// receive packets

			quit := false
			for !quit {
				select {
				case packetData := <-packetReceiveQueue:

					packetType := packetData[core.VersionBytes]

					packetBytes := len(packetData)

					switch packetType {

					case core.PayloadPacket:

						core.Debug("received %d byte payload packet from gateway", len(packetData))

						// session id must match client public key

						sessionIdIndex := core.VersionBytes + core.PacketTypeBytes + core.ChonkleBytes

						sessionId := packetData[sessionIdIndex : sessionIdIndex + core.SessionIdBytes]

						if !core.SessionIdEqual(sessionId, clientPublicKey) {
							core.Debug("session id mismatch")
							continue
						}

						// decrypt packet

						sequenceIndex := core.VersionBytes + core.PacketTypeBytes + core.ChonkleBytes + core.SessionIdBytes
						encryptedDataIndex := core.VersionBytes + core.PacketTypeBytes + core.ChonkleBytes + core.SessionIdBytes + core.SequenceBytes

						sequenceData := packetData[sequenceIndex : sequenceIndex+core.SequenceBytes]
						encryptedData := packetData[encryptedDataIndex : packetBytes - core.PittleBytes]

						nonce := make([]byte, core.NonceBytes_Box)
						for i := 0; i < core.SequenceBytes; i++ {
							nonce[i] = sequenceData[i]
						}
						nonce[9] |= (1<<0)
						nonce[9] &= 1^(1<<1)

						err = core.Decrypt_Box(gatewayPublicKey, clientPrivateKey, nonce, encryptedData, len(encryptedData))
						if err != nil {
							core.Debug("could not decrypt payload packet")
							continue
						}

						// split decrypted packet into various pieces

						headerIndex := core.PrefixBytes
						
						payloadIndex := headerIndex + core.HeaderBytes
						payloadBytes := packetBytes - payloadIndex - core.PostfixBytes

						header := packetData[headerIndex:headerIndex+core.HeaderBytes]

						payload := packetData[payloadIndex:payloadIndex+payloadBytes]

						// check encrypted packet type matches

						packetType := header[core.SessionIdBytes+core.SequenceBytes+core.AckBytes+core.AckBitsBytes]
						if packetType != core.PayloadPacket {
							core.Debug("packet type mismatch: %d", packetType)
							continue
						}

						// packet sequence must not be too old

						index := 0
						sequence := uint64(0)
						core.ReadUint64(sequenceData, &index, &sequence)

						if receiveSequence > OldSequenceThreshold && sequence < receiveSequence - OldSequenceThreshold {
							core.Debug("packet sequence is too old: %d", sequence)
							continue
						}

						if sequence > receiveSequence {
							receiveSequence = sequence
						}

						receivedPackets[sequence%SequenceBufferSize] = sequence

						// process payload packet

						core.Debug("payload is %d bytes\n", len(payload))

						// -------------------------
						// todo: call function to process payload
						if len(payload) != core.MinPayloadBytes {
							panic("incorrect payload bytes")
						}

						for i := 0; i < len(payload); i++ {
							if payload[i] != byte(i) {
								panic(fmt.Sprintf("payload data mismatch at index %d. expected %d, got %d\n", i, byte(i), payload[i]))
							}
						}
						// todo end
						// -------------------------

						// update reliability

						packet_sequence := uint64(0)
						packet_ack := uint64(0)
						packet_ack_bits := [core.AckBitsBytes]byte{}

						index = core.SessionIdBytes
						core.ReadUint64(header, &index, &packet_sequence)
						core.ReadUint64(header, &index, &packet_ack)
						core.ReadBytes(header, &index, packet_ack_bits[:], core.AckBitsBytes)

						core.Debug("recv packet sequence = %d", packet_sequence)
						core.Debug("recv packet ack = %d", packet_ack)
						core.Debug("recv packet ack_bits = [%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x", 
							packet_ack_bits[0],
							packet_ack_bits[1],
							packet_ack_bits[2],
							packet_ack_bits[3],
							packet_ack_bits[4],
							packet_ack_bits[5],
							packet_ack_bits[6],
							packet_ack_bits[7],
							packet_ack_bits[8],
							packet_ack_bits[9],
							packet_ack_bits[10],
							packet_ack_bits[11],
							packet_ack_bits[12],
							packet_ack_bits[13],
							packet_ack_bits[14],
							packet_ack_bits[15],
							packet_ack_bits[16],
							packet_ack_bits[17],
							packet_ack_bits[18],
							packet_ack_bits[19],
							packet_ack_bits[20],
							packet_ack_bits[21],
							packet_ack_bits[22],
							packet_ack_bits[23],
							packet_ack_bits[24],
							packet_ack_bits[25],
							packet_ack_bits[26],
							packet_ack_bits[27],
							packet_ack_bits[28],
							packet_ack_bits[29],
							packet_ack_bits[30],
							packet_ack_bits[31])

						// process acks

						acks := core.ProcessAcks(packet_ack, packet_ack_bits[:], ackedPackets[:], ackBuffer[:])						

						for i := range acks {
							core.Debug("ack %d", acks[i])
							ackedPackets[acks[i]%SequenceBufferSize] = acks[i]
						}

						// clear challenge token

						if hasChallengeToken {
							core.Info("connected")
							hasChallengeToken = false
							connectedToServer = true
						}

					case core.ChallengePacket:
						
						core.Debug("received %d byte challenge packet from gateway", len(packetData))
						
						if len(packetData) != 142 {
							core.Debug("bad challenge packet size: %d", len(packetData))
							continue
						}

						nonceIndex := core.VersionBytes + core.PacketTypeBytes + core.ChonkleBytes

						encryptedDataIndex := nonceIndex + core.NonceBytes_Box

						encryptedData := packetData[encryptedDataIndex:len(packetData)]

						nonce := packetData[nonceIndex:core.NonceBytes_Box]

						err = core.Decrypt_Box(gatewayPublicKey, clientPrivateKey, nonce, encryptedData, len(encryptedData) - core.PittleBytes)
						if err != nil {
							core.Debug("could not decrypt challenge packet")
							continue
						}

						packetChallengeTokenData := packetData[encryptedDataIndex:encryptedDataIndex+core.EncryptedChallengeTokenBytes]

						packetChallengeSequence := uint64(0)
						index := encryptedDataIndex + core.EncryptedChallengeTokenBytes
						core.ReadUint64(packetData, &index, &packetChallengeSequence)
						
						if !hasChallengeToken || challengeTokenSequence < packetChallengeSequence {
							if connectedToServer {
								core.Info("reconnecting")								
								connectedToServer = false
							}
							hasChallengeToken = true
							copy(challengeTokenData[:], packetChallengeTokenData)
							challengeTokenSequence = packetChallengeSequence
							challengeTokenExpireTimestamp = uint64(time.Now().Unix()) + 2
							core.Debug("updated challenge token: %d", packetChallengeSequence)
						}
					}

				default:
					quit = true
				}
			}

			// send payload packet

			ack_bits := [core.AckBitsBytes]byte{}

			core.GetAckBits(receiveSequence, receivedPackets[:], ack_bits[:])

			packetData := make([]byte, MaxPacketSize)

			payload := make([]byte, core.MinPayloadBytes)
			for i := 0; i < core.MinPayloadBytes; i++ {
				payload[i] = byte(i)
			}

			version := byte(0)

			index := 0

			core.Debug("send packet sequence = %d", sendSequence)
			core.Debug("send packet ack = %d", receiveSequence)
			core.Debug("send packet ack_bits = [%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x", 
				ack_bits[0],
				ack_bits[1],
				ack_bits[2],
				ack_bits[3],
				ack_bits[4],
				ack_bits[5],
				ack_bits[6],
				ack_bits[7],
				ack_bits[8],
				ack_bits[9],
				ack_bits[10],
				ack_bits[11],
				ack_bits[12],
				ack_bits[13],
				ack_bits[14],
				ack_bits[15],
				ack_bits[16],
				ack_bits[17],
				ack_bits[18],
				ack_bits[19],
				ack_bits[20],
				ack_bits[21],
				ack_bits[22],
				ack_bits[23],
				ack_bits[24],
				ack_bits[25],
				ack_bits[26],
				ack_bits[27],
				ack_bits[28],
				ack_bits[29],
				ack_bits[30],
				ack_bits[31])

			core.WriteUint8(packetData, &index, version)
			core.WriteUint8(packetData, &index, core.PayloadPacket)
			chonkle := packetData[index : index+core.ChonkleBytes]
			index += core.ChonkleBytes
			core.WriteBytes(packetData, &index, sessionId, core.SessionIdBytes)
			sequenceData := packetData[index : index+core.SequenceBytes]
			core.WriteUint64(packetData, &index, sendSequence)
			encryptStart := index
			core.WriteUint64(packetData, &index, receiveSequence)
			core.WriteBytes(packetData, &index, ack_bits[:], len(ack_bits))
			core.WriteUint8(packetData, &index, core.PayloadPacket)
			if hasChallengeToken {
				core.WriteUint8(packetData, &index, core.Flags_ChallengeToken)
				core.WriteBytes(packetData, &index, challengeTokenData[:], core.EncryptedChallengeTokenBytes)
			} else {
				core.WriteUint8(packetData, &index, 0)
			}
			core.WriteBytes(packetData, &index, payload[:], core.MinPayloadBytes)
			encryptFinish := index
			index += core.HMACBytes_Box
			pittle := packetData[index : index+core.PittleBytes]
			index += core.PittleBytes

			nonce := make([]byte, core.NonceBytes_Box)
			for i := 0; i < core.SequenceBytes; i++ {
				nonce[i] = sequenceData[i]
			}

			core.Encrypt_Box(clientPrivateKey, gatewayPublicKey, nonce, packetData[encryptStart:encryptFinish], encryptFinish-encryptStart)

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

			core.Debug("sent %d byte packet to %s", len(packetData), gatewayAddress)

			// time out the challenge token if it's too old

			if hasChallengeToken && challengeTokenExpireTimestamp <= uint64(time.Now().Unix()) {
				core.Debug("timed out challenge token")
				hasChallengeToken = false
			}

			// sleep till next frame

			time.Sleep(100 * time.Millisecond)

			sendSequence++
		}

	}()

	core.Info("started client on port %s", udpPort)

	core.Info("connecting to %s", gatewayAddress)

	// Wait for shutdown signal
	termChan := make(chan os.Signal, 1)
	signal.Notify(termChan, os.Interrupt, syscall.SIGTERM)
	<-termChan

	core.Info("\nshutting down")

	ctxCancelFunc()

	core.Info("shutdown completed")

	return 0
}
