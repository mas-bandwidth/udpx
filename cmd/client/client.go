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

package main

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/networknext/udpx/modules/core"
	"github.com/networknext/udpx/modules/envvar"
)

const MaxPacketSize = 1500
const OldSequenceThreshold = 100
const SequenceBufferSize = 1024
const QueueSize = 1024

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

	connectToken, err := envvar.GetBase64("CONNECT_TOKEN", nil)
	if err != nil || len(connectToken) != core.ConnectTokenBytes {
		core.Error("missing or invalid CONNECT_TOKEN: %v", err)
		return 1
	}

	index := 0
	var connectData core.ConnectData
	if !core.ReadConnectData(connectToken, &index, &connectData) {
		core.Error("invalid connect data")
		return 1
	}

	envelopeUpKbps := connectData.EnvelopeUpKbps
	packetsPerSecond := int(connectData.PacketsPerSecond)

	var bandwidthMutex sync.RWMutex
	sendBandwidthBitsAccumulator := uint64(0)
	sendBandwidthBitsPerSecondMax := uint64(envelopeUpKbps * 1000)
	sendBandwidthBitsResetTime := time.Now().Add(time.Second)

	var sessionTokenMutex sync.RWMutex
	sessionTokenData := make([]byte, core.EncryptedSessionTokenBytes)
	copy(sessionTokenData[:], connectToken[core.ConnectDataBytes:])
	sessionTokenSequence := uint64(0)
	sessionTokenExpireTime := time.Now().Add(time.Second * core.ConnectTokenExpireSeconds)

	gatewayAddress := &connectData.GatewayAddress
	gatewayPublicKey := connectData.GatewayPublicKey[:]
	clientPublicKey := connectData.ClientPublicKey[:]
	clientPrivateKey := connectData.ClientPrivateKey[:]
	sessionId := clientPublicKey

	var gatewayIdMutex sync.RWMutex
	var gatewayId [core.GatewayIdBytes]byte

	var serverIdMutex sync.RWMutex
	var serverId [core.ServerIdBytes]byte

	core.Info("starting client on port %s", udpPort)

	core.Info("session id is %s", core.IdString(sessionId))

	core.Info("connecting to %s", gatewayAddress)

	// setup

	connectedToServer := false
	hasChallengeToken := false
	challengeTokenData := [core.EncryptedChallengeTokenBytes]byte{}
	challengeTokenSequence := uint64(0)
	challengeTokenExpireTimestamp := uint64(0)
	challengeTokenGatewayId := [core.GatewayIdBytes]byte{}

	sendSequence := uint64(10000) + uint64(rand.Intn(10000))
	receiveSequence := uint64(0)

	packetReceiveQueue := make(chan []byte, QueueSize)

	ackBuffer := make([]uint64, SequenceBufferSize)
	ackedPackets := make([]uint64, SequenceBufferSize)
	receivedPackets := make([]uint64, SequenceBufferSize)

	payloadAckQueue := make(chan uint64, QueueSize)
	payloadSendQueue := make(chan []byte, QueueSize)
	payloadReceiveQueue := make(chan []byte, QueueSize)

	sequenceToPayloadId := make([]uint64, SequenceBufferSize)
	for i := range sequenceToPayloadId {
		sequenceToPayloadId[i] = ^uint64(0)
	}

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

		// send packets

		go func() {

			payloadId := uint64(0)

			for {
				select {
				case payload := <-payloadSendQueue:

					ack_bits := [core.AckBitsBytes]byte{}

					core.GetAckBits(receiveSequence, receivedPackets[:], ack_bits[:])

					packetData := make([]byte, MaxPacketSize)

					version := byte(0)

					index := 0

					core.Debug("send packet sequence = %d", sendSequence)
					core.Debug("send packet ack = %d", receiveSequence)
					core.Debug("send packet ack_bits = [%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x]",
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
					sessionTokenMutex.RLock()
					core.WriteBytes(packetData, &index, sessionTokenData, core.EncryptedSessionTokenBytes)
					core.WriteUint64(packetData, &index, sessionTokenSequence)
					sessionTokenMutex.RUnlock()
					core.WriteBytes(packetData, &index, sessionId, core.SessionIdBytes)
					sequenceData := packetData[index : index+core.SequenceBytes]
					core.WriteUint64(packetData, &index, sendSequence)
					encryptStart := index
					core.WriteUint64(packetData, &index, receiveSequence)
					core.WriteBytes(packetData, &index, ack_bits[:], len(ack_bits))
					if hasChallengeToken {
						core.WriteBytes(packetData, &index, challengeTokenGatewayId[:], core.GatewayIdBytes)
					} else {
						gatewayIdMutex.RLock()
						core.WriteBytes(packetData, &index, gatewayId[:], core.GatewayIdBytes)
						gatewayIdMutex.RUnlock()
					}
					serverIdMutex.RLock()
					core.WriteBytes(packetData, &index, serverId[:], core.ServerIdBytes)
					serverIdMutex.RUnlock()
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

					// do we have enough bandwidth available to send this packet?

					wireBits := uint64(core.WirePacketBits(len(packetData)))

					canSendPacket := true

					bandwidthMutex.Lock()
					if sendBandwidthBitsAccumulator+wireBits <= sendBandwidthBitsPerSecondMax {
						sendBandwidthBitsAccumulator += wireBits
					} else {
						canSendPacket = false
					}
					bandwidthMutex.Unlock()

					if !canSendPacket {
						core.Debug("choke")
						continue
					}

					// send the packet

					if _, err := conn.WriteToUDP(packetData, gatewayAddress); err != nil {
						core.Error("failed to write udp packet: %v", err)
					}

					core.Debug("sent %d byte packet to %s", len(packetData), gatewayAddress)

					sequenceToPayloadId[sendSequence%SequenceBufferSize] = payloadId
					sendSequence++
					payloadId++

					// time out the challenge token if it's too old

					if hasChallengeToken && challengeTokenExpireTimestamp <= uint64(time.Now().Unix()) {
						core.Debug("timed out challenge token")
						hasChallengeToken = false
					}
				}
			}
		}()

		go func() {

			// receive packets (stateless)

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

		// receive packets (stateful)

		for {

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

						sessionIdIndex := core.PrefixBytes

						sessionId := packetData[sessionIdIndex : sessionIdIndex+core.SessionIdBytes]

						if !core.IdEqual(sessionId, clientPublicKey) {
							core.Debug("session id mismatch")
							continue
						}

						// decrypt packet

						sequenceIndex := core.PrefixBytes + core.SessionIdBytes
						encryptedDataIndex := sequenceIndex + core.SequenceBytes

						sequenceData := packetData[sequenceIndex : sequenceIndex+core.SequenceBytes]
						encryptedData := packetData[encryptedDataIndex : packetBytes-core.PittleBytes]

						nonce := make([]byte, core.NonceBytes_Box)
						for i := 0; i < core.SequenceBytes; i++ {
							nonce[i] = sequenceData[i]
						}
						nonce[9] |= (1 << 0)
						nonce[9] &= 1 ^ (1 << 1)

						err = core.Decrypt_Box(gatewayPublicKey, clientPrivateKey, nonce, encryptedData, len(encryptedData))
						if err != nil {
							core.Debug("could not decrypt payload packet")
							continue
						}

						// split decrypted packet into various pieces

						headerIndex := core.PrefixBytes

						payloadIndex := headerIndex + core.HeaderBytes
						payloadBytes := packetBytes - payloadIndex - core.PostfixBytes

						header := packetData[headerIndex : headerIndex+core.HeaderBytes]

						payload := packetData[payloadIndex : payloadIndex+payloadBytes]

						// check encrypted packet type matches

						packetType := header[core.SessionIdBytes+core.SequenceBytes+core.AckBytes+core.AckBitsBytes+core.GatewayIdBytes+core.ServerIdBytes]
						if packetType != core.PayloadPacket {
							core.Debug("packet type mismatch: %d", packetType)
							continue
						}

						// packet sequence must not be too old

						index := 0
						sequence := uint64(0)
						core.ReadUint64(sequenceData, &index, &sequence)

						if receiveSequence > OldSequenceThreshold && sequence < receiveSequence-OldSequenceThreshold {
							core.Debug("packet sequence is too old: %d", sequence)
							continue
						}

						if sequence > receiveSequence {
							receiveSequence = sequence
						}

						receivedPackets[sequence%SequenceBufferSize] = sequence

						// update session token if the gateway has a newer one

						sessionTokenDataIndex := core.VersionBytes + core.PacketTypeBytes + core.ChonkleBytes
						sessionTokenSequenceIndex := sessionTokenDataIndex + core.EncryptedSessionTokenBytes

						packetSessionTokenData := packetData[sessionTokenDataIndex : sessionTokenDataIndex+core.EncryptedSessionTokenBytes]

						sessionTokenMutex.Lock()

						index = sessionTokenSequenceIndex
						var packetSessionTokenSequence uint64
						core.ReadUint64(packetData, &index, &packetSessionTokenSequence)

						if packetSessionTokenSequence > sessionTokenSequence {
							core.Info("updated session token %d", packetSessionTokenSequence)
							copy(sessionTokenData[:], packetSessionTokenData[:])
							sessionTokenSequence = packetSessionTokenSequence
							sessionTokenExpireTime = time.Now().Add(time.Second * core.ConnectTokenExpireSeconds)
						}

						sessionTokenMutex.Unlock()

						// process payload packet

						core.Debug("payload is %d bytes", len(payload))

						payloadReceiveQueue <- payload

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
						core.Debug("recv packet ack_bits = [%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x]",
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
							core.Debug("ack packet %d", acks[i])
							ackedPackets[acks[i]%SequenceBufferSize] = acks[i]
							payloadAck := sequenceToPayloadId[acks[i]%SequenceBufferSize]
							if payloadAck != ^uint64(0) {
								payloadAckQueue <- payloadAck
							}
						}

						// check if we have a new gateway

						gatewayIdIndex := sessionIdIndex + core.SessionIdBytes + core.SequenceBytes + core.AckBytes + core.AckBitsBytes

						packetGatewayId := packetData[gatewayIdIndex : gatewayIdIndex+core.GatewayIdBytes]

						gatewayIdMutex.Lock()
						if !core.IdEqual(packetGatewayId, gatewayId[:]) {
							core.Info("connected to gateway %s", core.IdString(packetGatewayId))
							copy(gatewayId[:], packetGatewayId[:])
						}
						gatewayIdMutex.Unlock()

						// check if we have a new server

						serverIdIndex := gatewayIdIndex + core.GatewayIdBytes

						packetServerId := packetData[serverIdIndex : serverIdIndex+core.ServerIdBytes]

						serverIdMutex.Lock()
						newServer := !core.IdEqual(packetServerId, serverId[:])
						if newServer {
							core.Info("connected to server %s", core.IdString(packetServerId))
							copy(serverId[:], packetServerId[:])
						}
						serverIdMutex.Unlock()

						// clear challenge token

						if hasChallengeToken {
							core.Debug("cleared challenge token")
							hasChallengeToken = false
							connectedToServer = true
						}

					case core.ChallengePacket:

						core.Debug("received %d byte challenge packet from gateway", len(packetData))

						if len(packetData) != core.ChallengePacketBytes {
							core.Debug("bad challenge packet size: got %d, expected %d", len(packetData), core.ChallengePacketBytes)
							continue
						}

						nonceIndex := core.VersionBytes + core.PacketTypeBytes + core.ChonkleBytes + core.EncryptedSessionTokenBytes + core.SequenceBytes

						encryptedDataIndex := nonceIndex + core.NonceBytes_Box

						encryptedData := packetData[encryptedDataIndex:]

						nonce := packetData[nonceIndex : nonceIndex+core.NonceBytes_Box]

						err = core.Decrypt_Box(gatewayPublicKey, clientPrivateKey, nonce, encryptedData, len(encryptedData)-core.PittleBytes)
						if err != nil {
							core.Debug("could not decrypt challenge packet")
							continue
						}

						packetChallengeTokenData := packetData[encryptedDataIndex : encryptedDataIndex+core.EncryptedChallengeTokenBytes]

						packetChallengeSequence := uint64(0)
						index := encryptedDataIndex + core.EncryptedChallengeTokenBytes
						core.ReadUint64(packetData, &index, &packetChallengeSequence)

						var packetGatewayId [core.GatewayIdBytes]byte
						core.ReadBytes(packetData, &index, packetGatewayId[:], core.GatewayIdBytes)

						if !hasChallengeToken || challengeTokenSequence < packetChallengeSequence {
							if connectedToServer {
								core.Info("reconnecting...")
								connectedToServer = false
							}
							hasChallengeToken = true
							copy(challengeTokenData[:], packetChallengeTokenData)
							challengeTokenSequence = packetChallengeSequence
							challengeTokenExpireTimestamp = uint64(time.Now().Unix()) + 2
							copy(challengeTokenGatewayId[:], packetGatewayId[:])
							core.Debug("updated challenge token: %d", packetChallengeSequence)
						}
					}

				default:
					quit = true
				}
			}
		}
	}()

	// main loop

	termChan := make(chan os.Signal, 1)

	go func() {

		ackBuffer := [QueueSize]uint64{}

		for {

			// send payload

			payload := make([]byte, core.MinPayloadBytes)
			for i := 0; i < core.MinPayloadBytes; i++ {
				payload[i] = byte(i)
			}

			payloadSendQueue <- payload

			// process payload acks

			acks := GetPayloadAcks(payloadAckQueue, ackBuffer[:])
			for i := 0; i < len(acks); i++ {
				core.Debug("ack payload %d", acks[i])
			}

			// receive payloads

			for {
				payload := ReceivePayload(payloadReceiveQueue)
				if payload == nil {
					break
				}
				if len(payload) != core.MinPayloadBytes {
					panic("incorrect payload bytes")
				}
				for i := 0; i < len(payload); i++ {
					if payload[i] != byte(i) {
						panic(fmt.Sprintf("payload data mismatch at index %d. expected %d, got %d\n", i, byte(i), payload[i]))
					}
				}
			}

			// have we timed out?

			timedOut := false
			sessionTokenMutex.RLock()
			if sessionTokenExpireTime.Before(time.Now()) {
				timedOut = true
			}
			sessionTokenMutex.RUnlock()

			if timedOut {
				core.Info("disconnected")
				termChan <- syscall.SIGTERM
			}

			// update bandwidth usage

			bandwidthMutex.Lock()
			if sendBandwidthBitsResetTime.Before(time.Now()) {
				sendBandwidthMbps := float64(sendBandwidthBitsAccumulator) / 1000000.0
				sendBandwidthBitsResetTime = time.Now().Add(time.Second)
				sendBandwidthBitsAccumulator = 0
				core.Debug("%.2f mbps", sendBandwidthMbps)
			}
			bandwidthMutex.Unlock()

			// sleep till next frame

			frameTime := time.Duration(1000000000 / packetsPerSecond)

			time.Sleep(frameTime)
		}
	}()

	signal.Notify(termChan, os.Interrupt, syscall.SIGTERM)
	<-termChan

	core.Info("shutting down")

	ctxCancelFunc()

	core.Info("shutdown completed")

	return 0
}

func ReceivePayload(queue chan []byte) []byte {
	select {
	case payload := <-queue:
		return payload
	default:
		return nil
	}
}

func GetPayloadAcks(queue chan uint64, buffer []uint64) []uint64 {
	index := 0
	select {
	case ack := <-queue:
		buffer[index] = ack
		index++
	default:
	}
	return buffer[:index]
}
