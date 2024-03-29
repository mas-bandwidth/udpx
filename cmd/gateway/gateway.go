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

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/networknext/udpx/modules/core"
	"github.com/networknext/udpx/modules/envvar"

	"github.com/gorilla/mux"
	"golang.org/x/sys/unix"
)

const MaxPacketSize = 1500
const SessionMapSwapTime = 60
const ChallengeTokenTimeout = 10
const OldSequenceThreshold = 100

type SessionTokenUpdate struct {
	SessionTokenData []byte
	ExpireTimestamp  uint64
}

type SessionEntry struct {
	ReceivedSequence                 uint64
	ReceivedPackets                  [OldSequenceThreshold]uint64
	UpdatingSessionToken             bool
	SessionTokenChannel              chan SessionTokenUpdate
	SessionTokenData                 [core.EncryptedSessionTokenBytes]byte
	SessionTokenExpireTimestamp      uint64
	SessionTokenSequence             uint64
	SessionTokenCooldown             time.Time
	SessionTokenRetryCount           int
	ReceiveBandwidthBitsAccumulator  uint64
	ReceiveBandwidthBitsPerSecondMax uint64
	ReceiveBandwidthBitsResetTime    time.Time
	PacketsReceivedInLastSecond      uint64
	PacketsPerSecondMax              uint64
}

func main() {
	os.Exit(mainReturnWithCode())
}

func mainReturnWithCode() int {

	serviceName := "udpx gateway"

	core.Info("%s", serviceName)

	// configure

	gatewayAddress, err := envvar.GetAddress("GATEWAY_ADDRESS", core.ParseAddress("127.0.0.1:40000"))
	if err != nil {
		core.Error("invalid GATEWAY_ADDRESS: %v", err)
		return 1
	}

	gatewayInternalAddress, err := envvar.GetAddress("GATEWAY_INTERNAL_ADDRESS", core.ParseAddress("127.0.0.1:40001"))
	if err != nil {
		core.Error("invalid GATEWAY_INTERNAL_ADDRESS: %v", err)
		return 1
	}

	serverAddress, err := envvar.GetAddress("SERVER_ADDRESS", core.ParseAddress("127.0.0.1:40000"))
	if err != nil {
		core.Error("invalid SERVER_ADDRESS: %v", err)
		return 1
	}

	gatewayPrivateKey, err := envvar.GetBase64("GATEWAY_PRIVATE_KEY", nil)
	if err != nil || len(gatewayPrivateKey) != core.PrivateKeyBytes_Box {
		core.Error("missing or invalid GATEWAY_PRIVATE_KEY: %v", err)
		return 1
	}

	authPublicKey, err := envvar.GetBase64("AUTH_PUBLIC_KEY", nil)
	if err != nil || len(authPublicKey) != core.PublicKeyBytes_Box {
		core.Error("missing or invalid AUTH_PUBLIC_KEY: %v", err)
		return 1
	}

	numThreads, err := envvar.GetInt("NUM_THREADS", 1)
	if err != nil {
		core.Error("invalid NUM_THREADS: %v", err)
		return 1
	}

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

	udpPort := envvar.Get("UDP_PORT", "40000")

	core.Info("starting gateway on port %s", udpPort)

	gatewayId := core.RandomBytes(core.GatewayIdBytes)

	core.Info("gateway id is %s", core.IdString(gatewayId))

	challengePrivateKey := core.Keygen_SecretBox()

	ctx, ctxCancelFunc := context.WithCancel(context.Background())

	var wg sync.WaitGroup

	// --------------------------------------------------

	// Start HTTP server
	{
		router := mux.NewRouter()
		router.HandleFunc("/health", healthHandler).Methods("GET")
		router.HandleFunc("/status", statusHandler).Methods("GET")

		httpPort := envvar.Get("HTTP_PORT", "40000")

		srv := &http.Server{
			Addr:    ":" + httpPort,
			Handler: router,
		}

		go func() {
			core.Debug("started http server on port %s", httpPort)
			err := srv.ListenAndServe()
			if err != nil {
				core.Error("failed to start http server: %v", err)
				return
			}
		}()
	}

	// --------------------------------------------------

	// listen on public address

	wg.Add(numThreads)

	publicSocket := make([]*net.UDPConn, numThreads)

	{
		lc := net.ListenConfig{
			Control: func(network string, address string, c syscall.RawConn) error {
				err := c.Control(func(fileDescriptor uintptr) {
					err := unix.SetsockoptInt(int(fileDescriptor), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
					if err != nil {
						panic(fmt.Sprintf("failed to set reuse address socket option: %v", err))
					}

					err = unix.SetsockoptInt(int(fileDescriptor), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
					if err != nil {
						panic(fmt.Sprintf("failed to set reuse port socket option: %v", err))
					}
				})

				return err
			},
		}

		for i := 0; i < numThreads; i++ {

			lp, err := lc.ListenPacket(ctx, "udp", "0.0.0.0:"+udpPort)
			if err != nil {
				panic(fmt.Sprintf("could not bind socket: %v", err))
			}

			conn := lp.(*net.UDPConn)

			if err := conn.SetReadBuffer(readBuffer); err != nil {
				panic(fmt.Sprintf("could not set connection read buffer size: %v", err))
			}

			if err := conn.SetWriteBuffer(writeBuffer); err != nil {
				panic(fmt.Sprintf("could not set connection write buffer size: %v", err))
			}

			publicSocket[i] = conn
		}

		for i := 0; i < numThreads; i++ {

			go func(thread int) {

				conn := publicSocket[thread]

				defer conn.Close()

				buffer := [MaxPacketSize]byte{}

				sessionMap_Old := make(map[[core.SessionIdBytes]byte]*SessionEntry)
				sessionMap_New := make(map[[core.SessionIdBytes]byte]*SessionEntry)

				swapTime := time.Now().Unix() + SessionMapSwapTime
				swapCount := 0

				for {

					packetBytes, from, err := conn.ReadFromUDP(buffer[:])
					if err != nil {
						core.Debug("failed to read udp packet: %v", err)
						break
					}

					swapCount++
					if swapCount > 100 {
						currentTime := time.Now().Unix()
						if currentTime >= swapTime {
							swapCount = 0
							swapTime = currentTime + SessionMapSwapTime
							sessionMap_Old = sessionMap_New
							sessionMap_New = make(map[[core.SessionIdBytes]byte]*SessionEntry)
						}
					}

					if packetBytes < core.MinPacketSize {
						core.Debug("packet is too small")
						continue
					}

					packetData := buffer[:packetBytes]

					core.Debug("recv %d byte packet from %s", packetBytes, from)

					// drop unknown packet versions

					if packetData[0] != 0 {
						core.Debug("unknown packet version: %d", packetData[0])
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
					core.GetAddressData(gatewayAddress, toAddressData[:], &toAddressPort)

					if !core.AdvancedPacketFilter(packetData, magic[:], fromAddressData[:], fromAddressPort, toAddressData[:], toAddressPort, packetBytes) {
						core.Debug("advanced packet filter failed")
						continue
					}

					// before we decrypt the session token in place, save a copy of the encrypted data

					sessionTokenIndex := core.VersionBytes + core.PacketTypeBytes + core.ChonkleBytes
					sessionTokenData := packetData[sessionTokenIndex : sessionTokenIndex+core.EncryptedSessionTokenBytes]

					var sessionTokenDataCopy [core.EncryptedSessionTokenBytes]byte

					copy(sessionTokenDataCopy[:], sessionTokenData[:])

					sessionTokenSequenceIndex := sessionTokenIndex + core.EncryptedSessionTokenBytes
					index := sessionTokenSequenceIndex
					sessionTokenSequence := uint64(0)
					core.ReadUint64(packetData, &index, &sessionTokenSequence)

					// verify session token

					index = 0
					var sessionToken core.SessionToken
					result := core.ReadEncryptedSessionToken(sessionTokenData, &index, &sessionToken, authPublicKey, gatewayPrivateKey)
					if !result {
						core.Debug("could not decrypt session token")
						continue
					}

					if sessionToken.ExpireTimestamp < uint64(time.Now().Unix()) {
						core.Debug("session token has expired")
						continue
					}

					sessionIdIndex := core.PrefixBytes

					senderPublicKey := packetData[sessionIdIndex : sessionIdIndex+core.SessionIdBytes]

					var sessionId [core.SessionIdBytes]byte
					copy(sessionId[:], senderPublicKey[:])

					if !core.IdEqual(sessionToken.SessionId[:], sessionId[:]) {
						core.Debug("session id mismatch")
						continue
					}

					// decrypt packet

					sequenceIndex := sessionIdIndex + core.SessionIdBytes
					encryptedDataIndex := core.PrefixBytes + core.SessionIdBytes + core.SequenceBytes

					sequenceData := packetData[sequenceIndex : sequenceIndex+core.SequenceBytes]
					encryptedData := packetData[encryptedDataIndex : packetBytes-core.PittleBytes]

					nonce := make([]byte, core.NonceBytes_Box)
					for i := 0; i < core.SequenceBytes; i++ {
						nonce[i] = sequenceData[i]
					}

					err = core.Decrypt_Box(senderPublicKey, gatewayPrivateKey, nonce, encryptedData, len(encryptedData))
					if err != nil {
						core.Debug("could not decrypt payload packet")
						continue
					}

					// split packet into various pieces

					headerIndex := core.PrefixBytes

					payloadIndex := headerIndex + core.HeaderBytes
					payloadBytes := packetBytes - payloadIndex - core.PostfixBytes

					header := packetData[headerIndex : headerIndex+core.HeaderBytes]

					payload := packetData[payloadIndex : payloadIndex+payloadBytes]

					// ignore packet types we don't support

					packetType := header[core.SessionIdBytes+core.SequenceBytes+core.AckBytes+core.AckBitsBytes+core.GatewayIdBytes+core.ServerIdBytes]
					if packetType != core.PayloadPacket {
						core.Debug("invalid packet type: %d", packetType)
						continue
					}

					// get packet sequence number

					index = 0
					sequence := uint64(0)
					core.ReadUint64(sequenceData, &index, &sequence)

					// get packet gateway id

					gatewayIdIndex := headerIndex + core.SessionIdBytes + core.SequenceBytes + core.AckBytes + core.AckBitsBytes

					index = 0
					var packetGatewayId [core.GatewayIdBytes]byte
					core.ReadBytes(packetData[gatewayIdIndex:gatewayIdIndex+core.GatewayIdBytes], &index, packetGatewayId[:], core.GatewayIdBytes)

					// get challenge token data

					flagsIndex := core.SessionIdBytes + core.SequenceBytes + core.AckBytes + core.AckBitsBytes + core.GatewayIdBytes + core.ServerIdBytes + core.PacketTypeBytes
					var challengeTokenData []byte
					hasChallengeToken := (header[flagsIndex] & core.Flags_ChallengeToken) != 0
					if hasChallengeToken {
						challengeTokenData = payload[0:core.EncryptedChallengeTokenBytes]
						payload = payload[core.EncryptedChallengeTokenBytes:]
					}

					// clear flags in header

					header[flagsIndex] = 0

					// process payload packet

					core.Debug("payload is %d bytes", len(payload))

					sessionEntry := sessionMap_New[sessionId]
					if sessionEntry == nil {
						sessionEntry = sessionMap_Old[sessionId]
						if sessionEntry != nil {
							// migrate old -> new session map
							sessionMap_New[sessionId] = sessionEntry
						}
					}

					if sessionEntry == nil {

						// *** no session entry ***

						if hasChallengeToken {

							// payload packet has a challenge token (challenge/response)

							index := 0
							var challengeToken core.ChallengeToken
							result := core.ReadEncryptedChallengeToken(challengeTokenData, &index, &challengeToken, challengePrivateKey)
							if !result {
								core.Debug("challenge token did not decrypt")
								continue
							}

							if challengeToken.ExpireTimestamp <= uint64(time.Now().Unix()) {
								core.Debug("challenge token expired")
								continue
							}

							if !core.AddressEqual(&challengeToken.ClientAddress, from) {
								core.Debug("challenge token client address mismatch")
								continue
							}

							var sessionId [core.SessionIdBytes]byte
							for i := 0; i < core.SessionIdBytes; i++ {
								sessionId[i] = senderPublicKey[i]
							}

							// create new session entry

							sessionEntry := &SessionEntry{ReceivedSequence: challengeToken.Sequence}

							sessionEntry.SessionTokenChannel = make(chan SessionTokenUpdate, 1)
							copy(sessionEntry.SessionTokenData[:], sessionTokenDataCopy[:])
							sessionEntry.SessionTokenExpireTimestamp = sessionToken.ExpireTimestamp
							sessionEntry.SessionTokenSequence = sessionTokenSequence
							sessionEntry.ReceiveBandwidthBitsPerSecondMax = uint64(sessionToken.EnvelopeUpKbps * 1000.0)
							sessionEntry.PacketsPerSecondMax = uint64(float32(sessionToken.PacketsPerSecond) * 1.1)

							sessionEntry.ReceiveBandwidthBitsResetTime = time.Now().Add(time.Second)

							sessionMap_New[sessionId] = sessionEntry

							core.Info("new session %s from %s", core.IdString(sessionId[:]), from.String())

						} else {

							// respond with a challenge

							challengePacketData := make([]byte, MaxPacketSize)

							challengeToken := core.ChallengeToken{}
							challengeToken.ExpireTimestamp = uint64(time.Now().Unix() + ChallengeTokenTimeout)
							challengeToken.ClientAddress = *from
							challengeToken.Sequence = sequence

							nonce := [core.NonceBytes_Box]byte{}
							core.RandomBytes_InPlace(nonce[:])
							nonce[9] &= 1 ^ (1 << 0)
							nonce[9] |= (1 << 1)

							index := 0

							dummySessionToken := [core.EncryptedSessionTokenBytes]byte{}
							dummySessionTokenSequence := uint64(0)

							version := byte(0)
							core.WriteUint8(challengePacketData, &index, version)
							core.WriteUint8(challengePacketData, &index, core.ChallengePacket)
							chonkle := challengePacketData[index : index+core.ChonkleBytes]
							index += core.ChonkleBytes
							core.WriteBytes(challengePacketData, &index, dummySessionToken[:], core.EncryptedSessionTokenBytes)
							core.WriteUint64(challengePacketData, &index, dummySessionTokenSequence)
							core.WriteBytes(challengePacketData, &index, nonce[:], core.NonceBytes_Box)
							encryptStart := index
							core.WriteEncryptedChallengeToken(challengePacketData, &index, &challengeToken, challengePrivateKey)
							core.WriteUint64(challengePacketData, &index, sequence)
							core.WriteBytes(challengePacketData, &index, gatewayId[:], core.GatewayIdBytes)
							encryptFinish := index
							index += core.HMACBytes_Box
							pittle := challengePacketData[index : index+core.PittleBytes]
							index += core.PittleBytes

							challengePacketBytes := index
							challengePacketData = challengePacketData[:challengePacketBytes]

							core.Encrypt_Box(gatewayPrivateKey, sessionId[:], nonce[:], challengePacketData[encryptStart:encryptFinish], encryptFinish-encryptStart)

							// setup packet prefix and postfix

							var magic [core.MagicBytes]byte

							var fromAddressData [4]byte
							var fromAddressPort uint16

							var toAddressData [4]byte
							var toAddressPort uint16

							core.GetAddressData(gatewayAddress, fromAddressData[:], &fromAddressPort)
							core.GetAddressData(from, toAddressData[:], &toAddressPort)

							core.GenerateChonkle(chonkle[:], magic[:], fromAddressData[:], fromAddressPort, toAddressData[:], toAddressPort, challengePacketBytes)

							core.GeneratePittle(pittle[:], fromAddressData[:], fromAddressPort, toAddressData[:], toAddressPort, challengePacketBytes)

							if !core.BasicPacketFilter(challengePacketData, challengePacketBytes) {
								panic("basic packet filter failed")
							}

							if !core.AdvancedPacketFilter(challengePacketData, magic[:], fromAddressData[:], fromAddressPort, toAddressData[:], toAddressPort, challengePacketBytes) {
								panic("advanced packet filter failed")
							}

							// send it to the client

							if _, err := conn.WriteToUDP(challengePacketData, from); err != nil {
								core.Error("failed to send challenge packet to client: %v", err)
							}

							core.Debug("send %d byte challenge packet to %s", len(challengePacketData), from.String())

						}

						continue
					}

					// drop packets without the correct gateway id

					if !core.IdEqual(packetGatewayId[:], gatewayId[:]) {
						core.Debug("wrong gateway id")
						continue
					}

					// drop packets that are too old

					oldSequence := uint64(0)

					if sessionEntry.ReceivedSequence > OldSequenceThreshold {
						oldSequence = sessionEntry.ReceivedSequence - OldSequenceThreshold
					}

					if sequence < oldSequence {
						core.Debug("sequence number is too old: %d", sequence)
						continue
					}

					// drop packets that have already been forwarded to the server

					if sessionEntry.ReceivedPackets[sequence%OldSequenceThreshold] == sequence {
						core.Debug("packet %d has already been forwarded to the server", sequence)
					}

					// do we have enough bandwidth available to receive this packet?

					if sessionEntry.ReceiveBandwidthBitsResetTime.Before(time.Now()) {
						receiveBandwidthMbps := float64(sessionEntry.ReceiveBandwidthBitsAccumulator) / 1000000.0
						sessionEntry.ReceiveBandwidthBitsResetTime = time.Now().Add(time.Second)
						sessionEntry.ReceiveBandwidthBitsAccumulator = 0
						sessionEntry.PacketsReceivedInLastSecond = 0
						core.Debug("session %s is %.2f mbps", core.IdString(sessionId[:]), receiveBandwidthMbps)
					}

					wireBits := uint64(core.WirePacketBits(len(packetData)))

					canReceivePacket := true

					if sessionEntry.ReceiveBandwidthBitsAccumulator+wireBits <= sessionEntry.ReceiveBandwidthBitsPerSecondMax {
						sessionEntry.ReceiveBandwidthBitsAccumulator += wireBits
					} else {
						canReceivePacket = false
					}

					if !canReceivePacket {
						core.Debug("choke bw")
						continue
					}

					// too many packets per-second?

					if sessionEntry.PacketsReceivedInLastSecond > sessionEntry.PacketsPerSecondMax {
						canReceivePacket = false
						core.Debug("choke pps")
						continue						
					}

					sessionEntry.PacketsReceivedInLastSecond++

					// update session token

					if sessionEntry.SessionTokenExpireTimestamp-uint64(10) <= uint64(time.Now().Unix()) && !sessionEntry.UpdatingSessionToken && sessionEntry.SessionTokenCooldown.Before(time.Now()) {

						sessionEntry.UpdatingSessionToken = true

						if sessionEntry.SessionTokenRetryCount == 0 {
							core.Debug("updating session token %s", core.IdString(sessionToken.SessionId[:]))
						} else {
							core.Debug("updating session token %s retry #%d", core.IdString(sessionToken.SessionId[:]), sessionEntry.SessionTokenRetryCount)
						}

						go func(channel chan SessionTokenUpdate, inputSessionTokenData [core.EncryptedSessionTokenBytes]byte) {

							var netTransport = &http.Transport{
								Dial: (&net.Dialer{
									Timeout: time.Second,
								}).Dial,
								TLSHandshakeTimeout: time.Second,
							}

							var c = &http.Client{
								Timeout:   time.Second,
								Transport: netTransport,
							}

							r, err := http.NewRequest("POST", "http://localhost:60000/session_token", bytes.NewBuffer(inputSessionTokenData[:]))
							if err != nil {
								core.Debug("failed to create post request: %v", err)
								channel <- SessionTokenUpdate{}
								return
							}
							response, err := c.Do(r)

							if response == nil {
								core.Debug("nil response from post")
								channel <- SessionTokenUpdate{}
								return
							}

							defer response.Body.Close()

							if err != nil {
								core.Debug("error on post request: %s", err)
								channel <- SessionTokenUpdate{}
								return
							}

							responseData, err := ioutil.ReadAll(response.Body)
							if err != nil {
								core.Debug("error reading response data: %v")
								channel <- SessionTokenUpdate{}
								return
							}

							if len(responseData) != core.EncryptedSessionTokenBytes {
								core.Debug("bad response size: %d", len(responseData))
								channel <- SessionTokenUpdate{}
								return
							}

							sessionTokenData := make([]byte, core.EncryptedSessionTokenBytes)
							copy(sessionTokenData[:], responseData[:])

							index := 0
							var sessionToken core.SessionToken
							result := core.ReadEncryptedSessionToken(responseData[:], &index, &sessionToken, authPublicKey[:], gatewayPrivateKey[:])
							if !result {
								core.Debug("invalid session token")
								channel <- SessionTokenUpdate{}
								return
							}

							channel <- SessionTokenUpdate{SessionTokenData: sessionTokenData, ExpireTimestamp: sessionToken.ExpireTimestamp}

						}(sessionEntry.SessionTokenChannel, sessionTokenDataCopy)
					}

					if sessionEntry.UpdatingSessionToken {
						select {
						case update := <-sessionEntry.SessionTokenChannel:
							if len(update.SessionTokenData) != 0 {
								copy(sessionEntry.SessionTokenData[:], update.SessionTokenData[:])
								sessionEntry.SessionTokenExpireTimestamp = update.ExpireTimestamp
								sessionEntry.SessionTokenSequence++
								sessionEntry.SessionTokenRetryCount = 0
								core.Info("updated session token for session %s %d", core.IdString(sessionId[:]), sessionEntry.SessionTokenSequence)
							} else {
								core.Debug("failed to update session token %s :(", core.IdString(sessionId[:]))
								sessionEntry.SessionTokenRetryCount++
								sessionEntry.SessionTokenCooldown = time.Now().Add(time.Second)
							}
							sessionEntry.UpdatingSessionToken = false
						default:
						}
					}

					// forward payload packet to server

					forwardPacketData := make([]byte, MaxPacketSize)

					index = 0

					version := byte(0)

					core.WriteUint8(forwardPacketData, &index, version)
					core.WriteAddress(forwardPacketData, &index, gatewayInternalAddress)
					core.WriteAddress(forwardPacketData, &index, from)
					core.WriteBytes(forwardPacketData[:], &index, sessionEntry.SessionTokenData[:], core.EncryptedSessionTokenBytes)
					core.WriteUint64(forwardPacketData[:], &index, sessionEntry.SessionTokenSequence)
					core.WriteBytes(forwardPacketData, &index, header, core.HeaderBytes)
					core.WriteBytes(forwardPacketData, &index, payload, len(payload))

					forwardPacketBytes := index
					forwardPacketData = forwardPacketData[:forwardPacketBytes]

					if _, err := conn.WriteToUDP(forwardPacketData, serverAddress); err != nil {
						core.Error("failed to forward payload to server: %v", err)
					}

					core.Debug("send %d byte packet to %s", forwardPacketBytes, serverAddress.String())

					// mark packet as received

					if sessionEntry.ReceivedSequence < sequence {
						sessionEntry.ReceivedSequence = sequence
					}

					sessionEntry.ReceivedPackets[sequence%OldSequenceThreshold] = sequence
				}

				wg.Done()

			}(i)
		}
	}

	// -----------------------------------------------------------------

	// listen on internal address

	wg.Add(numThreads)

	{
		lc := net.ListenConfig{
			Control: func(network string, address string, c syscall.RawConn) error {
				err := c.Control(func(fileDescriptor uintptr) {
					err := unix.SetsockoptInt(int(fileDescriptor), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
					if err != nil {
						panic(fmt.Sprintf("failed to set reuse address socket option: %v", err))
					}

					err = unix.SetsockoptInt(int(fileDescriptor), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
					if err != nil {
						panic(fmt.Sprintf("failed to set reuse port socket option: %v", err))
					}
				})

				return err
			},
		}

		for i := 0; i < numThreads; i++ {

			go func(thread int) {

				lp, err := lc.ListenPacket(ctx, "udp", gatewayInternalAddress.String())
				if err != nil {
					panic(fmt.Sprintf("could not bind internal socket: %v", err))
				}

				conn := lp.(*net.UDPConn)
				defer conn.Close()

				if err := conn.SetReadBuffer(readBuffer); err != nil {
					panic(fmt.Sprintf("could not set internal connection read buffer size: %v", err))
				}

				if err := conn.SetWriteBuffer(writeBuffer); err != nil {
					panic(fmt.Sprintf("could not set internal connection write buffer size: %v", err))
				}

				buffer := [MaxPacketSize]byte{}

				for {

					packetBytes, from, err := conn.ReadFromUDP(buffer[:])
					if err != nil {
						core.Error("failed to read internal udp packet: %v", err)
						break
					}

					packetData := buffer[:packetBytes]

					core.Debug("recv internal %d byte packet from %s", packetBytes, from.String())

					if packetBytes < core.PacketTypeBytes+core.VersionBytes+core.AddressBytes+core.EncryptedSessionTokenBytes+core.SequenceBytes+core.HeaderBytes+core.MinPayloadBytes {
						core.Debug("internal packet is too small")
						continue
					}

					if packetData[0] != 0 {
						core.Debug("unknown internal packet version: %d", packetData[0])
						continue
					}

					if packetData[1] != core.PayloadPacket {
						core.Debug("unknown internal packet type: %d", packetData[1])
						continue
					}

					// read the client address the packet should be forwarded to

					index := core.VersionBytes + core.PacketTypeBytes
					var clientAddress net.UDPAddr
					core.ReadAddress(packetData, &index, &clientAddress)

					// grab the session token

					sessionTokenData := packetData[index : index+core.EncryptedSessionTokenBytes]
					index += core.EncryptedSessionTokenBytes

					// grab the session token sequence

					sessionTokenSequence := packetData[index : index+core.SequenceBytes]
					index += core.SequenceBytes

					// split the packet apart into sections

					headerIndex := core.VersionBytes + core.PacketTypeBytes + core.AddressBytes + core.EncryptedSessionTokenBytes + core.SequenceBytes

					payloadIndex := headerIndex + core.HeaderBytes
					payloadBytes := len(packetData) - payloadIndex

					core.Debug("payload bytes is %d", payloadBytes)

					header := packetData[headerIndex : headerIndex+core.HeaderBytes]
					payload := packetData[payloadIndex : payloadIndex+payloadBytes]

					// build the packet to send to the client

					forwardPacketData := make([]byte, MaxPacketSize)

					index = 0

					version := byte(0)

					encryptStart := core.PrefixBytes + core.SessionIdBytes + core.SequenceBytes

					core.WriteUint8(forwardPacketData, &index, version)
					core.WriteUint8(forwardPacketData, &index, core.PayloadPacket)
					chonkle := forwardPacketData[index : index+core.ChonkleBytes]
					index += core.ChonkleBytes
					core.WriteBytes(forwardPacketData, &index, sessionTokenData, core.EncryptedSessionTokenBytes)
					core.WriteBytes(forwardPacketData, &index, sessionTokenSequence, core.SequenceBytes)
					core.WriteBytes(forwardPacketData, &index, header, core.HeaderBytes)
					core.WriteBytes(forwardPacketData, &index, payload, payloadBytes)
					encryptFinish := index
					index += core.HMACBytes_Box
					pittle := forwardPacketData[index : index+core.PittleBytes]
					index += core.PittleBytes

					forwardPacketBytes := index
					forwardPacketData = forwardPacketData[:forwardPacketBytes]

					// encrypt the packet

					sessionId := header[:core.SessionIdBytes]

					sequenceData := header[core.SessionIdBytes : core.SessionIdBytes+core.SequenceBytes]

					index = 0
					sequence := uint64(0)
					core.ReadUint64(sequenceData, &index, &sequence)

					nonce := make([]byte, core.NonceBytes_Box)
					for i := 0; i < core.SequenceBytes; i++ {
						nonce[i] = sequenceData[i]
					}
					nonce[9] |= (1 << 0)
					nonce[9] &= 1 ^ (1 << 1)

					core.Encrypt_Box(gatewayPrivateKey, sessionId, nonce, forwardPacketData[encryptStart:encryptFinish], encryptFinish-encryptStart)

					// setup packet prefix and postfix

					var magic [core.MagicBytes]byte

					var fromAddressData [4]byte
					var fromAddressPort uint16

					var toAddressData [4]byte
					var toAddressPort uint16

					core.GetAddressData(gatewayAddress, fromAddressData[:], &fromAddressPort)
					core.GetAddressData(&clientAddress, toAddressData[:], &toAddressPort)

					core.GenerateChonkle(chonkle[:], magic[:], fromAddressData[:], fromAddressPort, toAddressData[:], toAddressPort, forwardPacketBytes)

					core.GeneratePittle(pittle[:], fromAddressData[:], fromAddressPort, toAddressData[:], toAddressPort, forwardPacketBytes)

					if !core.BasicPacketFilter(forwardPacketData, forwardPacketBytes) {
						panic("basic packet filter failed")
					}

					if !core.AdvancedPacketFilter(forwardPacketData, magic[:], fromAddressData[:], fromAddressPort, toAddressData[:], toAddressPort, forwardPacketBytes) {
						panic("advanced packet filter failed")
					}

					// send it to the client

					if _, err := publicSocket[thread].WriteToUDP(forwardPacketData, &clientAddress); err != nil {
						core.Error("failed to forward packet to client: %v", err)
					}

					core.Debug("send %d byte packet to %s", len(forwardPacketData), clientAddress.String())
				}

				wg.Done()

			}(i)
		}
	}

	// -----------------------------------------------------------------

	termChan := make(chan os.Signal, 1)
	signal.Notify(termChan, os.Interrupt, syscall.SIGTERM)
	<-termChan

	fmt.Println("\nshutting down")

	ctxCancelFunc()

	fmt.Println("shutdown completed")

	return 0
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	_, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(http.StatusText(http.StatusOK)))
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "hello world\n")
}
