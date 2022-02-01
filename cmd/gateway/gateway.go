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

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"

import (
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
	"bytes"

	"github.com/networknext/udpx/modules/core"
	"github.com/networknext/udpx/modules/envvar"

	"github.com/gorilla/mux"
	"golang.org/x/sys/unix"
)

const MaxPacketSize = 1500
const SessionMapSwapTime = 60
const ChallengeTokenTimeout = 10
const OldSequenceThreshold = 100

type SessionEntry struct {
	ReceivedSequence     uint64
	ReceivedPackets      [OldSequenceThreshold]uint64
	UpdatingSessionToken bool
	SessionToken         chan [1][]byte
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

					// before we decrypt the session token, save a copy so we can use it later

					sessionTokenIndex := core.VersionBytes + core.PacketTypeBytes + core.ChonkleBytes
					sessionTokenData := packetData[sessionTokenIndex : sessionTokenIndex+core.EncryptedSessionTokenBytes]

					var sessionTokenDataCopy [core.EncryptedSessionTokenBytes]byte

					copy(sessionTokenDataCopy[:], sessionTokenData[:])

					// verify session token

					index := 0
					var sessionToken core.SessionToken
					result := core.ReadEncryptedSessionToken(sessionTokenData, &index, &sessionToken, authPublicKey, gatewayPrivateKey)
					if !result {
						// todo: debug
						core.Error("could not decrypt session token")
						continue
					}

					if sessionToken.ExpireTimestamp < uint64(time.Now().Unix()) {
						// todo: debug
						core.Error("session token has expired")
						continue
					}

					sessionIdIndex := core.PrefixBytes

					senderPublicKey := packetData[sessionIdIndex : sessionIdIndex+core.SessionIdBytes]

					var sessionId [core.SessionIdBytes]byte
					copy(sessionId[:], senderPublicKey[:])

					if !core.IdEqual(sessionToken.SessionId[:], sessionId[:]) {
						core.Error("session id mismatch")
						continue
					}

					// decrypt packet

					sequenceIndex := sessionIdIndex + core.SessionIdBytes
					encryptedDataIndex := core.VersionBytes + core.PacketTypeBytes + core.ChonkleBytes + core.EncryptedSessionTokenBytes + core.SessionIdBytes + core.SequenceBytes

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

							sessionEntry := &SessionEntry{ReceivedSequence: challengeToken.Sequence}
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

							version := byte(0)
							core.WriteUint8(challengePacketData, &index, version)
							core.WriteUint8(challengePacketData, &index, core.ChallengePacket)
							chonkle := challengePacketData[index : index+core.ChonkleBytes]
							index += core.ChonkleBytes
							core.WriteBytes(challengePacketData, &index, dummySessionToken[:], core.EncryptedSessionTokenBytes)
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

					// update session token

					if sessionToken.ExpireTimestamp - uint64(10) <= uint64(time.Now().Unix()) && !sessionEntry.UpdatingSessionToken {

						sessionEntry.UpdatingSessionToken = true

						fmt.Printf("updating session token for session %s\n", core.IdString(sessionToken.SessionId[:]))

						go func(updateSessionTokenData [core.EncryptedSessionTokenBytes]byte) {

							fmt.Printf("update session token data %d bytes\n", len(updateSessionTokenData))

							var netTransport = &http.Transport{
							  Dial: (&net.Dialer{
							    Timeout: 5 * time.Second,
							  }).Dial,
							  TLSHandshakeTimeout: 5 * time.Second,
							}
							
							var c = &http.Client{
							  Timeout: time.Second * 5,
							  Transport: netTransport,
							}
														
							r, err := http.NewRequest("POST", "http://localhost:60000/session_token", bytes.NewBuffer(updateSessionTokenData[:]))
							if err != nil {
							    fmt.Printf("failed to create post request for session %s: %v\n", core.IdString(sessionToken.SessionId[:]), err)
							    return
							}
							response, err := c.Do(r)

							if response == nil {
								fmt.Printf("nil response\n")
							} else {
								fmt.Printf("response: %s, %v\n", response.Status, err)
							}

						}(sessionTokenDataCopy)
					}

					// forward payload packet to server

					forwardPacketData := make([]byte, MaxPacketSize)

					index = 0

					version := byte(0)

					core.WriteUint8(forwardPacketData, &index, version)
					core.WriteAddress(forwardPacketData, &index, gatewayInternalAddress)
					core.WriteAddress(forwardPacketData, &index, from)
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

					if packetBytes <= core.PacketTypeBytes+core.VersionBytes+core.AddressBytes {
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

					// split the packet apart into sections

					headerIndex := core.VersionBytes + core.PacketTypeBytes + core.AddressBytes

					payloadIndex := headerIndex + core.HeaderBytes
					payloadBytes := len(packetData) - payloadIndex

					core.Debug("payload bytes is %d", payloadBytes)

					header := packetData[headerIndex : headerIndex+core.HeaderBytes]
					payload := packetData[payloadIndex : payloadIndex+payloadBytes]

					// build the packet to send to the client

					forwardPacketData := make([]byte, MaxPacketSize)

					index = 0

					version := byte(0)

					encryptStart := core.VersionBytes + core.PacketTypeBytes + core.ChonkleBytes + core.EncryptedSessionTokenBytes + core.SessionIdBytes + core.SequenceBytes

					core.WriteUint8(forwardPacketData, &index, version)
					core.WriteUint8(forwardPacketData, &index, core.PayloadPacket)
					chonkle := forwardPacketData[index : index+core.ChonkleBytes]
					index += core.ChonkleBytes
					// todo: session token
					index += core.EncryptedSessionTokenBytes
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
