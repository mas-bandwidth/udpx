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

	"github.com/networknext/udpx/modules/core"
	"github.com/networknext/udpx/modules/envvar"

	"github.com/gorilla/mux"
	"golang.org/x/sys/unix"
)

const MaxPacketSize = 1500
const SessionMapSwapTime = 60

type SessionEntry struct {
	sequence uint64
}

func main() {
	os.Exit(mainReturnWithCode())
}

func mainReturnWithCode() int {

	serviceName := "udpx gateway"

	fmt.Printf("%s\n", serviceName)

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
	if err != nil || len(gatewayPrivateKey) != core.PrivateKeyBytes {
		core.Error("missing or invalid GATEWAY_PRIVATE_KEY: %v\n", err)
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
			fmt.Printf("started http server on port %s\n", httpPort)
			err := srv.ListenAndServe()
			if err != nil {
				core.Error("failed to start http server: %v", err)
				return
			}
		}()
	}

	// --------------------------------------------------

	// listen for udp packets on public address

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
						core.Error("failed to read udp packet: %v", err)
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
						fmt.Printf("packet is too small\n")
						continue
					}

					packetData := buffer[:packetBytes]

					fmt.Printf("recv %d byte packet from %s\n", packetBytes, from)

					// drop unknown packet versions

					if packetData[0] != 0 {
						fmt.Printf("unknown packet version\n")
						continue
					}

					// packet filter

					var magic [8]byte
					
					var fromAddressData [4]byte
					var fromAddressPort uint16
			
					var toAddressData [4]byte
					var toAddressPort uint16
			
					core.GetAddressData(from, fromAddressData[:], &fromAddressPort)
					core.GetAddressData(gatewayAddress, toAddressData[:], &toAddressPort)

					if !core.BasicPacketFilter(packetData, packetBytes) {
						fmt.Printf("basic packet filter failed\n")
						continue
					}

					if !core.AdvancedPacketFilter(packetData, magic[:], fromAddressData[:], fromAddressPort, toAddressData[:], toAddressPort, packetBytes) {
						fmt.Printf("advanced packet filter failed\n")
						continue
					}

					// decrypt

					publicKeyIndex := core.VersionBytes + core.ChonkleBytes
					sequenceIndex := core.VersionBytes + core.ChonkleBytes + core.SessionIdBytes
					encryptedDataIndex := core.VersionBytes + core.ChonkleBytes + core.SessionIdBytes + core.SequenceBytes

					senderPublicKey := packetData[publicKeyIndex:publicKeyIndex+core.SessionIdBytes]
					sequenceData := packetData[sequenceIndex:sequenceIndex+core.SequenceBytes]
					encryptedData := packetData[encryptedDataIndex:packetBytes-core.PittleBytes]

					nonce := make([]byte, core.NonceBytes)
					for i := 0; i < core.SequenceBytes; i++ {
						nonce[i] = sequenceData[i]
					}

					err = core.Decrypt(senderPublicKey, gatewayPrivateKey, nonce, encryptedData, len(encryptedData))
					if err != nil {
						fmt.Printf("decryption failed\n")
						continue
					}

					// decrypt payload

					payloadIndex := core.VersionBytes + core.ChonkleBytes
					payloadData := packetData[payloadIndex:packetBytes-core.PittleBytes-core.HMACBytes]
					payloadBytes := len(payloadData)

					// what sort of packet is this?

					packetType := payloadData[core.SessionIdBytes+core.SequenceBytes+core.AckBytes+core.AckBitsBytes]

					switch packetType {

						case core.PayloadPacket:

							// *** PAYLOAD PACKET ***

							var sessionId [core.SessionIdBytes]byte
							for i := 0; i < core.SessionIdBytes; i++ {
								sessionId[i] = senderPublicKey[i]
							}

							sessionEntry := sessionMap_New[sessionId]
							if sessionEntry == nil {
								sessionEntry = sessionMap_Old[sessionId]
								if sessionEntry != nil {
									// migrate old -> new
									sessionMap_New[sessionId] = sessionEntry
								}
							}

							if sessionEntry == nil {
								// todo: so temporary...
								challengePacketData := make([]byte, 1)
								challengePacketData[0] = core.ChallengePacket
								if _, err := conn.WriteToUDP(challengePacketData, from); err != nil {
									core.Error("failed to send challenge packet to client: %v", err)
								}
								fmt.Printf("send %d byte challenge packet to %s\n", len(challengePacketData), from.String())
								continue
							}

							// forward payload packet to server

							forwardPacketData := make([]byte, MaxPacketSize)

							index := 0
							core.WriteAddress(forwardPacketData, &index, gatewayInternalAddress)
							core.WriteAddress(forwardPacketData, &index, from)
							core.WriteBytes(forwardPacketData, &index, payloadData, payloadBytes)	// todo: obvs this should be zero copy

							forwardPacketBytes := index
							forwardPacketData = forwardPacketData[:forwardPacketBytes]

							if _, err := conn.WriteToUDP(forwardPacketData, serverAddress); err != nil {
								core.Error("failed to forward payload to server: %v", err)
							}
							fmt.Printf("send %d byte packet to %s\n", forwardPacketBytes, serverAddress.String())

						case core.ChallengeResponsePacket:

							// *** CHALLENGE RESPONSE PACKET ***

							var sessionId [core.SessionIdBytes]byte
							for i := 0; i < core.SessionIdBytes; i++ {
								sessionId[i] = senderPublicKey[i]
							}

							sessionEntry := &SessionEntry{}
							sessionMap_New[sessionId] = sessionEntry
						}
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

					fmt.Printf("recv internal %d byte packet from %s\n", packetBytes, from.String())

					if packetBytes <= core.PacketTypeBytes + core.VersionBytes + core.AddressBytes {
						fmt.Printf("internal packet is too small\n")
						continue
					}

					if packetData[0] != 0 {
						fmt.Printf("unknown internal packet type: %d\n", packetData[0])
						continue
					}

					if packetData[1] != 0 {
						fmt.Printf("unknown internal packet version: %d\n", packetData[1])
						continue
					}

					index := core.PacketTypeBytes + core.VersionBytes

					var clientAddress net.UDPAddr

					core.ReadAddress(packetData, &index, &clientAddress)

					packetData = packetData[index:]
					packetBytes = len(packetData)

					if _, err := publicSocket[thread].WriteToUDP(packetData, &clientAddress); err != nil {
						core.Error("failed to forward packet to client: %v", err)
					}
					fmt.Printf("send %d byte packet to %s\n", packetBytes, clientAddress.String())
				}

				wg.Done()

			}(i)
		}
	}

	// -----------------------------------------------------------------

	fmt.Printf("started udp server on port %s\n", udpPort)

	// Wait for shutdown signal
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
