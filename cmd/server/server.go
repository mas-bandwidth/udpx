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
const SequenceBufferSize = 1024

type SessionEntry struct {
	SendSequence uint64
	ReceiveSequence uint64
	ReceivedPackets [SequenceBufferSize]uint64
	AckedPackets [SequenceBufferSize]uint64
}

// Allows us to return an exit code and allows log flushes and deferred functions
// to finish before exiting.
func main() {
	os.Exit(mainReturnWithCode())
}

func mainReturnWithCode() int {

	serviceName := "udpx server"

	fmt.Printf("%s\n", serviceName)

	ctx, ctxCancelFunc := context.WithCancel(context.Background())

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

	udpPort := envvar.Get("UDP_PORT", "50000")

	var wg sync.WaitGroup

	wg.Add(numThreads)

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

			buffer := [MaxPacketSize]byte{}

			sessionMap_Old := make(map[[core.SessionIdBytes]byte]*SessionEntry)
			sessionMap_New := make(map[[core.SessionIdBytes]byte]*SessionEntry)

			swapTime := time.Now().Unix() + SessionMapSwapTime
			swapCount := 0

			for {

				packetBytes, _, err := conn.ReadFromUDP(buffer[:])
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

				if packetBytes <= 0 {
					continue
				}

				packetData := buffer[:packetBytes]

				index := 0

				var version uint8
				var gatewayInternalAddress net.UDPAddr
				var clientAddress net.UDPAddr
				var sessionId [core.SessionIdBytes]byte
				var sequence uint64
				var ack uint64
				var ack_bits [core.AckBitsBytes]byte
				var packetType byte
				var flags byte

				core.ReadUint8(packetData, &index, &version)

				if version != 0 {
					fmt.Printf("unknown packet version: %d\n", version)
					continue
				}

				core.ReadAddress(packetData, &index, &gatewayInternalAddress)
				core.ReadAddress(packetData, &index, &clientAddress)
				core.ReadBytes(packetData, &index, sessionId[:], core.SessionIdBytes)
				core.ReadUint64(packetData, &index, &sequence)
				core.ReadUint64(packetData, &index, &ack)
				core.ReadBytes(packetData, &index, ack_bits[:], core.AckBitsBytes)
				core.ReadUint8(packetData, &index, &packetType)
				core.ReadUint8(packetData, &index, &flags)

				if packetType != core.PayloadPacket {
					fmt.Printf("unknown packet type: %d\n", packetType)
					continue
				}

				if flags != 0 {
					fmt.Printf("unknown flags\n")
					continue
				}

				fmt.Printf("recv packet sequence = %d\n", sequence)
				fmt.Printf("recv packet ack = %d\n", ack)
				fmt.Printf("recv packet ack_bits = [%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x\n", 
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

				sessionEntry := sessionMap_New[sessionId]
				if sessionEntry == nil {
					sessionEntry = sessionMap_Old[sessionId]
					if sessionEntry == nil {
						// add new session entry
						sessionEntry = &SessionEntry{SendSequence: ack+10000, ReceiveSequence: sequence}
						sessionMap_New[sessionId] = sessionEntry
						fmt.Printf("new session %s from %s\n", core.SessionIdString(sessionId[:]), clientAddress.String())
					} else {
						// migrate old -> new session map
						sessionMap_New[sessionId] = sessionEntry
					}
				}

				if sessionEntry == nil {
					// this should never happen
					fmt.Printf("no session entry\n")
					continue
				}

				if sessionEntry.ReceiveSequence < sequence {
					sessionEntry.ReceiveSequence = sequence
				}

				sessionEntry.ReceivedPackets[sequence%SequenceBufferSize] = sequence

				payload := packetData[index:]

				fmt.Printf("received packet %d from %s with %d byte payload\n", sequence, core.SessionIdString(sessionId[:]), len(payload))

				if len(payload) != core.MinPayloadBytes {
					fmt.Printf("payload size mismatch. expected %d, got %d\n", core.MinPayloadBytes, len(payload))
					continue
				}

				for i := 0; i < core.MinPayloadBytes; i++ {
					if payload[i] != byte(i) {
						panic(fmt.Sprintf("payload data mismatch at index %d. expected %d, got %d\n", i, byte(i), payload[i]))
					}
				}

				// process acks

				var ackBuffer [SequenceBufferSize]uint64

				acks := core.ProcessAcks(ack, ack_bits[:], sessionEntry.AckedPackets[:], ackBuffer[:])						

				for i := range acks {
					fmt.Printf("ack %d\n", acks[i])
					sessionEntry.AckedPackets[acks[i]%SequenceBufferSize] = acks[i]
				}

				// temporary: dummy response to test server -> gateway -> client packet delivery

				responsePacketData := make([]byte, MaxPacketSize)

				dummyPayload := make([]byte, core.MinPayloadBytes)
				for i := 0; i < core.MinPayloadBytes; i++ {
					dummyPayload[i] = byte(i)
				}

				index = 0

				version = byte(0)
				flags = byte(0)

				send_sequence := sessionEntry.SendSequence
				send_ack := sessionEntry.ReceiveSequence
				var send_ack_bits [core.AckBitsBytes]byte

				core.GetAckBits(sessionEntry.ReceiveSequence, sessionEntry.ReceivedPackets[:], send_ack_bits[:])

				// todo: debug stuff

				fmt.Printf("send packet sequence = %d\n", send_sequence)
				fmt.Printf("send packet ack = %d\n", send_ack)
				fmt.Printf("send packet ack_bits = [%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x\n", 
					send_ack_bits[0],
					send_ack_bits[1],
					send_ack_bits[2],
					send_ack_bits[3],
					send_ack_bits[4],
					send_ack_bits[5],
					send_ack_bits[6],
					send_ack_bits[7],
					send_ack_bits[8],
					send_ack_bits[9],
					send_ack_bits[10],
					send_ack_bits[11],
					send_ack_bits[12],
					send_ack_bits[13],
					send_ack_bits[14],
					send_ack_bits[15],
					send_ack_bits[16],
					send_ack_bits[17],
					send_ack_bits[18],
					send_ack_bits[19],
					send_ack_bits[20],
					send_ack_bits[21],
					send_ack_bits[22],
					send_ack_bits[23],
					send_ack_bits[24],
					send_ack_bits[25],
					send_ack_bits[26],
					send_ack_bits[27],
					send_ack_bits[28],
					send_ack_bits[29],
					send_ack_bits[30],
					send_ack_bits[31])

				// ------------------

				sessionEntry.SendSequence++

				core.WriteUint8(responsePacketData, &index, version)
				core.WriteUint8(responsePacketData, &index, core.PayloadPacket)
				core.WriteAddress(responsePacketData, &index, &clientAddress)
				core.WriteBytes(responsePacketData, &index, sessionId[:], core.SessionIdBytes)
				core.WriteUint64(responsePacketData, &index, send_sequence)
				core.WriteUint64(responsePacketData, &index, send_ack)
				core.WriteBytes(responsePacketData, &index, send_ack_bits[:], len(send_ack_bits))
				core.WriteUint8(responsePacketData, &index, core.PayloadPacket)
				core.WriteUint8(responsePacketData, &index, flags)
				core.WriteBytes(responsePacketData, &index, dummyPayload, len(dummyPayload))

				responsePacketBytes := index
				responsePacketData = responsePacketData[:responsePacketBytes]

				if _, err := conn.WriteToUDP(responsePacketData, &gatewayInternalAddress); err != nil {
					core.Error("failed to send response payload to gateway: %v", err)
				}
				fmt.Printf("send %d byte response to %s\n", responsePacketBytes, gatewayInternalAddress.String())

			}

			wg.Done()

		}(i)
	}

	fmt.Printf("started udp server on port %s\n", udpPort)

	// Wait for shutdown signal
	termChan := make(chan os.Signal, 1)
	signal.Notify(termChan, os.Interrupt, syscall.SIGTERM)
	<-termChan

	fmt.Println("\nshutting down")

	ctxCancelFunc()

	// wait for something ...

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
