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
const QueueSize = 1024

type SessionEntry struct {
	SendSequence                  uint64
	ReceiveSequence               uint64
	AckedPackets                  [SequenceBufferSize]uint64
	ReceivedPackets               [SequenceBufferSize]uint64
	SendPayloadId                 uint64
	SequenceToPayloadId           [SequenceBufferSize]uint64
	SendBandwidthBitsAccumulator  uint64
	SendBandwidthBitsPerSecondMax uint64
	SendBandwidthBitsResetTime    time.Time
}

// Allows us to return an exit code and allows log flushes and deferred functions
// to finish before exiting.
func main() {
	os.Exit(mainReturnWithCode())
}

func mainReturnWithCode() int {

	serviceName := "udpx server"

	core.Info("%s", serviceName)

	// configure

	ctx, ctxCancelFunc := context.WithCancel(context.Background())

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

	serverId := core.RandomBytes(core.ServerIdBytes)

	core.Info("starting server on port %s", udpPort)

	core.Info("server id is %s", core.IdString(serverId))

	// --------------------------------------------------------------------

	// start web server
	{
		router := mux.NewRouter()
		router.HandleFunc("/health", healthHandler).Methods("GET")
		router.HandleFunc("/status", statusHandler).Methods("GET")

		httpPort := envvar.Get("HTTP_PORT", "50000")

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

	// --------------------------------------------------------------------

	// start udp server

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

				// read packet

				packetBytes, _, err := conn.ReadFromUDP(buffer[:])
				if err != nil {
					core.Debug("failed to read udp packet: %v", err)
					break
				}

				if packetBytes <= 0 {
					continue
				}

				packetData := buffer[:packetBytes]

				// swap session map periodically. times out old sessions without O(n) walk or contention

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

				// read packet

				index := 0

				var version uint8
				var gatewayInternalAddress net.UDPAddr
				var clientAddress net.UDPAddr
				var sessionId [core.SessionIdBytes]byte
				var sequence uint64
				var ack uint64
				var ack_bits [core.AckBitsBytes]byte
				var packetGatewayId [core.GatewayIdBytes]byte
				var packetServerId [core.ServerIdBytes]byte
				var packetType byte
				var flags byte

				core.ReadUint8(packetData, &index, &version)

				if version != 0 {
					core.Debug("unknown packet version: %d", version)
					continue
				}

				core.ReadAddress(packetData, &index, &gatewayInternalAddress)
				core.ReadAddress(packetData, &index, &clientAddress)
				sessionTokenData := packetData[index : index+core.EncryptedSessionTokenBytes]
				index += core.EncryptedSessionTokenBytes
				sessionTokenSequence := packetData[index : index+core.SequenceBytes]
				index += core.SequenceBytes
				core.ReadBytes(packetData, &index, sessionId[:], core.SessionIdBytes)
				core.ReadUint64(packetData, &index, &sequence)
				core.ReadUint64(packetData, &index, &ack)
				core.ReadBytes(packetData, &index, ack_bits[:], core.AckBitsBytes)
				core.ReadBytes(packetData, &index, packetGatewayId[:], core.GatewayIdBytes)
				core.ReadBytes(packetData, &index, packetServerId[:], core.ServerIdBytes)
				core.ReadUint8(packetData, &index, &packetType)
				core.ReadUint8(packetData, &index, &flags)

				if packetType != core.PayloadPacket {
					core.Debug("unknown packet type: %d", packetType)
					continue
				}

				if flags != 0 {
					core.Debug("unknown flags")
					continue
				}

				core.Debug("recv packet sequence = %d", sequence)
				core.Debug("recv packet ack = %d", ack)
				core.Debug("recv packet ack_bits = [%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x]",
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

				// lookup or create a session entry

				sessionEntry := sessionMap_New[sessionId]
				
				if sessionEntry == nil {
				
					sessionEntry = sessionMap_Old[sessionId]
				
					if sessionEntry == nil {
						
						// add new session entry

						sessionEntry = &SessionEntry{}
						sessionEntry.SendSequence = ack + 10000
						sessionEntry.ReceiveSequence = sequence
						sessionEntry.SendBandwidthBitsPerSecondMax = 10000 * 1000 // todo: gateway needs to pass this up to server (envelopeDownKbps)
						sessionEntry.SendBandwidthBitsResetTime = time.Now().Add(time.Second)
						for i := range sessionEntry.SequenceToPayloadId {
							sessionEntry.SequenceToPayloadId[i] = ^uint64(0)
						}
						
						sessionMap_New[sessionId] = sessionEntry
						
						core.Info("new session %s from %s", core.IdString(sessionId[:]), clientAddress.String())
				
					} else {
				
						// migrate old -> new session map
						sessionMap_New[sessionId] = sessionEntry
				
					}
				}

				if sessionEntry == nil {
					// this should never happen
					panic("no session entry")
				}

				// update received packet reliability

				if sessionEntry.ReceiveSequence < sequence {
					sessionEntry.ReceiveSequence = sequence
				}

				sessionEntry.ReceivedPackets[sequence%SequenceBufferSize] = sequence

				// validate payload (temporary)

				payload := packetData[index:]

				core.Debug("received packet %d from %s with %d byte payload", sequence, core.IdString(sessionId[:]), len(payload))

				if len(payload) != core.MinPayloadBytes {
					panic(fmt.Sprintf("payload size mismatch. expected %d, got %d\n", core.MinPayloadBytes, len(payload)))
				}

				for i := 0; i < core.MinPayloadBytes; i++ {
					if payload[i] != byte(i) {
						panic(fmt.Sprintf("payload data mismatch at index %d. expected %d, got %d\n", i, byte(i), payload[i]))
					}
				}

				// process packet acks

				var ackBuffer [SequenceBufferSize]uint64

				acks := core.ProcessAcks(ack, ack_bits[:], sessionEntry.AckedPackets[:], ackBuffer[:])

				for i := range acks {
					core.Debug("ack packet %d", acks[i])
					sessionEntry.AckedPackets[acks[i]%SequenceBufferSize] = acks[i]
					payloadAck := sessionEntry.SequenceToPayloadId[acks[i]%SequenceBufferSize]
					if payloadAck != ^uint64(0) {
						core.Debug("ack payload %d for session %s", payloadAck, core.IdString(sessionId[:]))
					}
				}

				// get response payload (temporary)

				responsePayload := make([]byte, core.MinPayloadBytes)
				for i := 0; i < core.MinPayloadBytes; i++ {
					responsePayload[i] = byte(i)
				}

				// do we have enough bandwidth available to send this packet?

				if sessionEntry.SendBandwidthBitsResetTime.Before(time.Now()) {
					sendBandwidthMbps := float64(sessionEntry.SendBandwidthBitsAccumulator) / 1000000.0
					sessionEntry.SendBandwidthBitsResetTime = time.Now().Add(time.Second)
					sessionEntry.SendBandwidthBitsAccumulator = 0
					core.Debug("session %s is %.2f mbps", core.IdString(sessionId[:]), sendBandwidthMbps)
				}

				gatewayPacketBytes := core.PacketBytesFromPayload(len(responsePayload))

				wireBits := uint64(core.WirePacketBits(gatewayPacketBytes))

				canSendPacket := true

				if sessionEntry.SendBandwidthBitsAccumulator + wireBits <= sessionEntry.SendBandwidthBitsPerSecondMax {
					sessionEntry.SendBandwidthBitsAccumulator += wireBits
				} else {
					canSendPacket = false
				}

				if !canSendPacket {
					core.Info("choke")
					continue
				}

				// build response payload packet

				version = byte(0)
				flags = byte(0)

				send_sequence := sessionEntry.SendSequence
				send_ack := sessionEntry.ReceiveSequence
				var send_ack_bits [core.AckBitsBytes]byte

				core.GetAckBits(sessionEntry.ReceiveSequence, sessionEntry.ReceivedPackets[:], send_ack_bits[:])

				core.Debug("send packet sequence = %d", send_sequence)
				core.Debug("send packet ack = %d", send_ack)
				core.Debug("send packet ack_bits = [%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x,%x]",
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

				// write response payload packet

				responsePacketData := make([]byte, MaxPacketSize)

				index = 0

				core.WriteUint8(responsePacketData, &index, version)
				core.WriteUint8(responsePacketData, &index, core.PayloadPacket)
				core.WriteAddress(responsePacketData, &index, &clientAddress)
				core.WriteBytes(responsePacketData, &index, sessionTokenData[:], core.EncryptedSessionTokenBytes)
				core.WriteBytes(responsePacketData, &index, sessionTokenSequence[:], core.SequenceBytes)
				core.WriteBytes(responsePacketData, &index, sessionId[:], core.SessionIdBytes)
				core.WriteUint64(responsePacketData, &index, send_sequence)
				core.WriteUint64(responsePacketData, &index, send_ack)
				core.WriteBytes(responsePacketData, &index, send_ack_bits[:], len(send_ack_bits))
				core.WriteBytes(responsePacketData, &index, packetGatewayId[:], core.GatewayIdBytes)
				core.WriteBytes(responsePacketData, &index, serverId[:], core.ServerIdBytes)
				core.WriteUint8(responsePacketData, &index, core.PayloadPacket)
				core.WriteUint8(responsePacketData, &index, flags)
				core.WriteBytes(responsePacketData, &index, responsePayload, len(responsePayload))

				responsePacketBytes := index
				responsePacketData = responsePacketData[:responsePacketBytes]

				// send it to the client

				if _, err := conn.WriteToUDP(responsePacketData, &gatewayInternalAddress); err != nil {
					core.Error("failed to send response payload to gateway: %v", err)
				}

				core.Debug("send %d byte response to %s", responsePacketBytes, gatewayInternalAddress.String())

				// update reliability

				sessionEntry.SequenceToPayloadId[sessionEntry.SendPayloadId%SequenceBufferSize] = sessionEntry.SendPayloadId
				sessionEntry.SendPayloadId++
				sessionEntry.SendSequence++
			}

			wg.Done()

		}(i)
	}

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
