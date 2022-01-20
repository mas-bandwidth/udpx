/*
   UDPX Copyright (c) 2022, Network Next, Inc. All rights reserved.

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

	"github.com/networknext/udpx/modules/core"
	"github.com/networknext/udpx/modules/envvar"

	"github.com/gorilla/mux"
	"golang.org/x/sys/unix"
)

const MaxPacketSize = 1500

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

				fmt.Printf("received %d byte udp packet from %s\n", packetBytes, from)

				// temp: reflect packet back to client to verify that client receives packets
				if _, err := conn.WriteToUDP(packetData, from); err != nil {
					core.Error("failed to write udp response packet: %v", err)
				}
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
