/*
   UDPX is Copyright (c) 2022, Network Next, Inc. All rights reserved.

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
	"fmt"
	"os"
	"os/exec"
)

const (
	clientBin       = "./dist/client"
	gatewayBin      = "./dist/gateway"
	serverBin       = "./dist/server"
	authBin         = "./dist/auth"
	connectTokenBin = "./dist/connect_token"
)

func client(port uint16) *exec.Cmd {

	// get connect token

	connect_token_cmd := exec.Command(connectTokenBin)
	if connect_token_cmd == nil {
		panic("could not exec connect token")
	}

	connect_token_cmd.Env = os.Environ()
	connect_token_cmd.Env = append(connect_token_cmd.Env, "GATEWAY_ADDRESS=127.0.0.1:40000")
	connect_token_cmd.Env = append(connect_token_cmd.Env, "GATEWAY_PUBLIC_KEY=vnIjsJWZzgq+nS9t3KU7ch5BFhgDkm2U2bm7/2W6eRs=")
	connect_token_cmd.Env = append(connect_token_cmd.Env, "GATEWAY_PRIVATE_KEY=qmnxBZs2UElVT4SXCdDuX4td+qtPkuXLL5VdOE0vvcA=")
	connect_token_cmd.Env = append(connect_token_cmd.Env, "AUTH_PRIVATE_KEY=VmmdIRwxUb7vmzupzHbBHqJF3WPpLrp0Y0EzepAzny0=")

	connectToken, err := connect_token_cmd.Output()
	if err != nil {
		panic("could not get connect token output")
	}

	// run client

	client_cmd := exec.Command(clientBin)
	if client_cmd == nil {
		panic("could not exec client!\n")
		return nil
	}

	client_cmd.Env = os.Environ()
	client_cmd.Env = append(client_cmd.Env, fmt.Sprintf("CONNECT_TOKEN=%s", connectToken))
	client_cmd.Env = append(client_cmd.Env, fmt.Sprintf("UDP_PORT=%d", port))
	client_cmd.Env = append(client_cmd.Env, fmt.Sprintf("CLIENT_ADDRESS=127.0.0.1:%d", port))

	// client_cmd.Stdout = os.Stdout
	// client_cmd.Stderr = os.Stderr

	client_cmd.Start()

	return client_cmd
}

func gateway() *exec.Cmd {

	cmd := exec.Command(gatewayBin)
	if cmd == nil {
		panic("could not create gateway!\n")
		return nil
	}

	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "HTTP_PORT=40000")
	cmd.Env = append(cmd.Env, "UDP_PORT=40000")
	cmd.Env = append(cmd.Env, "GATEWAY_ADDRESS=127.0.0.1:40000")
	cmd.Env = append(cmd.Env, "GATEWAY_INTERNAL_ADDRESS=127.0.0.1:40001")
	cmd.Env = append(cmd.Env, "GATEWAY_PRIVATE_KEY=qmnxBZs2UElVT4SXCdDuX4td+qtPkuXLL5VdOE0vvcA=")
	cmd.Env = append(cmd.Env, "AUTH_PUBLIC_KEY=i9XuIDN5ePgWiRGZZoxNKjQv3ZC9JAfMjXGTIr4peQM=")
	cmd.Env = append(cmd.Env, "SERVER_ADDRESS=127.0.0.1:50000")

	// cmd.Stdout = os.Stdout
	// cmd.Stderr = os.Stderr

	cmd.Start()

	return cmd
}

func server() *exec.Cmd {
	cmd := exec.Command(serverBin)
	if cmd == nil {
		panic("could not create server!\n")
		return nil
	}
	cmd.Env = append(cmd.Env, "HTTP_PORT=50000")
	cmd.Env = append(cmd.Env, "UDP_PORT=50000")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Start()
	return cmd
}

func auth() *exec.Cmd {

	cmd := exec.Command(authBin)

	if cmd == nil {
		panic("could not create auth!\n")
		return nil
	}

	cmd.Env = append(cmd.Env, "HTTP_PORT=60000")
	cmd.Env = append(cmd.Env, "GATEWAY_ADDRESS=127.0.0.1:40000")
	cmd.Env = append(cmd.Env, "GATEWAY_PUBLIC_KEY=vnIjsJWZzgq+nS9t3KU7ch5BFhgDkm2U2bm7/2W6eRs=")
	cmd.Env = append(cmd.Env, "GATEWAY_PRIVATE_KEY=qmnxBZs2UElVT4SXCdDuX4td+qtPkuXLL5VdOE0vvcA=")
	cmd.Env = append(cmd.Env, "AUTH_PUBLIC_KEY=i9XuIDN5ePgWiRGZZoxNKjQv3ZC9JAfMjXGTIr4peQM=")
	cmd.Env = append(cmd.Env, "AUTH_PRIVATE_KEY=VmmdIRwxUb7vmzupzHbBHqJF3WPpLrp0Y0EzepAzny0=")

	// cmd.Stdout = os.Stdout
	// cmd.Stderr = os.Stderr

	cmd.Start()

	return cmd
}

func soak() {

	const NumClients = 10

	auth_cmd := auth()
	server_cmd := server()
	gateway_cmd := gateway()
	client_cmd := make([]*exec.Cmd, NumClients)
	for i := 0; i < NumClients; i++ {
		client_cmd[i] = client(uint16(30000 + i))
	}

	server_cmd.Wait()

	auth_cmd.Process.Signal(os.Interrupt)
	auth_cmd.Wait()

	gateway_cmd.Process.Signal(os.Interrupt)
	gateway_cmd.Wait()

	for i := 0; i < NumClients; i++ {
		client_cmd[i].Process.Signal(os.Interrupt)
		client_cmd[i].Wait()
	}
}

func main() {
	soak()
}
