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
	"bytes"
	"os"
	"os/exec"
)

const (
	clientBin   = "./dist/client"
	gatewayBin = "./dist/gateway"
	serverBin  = "./dist/server"
)

func client() (*exec.Cmd, *bytes.Buffer) {

	cmd := exec.Command(clientBin)
	if cmd == nil {
		panic("could not create client!\n")
		return nil, nil
	}

	/*
	if mode != "" {
		cmd.Env = os.Environ()
		cmd.Env = append(cmd.Env, fmt.Sprintf("BACKEND_MODE=%s", mode))
	}
	*/

	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	cmd.Start()

	return cmd, &output
}

func gateway() (*exec.Cmd, *bytes.Buffer) {

	cmd := exec.Command(gatewayBin)
	if cmd == nil {
		panic("could not create gateway!\n")
		return nil, nil
	}

	/*
	if mode != "" {
		cmd.Env = os.Environ()
		cmd.Env = append(cmd.Env, fmt.Sprintf("BACKEND_MODE=%s", mode))
	}
	*/

	// var output bytes.Buffer
	// cmd.Stdout = &output
	// cmd.Stderr = &output
	cmd.Start()

	return cmd, nil // &output
}

func server() *exec.Cmd {
	cmd := exec.Command(serverBin)
	if cmd == nil {
		panic("could not create server!\n")
		return nil
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Start()
	return cmd
}

func soak() {

	server_cmd := server()

	server_cmd.Wait()

	/*
	backend_cmd.Wait()

	server_cmd.Process.Signal(os.Interrupt)
	backend_cmd.Process.Signal(os.Interrupt)

	server_cmd.Wait()
	backend_cmd.Wait()
	*/

}

func main() {
	soak()
}
