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
	"encoding/base64"
	"fmt"
	"github.com/networknext/udpx/modules/core"
	"github.com/networknext/udpx/modules/envvar"
)

func main() {

	var userId [core.UserIdBytes]byte

	gatewayAddress, err := envvar.GetAddress("GATEWAY_ADDRESS", core.ParseAddress("127.0.0.1:40000"))
	if err != nil {
		core.Error("invalid GATEWAY_ADDRESS: %v", err)
		return
	}

	gatewayPublicKey, err := envvar.GetBase64("GATEWAY_PUBLIC_KEY", nil)
	if err != nil || len(gatewayPublicKey) != core.PublicKeyBytes_Box {
		core.Error("missing or invalid GATEWAY_PUBLIC_KEY: %v", err)
		return
	}

	sessionPrivateKey, err := envvar.GetBase64("SESSION_PRIVATE_KEY", nil)
	if err != nil || len(sessionPrivateKey) != core.PrivateKeyBytes_Box {
		core.Error("missing or invalid SESSION_PRIVATE_KEY: %v", err)
		return
	}

	connect_token := core.GenerateConnectToken(userId[:], gatewayAddress, gatewayPublicKey[:], sessionPrivateKey, gatewayPublicKey)

	connect_token_base64 := base64.StdEncoding.EncodeToString(connect_token)

	fmt.Printf("%s\n", connect_token_base64)
}
