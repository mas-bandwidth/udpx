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

	authPrivateKey, err := envvar.GetBase64("AUTH_PRIVATE_KEY", nil)
	if err != nil || len(authPrivateKey) != core.PrivateKeyBytes_Box {
		core.Error("missing or invalid AUTH_PRIVATE_KEY: %v", err)
		return
	}

	envelopeUpKbps := uint32(2500)
	envelopeDownKbps := uint32(10000)
	packetsPerSecond := uint8(100)

	connect_token := core.GenerateConnectToken(userId[:], envelopeUpKbps, envelopeDownKbps, packetsPerSecond, gatewayAddress, gatewayPublicKey[:], authPrivateKey, gatewayPublicKey)

	connect_token_base64 := base64.StdEncoding.EncodeToString(connect_token)

	fmt.Printf("%s\n", connect_token_base64)
}
