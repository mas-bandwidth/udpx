/*
   Copyright (c) 2023 - 2024, Mas Bandwidth LLC, All rights reserved.


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

package envvar

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func Exists(name string) bool {
	_, ok := os.LookupEnv(name)
	return ok
}

func Get(name string, defaultValue string) string {
	value, ok := os.LookupEnv(name)
	if !ok {
		return defaultValue
	}

	return value
}

func GetList(name string, defaultValue []string) []string {
	valueStrings, ok := os.LookupEnv(name)
	if !ok {
		return defaultValue
	}

	value := strings.Split(valueStrings, ",")
	return value
}

func GetInt(name string, defaultValue int) (int, error) {
	valueString, ok := os.LookupEnv(name)
	if !ok {
		return defaultValue, nil
	}

	value, err := strconv.ParseInt(valueString, 10, 64)
	if err != nil {
		return defaultValue, fmt.Errorf("could not parse value of env var %s as an integer. Value: %s", name, valueString)
	}

	return int(value), nil
}

func GetFloat(name string, defaultValue float64) (float64, error) {
	valueString, ok := os.LookupEnv(name)
	if !ok {
		return defaultValue, nil
	}

	value, err := strconv.ParseFloat(valueString, 64)
	if err != nil {
		return defaultValue, fmt.Errorf("could not parse value of env var %s as a float. Value: %s", name, valueString)
	}

	return value, nil
}

func GetBool(name string, defaultValue bool) (bool, error) {
	valueString, ok := os.LookupEnv(name)
	if !ok {
		return defaultValue, nil
	}

	value, err := strconv.ParseBool(valueString)
	if err != nil {
		return defaultValue, fmt.Errorf("could not parse value of env var %s as a bool. Value: %s", name, valueString)
	}

	return value, nil
}

func GetDuration(name string, defaultValue time.Duration) (time.Duration, error) {
	valueString, ok := os.LookupEnv(name)
	if !ok {
		return defaultValue, nil
	}

	value, err := time.ParseDuration(valueString)
	if err != nil {
		return defaultValue, fmt.Errorf("could not parse value of env var %s as a duration. Value: %s", name, valueString)
	}

	return value, nil
}

func GetBase64(name string, defaultValue []byte) ([]byte, error) {
	valueString, ok := os.LookupEnv(name)
	if !ok {
		return defaultValue, nil
	}

	value, err := base64.StdEncoding.DecodeString(valueString)
	if err != nil {
		return defaultValue, fmt.Errorf("could not parse value of env var %s as a base64 encoded value. Value: %s", name, valueString)
	}

	return value, nil
}

func GetAddress(name string, defaultValue *net.UDPAddr) (*net.UDPAddr, error) {
	valueString, ok := os.LookupEnv(name)
	if !ok {
		return defaultValue, nil
	}

	value, err := net.ResolveUDPAddr("udp", valueString)
	if err != nil {
		return defaultValue, fmt.Errorf("could not parse value of env var %s as an address. Value: %s", name, valueString)
	}

	return value, nil
}
