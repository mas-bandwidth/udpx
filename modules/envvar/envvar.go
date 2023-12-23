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
