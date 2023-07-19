/*
* Large-Scale Discovery, a network scanning solution for information gathering in large IT/OT network environments.
*
* Copyright (c) Siemens AG, 2016-2023.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package discovery

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

type DCERPCTransport struct {
	target string
	port   string
}

type ServerAlive2Response struct {
	bindingsStringArray    []uint16
	bindingsSecurityOffset int
	bindingsNumEntries     int
}

func bindingToAddr(bindings []byte) (string, int) {
	offset := 2
	dataLen := bytes.Index(bindings, []byte("\x00\x00\x00")) + 3 - offset
	return string(bindings[offset : offset+dataLen]), dataLen + offset
}

func parseStringData(data []byte) ServerAlive2Response {

	// Prepare result data structure
	response := ServerAlive2Response{
		bindingsStringArray:    []uint16{},
		bindingsSecurityOffset: int(binary.LittleEndian.Uint16(data[14:16])),
		bindingsNumEntries:     int(binary.LittleEndian.Uint32(data[8:12])),
	}

	// Prepare some working variables
	offset := 16
	soFarItems := 0
	nbrSoFar := 0
	nbrItems := response.bindingsNumEntries

	// Iterate and process data
	var numbers []uint16
	for {
		if nbrItems == 0 || soFarItems >= len(data)-offset {
			break
		}
		nbrSoFar = soFarItems + 2
		number := binary.LittleEndian.Uint16(data[offset+soFarItems : offset+soFarItems+2])
		numbers = append(numbers, number)
		nbrItems -= 1
		soFarItems = nbrSoFar
	}

	// Add numbers to result data
	response.bindingsStringArray = numbers

	// Return result data
	return response
}

// extractAddresses extracts the hostname and IP addresses from response bytes
func extractAddresses(data []byte) (string, []string, error) {

	// Prepare memory for alive response data
	sa2r := parseStringData(data)
	if sa2r.bindingsStringArray == nil {
		return "", nil, fmt.Errorf("could not extract inferface information") // Target isn't listening on endpoint or access denied
	}

	// Parse oxIDs
	var oxIDs []byte
	for _, nbr := range sa2r.bindingsStringArray {
		bs := make([]byte, 2)
		binary.LittleEndian.PutUint16(bs, nbr)
		oxIDs = append(oxIDs, bs...)
	}

	// Return with no result if there is no data
	if sa2r.bindingsSecurityOffset == 0 {
		return "", []string{}, nil
	}

	// Check if returned values are as expected
	if len(oxIDs) < sa2r.bindingsSecurityOffset*2 {
		return "", nil, fmt.Errorf("unexpected OXID response")
	}

	// Parse binding strings
	strBindings := oxIDs[:sa2r.bindingsSecurityOffset*2]
	var stringBindings []string
	for {
		if string(strBindings[0:1]) == "\x00" && string(strBindings[1:2]) == "\x00" {
			break
		}
		addr, size := bindingToAddr(strBindings)
		addr = strings.Replace(addr, "\x00", "", -1) // Remove NULL bytes
		stringBindings = append(stringBindings, addr)
		strBindings = strBindings[size:]
	}

	// Return with no result if there is no data
	if len(stringBindings) < 2 {
		return "", []string{}, fmt.Errorf("unexpected OXID response legnth %d", len(stringBindings))
	}

	// Return extracted hostname and IP addresses
	return stringBindings[0], stringBindings[1:], nil
}

// allZero checks if a string is containing only zero bytes
func allZero(s []byte) bool {
	for _, v := range s {
		if v != 0 {
			return false
		}
	}
	return true
}

// queryHost connects to the target system, initializes the communication and extracts hostname and IPs from
// the response data
func queryHost(transport DCERPCTransport) (hostname string, ips []string, err error) {

	// Connect to target transport
	socket, errSocket := net.Dial("tcp", transport.target+":"+transport.port)
	if errSocket != nil {
		return "", nil, errSocket
	}

	// Prepare cleanup
	defer func() {
		_ = socket.Close()
	}()

	// Send binding payload
	bindRaw := "05000b03100000004800000001000000b810b810000000000100000000000100c4fefc9960521b10bbcb00aa0021347a00000000045d888aeb1cc9119fe808002b10486002000000"
	bind, _ := hex.DecodeString(bindRaw)
	_, errBind := socket.Write(bind)
	if errBind != nil {
		return "", nil, fmt.Errorf("binding request failed: %s", errBind)
	}

	// Read binding response
	respBind := make([]byte, 60)
	_, errBindResp := socket.Read(respBind)
	if errBindResp != nil {
		return "", nil, fmt.Errorf("binding response error: %s", errBindResp)
	}

	// Check if response contains information
	if allZero(respBind) {
		return "", nil, fmt.Errorf("no response to binding request")
	}

	// Send ServerAlive2() payload
	aliveRaw := "050000031000000018000000010000000000000000000500"
	alive, _ := hex.DecodeString(aliveRaw)
	_, errAlive := socket.Write(alive)
	if errAlive != nil {
		return "", nil, fmt.Errorf("alive request failed: %s", errAlive)
	}

	// Read ServerAlive2() response headers
	respHeader := make([]byte, 24)
	_, errAliveHeader := socket.Read(respHeader)
	if errAliveHeader != nil {
		return "", nil, fmt.Errorf("alive response error: %s", errAliveHeader)
	}

	// Read ServerAlive2() response data
	respData := make([]byte, 8192)
	_, errAliveData := socket.Read(respData)
	if errAliveData != nil {
		return "", nil, fmt.Errorf("alive response data error: %s", errAliveData)
	}

	// Check if alive response contains information
	if allZero(respData) {
		return "", nil, fmt.Errorf("no response to alive request")
	}

	// Extract network addresses from response
	var errExtract error
	hostname, ips, errExtract = extractAddresses(respData)
	if errExtract != nil {
		return "", nil, errExtract
	}

	// Return network addresses
	return hostname, ips, nil
}

// QueryInterfaces connects to a remote host via RPC to query its hostname and network interfaces
func QueryInterfaces(target string) (string, []string, error) {

	// Prepare DCERPCTransport object
	rpcTransport := DCERPCTransport{target: target, port: "135"}

	// Connect and extracts addresses
	hostname, ips, errQuery := queryHost(rpcTransport)

	// Return hostname and addresses
	return hostname, ips, errQuery
}
