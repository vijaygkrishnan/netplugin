/***
Copyright 2014 Cisco Systems Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package netutils

import (
	"fmt"
	"testing"
)

type testSubnetInfo struct {
	subnetIP      string
	subnetLen     uint
	hostID        uint
	hostIP        string
	ipv6Subnet    string
	ipv6SubnetLen uint
	ipv6HostID    string
	ipv6HostIP    string
}

var testSubnets = []testSubnetInfo{
	{subnetIP: "11.2.1.0", subnetLen: 24, hostID: 5, hostIP: "11.2.1.5"},
	{subnetIP: "10.123.16.0", subnetLen: 22, hostID: 513, hostIP: "10.123.18.1"},
	{subnetIP: "172.12.0.0", subnetLen: 16, hostID: 261, hostIP: "172.12.1.5"},
}

func TestGetSubnetIP(t *testing.T) {
	for _, te := range testSubnets {
		hostIP, err := GetSubnetIP(te.subnetIP, te.subnetLen, 32, te.hostID)
		if err != nil {
			t.Fatalf("error getting host ip from subnet %s/%d for hostid %d - err '%s'",
				te.subnetIP, te.subnetLen, te.hostID, err)
		}
		if hostIP != te.hostIP {
			t.Fatalf("obtained ip %s doesn't match expected ip %s for subnet %s/%d\n",
				hostIP, te.hostIP, te.subnetIP, te.subnetLen)
		}
	}
}

var testInvalidSubnets = []testSubnetInfo{
	{subnetIP: "11.2.1.0", subnetLen: 32, hostID: 5, hostIP: "11.2.1.5"},
	{subnetIP: "10.123.16.0", subnetLen: 22, hostID: 1025, hostIP: "10.123.18.1"},
	{subnetIP: "172.12.0.0", subnetLen: 4, hostID: 261, hostIP: "172.12.1.5"},
}

func TestInvalidGetSubnetIP(t *testing.T) {
	for _, te := range testInvalidSubnets {
		_, err := GetSubnetIP(te.subnetIP, te.subnetLen, 32, te.hostID)
		if err == nil {
			t.Fatalf("Expecting error on invalid config subnet %s/%d for hostid %d",
				te.subnetIP, te.subnetLen, te.hostID)
		}
	}
}

func TestGetIPNumber(t *testing.T) {
	for _, te := range testSubnets {
		hostID, err := GetIPNumber(te.subnetIP, te.subnetLen, 32, te.hostIP)
		if err != nil {
			t.Fatalf("error getting host ip from subnet %s/%d for hostid %d ",
				te.subnetIP, te.subnetLen, te.hostID)
		}
		if hostID != te.hostID {
			t.Fatalf("obtained ip %d doesn't match with expected ip %d \n",
				hostID, te.hostID)
		}
	}
}

var testv6Subnets = []testSubnetInfo{
	{ipv6Subnet: "2016:430::", ipv6SubnetLen: 64, ipv6HostID: "::254", ipv6HostIP: "2016:430::254"},
	{ipv6Subnet: "babe:face::80", ipv6SubnetLen: 121, ipv6HostID: "::45", ipv6HostIP: "babe:face::c5"},
	{ipv6Subnet: "2001::", ipv6SubnetLen: 100, ipv6HostID: "::2", ipv6HostIP: "2001::2"},
}

func TestGetSubnetIPv6(t *testing.T) {
	for _, te := range testv6Subnets {
		ipv6HostIP, err := GetSubnetIPv6(te.ipv6Subnet, te.ipv6SubnetLen, 128, te.ipv6HostID)
		if err != nil {
			t.Fatalf("error getting host ip from ipv6Subnet %s/%d for hostid %s - err '%s'",
				te.ipv6Subnet, te.ipv6SubnetLen, te.ipv6HostID, err)
		}
		if ipv6HostIP != te.ipv6HostIP {
			t.Fatalf("obtained ip %s doesn't match expected ip %s for ipv6Subnet %s/%d\n",
				ipv6HostIP, te.ipv6HostIP, te.ipv6Subnet, te.ipv6SubnetLen)
		}
	}
}

var testInvalidv6Subnets = []testSubnetInfo{
	{ipv6Subnet: "2016:430::", ipv6SubnetLen: 128, ipv6HostID: "::254"},
	{ipv6Subnet: "babe:face::80", ipv6SubnetLen: 121, ipv6HostID: "::c5"},
	{ipv6Subnet: "babe:face::80", ipv6SubnetLen: 121, ipv6HostID: "::105"},
	{ipv6Subnet: "2001::", ipv6SubnetLen: 130, ipv6HostID: "::2", ipv6HostIP: "2001::2"},
}

func TestInvalidGetSubnetIPv6(t *testing.T) {
	for _, te := range testInvalidSubnets {
		_, err := GetSubnetIPv6(te.ipv6Subnet, te.ipv6SubnetLen, 128, te.ipv6HostID)
		if err == nil {
			t.Fatalf("Expecting error on invalid config subnet %s/%d for hostid %s",
				te.ipv6Subnet, te.ipv6SubnetLen, te.ipv6HostID)
		}
	}
}

type testHostID struct {
	hostID     string
	nextHostID string
}

var testHostIDs = []testHostID{
	{hostID: "", nextHostID: "::1"},         // verify initial case
	{hostID: "::", nextHostID: "::2"},       // lasthost specifically set to 0
	{hostID: "::4", nextHostID: "::5"},      // find next of 4
	{hostID: "::4", nextHostID: "::6"},      // this time next of 4 should skip 5
	{hostID: "::FFFF", nextHostID: "::1:0"}, // verifying the carryover case
}

func TestGetNextIPv6HostID(t *testing.T) {
	var allocMap map[string]bool
	for _, te := range testHostIDs {
		nextHostID := GetNextIPv6HostID(te.hostID, allocMap)
		if nextHostID != te.nextHostID {
			t.Fatalf("obtained nextHostID %s doesn't match expected ID %s \n",
				nextHostID, te.nextHostID)
		}
		ReserveIPv6HostID(nextHostID, &allocMap)
	}
}

func TestValidRange(t *testing.T) {
	rangeStr := "5-100, 101-200"
	_, err := ParseTagRanges(rangeStr, "vlan")
	if err != nil {
		t.Fatalf("error '%s' parsing valid vlan range '%s'\n", err, rangeStr)
	}
}

func TestInvalidVlanRange(t *testing.T) {
	rangeStr := "5--100, 101-200"
	_, err := ParseTagRanges(rangeStr, "vlan")
	if err == nil {
		t.Fatalf("successfully parsed invalid vlan range '%s'\n", rangeStr)
	}
}

func TestInvalidVlanValue(t *testing.T) {
	rangeStr := "5-100, 101-5000"
	_, err := ParseTagRanges(rangeStr, "vlan")
	if err == nil {
		t.Fatalf("successfully parsed invalid vlan id '%s'\n", rangeStr)
	}
}

func TestInvalidMinMaxVlan(t *testing.T) {
	rangeStr := "5-100, 200-101"
	_, err := ParseTagRanges(rangeStr, "vlan")
	if err == nil {
		t.Fatalf("successfully parsed invalid min-max vlan values '%s'\n", rangeStr)
	}
}

func TestInvalidRangeExtraSeperators(t *testing.T) {
	rangeStr := "5-100,,101-200"
	_, err := ParseTagRanges(rangeStr, "vlan")
	if err == nil {
		t.Fatalf("successfully parsed vlan range with extra seperators '%s'\n", rangeStr)
	}
}

func TestValidVxlanRange(t *testing.T) {
	rangeStr := "10000-16000"
	_, err := ParseTagRanges(rangeStr, "vxlan")
	if err != nil {
		t.Fatalf("error '%s' parsing valid vxlan range '%s'\n", err, rangeStr)
	}
}

func TestInvalidVxlanMultipleRanges(t *testing.T) {
	rangeStr := "101-400, 10000-15000"
	_, err := ParseTagRanges(rangeStr, "vxlan")
	if err == nil {
		t.Fatalf("successfully parsed invalid vxlan value '%s'\n", rangeStr)
	}
}

func TestInvalidVxlanValue(t *testing.T) {
	rangeStr := "101-75535"
	_, err := ParseTagRanges(rangeStr, "vxlan")
	if err == nil {
		t.Fatalf("successfully parsed invalid vxlan value '%s'\n", rangeStr)
	}
}

func TestInvalidMinMaxVxlan(t *testing.T) {
	rangeStr := "8000-7999"
	_, err := ParseTagRanges(rangeStr, "vxlan")
	if err == nil {
		t.Fatalf("successfully parsed invalid min-max vxlan values '%s'\n", rangeStr)
	}
}

type testSubnetAllocInfo struct {
	subnetIP       string
	subnetLen      uint
	subnetAllocLen uint
	hostID         uint
	hostIP         string
}

var testSubnetAllocs = []testSubnetAllocInfo{
	{subnetIP: "11.1.0.0", subnetLen: 16, subnetAllocLen: 24,
		hostID: 5, hostIP: "11.1.5.0"},
	{subnetIP: "10.0.0.0", subnetLen: 8, subnetAllocLen: 24,
		hostID: 5, hostIP: "10.0.5.0"},
}

func TestGetSubnetAlloc(t *testing.T) {
	for _, te := range testSubnetAllocs {
		hostIP, err := GetSubnetIP(te.subnetIP, te.subnetLen,
			te.subnetAllocLen, te.hostID)
		if err != nil {
			t.Fatalf("error getting subnet ip from subnet-range %s/%d alloc-size %d "+
				"for id %d - err '%s'",
				te.subnetIP, te.subnetLen, te.subnetAllocLen, te.hostID, err)
		}
		if hostIP != te.hostIP {
			t.Fatalf("obtained ip %s doesn't match expected ip %s for subnet %s/%d "+
				"for AllocLen %d \n",
				hostIP, te.hostIP, te.subnetIP, te.subnetLen, te.subnetAllocLen)
		}
	}
}

func TestGetSubnetNumber(t *testing.T) {
	for _, te := range testSubnetAllocs {
		hostID, err := GetIPNumber(te.subnetIP, te.subnetLen,
			te.subnetAllocLen, te.hostIP)
		if err != nil {
			t.Fatalf("error getting subnet ip from subnet %s/%d for hostid %d "+
				"for subnet alloc size %d \n",
				te.subnetIP, te.subnetLen, te.hostID, te.subnetAllocLen)
		}
		if hostID != te.hostID {
			t.Fatalf("obtained subnet ip %d doesn't match with expected ip %d "+
				"for subnet %s/%d alloc size %d \n",
				hostID, te.hostID, te.subnetIP, te.subnetLen, te.subnetAllocLen)
		}
	}
}

func TestGetAddrList(t *testing.T) {
	addrList, err := GetNetlinkAddrList()
	if err != nil {
		t.Fatalf("Error getting address list. Err: %v", err)
	}

	fmt.Printf("Got netlink address list: %v\n", addrList)

	addrList, err = GetLocalAddrList()
	if err != nil {
		t.Fatalf("Error getting address list. Err: %v", err)
	}

	fmt.Printf("Got local address list: %v\n", addrList)
}
