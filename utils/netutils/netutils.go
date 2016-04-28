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
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unsafe"

	log "github.com/Sirupsen/logrus"
	"github.com/jainvipin/bitset"
	"github.com/vishvananda/netlink"

	"github.com/contiv/netplugin/core"
)

var endianNess string

func init() {
	// Determine endianness
	var test uint32 = 0xff
	firstByte := (*byte)(unsafe.Pointer(&test))
	if *firstByte == 0 {
		endianNess = "big"
	} else {
		endianNess = "little"
	}
}

// IsIPv6 Checks if the address string is IPv6 address
func IsIPv6(ip string) bool { return strings.Contains(ip, ":") }

// InitSubnetBitset initializes a bit set with 2^(32 - subnetLen) bits
func InitSubnetBitset(b *bitset.BitSet, subnetLen uint) {
	maxSize := 1 << (32 - subnetLen)
	b.Set(uint(maxSize))
	b.Set(uint(0))
}

// CreateBitset initializes a bit set with 2^numBitsWide bits
func CreateBitset(numBitsWide uint) *bitset.BitSet {
	maxSize := 1 << numBitsWide
	return bitset.New(uint(maxSize))
}

func ipv4ToUint32(ipaddr string) (uint32, error) {
	var ipUint32 uint32

	ip := net.ParseIP(ipaddr).To4()
	if ip == nil {
		return 0, core.Errorf("ipv4 to uint32 conversion: invalid ip format")
	}
	if endianNess == "little" {
		ipUint32 = (uint32(ip[3]) | (uint32(ip[2]) << 8) |
			(uint32(ip[1]) << 16) | (uint32(ip[0]) << 24))
	} else {
		ipUint32 = uint32(ip[0]) | (uint32(ip[1]) << 8) |
			(uint32(ip[2]) << 16) | (uint32(ip[3]) << 24)
	}

	return ipUint32, nil
}

func ipv4Uint32ToString(ipUint32 uint32) (string, error) {
	var b1, b2, b3, b4 byte

	if endianNess == "little" {
		b1, b2, b3, b4 = byte(ipUint32>>24), byte(ipUint32>>16),
			byte(ipUint32>>8), byte(ipUint32)
	} else {
		b1, b2, b3, b4 = byte(ipUint32), byte(ipUint32>>8),
			byte(ipUint32>>16), byte((ipUint32)>>24)
	}

	return fmt.Sprintf("%d.%d.%d.%d", b1, b2, b3, b4), nil
}

// ReserveIPv6HostID sets the hostId in the AllocMap
func ReserveIPv6HostID(hostID string, IPv6AllocMap *map[string]bool) {
	if hostID == "" {
		return
	}
	if *IPv6AllocMap == nil {
		*IPv6AllocMap = make(map[string]bool)
	}
	(*IPv6AllocMap)[hostID] = true
}

// GetNextIPv6HostID returns the next available hostId in the AllocMap
func GetNextIPv6HostID(hostID string, IPv6AllocMap map[string]bool) string {
	if hostID == "" {
		hostID = "::"
	}
	hostidIP := net.ParseIP(hostID)
	// start with the carryOver 1 to get the next hostID
	var carryOver = 1
	var allocd = true

	for allocd == true {
		for i := len(hostidIP) - 1; i >= 0; i-- {
			var temp int
			temp = int(hostidIP[i]) + carryOver
			if temp > int(0xFF) {
				hostidIP[i] = 0
				carryOver = 1
			} else {
				hostidIP[i] = uint8(temp)
				carryOver = 0
				break
			}
		}
		if _, allocd = IPv6AllocMap[hostidIP.String()]; allocd == true {
			// Already allocated find the next hostID
			carryOver = 1
		}
	}
	return hostidIP.String()
}

// GetSubnetIPv6 given a subnet IP and host identifier, calculates an IPv6 address
// within the subnet for use.
func GetSubnetIPv6(subnetAddr string, subnetLen, allocSubnetLen uint, hostID string) (string, error) {
	if subnetAddr == "" {
		return "", core.Errorf("null subnet")
	}

	if subnetLen > 128 || subnetLen < 16 {
		return "", core.Errorf("subnet length %d not supported", subnetLen)
	}
	if subnetLen > allocSubnetLen {
		return "", core.Errorf("subnet length %d is bigger than subnet alloc len %d",
			subnetLen, allocSubnetLen)
	}

	subnetIP := net.ParseIP(subnetAddr)
	hostidIP := net.ParseIP(hostID)
	hostIP := net.IPv6zero

	var offset int
	for offset = 0; offset < int(subnetLen/8); offset++ {
		hostIP[offset] = subnetIP[offset]
	}
	// copy the overlapping byte in subnetIP and hostID
	if subnetLen%8 != 0 && subnetIP[offset] != 0 {
		if hostidIP[offset]&subnetIP[offset] != 0 {
			return "", core.Errorf("host id %s exceeds subnet %s capacity ",
				hostID, subnetAddr)
		}
		hostIP[offset] = hostidIP[offset] | subnetIP[offset]
		offset++
	}

	for ; offset < len(hostidIP); offset++ {
		hostIP[offset] = hostidIP[offset]
	}
	return hostIP.String(), nil
}

// GetSubnetIP given a subnet IP and host identifier, calculates an IP within
// the subnet for use.
func GetSubnetIP(subnetIP string, subnetLen uint, allocSubnetLen, hostID uint) (string, error) {
	if subnetIP == "" {
		return "", core.Errorf("null subnet")
	}

	if subnetLen > 32 || subnetLen < 8 {
		return "", core.Errorf("subnet length %d not supported", subnetLen)
	}
	if subnetLen > allocSubnetLen {
		return "", core.Errorf("subnet length %d is bigger than subnet alloc len %d",
			subnetLen, allocSubnetLen)
	}

	maxHosts := uint(1 << (allocSubnetLen - subnetLen))
	if hostID >= maxHosts {
		return "", core.Errorf("host id %d is beyond subnet's capacity %d",
			hostID, maxHosts)
	}

	// Get next hostID that is free
	// -- nextHostID :=

	hostIPUint32, err := ipv4ToUint32(subnetIP)
	if err != nil {
		return "", core.Errorf("unable to convert subnet %s to uint32", subnetIP)
	}
	hostIPUint32 += uint32(hostID << (32 - allocSubnetLen))
	return ipv4Uint32ToString(hostIPUint32)
}

// GetIPv6HostID obtains the host id from the host IP. SEe `GetSubnetIP` for more information.
func GetIPv6HostID(subnetAddr string, subnetLen uint, allocSubnetLen uint, hostAddr string) (string, error) {
	if subnetLen > 128 || subnetLen < 16 {
		return "", core.Errorf("subnet length %d not supported", subnetLen)
	}
	if subnetLen > allocSubnetLen {
		return "", core.Errorf("subnet length %d is bigger than subnet alloc len %d",
			subnetLen, allocSubnetLen)
	}
	if allocSubnetLen != 128 {
		return "", core.Errorf("Trying to allocate IPv6 address with mask-len %d < 128",
			allocSubnetLen)
	}
	// Initialize hostID
	hostID := net.IPv6zero

	var offset uint

	// get the overlapping byte
	offset = subnetLen / 8
	subnetIP := net.ParseIP(subnetAddr)
	if subnetIP == nil {
		return "", core.Errorf("Invalid subnetAddr %s ", subnetAddr)
	}
	s := uint8(subnetIP[offset])
	hostIP := net.ParseIP(hostAddr)
	if hostIP == nil {
		return "", core.Errorf("Invalid hostAddr %s ", hostAddr)
	}
	h := uint8(hostIP[offset])
	hostID[offset] = byte(h - s)

	// Copy the rest of the bytes
	for i := (offset + 1); i < allocSubnetLen/8; i++ {
		hostID[i] = hostIP[i]
		offset++
	}
	return hostID.String(), nil
}

// GetIPNumber obtains the host id from the host IP. SEe `GetSubnetIP` for more information.
func GetIPNumber(subnetIP string, subnetLen uint, allocSubnetLen uint, hostIP string) (uint, error) {
	if subnetLen > 32 || subnetLen < 8 {
		return 0, core.Errorf("subnet length %d not supported", subnetLen)
	}
	if subnetLen > allocSubnetLen {
		return 0, core.Errorf("subnet length %d is bigger than subnet alloc len %d",
			subnetLen, allocSubnetLen)
	}

	hostIPUint32, err := ipv4ToUint32(hostIP)
	if err != nil {
		return 0, core.Errorf("unable to convert hostIP %s to uint32", hostIP)
	}

	subnetIPUint32, err := ipv4ToUint32(subnetIP)
	if err != nil {
		return 0, core.Errorf("unable to convert subnetIP %s to uint32", subnetIP)
	}
	hostID := uint((hostIPUint32 - subnetIPUint32) >> (32 - allocSubnetLen))

	maxHosts := uint(1 << (allocSubnetLen - subnetLen))
	if hostID >= maxHosts {
		return 0, core.Errorf("hostIP %s is exceeding beyond subnet %s/%d, hostID %d",
			hostIP, subnetIP, subnetLen, hostID)
	}

	return uint(hostID), nil
}

// TagRange represents a range of integers, intended for VLAN and VXLAN
// tagging.
type TagRange struct {
	Min int
	Max int
}

// ParseTagRanges takes a string such as 12-24,48-64 and turns it into a series
// of TagRange.
func ParseTagRanges(ranges string, tagType string) ([]TagRange, error) {
	var err error

	if ranges == "" {
		return []TagRange{{0, 0}}, nil
	}

	if tagType != "vlan" && tagType != "vxlan" {
		return nil, core.Errorf("invalid tag type %s", tagType)
	}
	rangesStr := strings.Split(ranges, ",")

	if len(rangesStr) > 1 && tagType == "vxlan" {
		return nil, core.Errorf("do not support more than 2 vxlan tag ranges")
	}

	tagRanges := make([]TagRange, len(rangesStr), len(rangesStr))
	for idx, oneRangeStr := range rangesStr {
		oneRangeStr = strings.Trim(oneRangeStr, " ")
		tagNums := strings.Split(oneRangeStr, "-")
		if len(tagNums) > 2 {
			return nil, core.Errorf("invalid tags %s, correct '10-50,70-100'",
				oneRangeStr)
		}
		tagRanges[idx].Min, err = strconv.Atoi(tagNums[0])
		if err != nil {
			return nil, core.Errorf("invalid integer %d conversion error '%s'",
				tagRanges[idx].Min, err)
		}
		tagRanges[idx].Max, err = strconv.Atoi(tagNums[1])
		if err != nil {
			return nil, core.Errorf("invalid integer %d conversion error '%s'",
				tagRanges[idx].Max, err)
		}

		if tagRanges[idx].Min > tagRanges[idx].Max {
			return nil, core.Errorf("invalid range %s, min is greater than max",
				oneRangeStr)
		}
		if tagRanges[idx].Min < 1 {
			return nil, core.Errorf("invalid range %s, values less than 1",
				oneRangeStr)
		}
		if tagType == "vlan" && tagRanges[idx].Max > 4095 {
			return nil, core.Errorf("invalid range %s, vlan values exceed 4095 max allowed",
				oneRangeStr)
		}
		if tagType == "vxlan" && tagRanges[idx].Max > 65535 {
			return nil, core.Errorf("invalid range %s, vlan values exceed 65535 max allowed",
				oneRangeStr)
		}
		if tagType == "vxlan" &&
			(tagRanges[idx].Max-tagRanges[idx].Min > 16000) {
			return nil, core.Errorf("does not allow vxlan range to exceed 16000 range %s",
				oneRangeStr)
		}
	}

	return tagRanges, nil
}

// ParseCIDR parses a CIDR string into a gateway IP and length.
func ParseCIDR(cidrStr string) (string, uint, error) {
	strs := strings.Split(cidrStr, "/")
	if len(strs) != 2 {
		return "", 0, core.Errorf("invalid cidr format")
	}

	subnetStr := strs[0]
	subnetLen, err := strconv.Atoi(strs[1])
	if (IsIPv6(subnetStr) && subnetLen > 128) || err != nil || (!IsIPv6(subnetStr) && subnetLen > 32) {
		return "", 0, core.Errorf("invalid mask in gateway/mask specification ")
	}

	return subnetStr, uint(subnetLen), nil
}

// GetInterfaceIP obtains the ip addr of a local interface on the host.
func GetInterfaceIP(linkName string) (string, error) {
	var addrs []netlink.Addr
	localIPAddr := ""

	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return "", err
	}
	addrs, err = netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return "", err
	}
	if len(addrs) > 0 {
		localIPAddr = addrs[0].IP.String()
	}

	err = core.Errorf("local ip not found")
	if localIPAddr != "" {
		err = nil
	}

	return localIPAddr, err
}

// SetInterfaceMac : Set mac address of an interface
func SetInterfaceMac(name string, macaddr string) error {
	iface, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	hwaddr, err := net.ParseMAC(macaddr)
	if err != nil {
		return err
	}
	return netlink.LinkSetHardwareAddr(iface, hwaddr)
}

// GetNetlinkAddrList returns a list of local IP addresses
func GetNetlinkAddrList() ([]string, error) {
	var addrList []string
	// get the link list
	linkList, err := netlink.LinkList()
	if err != nil {
		return addrList, err
	}

	log.Debugf("Got link list(%d): %+v", len(linkList), linkList)

	// Loop thru each interface and add its ip addr to list
	for _, link := range linkList {
		if strings.HasPrefix(link.Attrs().Name, "docker") || strings.HasPrefix(link.Attrs().Name, "veth") ||
			strings.HasPrefix(link.Attrs().Name, "vport") || strings.HasPrefix(link.Attrs().Name, "lo") {
			continue
		}
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			return addrList, err
		}

		for _, addr := range addrs {
			addrList = append(addrList, addr.IP.String())
		}
	}

	return addrList, err
}

// GetLocalAddrList returns a list of local IP addresses
func GetLocalAddrList() ([]string, error) {
	var addrList []string
	// get the link list
	intfList, err := net.Interfaces()
	if err != nil {
		return addrList, err
	}

	log.Debugf("Got address list(%d): %+v", len(intfList), intfList)

	// Loop thru each interface and add its ip addr to list
	for _, intf := range intfList {
		if strings.HasPrefix(intf.Name, "docker") || strings.HasPrefix(intf.Name, "veth") ||
			strings.HasPrefix(intf.Name, "vport") || strings.HasPrefix(intf.Name, "lo") {
			continue
		}

		addrs, err := intf.Addrs()
		if err != nil {
			return addrList, err
		}

		for _, addr := range addrs {
			addrList = append(addrList, addr.String())
		}
	}

	return addrList, err
}

// IsAddrLocal check if an address is local
func IsAddrLocal(findAddr string) bool {
	// get the local addr list
	addrList, err := GetNetlinkAddrList()
	if err != nil {
		return false
	}

	// find the address
	for _, addr := range addrList {
		if addr == findAddr {
			return true
		}
	}

	return false
}

// GetFirstLocalAddr returns the first ip address
func GetFirstLocalAddr() (string, error) {
	// get the local addr list
	addrList, err := GetNetlinkAddrList()
	if err != nil {
		return "", err
	}

	if len(addrList) > 0 {
		return addrList[0], nil
	}

	return "", errors.New("No address was found")
}
