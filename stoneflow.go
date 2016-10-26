/*
Copyright 2016 Matthew Stone

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
package stoneflow

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/op/go-logging"
	"net"
)

var log = logging.MustGetLogger("s2flow")

type StoneFlow struct {
	ReadIn chan *EtherFrame
}

func (stoneflow *StoneFlow) ParseTypeTwo(buf []byte) {
	log.Debugf("Parsing Version 5")
	for len(buf) > 0 {
		if len(buf) < 8 {
			return
		}
		sFlowType := binary.BigEndian.Uint32(buf[0:4])
		buf = buf[8:]
		if sFlowType == 1 {
			if len(buf) < 88 {
				return
			}
			ifCounters := stoneflow.ParseIfCounters(buf)
			log.Debugf("If Counters: %v", ifCounters)
			buf = buf[88:]
		} else if sFlowType == 2 {
			if len(buf) < 52 {
				return
			}
			ethernetCounters := stoneflow.ParseEthernetCounters(buf)
			log.Debugf("Ethernet Counters: %v", ethernetCounters)
			buf = buf[52:]
		} else if sFlowType == 3 {
			if len(buf) < 72 {
				return
			}
			log.Debugf("Parsing Type 3")
			buf = buf[72:]
		} else if sFlowType == 4 {
			if len(buf) < 80 {
				return
			}
			vlanCounters := stoneflow.ParseVlanCounters(buf)
			log.Debugf("Vlan Counters: %v", vlanCounters)
			buf = buf[80:]
		} else if sFlowType == 5 {
			if len(buf) < 28 {
				return
			}

			log.Debugf("Parsing Type 4")
			vlanCounters := stoneflow.ParseVlanCounters(buf)
			log.Debugf("Vlan Counters: %v", vlanCounters)
			buf = buf[28:]
		} else if sFlowType > 5 || sFlowType <= 0 {
			log.Warningf("sFlowType not recognized: %v", sFlowType)
			log.Warningf("Buffer: %v", buf)
			return
		}
	}
}

type Headers struct {
	version        uint32
	addressType    uint32
	address        []byte
	subAgentID     uint32
	sequenceNumber uint32
	sysUptime      uint32
	numSamples     uint32
}

func (stoneflow *StoneFlow) ParseHeaders(buf []byte) (*Headers, error) {
	if len(buf) < 8 {
		return nil, errors.New("Invalid header length")
	}
	var address []byte
	var addressEnd int

	version := binary.BigEndian.Uint32(buf[0:4])
	addressType := binary.BigEndian.Uint32(buf[4:8])
	if addressType == 1 {
		if len(buf) < 28 {
			return nil, errors.New("Invalid header length")
		}
		address = buf[8:12]
		addressEnd = 12
	} else if addressType == 2 {
		if len(buf) < 40 {
			return nil, errors.New("Invalid header length")
		}

		address = buf[8:24]
		addressEnd = 24
	} else {
		return nil, errors.New("Unknown Address Type")
	}

	subAgentID := binary.BigEndian.Uint32(buf[addressEnd : addressEnd+4])
	sequenceNumber := binary.BigEndian.Uint32(buf[addressEnd+4 : addressEnd+8])
	sysUptime := binary.BigEndian.Uint32(buf[addressEnd+8 : addressEnd+12])
	numSamples := binary.BigEndian.Uint32(buf[addressEnd+12 : addressEnd+16])

	headers := &Headers{
		version:        version,
		addressType:    addressType,
		address:        address,
		subAgentID:     subAgentID,
		sequenceNumber: sequenceNumber,
		sysUptime:      sysUptime,
		numSamples:     numSamples}

	return headers, nil
}

type SampleDataHeader struct {
	sequenceNumber uint32
	idType         uint8
	indexValue     uint16
	rate           uint32
	totalPackets   uint32
	drops          uint32
	ifIndexIn      uint32
	ifIndexOut     uint32
	flowRecords    uint32
}

func (stoneflow *StoneFlow) ParseSampleHeader(buf []byte) *SampleDataHeader {
	log.Debugf("%v\n", buf)
	parsedSampleDataHeader := &SampleDataHeader{
		sequenceNumber: binary.BigEndian.Uint32(buf[0:4]),
		idType:         uint8(buf[4]),
		indexValue:     binary.BigEndian.Uint16(buf[5:8]),
		rate:           binary.BigEndian.Uint32(buf[8:12]),
		totalPackets:   binary.BigEndian.Uint32(buf[12:16]),
		drops:          binary.BigEndian.Uint32(buf[16:20]),
		ifIndexIn:      binary.BigEndian.Uint32(buf[20:24]),
		ifIndexOut:     binary.BigEndian.Uint32(buf[24:28]),
		flowRecords:    binary.BigEndian.Uint32(buf[28:32])}

	return parsedSampleDataHeader
}

type IfCounters struct {
	ifIndex            uint32
	ifType             uint32
	ifSpeed            uint64
	ifDirection        uint32
	ifStatus           uint32
	ifInOctets         uint64
	ifInUcastPkts      uint32
	ifInMulticastPkts  uint32
	ifInBroadcastPkts  uint32
	ifInDiscards       uint32
	ifInErrors         uint32
	ifInUnknownProtos  uint32
	ifOutOctets        uint64
	ifOutUcastPkts     uint32
	ifOutMulticastPkts uint32
	ifOutBroadcastPkts uint32
	ifOutDiscards      uint32
	ifOutErrors        uint32
	ifPromiscuousMode  uint32
}

func (stoneflow *StoneFlow) ParseIfCounters(buf []byte) *IfCounters {
	parsedIfCounters := &IfCounters{
		ifIndex:            binary.BigEndian.Uint32(buf[0:4]),
		ifType:             binary.BigEndian.Uint32(buf[4:8]),
		ifSpeed:            binary.BigEndian.Uint64(buf[8:16]),
		ifDirection:        binary.BigEndian.Uint32(buf[16:20]),
		ifStatus:           binary.BigEndian.Uint32(buf[20:24]),
		ifInOctets:         binary.BigEndian.Uint64(buf[24:32]),
		ifInUcastPkts:      binary.BigEndian.Uint32(buf[32:36]),
		ifInMulticastPkts:  binary.BigEndian.Uint32(buf[36:40]),
		ifInBroadcastPkts:  binary.BigEndian.Uint32(buf[40:44]),
		ifInDiscards:       binary.BigEndian.Uint32(buf[44:48]),
		ifInErrors:         binary.BigEndian.Uint32(buf[48:52]),
		ifInUnknownProtos:  binary.BigEndian.Uint32(buf[52:56]),
		ifOutOctets:        binary.BigEndian.Uint64(buf[56:64]),
		ifOutUcastPkts:     binary.BigEndian.Uint32(buf[64:68]),
		ifOutMulticastPkts: binary.BigEndian.Uint32(buf[68:72]),
		ifOutBroadcastPkts: binary.BigEndian.Uint32(buf[72:76]),
		ifOutDiscards:      binary.BigEndian.Uint32(buf[76:80]),
		ifOutErrors:        binary.BigEndian.Uint32(buf[80:84]),
		ifPromiscuousMode:  binary.BigEndian.Uint32(buf[84:88])}

	return parsedIfCounters
}

type EthernetCounters struct {
	dot3StatsAlignmentErrors           uint32
	dot3StatsFCSErrors                 uint32
	dot3StatsSingleCollisionbufs       uint32
	dot3StatsMultipleCollisionbufs     uint32
	dot3StatsSQETestErrors             uint32
	dot3StatsDeferredTransmissions     uint32
	dot3StatsLateCollisions            uint32
	dot3StatsExcessiveCollisions       uint32
	dot3StatsInternalMacTransmitErrors uint32
	dot3StatsCarrierSenseErrors        uint32
	dot3StatsbufTooLongs               uint32
	dot3StatsInternalMacReceiveErrors  uint32
	dot3StatsSymbolErrors              uint32
}

func (stoneflow *StoneFlow) ParseEthernetCounters(buf []byte) *EthernetCounters {

	parsedEthernetCounters := &EthernetCounters{
		dot3StatsAlignmentErrors:           binary.BigEndian.Uint32(buf[0:4]),
		dot3StatsFCSErrors:                 binary.BigEndian.Uint32(buf[4:8]),
		dot3StatsSingleCollisionbufs:       binary.BigEndian.Uint32(buf[8:12]),
		dot3StatsMultipleCollisionbufs:     binary.BigEndian.Uint32(buf[12:16]),
		dot3StatsSQETestErrors:             binary.BigEndian.Uint32(buf[16:20]),
		dot3StatsDeferredTransmissions:     binary.BigEndian.Uint32(buf[20:24]),
		dot3StatsLateCollisions:            binary.BigEndian.Uint32(buf[24:28]),
		dot3StatsExcessiveCollisions:       binary.BigEndian.Uint32(buf[28:32]),
		dot3StatsInternalMacTransmitErrors: binary.BigEndian.Uint32(buf[32:36]),
		dot3StatsCarrierSenseErrors:        binary.BigEndian.Uint32(buf[36:40]),
		dot3StatsbufTooLongs:               binary.BigEndian.Uint32(buf[40:44]),
		dot3StatsInternalMacReceiveErrors:  binary.BigEndian.Uint32(buf[44:48]),
		dot3StatsSymbolErrors:              binary.BigEndian.Uint32(buf[48:52])}

	return parsedEthernetCounters
}

type VlanCounters struct {
	vlanId        uint32
	octets        uint64
	ucastPkts     uint32
	multicastPkts uint32
	broadcastPkts uint32
	discards      uint32
}

func (stoneflow *StoneFlow) ParseVlanCounters(buf []byte) *VlanCounters {

	parsedVlanCounters := &VlanCounters{
		vlanId:        binary.BigEndian.Uint32(buf[0:4]),
		octets:        binary.BigEndian.Uint64(buf[4:12]),
		ucastPkts:     binary.BigEndian.Uint32(buf[12:16]),
		multicastPkts: binary.BigEndian.Uint32(buf[16:20]),
		broadcastPkts: binary.BigEndian.Uint32(buf[20:24]),
		discards:      binary.BigEndian.Uint32(buf[24:28])}

	return parsedVlanCounters
}

func (stoneflow *StoneFlow) CheckError(err error) bool {
	if err != nil {
		log.Errorf("Error: %v", err)

		return true
	}

	return false
}

type EtherFrame struct {
	SrcMac  []byte
	DstMac  []byte
	SrcIP   []byte
	DstIP   []byte
	SrcPort []byte
	DstPort []byte
}

func (stoneflow *StoneFlow) ParseFrame(buf []byte) *EtherFrame {
	etherFrame := &EtherFrame{
		SrcMac:  buf[16:22],
		DstMac:  buf[22:28],
		SrcIP:   buf[42:46],
		DstIP:   buf[46:50],
		SrcPort: buf[50:52],
		DstPort: buf[52:54]}

	return etherFrame
}

func (stoneflow *StoneFlow) ParseFlowRecord(buf []byte) error {
	for len(buf) > 0 {
		dataFormat := binary.BigEndian.Uint32(buf[0:4])
		flowLength := binary.BigEndian.Uint32(buf[4:8])
		log.Debugf("Buffer: %v", buf)
		log.Debugf("Flow Length: %v", flowLength)
		if flowLength <= 0 {
			return errors.New("Invalid flow length")
		}

		buf = buf[8:]

		if len(buf) < int(flowLength) {
			return errors.New("Invalid flow length")
		}

		flowBuf := buf[:flowLength]
		buf = buf[flowLength:]

		if dataFormat == 1 {
			log.Debug("Parsing flow record of Type 1.")
			frame := stoneflow.ParseFrame(flowBuf)
			log.Debug("Frame: %v", frame)
			stoneflow.ReadIn <- frame
		}
		if dataFormat == 1001 {
			log.Debug("Parsing flow record of Type 1001.")
		}
	}
	return nil
}

func (stoneflow *StoneFlow) ParseSampleData(buf []byte) error {
	var err error
	if len(buf) < 33 {
		return errors.New("Incorrect length for Sample Data header")
	}
	sampleHeader := stoneflow.ParseSampleHeader(buf)
	log.Infof("Sample Header: %v", sampleHeader)
	buf = buf[32:]
	err = stoneflow.ParseFlowRecord(buf)
	if stoneflow.CheckError(err) {
		return err
	}

	log.Debugf("Buffer Length: %v", len(buf))

	return nil
}

func (stoneflow *StoneFlow) ParseVersionFive(buf []byte) {
	for len(buf) > 0 {
		log.Debug("Parsing Version 5")
		if len(buf) < 8 {
			return
		}
		sFlowType := binary.BigEndian.Uint32(buf[0:4])
		buf = buf[4:]

		if sFlowType == 1 {
			sampleLength := binary.BigEndian.Uint32(buf[0:4])
			if sampleLength <= 32 {
				break
			}
			log.Infof("Sample Length: %v", sampleLength)
			buf = buf[4:]
			buf = buf[:sampleLength]
			log.Debug("Parsing Sample Data")
			stoneflow.ParseSampleData(buf)
		}
	}
}

func (stoneflow *StoneFlow) DatagramHandler(buf []byte) {
	sFlowHeaders, err := stoneflow.ParseHeaders(buf)
	if stoneflow.CheckError(err) {
		return
	}

	log.Infof("sFlow Headers: %v\n", sFlowHeaders)

	if sFlowHeaders.version != 5 {
		log.Warningf("sFlow datagram not version 5")
	} else {
		buf = buf[24+len(sFlowHeaders.address):]
		log.Debugf("Len: %v", 24+len(sFlowHeaders.address))
		stoneflow.ParseVersionFive(buf)
	}
}

func (stoneflow *StoneFlow) StartSFlow() {
	address, err := net.ResolveUDPAddr("udp", ":6343")
	l, err := net.ListenUDP("udp", address)
	if err != nil {
		fmt.Print("error")
	}
	defer l.Close()

	for {
		buf := make([]byte, 1500)
		n, _, err := l.ReadFromUDP(buf)
		stoneflow.CheckError(err)
		//log.Debugf("Received from %v: %v\n", addr, buf)

		// Make a copy of the received data
		pkt := make([]byte, n)
		copy(pkt, buf)

		go stoneflow.DatagramHandler(pkt)
	}
}

func CreateSFlow() *StoneFlow {
	stoneflowchannel := make(chan *EtherFrame)
	stoneflow := &StoneFlow{ReadIn: stoneflowchannel}
	go stoneflow.StartSFlow()

	return stoneflow
}
