package main

import (
	"github.com/hashicorp/golang-lru"
	"net"
	"time"
	_ "fmt"
	"encoding/binary"
)

var slabNumber uint16 = 8

type reqElementKey struct {
	srcIP		uint32;
	dstIP		uint32;
	srcPort		uint16;
	dstPort		uint16;
	queryID		uint16;
}

type reqElementValue struct {
	req_time	time.Time;
	req_type	uint16;
	req_name	string;
}


func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}


type reqCache struct {
	lruCache []*lru.Cache
}

func (rC *reqCache) Init(size int){
	for i:=0; i<(int)(slabNumber); i++{
		lc, _ := lru.New(size)
		rC.lruCache = append(rC.lruCache, lc)
	}
	//rC.lruCache, _ = lru.New(size)
}

func (rC *reqCache)addRequest(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16, queryID uint16, qtype uint16, qName string, tinenow time.Time){

	//fmt.Printf("%s,%s,%d,%d,%d\n", srcIP, dstIP, srcPort, dstPort, queryID)

	//fmt.Printf("cache lenth: %d\n", rC.lruCache.Len())
	reqE := reqElementKey{ip2int(srcIP), ip2int(dstIP), srcPort, dstPort, queryID}
	reqV := reqElementValue{tinenow, qtype, qName}

	rC.lruCache[queryID&(slabNumber-1)].Add(reqE, reqV)
}


func (rc *reqCache)findRequest(srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16, queryID uint16)(*time.Time){

	reqE := reqElementKey{ip2int(dstIP), ip2int(srcIP), dstPort, srcPort, queryID}

	reqV, _ := rc.lruCache[queryID&(slabNumber-1)].Peek(reqE)

	if(reqV == nil){
		return nil
	}else{
		req_time := (reqV.(reqElementValue).req_time)
		return &req_time
	}

}
