package main

import (
	"time"
	"flag"
	"log"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	dns "github.com/miekg/dns"
	"runtime"
	"strings"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	device       string
	snapshot_len int32  = 1500
	promiscuous  bool   = true
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
	processorNumber int

	maxWorkers	int = 8
	WorkerPoll	chan chan gopacket.Packet
	requestCache	reqCache
	dnsLog		*log.Logger
	dnsLogPath	string
	dnsLogSize	int
)

type Worker struct{
	WorkerPoll chan chan gopacket.Packet
	PacketChannel	chan gopacket.Packet
	quit 		chan bool
}

func newWorker(workerPool chan chan gopacket.Packet) Worker{
	return Worker{
		workerPool,
		make(chan gopacket.Packet),
		make(chan bool)}
	}
func (w Worker) Start() {
	go func() {
		for {
			w.WorkerPoll <- w.PacketChannel
			select {
			case packet := <-w.PacketChannel:
				analysis_packet(packet)
			case <-w.quit:
				return
			}

		}
	}()
}

//type packetDispatcher struct {
//	maxWorkers	int
//	WorkerPoll	chan chan gopacket.Packet
//}

//func newPacketDispatcher(maxWorkers int) *packetDispatcher{
//	pool := make(chan chan gopacket.Packet, maxWorkers)
//	return &packetDispatcher{maxWorkers, pool}
//}
func RRString(rr dns.RR) string{

	retString := dns.Type(rr.Header().Rrtype).String() + "_"

	ss := strings.Split(rr.String(), "\t")
	retString += ss[len(ss)-1]

	return retString
}

func AnswerString(msg *dns.Msg)string {
	retString := ""
	for index, rr := range msg.Answer{
		if index > 0 {
			retString += ";"
		}
		retString += RRString(rr)
	}
	return retString
}

func analysis_packet(packet gopacket.Packet) {
	// Process packet here
	//fmt.Println(packet)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		//fmt.Println("UDP layers detected")
		ip := ipLayer.(*layers.IPv4)
		udp := udpLayer.(*layers.UDP)
		//fmt.Printf("From port %d to %d\n", udp.SrcPort, udp.DstPort)
		//fmt.Println(udp.Payload)

		msg := new(dns.Msg)
		err := msg.Unpack(udp.Payload)
		if (err != nil) {
			fmt.Println("dns unpack error")
			return
		}

		//fmt.Println(msg)

		if msg.Response {
			//find request info and logout
			req_time := requestCache.findRequest(ip.SrcIP, ip.DstIP, (uint16)(udp.SrcPort), (uint16)(udp.DstPort), msg.Id)
			var duration float32

			if(req_time == nil){
				duration = 100
			}else{
				duration = (float32)(time.Now().UnixNano() - req_time.UnixNano())/1000000
			}


			dnsLog.Printf("%s|%d|%s|%d|%s|%s|%s|%s|%s|%.4f\n", ip.DstIP.String(), udp.DstPort,
				ip.SrcIP.String(), udp.SrcPort,
				dns.RcodeToString[msg.Rcode],
				dns.Type(msg.Question[0].Qtype).String(),
				msg.Question[0].Name,
				AnswerString(msg),
				time.Now().Format("20060102150405.000"), duration)
			//fmt.Println("get response")
		}else{
			//a request info should saved into LRU cache
			requestCache.addRequest(ip.SrcIP, ip.DstIP, (uint16)(udp.SrcPort), (uint16)(udp.DstPort), msg.Id, msg.Question[0].Qtype, msg.Question[0].Name)
			//fmt.Println("get request")
		}
		//for rr := range msg.Answer[] {

		//}
	}
}

func main() {

	flag.StringVar(&device, "i", "eth0", "ether card name" )
	flag.IntVar(&processorNumber, "p", runtime.NumCPU(), "number of processor to use")
	flag.StringVar(&dnsLogPath, "o", "./", "log path")
	flag.IntVar(&dnsLogSize, "b", 1, "fixed file size (MB), default is 1(MB)")
	flag.Parse()

	WorkerPoll = make(chan chan gopacket.Packet, maxWorkers)

	runtime.GOMAXPROCS(processorNumber)

	requestCache.Init(10)


	var dnsFileName = dnsLogPath + "/dns_cap.log"
	dnsLog = log.New(&lumberjack.Logger{
		Filename:   dnsFileName,
		MaxSize:    dnsLogSize, // megabytes after which new file is created
		MaxBackups: 0, // number of backups
		MaxAge:     0, //days
		LocalTime:	true,
	}, "", log.Ldate|log.Ltime)


	for i:=0; i<maxWorkers;i++ {
		worker:=newWorker(WorkerPoll)
		worker.Start()
	}

	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {log.Fatal(err) }
	defer handle.Close()

	// Set filter
	var filter string = "udp and port 53"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Only capturing UDP port 53 packets.")


	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		go func(packet gopacket.Packet){
			packetChannel := <-WorkerPoll
			packetChannel <- packet
		}(packet)
	}
}
