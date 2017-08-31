package main

import (
	"time"
	"flag"
	"log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	layers "github.com/google/gopacket/layers"
	dns "github.com/miekg/dns"
	"runtime"
	"strings"
	//"gopkg.in/RS-liuyang/rotate-log.v2"
	"github.com/RS-liuyang/rotate-log"
	_ "io/ioutil"
	"path/filepath"
	"github.com/hashicorp/golang-lru"
	"sort"
	gdq "github.com/Workiva/go-datastructures/queue"
	"fmt"
)

var (
	device       string
	pcapFile	 string
	snapshot_len int32  = 1500
	promiscuous  bool   = true
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
	processorNumber int

	maxWorkers	int
	WorkerPoll	chan chan gopacket.Packet
	requestCache	reqCache
	requestCacheSize	int = 100 * 10000
	dnsLog		*log.Logger
	dnsLogPath	string
	dnsLogSize	int = 100
	dnsLogMaxBak	int

	finishedFiles *lru.Cache
	pcapFiles	chan(string) = make(chan string, 10000)

	sourceDir	string
	sourceFilePattern		string = "*.pcap"
	sourceFiles []string

	configFileName	string
	pcapLinkType	int = -1

	logbuffer	*gdq.RingBuffer
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
				//debug
				//continue
				analysis_packet(packet)
			case <-w.quit:
				return
			}

		}
	}()
}

func listFiles(directory string, pattern string) (FilesNames []string, err error) {

	filepattern := directory +"/" +pattern
	files, err := filepath.Glob(filepattern)

	sort.Strings(files)

	return files, err
}

func getFilesPeriod() {
	for {
		FileList, _ := listFiles(sourceDir, sourceFilePattern)
		for _, filename := range FileList {
			dealed, _ := finishedFiles.Peek(filename)
			if (dealed != nil) {
				//fmt.Printf("%s already in process\n", filename)
				continue
			}
			pcapFiles <- filename
			finishedFiles.Add(filename, true)
		}
		time.Sleep(10 * time.Second)
	}
}

func DealFile() {
	for{
		filename := <-pcapFiles
		dealPcap(filename)
	}
}

func RRString(rr dns.RR) string{

	if rr.Header().Rrtype == dns.TypeA || rr.Header().Rrtype == dns.TypeAAAA {

	}else{
		return ""
	}
	retString := dns.Type(rr.Header().Rrtype).String() + "_"

	ss := strings.Split(rr.String(), "\t")
	retString += ss[len(ss)-1]

	return retString
}

func AnswerString(msg *dns.Msg)string {
	retString := ""
	for _, rr := range msg.Answer{
	//for index, rr := range msg.Answer{
		//if index > 0 {
		s_rr := RRString(rr)
		if len(s_rr) == 0{
			continue
		}
		if len(retString)>0 {
			retString += ";"
		}
		retString += s_rr //RRString(rr)
	}
	return retString
}

func analysis_packet(packet gopacket.Packet) {
	// Process packet here
	//fmt.Println(packet)

	defer func() {
		panicked := recover()

		if panicked != nil {
			log.Printf("%v\n", panicked)
			//log.Printf("cache size is %d\n", requestCache.lruCache.Len())
		}
	}()

	var timenow time.Time

	if(packet.Metadata() == nil){
		timenow = time.Now()
	}else{
		timenow = packet.Metadata().Timestamp
	}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		log.Println("ip layer missing")
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
			//fmt.Println("dns unpack error")
			return
		}

		if len(msg.Question) == 0 {
			return
		}
		//fmt.Println(msg)

		if msg.Response {
			//find request info and logout
			req_time := requestCache.findRequest(ip.SrcIP, ip.DstIP, (uint16)(udp.SrcPort), (uint16)(udp.DstPort), msg.Id)
			var duration float32

			if(req_time == nil){
				tmp_time := timenow.Add(time.Duration(-100)*time.Millisecond)
				req_time = &tmp_time
				duration = 100
			}else{
				duration = (float32)(timenow.UnixNano() - req_time.UnixNano())/1000000
			}

			//debug
			//return
			logbuffer.Put(fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d|%d|%d|%s|%.3f\n",
				ip.DstIP.String(),
				ip.SrcIP.String(),
				req_time.Format("20060102150405.000000"),
				timenow.Format("20060102150405.000000"),
				//strings.TrimSuffix(msg.Question[0].Name, "."),
				msg.Question[0].Name[0:len(msg.Question[0].Name)-1],
				dns.Type(msg.Question[0].Qtype).String(),
				msg.Id,
				udp.DstPort,
				msg.Rcode,
				AnswerString(msg),
				duration))

/*
			dnsLog.Printf("%s|%d|%s|%d|%s|%s|%s|%s|%s|%.4f\n", ip.DstIP.String(), udp.DstPort,
				ip.SrcIP.String(), udp.SrcPort,
				dns.RcodeToString[msg.Rcode],
				dns.Type(msg.Question[0].Qtype).String(),
				msg.Question[0].Name,
				AnswerString(msg),
				timenow.Format("20060102150405.000"), duration)
*/

		}else{
			//a request info should saved into LRU cache
			requestCache.addRequest(ip.SrcIP, ip.DstIP, (uint16)(udp.SrcPort), (uint16)(udp.DstPort), msg.Id, msg.Question[0].Qtype, msg.Question[0].Name, timenow)
			//fmt.Println("get request")
		}
		//for rr := range msg.Answer[] {

		//}
	}
}

func main() {
	flag.StringVar(&configFileName, "c", "", "config file name")
	flag.StringVar(&sourceDir, "d", "", "source pcap path")
	flag.StringVar(&device, "i", "eth0", "ether card name" )
	flag.StringVar(&pcapFile, "r", "", "pcap file name")
	flag.IntVar(&processorNumber, "p", runtime.NumCPU(), "number of processor to use")
	flag.StringVar(&dnsLogPath, "o", "./", "log path")
	flag.IntVar(&dnsLogSize, "b", 100, "fixed file size (MB), default is 100(MB)")
	flag.Parse()

	maxWorkers = processorNumber

	if configFileName != "" {
		log.Printf("Parsing config file -- %s\n", configFileName)
		config := newConfig(configFileName)

		sourceDir = config.Pcap_path
		sourceFilePattern = config.Pcap_Patten
		dnsLogPath = config.Log_Path
		dnsLogSize = config.MaxLogSize
		dnsLogMaxBak = config.MaxBackups
		if(config.LinkType != 0){
			pcapLinkType = config.LinkType
		}
		if(config.MaxLogSize != 0){
			requestCacheSize = config.ReqCacheSize * 10000
		}

		log.Printf("Pcap Source directoy: %s\n", sourceDir)
		log.Printf("Pcap file pattern: %s\n", sourceFilePattern)
		log.Printf("dns log directory: %s\n", dnsLogPath)
		log.Printf("dns log file max size: %dMB\n", dnsLogSize)
		log.Printf("dns log file max backup number: %d\n", dnsLogMaxBak)
		log.Printf("predefined pcap linktype: %d\n", pcapLinkType)
		log.Printf("request cache size: %d\n", requestCacheSize)
	}


	WorkerPoll = make(chan chan gopacket.Packet, maxWorkers)

	if(processorNumber+2 > runtime.NumCPU()){
		processorNumber = runtime.NumCPU()
	}else{
		processorNumber +=2
	}
	runtime.GOMAXPROCS(processorNumber)

	requestCache.Init(requestCacheSize)

	finishedFiles, _ = lru.New(10000)

	logbuffer = gdq.NewRingBuffer(10000)

	var dnsFileName = dnsLogPath + "/dnscap.log"
	/*

	dnsLog = log.New(&lumberjack.Logger{
		Filename:   dnsFileName,
		MaxSize:    dnsLogSize, // megabytes after which new file is created
		MaxBackups: dnsLogMaxBak, // number of backups
		MaxAge:     0, //days
		LocalTime:	true,
	}, "", log.Ldate|log.Ltime)


	dnsLog.SetFlags(0)
	*/

	for i:=0; i<maxWorkers;i++ {
		worker:=newWorker(WorkerPoll)
		worker.Start()
	}

	go func(){
		dnsLog2 := lumberjack.Logger{
			Filename:   dnsFileName,
			MaxSize:    dnsLogSize, // megabytes after which new file is created
			MaxBackups: dnsLogMaxBak, // number of backups
			MaxAge:     0, //days
			LocalTime:	true,
		}

		for{
			s , _:=logbuffer.Get()
			b :=[]byte(s.(string))
			dnsLog2.Write(b)
			//dnsLog.Print(s)
		}
	}()

	if(sourceDir != "") {
		go getFilesPeriod()
		DealFile()

	}else if(pcapFile == ""){
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
		log.Println("Only capturing UDP port 53 packets.")
	}else{
		// Open file instead of device
		handle, err = pcap.OpenOffline(pcapFile)
		if err != nil { log.Fatal(err) }
		defer handle.Close()
		log.Println("open pcap file ", pcapFile)
	}


	// Use the handle as a packet source to process all packets
	//packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource := gopacket.NewPacketSource(handle, layers.LinkTypeRaw)
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	for packet := range packetSource.Packets() {
		//analysis_packet(packet)
		//go func(packet gopacket.Packet){
		//	analysis_packet(packet)

		packetChannel := <-WorkerPoll
		packetChannel <- packet
		//}(packet)
	}
}

func dealPcap(pcapFile string) {

	handle, err = pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Println(err)
		finishedFiles.Remove(pcapFile)
		return
	}

	log.Println("processing pcap file ", pcapFile)

	var packetSource *gopacket.PacketSource
	// Use the handle as a packet source to process all packets
	if(pcapLinkType == -1 || pcapLinkType == 0){
		packetSource = gopacket.NewPacketSource(handle, handle.LinkType())
	}else{
		packetSource = gopacket.NewPacketSource(handle, (layers.LinkType)(pcapLinkType))
	}

	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	for packet := range packetSource.Packets() {

		packetChannel := <-WorkerPoll
		packetChannel <- packet
	}

	log.Println("processing finished")
}