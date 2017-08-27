package main

import (
	"os"
	"log"
	"io/ioutil"
	"encoding/json"
)

type Config struct {
	Pcap_path		string
	Pcap_Patten		string
	Log_Path		string
	MaxLogSize		int
	MaxBackups		int
	LinkType		int
	ReqCacheSize	int
}

func newConfig(configFile string) *Config{
	config := parseJson(configFile)
	return config

}

func parseJson(path string) *Config {

	f, err := os.Open(path)
	if err != nil {
		log.Fatal("Open config file failed: ", err)
		os.Exit(1)
	}
	defer f.Close()

	b, err := ioutil.ReadAll(f)
	if err != nil {
		log.Fatal("Read config file failed: ", err)
		os.Exit(1)
	}

	j := new(Config)
	err = json.Unmarshal(b, j)
	if err != nil {
		log.Fatal("Json syntex error: ", err)
		os.Exit(1)
	}

	return j
}