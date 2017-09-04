// vtFileSearch - shows how to use VT Intelligence to search for files that match certain criteria.
//
// scusi@posteo.de
//
package main

import (
	"flag"
	"fmt"
	"github.com/williballenthin/govt"
	"log"
	"os"
)

var apikey string
var query string
var hashlist []string
var offset string
var Client *govt.Client
var err error

func init() {
	flag.StringVar(&apikey, "apikey", os.Getenv("VT_API_KEY"), "Set environment variable VT_API_KEY to your VT API Key or specify on prompt")
	flag.StringVar(&query, "query", "", "your search request")
}

func main() {
	flag.Parse()
	Client, err = govt.New(
		govt.SetErrorLog(log.New(os.Stderr, "VT: ", log.Lshortfile)),
		govt.SetApikey(apikey),
	)
	offset = ""
	fetchAllHashes(query, offset)
	fmt.Printf("found %d matches:\n", len(hashlist))
	for i, h := range hashlist {
		fmt.Printf("[%04d]\t\t%s\n", i, h)
	}
}

func fetchAllHashes(query, offset string) {
	result, err := Client.SearchFile(query, offset)
	if err != nil {
		log.Fatal(err)
	}
	//fmt.Printf("%+v\n", result)
	offset = result.Offset
	for _, h := range result.Hashes {
		hashlist = append(hashlist, h)
	}
	if offset != "" {
		fetchAllHashes(query, offset)
	}
	return
}
