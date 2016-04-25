// vtUrlScanList - Requests VirusTotal to scan URLs from a given file. The file must contain urls (one per line)
//  vtUrlScanList -list=urls.txt
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/williballenthin/govt"
	"os"
)

var apikey string
var apiurl string
var domain string
var list string

// init - initializes flag variables.
func init() {
	flag.StringVar(&apikey, "apikey", os.Getenv("VT_API_KEY"), "Set environment variable VT_API_KEY to your VT API Key or specify on prompt")
	flag.StringVar(&apiurl, "apiurl", "https://www.virustotal.com/vtapi/v2/", "URL of the VirusTotal API to be used.")
	flag.StringVar(&list, "list", "", "file with list of urls (one per line)")
}

// check - an error checking function
func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	flag.Parse()
	if list == "" {
		fmt.Println("-list=<file> missing!")
		os.Exit(1)
	}
	// create a new VT client
	c := govt.Client{Apikey: apikey, Url: apiurl}

	// read the list of files
	f, err := os.Open(list)
	check(err)
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		url := scanner.Text()
		// get an URL report
		r, err := c.ScanUrl(url)
		check(err)
		//fmt.Printf("r: %s\n", r)
		j, err := json.MarshalIndent(r, "", "    ")
		fmt.Printf("UrlScan: ")
		os.Stdout.Write(j)
		fmt.Println()
	}

}
