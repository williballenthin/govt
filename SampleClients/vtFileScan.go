// vtFileScan - request VirusTotal to scan a given file.
//  vtFileScan -file=/path/to/fileToScan.ext
//
package main

import (
	"encoding/json"
	"fmt"
	"github.com/williballenthin/govt"
	//"github.com/scusi/govt"
	"flag"
	"os"
)

var apikey string
var apiurl string
var domain string
var file string

// init - initializes flag variables.
func init() {
	flag.StringVar(&apikey, "apikey", os.Getenv("VT_API_KEY"), "Set environment variable VT_API_KEY to your VT API Key or specify on prompt")
	flag.StringVar(&apiurl, "apiurl", "https://www.virustotal.com/vtapi/v2/", "URL of the VirusTotal API to be used.")
	flag.StringVar(&file, "file", "", "file to send to VT for scanning.")
}

// check - an error checking function
func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	flag.Parse()
	if file == "" {
		fmt.Println("-file=<fileToScan.ext> fehlt!")
		os.Exit(1)
	}
	c := govt.Client{Apikey: apikey, Url: apiurl}

	// get a file report
	r, err := c.ScanFile(file)
	check(err)
	//fmt.Printf("r: %s\n", r)
	j, err := json.MarshalIndent(r, "", "    ")
	fmt.Printf("FileReport: ")
	os.Stdout.Write(j)

}
