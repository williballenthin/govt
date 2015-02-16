// vtDomainReport.go - fetches and shows a VirusTotal Domain Report.
// usage:
//  vtDomainReport.go -domain=scusiblog.org
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
var md5 string

// init - initializes flag variables.
func init() {
	flag.StringVar(&apikey, "apikey", os.Getenv("VT_API_KEY"), "Set environment variable VT_API_KEY to your VT API Key or specify on prompt")
	flag.StringVar(&apiurl, "apiurl", "https://www.virustotal.com/vtapi/v2/", "URL of the VirusTotal API to be used.")
	flag.StringVar(&domain, "domain", "", "a domain to ask information about from VT.")
}

// check - an error checking function
func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	flag.Parse()
	if domain == "" {
		fmt.Println("-domain=<domainname> fehlt!")
		os.Exit(1)
	}
	c := govt.Client{Apikey: apikey, Url: apiurl}

	// get a domain report (passive dns info)
	d, err := c.GetDomainReport(domain)
	check(err)
	j, err := json.MarshalIndent(d, "", "  ")
	fmt.Printf("DomainReport: ")
	os.Stdout.Write(j)
}
