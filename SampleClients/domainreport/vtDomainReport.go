// vtDomainReport.go - fetches and shows a VirusTotal Domain Report.
// usage:
//  vtDomainReport.go -domain=scusiblog.org
//
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/slavikm/govt"
	"os"
)

var apikey string
var apiurl string
var domain string

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
	c, err := govt.New(govt.SetApikey(apikey), govt.SetUrl(apiurl))
	check(err)
	// get a domain report (passive dns info)
	d, err := c.GetDomainReport(domain)
	check(err)
	j, err := json.MarshalIndent(d, "", "  ")
	fmt.Printf("DomainReport: ")
	os.Stdout.Write(j)
}
