// vtUrlScan - Requests VirusTotal to scan a given URL
//  vtUrlScan -url=http://www.virustotal.com/
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
var url string

// init - initializes flag variables.
func init() {
	flag.StringVar(&apikey, "apikey", os.Getenv("VT_API_KEY"), "Set environment variable VT_API_KEY to your VT API Key or specify on prompt")
	flag.StringVar(&apiurl, "apiurl", "https://www.virustotal.com/vtapi/v2/", "URL of the VirusTotal API to be used.")
	flag.StringVar(&url, "url", "", "url of a file to as VT about.")
}

// check - an error checking function
func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	flag.Parse()
	if url == "" {
		fmt.Println("-url=<url> fehlt!")
		os.Exit(1)
	}
	c, err := govt.New(govt.SetApikey(apikey), govt.SetUrl(apiurl))
	check(err)

	// get an URL report
	r, err := c.ScanUrl(url)
	check(err)
	fmt.Printf("r: %s\n", r)
	j, err := json.MarshalIndent(r, "", "    ")
	fmt.Printf("UrlReport: ")
	os.Stdout.Write(j)
}
