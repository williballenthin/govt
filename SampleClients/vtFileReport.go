// vtFileReport - fetches a report from VirusTotal for the given resource. A resource can be MD5, SHA-1 or SHA-2 of a file.
//  vtFileReport -rsrc=8ac31b7350a95b0b492434f9ae2f1cde
//
package main

import (
	"encoding/json"
	"fmt"
	//"github.com/williballenthin/govt"
	"flag"
	"github.com/scusi/govt"
	"os"
)

var apikey string
var apiurl string
var domain string
var rsrc string

// init - initializes flag variables.
func init() {
	flag.StringVar(&apikey, "apikey", os.Getenv("VT_API_KEY"), "Set environment variable VT_API_KEY to your VT API Key or specify on prompt")
	flag.StringVar(&apiurl, "apiurl", "https://www.virustotal.com/vtapi/v2/", "URL of the VirusTotal API to be used.")
	flag.StringVar(&rsrc, "rsrc", "8ac31b7350a95b0b492434f9ae2f1cde", "resource of file to retrieve report for. A resource can be md5, sha-1 or sha-2 sum of a file.")
}

// check - an error checking function
func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	flag.Parse()
	if rsrc == "" {
		fmt.Println("-rsrc=<md5|sha-1|sha-2> not given!")
		os.Exit(1)
	}
	c := govt.Client{Apikey: apikey, Url: apiurl}

	// get a file report
	r, err := c.GetFileReport(rsrc)
	check(err)
	//fmt.Printf("r: %s\n", r)
	j, err := json.MarshalIndent(r, "", "    ")
	fmt.Printf("FileReport: ")
	os.Stdout.Write(j)
	//fmt.Printf("%d %s \t%s \t%s \t%d/%d\n", r.Status.ResponseCode, r.Status.VerboseMsg, r.Resource, r.ScanDate, r.Positives, r.Total)
}
