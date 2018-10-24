// vtFileBehaviour - fetches a Cuckoo behaviour report from VirusTotal for the given resource. A resource can be MD5, SHA-1 or SHA-2 of a file.
//  vtFileBehaviour -rsrc=1F4C43ADFD45381CFDAD1FAFEA16B808
//
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/williballenthin/govt"
)

var apikey string
var apiurl string
var rsrc string

// init - initializes flag variables.
func init() {
	flag.StringVar(&apikey, "apikey", os.Getenv("VT_API_KEY"), "Set environment variable VT_API_KEY to your VT API Key or specify on prompt")
	flag.StringVar(&apiurl, "apiurl", "https://www.virustotal.com/vtapi/v2/", "URL of the VirusTotal API to be used.")
	flag.StringVar(&rsrc, "rsrc", "", "resource of file to retrieve behaviour report for. A resource can be md5, sha-1 or sha-2 sum of a file.")
}

// check - an error checking function
func check(e error) {
	if e != nil {
		log.Println(e)
		panic(e)
	}
}

func main() {
	flag.Parse()
	if rsrc == "" {
		fmt.Println("-rsrc=<md5|sha-1|sha-2> not given!")
		os.Exit(1)
	}
	c, err := govt.New(govt.SetApikey(apikey), govt.SetUrl(apiurl))
	check(err)

	// Get a file behaviour report
	r, err := c.GetFileBehaviour(rsrc)
	check(err)
	j, err := json.MarshalIndent(r, "", "    ")
	check(err)
	fmt.Printf("FileBehaviour: ")
	os.Stdout.Write(j)
}
