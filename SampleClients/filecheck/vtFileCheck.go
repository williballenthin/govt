// vtFileCheck.go - checks if VirusTotal knows a given file.
package main

import (
	"flag"
	"fmt"
	"github.com/slavikm/govt"
	"os"
)

var apikey string
var apiurl string
var rsrc string

func init() {
	flag.StringVar(&apikey, "apikey", os.Getenv("VT_API_KEY"), "Set environment variable VT_API_KEY to your VT API Key or specify on prompt")
	flag.StringVar(&apiurl, "apiurl", "https://www.virustotal.com/vtapi/v2/", "URL of the VirusTotal API to be used.")
	flag.StringVar(&rsrc, "rsrc", "8ac31b7350a95b0b492434f9ae2f1cde", "resource of file to check VT for. Resource can be md5, sha-1 or sha-2 sum of a file.")
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	flag.Parse()
	c, err := govt.New(govt.SetApikey(apikey), govt.SetUrl(apiurl))
	check(err)

	r, err := c.GetFileReport(rsrc)
	check(err)
	if r.ResponseCode == 0 {
		//fmt.Println( r.VerboseMsg )
		fmt.Println(rsrc + " NOT KNOWN by VirusTotal")
	} else {
		//fmt.Println(rsrc + "["+r.Positives+"/"+r.Total+"] IS KNOWN by VirusTotal")
		fmt.Printf("%s [%d/%d] IS KNOWN by VirusTotal\n", rsrc, r.Positives, r.Total)
		//j, err := json.MarshalIndent(r, "", "    ")
		//fmt.Printf("FileReport: ")
		//os.Stdout.Write(j)
	}
}
