// vtUrlScanList - Requests VirusTotal to scan URLs from a given file. The file must contain urls (one per line)
//  vtUrlScanList -list=urls.txt
package main

import (
	//"encoding/json"
	"bufio"
	"flag"
	"fmt"
	"github.com/williballenthin/govt"
	"os"
	//"time"
	"net/url"
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
		str := scanner.Text()
		// TODO: check if input is a url, otherwise skip it
		url, err := parseUrl(str)
		if err != nil {
			break
		}
		// get an URL report
		r, err := c.GetUrlReport(url.String())
		check(err)
		//fmt.Printf("r: %s\n", r)
		//j, err := json.MarshalIndent(r, "", "    ")
		//fmt.Printf("UrlReport: ")
		//os.Stdout.Write(j)
		//fmt.Println()
		fmt.Printf("[%d/%d] %s\n", r.Positives, r.Total, url)
		// the following sleep is needed because the API is rate limited to 4 requests per minute,
		// unless your api key is encountered not beeing rate limited.
		// time.Sleep(25 * time.Second)
	}

}

// parseURL - takes an URL string as input and returns a pointer to an url.URL object
func parseUrl(ustr string) (u *url.URL, err error) {
	u, err = url.Parse(ustr)
	return u, err
}
