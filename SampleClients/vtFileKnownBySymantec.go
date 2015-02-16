// vtFileKnownBySymantec.go - checks via VirusTotal if a given file is detected by Symantec AV.
package main

import (
	"fmt"
	"io"
	"os"
	//"log"
	"bytes"
	"flag"
	//"strconv"
	"bufio"
	"crypto/md5"
	"encoding/json"
	"github.com/williballenthin/govt"
	"io/ioutil"
)

var apikey string
var apiurl string
var rsrc string
var file string
var vtUpload bool

func init() {
	flag.StringVar(&apiurl, "apiurl", "https://www.virustotal.com/vtapi/v2/", "URL of the VirusTotal API to be used.")
	flag.StringVar(&rsrc, "rsrc", "8ac31b7350a95b0b492434f9ae2f1cde", "resource of file to check VT for. Resource can be md5, sha-1 or sha-2 sum of a file.")
	flag.StringVar(&file, "file", "", "submit a file instead of a resource")
	flag.BoolVar(&vtUpload, "upload-vt", false, "if 'true' files unknown to VT will be uploaded to VT")
}

func loader(filename string) (content []byte, err error) {
	//log.Printf("load file '%s'\n", filename)
	content, err = ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return content, nil
}

// calculate md5 of a given file
func calcMd5(filename string) (md5sum string) {
	content, err := loader(filename)
	check(err)
	md5 := md5.New()
	w := io.Writer(md5)
	w.Write(content)
	//log.Printf("%s has MD5: %x", filename, md5.Sum(nil))
	return string(md5.Sum(nil))
}

func getApiKeyFromEnv() (apikey string) {
	apikey = os.Getenv("VT_API_KEY")
	if len(apikey) == 0 {
		panic("VT_API_KEY is not set!\n")
	}
	if len(apikey) < 64 {
		panic("VT_API_KEY is to short!\n")
	}
	return apikey
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	flag.Parse()
	//log.Printf("flags parsed")
	if file != "" {
		//log.Printf("param 'file' is set")
		md5s := &bytes.Buffer{}
		w := bufio.NewWriter(md5s)
		//bw, err := fmt.Fprintf(w, "%x", calcMd5(file) )
		_, err := fmt.Fprintf(w, "%x", calcMd5(file))
		w.Flush()
		check(err)
		//fmt.Printf("%d bytes written to buffer\n", bw)
		//fmt.Printf("buffer as string: '%s'\n", md5s.String() )
		//fmt.Println("md5s.String():", md5s.String() )
		//os.Exit(1)
		rsrc = md5s.String()
	} else {
		//log.Printf("param 'file' not set")
		file = "/path/to/" + rsrc
	}
	apikey := getApiKeyFromEnv()
	//log.Printf("APIKEY is: %s", apikey)
	c := govt.Client{Apikey: apikey, Url: apiurl}
	r, err := c.GetFileReport(rsrc)
	check(err)
	//log.Printf("GetFile response was: %s", r.VerboseMsg)
	//log.Printf("GetFile response was: %#v", r)
	if r.ResponseCode == 0 {
		//log.Println("ResponseCode was '0'")
		//fmt.Println( r.VerboseMsg )
		fmt.Println(rsrc + " NOT KNOWN by VirusTotal")
		if vtUpload == true {
			r, err := c.ScanFile(file)
			check(err)
			j, err := json.MarshalIndent(r, "", "    ")
			fmt.Printf("FileReport: ")
			os.Stdout.Write(j)
		} else {
			fmt.Println("For uploading to VT use vtFileScan -file=" + file)
		}
	} else {
		//log.Println("ResponseCode was NOT '0'")
		//fmt.Println(rsrc +" IS KNOWN by VirusTotal")
		sr := r.Scans["Symantec"]
		if sr.Detected == true {
			fmt.Printf("%s detected by Symantec Version %s as %s since update %s\n", rsrc, sr.Version, sr.Result, sr.Update)
		} else {
			fmt.Printf("%s NOT detected by Symantec; Detection Rate: [%d/%d]\n", rsrc, r.Positives, r.Total)
			fmt.Printf("If you want to upload this file to VT use: 'vtFileScan -file=%s'\n", file)
			fmt.Printf("If you want to submit it to Symantec use: 'symantecUpload -file=%s'\n", file)
			for s := range r.Scans {
				if r.Scans[s].Detected == true {
					//log.Printf("detected by: '%s'\n", s)
				} else {
					continue
				}
			}
		}
		//j, err := json.MarshalIndent(r, "", "    ")
		//fmt.Printf("FileReport: ")
		//os.Stdout.Write(j)
	}
	//log.Println("End of Execution")
}
