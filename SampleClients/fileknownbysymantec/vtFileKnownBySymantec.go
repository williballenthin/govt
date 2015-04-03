// vtFileKnownBySymantec.go - checks via VirusTotal if a given file is detected by Symantec AV.
package main

import (
	"crypto/md5"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/slavikm/govt"
	"io"
	"os"
)

var apikey string
var apiurl string
var rsrc string
var file string
var vtUpload bool

func init() {
	flag.StringVar(&apikey, "apikey", os.Getenv("VT_API_KEY"), "Set environment variable VT_API_KEY to your VT API Key or specify on prompt")
	flag.StringVar(&apiurl, "apiurl", "https://www.virustotal.com/vtapi/v2/", "URL of the VirusTotal API to be used.")
	flag.StringVar(&rsrc, "rsrc", "8ac31b7350a95b0b492434f9ae2f1cde", "resource of file to check VT for. Resource can be md5, sha-1 or sha-2 sum of a file.")
	flag.StringVar(&file, "file", "", "submit a file instead of a resource")
	flag.BoolVar(&vtUpload, "upload-vt", false, "if 'true' files unknown to VT will be uploaded to VT")
}

// calculate md5 of a given file
func calcMd5(filename string) (md5sum string) {
	f, err := os.Open(filename)
	check(err)
	defer f.Close()
	md5 := md5.New()
	_, err = io.Copy(md5, f)
	return fmt.Sprintf("%x", md5.Sum(nil))
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	flag.Parse()
	fileForError := ""
	if file != "" {
		rsrc = calcMd5(file)
		fileForError = file
	} else {
		fileForError = "</path/to/file>"
	}

	c, err := govt.New(govt.SetApikey(apikey), govt.SetUrl(apiurl))
	check(err)

	r, err := c.GetFileReport(rsrc)
	check(err)
	if r.ResponseCode == 0 {
		fmt.Println(rsrc + " NOT KNOWN by VirusTotal")
		if vtUpload == true && file != "" {
			r, err := c.ScanFile(file)
			check(err)
			j, err := json.MarshalIndent(r, "", "    ")
			fmt.Printf("FileReport: ")
			os.Stdout.Write(j)
		} else {
			fmt.Printf("For uploading to VT use vtFileScan -file=%s\n", fileForError)
		}
	} else {
		sr := r.Scans["Symantec"]
		if sr.Detected == true {
			fmt.Printf("%s detected by Symantec Version %s as %s since update %s\n", rsrc, sr.Version, sr.Result, sr.Update)
		} else {
			fmt.Printf("%s NOT detected by Symantec; Detection Rate: [%d/%d]\n", rsrc, r.Positives, r.Total)
			fmt.Printf("If you want to upload this file to VT use: 'vtFileScan -file=%s'\n", fileForError)
			fmt.Printf("If you want to submit it to Symantec use: 'symantecUpload -file=%s'\n", fileForError)
		}
	}
}
