/*
govt is a VirusTotal API v2 client written for Google Go.

Written by Willi Ballenthin while at Mandiant.
June, 2013.
*/
package govt

import "os"
import "fmt"
import "bytes"
import "net/url"
import "net/http"
import "encoding/json"

// Client interacts with the services provided by VirusTotal.
type Client struct {
	Apikey string // private API key
	Url    string // VT URL, probably ends with .../v2/. Must end in '/'.
}

// Status is the set of fields shared among all VT responses.
type Status struct {
	ResponseCode int    `json:"response_code"`
	VerboseMsg   string `json:"verbose_msg"`
}

// FileScan is defined by VT.
type FileScan struct {
	Detected bool   `json:"detected"`
	Version  string `json:"version"`
	Result   string `json:"result"`
	Update   string `json:"update"`
}

// FileReport is defined by VT.
type FileReport struct {
	Status
	Resource  string              `json:"resource"`
	ScanId    string              `json:"scan_id"`
	Md5       string              `json:"md5"`
	Sha1      string              `json:"sha1"`
	Sha256    string              `json:"sha256"`
	ScanDate  string              `json:"scan_date"`
	Positives uint16              `json:"positives"`
	Total     uint16              `json:"total"`
	Scans     map[string]FileScan `json:"scans"`
	Permalink string              `json:"permalink"`
}

// RescanFileResult is defined by VT.
type RescanFileResult struct {
	Status
	Resource  string `json:"resource"`
	ScanId    string `json:"scan_id"`
	Permalink string `json:"permalink"`
	Sha256    string `json:"sha256"`
}

// RescanFileResults is defined by VT.
type RescanFileResults []RescanFileResult

// ScanUrlResult is defined by VT.
type ScanUrlResult struct {
	Status
	ScanId    string `json:"scan_id"`
	ScanDate  string `json:"scan_date"`
	Permalink string `json:"permalink"`
	Url       string `json:"url"`
}

// UrlScan is defined by VT.
type UrlScan struct {
	Detected bool   `json:"detected"`
	Result   string `json:"result"`
}

// UrlReport is defined by VT.
type UrlReport struct {
	Status
	Url        string             `json:"url"`
	Resource   string             `json:"resource"`
	ScanId     string             `json:"scan_id"`
	ScanDate   string             `json:"scan_date"`
	Permalink  string             `json:"permalink"`
	Positives  uint16                `json:"positives"`
	Scans      map[string]UrlScan `json:"scans"`
	FileScanId string             `json:"filescan_id"`
}

// UrlReports is defined by VT.
type UrlReports []UrlReport

// ScanUrlResults is defined by VT.
type ScanUrlResults []ScanUrlResult

// IpResolution is defined by VT.
type IpResolution struct {
  LastResolved string `json:"last_resolved"`
  Hostname string `json:"hostname"`
}

// DetectedUrl is defined by VT.
type DetectedUrl struct {
  Url string `json:"url"`
  Total uint16 `json:"total"`
  Positives uint16 `json:"positives"`
  ScanDate string `json:"scan_date"`
}

// IpReport is defined by VT.
type IpReport struct {
  Status
  Resolutions []IpResolution
  DetectedUrls []DetectedUrl
}

// DomainResolution is defined by VT.
type DomainResolution struct {
  LastResolved string `json:"last_resolved"`
  IpAddress string `json:"ip_address"`
}

// DomainReport is defined by VT.
type DomainReport struct {
  Status
  Resolutions []DomainResolution
  DetectedUrls []DetectedUrl
}

// ClientError is a generic error specific to the `govt` package.
type ClientError struct {
	msg string
}

// Error returns a string representation of the error condition.
func (self ClientError) Error() string {
	return self.msg
}

// UseDefaultUrl configures a `Client` to use the default public
//   VT URL published on their website.
func (self *Client) UseDefaultUrl() {
	self.Url = "https://www.virustotal.com/vtapi/v2/"
}

// checkApiKey ensures that the user configured her API key,
//   or returns an error.
func (self *Client) checkApiKey() (err error) {
	if self.Apikey == "" {
		return ClientError{msg: "Empty API key is invalid"}
	} else {
		return nil
	}
}

// makeApiGetRequest fetches a URL with querystring via HTTP GET and
//  returns the response if the status code is HTTP 200
// `parameters` should not include the apikey.
// The caller must call `resp.Body.Close()`.
func (self *Client) makeApiGetRequest(fullurl string, parameters map[string]string) (resp *http.Response, err error) {
	if err = self.checkApiKey(); err != nil {
		return resp, err
	}

	values := url.Values{}
	values.Set("apikey", self.Apikey)
	for k, v := range parameters {
		values.Add(k, v)
	}

	resp, err = http.Get(fullurl + values.Encode())
	if err != nil {
		return resp, err
	}

	if resp.StatusCode != 200 {
		var msg string = fmt.Sprintf("Unexpected status code: %d", resp.StatusCode)
		resp.Write(os.Stdout)
		return resp, ClientError{msg: msg}
	}

	return resp, nil
}

// makeApiPostRequest fetches a URL with querystring via HTTP POST and
//  returns the response if the status code is HTTP 200
// `parameters` should not include the apikey.
// The caller must call `resp.Body.Close()`.
func (self *Client) makeApiPostRequest(fullurl string, parameters map[string]string) (resp *http.Response, err error) {
	if err = self.checkApiKey(); err != nil {
		return resp, err
	}

	values := url.Values{}
	values.Set("apikey", self.Apikey)
	for k, v := range parameters {
		values.Add(k, v)
	}

	resp, err = http.PostForm(fullurl, values)
	if err != nil {
		return resp, err
	}

	if resp.StatusCode != 200 {
		var msg string = fmt.Sprintf("Unexpected status code: %d", resp.StatusCode)
		resp.Write(os.Stdout)
		return resp, ClientError{msg: msg}
	}

	return resp, nil
}

// ScanUrl asks VT to redo analysis on the specified file.
func (self *Client) ScanUrl(url string) (r *ScanUrlResult, err error) {
	r = &ScanUrlResult{}

	theurl := self.Url + "url/rescan"
	parameters := map[string]string{"url": url}
	resp, err := self.makeApiPostRequest(theurl, parameters)
	if err != nil {
		return r, err
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	if err = dec.Decode(r); err != nil {
		return r, err
	}

	return r, nil
}

// ScanUrls asks VT to redo analysis on the specified files.
func (self *Client) ScanUrls(urls []string) (r *ScanUrlResults, err error) {
	r = &ScanUrlResults{}

	var allUrls bytes.Buffer
	for _, url := range urls {
		allUrls.WriteString(url)
		allUrls.WriteString("\n")
	}

	url := self.Url + "file/rescan"
	parameters := map[string]string{"resource": allUrls.String()}
	resp, err := self.makeApiPostRequest(url, parameters)
	if err != nil {
		return r, err
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	if err = dec.Decode(r); err != nil {
		return r, err
	}

	return r, nil
}

// RescanFile asks VT to redo analysis on the specified file.
func (self *Client) RescanFile(md5 string) (r *RescanFileResult, err error) {
	r = &RescanFileResult{}

	url := self.Url + "file/rescan"
	parameters := map[string]string{"resource": md5}
	resp, err := self.makeApiPostRequest(url, parameters)
	if err != nil {
		return r, err
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	if err = dec.Decode(r); err != nil {
		return r, err
	}

	return r, nil
}

// RescanFile asks VT to redo analysis on the specified files.
func (self *Client) RescanFiles(md5s []string) (r *RescanFileResults, err error) {
	r = &RescanFileResults{}

	var allMd5s bytes.Buffer
	for _, md5 := range md5s {
		allMd5s.WriteString(md5)
		allMd5s.WriteString(",")
	}

	url := self.Url + "file/rescan"
	parameters := map[string]string{"resource": allMd5s.String()}
	resp, err := self.makeApiPostRequest(url, parameters)
	if err != nil {
		return r, err
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	if err = dec.Decode(r); err != nil {
		return r, err
	}

	return r, nil
}

// GetFileReport fetches the AV scan reports tracked by VT given an MD5 hash value.
func (self *Client) GetFileReport(md5 string) (r *FileReport, err error) {
	r = &FileReport{}

	url := self.Url + "file/report?"
	parameters := map[string]string{"resource": md5}
	resp, err := self.makeApiGetRequest(url, parameters)
	if err != nil {
		return r, err
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	if err = dec.Decode(r); err != nil {
		return r, err
	}

	return r, nil
}

// GetUrlReport fetches the AV scan reports tracked by VT given a URL.
// Does not support the optional `scan` parameter.
func (self *Client) GetUrlReport(url string) (r *UrlReport, err error) {
	r = &UrlReport{}

	theurl := self.Url + "url/report"
	parameters := map[string]string{"resource": url}
	resp, err := self.makeApiPostRequest(theurl, parameters)
	if err != nil {
		return r, err
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	if err = dec.Decode(r); err != nil {
		return r, err
	}

	return r, nil
}

// GetUrlReports fetches AV scan reports tracked by VT given URLs.
// Does not support the optional `scan` parameter.
func (self *Client) GetUrlReports(urls []string) (r *UrlReports, err error) {
	r = &UrlReports{}

	var allUrls bytes.Buffer
	for _, url := range urls {
		allUrls.WriteString(url)
		allUrls.WriteString(", ")
	}

	theurl := self.Url + "url/report"
	parameters := map[string]string{"resource": allUrls.String()}
	resp, err := self.makeApiPostRequest(theurl, parameters)
	if err != nil {
		return r, err
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	if err = dec.Decode(r); err != nil {
		return r, err
	}

	return r, nil
}

// GetIpReport fetches the passive DNS information about an IP address.
func (self *Client) GetIpReport(ip string) (r *IpReport, err error) {
	r = &IpReport{}

	url := self.Url + "ip-address/report?"
	parameters := map[string]string{"ip": ip}
	resp, err := self.makeApiGetRequest(url, parameters)
	if err != nil {
		return r, err
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	if err = dec.Decode(r); err != nil {
		return r, err
	}

	return r, nil
}

// GetDomainReport fetches the passive DNS information about a DNS address.
func (self *Client) GetDomainReport(domain string) (r *DomainReport, err error) {
	r = &DomainReport{}

	url := self.Url + "domain/report?"
	parameters := map[string]string{"domain": domain}
	resp, err := self.makeApiGetRequest(url, parameters)
	if err != nil {
		return r, err
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	if err = dec.Decode(r); err != nil {
		return r, err
	}

	return r, nil
}

// MakeComment adds a comment to a file/URL/IP/domain.
func (self *Client) MakeComment(resource string, comment string) (status *Status, err error) {
	status = &Status{}

	url := self.Url + "comments/put"
	parameters := map[string]string{"resource": resource, "comment": comment}
	resp, err := self.makeApiPostRequest(url, parameters)
	if err != nil {
		return status, err
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	if err = dec.Decode(status); err != nil {
		return status, err
	}

	return status, nil
}
