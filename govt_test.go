/*
A few test cases for the `govt` package.

We cannot have many test cases, because the public API is limited to four requests per minute.
So here, we demonstrate that the scheme works, and leave it at that

Written by Willi Ballenthin while at Mandiant.
June, 2013.
*/
package govt

import "testing"

var apikey string = ""

// TestGetFileReport tests the structure and execution of a request.
func TestGetFileReport(t *testing.T) {
	govt, err := New(SetApikey(apikey))
	if err != nil {
		t.Fatal(err)
	}

	var testMd5 string = "eeb024f2c81f0d55936fb825d21a91d6"
	report, err := govt.GetFileReport(testMd5)
	if err != nil {
		t.Error("Error requesting report: ", err.Error())
		return
	}
	if report.ResponseCode != 1 {
		t.Error("Response code indicates failure: %d", report.ResponseCode)
		return
	}

	if report.Md5 != testMd5 {
		t.Error("Requested MD5 does not match result: ", testMd5, " vs. ", report.Md5)
		return
	}
}

// TestGetFileReports tests the structure and execution of a request.
func TestGetFileReports(t *testing.T) {
	govt, err := New(SetApikey(apikey))
	if err != nil {
		t.Fatal(err)
	}

	md5s := []string{"eeb024f2c81f0d55936fb825d21a91d6", "1F4C43ADFD45381CFDAD1FAFEA16B808"}
	reports, err := govt.GetFileReports(md5s)
	if err != nil {
		t.Error("Error requesting reports: ", err.Error())
		return
	}

	for _, r := range *reports {
		if r.ResponseCode != 1 {
			t.Error("Response code indicates failure: %d", r.ResponseCode)
			return
		}
	}
}

// TestRescanFile tests the structure and execution of a request.
func TestRescanFile(t *testing.T) {
	govt, err := New(SetApikey(apikey))
	if err != nil {
		t.Fatal(err)
	}

	var testMd5 string = "eeb024f2c81f0d55936fb825d21a91d6"
	report, err := govt.RescanFile(testMd5)
	if err != nil {
		t.Error("Error requesting rescan: ", err.Error())
		return
	}
	if report.ResponseCode != 1 {
		t.Error("Response code indicates failure: %d", report.ResponseCode)
		return
	}
}

/* unless you have a high API quota, I recommend not executing the full test suite,
 *  as you'll quickly blow through you're allotment

// TestRescanFiles tests the structure and execution of a request.
func TestRescanFiles(t *testing.T) {
  govt, err := New(SetApikey(apikey))
  if err != nil {
    t.Fatal(err)
  }

	testMd5s := []string{"eeb024f2c81f0d55936fb825d21a91d6", "eeb024f2c81f0d55936fb825d21a91d6"}
	reports, err := govt.RescanFiles(testMd5s)
	if err != nil {
		t.Error("Error requesting rescan: ", err.Error())
    return
	}
  for _, report := range *reports {
    if report.ResponseCode != 1 {
      t.Error("Response code indicates failure: %d", report.ResponseCode)
      return
    }
  }
}

// TestScanUrl tests the structure and execution of a request.
func TestScanUrl(t *testing.T) {
  govt, err := New(SetApikey(apikey))
  if err != nil {
    t.Fatal(err)
  }

	var testUrl string = "http://www.virustotal.com"
	report, err := govt.RescanFile(testUrl)
	if err != nil {
		t.Error("Error requesting Scan: ", err.Error())
    return
	}
  if report.ResponseCode != 1 {
		t.Error("Response code indicates failure: %d", report.ResponseCode)
    return
  }
}

// TestScanUrls tests the structure and execution of a request.
func TestScanUrls(t *testing.T) {
  govt, err := New(SetApikey(apikey))
  if err != nil {
    t.Fatal(err)
  }

	testUrls := []string{"http://www.virustotal.com", "http://www.google.com"}
	reports, err := govt.ScanUrls(testUrls)
	if err != nil {
		t.Error("Error requesting scan: ", err.Error())
    return
	}
  for _, report := range *reports {
    if report.ResponseCode != 1 {
      t.Error("Response code indicates failure: %d", report.ResponseCode)
      return
    }
  }
}

// TestGetUrlReport tests the structure and execution of a request.
func TestGetUrlReport(t *testing.T) {
  govt, err := New(SetApikey(apikey))
  if err != nil {
    t.Fatal(err)
  }

	var testUrl string = "http://www.virustotal.com"
	report, err := govt.GetUrlReport(testUrl)
	if err != nil {
		t.Error("Error requesting report: ", err.Error())
    return
	}
  if report.ResponseCode != 1 {
		t.Error("Response code indicates failure: %d", report.ResponseCode)
    return
  }

	if report.Url != testUrl {
		t.Error("Requested URL does not match result: ", testUrl, " vs. ", report.Url)
    return
	}
}

// TestGetUrlReports tests the structure and execution of a request.
func TestGetUrlReports(t *testing.T) {
  govt, err := New(SetApikey(apikey))
  if err != nil {
    t.Fatal(err)
  }

	var testUrls []string = []string{"http://www.virustotal.com", "http://www.google.com"}
	reports, err := govt.GetUrlReports(testUrls)
	if err != nil {
		t.Error("Error requesting report: ", err.Error())
    return
	}
  for _, report := range *reports {
    if report.ResponseCode != 1 {
      t.Error("Response code indicates failure: %d", report.ResponseCode)
      return
    }
  }
}

// TestGetIpReport tests the structure and execution of a request.
//   It does not perform logical tests on the returned data.
func TestGetIpReport(t *testing.T) {
  govt, err := New(SetApikey(apikey))
  if err != nil {
    t.Fatal(err)
  }

	var testIp string = "8.8.8.8"
	report, err := govt.GetIpReport(testIp)
	if err != nil {
		t.Error("Error requesting report: ", err.Error())
    return
	}
  if report.ResponseCode != 1 {
		t.Error("Response code indicates failure: %d", report.ResponseCode)
    return
  }
}

// TestGetDomainReport tests the structure and execution of a request.
//   It does not perform logical tests on the returned data.
func TestGetDomainReport(t *testing.T) {
  govt, err := New(SetApikey(apikey))
  if err != nil {
    t.Fatal(err)
  }

	var testDomain string = "www.virustotal.com"
	report, err := govt.GetDomainReport(testDomain)
	if err != nil {
		t.Error("Error requesting report: ", err.Error())
    return
	}
  if report.ResponseCode != 1 {
		t.Error("Response code indicates failure: %d", report.ResponseCode)
    return
  }
}
*/
