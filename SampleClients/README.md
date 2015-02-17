# Sample Clients for govt

Provides some example program that use the govt module.

In general all client programs get their VirusTotal API Key via an environment variable (VT_API_KEY).
Therefore you have to export VT_API_KEY before useing any of the provided examples.

 ```export VT_API_KEY=<YOUR_API_KEY_GOES_HERE>```


## Overview

* vtDomainReport.go - fetches a domain report for a given domain
* vtFileCheck.go - checks if a given resource is known by VT (without uploading a given sample)
* vtFileDownload.go - downloads a sample from VT (needs private API Key)
* vtFileNetworkTraffic.go - downloads pcap from VT for a given resource
* vtFileKnownBySymantec.go - checks if a given resource is detected by a certain AV , Symantec is used in this example
* vtFileReport.go - fetches a report for a given sample
* vtFileRescan.go - initiates a rescan for a given sample
* vtFileScan.go - uploads a file for scanning
* vtIpReport.go - fetches a report for a given IP address
* vtUrlReport.go - fetches a report for a given url
* vtUrlScan.go - initiates a url scan for a given url.
