package main

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
)

type Feedback struct {
	Record []struct {
		Row struct {
			SourceIP        string `xml:"source_ip"`
			Count           int    `xml:"count"`
			PolicyEvaluated struct {
				DKIM string `xml:"dkim"`
				SPF  string `xml:"spf"`
			} `xml:"policy_evaluated"`
		} `xml:"row"`
		AuthResults struct {
			DKIM []struct {
				Domain   string `xml:"domain"`
				Result   string `xml:"result"`
				Selector string `xml:"selector"`
			}
			SPF struct {
				Domain string `xml:"domain"`
				Result string `xml:"result"`
			} `xml:"spf"`
		} `xml:"auth_results"`
	} `xml:"record"`
}

func main() {
	byteValue, _ := ioutil.ReadAll(os.Stdin)
	var feedback Feedback
	xml.Unmarshal(byteValue, &feedback)
	for _, rec := range feedback.Record {
		/*
			ip := net.ParseIP(rec.Row.SourceIP)
			r := spf.CheckHost(ip, rec.AuthResults.SPF.Domain, "mrobinson@storj.io", "")
			fmt.Printf("%24s %3d %8s %s\n",
				rec.Row.SourceIP,
				rec.Row.Count,
				r,
				rec.AuthResults.SPF.Domain,
			)
		*/
		fmt.Printf("%24s %3d %4s %4s\n",
			rec.Row.SourceIP,
			rec.Row.Count,
			rec.Row.PolicyEvaluated.DKIM,
			rec.Row.PolicyEvaluated.SPF,
		)
	}
}
