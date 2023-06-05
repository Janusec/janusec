/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2023-06-04 14:05
 */

package gateway

import (
	"fmt"
	"janusec/backend"
	"janusec/models"
	"janusec/utils"
	"net"
	"strings"

	"github.com/miekg/dns"
)

func DNSHandler(writer dns.ResponseWriter, req *dns.Msg) {
	var resp dns.Msg
	resp.SetReply(req)
	for _, question := range req.Question {
		fmt.Println("question:", question.Name, question.Qtype)
		dnsDomainName := GetDNSDomainByQuestionName(question.Name)
		dnsDomain, err := backend.GetDNSDomainByName(dnsDomainName)
		if err != nil {
			utils.DebugPrintln("DNSHandler GetDNSDomainByName", err)
		}
		switch question.Qtype {
		case dns.TypeA:
			dnsRecordsA := GetDNSRecords(dnsDomain, dns.Type(dns.TypeA))
			for _, dnsRecordA := range dnsRecordsA {
				var ip string
				if dnsRecordA.Auto {
					ip = "127.0.0.1"
					fmt.Println("To Do")
				} else {
					ip = dnsRecordA.Value
				}
				recordA := dns.A{
					Hdr: dns.RR_Header{
						Name:   question.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    30,
					},
					A: net.ParseIP(ip).To4(),
				}
				resp.Answer = append(resp.Answer, &recordA)
			}

		case dns.TypeAAAA:
			dnsRecordsAAAA := GetDNSRecords(dnsDomain, dns.Type(dns.TypeAAAA))
			for _, dnsRecordAAAA := range dnsRecordsAAAA {
				var ip string
				if dnsRecordAAAA.Auto {
					ip = "127.0.0.1"
					fmt.Println("To Do")
				} else {
					ip = dnsRecordAAAA.Value
				}
				recordAAAA := dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   question.Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    30,
					},
					AAAA: net.ParseIP(ip).To16(),
				}
				resp.Answer = append(resp.Answer, &recordAAAA)
			}
		}
	}
	//fmt.Println("resp.Answer:", resp.Answer)
	err := writer.WriteMsg(&resp)
	if err != nil {
		return
	}
}

// GetDNSDomainByQuestionName convert a.example.com. to example.com
func GetDNSDomainByQuestionName(qName string) string {
	// first trim ending dot, a.example.com. to a.example.com
	domainFields := strings.Split(strings.TrimSuffix(qName, "."), ".")
	lenDomainFields := len(domainFields)
	dnsDomain := domainFields[lenDomainFields-2] + "." + domainFields[lenDomainFields-1]
	return dnsDomain
}

func GetDNSRecords(dnsDomain *models.DNSDomain, qtype dns.Type) []*models.DNSRecord {
	dnsRecords := []*models.DNSRecord{}
	for _, dnsRecord := range dnsDomain.DNSRecords {
		if dnsRecord.Rrtype == qtype {
			dnsRecords = append(dnsRecords, dnsRecord)
		}
	}
	return dnsRecords
}
