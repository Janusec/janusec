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
		if dnsDomain == nil {
			continue
		}
		dnsRecords := GetDNSRecords(dnsDomain, dns.Type(question.Qtype))

		switch question.Qtype {
		case dns.TypeA:
			for _, dnsRecord := range dnsRecords {
				var ip string
				if dnsRecord.Auto {
					ip = GetAvailableNodesIP()
				} else {
					ip = dnsRecord.Value
				}
				recordA := dns.A{
					Hdr: dns.RR_Header{
						Name:   question.Name,
						Rrtype: question.Qtype,
						Class:  dns.ClassINET,
						Ttl:    dnsRecord.TTL,
					},
					A: net.ParseIP(ip).To4(),
				}
				resp.Answer = append(resp.Answer, &recordA)
			}

		case dns.TypeAAAA:
			for _, dnsRecord := range dnsRecords {
				var ip string
				if dnsRecord.Auto {
					ip = GetAvailableNodesIP()
				} else {
					ip = dnsRecord.Value
				}
				recordAAAA := dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   question.Name,
						Rrtype: question.Qtype,
						Class:  dns.ClassINET,
						Ttl:    dnsRecord.TTL,
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
	if dnsDomain != nil {
		for _, dnsRecord := range dnsDomain.DNSRecords {
			if dnsRecord.Rrtype == qtype {
				dnsRecords = append(dnsRecords, dnsRecord)
			}
		}
	}
	return dnsRecords
}

func GetAvailableNodesIP() string {
	fmt.Println("GetAvailableNodesIP To Do")
	return "127.0.0.1"
}

func GetPublicIP() string {
	conn, error := net.Dial("udp", "8.8.8.8:80")
	if error != nil {
		fmt.Println(error)
	}
	defer conn.Close()
	ipAddress := conn.LocalAddr().(*net.UDPAddr)
	fmt.Println(ipAddress, ipAddress.IP.String())
	return ipAddress.IP.String()
}
