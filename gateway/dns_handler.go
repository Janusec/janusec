/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2023-06-04 14:05
 */

package gateway

import (
	"janusec/backend"
	"janusec/models"
	"janusec/utils"
	"net"
	"strings"

	"github.com/miekg/dns"
)

func DNSHandler(writer dns.ResponseWriter, reqMsg *dns.Msg) {
	clientIP := removeAddrPort(writer.RemoteAddr().String())
	var respMsg dns.Msg
	respMsg.SetReply(reqMsg)
	for i := 0; i < len(reqMsg.Question); i++ {
		question := reqMsg.Question[i]
		//fmt.Println("question:", question.Name, question.Qtype)
		rrName, dnsDomainName := GetRNameDomainNameByQuestionName(question.Name)
		dnsDomain, err := backend.GetDNSDomainByName(dnsDomainName)
		if err != nil {
			utils.DebugPrintln("DNSHandler GetDNSDomainByName", err)
		}
		if dnsDomain == nil {
			continue
		}
		dnsRecords := GetDNSRecords(dnsDomain, dns.Type(question.Qtype), rrName)
		switch question.Qtype {
		case dns.TypeA:
			if len(dnsRecords) == 0 {
				// forward to cname if no TypeA record
				newQuestion := dns.Question{
					Name:   question.Name,
					Qtype:  dns.TypeCNAME,
					Qclass: dns.ClassINET,
				}
				reqMsg.Question = append(reqMsg.Question, newQuestion)
				continue
			}
			for _, dnsRecord := range dnsRecords {
				var ip string
				if dnsRecord.Auto {
					ip = backend.GetAvailableNodeIP(clientIP, dnsRecord.Internal)
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
				respMsg.Answer = append(respMsg.Answer, &recordA)
			}

		case dns.TypeAAAA:
			for _, dnsRecord := range dnsRecords {
				var ip string
				if dnsRecord.Auto {
					ip = backend.GetAvailableNodeIP(clientIP, dnsRecord.Internal)
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
				respMsg.Answer = append(respMsg.Answer, &recordAAAA)
			}
		case dns.TypeCNAME:
			for _, dnsRecord := range dnsRecords {
				recordCName := dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   question.Name,
						Rrtype: question.Qtype,
						Class:  dns.ClassINET,
						Ttl:    dnsRecord.TTL,
					},
					Target: strings.TrimSuffix(dnsRecord.Value, ".") + ".",
				}
				respMsg.Answer = append(respMsg.Answer, &recordCName)
				// forward to TypeA
				newQuestion := dns.Question{
					Name:   recordCName.Target + dnsDomainName + ".",
					Qtype:  dns.TypeA,
					Qclass: dns.ClassINET,
				}
				reqMsg.Question = append(reqMsg.Question, newQuestion)
			}
		case dns.TypeTXT:
			for _, dnsRecord := range dnsRecords {
				recordTxt := dns.TXT{
					Hdr: dns.RR_Header{
						Name:   question.Name,
						Rrtype: question.Qtype,
						Class:  dns.ClassNONE,
						Ttl:    dnsRecord.TTL,
					},
					Txt: []string{dnsRecord.Value},
				}
				respMsg.Answer = append(respMsg.Answer, &recordTxt)
			}
		case dns.TypeNS:
			for _, dnsRecord := range dnsRecords {
				recordNS := dns.NS{
					Hdr: dns.RR_Header{
						Name:   question.Name,
						Rrtype: question.Qtype,
						Class:  dns.ClassINET,
						Ttl:    dnsRecord.TTL,
					},
					Ns: strings.TrimSuffix(dnsRecord.Value, ".") + ".",
				}
				respMsg.Answer = append(respMsg.Answer, &recordNS)
			}
		case dns.TypeMX:
			for _, dnsRecord := range dnsRecords {
				recordMX := dns.MX{
					Hdr: dns.RR_Header{
						Name:   question.Name,
						Rrtype: question.Qtype,
						Class:  dns.ClassINET,
						Ttl:    dnsRecord.TTL,
					},
					Preference: 0,
					Mx:         strings.TrimSuffix(dnsRecord.Value, ".") + ".",
				}
				respMsg.Answer = append(respMsg.Answer, &recordMX)
			}
		}
	}
	//fmt.Println("resp.Answer:", respMsg.Answer)
	respMsg.Authoritative = true
	respMsg.RecursionAvailable = true
	err := writer.WriteMsg(&respMsg)
	if err != nil {
		utils.DebugPrintln("DNSHandler WriteMsg", err)
		return
	}
}

// GetRNameDomainNameByQuestionName convert a.example.com. to example.com
func GetRNameDomainNameByQuestionName(qName string) (string, string) {
	// first trim ending dot, a.b.example.com. to a.b.example.com
	// then split to [a, b, example, com]
	domainFields := strings.Split(strings.TrimSuffix(qName, "."), ".")
	lenDomainFields := len(domainFields)
	dnsDomain := domainFields[lenDomainFields-2] + "." + domainFields[lenDomainFields-1]
	rName := strings.TrimSuffix(qName, "."+dnsDomain+".")
	return rName, dnsDomain
}

func GetDNSRecords(dnsDomain *models.DNSDomain, qtype dns.Type, rrName string) []*models.DNSRecord {
	dnsRecords := []*models.DNSRecord{}
	if dnsDomain != nil {
		for _, dnsRecord := range dnsDomain.DNSRecords {
			if (dnsRecord.Rrtype == qtype) && (dnsRecord.Name == rrName) {
				dnsRecords = append(dnsRecords, dnsRecord)
			}
		}
	}
	return dnsRecords
}

func removeAddrPort(addr string) string {
	index := strings.IndexByte(addr, ':')
	if index > 0 {
		return addr[0:index]
	}
	return addr
}
