/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2023-06-04 14:05
 */

package backend

import (
	"encoding/json"
	"errors"
	"fmt"
	"janusec/data"
	"janusec/models"
	"janusec/utils"
	"net"

	"github.com/miekg/dns"
)

func DNSHandler(writer dns.ResponseWriter, req *dns.Msg) {
	var resp dns.Msg
	resp.SetReply(req)
	for _, question := range req.Question {
		fmt.Println("question:", question, question.Qtype)
		switch question.Qtype {
		case dns.TypeA:
			recordA := dns.A{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    30,
				},
				A: net.ParseIP("127.0.0.1").To4(),
			}
			resp.Answer = append(resp.Answer, &recordA)
		case dns.TypeAAAA:
			recordAAAA := dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    30,
				},
				AAAA: net.ParseIP("::1").To16(),
			}
			resp.Answer = append(resp.Answer, &recordAAAA)
		}
	}
	fmt.Println("resp.Answer:", resp.Answer)
	err := writer.WriteMsg(&resp)
	if err != nil {
		return
	}
}

func GetDNSRecordsByDomainID(authUser *models.AuthUser, dnsDomainID int64) ([]*models.DNSRecord, error) {
	if authUser.IsSuperAdmin {
		dnsDomain, err := GetDNSDomainByID(dnsDomainID)
		if err == nil {
			return dnsDomain.DNSRecords, nil
		}
	}
	return []*models.DNSRecord{}, errors.New("not found or no privileges")
}

func UpdateDNSRecord(body []byte, clientIP string, authUser *models.AuthUser) (*models.DNSRecord, error) {
	var rpcDNSRecordRequest models.APIDNSRecordRequest
	if err := json.Unmarshal(body, &rpcDNSRecordRequest); err != nil {
		utils.DebugPrintln("UpdateDNSRecord", err)
		return nil, err
	}
	dnsRecord := rpcDNSRecordRequest.Object
	dnsDomain, err := GetDNSDomainByID(dnsRecord.DNSDomainID)
	if err != nil {
		return nil, err
	}
	if dnsRecord.ID == 0 {
		// new dnsRecord
		dnsRecord.ID = utils.GenSnowflakeID()
		data.DAL.InsertDNSRecord(dnsRecord)
		dnsDomain.DNSRecords = append(dnsDomain.DNSRecords, dnsRecord)
		go utils.OperationLog(clientIP, authUser.Username, "Add DNSRecord", dnsRecord.Name)
	} else {
		// update
		err := data.DAL.UpdateDNSRecord(dnsRecord)
		if err != nil {
			utils.DebugPrintln("UpdateDNSRecord", err)
		}
		// update dnsRecord pointer dnsRecords
		UpdateDNSRecords(dnsDomain, dnsRecord)
		go utils.OperationLog(clientIP, authUser.Username, "Update DNSRecord", dnsRecord.Name)
	}
	return dnsRecord, nil
}

func UpdateDNSRecords(dnsDomain *models.DNSDomain, dnsRecord *models.DNSRecord) {
	for i, obj := range dnsDomain.DNSRecords {
		if obj.ID == dnsRecord.ID {
			dnsDomain.DNSRecords[i] = dnsRecord
		}
	}
}

func DeleteDNSRecord(dnsRecordID int64, clientIP string, authUser *models.AuthUser) error {
	dnsRecord, err := data.DAL.SelectDNSRecordByID(dnsRecordID)
	if err != nil {
		return err
	}
	err = data.DAL.DeleteDNSRecordByID(dnsRecord.ID)
	if err != nil {
		utils.DebugPrintln("DeleteDNSRecord ", err)
		return err
	}
	dnsDomain, err := GetDNSDomainByID(dnsRecord.DNSDomainID)
	if err != nil {
		return err
	}
	err = DeleteDNSRecordFromDNSDomain(dnsDomain, dnsRecord)
	if err != nil {
		utils.DebugPrintln("DeleteDNSRecordFromDNSRecords", err)
	}
	go utils.OperationLog(clientIP, authUser.Username, "Delete DNSRecord", dnsRecord.Name)
	return nil
}

func DeleteDNSRecordFromDNSDomain(dnsDomain *models.DNSDomain, dnsRecordA *models.DNSRecord) error {
	for i, dnsRecord := range dnsDomain.DNSRecords {
		if dnsRecord.ID == dnsRecordA.ID {
			dnsDomain.DNSRecords = append(dnsDomain.DNSRecords[:i], dnsDomain.DNSRecords[i+1:]...)
			return nil
		}
	}
	return errors.New("dnsRecord not found")
}
