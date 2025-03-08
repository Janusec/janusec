/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2023-06-04 14:05
 */

package backend

import (
	"encoding/json"
	"errors"
	"janusec/data"
	"janusec/models"
	"janusec/utils"

	"github.com/miekg/dns"
)

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
		utils.DebugPrintln("UpdateDNSRecord Unmarshal", err)
		return nil, err
	}
	dnsRecord := rpcDNSRecordRequest.Object
	dnsDomain, err := GetDNSDomainByID(dnsRecord.DNSDomainID)
	if err != nil {
		return nil, err
	}
	if uint16(dnsRecord.Rrtype) == dns.TypeMX {
		// Modify Name for MX
		dnsRecord.Name = dnsDomain.Name + "."
	}
	if dnsRecord.ID == 0 {
		// new dnsRecord
		dnsRecord.ID = utils.GenSnowflakeID()
		err = data.DAL.InsertDNSRecord(dnsRecord)
		if err != nil {
			utils.DebugPrintln("InsertDNSRecord", err)
		}
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
