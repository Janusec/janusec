/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2023-06-04 18:52
 */

package backend

import (
	"encoding/json"
	"errors"
	"janusec/data"
	"janusec/models"
	"janusec/utils"
)

var (
	dnsDomains = []*models.DNSDomain{}
)

func LoadDNSDomains() {
	dnsDomains = dnsDomains[0:0]
	dnsDomains = data.DAL.SelectDNSDomains()
	for _, dnsDomain := range dnsDomains {
		dnsDomain.DNSRecords = data.DAL.SelectDNSRecordsByDomainID(dnsDomain.ID)
	}
}

func GetDNSDomains(authUser *models.AuthUser) ([]*models.DNSDomain, error) {
	if authUser.IsSuperAdmin {
		return dnsDomains, nil
	}
	return nil, errors.New("no privileges")
}

func GetDNSDomainByID(dnsDomainID int64) (*models.DNSDomain, error) {
	for _, dnsDomain := range dnsDomains {
		if dnsDomain.ID == dnsDomainID {
			return dnsDomain, nil
		}
	}
	return nil, errors.New("not found")
}

func GetDNSDomainByName(domainName string) (*models.DNSDomain, error) {
	for _, dnsDomain := range dnsDomains {
		if dnsDomain.Name == domainName {
			return dnsDomain, nil
		}
	}
	return nil, errors.New("not found")
}

func UpdateDNSDomain(body []byte, clientIP string, authUser *models.AuthUser) (*models.DNSDomain, error) {
	var rpcDNSDomainRequest models.APIDNSDomainRequest
	if err := json.Unmarshal(body, &rpcDNSDomainRequest); err != nil {
		utils.DebugPrintln("UpdateDNSDomain", err)
		return nil, err
	}
	dnsDomain := rpcDNSDomainRequest.Object
	if dnsDomain.ID == 0 {
		// new dnsDomain
		dnsDomain.ID = utils.GenSnowflakeID()
		err := data.DAL.InsertDNSDomain(dnsDomain)
		if err != nil {
			utils.DebugPrintln("InsertDNSDomain", err)
			return nil, err
		}
		dnsDomains = append(dnsDomains, dnsDomain)
		go utils.OperationLog(clientIP, authUser.Username, "Add DNSDomain", dnsDomain.Name)
	} else {
		// update
		err := data.DAL.UpdateDNSDomain(dnsDomain)
		if err != nil {
			utils.DebugPrintln("UpdateDNSDomain", err)
		}
		UpdateDNSDomains(dnsDomain)
		go utils.OperationLog(clientIP, authUser.Username, "Update DNSDomain", dnsDomain.Name)
	}
	return dnsDomain, nil
}

func UpdateDNSDomains(dnsDomain *models.DNSDomain) {
	for i, obj := range dnsDomains {
		if obj.ID == dnsDomain.ID {
			dnsDomains[i] = dnsDomain
		}
	}
}

func DeleteDNSDomain(dnsDomainID int64, clientIP string, authUser *models.AuthUser) error {
	if !authUser.IsSuperAdmin {
		return errors.New("no privileges")
	}
	dnsDomain, err := GetDNSDomainByID(dnsDomainID)
	if err != nil {
		return err
	}
	if len(dnsDomain.DNSRecords) > 0 {
		return errors.New("there exists resource records for this domain name, can not be deleted")
	}
	err = data.DAL.DeleteDNSDomainByID(dnsDomain.ID)
	if err != nil {
		utils.DebugPrintln("DeleteDNSDomain ", err)
		return err
	}
	err = DeleteFromDNSDomains(dnsDomain)
	if err != nil {
		utils.DebugPrintln("DeleteDNSRecordFromDNSRecords", err)
	}
	go utils.OperationLog(clientIP, authUser.Username, "Delete DNSDomain", dnsDomain.Name)
	return nil
}

func DeleteFromDNSDomains(dnsDomain *models.DNSDomain) error {
	for i, obj := range dnsDomains {
		if obj.ID == dnsDomain.ID {
			dnsDomains = append(dnsDomains[:i], dnsDomains[i+1:]...)
			return nil
		}
	}
	return errors.New("dnsRecord not found")
}
