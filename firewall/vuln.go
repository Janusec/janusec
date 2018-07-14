/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:36:02
 * @Last Modified: U2, 2018-07-14 16:36:02
 */

package firewall

import (
	"sync"

	"../data"
	"../models"
)

var (
	vuln_types []*models.VulnType
	//VulnMap map[int64]string
	VulnMap sync.Map
)

func InitVulnType() {
	if data.IsMaster {
		data.DAL.CreateTableIfNotExistsVulnType()
		exist_vuln := data.DAL.ExistsVulnType()
		if exist_vuln == false {
			data.DAL.InsertVulnType(001, "None")
			data.DAL.InsertVulnType(100, "Sensitive Data Leakage")
			data.DAL.InsertVulnType(200, "SQL Injection")
			data.DAL.InsertVulnType(210, "Command Injection")
			data.DAL.InsertVulnType(220, "Code Injection")
			data.DAL.InsertVulnType(230, "LDAP Injection")
			data.DAL.InsertVulnType(240, "XPATH Injection")
			data.DAL.InsertVulnType(300, "Cross-site Scripting(XSS)")
			data.DAL.InsertVulnType(400, "Path Traversal")
			data.DAL.InsertVulnType(410, "Remote File Inclusion(RFI)")
			data.DAL.InsertVulnType(420, "Local File Inclusion(LFI)")
			data.DAL.InsertVulnType(500, "Web Shell")
			data.DAL.InsertVulnType(510, "Upload")
			data.DAL.InsertVulnType(600, "Crawler/Scanner")
			data.DAL.InsertVulnType(700, "Server-Side Request Forgery(SSRF)")
			data.DAL.InsertVulnType(710, "Client-Side Request Forgery(CSRF)")
			data.DAL.InsertVulnType(800, "Logic Vulnerability")
			data.DAL.InsertVulnType(900, "Open Source Vulnerability")
			data.DAL.InsertVulnType(920, "Broken Authentication")
			data.DAL.InsertVulnType(930, "Broken Access Control")
			data.DAL.InsertVulnType(940, "Misconfiguration")
			data.DAL.InsertVulnType(950, "Insecure Deserialization")
			data.DAL.InsertVulnType(960, "XML External Entity(XXE)")
			data.DAL.InsertVulnType(999, "Other")
		}
		vuln_types, _ = data.DAL.SelectVulnTypes()
	} else {
		vuln_types = RPCSelectVulntypes()
	}
	for _, vuln_type := range vuln_types {
		//VulnMap[vuln_type.ID] = vuln_type.Name
		VulnMap.Store(vuln_type.ID, vuln_type.Name)
	}
}

func GetVulnTypes() ([]*models.VulnType, error) {
	return vuln_types, nil
}
