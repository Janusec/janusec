/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:36:02
 * @Last Modified: U2, 2018-07-14 16:36:02
 */

package firewall

import (
	"os"
	"sync"

	"janusec/data"
	"janusec/models"
	"janusec/utils"
)

var (
	vulnTypes []*models.VulnType

	// VulnMap map[int64]string
	VulnMap sync.Map
)

// InitVulnType ...
func InitVulnType() {
	if data.IsPrimary {
		err := data.DAL.CreateTableIfNotExistsVulnType()
		if err != nil {
			utils.DebugPrintln("InitVulnType CreateTableIfNotExistsVulnType error", err)
			os.Exit(1)
		}
		existVuln := data.DAL.ExistsVulnType()
		if existVuln == false {
			err := data.DAL.InsertVulnType(001, "None")
			if err != nil {
				utils.DebugPrintln("InsertVulnType error", err)
			} else {
				_ = data.DAL.InsertVulnType(100, "Sensitive Data Leakage")
				_ = data.DAL.InsertVulnType(200, "SQL Injection")
				_ = data.DAL.InsertVulnType(210, "Command Injection")
				_ = data.DAL.InsertVulnType(220, "Code Injection")
				_ = data.DAL.InsertVulnType(230, "LDAP Injection")
				_ = data.DAL.InsertVulnType(240, "XPATH Injection")
				_ = data.DAL.InsertVulnType(300, "Cross-site Scripting(XSS)")
				_ = data.DAL.InsertVulnType(400, "Path Traversal")
				_ = data.DAL.InsertVulnType(410, "Remote File Inclusion(RFI)")
				_ = data.DAL.InsertVulnType(420, "Local File Inclusion(LFI)")
				_ = data.DAL.InsertVulnType(500, "Web Shell")
				_ = data.DAL.InsertVulnType(510, "Upload")
				_ = data.DAL.InsertVulnType(600, "Crawler/Scanner")
				_ = data.DAL.InsertVulnType(700, "Server-Side Request Forgery(SSRF)")
				_ = data.DAL.InsertVulnType(710, "Client-Side Request Forgery(CSRF)")
				_ = data.DAL.InsertVulnType(800, "Logic Vulnerability")
				_ = data.DAL.InsertVulnType(900, "Open Source Vulnerability")
				_ = data.DAL.InsertVulnType(920, "Broken Authentication")
				_ = data.DAL.InsertVulnType(930, "Broken Access Control")
				_ = data.DAL.InsertVulnType(940, "Misconfiguration")
				_ = data.DAL.InsertVulnType(950, "Insecure Deserialization")
				_ = data.DAL.InsertVulnType(960, "XML External Entity(XXE)")
				_ = data.DAL.InsertVulnType(999, "Other")
			}
		}
		vulnTypes, _ = data.DAL.SelectVulnTypes()
	} else {
		vulnTypes = RPCSelectVulntypes()
	}
	for _, vulnType := range vulnTypes {
		VulnMap.Store(vulnType.ID, vulnType.Name)
	}
}

// GetVulnTypes ...
func GetVulnTypes() ([]*models.VulnType, error) {
	return vulnTypes, nil
}
