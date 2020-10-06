/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:31:33
 * @Last Modified: U2, 2018-07-14 16:31:33
 */

package data

import (
	"time"

	"janusec/models"
	"janusec/utils"
)

var (
	Settings               []*models.Setting
	Backend_Last_Modified  int64         = 0 // seconds since 1970.01.01
	Firewall_Last_Modified int64         = 0
	Sync_Seconds           time.Duration = (120 * time.Second)
)

func UpdateBackendLastModified() {
	Backend_Last_Modified = time.Now().Unix()
	err := DAL.SaveIntSetting("Backend_Last_Modified", Backend_Last_Modified)
	if err != nil {
		utils.DebugPrintln("UpdateBackendLastModified SaveIntSetting", err)
	}
	setting := GetSettingByName("Backend_Last_Modified")
	setting.Value = Backend_Last_Modified
}

func UpdateFirewallLastModified() {
	Firewall_Last_Modified = time.Now().Unix()
	err := DAL.SaveIntSetting("Firewall_Last_Modified", Firewall_Last_Modified)
	if err != nil {
		utils.DebugPrintln("UpdateFirewallLastModified SaveIntSetting", err)
	}
	setting := GetSettingByName("Firewall_Last_Modified")
	setting.Value = Backend_Last_Modified
}

func GetSettingByName(name string) *models.Setting {
	for _, setting := range Settings {
		if setting.Name == name {
			return setting
		}
	}
	return nil
}
