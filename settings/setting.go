/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:21:26
 * @Last Modified: U2, 2018-07-14 16:21:26
 */

package settings

import (
	"time"

	"../data"
	"../models"
)

func InitDefaultSettings() {
	data.DAL.LoadInstanceKey()
	if data.DAL.ExistsSetting("Backend_Last_Modified") == false {
		data.DAL.SaveIntSetting("Backend_Last_Modified", 0)
	}
	if data.DAL.ExistsSetting("Firewall_Last_Modified") == false {
		data.DAL.SaveIntSetting("Firewall_Last_Modified", 0)
	}
	if data.DAL.ExistsSetting("Sync_Seconds") == false {
		data.DAL.SaveIntSetting("Sync_Seconds", 600)
	}
	if data.DAL.ExistsSetting("Log_Expire_Seconds") == false {
		data.DAL.SaveIntSetting("Log_Expire_Seconds", 7*86400)
	}
}

func LoadSettings() {
	if data.IsMaster {
		data.Backend_Last_Modified, _ = data.DAL.SelectIntSetting("Backend_Last_Modified")
		data.Firewall_Last_Modified, _ = data.DAL.SelectIntSetting("Firewall_Last_Modified")
		Sync_Seconds_int64, _ := data.DAL.SelectIntSetting("Sync_Seconds")
		data.Sync_Seconds = time.Duration(Sync_Seconds_int64)
		data.Settings = append(data.Settings, &models.Setting{Name: "Backend_Last_Modified", Value: data.Backend_Last_Modified})
		data.Settings = append(data.Settings, &models.Setting{Name: "Firewall_Last_Modified", Value: data.Firewall_Last_Modified})
		data.Settings = append(data.Settings, &models.Setting{Name: "Sync_Seconds", Value: data.Sync_Seconds})
	} else {
		setting_items := data.RPCGetSettings()
		for _, setting_item := range setting_items {
			switch setting_item.Name {
			case "Backend_Last_Modified":
				data.Backend_Last_Modified = int64(setting_item.Value.(float64))
			case "Firewall_Last_Modified":
				data.Firewall_Last_Modified = int64(setting_item.Value.(float64))
			case "Sync_Seconds":
				data.Sync_Seconds = time.Duration(setting_item.Value.(float64))
			}
		}
		go UpdateTimeTick()
	}
}

func GetSettings() ([]*models.Setting, error) {
	return data.Settings, nil
}
