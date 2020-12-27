/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:21:26
 * @Last Modified: U2, 2018-07-14 16:21:26
 */

package settings

import (
	"time"

	"janusec/data"
	"janusec/models"
	"janusec/utils"
)

var (
	globalSettings *models.GlobalSettings
)

func InitDefaultSettings() {
	data.DAL.LoadInstanceKey()
	data.DAL.LoadNodesKey()
	var err error
	if data.DAL.ExistsSetting("Backend_Last_Modified") == false {
		err = data.DAL.SaveIntSetting("Backend_Last_Modified", 0)
	}
	if data.DAL.ExistsSetting("Firewall_Last_Modified") == false {
		err = data.DAL.SaveIntSetting("Firewall_Last_Modified", 0)
	}
	if data.DAL.ExistsSetting("Sync_Seconds") == false {
		err = data.DAL.SaveIntSetting("Sync_Seconds", 600)
	}
	if data.DAL.ExistsSetting("waf_log_days") == false {
		err = data.DAL.SaveIntSetting("waf_log_days", 7)
	}
	if data.DAL.ExistsSetting("cc_log_days") == false {
		err = data.DAL.SaveIntSetting("cc_log_days", 7)
	}
	if data.DAL.ExistsSetting("access_log_days") == false {
		err = data.DAL.SaveIntSetting("access_log_days", 180)
	}
	if data.DAL.ExistsSetting("init_time") == false {
		// 0.9.13 +
		err = data.DAL.SaveIntSetting("init_time", time.Now().Unix())
	}
	if err != nil {
		utils.DebugPrintln("InitDefaultSettings error", err)
	}
}

func LoadSettings() {
	if data.IsPrimary {
		data.Backend_Last_Modified, _ = data.DAL.SelectIntSetting("Backend_Last_Modified")
		data.Firewall_Last_Modified, _ = data.DAL.SelectIntSetting("Firewall_Last_Modified")
		SyncSecondsInt64, _ := data.DAL.SelectIntSetting("Sync_Seconds")
		data.Sync_Seconds = time.Duration(SyncSecondsInt64)
		data.Settings = append(data.Settings, &models.Setting{Name: "Backend_Last_Modified", Value: data.Backend_Last_Modified})
		data.Settings = append(data.Settings, &models.Setting{Name: "Firewall_Last_Modified", Value: data.Firewall_Last_Modified})
		data.Settings = append(data.Settings, &models.Setting{Name: "Sync_Seconds", Value: data.Sync_Seconds})

		// 0.9.15 add
		wafLogDays, _ := data.DAL.SelectIntSetting("waf_log_days")
		ccLogDays, _ := data.DAL.SelectIntSetting("cc_log_days")
		accessLogDays, _ := data.DAL.SelectIntSetting("access_log_days")
		globalSettings = &models.GlobalSettings{
			WAFLogDays:    wafLogDays,
			CCLogDays:     ccLogDays,
			AccessLogDays: accessLogDays,
		}
	} else {
		// Load OAuth Config
		data.CFG.PrimaryNode.OAuth = *(data.RPCGetOAuthConfig())
		// Load Memory Settings
		settingItems := data.RPCGetSettings()
		for _, settingItem := range settingItems {
			switch settingItem.Name {
			case "Backend_Last_Modified":
				data.Backend_Last_Modified = int64(settingItem.Value.(float64))
			case "Firewall_Last_Modified":
				data.Firewall_Last_Modified = int64(settingItem.Value.(float64))
			case "Sync_Seconds":
				data.Sync_Seconds = time.Duration(settingItem.Value.(float64))
			}
		}
		go UpdateTimeTick()
	}
}

// GetSettings for replica nodes
func GetSettings() ([]*models.Setting, error) {
	return data.Settings, nil
}

// GetGlobalSettings for admin configuration
func GetGlobalSettings() (*models.GlobalSettings, error) {
	return globalSettings, nil
}

// UpdateGlobalSettings ...
func UpdateGlobalSettings(param map[string]interface{}) (*models.GlobalSettings, error) {
	settings := param["object"].(map[string]interface{})
	wafLogDays := int64(settings["waf_log_days"].(float64))
	ccLogDays := int64(settings["cc_log_days"].(float64))
	accessLogDays := int64(settings["access_log_days"].(float64))
	globalSettings.WAFLogDays = wafLogDays
	globalSettings.CCLogDays = ccLogDays
	globalSettings.AccessLogDays = accessLogDays
	data.DAL.SaveIntSetting("waf_log_days", wafLogDays)
	data.DAL.SaveIntSetting("cc_log_days", ccLogDays)
	data.DAL.SaveIntSetting("access_log_days", accessLogDays)
	return globalSettings, nil
}
