/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:31:33
 * @Last Modified: U2, 2018-07-14 16:31:33
 */

package data

import (
	"encoding/json"
	"errors"
	"time"

	"janusec/models"
	"janusec/utils"
)

var (
	Settings                             = []*models.Setting{}
	Backend_Last_Modified  int64         = 0 // seconds since 1970.01.01
	Firewall_Last_Modified int64         = 0
	Sync_Seconds           time.Duration = (120 * time.Second)

	globalSettings *models.GlobalSettings
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

func InitDefaultSettings() {
	DAL.LoadInstanceKey()
	DAL.LoadNodesKey()
	var err error
	if DAL.ExistsSetting("Backend_Last_Modified") == false {
		err = DAL.SaveIntSetting("Backend_Last_Modified", 0)
	}
	if DAL.ExistsSetting("Firewall_Last_Modified") == false {
		err = DAL.SaveIntSetting("Firewall_Last_Modified", 0)
	}
	if DAL.ExistsSetting("Sync_Seconds") == false {
		err = DAL.SaveIntSetting("Sync_Seconds", 600)
	}
	if DAL.ExistsSetting("waf_log_days") == false {
		err = DAL.SaveIntSetting("waf_log_days", 7)
	}
	if DAL.ExistsSetting("cc_log_days") == false {
		err = DAL.SaveIntSetting("cc_log_days", 7)
	}
	if DAL.ExistsSetting("access_log_days") == false {
		err = DAL.SaveIntSetting("access_log_days", 180)
	}
	if DAL.ExistsSetting("init_time") == false {
		// 0.9.13 +
		err = DAL.SaveIntSetting("init_time", time.Now().Unix())
	}
	if err != nil {
		utils.DebugPrintln("InitDefaultSettings error", err)
	}
}

func LoadSettings() {
	if IsPrimary {
		Backend_Last_Modified, _ = DAL.SelectIntSetting("Backend_Last_Modified")
		Firewall_Last_Modified, _ = DAL.SelectIntSetting("Firewall_Last_Modified")
		SyncSecondsInt64, _ := DAL.SelectIntSetting("Sync_Seconds")
		Sync_Seconds = time.Duration(SyncSecondsInt64)
		Settings = append(Settings, &models.Setting{Name: "Backend_Last_Modified", Value: Backend_Last_Modified})
		Settings = append(Settings, &models.Setting{Name: "Firewall_Last_Modified", Value: Firewall_Last_Modified})
		Settings = append(Settings, &models.Setting{Name: "Sync_Seconds", Value: Sync_Seconds})

		// 0.9.15 add
		wafLogDays, _ := DAL.SelectIntSetting("waf_log_days")
		ccLogDays, _ := DAL.SelectIntSetting("cc_log_days")
		accessLogDays, _ := DAL.SelectIntSetting("access_log_days")
		globalSettings = &models.GlobalSettings{
			WAFLogDays:    wafLogDays,
			CCLogDays:     ccLogDays,
			AccessLogDays: accessLogDays,
		}
	} else {
		// Load OAuth Config
		CFG.PrimaryNode.OAuth = *(RPCGetOAuthConfig())
		// Load Memory Settings
		settingItems := RPCGetSettings()
		for _, settingItem := range settingItems {
			switch settingItem.Name {
			case "Backend_Last_Modified":
				Backend_Last_Modified = int64(settingItem.Value.(float64))
			case "Firewall_Last_Modified":
				Firewall_Last_Modified = int64(settingItem.Value.(float64))
			case "Sync_Seconds":
				Sync_Seconds = time.Duration(settingItem.Value.(float64))
			}
		}
		//go UpdateTimeTick()
	}
}

// GetSettings for replica nodes
func GetSettings() ([]*models.Setting, error) {
	return Settings, nil
}

// GetGlobalSettings for admin configuration
func GetGlobalSettings(authUser *models.AuthUser) (*models.GlobalSettings, error) {
	if authUser.IsSuperAdmin == false {
		return nil, errors.New("Only super administrators can perform this operation")
	}
	return globalSettings, nil
}

// GetGlobalSettings2 for admin configuration
func GetGlobalSettings2() *models.GlobalSettings {
	return globalSettings
}

// UpdateGlobalSettings ...
func UpdateGlobalSettings(param map[string]interface{}, authUser *models.AuthUser) (*models.GlobalSettings, error) {
	if authUser.IsSuperAdmin == false {
		return nil, errors.New("Only super administrators can perform this operation")
	}
	settings := param["object"].(map[string]interface{})
	wafLogDays := int64(settings["waf_log_days"].(float64))
	ccLogDays := int64(settings["cc_log_days"].(float64))
	accessLogDays := int64(settings["access_log_days"].(float64))
	globalSettings.WAFLogDays = wafLogDays
	globalSettings.CCLogDays = ccLogDays
	globalSettings.AccessLogDays = accessLogDays
	DAL.SaveIntSetting("waf_log_days", wafLogDays)
	DAL.SaveIntSetting("cc_log_days", ccLogDays)
	DAL.SaveIntSetting("access_log_days", accessLogDays)
	return globalSettings, nil
}

func RPCGetSettings() []*models.Setting {
	rpcRequest := &models.RPCRequest{
		Action: "get_settings", Object: nil}
	resp, err := GetRPCResponse(rpcRequest)
	utils.CheckError("RPCGetSettings", err)
	rpcSettings := &models.RPCSettings{}
	if err = json.Unmarshal(resp, rpcSettings); err != nil {
		utils.CheckError("RPCGetSettings Unmarshal", err)
	}
	return rpcSettings.Object
}

func RPCGetOAuthConfig() *models.OAuthConfig {
	rpcRequest := &models.RPCRequest{
		Action: "get_oauth_conf", Object: nil}
	resp, err := GetRPCResponse(rpcRequest)
	utils.CheckError("RPCGetOAuthConfig", err)
	rpcOAuthConf := &models.RPCOAuthConfig{}
	if err = json.Unmarshal(resp, rpcOAuthConf); err != nil {
		utils.CheckError("RPCGetOAuthConfig Unmarshal", err)
	}
	//fmt.Println("RPCGetOAuthConfig", rpcOAuthConf.Object)
	return rpcOAuthConf.Object
}
