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
	// Settings for replica nodes
	Settings = []*models.Setting{}

	// BackendLastModified seconds since 1970.01.01
	BackendLastModified int64

	// FirewallLastModified seconds since 1970.01.01
	FirewallLastModified int64

	// SyncSeconds for update
	SyncSeconds time.Duration = (120 * time.Second)

	// globalSettings include logs retention etc.
	globalSettings *models.GlobalSettings
)

// UpdateBackendLastModified ...
func UpdateBackendLastModified() {
	BackendLastModified = time.Now().Unix()
	err := DAL.SaveIntSetting("backend_last_modified", BackendLastModified)
	if err != nil {
		utils.DebugPrintln("UpdateBackendLastModified SaveIntSetting", err)
	}
	setting := GetSettingByName("backend_last_modified")
	setting.Value = BackendLastModified
}

// UpdateFirewallLastModified ...
func UpdateFirewallLastModified() {
	FirewallLastModified = time.Now().Unix()
	err := DAL.SaveIntSetting("firewall_last_modified", FirewallLastModified)
	if err != nil {
		utils.DebugPrintln("UpdateFirewallLastModified SaveIntSetting", err)
	}
	setting := GetSettingByName("firewall_last_modified")
	setting.Value = FirewallLastModified
}

// GetSettingByName ...
func GetSettingByName(name string) *models.Setting {
	for _, setting := range Settings {
		if setting.Name == name {
			return setting
		}
	}
	return nil
}

// InitDefaultSettings ...
func InitDefaultSettings() {
	DAL.LoadInstanceKey()
	DAL.LoadNodesKey()
	var err error
	if DAL.ExistsSetting("backend_last_modified") == false {
		err = DAL.SaveIntSetting("backend_last_modified", 0)
	}
	if DAL.ExistsSetting("firewall_last_modified") == false {
		err = DAL.SaveIntSetting("firewall_last_modified", 0)
	}
	if DAL.ExistsSetting("sync_seconds") == false {
		err = DAL.SaveIntSetting("sync_seconds", 600)
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

// LoadSettings ...
func LoadSettings() {
	if IsPrimary {
		BackendLastModified, _ = DAL.SelectIntSetting("backend_last_modified")
		FirewallLastModified, _ = DAL.SelectIntSetting("firewall_last_modified")
		SyncSecondsInt64, _ := DAL.SelectIntSetting("sync_seconds")
		SyncSeconds = time.Duration(SyncSecondsInt64)
		Settings = append(Settings, &models.Setting{Name: "backend_last_modified", Value: BackendLastModified})
		Settings = append(Settings, &models.Setting{Name: "firewall_last_modified", Value: FirewallLastModified})
		Settings = append(Settings, &models.Setting{Name: "sync_seconds", Value: SyncSeconds})

		// 1.0.0 add
		authEnabled, _ := DAL.SelectBoolSetting("auth_enabled")
		authProvider, _ := DAL.SelectStringSetting("auth_provider")
		websshEnabled, _ := DAL.SelectBoolSetting("webssh_enabled")
		// 0.9.15 add
		wafLogDays, _ := DAL.SelectIntSetting("waf_log_days")
		ccLogDays, _ := DAL.SelectIntSetting("cc_log_days")
		accessLogDays, _ := DAL.SelectIntSetting("access_log_days")
		globalSettings = &models.GlobalSettings{
			AuthEnabled:   authEnabled,
			AuthProvider:  authProvider,
			WebSSHEnabled: websshEnabled,
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
			case "backend_last_modified":
				BackendLastModified = int64(settingItem.Value.(float64))
			case "firewall_last_modified":
				FirewallLastModified = int64(settingItem.Value.(float64))
			case "sync_seconds":
				SyncSeconds = time.Duration(settingItem.Value.(float64))
			}
		}
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

func GetWxworkConfig() (*models.WxworkConfig, error) {
	displayName, _ := DAL.SelectStringSetting("display_name")
	callback, _ := DAL.SelectStringSetting("callback")
	corpID, _ := DAL.SelectStringSetting("corpid")
	agentID, _ := DAL.SelectStringSetting("agentid")
	corpSecret, _ := DAL.SelectStringSetting("corpsecret")
	wxworkConfig := &models.WxworkConfig{
		DisplayName: displayName,
		Callback:    callback,
		CorpID:      corpID,
		AgentID:     agentID,
		CorpSecret:  corpSecret,
	}
	return wxworkConfig, nil
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

// RPCGetSettings ...
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

// RPCGetOAuthConfig ...
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
