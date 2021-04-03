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

	// GlobalSettings include logs retention etc.
	GlobalSettings *models.GlobalSettings

	// added in v1.0.0
	AuthConfig *models.OAuthConfig
)

// LoadAuthConfig ...
func LoadAuthConfig() {
	if !GlobalSettings.AuthEnabled {
		AuthConfig = &models.OAuthConfig{
			Enabled:  GlobalSettings.AuthEnabled,
			Provider: "",
		}
		return
	}
	// Enabled
	AuthConfig = &models.OAuthConfig{
		Enabled:  GlobalSettings.AuthEnabled,
		Provider: GlobalSettings.AuthProvider,
		Wxwork:   GetWxworkConfig(),
		Dingtalk: GetDingtalkConfig(),
		Feishu:   GetFeishuConfig(),
		LDAP:     GetLDAPConfig(),
		CAS2:     GetCAS2Config(),
	}
}

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
		if len(authProvider) == 0 {
			authProvider = "wxwork"
		}
		websshEnabled, _ := DAL.SelectBoolSetting("webssh_enabled")

		// 0.9.15 add
		wafLogDays, _ := DAL.SelectIntSetting("waf_log_days")
		ccLogDays, _ := DAL.SelectIntSetting("cc_log_days")
		accessLogDays, _ := DAL.SelectIntSetting("access_log_days")
		GlobalSettings = &models.GlobalSettings{
			AuthEnabled:   authEnabled,
			AuthProvider:  authProvider,
			WebSSHEnabled: websshEnabled,
			WAFLogDays:    wafLogDays,
			CCLogDays:     ccLogDays,
			AccessLogDays: accessLogDays,
		}
		LoadAuthConfig()
	} else {
		// Load OAuth Config
		//CFG.PrimaryNode.OAuth = *(RPCGetOAuthConfig())
		AuthConfig = RPCGetOAuthConfig()
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
	return GlobalSettings, nil
}

// GetGlobalSettings2 for admin configuration
func GetGlobalSettings2() *models.GlobalSettings {
	return GlobalSettings
}

// GetWxworkConfig return Auth Wxwork config
func GetWxworkConfig() *models.WxworkConfig {
	displayName, _ := DAL.SelectStringSetting("wxwork_display_name")
	if len(displayName) == 0 {
		displayName = "Login with WeChat Work"
	}
	callback, _ := DAL.SelectStringSetting("wxwork_callback")
	if len(callback) == 0 {
		callback = "http://your_domain.com/oauth/wxwork"
	}
	corpID, _ := DAL.SelectStringSetting("wxwork_corpid")
	if len(corpID) == 0 {
		corpID = "wwd03be1f8"
	}
	agentID, _ := DAL.SelectStringSetting("wxwork_agentid")
	if len(agentID) == 0 {
		agentID = "1000002"
	}
	corpSecret, _ := DAL.SelectStringSetting("wxwork_corpsecret")
	if len(corpSecret) == 0 {
		corpSecret = "BgZtz_hssdZV5em-AyGhOgLlm18rU_NdZI"
	}
	wxworkConfig := &models.WxworkConfig{
		DisplayName: displayName,
		Callback:    callback,
		CorpID:      corpID,
		AgentID:     agentID,
		CorpSecret:  corpSecret,
	}
	return wxworkConfig
}

// UpdateWxworkConfig ...
func UpdateWxworkConfig(param map[string]interface{}, authUser *models.AuthUser) (*models.WxworkConfig, error) {
	if authUser.IsSuperAdmin == false {
		return nil, errors.New("Only super administrators can perform this operation")
	}
	wxworkConfig := param["object"].(map[string]interface{})
	displayName := wxworkConfig["display_name"].(string)
	callback := wxworkConfig["callback"].(string)
	corpid := wxworkConfig["corpid"].(string)
	agentid := wxworkConfig["agentid"].(string)
	corpsecret := wxworkConfig["corpsecret"].(string)
	DAL.SaveStringSetting("wxwork_display_name", displayName)
	DAL.SaveStringSetting("wxwork_callback", callback)
	DAL.SaveStringSetting("wxwork_corpid", corpid)
	DAL.SaveStringSetting("wxwork_agentid", agentid)
	DAL.SaveStringSetting("wxwork_corpsecret", corpsecret)
	newWxworkConfig := &models.WxworkConfig{
		DisplayName: displayName,
		Callback:    callback,
		CorpID:      corpid,
		AgentID:     agentid,
		CorpSecret:  corpsecret,
	}
	AuthConfig.Wxwork = newWxworkConfig
	return newWxworkConfig, nil
}

// GetDingtalkConfig return Auth Dingtalk config
func GetDingtalkConfig() *models.DingtalkConfig {
	displayName, _ := DAL.SelectStringSetting("dingtalk_display_name")
	if len(displayName) == 0 {
		displayName = "Login with Dingtalk"
	}
	callback, _ := DAL.SelectStringSetting("dingtalk_callback")
	if len(callback) == 0 {
		callback = "http://your_domain.com/oauth/dingtalk"
	}
	appID, _ := DAL.SelectStringSetting("dingtalk_appid")
	if len(appID) == 0 {
		appID = "dingoa8xvc"
	}
	appSecret, _ := DAL.SelectStringSetting("dingtalk_appsecret")
	if len(appSecret) == 0 {
		appSecret = "crrALdXUIj4T0zBekYh4u9sU_T1GZT"
	}
	dingtalkConfig := &models.DingtalkConfig{
		DisplayName: displayName,
		Callback:    callback,
		AppID:       appID,
		AppSecret:   appSecret,
	}
	return dingtalkConfig
}

// UpdateDingtalkConfig ...
func UpdateDingtalkConfig(param map[string]interface{}, authUser *models.AuthUser) (*models.DingtalkConfig, error) {
	if authUser.IsSuperAdmin == false {
		return nil, errors.New("Only super administrators can perform this operation")
	}
	dingtalkConfig := param["object"].(map[string]interface{})
	displayName := dingtalkConfig["display_name"].(string)
	callback := dingtalkConfig["callback"].(string)
	appid := dingtalkConfig["appid"].(string)
	appsecret := dingtalkConfig["appsecret"].(string)
	DAL.SaveStringSetting("dingtalk_display_name", displayName)
	DAL.SaveStringSetting("dingtalk_callback", callback)
	DAL.SaveStringSetting("dingtalk_appid", appid)
	DAL.SaveStringSetting("dingtalk_appsecret", appsecret)
	newDingtalkConfig := &models.DingtalkConfig{
		DisplayName: displayName,
		Callback:    callback,
		AppID:       appid,
		AppSecret:   appsecret,
	}
	AuthConfig.Dingtalk = newDingtalkConfig
	return newDingtalkConfig, nil
}

// GetFeishuConfig ...
func GetFeishuConfig() *models.FeishuConfig {
	displayName, _ := DAL.SelectStringSetting("feishu_display_name")
	if len(displayName) == 0 {
		displayName = "Login with Feishu"
	}
	callback, _ := DAL.SelectStringSetting("feishu_callback")
	if len(callback) == 0 {
		callback = "http://your_domain.com/oauth/feishu"
	}
	appID, _ := DAL.SelectStringSetting("feishu_appid")
	if len(appID) == 0 {
		appID = "cli_9ef21d00e"
	}
	appSecret, _ := DAL.SelectStringSetting("feishu_appsecret")
	if len(appSecret) == 0 {
		appSecret = "ihUBspRAG1PtNdDLUZ"
	}
	feishuConfig := &models.FeishuConfig{
		DisplayName: displayName,
		Callback:    callback,
		AppID:       appID,
		AppSecret:   appSecret,
	}
	return feishuConfig
}

// UpdateFeishuConfig ...
func UpdateFeishuConfig(param map[string]interface{}, authUser *models.AuthUser) (*models.FeishuConfig, error) {
	if authUser.IsSuperAdmin == false {
		return nil, errors.New("Only super administrators can perform this operation")
	}
	feishuConfig := param["object"].(map[string]interface{})
	displayName := feishuConfig["display_name"].(string)
	callback := feishuConfig["callback"].(string)
	appid := feishuConfig["appid"].(string)
	appsecret := feishuConfig["appsecret"].(string)
	DAL.SaveStringSetting("feishu_display_name", displayName)
	DAL.SaveStringSetting("feishu_callback", callback)
	DAL.SaveStringSetting("feishu_appid", appid)
	DAL.SaveStringSetting("feishu_appsecret", appsecret)
	newFeishuConfig := &models.FeishuConfig{
		DisplayName: displayName,
		Callback:    callback,
		AppID:       appid,
		AppSecret:   appsecret,
	}
	AuthConfig.Feishu = newFeishuConfig
	return newFeishuConfig, nil
}

// GetLDAPConfig ...
func GetLDAPConfig() *models.LDAPConfig {
	displayName, _ := DAL.SelectStringSetting("ldap_display_name")
	if len(displayName) == 0 {
		displayName = "Login with LDAP"
	}
	entrance, _ := DAL.SelectStringSetting("ldap_entrance")
	if len(entrance) == 0 {
		entrance = "http://your_domain.com/ldap/login"
	}
	address, _ := DAL.SelectStringSetting("ldap_address")
	if len(address) == 0 {
		address = "your_ldap_domain.com:389"
	}
	dn, _ := DAL.SelectStringSetting("ldap_dn")
	if len(dn) == 0 {
		dn = "uid={uid},ou=People,dc=your_domain,dc=com"
	}
	usingTLS, _ := DAL.SelectBoolSetting("ldap_using_tls")
	authenticatorEnabled, _ := DAL.SelectBoolSetting("ldap_authenticator_enabled")

	ldapConfig := &models.LDAPConfig{
		DisplayName:          displayName,
		Entrance:             entrance,
		Address:              address,
		DN:                   dn,
		UsingTLS:             usingTLS,
		AuthenticatorEnabled: authenticatorEnabled,
	}
	return ldapConfig
}

// UpdateLDAPConfig ...
func UpdateLDAPConfig(param map[string]interface{}, authUser *models.AuthUser) (*models.LDAPConfig, error) {
	if authUser.IsSuperAdmin == false {
		return nil, errors.New("Only super administrators can perform this operation")
	}
	ldapConfig := param["object"].(map[string]interface{})
	displayName := ldapConfig["display_name"].(string)
	entrance := ldapConfig["entrance"].(string)
	address := ldapConfig["address"].(string)
	dn := ldapConfig["dn"].(string)
	usingTLS := ldapConfig["using_tls"].(bool)
	authenticatorEnabled := ldapConfig["authenticator_enabled"].(bool)
	DAL.SaveStringSetting("ldap_display_name", displayName)
	DAL.SaveStringSetting("ldap_entrance", entrance)
	DAL.SaveStringSetting("ldap_address", address)
	DAL.SaveStringSetting("ldap_dn", dn)
	DAL.SaveBoolSetting("ldap_using_tls", usingTLS)
	DAL.SaveBoolSetting("ldap_authenticator_enabled", authenticatorEnabled)
	newLDAPConfig := &models.LDAPConfig{
		DisplayName:          displayName,
		Entrance:             entrance,
		Address:              address,
		DN:                   dn,
		UsingTLS:             usingTLS,
		AuthenticatorEnabled: authenticatorEnabled,
	}
	AuthConfig.LDAP = newLDAPConfig
	return newLDAPConfig, nil
}

// GetCAS2Config ...
func GetCAS2Config() *models.CAS2Config {
	displayName, _ := DAL.SelectStringSetting("cas2_display_name")
	if len(displayName) == 0 {
		displayName = "Login with CAS 2.0"
	}
	entrance, _ := DAL.SelectStringSetting("cas2_entrance")
	if len(entrance) == 0 {
		entrance = "https://cas_server/cas"
	}
	callback, _ := DAL.SelectStringSetting("cas2_callback")
	if len(callback) == 0 {
		callback = "http://your_domain.com/oauth/cas2"
	}
	cas2Config := &models.CAS2Config{
		DisplayName: displayName,
		Entrance:    entrance,
		Callback:    callback,
	}
	return cas2Config
}

// UpdateCAS2Config ...
func UpdateCAS2Config(param map[string]interface{}, authUser *models.AuthUser) (*models.CAS2Config, error) {
	if authUser.IsSuperAdmin == false {
		return nil, errors.New("Only super administrators can perform this operation")
	}
	cas2Config := param["object"].(map[string]interface{})
	displayName := cas2Config["display_name"].(string)
	entrance := cas2Config["entrance"].(string)
	callback := cas2Config["callback"].(string)
	DAL.SaveStringSetting("cas2_display_name", displayName)
	DAL.SaveStringSetting("cas2_entrance", entrance)
	DAL.SaveStringSetting("cas2_callback", callback)
	newCAS2Config := &models.CAS2Config{
		DisplayName: displayName,
		Entrance:    entrance,
		Callback:    callback,
	}
	AuthConfig.CAS2 = newCAS2Config
	return newCAS2Config, nil
}

// UpdateGlobalSettings ...
func UpdateGlobalSettings(param map[string]interface{}, authUser *models.AuthUser) (*models.GlobalSettings, error) {
	if authUser.IsSuperAdmin == false {
		return nil, errors.New("Only super administrators can perform this operation")
	}
	settings := param["object"].(map[string]interface{})
	authEnabled := settings["auth_enabled"].(bool)
	authProvider := settings["auth_provider"].(string)
	webSSHEnabled := settings["webssh_enabled"].(bool)
	GlobalSettings.AuthEnabled = authEnabled
	AuthConfig.Enabled = authEnabled
	GlobalSettings.AuthProvider = authProvider
	AuthConfig.Provider = authProvider
	GlobalSettings.WebSSHEnabled = webSSHEnabled
	DAL.SaveBoolSetting("auth_enabled", authEnabled)
	DAL.SaveStringSetting("auth_provider", authProvider)
	DAL.SaveBoolSetting("webssh_enabled", webSSHEnabled)
	wafLogDays := int64(settings["waf_log_days"].(float64))
	ccLogDays := int64(settings["cc_log_days"].(float64))
	accessLogDays := int64(settings["access_log_days"].(float64))
	GlobalSettings.WAFLogDays = wafLogDays
	GlobalSettings.CCLogDays = ccLogDays
	GlobalSettings.AccessLogDays = accessLogDays
	DAL.SaveIntSetting("waf_log_days", wafLogDays)
	DAL.SaveIntSetting("cc_log_days", ccLogDays)
	DAL.SaveIntSetting("access_log_days", accessLogDays)
	UpdateBackendLastModified()
	return GlobalSettings, nil
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
