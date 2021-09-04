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
	"fmt"
	"net/http"
	"time"

	"janusec/models"
	"janusec/utils"
)

var (
	// NodeSetting shared with all nodes
	NodeSetting *models.NodeShareSetting

	// PrimarySetting include oauth, logs retention, smtp etc.
	PrimarySetting *models.PrimarySetting
)

// UpdateBackendLastModified ...
func UpdateBackendLastModified() {
	NodeSetting.BackendLastModified = time.Now().Unix()
	err := DAL.SaveIntSetting("backend_last_modified", NodeSetting.BackendLastModified)
	if err != nil {
		utils.DebugPrintln("UpdateBackendLastModified SaveIntSetting", err)
	}
	utils.DebugPrintln("Backend Modified")
}

// UpdateFirewallLastModified ...
func UpdateFirewallLastModified() {
	NodeSetting.FirewallLastModified = time.Now().Unix()
	err := DAL.SaveIntSetting("firewall_last_modified", NodeSetting.FirewallLastModified)
	if err != nil {
		utils.DebugPrintln("UpdateFirewallLastModified SaveIntSetting", err)
	}
	utils.DebugPrintln("Firewall Modified")
}

// InitDefaultSettings ...
func InitDefaultSettings() {
	DAL.LoadInstanceKey()
	DAL.LoadNodesKey()
	var err error

	// Init PrimarySetting
	if !DAL.ExistsSetting("authenticator_enabled") {
		// for janusec-admin 2-factor authentication
		_ = DAL.SaveBoolSetting("authenticator_enabled", false)
	}
	if !DAL.ExistsSetting("auth_enabled") {
		_ = DAL.SaveBoolSetting("auth_enabled", false)
	}
	if !DAL.ExistsSetting("auth_provider") {
		_ = DAL.SaveStringSetting("auth_provider", "wxwork")
	}
	if !DAL.ExistsSetting("webssh_enabled") {
		_ = DAL.SaveBoolSetting("webssh_enabled", false)
	}
	if !DAL.ExistsSetting("waf_log_days") {
		_ = DAL.SaveIntSetting("waf_log_days", 7)
	}
	if !DAL.ExistsSetting("cc_log_days") {
		_ = DAL.SaveIntSetting("cc_log_days", 7)
	}
	if !DAL.ExistsSetting("access_log_days") {
		_ = DAL.SaveIntSetting("access_log_days", 180)
	}
	if !DAL.ExistsSetting("smtp_enabled") {
		_ = DAL.SaveBoolSetting("smtp_enabled", false)
	}
	if !DAL.ExistsSetting("skip_se_enabled") {
		// used for 5-second shield, v1.2.0, shared with NodeSetting
		_ = DAL.SaveBoolSetting("skip_se_enabled", true)
	}
	if !DAL.ExistsSetting("search_engines") {
		// used for 5-second shield, v1.2.0
		_ = DAL.SaveStringSetting("search_engines", "Google|Baidu|MicroMessenger|miniprogram|bing|sogou|Yisou|360spider|soso|duckduck|Yandex|Yahoo|AOL|teoma")
	}
	if !DAL.ExistsSetting("smtp_server") {
		_ = DAL.SaveStringSetting("smtp_server", "smtp.example.com")
	}
	if !DAL.ExistsSetting("smtp_port") {
		_ = DAL.SaveStringSetting("smtp_port", "587")
	}
	if !DAL.ExistsSetting("smtp_account") {
		_ = DAL.SaveStringSetting("smtp_account", "account@example.com")
	}
	if !DAL.ExistsSetting("smtp_password") {
		_ = DAL.SaveStringSetting("smtp_password", "******")
	}

	// NodeSetting
	if !DAL.ExistsSetting("backend_last_modified") {
		_ = DAL.SaveIntSetting("backend_last_modified", 0)
	}
	if !DAL.ExistsSetting("firewall_last_modified") {
		_ = DAL.SaveIntSetting("firewall_last_modified", 0)
	}
	// v1.2.0, sync interval change from 10 minutes to 2 minutes
	_ = DAL.SaveIntSetting("sync_seconds", 120)

	// skip_se_enabled shared with PrimarySetting
	// search_engines_pattern is generated based on search_engines
	// SMTP shared with PrimarySetting
	// AuthConfig wxwork
	if !DAL.ExistsSetting("wxwork_display_name") {
		DAL.SaveStringSetting("wxwork_display_name", "Login with WeChat Work")
	}
	if !DAL.ExistsSetting("wxwork_callback") {
		DAL.SaveStringSetting("wxwork_callback", "http://www.example.com/oauth/wxwork")
	}
	if !DAL.ExistsSetting("wxwork_corpid") {
		DAL.SaveStringSetting("wxwork_corpid", "wwd03be1f8")
	}
	if !DAL.ExistsSetting("wxwork_agentid") {
		DAL.SaveStringSetting("wxwork_agentid", "1000002")
	}
	if !DAL.ExistsSetting("wxwork_corpsecret") {
		DAL.SaveStringSetting("wxwork_corpsecret", "BgZtz_hssdZV5em-AyGhOgLlm18rU_NdZI")
	}
	// AuthConfig dingtalk
	if !DAL.ExistsSetting("dingtalk_display_name") {
		DAL.SaveStringSetting("dingtalk_display_name", "Login with Dingtalk")
	}
	if !DAL.ExistsSetting("dingtalk_callback") {
		DAL.SaveStringSetting("dingtalk_callback", "http://www.example.com/oauth/dingtalk")
	}
	if !DAL.ExistsSetting("dingtalk_appid") {
		DAL.SaveStringSetting("dingtalk_appid", "dingoa8xvc")
	}
	if !DAL.ExistsSetting("dingtalk_appsecret") {
		DAL.SaveStringSetting("dingtalk_appsecret", "crrALdXUIj4T0zBekYh4u9sU_T1GZT")
	}
	// AuthConfig feishu
	if !DAL.ExistsSetting("feishu_display_name") {
		DAL.SaveStringSetting("feishu_display_name", "Login with Feishu")
	}
	if !DAL.ExistsSetting("feishu_callback") {
		DAL.SaveStringSetting("feishu_callback", "http://www.example.com/oauth/feishu")
	}
	if !DAL.ExistsSetting("feishu_appid") {
		DAL.SaveStringSetting("feishu_appid", "cli_9ef21d00e")
	}
	if !DAL.ExistsSetting("feishu_appsecret") {
		DAL.SaveStringSetting("feishu_appsecret", "ihUBspRAG1PtNdDLUZ")
	}
	// AuthConfig lark
	if !DAL.ExistsSetting("lark_display_name") {
		DAL.SaveStringSetting("lark_display_name", "Login with Lark")
	}
	if !DAL.ExistsSetting("lark_callback") {
		DAL.SaveStringSetting("lark_callback", "http://www.example.com/oauth/lark")
	}
	if !DAL.ExistsSetting("lark_appid") {
		DAL.SaveStringSetting("lark_appid", "cli_9ef21d00e")
	}
	if !DAL.ExistsSetting("lark_appsecret") {
		DAL.SaveStringSetting("lark_appsecret", "ihUBspRAG1PtNdDLUZ")
	}
	// AuthConfig LDAP
	if !DAL.ExistsSetting("ldap_display_name") {
		DAL.SaveStringSetting("ldap_display_name", "Login with LDAP")
	}
	if !DAL.ExistsSetting("ldap_entrance") {
		DAL.SaveStringSetting("ldap_entrance", "http://www.example.com/ldap/login")
	}
	if !DAL.ExistsSetting("ldap_address") {
		DAL.SaveStringSetting("ldap_address", "your_ldap_domain.com:389")
	}
	if !DAL.ExistsSetting("ldap_dn") {
		DAL.SaveStringSetting("ldap_dn", "uid={uid},ou=People,dc=your_domain,dc=com")
	}
	if !DAL.ExistsSetting("ldap_using_tls") {
		_ = DAL.SaveBoolSetting("ldap_using_tls", false)
	}
	if !DAL.ExistsSetting("ldap_authenticator_enabled") {
		_ = DAL.SaveBoolSetting("ldap_authenticator_enabled", false)
	}
	// AuthConfig cas2
	if !DAL.ExistsSetting("cas2_display_name") {
		DAL.SaveStringSetting("cas2_display_name", "Login with CAS 2.0")
	}
	if !DAL.ExistsSetting("cas2_entrance") {
		DAL.SaveStringSetting("cas2_entrance", "https://cas_server/cas")
	}
	if !DAL.ExistsSetting("cas2_callback") {
		DAL.SaveStringSetting("cas2_callback", "http://www.example.com/oauth/cas2")
	}

	// Other
	if !DAL.ExistsSetting("init_time") {
		// 0.9.13 +
		_ = DAL.SaveIntSetting("init_time", time.Now().Unix())
	}
	if err != nil {
		utils.DebugPrintln("InitDefaultSettings error", err)
	}
}

// LoadSettings ...
func LoadSettings() {
	if IsPrimary {
		PrimarySetting = &models.PrimarySetting{}
		// 1.0.0 add
		PrimarySetting.AuthenticatorEnabled = DAL.SelectBoolSetting("authenticator_enabled") // v1.2.2
		PrimarySetting.AuthEnabled = DAL.SelectBoolSetting("auth_enabled")
		PrimarySetting.AuthProvider = DAL.SelectStringSetting("auth_provider")
		if len(PrimarySetting.AuthProvider) == 0 {
			PrimarySetting.AuthProvider = "wxwork"
		}
		PrimarySetting.WebSSHEnabled = DAL.SelectBoolSetting("webssh_enabled")
		// 0.9.15 add
		PrimarySetting.WAFLogDays = DAL.SelectIntSetting("waf_log_days")
		PrimarySetting.CCLogDays = DAL.SelectIntSetting("cc_log_days")
		PrimarySetting.AccessLogDays = DAL.SelectIntSetting("access_log_days")
		// v1.2.0 add search engines for 5-second shield
		PrimarySetting.SkipSEEnabled = DAL.SelectBoolSetting("skip_se_enabled")
		PrimarySetting.SearchEngines = DAL.SelectStringSetting("search_engines")
		// v1.2.0 add SMTP
		smtpSetting := &models.SMTPSetting{}
		smtpSetting.SMTPEnabled = DAL.SelectBoolSetting("smtp_enabled")
		smtpSetting.SMTPServer = DAL.SelectStringSetting("smtp_server")
		smtpSetting.SMTPPort = DAL.SelectStringSetting("smtp_port")
		smtpSetting.SMTPAccount = DAL.SelectStringSetting("smtp_account")
		smtpSetting.SMTPPassword = DAL.SelectStringSetting("smtp_password")
		smtpSetting.AdminEmails = DAL.GetAppAdminEmails()
		PrimarySetting.SMTP = smtpSetting

		// NodeSetting
		NodeSetting = &models.NodeShareSetting{}
		NodeSetting.BackendLastModified = DAL.SelectIntSetting("backend_last_modified")
		NodeSetting.FirewallLastModified = DAL.SelectIntSetting("firewall_last_modified")
		SyncScndsInt64 := DAL.SelectIntSetting("sync_seconds")
		NodeSetting.SyncInterval = time.Duration(SyncScndsInt64) * time.Second
		NodeSetting.SkipSEEnabled = PrimarySetting.SkipSEEnabled
		NodeSetting.SearchEnginesPattern = UpdateSecondShieldPattern(PrimarySetting.SearchEngines)
		// NodeSetting.SMTP and PrimarySetting.SMTP point to the same SMTP setting
		NodeSetting.SMTP = smtpSetting
		// LoadAuthConfig
		if !PrimarySetting.AuthEnabled {
			NodeSetting.AuthConfig = &models.OAuthConfig{
				Enabled:  false,
				Provider: "",
			}
		} else {
			NodeSetting.AuthConfig = &models.OAuthConfig{
				Enabled:  PrimarySetting.AuthEnabled,
				Provider: PrimarySetting.AuthProvider,
				Wxwork:   GetWxworkConfig(),
				Dingtalk: GetDingtalkConfig(),
				Feishu:   GetFeishuConfig(),
				Lark:     GetLarkConfig(),
				LDAP:     GetLDAPConfig(),
				CAS2:     GetCAS2Config(),
			}
		}
		return
	}
	// Replica nodes, load to Memory
	NodeSetting = RPCGetNodeSetting()
}

// GetPrimarySetting for admin configuration
func GetPrimarySetting(authUser *models.AuthUser) (*models.PrimarySetting, error) {
	if !authUser.IsSuperAdmin {
		return nil, errors.New("only super administrators can perform this operation")
	}
	return PrimarySetting, nil
}

// GetGlobalSettings2 for admin configuration
func GetGlobalSettings2() *models.PrimarySetting {
	return PrimarySetting
}

// GetWxworkConfig return Auth Wxwork config
func GetWxworkConfig() *models.WxworkConfig {
	displayName := DAL.SelectStringSetting("wxwork_display_name")
	callback := DAL.SelectStringSetting("wxwork_callback")
	corpID := DAL.SelectStringSetting("wxwork_corpid")
	agentID := DAL.SelectStringSetting("wxwork_agentid")
	corpSecret := DAL.SelectStringSetting("wxwork_corpsecret")
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
func UpdateWxworkConfig(param map[string]interface{}, clientIP string, authUser *models.AuthUser) (*models.WxworkConfig, error) {
	if !authUser.IsSuperAdmin {
		return nil, errors.New("only super administrators can perform this operation")
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
	NodeSetting.AuthConfig.Wxwork = newWxworkConfig
	go utils.OperationLog(clientIP, authUser.Username, "Update Wxwork Config", displayName)
	return newWxworkConfig, nil
}

// GetDingtalkConfig return Auth Dingtalk config
func GetDingtalkConfig() *models.DingtalkConfig {
	displayName := DAL.SelectStringSetting("dingtalk_display_name")
	callback := DAL.SelectStringSetting("dingtalk_callback")
	appID := DAL.SelectStringSetting("dingtalk_appid")
	appSecret := DAL.SelectStringSetting("dingtalk_appsecret")
	dingtalkConfig := &models.DingtalkConfig{
		DisplayName: displayName,
		Callback:    callback,
		AppID:       appID,
		AppSecret:   appSecret,
	}
	return dingtalkConfig
}

// UpdateDingtalkConfig ...
func UpdateDingtalkConfig(param map[string]interface{}, clientIP string, authUser *models.AuthUser) (*models.DingtalkConfig, error) {
	if !authUser.IsSuperAdmin {
		return nil, errors.New("only super administrators can perform this operation")
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
	NodeSetting.AuthConfig.Dingtalk = newDingtalkConfig
	go utils.OperationLog(clientIP, authUser.Username, "Update Dingtalk Config", displayName)
	return newDingtalkConfig, nil
}

// GetFeishuConfig ...
func GetFeishuConfig() *models.FeishuConfig {
	displayName := DAL.SelectStringSetting("feishu_display_name")
	callback := DAL.SelectStringSetting("feishu_callback")
	appID := DAL.SelectStringSetting("feishu_appid")
	appSecret := DAL.SelectStringSetting("feishu_appsecret")
	feishuConfig := &models.FeishuConfig{
		DisplayName: displayName,
		Callback:    callback,
		AppID:       appID,
		AppSecret:   appSecret,
	}
	return feishuConfig
}

// UpdateFeishuConfig ...
func UpdateFeishuConfig(param map[string]interface{}, clientIP string, authUser *models.AuthUser) (*models.FeishuConfig, error) {
	if !authUser.IsSuperAdmin {
		return nil, errors.New("only super administrators can perform this operation")
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
	NodeSetting.AuthConfig.Feishu = newFeishuConfig
	go utils.OperationLog(clientIP, authUser.Username, "Update Feishu Config", displayName)
	return newFeishuConfig, nil
}

// GetLarkConfig ...
func GetLarkConfig() *models.LarkConfig {
	displayName := DAL.SelectStringSetting("lark_display_name")
	callback := DAL.SelectStringSetting("lark_callback")
	appID := DAL.SelectStringSetting("lark_appid")
	appSecret := DAL.SelectStringSetting("lark_appsecret")
	larkConfig := &models.LarkConfig{
		DisplayName: displayName,
		Callback:    callback,
		AppID:       appID,
		AppSecret:   appSecret,
	}
	return larkConfig
}

// UpdateLarkConfig ...
func UpdateLarkConfig(param map[string]interface{}, clientIP string, authUser *models.AuthUser) (*models.LarkConfig, error) {
	if !authUser.IsSuperAdmin {
		return nil, errors.New("only super administrators can perform this operation")
	}
	larkConfig := param["object"].(map[string]interface{})
	displayName := larkConfig["display_name"].(string)
	callback := larkConfig["callback"].(string)
	appid := larkConfig["appid"].(string)
	appsecret := larkConfig["appsecret"].(string)
	DAL.SaveStringSetting("lark_display_name", displayName)
	DAL.SaveStringSetting("lark_callback", callback)
	DAL.SaveStringSetting("lark_appid", appid)
	DAL.SaveStringSetting("lark_appsecret", appsecret)
	newLarkConfig := &models.LarkConfig{
		DisplayName: displayName,
		Callback:    callback,
		AppID:       appid,
		AppSecret:   appsecret,
	}
	NodeSetting.AuthConfig.Lark = newLarkConfig
	go utils.OperationLog(clientIP, authUser.Username, "Update Lark Config", displayName)
	return newLarkConfig, nil
}

// GetLDAPConfig ...
func GetLDAPConfig() *models.LDAPConfig {
	displayName := DAL.SelectStringSetting("ldap_display_name")
	entrance := DAL.SelectStringSetting("ldap_entrance")
	address := DAL.SelectStringSetting("ldap_address")
	dn := DAL.SelectStringSetting("ldap_dn")
	usingTLS := DAL.SelectBoolSetting("ldap_using_tls")
	authenticatorEnabled := DAL.SelectBoolSetting("ldap_authenticator_enabled")

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
func UpdateLDAPConfig(param map[string]interface{}, clientIP string, authUser *models.AuthUser) (*models.LDAPConfig, error) {
	if !authUser.IsSuperAdmin {
		return nil, errors.New("only super administrators can perform this operation")
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
	NodeSetting.AuthConfig.LDAP = newLDAPConfig
	go utils.OperationLog(clientIP, authUser.Username, "Update LDAP Config", displayName)
	return newLDAPConfig, nil
}

// GetCAS2Config ...
func GetCAS2Config() *models.CAS2Config {
	displayName := DAL.SelectStringSetting("cas2_display_name")
	entrance := DAL.SelectStringSetting("cas2_entrance")
	callback := DAL.SelectStringSetting("cas2_callback")
	cas2Config := &models.CAS2Config{
		DisplayName: displayName,
		Entrance:    entrance,
		Callback:    callback,
	}
	return cas2Config
}

// UpdateCAS2Config ...
func UpdateCAS2Config(param map[string]interface{}, clientIP string, authUser *models.AuthUser) (*models.CAS2Config, error) {
	if !authUser.IsSuperAdmin {
		return nil, errors.New("only super administrators can perform this operation")
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
	NodeSetting.AuthConfig.CAS2 = newCAS2Config
	go utils.OperationLog(clientIP, authUser.Username, "Update CAS2 Config", displayName)
	return newCAS2Config, nil
}

// UpdatePrimarySetting ...
func UpdatePrimarySetting(r *http.Request, param map[string]interface{}, clientIP string, authUser *models.AuthUser) (*models.PrimarySetting, error) {
	if !authUser.IsSuperAdmin {
		return nil, errors.New("only super administrators can perform this operation")
	}
	var settingReq models.PrimarySettingRequest
	err := json.NewDecoder(r.Body).Decode(&settingReq)
	if err != nil {
		utils.DebugPrintln("UpdatePrimarySetting Decode", err)
	}
	defer r.Body.Close()
	PrimarySetting = settingReq.Object
	DAL.SaveBoolSetting("authenticator_enabled", PrimarySetting.AuthenticatorEnabled) // v1.2.2
	DAL.SaveBoolSetting("auth_enabled", PrimarySetting.AuthEnabled)
	DAL.SaveStringSetting("auth_provider", PrimarySetting.AuthProvider)
	NodeSetting.AuthConfig.Enabled = PrimarySetting.AuthEnabled
	NodeSetting.AuthConfig.Provider = PrimarySetting.AuthProvider
	DAL.SaveBoolSetting("webssh_enabled", PrimarySetting.WebSSHEnabled)
	DAL.SaveIntSetting("waf_log_days", PrimarySetting.WAFLogDays)
	DAL.SaveIntSetting("cc_log_days", PrimarySetting.CCLogDays)
	DAL.SaveIntSetting("access_log_days", PrimarySetting.AccessLogDays)
	DAL.SaveBoolSetting("skip_se_enabled", PrimarySetting.SkipSEEnabled)
	DAL.SaveStringSetting("search_engines", PrimarySetting.SearchEngines)
	NodeSetting.SearchEnginesPattern = UpdateSecondShieldPattern(PrimarySetting.SearchEngines)
	DAL.SaveBoolSetting("smtp_enabled", PrimarySetting.SMTP.SMTPEnabled)
	DAL.SaveStringSetting("smtp_server", PrimarySetting.SMTP.SMTPServer)
	DAL.SaveStringSetting("smtp_port", PrimarySetting.SMTP.SMTPPort)
	DAL.SaveStringSetting("smtp_account", PrimarySetting.SMTP.SMTPAccount)
	DAL.SaveStringSetting("smtp_password", PrimarySetting.SMTP.SMTPPassword)
	go utils.OperationLog(clientIP, authUser.Username, "Update Settings", "Global Settings")
	UpdateBackendLastModified()
	return PrimarySetting, nil
}

// RPCGetOAuthConfig ...
func RPCGetOAuthConfig() *models.OAuthConfig {
	rpcRequest := &models.RPCRequest{
		Action: "get_oauth_conf", Object: nil}
	resp, err := GetRPCResponse(rpcRequest)
	if err != nil {
		utils.DebugPrintln("RPCGetOAuthConfig", err)
	}
	rpcOAuthConf := &models.RPCOAuthConfig{}
	if err = json.Unmarshal(resp, rpcOAuthConf); err != nil {
		utils.DebugPrintln("RPCGetOAuthConfig Unmarshal", err)
	}
	//fmt.Println("RPCGetOAuthConfig", rpcOAuthConf.Object)
	return rpcOAuthConf.Object
}

// UpdateSecondShieldPattern ...
func UpdateSecondShieldPattern(searchEngines string) string {
	return fmt.Sprintf(`(?i)(%s)`, searchEngines)
}

func GetNodeSetting() *models.NodeShareSetting {
	return NodeSetting
}

func RPCGetNodeSetting() *models.NodeShareSetting {
	rpcRequest := &models.RPCRequest{
		Action: "get_node_setting", Object: nil}
	resp, err := GetRPCResponse(rpcRequest)
	if err != nil {
		utils.DebugPrintln("RPCGetNodeSetting", err)
	}
	rpcObject := &models.RPCNodeSetting{}
	if err = json.Unmarshal(resp, rpcObject); err != nil {
		utils.DebugPrintln("RPCGetNodeSetting Unmarshal", err)
	}
	if rpcObject.Object == nil {
		rpcObject.Object = &models.NodeShareSetting{
			SyncInterval: time.Duration(120) * time.Second,
		}
	}
	return rpcObject.Object
}
