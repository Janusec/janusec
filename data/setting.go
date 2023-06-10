/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:31:33
 * @Last Modified: U2, 2018-07-14 16:31:33
 */

package data

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
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

	// publicIP used for dns load balance
	publicIP string

	blockHTML string = `<!DOCTYPE html>
	<html>
	<head>
	<title>403 Forbidden</title>
	</head>
	<style>
	body {
		font-family: Arial, Helvetica, sans-serif;
		text-align: center;
	}

	.text-logo {
		display: block;
		width: 260px;
		font-size: 48px;  
		background-color: #F9F9F9;    
		color: #f5f5f5;    
		text-decoration: none;
		text-shadow: 2px 2px 4px #000000;
		box-shadow: 2px 2px 3px #D5D5D5;
		padding: 15px; 
		margin: auto;    
	}

	.block_div {
		padding: 10px;
		width: 70%;    
		margin: auto;
	}

	</style>
	<body>
	<div class="block_div">
	<h1 class="text-logo">JANUSEC</h1>
	<hr>
	Reason: {{.VulnName}}, Policy ID: {{.PolicyID}}, by Janusec Application Gateway
	</div>
	</body>
	</html>
	`
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

func UpdateDiscoveryLastModified() {
	NodeSetting.DiscoveryLastModified = time.Now().Unix()
	err := DAL.SaveIntSetting("discovery_last_modified", NodeSetting.DiscoveryLastModified)
	if err != nil {
		utils.DebugPrintln("UpdateDiscoveryLastModified SaveIntSetting", err)
	}
	utils.DebugPrintln("Discovery Modified")
}

// InitDefaultSettings only for primary node
func InitDefaultSettings() {
	DAL.LoadInstanceKey()
	DAL.LoadNodesKey()
	DAL.LoadAPIKey()
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

	// Security Audit
	if !DAL.ExistsSetting("waf_log_days") {
		_ = DAL.SaveIntSetting("waf_log_days", 7)
	}
	if !DAL.ExistsSetting("cc_log_days") {
		_ = DAL.SaveIntSetting("cc_log_days", 7)
	}
	if !DAL.ExistsSetting("access_log_days") {
		_ = DAL.SaveIntSetting("access_log_days", 180)
	}

	// Access Control
	// skip_se_enabled shared with PrimarySetting
	// search_engines_pattern is generated based on search_engines
	if !DAL.ExistsSetting("skip_se_enabled") {
		// used for 5-second shield, v1.2.0, shared with NodeSetting
		_ = DAL.SaveBoolSetting("skip_se_enabled", true)
	}
	if !DAL.ExistsSetting("search_engines") {
		// used for 5-second shield, v1.2.0
		_ = DAL.SaveStringSetting("search_engines", "Google|Baidu|MicroMessenger|miniprogram|bing|sogou|Yisou|360spider|soso|duckduck|Yandex|Yahoo|AOL|teoma")
	}
	if !DAL.ExistsSetting("webssh_enabled") {
		_ = DAL.SaveBoolSetting("webssh_enabled", false)
	}
	if !DAL.ExistsSetting("block_html") {
		_ = DAL.SaveStringSetting("block_html", blockHTML)
	}

	// SMTP shared with PrimarySetting
	if !DAL.ExistsSetting("smtp_enabled") {
		_ = DAL.SaveBoolSetting("smtp_enabled", false)
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
	// v1.2.6
	if !DAL.ExistsSetting("ldap_bind_required") {
		_ = DAL.SaveBoolSetting("ldap_bind_required", false)
	}
	if !DAL.ExistsSetting("ldap_base_dn") {
		DAL.SaveStringSetting("ldap_base_dn", "CN=Users,DC=your_domain,DC=com")
	}
	if !DAL.ExistsSetting("ldap_bind_username") {
		DAL.SaveStringSetting("ldap_bind_username", "administrator")
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

	// Data discoveries 1.3.2
	if !DAL.ExistsSetting("data_discovery_enabled") {
		DAL.SaveBoolSetting("data_discovery_enabled", false)
	}
	if !DAL.ExistsSetting("data_discovery_api") {
		DAL.SaveStringSetting("data_discovery_api", "")
	}
	if !DAL.ExistsSetting("data_discovery_tenant_id") {
		// 1.4.0fix5 add tenant_id for SaaS
		DAL.SaveStringSetting("data_discovery_tenant_id", "")
	}
	if !DAL.ExistsSetting("data_discovery_key") {
		DAL.SaveStringSetting("data_discovery_key", "")
	}

	// DNS 1.4.1
	if !DAL.ExistsSetting("dns_enabled") {
		DAL.SaveBoolSetting("dns_enabled", false)
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
		// 0.9.15 add
		PrimarySetting.WAFLogDays = DAL.SelectIntSetting("waf_log_days")
		PrimarySetting.CCLogDays = DAL.SelectIntSetting("cc_log_days")
		PrimarySetting.AccessLogDays = DAL.SelectIntSetting("access_log_days")
		// Access Control, v1.2.0 add search engines for 5-second shield, v1.3.3 add custom block html
		PrimarySetting.SkipSEEnabled = DAL.SelectBoolSetting("skip_se_enabled")
		PrimarySetting.SearchEngines = DAL.SelectStringSetting("search_engines")
		PrimarySetting.WebSSHEnabled = DAL.SelectBoolSetting("webssh_enabled")
		PrimarySetting.BlockHTML = DAL.SelectStringSetting("block_html")
		// v1.2.0 add SMTP
		smtpSetting := &models.SMTPSetting{}
		smtpSetting.SMTPEnabled = DAL.SelectBoolSetting("smtp_enabled")
		smtpSetting.SMTPServer = DAL.SelectStringSetting("smtp_server")
		smtpSetting.SMTPPort = DAL.SelectStringSetting("smtp_port")
		smtpSetting.SMTPAccount = DAL.SelectStringSetting("smtp_account")
		smtpSetting.SMTPPassword = DAL.SelectStringSetting("smtp_password")
		smtpSetting.AdminEmails = DAL.GetAppAdminEmails()
		PrimarySetting.SMTP = smtpSetting
		PrimarySetting.DataDiscoveryEnabled = DAL.SelectBoolSetting("data_discovery_enabled")
		PrimarySetting.DataDiscoveryAPI = DAL.SelectStringSetting("data_discovery_api")
		if len(PrimarySetting.DataDiscoveryAPI) == 0 {
			PrimarySetting.DataDiscoveryAPI = "http://127.0.0.1:8088/api/v1/data-discoveries"
			DAL.SaveStringSetting("data_discovery_api", PrimarySetting.DataDiscoveryAPI)
		}
		PrimarySetting.DataDiscoveryTenantID = DAL.SelectStringSetting("data_discovery_tenant_id")
		PrimarySetting.DataDiscoveryKey = DAL.SelectStringSetting("data_discovery_key")
		// v1.4.1 DNS
		PrimarySetting.DNSEnabled = DAL.SelectBoolSetting("dns_enabled")

		// NodeSetting
		NodeSetting = &models.NodeShareSetting{}
		NodeSetting.BackendLastModified = DAL.SelectIntSetting("backend_last_modified")
		NodeSetting.FirewallLastModified = DAL.SelectIntSetting("firewall_last_modified")
		SyncScndsInt64 := DAL.SelectIntSetting("sync_seconds")
		NodeSetting.SyncInterval = time.Duration(SyncScndsInt64) * time.Second
		NodeSetting.SkipSEEnabled = PrimarySetting.SkipSEEnabled
		NodeSetting.SearchEnginesPattern = UpdateSecondShieldPattern(PrimarySetting.SearchEngines)
		NodeSetting.BlockHTML = PrimarySetting.BlockHTML
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
		// v1.3.2 data discovery
		NodeSetting.DataDiscoveryEnabled = PrimarySetting.DataDiscoveryEnabled
		NodeSetting.DataDiscoveryAPI = PrimarySetting.DataDiscoveryAPI
		NodeSetting.DataDiscoveryTenantID = PrimarySetting.DataDiscoveryTenantID
		NodeSetting.DataDiscoveryKey = PrimarySetting.DataDiscoveryKey
		DataDiscoveryKey, _ = hex.DecodeString(NodeSetting.DataDiscoveryKey)
		return
	}
	// Replica nodes, load to Memory
	NodeSetting = RPCGetNodeSetting()
	// Set DataDiscoveryKey
	if len(NodeSetting.DataDiscoveryKey) > 0 {
		DataDiscoveryKey, _ = hex.DecodeString(NodeSetting.DataDiscoveryKey)
	}
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
func UpdateWxworkConfig(body []byte, clientIP string, authUser *models.AuthUser) (*models.WxworkConfig, error) {
	if !authUser.IsSuperAdmin {
		return nil, errors.New("only super administrators can perform this operation")
	}
	var rpcWxworkConfigRequest models.APIWxworkConfigRequest
	if err := json.Unmarshal(body, &rpcWxworkConfigRequest); err != nil {
		utils.DebugPrintln("UpdateWxworkConfig", err)
		return nil, err
	}
	wxworkConfig := rpcWxworkConfigRequest.Object
	DAL.SaveStringSetting("wxwork_display_name", wxworkConfig.DisplayName)
	DAL.SaveStringSetting("wxwork_callback", wxworkConfig.Callback)
	DAL.SaveStringSetting("wxwork_corpid", wxworkConfig.CorpID)
	DAL.SaveStringSetting("wxwork_agentid", wxworkConfig.AgentID)
	DAL.SaveStringSetting("wxwork_corpsecret", wxworkConfig.CorpSecret)

	NodeSetting.AuthConfig.Wxwork = wxworkConfig
	go utils.OperationLog(clientIP, authUser.Username, "Update Wxwork Config", wxworkConfig.DisplayName)
	return wxworkConfig, nil
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
func UpdateDingtalkConfig(body []byte, clientIP string, authUser *models.AuthUser) (*models.DingtalkConfig, error) {
	if !authUser.IsSuperAdmin {
		return nil, errors.New("only super administrators can perform this operation")
	}
	var rpcDingtalkConfigRequest models.APIDingtalkConfigRequest
	if err := json.Unmarshal(body, &rpcDingtalkConfigRequest); err != nil {
		utils.DebugPrintln("UpdateDingtalkConfig", err)
		return nil, err
	}
	dingtalkConfig := rpcDingtalkConfigRequest.Object
	/*
		dingtalkConfig := param["object"].(map[string]interface{})
		displayName := dingtalkConfig["display_name"].(string)
		callback := dingtalkConfig["callback"].(string)
		appid := dingtalkConfig["appid"].(string)
		appsecret := dingtalkConfig["appsecret"].(string)
	*/
	DAL.SaveStringSetting("dingtalk_display_name", dingtalkConfig.DisplayName)
	DAL.SaveStringSetting("dingtalk_callback", dingtalkConfig.Callback)
	DAL.SaveStringSetting("dingtalk_appid", dingtalkConfig.AppID)
	DAL.SaveStringSetting("dingtalk_appsecret", dingtalkConfig.AppSecret)

	NodeSetting.AuthConfig.Dingtalk = dingtalkConfig
	go utils.OperationLog(clientIP, authUser.Username, "Update Dingtalk Config", dingtalkConfig.DisplayName)
	return dingtalkConfig, nil
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
func UpdateFeishuConfig(body []byte, clientIP string, authUser *models.AuthUser) (*models.FeishuConfig, error) {
	if !authUser.IsSuperAdmin {
		return nil, errors.New("only super administrators can perform this operation")
	}
	var rpcFeishuConfigRequest models.APIFeishuConfigRequest
	if err := json.Unmarshal(body, &rpcFeishuConfigRequest); err != nil {
		utils.DebugPrintln("UpdateFeishuConfig", err)
		return nil, err
	}
	feishuConfig := rpcFeishuConfigRequest.Object
	DAL.SaveStringSetting("feishu_display_name", feishuConfig.DisplayName)
	DAL.SaveStringSetting("feishu_callback", feishuConfig.Callback)
	DAL.SaveStringSetting("feishu_appid", feishuConfig.AppID)
	DAL.SaveStringSetting("feishu_appsecret", feishuConfig.AppSecret)

	NodeSetting.AuthConfig.Feishu = feishuConfig
	go utils.OperationLog(clientIP, authUser.Username, "Update Feishu Config", feishuConfig.DisplayName)
	return feishuConfig, nil
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
func UpdateLarkConfig(body []byte, clientIP string, authUser *models.AuthUser) (*models.LarkConfig, error) {
	if !authUser.IsSuperAdmin {
		return nil, errors.New("only super administrators can perform this operation")
	}
	var rpcLarkConfigRequest models.APILarkConfigRequest
	if err := json.Unmarshal(body, &rpcLarkConfigRequest); err != nil {
		utils.DebugPrintln("UpdateLarkConfig", err)
		return nil, err
	}
	larkConfig := rpcLarkConfigRequest.Object
	DAL.SaveStringSetting("lark_display_name", larkConfig.DisplayName)
	DAL.SaveStringSetting("lark_callback", larkConfig.Callback)
	DAL.SaveStringSetting("lark_appid", larkConfig.AppID)
	DAL.SaveStringSetting("lark_appsecret", larkConfig.AppSecret)
	NodeSetting.AuthConfig.Lark = larkConfig
	go utils.OperationLog(clientIP, authUser.Username, "Update Lark Config", larkConfig.DisplayName)
	return larkConfig, nil
}

// GetLDAPConfig ...
func GetLDAPConfig() *models.LDAPConfig {
	displayName := DAL.SelectStringSetting("ldap_display_name")
	entrance := DAL.SelectStringSetting("ldap_entrance")
	address := DAL.SelectStringSetting("ldap_address")
	dn := DAL.SelectStringSetting("ldap_dn")
	usingTLS := DAL.SelectBoolSetting("ldap_using_tls")
	authenticatorEnabled := DAL.SelectBoolSetting("ldap_authenticator_enabled")
	bindRequired := DAL.SelectBoolSetting("ldap_bind_required")
	baseDN := DAL.SelectStringSetting("ldap_base_dn")
	bindUsername := DAL.SelectStringSetting("ldap_bind_username")
	hexBindPassword := DAL.SelectStringSetting("ldap_bind_password")
	var bindPassword string
	if len(hexBindPassword) == 0 {
		bindPassword = ""
	} else {
		encryptedBindPassword, _ := hex.DecodeString(hexBindPassword)
		bindPasswordByte, _ := AES256Decrypt(encryptedBindPassword, false)
		bindPassword = string(bindPasswordByte)
	}

	ldapConfig := &models.LDAPConfig{
		DisplayName:          displayName,
		Entrance:             entrance,
		Address:              address,
		DN:                   dn,
		UsingTLS:             usingTLS,
		AuthenticatorEnabled: authenticatorEnabled,
		BindRequired:         bindRequired,
		BaseDN:               baseDN,
		BindUsername:         bindUsername,
		BindPassword:         bindPassword,
	}
	return ldapConfig
}

// UpdateLDAPConfig ...
func UpdateLDAPConfig(body []byte, clientIP string, authUser *models.AuthUser) (*models.LDAPConfig, error) {
	if !authUser.IsSuperAdmin {
		return nil, errors.New("only super administrators can perform this operation")
	}
	var rpcLDAPConfigRequest models.APILDAPConfigRequest
	if err := json.Unmarshal(body, &rpcLDAPConfigRequest); err != nil {
		utils.DebugPrintln("UpdateLDAPConfig", err)
		return nil, err
	}
	ldapConfig := rpcLDAPConfigRequest.Object
	DAL.SaveStringSetting("ldap_display_name", ldapConfig.DisplayName)
	DAL.SaveStringSetting("ldap_entrance", ldapConfig.Entrance)
	DAL.SaveStringSetting("ldap_address", ldapConfig.Address)
	DAL.SaveStringSetting("ldap_dn", ldapConfig.DN)
	DAL.SaveBoolSetting("ldap_using_tls", ldapConfig.UsingTLS)
	DAL.SaveBoolSetting("ldap_authenticator_enabled", ldapConfig.AuthenticatorEnabled)
	DAL.SaveBoolSetting("ldap_bind_required", ldapConfig.BindRequired)
	DAL.SaveStringSetting("ldap_base_dn", ldapConfig.BaseDN)
	DAL.SaveStringSetting("ldap_bind_username", ldapConfig.BindUsername)
	var encrypedBindPassword string
	if len(ldapConfig.BindPassword) == 0 {
		encrypedBindPassword = ""
	} else {
		encryptedPasswordBytes := AES256Encrypt([]byte(ldapConfig.BindPassword), false)
		encrypedBindPassword = hex.EncodeToString(encryptedPasswordBytes)
	}
	DAL.SaveStringSetting("ldap_bind_password", encrypedBindPassword)
	NodeSetting.AuthConfig.LDAP = ldapConfig
	go utils.OperationLog(clientIP, authUser.Username, "Update LDAP Config", ldapConfig.DisplayName)
	return ldapConfig, nil
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
func UpdateCAS2Config(body []byte, clientIP string, authUser *models.AuthUser) (*models.CAS2Config, error) {
	if !authUser.IsSuperAdmin {
		return nil, errors.New("only super administrators can perform this operation")
	}
	var rpcCAS2ConfigRequest models.APICAS2ConfigRequest
	if err := json.Unmarshal(body, &rpcCAS2ConfigRequest); err != nil {
		utils.DebugPrintln("UpdateCAS2Config", err)
		return nil, err
	}
	cas2Config := rpcCAS2ConfigRequest.Object
	DAL.SaveStringSetting("cas2_display_name", cas2Config.DisplayName)
	DAL.SaveStringSetting("cas2_entrance", cas2Config.Entrance)
	DAL.SaveStringSetting("cas2_callback", cas2Config.Callback)
	NodeSetting.AuthConfig.CAS2 = cas2Config
	go utils.OperationLog(clientIP, authUser.Username, "Update CAS2 Config", cas2Config.DisplayName)
	return cas2Config, nil
}

// UpdatePrimarySetting ...
func UpdatePrimarySetting(r *http.Request, body []byte, clientIP string, authUser *models.AuthUser) (*models.PrimarySetting, error) {
	if !authUser.IsSuperAdmin {
		return nil, errors.New("only super administrators can perform this operation")
	}
	var settingReq models.PrimarySettingRequest
	if err := json.Unmarshal(body, &settingReq); err != nil {
		utils.DebugPrintln("UpdatePrimarySetting Unmarshal", err)
	}
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
	DAL.SaveStringSetting("block_html", PrimarySetting.BlockHTML)
	NodeSetting.BlockHTML = PrimarySetting.BlockHTML
	DAL.SaveBoolSetting("smtp_enabled", PrimarySetting.SMTP.SMTPEnabled)
	DAL.SaveStringSetting("smtp_server", PrimarySetting.SMTP.SMTPServer)
	DAL.SaveStringSetting("smtp_port", PrimarySetting.SMTP.SMTPPort)
	DAL.SaveStringSetting("smtp_account", PrimarySetting.SMTP.SMTPAccount)
	DAL.SaveStringSetting("smtp_password", PrimarySetting.SMTP.SMTPPassword)
	DAL.SaveBoolSetting("data_discovery_enabled", PrimarySetting.DataDiscoveryEnabled)
	DAL.SaveStringSetting("data_discovery_api", PrimarySetting.DataDiscoveryAPI)
	DAL.SaveStringSetting("data_discovery_tenant_id", PrimarySetting.DataDiscoveryTenantID)
	DAL.SaveStringSetting("data_discovery_key", PrimarySetting.DataDiscoveryKey)
	DAL.SaveBoolSetting("dns_enabled", PrimarySetting.DNSEnabled)
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
		Action: "get_node_setting",
		Object: nil,
	}
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
		utils.DebugPrintln("RPCGetNodeSetting failed, please check config.json and server time")
	}
	return rpcObject.Object
}

// GetPublicIP used for DNS load balance
func GetPublicIP() string {
	if len(publicIP) > 0 {
		return publicIP
	}
	conn, error := net.Dial("udp", "8.8.8.8:80")
	if error != nil {
		fmt.Println(error)
	}
	defer conn.Close()
	ipAddress := conn.LocalAddr().(*net.UDPAddr)
	publicIP = ipAddress.IP.String()
	fmt.Println("GetPublicIP", publicIP)
	return ipAddress.IP.String()
}
