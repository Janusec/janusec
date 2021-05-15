/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2020-03-14 18:47:18
 * @Last Modified: U2, 2020-03-14 18:47:18
 */

package gateway

import (
	"fmt"
	"net/http"

	"janusec/data"
	"janusec/usermgmt"
)

// OAuthInfo OAuth Information
type OAuthInfo struct {
	UseOAuth    bool   `json:"use_oauth"`
	DisplayName string `json:"display_name"`
	EntranceURL string `json:"entrance_url"`

	// AuthenticatorEnabled added in v1.2.2, for janusec-admin login
	AuthenticatorEnabled bool `json:"authenticator_enabled"`
}

// WxworkCallBackHandleFunc for Wxwork CallBack
func WxworkCallBackHandleFunc(w http.ResponseWriter, r *http.Request) {
	usermgmt.WxworkCallbackWithCode(w, r)
}

// DingtalkCallBackHandleFunc for Dingtalk CallBack
func DingtalkCallBackHandleFunc(w http.ResponseWriter, r *http.Request) {
	usermgmt.DingtalkCallbackWithCode(w, r)
}

// FeishuCallBackHandleFunc for Feishu CallBack
func FeishuCallBackHandleFunc(w http.ResponseWriter, r *http.Request) {
	usermgmt.FeishuCallbackWithCode(w, r)
}

// LarkCallBackHandleFunc for Lark CallBack
func LarkCallBackHandleFunc(w http.ResponseWriter, r *http.Request) {
	usermgmt.LarkCallbackWithCode(w, r)
}

// CAS2CallBackHandleFunc for CAS2 CallBack
func CAS2CallBackHandleFunc(w http.ResponseWriter, r *http.Request) {
	usermgmt.CAS2CallbackWithCode(w, r)
}

// LDAPCallBackHandleFunc for LDAP CallBack
func LDAPCallBackHandleFunc(w http.ResponseWriter, r *http.Request) {
	usermgmt.LDAPAuthFunc(w, r)
}

// OAuthGetHandleFunc Get OAuth Information and Response
func OAuthGetHandleFunc(w http.ResponseWriter, r *http.Request) {
	obj, err := GetOAuthInfo()
	GenResponseByObject(w, obj, err)
}

// GetOAuthInfo Get OAuth Information
func GetOAuthInfo() (*OAuthInfo, error) {
	oauthInfo := OAuthInfo{}
	oauthInfo.AuthenticatorEnabled = data.PrimarySetting.AuthenticatorEnabled
	if !data.NodeSetting.AuthConfig.Enabled {
		return &oauthInfo, nil
	}
	switch data.NodeSetting.AuthConfig.Provider {
	case "wxwork":
		entranceURL := fmt.Sprintf("https://open.work.weixin.qq.com/wwopen/sso/qrConnect?appid=%s&agentid=%s&redirect_uri=%s&state=admin",
			data.NodeSetting.AuthConfig.Wxwork.CorpID,
			data.NodeSetting.AuthConfig.Wxwork.AgentID,
			data.NodeSetting.AuthConfig.Wxwork.Callback)
		oauthInfo.UseOAuth = true
		oauthInfo.DisplayName = data.NodeSetting.AuthConfig.Wxwork.DisplayName
		oauthInfo.EntranceURL = entranceURL
		return &oauthInfo, nil
	case "dingtalk":
		entranceURL := fmt.Sprintf("https://oapi.dingtalk.com/connect/qrconnect?appid=%s&response_type=code&scope=snsapi_login&state=admin&redirect_uri=%s",
			data.NodeSetting.AuthConfig.Dingtalk.AppID,
			data.NodeSetting.AuthConfig.Dingtalk.Callback)
		oauthInfo.UseOAuth = true
		oauthInfo.DisplayName = data.NodeSetting.AuthConfig.Dingtalk.DisplayName
		oauthInfo.EntranceURL = entranceURL
		return &oauthInfo, nil
	case "feishu":
		entranceURL := fmt.Sprintf("https://open.feishu.cn/open-apis/authen/v1/index?redirect_uri=%s&app_id=%s&state=admin",
			data.NodeSetting.AuthConfig.Feishu.Callback,
			data.NodeSetting.AuthConfig.Feishu.AppID)
		oauthInfo.UseOAuth = true
		oauthInfo.DisplayName = data.NodeSetting.AuthConfig.Feishu.DisplayName
		oauthInfo.EntranceURL = entranceURL
		return &oauthInfo, nil
	case "lark":
		entranceURL := fmt.Sprintf("https://open.larksuite.com/open-apis/authen/v1/index?redirect_uri=%s&app_id=%s&state=admin",
			data.NodeSetting.AuthConfig.Lark.Callback,
			data.NodeSetting.AuthConfig.Lark.AppID)
		oauthInfo.UseOAuth = true
		oauthInfo.DisplayName = data.NodeSetting.AuthConfig.Lark.DisplayName
		oauthInfo.EntranceURL = entranceURL
		return &oauthInfo, nil
	case "ldap":
		entranceURL := data.NodeSetting.AuthConfig.LDAP.Entrance + "?state=admin"
		oauthInfo.UseOAuth = true
		oauthInfo.DisplayName = data.NodeSetting.AuthConfig.LDAP.DisplayName
		oauthInfo.EntranceURL = entranceURL
		return &oauthInfo, nil
	case "cas2":
		entranceURL := fmt.Sprintf("%s/login?renew=true&service=%s?state=admin",
			data.NodeSetting.AuthConfig.CAS2.Entrance, data.NodeSetting.AuthConfig.CAS2.Callback)
		oauthInfo.UseOAuth = true
		oauthInfo.DisplayName = data.NodeSetting.AuthConfig.CAS2.DisplayName
		oauthInfo.EntranceURL = entranceURL
		return &oauthInfo, nil
	}
	oauthInfo.UseOAuth = false
	return &oauthInfo, nil // errors.New("No OAuth2 provider, you can enable it in config.json")
}
