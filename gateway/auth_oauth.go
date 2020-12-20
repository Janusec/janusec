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

type OAuthInfo struct {
	UseOAuth    bool   `json:"use_oauth"`
	DisplayName string `json:"display_name"`
	EntranceURL string `json:"entrance_url"`
}

func WxworkCallBackHandleFunc(w http.ResponseWriter, r *http.Request) {
	usermgmt.WxworkCallbackWithCode(w, r)
}

func DingtalkCallBackHandleFunc(w http.ResponseWriter, r *http.Request) {
	usermgmt.DingtalkCallbackWithCode(w, r)
}

func FeishuCallBackHandleFunc(w http.ResponseWriter, r *http.Request) {
	usermgmt.FeishuCallbackWithCode(w, r)
}

func CAS2CallBackHandleFunc(w http.ResponseWriter, r *http.Request) {
	usermgmt.CAS2CallbackWithCode(w, r)
}

func LDAPCallBackHandleFunc(w http.ResponseWriter, r *http.Request) {
	usermgmt.LDAPAuthFunc(w, r)
}

func OAuthGetHandleFunc(w http.ResponseWriter, r *http.Request) {
	obj, err := GetOAuthInfo()
	GenResponseByObject(w, obj, err)
}

func GetOAuthInfo() (*OAuthInfo, error) {
	oauthInfo := OAuthInfo{}
	if data.CFG.PrimaryNode.OAuth.Enabled == false {
		return &oauthInfo, nil
	}
	switch data.CFG.PrimaryNode.OAuth.Provider {
	case "wxwork":
		entranceURL := fmt.Sprintf("https://open.work.weixin.qq.com/wwopen/sso/qrConnect?appid=%s&agentid=%s&redirect_uri=%s&state=admin",
			data.CFG.PrimaryNode.OAuth.Wxwork.CorpID,
			data.CFG.PrimaryNode.OAuth.Wxwork.AgentID,
			data.CFG.PrimaryNode.OAuth.Wxwork.Callback)
		oauthInfo.UseOAuth = true
		oauthInfo.DisplayName = data.CFG.PrimaryNode.OAuth.Wxwork.DisplayName
		oauthInfo.EntranceURL = entranceURL
		return &oauthInfo, nil
	case "dingtalk":
		entranceURL := fmt.Sprintf("https://oapi.dingtalk.com/connect/qrconnect?appid=%s&response_type=code&scope=snsapi_login&state=admin&redirect_uri=%s",
			data.CFG.PrimaryNode.OAuth.Dingtalk.AppID,
			data.CFG.PrimaryNode.OAuth.Dingtalk.Callback)
		oauthInfo.UseOAuth = true
		oauthInfo.DisplayName = data.CFG.PrimaryNode.OAuth.Dingtalk.DisplayName
		oauthInfo.EntranceURL = entranceURL
		return &oauthInfo, nil
	case "feishu":
		entranceURL := fmt.Sprintf("https://open.feishu.cn/open-apis/authen/v1/index?redirect_uri=%s&app_id=%s&state=admin",
			data.CFG.PrimaryNode.OAuth.Feishu.Callback,
			data.CFG.PrimaryNode.OAuth.Feishu.AppID)
		oauthInfo.UseOAuth = true
		oauthInfo.DisplayName = data.CFG.PrimaryNode.OAuth.Feishu.DisplayName
		oauthInfo.EntranceURL = entranceURL
		return &oauthInfo, nil
	case "ldap":
		entranceURL := data.CFG.PrimaryNode.OAuth.LDAP.Entrance + "?state=admin"
		oauthInfo.UseOAuth = true
		oauthInfo.DisplayName = data.CFG.PrimaryNode.OAuth.LDAP.DisplayName
		oauthInfo.EntranceURL = entranceURL
		return &oauthInfo, nil
	case "cas2":
		entranceURL := fmt.Sprintf("%s/login?renew=true&service=%s?state=admin",
			data.CFG.PrimaryNode.OAuth.CAS2.Entrance, data.CFG.PrimaryNode.OAuth.CAS2.Callback)
		oauthInfo.UseOAuth = true
		oauthInfo.DisplayName = data.CFG.PrimaryNode.OAuth.CAS2.DisplayName
		oauthInfo.EntranceURL = entranceURL
		return &oauthInfo, nil
	}
	oauthInfo.UseOAuth = false
	return &oauthInfo, nil // errors.New("No OAuth2 provider, you can enable it in config.json")
}
