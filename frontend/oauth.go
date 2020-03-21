/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2020-03-14 18:47:18
 * @Last Modified: U2, 2020-03-14 18:47:18
 */

package frontend

import (
	"fmt"
	"net/http"

	"github.com/Janusec/janusec/data"

	"github.com/Janusec/janusec/usermgmt"
)

type OAuthInfo struct {
	UseOAuth    bool   `json:"use_oauth"`
	DisplayName string `json:"display_name"`
	EntranceURL string `json:"entrance_url"`
}

func WxworkCallBackHandleFunc(w http.ResponseWriter, r *http.Request) {
	usermgmt.WxworkCallbackWithCode(w, r)
	http.Redirect(w, r, "/janusec-admin/", http.StatusFound)
}

func DingtalkCallBackHandleFunc(w http.ResponseWriter, r *http.Request) {
	usermgmt.DingtalkCallbackWithCode(w, r)
	http.Redirect(w, r, "/janusec-admin/", http.StatusFound)
}

func OAuthGetHandleFunc(w http.ResponseWriter, r *http.Request) {
	obj, err := GetOAuthInfo()
	GenResponseByObject(w, obj, err)
}

func GetOAuthInfo() (*OAuthInfo, error) {
	oauthInfo := OAuthInfo{}
	switch data.CFG.MasterNode.Admin.OAuth {
	case "wxwork":
		entranceURL := fmt.Sprintf("https://open.work.weixin.qq.com/wwopen/sso/qrConnect?appid=%s&agentid=%s&redirect_uri=%s&state=admin",
			data.CFG.MasterNode.Wxwork.CorpID,
			data.CFG.MasterNode.Wxwork.AgentID,
			data.CFG.MasterNode.Wxwork.Callback)
		oauthInfo.UseOAuth = true
		oauthInfo.DisplayName = data.CFG.MasterNode.Wxwork.DisplayName
		oauthInfo.EntranceURL = entranceURL
		return &oauthInfo, nil
	case "dingtalk":
		entranceURL := fmt.Sprintf("https://oapi.dingtalk.com/connect/qrconnect?appid=%s&response_type=code&scope=snsapi_login&state=admin&redirect_uri=%s",
			data.CFG.MasterNode.Dingtalk.AppID,
			data.CFG.MasterNode.Dingtalk.Callback)
		oauthInfo.UseOAuth = true
		oauthInfo.DisplayName = data.CFG.MasterNode.Dingtalk.DisplayName
		oauthInfo.EntranceURL = entranceURL
		return &oauthInfo, nil
	}
	oauthInfo.UseOAuth = false
	return &oauthInfo, nil // errors.New("No OAuth2 provider, you can enable it in config.json")
}
