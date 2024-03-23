/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2020-03-21 19:14:44
 * @Last Modified: U2, 2020-03-21 19:14:44
 */

package usermgmt

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"janusec/data"
	"janusec/models"
	"janusec/utils"

	"github.com/gorilla/sessions"
	"github.com/patrickmn/go-cache"
)

// DingtalkResponse V1
/*
type DingtalkResponseV1 struct {
	ErrCode  int64            `json:"errcode"`
	ErrMsg   string           `json:"errmsg"`
	UserInfo DingtalkUserInfo `json:"user_info"`
}
*/

// DingtalkUserInfo V1 & V2
// Doc: https://open.dingtalk.com/document/orgapp/dingtalk-retrieve-user-information
type DingtalkUserInfo struct {
	Nick    string `json:"nick"`
	OpenID  string `json:"openid"`
	UnionID string `json:"unionid"`
}

/*
// GetSignature for API v1
func GetSignature(msg []byte, key []byte) string {
	hmac := hmac.New(sha256.New, key)
	_, err := hmac.Write(msg)
	if err != nil {
		utils.DebugPrintln("GetSignature hmac.Write error", err)
	}
	digest := hmac.Sum(nil)
	return url.QueryEscape(base64.StdEncoding.EncodeToString(digest))
}
*/

// AccessToken Response V2, added on Mar 23, 2024
// Doc: https://open.dingtalk.com/document/orgapp/obtain-user-token#h2-hxj-mpf-5bd
type AccessTokenResp struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpireIn     int64  `json:"expireIn"`
	CorpId       string `json:"corpId"`
}

// This is the API v1, instead by v2
// https://ding-doc.dingtalk.com/doc#/serverapi3/mrugr3
// Step 1: To https://oapi.dingtalk.com/connect/qrconnect?appid=APPID&response_type=code&scope=snsapi_login&state=STATE&redirect_uri=REDIRECT_URI
// If state==admin, for janusec-admin; else for frontend applications
/*
func DingtalkCallbackWithCodeV1(w http.ResponseWriter, r *http.Request) {
	// Step 2.1: Callback with code, https://gate.janusec.com/janusec-admin/oauth/dingtalk?code=BM8k8U6RwtQtNY&state=admin
	code := r.FormValue("code")
	state := r.FormValue("state")
	// Step 2.2: Within Callback, get user_info.nick
	// POST HTTPS with body { "tmp_auth_code": "23152698ea18304da4d0ce1xxxxx" }  == code ?
	// https://oapi.dingtalk.com/sns/getuserinfo_bycode?accessKey=xxx&timestamp=xxx&signature=xxx
	// accessKey=appid
	// https://ding-doc.dingtalk.com/doc#/serverapi2/kymkv6
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	signature := GetSignature([]byte(timestamp), []byte(data.NodeSetting.AuthConfig.Dingtalk.AppSecret))
	accessTokenURL := fmt.Sprintf("https://oapi.dingtalk.com/sns/getuserinfo_bycode?accessKey=%s&timestamp=%s&signature=%s",
		data.NodeSetting.AuthConfig.Dingtalk.AppID,
		timestamp,
		signature)

	body := fmt.Sprintf(`{"tmp_auth_code": "%s"}`, code)
	request, _ := http.NewRequest("POST", accessTokenURL, bytes.NewReader([]byte(body)))
	request.Header.Set("Content-Type", "application/json")
	resp, err := utils.GetResponse(request)
	if err != nil {
		utils.DebugPrintln("DingtalkCallbackWithCode GetResponse", err)
	}
	dingtalkResponse := DingtalkResponse{}
	err = json.Unmarshal(resp, &dingtalkResponse)
	if err != nil {
		utils.DebugPrintln("DingtalkCallbackWithCode json.Unmarshal error", err)
	}
	dingtalkUser := dingtalkResponse.UserInfo
	if state == "admin" {
		appUser := data.DAL.SelectAppUserByName(dingtalkUser.Nick)
		var userID int64
		if appUser == nil {
			// Insert into db if not existed
			userID, err = data.DAL.InsertIfNotExistsAppUser(dingtalkUser.Nick, "", "", "", false, false, false, false)
			if err != nil {
				w.WriteHeader(403)
				w.Write([]byte("Error: " + err.Error()))
				return
			}
		} else {
			userID = appUser.ID
		}
		// create session
		authUser := &models.AuthUser{
			UserID:        userID,
			Username:      dingtalkUser.Nick,
			Logged:        true,
			IsSuperAdmin:  appUser.IsSuperAdmin,
			IsCertAdmin:   appUser.IsCertAdmin,
			IsAppAdmin:    appUser.IsAppAdmin,
			NeedModifyPWD: false}
		session, _ := store.Get(r, "sessionid")
		session.Values["authuser"] = authUser
		session.Options = &sessions.Options{Path: "/janusec-admin/", MaxAge: 86400}
		err = session.Save(r, w)
		if err != nil {
			utils.DebugPrintln("DingtalkCallbackWithCode session save error", err)
		}
		RecordAuthLog(r, authUser.Username, "DingTalk", data.CFG.PrimaryNode.Admin.Portal)
		http.Redirect(w, r, data.CFG.PrimaryNode.Admin.Portal, http.StatusTemporaryRedirect)
		return
	}
	// Gateway OAuth for employees and internal application
	oauthStateI, found := OAuthCache.Get(state)
	if found {
		oauthState := oauthStateI.(models.OAuthState)
		oauthState.UserID = dingtalkUser.Nick
		oauthState.AccessToken = "N/A"
		OAuthCache.Set(state, oauthState, cache.DefaultExpiration)
		RecordAuthLog(r, oauthState.UserID, "DingTalk", oauthState.CallbackURL)
		http.Redirect(w, r, oauthState.CallbackURL, http.StatusTemporaryRedirect)
		return
	}
	//fmt.Println("Time expired")
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}
*/

// This is the API v2, added on Mar 23, 2024
// Doc: https://open.dingtalk.com/document/orgapp/tutorial-obtaining-user-personal-information
// Step 1: https://login.dingtalk.com/oauth2/auth?redirect_uri=https://.../oauth/dingtalk&response_type=code&client_id=...&scope=openid&state=...&prompt=consent
// If state==admin, for janusec-admin; else for frontend applications
func DingtalkCallbackWithCode(w http.ResponseWriter, r *http.Request) {
	// Step 2.1: Callback with code, GET
	// https://test.janusec.com/oauth/dingtalk?authCode=18025489140734ecb0ccf637ee5439f9&state=...
	authCode := r.FormValue("authCode")
	state := r.FormValue("state")
	// Step 2.2: Within Callback, acquire token
	// Doc: https://open.dingtalk.com/document/orgapp/obtain-user-token
	// POST https://api.dingtalk.com/v1.0/oauth2/userAccessToken
	// body { "clientId": "...AppKey", "clientSecret": "...AppSecret", "code": "...authCode", "grantType": "authorization_code"}
	accessTokenURL := `https://api.dingtalk.com/v1.0/oauth2/userAccessToken`
	body := fmt.Sprintf(`{"clientId":"%s","clientSecret":"%s","code":"%s","grantType": "authorization_code"}`,
		data.NodeSetting.AuthConfig.Dingtalk.AppID,
		data.NodeSetting.AuthConfig.Dingtalk.AppSecret,
		authCode)
	request, _ := http.NewRequest("POST", accessTokenURL, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	resp, err := utils.GetResponse(request)
	if err != nil {
		utils.DebugPrintln("DingtalkCallbackWithCode GetResponse accessToken", err)
	}
	accessTokenResp := AccessTokenResp{}
	err = json.Unmarshal(resp, &accessTokenResp)
	if err != nil {
		utils.DebugPrintln("DingtalkCallbackWithCode json.Unmarshal AccessTokenResp error", err)
	}
	// check wether the corpid is valid
	if accessTokenResp.CorpId != data.NodeSetting.AuthConfig.Dingtalk.CorpID {
		w.WriteHeader(403)
		w.Write([]byte("Error: You are not a member of the corporation now!"))
		return
	}

	// Step 2.3: Get UserInfo
	// Doc: https://open.dingtalk.com/document/orgapp/dingtalk-retrieve-user-information
	// GET  https://api.dingtalk.com/v1.0/contact/users/{unionId}
	// Header x-acs-dingtalk-access-token:String
	request, _ = http.NewRequest("GET", `https://api.dingtalk.com/v1.0/contact/users/me`, nil)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("x-acs-dingtalk-access-token", accessTokenResp.AccessToken)
	resp, err = utils.GetResponse(request)
	if err != nil {
		utils.DebugPrintln("DingtalkCallbackWithCode GetResponse userinfo", err)
	}
	dingtalkUser := DingtalkUserInfo{}
	err = json.Unmarshal(resp, &dingtalkUser)
	if err != nil {
		utils.DebugPrintln("DingtalkCallbackWithCode json.Unmarshal userinfo error", err)
	}
	if state == "admin" {
		appUser := data.DAL.SelectAppUserByName(dingtalkUser.Nick)
		var userID int64
		if appUser == nil {
			// Insert into db if not existed
			userID, err = data.DAL.InsertIfNotExistsAppUser(dingtalkUser.Nick, "", "", "", false, false, false, false)
			if err != nil {
				w.WriteHeader(403)
				w.Write([]byte("Error: " + err.Error()))
				return
			}
		} else {
			userID = appUser.ID
		}
		// create session
		authUser := &models.AuthUser{
			UserID:        userID,
			Username:      dingtalkUser.Nick,
			Logged:        true,
			IsSuperAdmin:  appUser.IsSuperAdmin,
			IsCertAdmin:   appUser.IsCertAdmin,
			IsAppAdmin:    appUser.IsAppAdmin,
			NeedModifyPWD: false}
		session, _ := store.Get(r, "sessionid")
		session.Values["authuser"] = authUser
		session.Options = &sessions.Options{Path: "/janusec-admin/", MaxAge: 86400}
		err = session.Save(r, w)
		if err != nil {
			utils.DebugPrintln("DingtalkCallbackWithCode session save error", err)
		}
		RecordAuthLog(r, authUser.Username, "DingTalk", data.CFG.PrimaryNode.Admin.Portal)
		http.Redirect(w, r, data.CFG.PrimaryNode.Admin.Portal, http.StatusTemporaryRedirect)
		return
	}
	// Gateway OAuth for employees and internal application
	oauthStateI, found := OAuthCache.Get(state)
	if found {
		oauthState := oauthStateI.(models.OAuthState)
		oauthState.UserID = dingtalkUser.Nick
		oauthState.AccessToken = "N/A"
		OAuthCache.Set(state, oauthState, cache.DefaultExpiration)
		RecordAuthLog(r, oauthState.UserID, "DingTalk", oauthState.CallbackURL)
		http.Redirect(w, r, oauthState.CallbackURL, http.StatusTemporaryRedirect)
		return
	}
	//fmt.Println("Time expired")
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}
