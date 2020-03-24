/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2020-03-21 19:14:44
 * @Last Modified: U2, 2020-03-21 19:14:44
 */

package usermgmt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/Janusec/janusec/data"
	"github.com/Janusec/janusec/models"
	"github.com/gorilla/sessions"
	"github.com/patrickmn/go-cache"
)

type DingtalkResponse struct {
	ErrCode  int64            `json:"errcode"`
	ErrMsg   string           `json:"errmsg"`
	UserInfo DingtalkUserInfo `json:"user_info"`
}

type DingtalkUserInfo struct {
	Nick    string `json:"nick"`
	OpenID  string `json:"openid"`
	UnionID string `json:"unionid"`
}

func GetSignature(msg []byte, key []byte) string {
	hmac := hmac.New(sha256.New, key)
	hmac.Write(msg)
	digest := hmac.Sum(nil)
	return url.QueryEscape(base64.StdEncoding.EncodeToString(digest))
}

// https://ding-doc.dingtalk.com/doc#/serverapi3/mrugr3
// Step 1: To https://oapi.dingtalk.com/connect/qrconnect?appid=APPID&response_type=code&scope=snsapi_login&state=STATE&redirect_uri=REDIRECT_URI
// If state==admin, for janusec-admin; else for frontend applications
func DingtalkCallbackWithCode(w http.ResponseWriter, r *http.Request) (*models.AuthUser, error) {
	// Step 2.1: Callback with code, https://gate.janusec.com/janusec-admin/oauth/dingtalk?code=BM8k8U6RwtQtNY&state=admin
	code := r.FormValue("code")
	state := r.FormValue("state")
	// Step 2.2: Within Callback, get user_info.nick
	// POST HTTPS with body { "tmp_auth_code": "23152698ea18304da4d0ce1xxxxx" }  == code ?
	// https://oapi.dingtalk.com/sns/getuserinfo_bycode?accessKey=xxx&timestamp=xxx&signature=xxx
	// accessKey=appid
	// https://ding-doc.dingtalk.com/doc#/serverapi2/kymkv6
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	signature := GetSignature([]byte(timestamp), []byte(data.CFG.MasterNode.OAuth.Dingtalk.AppSecret))
	accessTokenURL := fmt.Sprintf("https://oapi.dingtalk.com/sns/getuserinfo_bycode?accessKey=%s&timestamp=%s&signature=%s",
		data.CFG.MasterNode.OAuth.Dingtalk.AppID,
		timestamp,
		signature)

	body := fmt.Sprintf(`{"tmp_auth_code": "%s"}`, code)
	request, _ := http.NewRequest("POST", accessTokenURL, bytes.NewReader([]byte(body)))
	resp, _ := GetResponse(request)
	dingtalkResponse := DingtalkResponse{}
	json.Unmarshal(resp, &dingtalkResponse)
	dingtalkUser := dingtalkResponse.UserInfo
	if state == "admin" {
		// Insert into db if not existed
		id, _ := data.DAL.InsertIfNotExistsAppUser(dingtalkUser.Nick, "", "", "", false, false, false, false)
		// create session
		authUser := &models.AuthUser{
			UserID:        id,
			Username:      dingtalkUser.Nick,
			Logged:        true,
			IsSuperAdmin:  false,
			IsCertAdmin:   false,
			IsAppAdmin:    false,
			NeedModifyPWD: false}
		session, _ := store.Get(r, "sessionid")
		session.Values["authuser"] = authUser
		session.Options = &sessions.Options{Path: "/janusec-admin/", MaxAge: 86400}
		session.Save(r, w)
		return authUser, nil
	}
	// Gateway OAuth for employees and internal application
	oauthStateI, found := OAuthCache.Get(state)
	if found {
		oauthState := oauthStateI.(models.OAuthState)
		oauthState.UserID = dingtalkUser.Nick
		oauthState.AccessToken = "N/A"
		OAuthCache.Set(state, oauthState, cache.DefaultExpiration)
		//fmt.Println("1008 set cache state=", oauthState, "307 to:", oauthState.CallbackURL)
		http.Redirect(w, r, oauthState.CallbackURL, http.StatusTemporaryRedirect)
		return nil, nil
	}
	//fmt.Println("1009 Time expired")
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	return nil, nil
}
