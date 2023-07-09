/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2020-03-14 09:58:15
 * @Last Modified: U2, 2020-03-14 09:58:15
 */

package usermgmt

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"janusec/data"
	"janusec/models"
	"janusec/utils"

	"github.com/gorilla/sessions"

	"github.com/patrickmn/go-cache"
)

var (
	OAuthCache = cache.New(5*time.Minute, 5*time.Minute)
)

type WxworkAccessToken struct {
	ErrCode     int64  `json:"errcode"`
	ErrMsg      string `json:"errmsg"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

type WxworkUser struct {
	ErrCode int64  `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
	UserID  string `json:"UserId"`
}

// https://work.weixin.qq.com/api/doc/90000/90135/91025
// Step 1: To https://open.work.weixin.qq.com/wwopen/sso/qrConnect?appid=CORPID&agentid=AGENTID&redirect_uri=REDIRECT_URI&state=admin
// If state==admin, for janusec-admin; else for frontend applications
func WxworkCallbackWithCode(w http.ResponseWriter, r *http.Request) {
	// Step 2.1: Callback with code, http://gate.janusec.com/?code=BM8k8U6RwtQtNY&state=admin&appid=wwd03ba1f8
	code := r.FormValue("code")
	state := r.FormValue("state")
	// Step 2.2: Within Callback, get access_token
	// https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=wwd03ba1f8&corpsecret=NdZI
	// Response format: https://work.weixin.qq.com/api/doc/90000/90135/91039
	accessTokenURL := fmt.Sprintf("https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=%s&corpsecret=%s",
		data.NodeSetting.AuthConfig.Wxwork.CorpID, data.NodeSetting.AuthConfig.Wxwork.CorpSecret)
	request, _ := http.NewRequest("GET", accessTokenURL, nil)
	resp, err := utils.GetResponse(request)
	if err != nil {
		utils.DebugPrintln("WxworkCallbackWithCode GetResponse", err)
	}
	tokenResponse := WxworkAccessToken{}
	err = json.Unmarshal(resp, &tokenResponse)
	if err != nil {
		utils.DebugPrintln("WxworkCallbackWithCode json.Unmarshal error", err)
	}
	// Step 2.3: Get UserID, https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo?access_token=ACCESS_TOKEN&code=CODE
	userURL := fmt.Sprintf("https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo?access_token=%s&code=%s", tokenResponse.AccessToken, code)
	request, _ = http.NewRequest("GET", userURL, nil)
	resp, err = utils.GetResponse(request)
	if err != nil {
		utils.DebugPrintln("WxworkCallbackWithCode GetResponse", err)
	}
	wxworkUser := WxworkUser{}
	err = json.Unmarshal(resp, &wxworkUser)
	if err != nil {
		utils.DebugPrintln("WxworkCallbackWithCode json.Unmarshal error", err)
	}
	if state == "admin" {
		appUser := data.DAL.SelectAppUserByName(wxworkUser.UserID)
		var userID int64
		if appUser == nil {
			// Insert into db if not existed
			userID, err = data.DAL.InsertIfNotExistsAppUser(wxworkUser.UserID, "", "", "", false, false, false, false)
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
			Username:      wxworkUser.UserID,
			Logged:        true,
			IsSuperAdmin:  appUser.IsSuperAdmin,
			IsCertAdmin:   appUser.IsCertAdmin,
			IsAppAdmin:    appUser.IsAppAdmin,
			NeedModifyPWD: false}
		session, _ := store.Get(r, "sessionid")
		session.Values["authuser"] = authUser
		session.Options = &sessions.Options{Path: "/janusec-admin/", MaxAge: tokenResponse.ExpiresIn}
		err = session.Save(r, w)
		if err != nil {
			utils.DebugPrintln("WxworkCallbackWithCode session save error", err)
		}
		RecordAuthLog(r, authUser.Username, "WxWork", data.CFG.PrimaryNode.Admin.Portal)
		http.Redirect(w, r, data.CFG.PrimaryNode.Admin.Portal, http.StatusTemporaryRedirect)
		return
	}
	// Gateway OAuth for employees and internal application
	oauthStateI, found := OAuthCache.Get(state)
	if found {
		oauthState := oauthStateI.(models.OAuthState)
		oauthState.UserID = wxworkUser.UserID
		oauthState.AccessToken = tokenResponse.AccessToken
		OAuthCache.Set(state, oauthState, cache.DefaultExpiration)
		RecordAuthLog(r, oauthState.UserID, "WxWork", oauthState.CallbackURL)
		//fmt.Println("307 to:", oauthState.CallbackURL)
		http.Redirect(w, r, oauthState.CallbackURL, http.StatusTemporaryRedirect)
		return
	}
	//fmt.Println("Time expired")
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}
