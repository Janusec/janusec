/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2020-03-23 21:02:39
 * @Last Modified: U2, 2020-03-23 21:02:39
 */

package usermgmt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"janusec/utils"

	"janusec/data"
	"janusec/models"

	"github.com/gorilla/sessions"
	"github.com/patrickmn/go-cache"
)

type LarkAccessToken struct {
	Code           int64  `json:"code"`
	Msg            string `json:"msg"`
	AppAccessToken string `json:"app_access_token"`
	Expire         int    `json:"expire"`
}

// https://open.larksuite.com/document/ukTMukTMukTM/uEDO4UjLxgDO14SM4gTN
type LarkUserReqBody struct {
	AppAccessToken string `json:"app_access_token"`
	GrantType      string `json:"grant_type"`
	Code           string `json:"code"`
}

// https://open.larksuite.com/document/uMzMyEjLzMjMx4yMzITM/ukTN0EjL5UDNx4SO1QTM
type LarkUser struct {
	Code int64        `json:"code"`
	Msg  string       `json:"msg"`
	Data LarkAuthData `json:"data"`
}

type LarkAuthData struct {
	AccessToken string `json:"access_token"`
	EnName      string `json:"en_name"`
}

// Doc: https://open.larksuite.com/document/uMzMyEjLzMjMx4yMzITM/ugTN0EjL4UDNx4CO1QTM
// Step 1: GET https://open.larksuite.com/open-apis/authen/v1/index?redirect_uri={REDIRECT_URI}&app_id={APPID}&state={STATE}
// If state==admin, for janusec-admin; else for frontend applications
func LarkCallbackWithCode(w http.ResponseWriter, r *http.Request) {
	// Step 2.1: Callback with code and state, http://gate.janusec.com/?code=BM8k8U6RwtQtNY&state=admin
	code := r.FormValue("code")
	state := r.FormValue("state")
	// Step 2.2: Within Callback, get app_access_token
	// Doc: https://open.larksuite.com/document/uMzMyEjLzMjMx4yMzITM/uMjN0EjLzYDNx4yM2QTM
	// POST https://open.larksuite.com/open-apis/auth/v3/app_access_token/internal/
	// {"app_id":"cli_slkdasd", "app_secret":"dskLLdkasdKK"}
	// accessTokenURL := "https://open.larksuite.com/open-apis/auth/v3/app_access_token/internal/"
	body := fmt.Sprintf(`{"app_id":"%s", "app_secret":"%s"}`,
		data.NodeSetting.AuthConfig.Lark.AppID,
		data.NodeSetting.AuthConfig.Lark.AppSecret)
	request, _ := http.NewRequest("POST",
		"https://open.larksuite.com/open-apis/auth/v3/app_access_token/internal",
		bytes.NewReader([]byte(body)))
	resp, err := GetResponse(request)
	if err != nil {
		utils.DebugPrintln("LarkCallbackWithCode GetResponse", err)
	}
	tokenResponse := LarkAccessToken{}
	err = json.Unmarshal(resp, &tokenResponse)
	if err != nil {
		utils.DebugPrintln("LarkCallbackWithCode json.Unmarshal error", err)
	}
	// Step 2.3: Get User name
	// https://open.larksuite.com/document/uMzMyEjLzMjMx4yMzITM/ukTN0EjL5UDNx4SO1QTM
	userURL := "https://open.larksuite.com/open-apis/authen/v1/access_token"
	larkUserReqBody := LarkUserReqBody{
		AppAccessToken: tokenResponse.AppAccessToken,
		GrantType:      "authorization_code",
		Code:           code,
	}
	bytesData, err := json.Marshal(larkUserReqBody)
	if err != nil {
		utils.DebugPrintln("LarkCallbackWithCode json.Marshal", err)
	}
	request, err = http.NewRequest("POST", userURL, bytes.NewReader(bytesData))
	if err != nil {
		utils.DebugPrintln("LarkCallbackWithCode http.NewRequest", err)
	}
	request.Header.Set("Content-Type", "application/json")

	resp, err = GetResponse(request)
	if err != nil {
		utils.DebugPrintln("LarkCallbackWithCode GetResponse", err)
	}
	larkUser := LarkUser{}
	err = json.Unmarshal(resp, &larkUser)
	if err != nil {
		utils.DebugPrintln("LarkCallbackWithCode json.Unmarshal error", err)
	}
	if state == "admin" {
		// Insert into db if not existed
		id, err := data.DAL.InsertIfNotExistsAppUser(larkUser.Data.EnName, "", "", "", false, false, false, false)
		if err != nil {
			w.WriteHeader(403)
			w.Write([]byte("Error: " + err.Error()))
			return
		}
		// create session
		authUser := &models.AuthUser{
			UserID:        id,
			Username:      larkUser.Data.EnName,
			Logged:        true,
			IsSuperAdmin:  false,
			IsCertAdmin:   false,
			IsAppAdmin:    false,
			NeedModifyPWD: false}
		session, _ := store.Get(r, "sessionid")
		session.Values["authuser"] = authUser
		session.Options = &sessions.Options{Path: "/janusec-admin/", MaxAge: tokenResponse.Expire}
		err = session.Save(r, w)
		if err != nil {
			utils.DebugPrintln("LarkCallbackWithCode session save error", err)
		}
		RecordAuthLog(r, authUser.Username, "Lark", data.CFG.PrimaryNode.Admin.Portal)
		http.Redirect(w, r, data.CFG.PrimaryNode.Admin.Portal, http.StatusFound)
		return
	}
	// Gateway OAuth for employees and internal application
	oauthStateI, found := OAuthCache.Get(state)
	if found {
		oauthState := oauthStateI.(models.OAuthState)
		oauthState.UserID = larkUser.Data.EnName
		oauthState.AccessToken = larkUser.Data.AccessToken
		OAuthCache.Set(state, oauthState, cache.DefaultExpiration)
		RecordAuthLog(r, oauthState.UserID, "Lark", oauthState.CallbackURL)
		http.Redirect(w, r, oauthState.CallbackURL, http.StatusTemporaryRedirect)
		return
	}
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}
