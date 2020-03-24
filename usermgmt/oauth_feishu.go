/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2020-03-23 21:02:39
 * @Last Modified: U2, 2020-03-23 21:02:39
 */

package usermgmt

/*
import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Janusec/janusec/data"
	"github.com/Janusec/janusec/models"
	"github.com/gorilla/sessions"
	"github.com/patrickmn/go-cache"
)

type FeishuAccessToken struct {
	Code           int64  `json:"code"`
	Msg            string `json:"msg"`
	AppAccessToken string `json:"app_access_token"`
	Expire         int    `json:"expire"`
}

// https://open.feishu.cn/document/ukTMukTMukTM/uEDO4UjLxgDO14SM4gTN
type FeishuUserReqBody struct {
	AppAccessToken string `json:"app_access_token"`
	GrantType      string `json:"grant_type"`
	Code           string `json:"code"`
}

// https://open.feishu.cn/document/ukTMukTMukTM/uEDO4UjLxgDO14SM4gTN
type FeishuUser struct {
	Code int64          `json:"code"`
	Msg  string         `json:"msg"`
	Data FeishuAuthData `json:"data"`
}

type FeishuAuthData struct {
	AccessToken string `json:"access_token"`
	Name        string `json:"name"`
}
*/

/*
// Doc: https://open.feishu.cn/document/ukTMukTMukTM/ukzN4UjL5cDO14SO3gTN
// Step 1: GET https://open.feishu.cn/open-apis/authen/v1/index?redirect_uri={REDIRECT_URI}&app_id={APPID}&state={STATE}
// If state==admin, for janusec-admin; else for frontend applications
func FeishuCallbackWithCode(w http.ResponseWriter, r *http.Request) (*models.AuthUser, error) {
	// Step 2.1: Callback with code and state, http://gate.janusec.com/?code=BM8k8U6RwtQtNY&state=admin
	code := r.FormValue("code")
	state := r.FormValue("state")
	// Step 2.2: Within Callback, get app_access_token
	// Doc: https://open.feishu.cn/document/ukTMukTMukTM/uADN14CM0UjLwQTN
	// POST https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal/
	// {"app_id":"cli_slkdjalasdkjasd", "app_secret":"dskLLdkasdjlasdKK"}
	accessTokenURL := "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal/"
	body := fmt.Sprintf(`{"app_id":"%s", "app_secret":"%s"}`,
		data.CFG.MasterNode.OAuth.Feishu.AppID,
		data.CFG.MasterNode.OAuth.Feishu.AppSecret)
	request, _ := http.NewRequest("POST", accessTokenURL, bytes.NewReader([]byte(body)))
	resp, _ := GetResponse(request)
	tokenResponse := FeishuAccessToken{}
	json.Unmarshal(resp, &tokenResponse)
	fmt.Println("3001 Feishu body", body, "tokenResponse", tokenResponse)
	// Step 2.3: Get User name
	// https://open.feishu.cn/document/ukTMukTMukTM/uEDO4UjLxgDO14SM4gTN
	userURL := "https://open.feishu.cn/open-apis/authen/v1/access_token"
	feishuUserReqBody := FeishuUserReqBody{
		AppAccessToken: tokenResponse.AppAccessToken,
		GrantType:      "authorization_code",
		Code:           code,
	}
	bytesData, _ := json.Marshal(feishuUserReqBody)
	request, _ = http.NewRequest("POST", userURL, bytes.NewReader([]byte(bytesData)))
	resp, _ = GetResponse(request)
	feishuUser := FeishuUser{}
	json.Unmarshal(resp, &feishuUser)
	fmt.Println("3002 Feishu body", string(bytesData), "feishuUser", feishuUser)
	if state == "admin" {
		// Insert into db if not existed
		id, _ := data.DAL.InsertIfNotExistsAppUser(feishuUser.Data.Name, "", "", "", false, false, false, false)
		// create session
		authUser := &models.AuthUser{
			UserID:        id,
			Username:      feishuUser.Data.Name,
			Logged:        true,
			IsSuperAdmin:  false,
			IsCertAdmin:   false,
			IsAppAdmin:    false,
			NeedModifyPWD: false}
		session, _ := store.Get(r, "sessionid")
		session.Values["authuser"] = authUser
		session.Options = &sessions.Options{Path: "/janusec-admin/", MaxAge: tokenResponse.Expire}
		session.Save(r, w)
		return authUser, nil
	}
	// Gateway OAuth for employees and internal application
	oauthStateI, found := OAuthCache.Get(state)
	if found {
		oauthState := oauthStateI.(models.OAuthState)
		oauthState.UserID = feishuUser.Data.Name
		oauthState.AccessToken = feishuUser.Data.AccessToken
		OAuthCache.Set(state, oauthState, cache.DefaultExpiration)
		fmt.Println("1008 set cache state=", oauthState, "307 to:", oauthState.CallbackURL)
		http.Redirect(w, r, oauthState.CallbackURL, http.StatusTemporaryRedirect)
		return nil, nil
	}
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	return nil, nil
}
*/
