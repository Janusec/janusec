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
	"io/ioutil"
	"net/http"

	"github.com/Janusec/janusec/data"
	"github.com/Janusec/janusec/models"
	"github.com/gorilla/sessions"

	"github.com/Janusec/iknow/common"
	"github.com/Janusec/janusec/utils"
)

/*
type WxworkRequest struct {
	CorpID     string `json:"corpid"`
	CorpSecret string `json:"corpsecret"`
	//Code         string `json:"code"`
}
*/

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
// Step 1: To https://open.work.weixin.qq.com/wwopen/sso/qrConnect?appid=CORPID&agentid=AGENTID&redirect_uri=REDIRECT_URI&state=STATE
func CallbackWithCode(w http.ResponseWriter, r *http.Request) (*models.AuthUser, error) {
	// Step 2.1: Callback with code, http://gate.janusec.com/?code=BM8k8U6RwtQtNY&state=janusec&appid=wwd03ba1f8
	code := r.FormValue("code")
	utils.DebugPrintln("CallbackWithCode", code)
	// Step 2.2: Within Callback, get access_token
	// https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=wwd03ba1f8&corpsecret=NdZI
	// Response format: https://work.weixin.qq.com/api/doc/90000/90135/91039
	accessTokenURL := fmt.Sprintf("https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=%s&corpsecret=%s",
		data.CFG.MasterNode.Wxwork.CorpID, data.CFG.MasterNode.Wxwork.CorpSecret)
	request, err := http.NewRequest("GET", accessTokenURL, nil)
	resp, err := GetResponse(request)
	utils.DebugPrintln("CallbackWithCode Get Access Token", err)
	tokenResponse := WxworkAccessToken{}
	err = json.Unmarshal(resp, &tokenResponse)
	utils.DebugPrintln("CallbackWithCode Parse Access Token", err)
	// Step 2.3: Get UserID, https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo?access_token=ACCESS_TOKEN&code=CODE
	userURL := fmt.Sprintf("https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo?access_token=%s&code=%s", tokenResponse.AccessToken, code)
	request, err = http.NewRequest("GET", userURL, nil)
	resp, err = GetResponse(request)
	wxworkUser := WxworkUser{}
	json.Unmarshal(resp, &wxworkUser)
	utils.DebugPrintln("CallbackWithCode Get UserID", wxworkUser.UserID)
	// Insert into db if not existed
	id, err := data.DAL.InsertIfNotExistsAppUser(wxworkUser.UserID, "", "", "", false, false, false, false)
	// create session
	session, _ := store.Get(r, "sessionid")
	session.Values["username"] = wxworkUser.UserID
	session.Values["user_id"] = id
	session.Values["need_modify_pwd"] = false
	session.Options = &sessions.Options{Path: "/janusec-admin/", MaxAge: tokenResponse.ExpiresIn}
	session.Save(r, w)
	authUser := &models.AuthUser{Username: wxworkUser.UserID, Logged: true, NeedModifyPWD: false}
	return authUser, nil
}

func GetResponse(request *http.Request) (respBytes []byte, err error) {
	request.Header.Set("Accept", "application/json")
	client := http.Client{}
	resp, err := client.Do(request)
	common.CheckError("GetResponse Do", err)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBytes, err = ioutil.ReadAll(resp.Body)
	return respBytes, err
}

/*
func OAuth2Demo(ctx *gin.Context) {
	// This is a demo instead of Github
	ctx.Redirect(http.StatusFound, "/oauth2/callback/github?code=a9fe4d0d42cfbd2ba1d8")
}
*/
