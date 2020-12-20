/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2020-12-20 14:37:39
 * @Last Modified: U2, 2020-12-20 14:37:39
 */

package usermgmt

import (
	"encoding/xml"
	"fmt"
	"janusec/data"
	"janusec/models"
	"janusec/utils"
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/patrickmn/go-cache"
)

// CASServiceResponse is the validation response from CAS Server
type CASServiceResponse struct {
	XMLName               xml.Name              `xml:"http://www.yale.edu/tp/cas serviceResponse"`
	AuthenticationSuccess AuthenticationSuccess `xml:"http://www.yale.edu/tp/cas authenticationSuccess"`
}

// AuthenticationSuccess ...
type AuthenticationSuccess struct {
	CASUser string `xml:"http://www.yale.edu/tp/cas user"`
}

// CAS2CallbackWithCode Doc: https://apereo.github.io/cas/5.3.x/protocol/CAS-Protocol-V2-Specification.html
// Step 1: GET http://192.168.100.109:8080/cas/login?service=http://xxx.xxx.xxx/oauth/cas2?state=admin
// For janusec-admin, state=admin. For applications, state!=admin
func CAS2CallbackWithCode(w http.ResponseWriter, r *http.Request) {
	// Step 2.1: Callback with ticket, http://xxx.xxx.xxx/oauth/cas2?state=admin&ticket=ST-1-1uYs7tNVYUEjpyJOHwLTZ6Cxv0ICentOS8X
	state := r.FormValue("state")
	ticket := r.FormValue("ticket")
	// Step 2.2 validate: http://192.168.100.109:8080/cas/serviceValidate?service=http://iknow.janusec.com&ticket=ST-1-1uYs7tNVYUEjpyJOHwLTZ6Cxv0ICentOS8X
	validateURL := fmt.Sprintf("%s/serviceValidate?service=%s?state=%s&ticket=%s", data.CFG.PrimaryNode.OAuth.CAS2.Entrance, data.CFG.PrimaryNode.OAuth.CAS2.Callback, state, ticket)
	request, _ := http.NewRequest("GET", validateURL, nil)
	resp, err := GetResponse(request)
	if err != nil {
		utils.DebugPrintln("CAS2CallbackWithCode GetResponse", err)
	}
	var casServiceResponse CASServiceResponse
	err = xml.Unmarshal(resp, &casServiceResponse)
	if err != nil {
		w.WriteHeader(403)
		w.Write([]byte("Error: " + err.Error()))
		return
	}
	/*
		<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
		    <cas:authenticationSuccess>
		        <cas:user>casuser</cas:user>
		    </cas:authenticationSuccess>
		</cas:serviceResponse>
	*/
	/*
		<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
			<cas:authenticationFailure code="INVALID_SERVICE">
			Ticket &#39;ST-9-eHr4cRTrh8APWt...;.
			</cas:authenticationFailure>
		</cas:serviceResponse>
	*/
	casUser := casServiceResponse.AuthenticationSuccess.CASUser

	if state == "admin" {
		// To do: for janusec-admin
		// Insert into db if not existed
		id, err := data.DAL.InsertIfNotExistsAppUser(casUser, "", "", "", false, false, false, false)
		if err != nil {
			w.WriteHeader(403)
			w.Write([]byte("Error: " + err.Error()))
			return
		}
		// create session
		authUser := &models.AuthUser{
			UserID:        id,
			Username:      casUser,
			Logged:        true,
			IsSuperAdmin:  false,
			IsCertAdmin:   false,
			IsAppAdmin:    false,
			NeedModifyPWD: false}
		session, _ := store.Get(r, "sessionid")
		session.Values["authuser"] = authUser
		session.Options = &sessions.Options{Path: "/janusec-admin/", MaxAge: 86400}
		err = session.Save(r, w)
		if err != nil {
			utils.DebugPrintln("CAS2CallbackWithCode session save error", err)
		}
		http.Redirect(w, r, data.CFG.PrimaryNode.Admin.Portal, http.StatusFound)
		return

	} else {
		// for applications
		oauthStateI, found := OAuthCache.Get(state)
		if found {
			oauthState := oauthStateI.(models.OAuthState)
			oauthState.UserID = casUser
			OAuthCache.Set(state, oauthState, cache.DefaultExpiration)
			//fmt.Println("1008 set cache state=", oauthState, "307 to:", oauthState.CallbackURL)
			http.Redirect(w, r, oauthState.CallbackURL, http.StatusTemporaryRedirect)
			return
		}
		//fmt.Println("1009 Time expired")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}

}
