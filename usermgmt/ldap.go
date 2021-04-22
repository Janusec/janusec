/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2020-05-16 13:16:44
 * @Last Modified: U2, 2020-05-16 13:16:44
 */

package usermgmt

import (
	"crypto/tls"
	"net/http"
	"strconv"
	"strings"

	"janusec/models"
	"janusec/utils"

	"github.com/gorilla/sessions"
	"github.com/patrickmn/go-cache"

	"janusec/data"

	"github.com/go-ldap/ldap/v3"
)

// LDAPAuthFunc CallBack at /ldap/auth
func LDAPAuthFunc(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	username := r.FormValue("username")
	password := r.FormValue("password")

	// LDAP Auth
	var conn *ldap.Conn
	var err error
	if data.AuthConfig.LDAP.UsingTLS {
		conn, err = ldap.DialTLS("tcp",
			data.AuthConfig.LDAP.Address,
			&tls.Config{MinVersion: tls.VersionTLS12})
	} else {
		conn, err = ldap.Dial("tcp", data.AuthConfig.LDAP.Address)
	}
	if err != nil {
		utils.DebugPrintln("AuthWithLDAP Dial", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer conn.Close()
	dn := strings.Replace(data.AuthConfig.LDAP.DN, "{uid}", username, 1)
	err = conn.Bind(dn, password)
	if err != nil {
		utils.DebugPrintln("AuthWithLDAP Auth Error", username, err)
		var entrance string
		if state == "admin" {
			entrance = data.AuthConfig.LDAP.Entrance + "?state=" + state
		} else {
			entrance = "/ldap/login?state=" + state
		}
		// Go to LDAP login page
		http.Redirect(w, r, entrance, http.StatusFound)
		return
	}
	// TOTP Auth
	if data.AuthConfig.LDAP.AuthenticatorEnabled {
		totpItem, err := GetTOTPByUID(username)
		if err != nil {
			// Not exist totp item, means it is the First Login, Create totp key for current uid
			totpKey := genKey()
			_, err := data.DAL.InsertTOTPItem(username, totpKey, false)
			if err != nil {
				utils.DebugPrintln("InsertTOTPItem error", err)
			}
			// redirect to qrcode scaning page to register in Mobile APP
			http.Redirect(w, r, "/oauth/code/register?uid="+username, http.StatusFound)
			return
		}
		if !totpItem.TOTPVerified {
			// TOTP Not Verified, redirect to register
			http.Redirect(w, r, "/oauth/code/register?uid="+username, http.StatusFound)
			return
		}
		// Verify TOTP Auth Code
		totpCode := r.FormValue("code")
		totpCodeInt, _ := strconv.ParseUint(totpCode, 10, 32)
		verifyOK := VerifyCode(totpItem.TOTPKey, uint32(totpCodeInt))
		if !verifyOK {
			http.Redirect(w, r, "/ldap/login", http.StatusFound)
			return
		}
	}
	// Janusec admin user
	if state == "admin" {
		// Insert into db if not existed
		id, err := data.DAL.InsertIfNotExistsAppUser(username, "", "", "", false, false, false, false)
		if err != nil {
			w.WriteHeader(403)
			w.Write([]byte("Error: " + err.Error()))
			return
		}
		// create session
		authUser := &models.AuthUser{
			UserID:        id,
			Username:      username,
			Logged:        true,
			IsSuperAdmin:  false,
			IsCertAdmin:   false,
			IsAppAdmin:    false,
			NeedModifyPWD: false}
		session, _ := store.Get(r, "sessionid")
		session.Values["authuser"] = authUser
		session.Options = &sessions.Options{Path: "/janusec-admin/", MaxAge: 7200}
		err = session.Save(r, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		RecordAuthLog(r, authUser.Username, "LDAP", data.CFG.PrimaryNode.Admin.Portal)
		http.Redirect(w, r, data.CFG.PrimaryNode.Admin.Portal, http.StatusFound)
		return
	}
	// Gateway OAuth for employees and internal application
	oauthStateI, found := OAuthCache.Get(state)
	if found {
		oauthState := oauthStateI.(models.OAuthState)
		oauthState.UserID = username
		oauthState.AccessToken = "N/A"
		OAuthCache.Set(state, oauthState, cache.DefaultExpiration)
		RecordAuthLog(r, oauthState.UserID, "LDAP", oauthState.CallbackURL)
		http.Redirect(w, r, oauthState.CallbackURL, http.StatusFound)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}
