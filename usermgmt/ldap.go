/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2020-05-16 13:16:44
 * @Last Modified: U2, 2020-05-16 13:16:44
 */

package usermgmt

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"

	"github.com/Janusec/janusec/models"
	"github.com/Janusec/janusec/utils"
	"github.com/gorilla/sessions"
	"github.com/patrickmn/go-cache"

	"github.com/Janusec/janusec/data"
	"github.com/go-ldap/ldap"
)

// AuthWithLDAP 389, 636
/*
func AuthWithLDAP(uid string, passwd string) (userid string, err error) {
	var conn *ldap.Conn
	if data.CFG.MasterNode.OAuth.LDAP.UsingTLS {
		conn, err = ldap.DialTLS("tcp", data.CFG.MasterNode.OAuth.LDAP.Address, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = ldap.Dial("tcp", data.CFG.MasterNode.OAuth.LDAP.Address)
	}
	if err != nil {
		utils.DebugPrintln("AuthWithLDAP Dial", err)
		return "", err
	}
	defer conn.Close()

	// Auth
	dn := strings.Replace(data.CFG.MasterNode.OAuth.LDAP.DN, "{uid}", uid, 1)

	err = conn.Bind(dn, passwd)
	if err != nil {
		utils.DebugPrintln("AuthWithLDAP Auth Error", userid, err)
		return "", err
	}
	// Auth OK
	return userid, nil
}
*/

// LDAPAuthFunc CallBack at /ldap/auth
func LDAPAuthFunc(w http.ResponseWriter, r *http.Request) (*models.AuthUser, error) {
	state := r.FormValue("state")
	username := r.FormValue("username")
	password := r.FormValue("password")
	fmt.Println("LDAPAuthFunc", state, username, password)

	var conn *ldap.Conn
	var err error
	if data.CFG.MasterNode.OAuth.LDAP.UsingTLS {
		conn, err = ldap.DialTLS("tcp", data.CFG.MasterNode.OAuth.LDAP.Address, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = ldap.Dial("tcp", data.CFG.MasterNode.OAuth.LDAP.Address)
	}
	if err != nil {
		utils.DebugPrintln("AuthWithLDAP Dial", err)
		return nil, err
	}
	defer conn.Close()

	// Auth
	dn := strings.Replace(data.CFG.MasterNode.OAuth.LDAP.DN, "{uid}", username, 1)

	err = conn.Bind(dn, password)
	if err != nil {
		utils.DebugPrintln("AuthWithLDAP Auth Error", username, err)
		var entrance string
		if state == "admin" {
			entrance = data.CFG.MasterNode.OAuth.LDAP.Entrance + "?state=" + state
		} else {
			entrance = "/ldap/login?state=" + state
		}
		// Go to LDAP login page
		http.Redirect(w, r, entrance, http.StatusFound)
		return nil, err
	}

	if state == "admin" {
		// Insert into db if not existed
		id, _ := data.DAL.InsertIfNotExistsAppUser(username, "", "", "", false, false, false, false)
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
		session.Save(r, w)
		return authUser, nil
	}
	// Gateway OAuth for employees and internal application
	oauthStateI, found := OAuthCache.Get(state)
	if found {
		oauthState := oauthStateI.(models.OAuthState)
		oauthState.UserID = username
		oauthState.AccessToken = "N/A"
		OAuthCache.Set(state, oauthState, cache.DefaultExpiration)
		fmt.Println("1008 set cache state=", oauthState, "307 to:", oauthState.CallbackURL)
		http.Redirect(w, r, oauthState.CallbackURL, http.StatusTemporaryRedirect)
		return nil, nil
	}
	fmt.Println("1009 Time expired")
	http.Redirect(w, r, "/", http.StatusFound)
	return nil, nil
}
