/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:20:35
 * @Last Modified: U2, 2018-07-14 16:20:35
 */

package usermgmt

import (
	"errors"
	"net/http"

	"janusec/data"
	"janusec/models"
	"janusec/utils"

	"github.com/gorilla/sessions"
)

var (
	store = sessions.NewCookieStore([]byte("janusec-app-gateway"))
)

func IsLogIn(w http.ResponseWriter, r *http.Request) (isLogIn bool, userID int64) {
	session, _ := store.Get(r, "sessionid")
	authUserI := session.Values["authuser"]
	if authUserI != nil {
		authUser := authUserI.(models.AuthUser)
		return true, authUser.UserID
	}
	return false, 0
}

func GetAuthUser(w http.ResponseWriter, r *http.Request) (*models.AuthUser, error) {
	session, _ := store.Get(r, "sessionid")
	authUserI := session.Values["authuser"]
	if authUserI != nil {
		authUser := authUserI.(models.AuthUser)
		return &authUser, nil
	}
	return nil, errors.New("Please login")
}

func Login(w http.ResponseWriter, r *http.Request, param map[string]interface{}) (*models.AuthUser, error) {
	obj := param["object"].(map[string]interface{})
	username := obj["username"].(string)
	password := obj["passwd"].(string)
	appUser := data.DAL.SelectAppUserByName(username)

	tmpHashpwd := data.SHA256Hash(password + appUser.Salt)
	if tmpHashpwd == appUser.HashPwd {
		authUser := &models.AuthUser{
			UserID:        appUser.ID,
			Username:      username,
			Logged:        true,
			IsSuperAdmin:  appUser.IsSuperAdmin,
			IsCertAdmin:   appUser.IsCertAdmin,
			IsAppAdmin:    appUser.IsAppAdmin,
			NeedModifyPWD: appUser.NeedModifyPWD}
		session, _ := store.Get(r, "sessionid")
		session.Values["authuser"] = authUser
		session.Options = &sessions.Options{Path: "/janusec-admin/", MaxAge: 86400 * 7}
		err := session.Save(r, w)
		if err != nil {
			utils.DebugPrintln("session save error", err)
		}
		return authUser, nil
	}
	return nil, errors.New("Login failed.")
}

func Logout(w http.ResponseWriter, r *http.Request) error {
	session, _ := store.Get(r, "sessionid")
	session.Values["authuser"] = nil
	session.Options = &sessions.Options{Path: "/janusec-admin/", MaxAge: 0}
	err := session.Save(r, w)
	if err != nil {
		utils.DebugPrintln("session save error", err)
	}
	return nil
}

func GetAppUsers(authUser *models.AuthUser) ([]*models.AppUser, error) {
	var appUsers = []*models.AppUser{}
	query_users := data.DAL.SelectAppUsers()
	for _, query_user := range query_users {
		appUser := new(models.AppUser)
		appUser.ID = query_user.ID
		appUser.Username = query_user.Username
		if query_user.Email.Valid {
			appUser.Email = query_user.Email.String
		} else {
			appUser.Email = ""
		}
		appUser.IsSuperAdmin = query_user.IsSuperAdmin
		appUser.IsCertAdmin = query_user.IsCertAdmin
		appUser.IsAppAdmin = query_user.IsAppAdmin
		if authUser.IsSuperAdmin || authUser.UserID == appUser.ID {
			appUsers = append(appUsers, appUser)
		}
	}
	return appUsers, nil

}

func GetAdmin(param map[string]interface{}) (*models.AppUser, error) {
	var userID = int64(param["id"].(float64))
	return GetAppUserByID(userID)
}

func GetAppUserByID(userID int64) (*models.AppUser, error) {
	if userID > 0 {
		appUser := new(models.AppUser)
		appUser.ID = userID
		query_user := data.DAL.SelectAppUserByID(userID)
		appUser.Username = query_user.Username
		if query_user.Email.Valid {
			appUser.Email = query_user.Email.String
		} else {
			appUser.Email = ""
		}
		appUser.IsSuperAdmin = query_user.IsSuperAdmin
		appUser.IsCertAdmin = query_user.IsCertAdmin
		appUser.IsAppAdmin = query_user.IsAppAdmin
		return appUser, nil
	} else {
		return nil, errors.New("id error")
	}
}

func UpdateUser(w http.ResponseWriter, r *http.Request, param map[string]interface{}, authUser *models.AuthUser) (*models.AppUser, error) {
	var user = param["object"].(map[string]interface{})
	var userID = int64(user["id"].(float64))
	var username = user["username"].(string)
	var password string
	if user["password"] == nil {
		password = ""
	} else {
		password = user["password"].(string)
	}
	email := ""
	if user["email"] != nil {
		email = user["email"].(string)
	}
	isSuperAdmin := false
	isCertAdmin := false
	isAppAdmin := false
	if authUser.IsSuperAdmin {
		isSuperAdmin = user["is_super_admin"].(bool)
		isCertAdmin = user["is_cert_admin"].(bool)
		isAppAdmin = user["is_app_admin"].(bool)
	}
	salt := data.GetRandomSaltString()
	hashpwd := data.SHA256Hash(password + salt)
	appUser := new(models.AppUser)
	if userID == 0 {
		// new user
		newID, err := data.DAL.InsertIfNotExistsAppUser(username, hashpwd, salt, email, isSuperAdmin, isCertAdmin, isAppAdmin, true)
		if err != nil {
			return nil, err
		}
		appUser.ID = newID
	} else {
		// update existed user
		if len(password) > 0 {
			err := data.DAL.UpdateAppUserWithPwd(username, hashpwd, salt, email, isSuperAdmin, isCertAdmin, isAppAdmin, false, userID)
			if err != nil {
				return nil, err
			}
			session, _ := store.Get(r, "sessionid")
			authUser := session.Values["authuser"].(models.AuthUser)
			authUser.NeedModifyPWD = false
			session.Values["authuser"] = authUser
			session.Options = &sessions.Options{Path: "/janusec-admin/", MaxAge: 86400 * 7}
			err = session.Save(r, w)
			if err != nil {
				utils.DebugPrintln("session save error", err)
			}
		} else {
			err := data.DAL.UpdateAppUserNoPwd(username, email, isSuperAdmin, isCertAdmin, isAppAdmin, userID)
			if err != nil {
				return nil, err
			}
		}
		appUser.ID = userID
	}
	appUser.Username = username
	appUser.Email = email
	appUser.IsSuperAdmin = isSuperAdmin
	appUser.IsCertAdmin = isCertAdmin
	appUser.IsAppAdmin = isAppAdmin
	return appUser, nil
}

func DeleteUser(userID int64) error {
	err := data.DAL.DeleteAppUser(userID)
	return err
}

func GetLoginUsername(r *http.Request) string {
	session, _ := store.Get(r, "sessionid")
	authUserI := session.Values["authuser"]
	if authUserI != nil {
		authUser := authUserI.(models.AuthUser)
		return authUser.Username
	}
	return ""
}
