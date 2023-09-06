/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:20:35
 * @Last Modified: U2, 2018-07-14 16:20:35
 */

package usermgmt

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

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
	return nil, errors.New("please login")
}

func Login(w http.ResponseWriter, r *http.Request, body []byte, clientIP string) (*models.AuthUser, error) {
	var apiLoginUserRequest models.APILoginUserRequest
	if err := json.Unmarshal(body, &apiLoginUserRequest); err != nil {
		utils.DebugPrintln("Login Unmarshal", err)
		return nil, err
	}
	loginUser := apiLoginUserRequest.Object
	appUser := data.DAL.SelectAppUserByName(loginUser.Username)
	if appUser == nil {
		// not exists
		return nil, errors.New("wrong authentication credentials")
	}
	tmpHashpwd := data.SHA256Hash(loginUser.Password + appUser.Salt)
	if tmpHashpwd != appUser.HashPwd {
		return nil, errors.New("wrong authentication credentials")
	}
	// check auth code
	if data.PrimarySetting.AuthenticatorEnabled {
		totpItem, err := GetTOTPByUID(appUser.Username)
		if err != nil {
			// Not exist totp item, means it is the First Login, Create totp key for current uid
			totpKey := genKey()
			_, err := data.DAL.InsertTOTPItem(appUser.Username, totpKey, false)
			if err != nil {
				utils.DebugPrintln("InsertTOTPItem error", err)
			}
			authUser := &models.AuthUser{
				UserID:       appUser.ID,
				Username:     appUser.Username,
				Logged:       false,
				TOTPKey:      totpKey,
				TOTPVerified: false,
			}
			return authUser, nil
		}
		if !totpItem.TOTPVerified {
			// TOTP Not Verified, redirect to register
			authUser := &models.AuthUser{
				UserID:       appUser.ID,
				Username:     appUser.Username,
				Logged:       false,
				TOTPKey:      totpItem.TOTPKey,
				TOTPVerified: false,
			}
			return authUser, nil
		}
		// Verify TOTP Auth Code
		totpCode := loginUser.TOTPKey // obj["totp_key"].(string)
		totpCodeInt, _ := strconv.ParseUint(totpCode, 10, 32)
		verifyOK := VerifyCode(totpItem.TOTPKey, uint32(totpCodeInt))
		if !verifyOK {
			return nil, errors.New("wrong authentication credentials")
		}
	}

	// auth code ok
	authUser := &models.AuthUser{
		UserID:        appUser.ID,
		Username:      appUser.Username,
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
	go utils.AuthLog(clientIP, appUser.Username, "JANUSEC", "/janusec-admin/")
	return authUser, nil
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
	queryUsers := data.DAL.SelectAppUsers()
	for _, queryUser := range queryUsers {
		appUser := new(models.AppUser)
		appUser.ID = queryUser.ID
		appUser.Username = queryUser.Username
		if queryUser.Email.Valid {
			appUser.Email = queryUser.Email.String
		} else {
			appUser.Email = ""
		}
		appUser.IsSuperAdmin = queryUser.IsSuperAdmin
		appUser.IsCertAdmin = queryUser.IsCertAdmin
		appUser.IsAppAdmin = queryUser.IsAppAdmin
		if authUser.IsSuperAdmin || authUser.UserID == appUser.ID {
			appUsers = append(appUsers, appUser)
		}
	}
	return appUsers, nil

}

func GetAppUserByID(userID int64) (*models.AppUser, error) {
	if userID > 0 {
		appUser := new(models.AppUser)
		appUser.ID = userID
		queryUser := data.DAL.SelectAppUserByID(userID)
		appUser.Username = queryUser.Username
		if queryUser.Email.Valid {
			appUser.Email = queryUser.Email.String
		} else {
			appUser.Email = ""
		}
		appUser.IsSuperAdmin = queryUser.IsSuperAdmin
		appUser.IsCertAdmin = queryUser.IsCertAdmin
		appUser.IsAppAdmin = queryUser.IsAppAdmin
		appUser.NeedModifyPWD = queryUser.NeedModifyPWD
		return appUser, nil
	} else {
		return nil, errors.New("id error")
	}
}

func UpdateAppUser(w http.ResponseWriter, r *http.Request, body []byte, clientIP string, authUser *models.AuthUser) (*models.AppUser, error) {
	var rpcAppUserRequest models.APIAppUserRequest
	if err := json.Unmarshal(body, &rpcAppUserRequest); err != nil {
		utils.DebugPrintln("UpdateAppUser", err)
		return nil, err
	}
	frontUser := rpcAppUserRequest.Object
	appUser := &models.AppUser{}
	appUser.ID = frontUser.ID
	appUser.Username = frontUser.Username
	appUser.Email = frontUser.Email
	appUser.IsAppAdmin = frontUser.IsAppAdmin
	appUser.IsCertAdmin = frontUser.IsCertAdmin
	appUser.IsSuperAdmin = frontUser.IsSuperAdmin
	if !authUser.IsSuperAdmin {
		appUser.IsAppAdmin = false
		appUser.IsCertAdmin = false
		appUser.IsSuperAdmin = false
	}
	if len(frontUser.Password) > 0 {
		// Update salt if password not null
		appUser.Salt = data.GetRandomSaltString()
		appUser.HashPwd = data.SHA256Hash(frontUser.Password + appUser.Salt)
	}
	if appUser.ID == 0 {
		// new user
		newID, err := data.DAL.InsertIfNotExistsAppUser(appUser.Username, appUser.HashPwd, appUser.Salt, appUser.Email, appUser.IsSuperAdmin, appUser.IsCertAdmin, appUser.IsAppAdmin, true)
		if err != nil {
			return nil, err
		}
		appUser.ID = newID
		go utils.OperationLog(clientIP, authUser.Username, "Add User", appUser.Username)
	} else {
		// update existed user
		if len(frontUser.Password) > 0 {
			err := data.DAL.UpdateAppUserWithPwd(appUser.Username, appUser.HashPwd, appUser.Salt, appUser.Email, appUser.IsSuperAdmin, appUser.IsCertAdmin, appUser.IsAppAdmin, false, appUser.ID)
			if err != nil {
				utils.DebugPrintln("UpdateAppUser", err)
				return nil, err
			}
			if appUser.ID == authUser.UserID {
				session, _ := store.Get(r, "sessionid")
				authUser := session.Values["authuser"].(models.AuthUser)
				authUser.NeedModifyPWD = false
				session.Values["authuser"] = authUser
				session.Options = &sessions.Options{Path: "/janusec-admin/", MaxAge: 86400 * 7}
				err = session.Save(r, w)
				if err != nil {
					utils.DebugPrintln("session save error", err)
				}
			}
		} else {
			err := data.DAL.UpdateAppUserNoPwd(appUser.Username, appUser.Email, appUser.IsSuperAdmin, appUser.IsCertAdmin, appUser.IsAppAdmin, appUser.ID)
			if err != nil {
				return nil, err
			}
		}
		go utils.OperationLog(clientIP, authUser.Username, "Update User", appUser.Username)
	}
	return appUser, nil
}

func DeleteUser(userID int64, clientIP string, authUser *models.AuthUser) error {
	if !authUser.IsSuperAdmin && userID != authUser.UserID {
		return errors.New("delete others is not permitted")
	}
	err := data.DAL.DeleteAppUser(userID)
	go utils.OperationLog(clientIP, authUser.Username, "Delete User", strconv.FormatInt(userID, 10))
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

// VerifyTOTP for janusec-admin
func VerifyTOTP(body []byte) error {
	var apiTOTPVerifyRequest models.APITOTPVerifyRequest
	if err := json.Unmarshal(body, &apiTOTPVerifyRequest); err != nil {
		utils.DebugPrintln("VerifyTOTP", err)
		return err
	}
	uid := apiTOTPVerifyRequest.UID
	code := apiTOTPVerifyRequest.Code
	totpItem, _ := GetTOTPByUID(uid)
	totpCodeInt, _ := strconv.ParseUint(code, 10, 32)
	verifyOK := VerifyCode(totpItem.TOTPKey, uint32(totpCodeInt))
	if verifyOK {
		_, err := UpdateTOTPVerified(totpItem.ID)
		if err != nil {
			utils.DebugPrintln("VerifyTOTP error", err)
		}
		return nil
	}
	return errors.New("verify failed")
}
