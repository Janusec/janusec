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

	"../data"
	"../models"
	"github.com/gorilla/sessions"
)

var (
	store = sessions.NewCookieStore([]byte("janusec-app-gateway"))
)

func IsLogIn(w http.ResponseWriter, r *http.Request) (is_logIn bool, user_id int64) {
	session, _ := store.Get(r, "sessionid")
	username := session.Values["username"]
	is_logIn = false
	user_id = 0
	if username != nil {
		is_logIn = true
		user_id = session.Values["user_id"].(int64)
	}
	//fmt.Println("IsLogIn:", is_logIn, "Username:", username)
	return is_logIn, user_id
}

func GetAuthUser(w http.ResponseWriter, r *http.Request) (*models.AuthUser, error) {
	session, _ := store.Get(r, "sessionid")
	user_id := session.Values["user_id"]
	username := session.Values["username"]
	need_modify_pwd := session.Values["need_modify_pwd"]
	if need_modify_pwd == nil {
		need_modify_pwd = false
	}
	if username != nil {
		authUser := &models.AuthUser{UserID: user_id.(int64), Username: username.(string), Logged: true, NeedModifyPWD: need_modify_pwd.(bool)}
		return authUser, nil
	}
	return nil, nil
}

func Login(w http.ResponseWriter, r *http.Request, param map[string]interface{}) (*models.AuthUser, error) {
	obj := param["object"].(map[string]interface{})
	username := obj["username"].(string)
	password := obj["passwd"].(string)
	user_id, hashpwd, salt, need_modify_pwd := data.DAL.SelectHashPwdAndSalt(username)

	tmp_hashpwd := data.SHA256Hash(password + salt)
	//fmt.Printf("Login password=%s salt=%s hashpwd=%s tmp_hashpwd=%s", password, salt, hashpwd, tmp_hashpwd)
	if tmp_hashpwd == hashpwd {
		session, _ := store.Get(r, "sessionid")
		session.Values["username"] = username
		session.Values["user_id"] = user_id
		session.Values["need_modify_pwd"] = need_modify_pwd
		session.Save(r, w)
		authUser := &models.AuthUser{Username: username, Logged: true, NeedModifyPWD: need_modify_pwd}
		return authUser, nil
	} else {
		return nil, errors.New("Login failed.")
	}
}

func Logout(w http.ResponseWriter, r *http.Request) error {
	session, _ := store.Get(r, "sessionid")
	session.Values["username"] = nil
	session.Values["user_id"] = nil
	session.Values["need_modify_pwd"] = nil
	session.Save(r, w)
	return nil
}

func GetAppUsers() ([]*models.AppUser, error) {
	var app_users []*models.AppUser
	query_users := data.DAL.SelectAppUsers()
	for _, query_user := range query_users {
		app_user := new(models.AppUser)
		app_user.ID = query_user.ID
		app_user.Username = query_user.Username
		if query_user.Email.Valid {
			app_user.Email = query_user.Email.String
		} else {
			app_user.Email = ""
		}
		app_user.IsSuperAdmin = query_user.IsSuperAdmin
		app_user.IsCertAdmin = query_user.IsCertAdmin
		app_user.IsAppAdmin = query_user.IsAppAdmin
		app_users = append(app_users, app_user)
	}
	return app_users, nil
}

func GetAdmin(param map[string]interface{}) (*models.AppUser, error) {
	var user_id = int64(param["id"].(float64))
	return GetAppUserByID(user_id)
}

func GetAppUserByID(user_id int64) (*models.AppUser, error) {
	if user_id > 0 {
		app_user := new(models.AppUser)
		app_user.ID = user_id
		query_user := data.DAL.SelectAppUserByID(user_id)
		app_user.Username = query_user.Username
		if query_user.Email.Valid {
			app_user.Email = query_user.Email.String
		} else {
			app_user.Email = ""
		}
		app_user.IsSuperAdmin = query_user.IsSuperAdmin
		app_user.IsCertAdmin = query_user.IsCertAdmin
		app_user.IsAppAdmin = query_user.IsAppAdmin
		return app_user, nil
	} else {
		return nil, errors.New("id error")
	}
}

func UpdateUser(w http.ResponseWriter, r *http.Request, param map[string]interface{}) (*models.AppUser, error) {
	var user = param["object"].(map[string]interface{})
	var user_id = int64(user["id"].(float64))
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

	var is_super_admin = user["is_super_admin"].(bool)
	var is_cert_admin = user["is_cert_admin"].(bool)
	var is_app_admin = user["is_app_admin"].(bool)
	salt := data.GetRandomSaltString()
	hashpwd := data.SHA256Hash(password + salt)
	app_user := new(models.AppUser)
	if user_id == 0 {
		// new user
		new_id, err := data.DAL.InsertIfNotExistsAppUser(username, hashpwd, salt, email, is_super_admin, is_cert_admin, is_app_admin, true)
		if err != nil {
			return nil, err
		}
		app_user.ID = new_id
	} else {
		// update existed user
		if len(password) > 0 {
			err := data.DAL.UpdateAppUserWithPwd(username, hashpwd, salt, email, is_super_admin, is_cert_admin, is_app_admin, false, user_id)
			if err != nil {
				return nil, err
			}
			session, _ := store.Get(r, "sessionid")
			session.Values["need_modify_pwd"] = false
			session.Save(r, w)

		} else {
			err := data.DAL.UpdateAppUserNoPwd(username, email, is_super_admin, is_cert_admin, is_app_admin, user_id)
			if err != nil {
				return nil, err
			}
		}
		app_user.ID = user_id
	}
	app_user.Username = username
	app_user.Email = email
	app_user.IsSuperAdmin = is_super_admin
	app_user.IsCertAdmin = is_cert_admin
	app_user.IsAppAdmin = is_app_admin
	return app_user, nil
}

func DeleteUser(user_id int64) error {
	err := data.DAL.DeleteAppUser(user_id)
	return err
}
