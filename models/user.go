/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2023-04-02 19:54:41
 */

package models

import "database/sql"

// AuthUser used for Authentication in Memory
type AuthUser struct {
	UserID        int64  `json:"user_id,string"`
	Username      string `json:"username"`
	Logged        bool   `json:"logged"`
	IsSuperAdmin  bool   `json:"is_super_admin"`
	IsCertAdmin   bool   `json:"is_cert_admin"`
	IsAppAdmin    bool   `json:"is_app_admin"`
	NeedModifyPWD bool   `json:"need_modify_pwd"`
	// v1.2.2
	TOTPKey      string `json:"totp_key"`
	TOTPVerified bool   `json:"totp_verified"`
}

// AppUser used for DB Storage
type AppUser struct {
	ID            int64  `json:"id,string"`
	Username      string `json:"username"`
	HashPwd       string `json:"-"`
	Salt          string `json:"-"`
	Email         string `json:"email"`
	IsSuperAdmin  bool   `json:"is_super_admin"`
	IsCertAdmin   bool   `json:"is_cert_admin"`
	IsAppAdmin    bool   `json:"is_app_admin"`
	NeedModifyPWD bool   `json:"need_modify_pwd"`
}

// FrontAppUser used for updating app user, receive from front end
type FrontAppUser struct {
	ID            int64  `json:"id,string"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	Email         string `json:"email"`
	IsSuperAdmin  bool   `json:"is_super_admin"`
	IsCertAdmin   bool   `json:"is_cert_admin"`
	IsAppAdmin    bool   `json:"is_app_admin"`
	NeedModifyPWD bool   `json:"need_modify_pwd"`
}

// QueryAppUser not include password and salt
type QueryAppUser struct {
	ID            int64
	Username      string
	Email         sql.NullString
	IsSuperAdmin  bool
	IsCertAdmin   bool
	IsAppAdmin    bool
	NeedModifyPWD bool
}

// TOTP Authenticator
type TOTP struct {
	ID           int64  `json:"id,string"`
	UID          string `json:"uid"`
	TOTPKey      string `json:"totp_key"`
	TOTPVerified bool   `json:"totp_verified"`
}

type LoginUser struct {
	Username string `json:"username"`
	Password string `json:"passwd"`
	TOTPKey  string `json:"totp_key"`
}

type APILoginUserRequest struct {
	Action string     `json:"action"`
	Object *LoginUser `json:"object"`
}

type APITOTPVerifyRequest struct {
	Action string `json:"action"`
	UID    string `json:"uid"`
	Code   string `json:"code"`
}
