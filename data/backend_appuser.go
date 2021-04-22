/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:24:13
 * @Last Modified: U2, 2018-07-14 16:24:13
 */

package data

import (
	"janusec/models"
	"janusec/utils"
)

const (
	sqlInsertAppUser        = `INSERT INTO "appusers"("username","hashpwd","salt","email","is_super_admin","is_cert_admin","is_app_admin","need_modify_pwd") VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING "id"`
	sqlIsExistUser          = `SELECT COALESCE((SELECT 1 FROM "appusers" WHERE "username"=$1 limit 1),0)`
	sqlSelectHashPwdAndSalt = `SELECT "id","hashpwd","salt","need_modify_pwd" FROM "appusers" WHERE "username"=$1`
	sqlSelectAppUsers       = `SELECT "id","username","email","is_super_admin","is_cert_admin","is_app_admin" FROM "appusers"`

	sqlUpdateAppUserWithPwd = `UPDATE "appusers" SET "username"=$1,"hashpwd"=$2,"salt"=$3,"email"=$4,"is_super_admin"=$5,"is_cert_admin"=$6,"is_app_admin"=$7,"need_modify_pwd"=$8 WHERE "id"=$9`
	sqlUpdateAppUserNoPwd   = `UPDATE "appusers" SET "username"=$1,"email"=$2,"is_super_admin"=$3,"is_cert_admin"=$4,"is_app_admin"=$5 WHERE "id"=$6`
	sqlDeleteAppUser        = `DELETE FROM "appusers" WHERE "id"=$1`
)

// CreateTableIfNotExistsAppUsers ...
func (dal *MyDAL) CreateTableIfNotExistsAppUsers() error {
	const sqlCreateTableIfNotExistsAppUsers = `CREATE TABLE IF NOT EXISTS "appusers"("id" bigserial PRIMARY KEY, "username" VARCHAR(128) NOT NULL, "hashpwd" VARCHAR(256) NOT NULL DEFAULT '', "salt" VARCHAR(32) NOT NULL DEFAULT '', "email" VARCHAR(128) NOT NULL DEFAULT '', "is_super_admin" boolean, "is_cert_admin" boolean, "is_app_admin" boolean, "need_modify_pwd" boolean)`
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsAppUsers)
	return err
}

// IsExistsAppUser ...
func (dal *MyDAL) IsExistsAppUser(username string) bool {
	var existAdmin int
	err := dal.db.QueryRow(sqlIsExistUser, username).Scan(&existAdmin)
	if err != nil {
		utils.DebugPrintln("IsExistsAppUser QueryRow", err)
	}
	if existAdmin == 0 {
		return false
	}
	return true
}

// GetAppUserIDByName ...
func (dal *MyDAL) GetAppUserIDByName(username string) (id int64, err error) {
	sqlSelectID := `SELECT "id" FROM "appusers" WHERE "username"=$1`
	err = dal.db.QueryRow(sqlSelectID, username).Scan(&id)
	return id, err
}

// InsertIfNotExistsAppUser ...
func (dal *MyDAL) InsertIfNotExistsAppUser(username string, hashpwd string, salt string, email string, isSuperAdmin, isCertAdmin, isAppAdmin bool, needModifyPwd bool) (id int64, err error) {
	id, err = dal.GetAppUserIDByName(username)
	if err == nil {
		return id, err
	}
	err = dal.db.QueryRow(sqlInsertAppUser, username, hashpwd, salt, email, isSuperAdmin, isCertAdmin, isAppAdmin, needModifyPwd).Scan(&id)
	return id, err
}

// SelectHashPwdAndSalt by username
func (dal *MyDAL) SelectHashPwdAndSalt(username string) (userID int64, hashpwd string, salt string, needModifyPwd bool) {
	err := dal.db.QueryRow(sqlSelectHashPwdAndSalt, username).Scan(&userID, &hashpwd, &salt, &needModifyPwd)
	utils.CheckError("SelectHashPwdAndSalt", err)
	return userID, hashpwd, salt, needModifyPwd
}

// SelectAppUserByName ...
func (dal *MyDAL) SelectAppUserByName(username string) *models.AppUser {
	appUser := &models.AppUser{}
	const sqlSelectAppUserByName = `SELECT "id","username","hashpwd","salt","email","is_super_admin","is_cert_admin","is_app_admin","need_modify_pwd" FROM "appusers" WHERE "username"=$1`
	err := dal.db.QueryRow(sqlSelectAppUserByName, username).Scan(
		&appUser.ID,
		&appUser.Username,
		&appUser.HashPwd,
		&appUser.Salt,
		&appUser.Email,
		&appUser.IsSuperAdmin,
		&appUser.IsCertAdmin,
		&appUser.IsAppAdmin,
		&appUser.NeedModifyPWD)
	utils.CheckError("SelectAppUserByName", err)
	return appUser
}

// SelectAppUsers ...
func (dal *MyDAL) SelectAppUsers() []*models.QueryAppUser {
	rows, err := dal.db.Query(sqlSelectAppUsers)
	utils.CheckError("SelectAppUsers", err)
	defer rows.Close()
	var queryUsers = []*models.QueryAppUser{}
	for rows.Next() {
		queryUser := &models.QueryAppUser{}
		_ = rows.Scan(&queryUser.ID, &queryUser.Username, &queryUser.Email, &queryUser.IsSuperAdmin, &queryUser.IsCertAdmin, &queryUser.IsAppAdmin)
		queryUsers = append(queryUsers, queryUser)
	}
	return queryUsers
}

// SelectAppUserByID ...
func (dal *MyDAL) SelectAppUserByID(userID int64) *models.QueryAppUser {
	queryUser := &models.QueryAppUser{}
	queryUser.ID = userID
	const sqlSelectAppUserByID = `SELECT "username","email","is_super_admin","is_cert_admin","is_app_admin","need_modify_pwd" FROM "appusers" WHERE "id"=$1`
	err := dal.db.QueryRow(sqlSelectAppUserByID, userID).Scan(&queryUser.Username, &queryUser.Email, &queryUser.IsSuperAdmin, &queryUser.IsCertAdmin, &queryUser.IsAppAdmin, &queryUser.NeedModifyPWD)
	utils.CheckError("SelectAppUserByID", err)
	return queryUser
}

// UpdateAppUserWithPwd ...
func (dal *MyDAL) UpdateAppUserWithPwd(username string, hashpwd string, salt string, email string, isSuperAdmin, isCertAdmin, isAppAdmin bool, needModifyPwd bool, userID int64) error {
	stmt, _ := dal.db.Prepare(sqlUpdateAppUserWithPwd)
	defer stmt.Close()
	_, err := stmt.Exec(username, hashpwd, salt, email, isSuperAdmin, isCertAdmin, isAppAdmin, needModifyPwd, userID)
	utils.CheckError("UpdateAppUserWithPwd", err)
	return err
}

// UpdateAppUserNoPwd ...
func (dal *MyDAL) UpdateAppUserNoPwd(username string, email string, isSuperAdmin, isCertAdmin, isAppAdmin bool, userID int64) error {
	stmt, _ := dal.db.Prepare(sqlUpdateAppUserNoPwd)
	defer stmt.Close()
	_, err := stmt.Exec(username, email, isSuperAdmin, isCertAdmin, isAppAdmin, userID)
	utils.CheckError("UpdateAppUserNoPwd", err)
	return err
}

// DeleteAppUser ...
func (dal *MyDAL) DeleteAppUser(userID int64) error {
	stmt, _ := dal.db.Prepare(sqlDeleteAppUser)
	defer stmt.Close()
	_, err := stmt.Exec(userID)
	utils.CheckError("DeleteAppUser", err)
	return err
}
