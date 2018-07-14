/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:24:13
 * @Last Modified: U2, 2018-07-14 16:24:13
 */

package data

import (
	"errors"

	"../models"
	"../utils"
)

const (
	sqlCreateTableIfNotExistsAppUsers = `CREATE TABLE IF NOT EXISTS appusers(id bigserial PRIMARY KEY, username varchar(128), hashpwd varchar(256), salt varchar(32), email varchar(128), is_super_admin boolean, is_cert_admin boolean, is_app_admin boolean, need_modify_pwd boolean)`
	sqlInsertAppUser                  = `INSERT INTO appusers(username,hashpwd,salt,email,is_super_admin,is_cert_admin,is_app_admin,need_modify_pwd) values($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`
	sqlIsExistUser                    = `SELECT coalesce((SELECT 1 FROM appusers WHERE username=$1 limit 1),0)`
	sqlSelectHashPwdAndSalt           = `SELECT id,hashpwd,salt,need_modify_pwd FROM appusers WHERE username=$1`
	sqlSelectAppUsers                 = `SELECT id,username,email,is_super_admin,is_cert_admin,is_app_admin FROM appusers`
	sqlSelectAppUserByID              = `SELECT username,email,is_super_admin,is_cert_admin,is_app_admin FROM appusers WHERE id=$1`
	sqlUpdateAppUserWithPwd           = `UPDATE appusers SET username=$1,hashpwd=$2,salt=$3,email=$4,is_super_admin=$5,is_cert_admin=$6,is_app_admin=$7,need_modify_pwd=$8 WHERE id=$9`
	sqlUpdateAppUserNoPwd             = `UPDATE appusers SET username=$1,email=$2,is_super_admin=$3,is_cert_admin=$4,is_app_admin=$5 WHERE id=$6`
	sqlDeleteAppUser                  = `DELETE FROM appusers WHERE id=$1`
)

func (dal *MyDAL) CreateTableIfNotExistsAppUsers() error {
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsAppUsers)
	return err
}

func (dal *MyDAL) IsExistsAppUser(username string) bool {
	var exist_admin int
	dal.db.QueryRow(sqlIsExistUser, username).Scan(&exist_admin)
	if exist_admin == 0 {
		return false
	} else {
		return true
	}
}

func (dal *MyDAL) InsertIfNotExistsAppUser(username string, hashpwd string, salt string, email string, is_super_admin, is_cert_admin, is_app_admin bool, need_modify_pwd bool) (new_id int64, err error) {
	if dal.IsExistsAppUser(username) == true {
		return 0, errors.New("Error: Username exists.")
	}
	err = dal.db.QueryRow(sqlInsertAppUser, username, hashpwd, salt, email, is_super_admin, is_cert_admin, is_app_admin, need_modify_pwd).Scan(&new_id)
	return new_id, err
}

func (dal *MyDAL) SelectHashPwdAndSalt(username string) (user_id int64, hashpwd string, salt string, need_modify_pwd bool) {
	err := dal.db.QueryRow(sqlSelectHashPwdAndSalt, username).Scan(&user_id, &hashpwd, &salt, &need_modify_pwd)
	utils.CheckError("SelectHashPwdAndSalt", err)
	return user_id, hashpwd, salt, need_modify_pwd
}

func (dal *MyDAL) SelectAppUsers() []*models.QueryAppUser {
	rows, err := dal.db.Query(sqlSelectAppUsers)
	utils.CheckError("SelectAppUsers", err)
	defer rows.Close()
	var query_users []*models.QueryAppUser
	for rows.Next() {
		query_user := new(models.QueryAppUser)
		err = rows.Scan(&query_user.ID, &query_user.Username, &query_user.Email, &query_user.IsSuperAdmin, &query_user.IsCertAdmin, &query_user.IsAppAdmin)
		query_users = append(query_users, query_user)
	}
	return query_users
}

func (dal *MyDAL) SelectAppUserByID(user_id int64) *models.QueryAppUser {
	query_user := new(models.QueryAppUser)
	query_user.ID = user_id
	err := dal.db.QueryRow(sqlSelectAppUserByID, user_id).Scan(&query_user.Username, &query_user.Email, &query_user.IsSuperAdmin, &query_user.IsCertAdmin, &query_user.IsAppAdmin)
	utils.CheckError("SelectAppUserByID", err)
	return query_user
}

func (dal *MyDAL) UpdateAppUserWithPwd(username string, hashpwd string, salt string, email string, is_super_admin, is_cert_admin, is_app_admin bool, need_modify_pwd bool, user_id int64) error {
	stmt, err := dal.db.Prepare(sqlUpdateAppUserWithPwd)
	defer stmt.Close()
	_, err = stmt.Exec(username, hashpwd, salt, email, is_super_admin, is_cert_admin, is_app_admin, need_modify_pwd, user_id)
	utils.CheckError("UpdateAppUserWithPwd", err)
	return err
}

func (dal *MyDAL) UpdateAppUserNoPwd(username string, email string, is_super_admin, is_cert_admin, is_app_admin bool, user_id int64) error {
	stmt, err := dal.db.Prepare(sqlUpdateAppUserNoPwd)
	defer stmt.Close()
	_, err = stmt.Exec(username, email, is_super_admin, is_cert_admin, is_app_admin, user_id)
	utils.CheckError("UpdateAppUserNoPwd", err)
	return err
}

func (dal *MyDAL) DeleteAppUser(user_id int64) error {
	stmt, err := dal.db.Prepare(sqlDeleteAppUser)
	defer stmt.Close()
	_, err = stmt.Exec(user_id)
	utils.CheckError("DeleteAppUser", err)
	return err
}
