/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:24:56
 * @Last Modified: U2, 2018-07-14 16:24:56
 */

package data

import (
	"github.com/Janusec/janusec/utils"
)

const (
	sqlCreateTableIfNotExistsSettings = `CREATE TABLE IF NOT EXISTS settings(id bigserial PRIMARY KEY, name varchar(128),bool_value boolean,int_value bigint,float_value decimal,string_value varchar(1024))`
	sqlCountSettings                  = `SELECT COUNT(1) FROM settings`
	sqlInsertBoolSetting              = `INSERT INTO settings(name,bool_value) values($1,$2)`
	sqlInsertIntSetting               = `INSERT INTO settings(name,int_value) values($1,$2)`
	sqlInsertFloatSetting             = `INSERT INTO settings(name,float_value) values($1,$2)`
	sqlInsertStringSetting            = `INSERT INTO settings(name,string_value) values($1,$2)`
	sqlUpdateBoolSetting              = `UPDATE settings set bool_value=$1 WHERE name=$2`
	sqlUpdateIntSetting               = `UPDATE settings set int_value=$1 WHERE name=$2`
	sqlUpdateFloatSetting             = `UPDATE settings set float_value=$1 WHERE name=$2`
	sqlUpdateStringSetting            = `UPDATE settings set string_value=$1 WHERE name=$2`
	sqlSelectBoolSetting              = `SELECT bool_value FROM settings WHERE name=$1`
	sqlSelectIntSetting               = `SELECT int_value FROM settings WHERE name=$1`
	sqlSelectFloatSetting             = `SELECT float_value FROM settings WHERE name=$1`
	sqlSelectStringSetting            = `SELECT string_value FROM settings WHERE name=$1`
	sqlExistsSetting                  = `SELECT coalesce((SELECT 1 FROM settings WHERE name=$1 limit 1),0)`
)

func (dal *MyDAL) ExistsSetting(name string) bool {
	var exist int
	err := dal.db.QueryRow(sqlExistsSetting, name).Scan(&exist)
	utils.CheckError("ExistsSetting", err)
	if exist == 0 {
		return false
	} else {
		return true
	}
}

func (dal *MyDAL) SelectBoolSetting(name string) (value bool, err error) {
	err = dal.db.QueryRow(sqlSelectBoolSetting, name).Scan(&value)
	return value, err
}

func (dal *MyDAL) SelectIntSetting(name string) (value int64, err error) {
	err = dal.db.QueryRow(sqlSelectIntSetting, name).Scan(&value)
	return value, err
}

func (dal *MyDAL) SelectFloatSetting(name string) (value float64, err error) {
	err = dal.db.QueryRow(sqlSelectFloatSetting, name).Scan(&value)
	return value, err
}

func (dal *MyDAL) SelectStringSetting(name string) (value string, err error) {
	err = dal.db.QueryRow(sqlSelectStringSetting, name).Scan(&value)
	return value, err
}

func (dal *MyDAL) SaveBoolSetting(name string, value bool) (err error) {
	if dal.ExistsSetting(name) == true {
		_, err = dal.db.Exec(sqlUpdateBoolSetting, value, name)
	} else {
		_, err = dal.db.Exec(sqlInsertBoolSetting, name, value)
	}
	return err
}

func (dal *MyDAL) SaveIntSetting(name string, value int64) (err error) {
	if dal.ExistsSetting(name) == true {
		_, err = dal.db.Exec(sqlUpdateIntSetting, value, name)
	} else {
		_, err = dal.db.Exec(sqlInsertIntSetting, name, value)
	}
	utils.CheckError("SaveIntSetting", err)
	return err
}

func (dal *MyDAL) SaveFloatSetting(name string, value float64) (err error) {
	if dal.ExistsSetting(name) == true {
		_, err = dal.db.Exec(sqlUpdateFloatSetting, value, name)
	} else {
		_, err = dal.db.Exec(sqlInsertFloatSetting, name, value)
	}
	return err
}

func (dal *MyDAL) SaveStringSetting(name string, value string) (err error) {
	if dal.ExistsSetting(name) == true {
		_, err = dal.db.Exec(sqlUpdateStringSetting, value, name)
	} else {
		_, err = dal.db.Exec(sqlInsertStringSetting, name, value)
	}
	return err
}

func (dal *MyDAL) CreateTableIfNotExistsSettings() error {
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsSettings)
	return err
}

func (dal *MyDAL) CountSettings() int64 {
	var settings_count int64
	err := dal.db.QueryRow(sqlCountSettings).Scan(&settings_count)
	utils.CheckError("CountSettings", err)
	return settings_count
}
