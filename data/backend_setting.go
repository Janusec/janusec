/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:24:56
 * @Last Modified: U2, 2018-07-14 16:24:56
 */

package data

import (
	"janusec/utils"
)

const (
	sqlCreateTableIfNotExistsSettings = `CREATE TABLE IF NOT EXISTS "settings"("id" bigserial PRIMARY KEY, "name" VARCHAR(128) NOT NULL,"bool_value" boolean,"int_value" bigint,"float_value" decimal,"string_value" VARCHAR(8192))`
	sqlCountSettings                  = `SELECT COUNT(1) FROM "settings"`
	sqlInsertBoolSetting              = `INSERT INTO "settings"("id","name","bool_value") VALUES($1,$2,$3)`
	sqlInsertIntSetting               = `INSERT INTO "settings"("id","name","int_value") VALUES($1,$2,$3)`
	sqlInsertFloatSetting             = `INSERT INTO "settings"("id","name","float_value") VALUES($1,$2,$3)`
	sqlInsertStringSetting            = `INSERT INTO "settings"("id","name","string_value") VALUES($1,$2,$3)`
	sqlUpdateBoolSetting              = `UPDATE "settings" SET "bool_value"=$1 WHERE "name"=$2`
	sqlUpdateIntSetting               = `UPDATE "settings" SET "int_value"=$1 WHERE "name"=$2`
	sqlUpdateFloatSetting             = `UPDATE "settings" SET "float_value"=$1 WHERE "name"=$2`
	sqlUpdateStringSetting            = `UPDATE "settings" SET "string_value"=$1 WHERE "name"=$2`
	sqlSelectBoolSetting              = `SELECT "bool_value" FROM "settings" WHERE "name"=$1`
	sqlSelectIntSetting               = `SELECT "int_value" FROM "settings" WHERE "name"=$1`
	sqlSelectFloatSetting             = `SELECT "float_value" FROM "settings" WHERE "name"=$1`
	sqlSelectStringSetting            = `SELECT "string_value" FROM "settings" WHERE "name"=$1`
	sqlExistsSetting                  = `SELECT COALESCE((SELECT 1 FROM "settings" WHERE "name"=$1 limit 1),0)`
)

// ExistsSetting ...
func (dal *MyDAL) ExistsSetting(name string) bool {
	var exist int
	err := dal.db.QueryRow(sqlExistsSetting, name).Scan(&exist)
	if err != nil {
		utils.DebugPrintln("Check ExistsSetting: "+name, err)
	}
	return exist != 0
}

// SelectBoolSetting ...
func (dal *MyDAL) SelectBoolSetting(name string) (value bool) {
	err := dal.db.QueryRow(sqlSelectBoolSetting, name).Scan(&value)
	if err != nil {
		utils.DebugPrintln("SelectBoolSetting: "+name, err)
	}
	return value
}

// SelectIntSetting ...
func (dal *MyDAL) SelectIntSetting(name string) (value int64) {
	err := dal.db.QueryRow(sqlSelectIntSetting, name).Scan(&value)
	if err != nil {
		utils.DebugPrintln("SelectIntSetting: "+name, err)
	}
	return value
}

// SelectFloatSetting ...
func (dal *MyDAL) SelectFloatSetting(name string) (value float64) {
	err := dal.db.QueryRow(sqlSelectFloatSetting, name).Scan(&value)
	if err != nil {
		utils.DebugPrintln("SelectFloatSetting: "+name, err)
	}
	return value
}

// SelectStringSetting ...
func (dal *MyDAL) SelectStringSetting(name string) (value string) {
	err := dal.db.QueryRow(sqlSelectStringSetting, name).Scan(&value)
	if err != nil {
		utils.DebugPrintln("SelectStringSetting: "+name, err)
	}
	return value
}

// SaveBoolSetting ...
func (dal *MyDAL) SaveBoolSetting(name string, value bool) (err error) {
	if dal.ExistsSetting(name) {
		_, err = dal.db.Exec(sqlUpdateBoolSetting, value, name)
	} else {
		id := utils.GenSnowflakeID()
		_, err = dal.db.Exec(sqlInsertBoolSetting, id, name, value)
	}
	if err != nil {
		utils.DebugPrintln("SaveBoolSetting: "+name, err)
	}
	return err
}

// SaveIntSetting ...
func (dal *MyDAL) SaveIntSetting(name string, value int64) (err error) {
	if dal.ExistsSetting(name) {
		_, err = dal.db.Exec(sqlUpdateIntSetting, value, name)
	} else {
		id := utils.GenSnowflakeID()
		_, err = dal.db.Exec(sqlInsertIntSetting, id, name, value)
	}
	if err != nil {
		utils.DebugPrintln("SaveIntSetting: "+name, err)
	}
	return err
}

// SaveFloatSetting ...
func (dal *MyDAL) SaveFloatSetting(name string, value float64) (err error) {
	if dal.ExistsSetting(name) {
		_, err = dal.db.Exec(sqlUpdateFloatSetting, value, name)
	} else {
		id := utils.GenSnowflakeID()
		_, err = dal.db.Exec(sqlInsertFloatSetting, id, name, value)
	}
	if err != nil {
		utils.DebugPrintln("SaveFloatSetting: "+name, err)
	}
	return err
}

// SaveStringSetting ...
func (dal *MyDAL) SaveStringSetting(name string, value string) (err error) {
	if dal.ExistsSetting(name) {
		_, err = dal.db.Exec(sqlUpdateStringSetting, value, name)
	} else {
		id := utils.GenSnowflakeID()
		_, err = dal.db.Exec(sqlInsertStringSetting, id, name, value)
	}
	if err != nil {
		utils.DebugPrintln("SaveStringSetting: "+name, err)
	}
	return err
}

// CreateTableIfNotExistsSettings ...
func (dal *MyDAL) CreateTableIfNotExistsSettings() error {
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsSettings)
	if err != nil {
		utils.DebugPrintln("CreateTableIfNotExistsSettings", err)
	}
	return err
}

// CountSettings ...
func (dal *MyDAL) CountSettings() int64 {
	var settingsCount int64
	err := dal.db.QueryRow(sqlCountSettings).Scan(&settingsCount)
	if err != nil {
		utils.DebugPrintln("CountSettings", err)
	}
	return settingsCount
}
