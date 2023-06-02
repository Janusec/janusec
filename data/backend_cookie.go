/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2023-05-28 14:28:07
 */

package data

import (
	"janusec/models"
	"janusec/utils"
)

// CreateTableIfNotExistsCookies ...
func (dal *MyDAL) CreateTableIfNotExistsCookies() error {
	const sqlCreateTableIfNotExistsCookies = `CREATE TABLE IF NOT EXISTS "cookies"("id" bigserial PRIMARY KEY, "app_id" bigint, "name" VARCHAR(256) NOT NULL, "domain" VARCHAR(256),  "path" VARCHAR(256), "duration" VARCHAR(256), "vendor" VARCHAR(256), "type" bigint, "description" VARCHAR(512), "access_time" bigint, "source" VARCHAR(512))`
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsCookies)
	return err
}

// SelectCookies ...
func (dal *MyDAL) SelectCookiesByAppID(appID int64) []*models.Cookie {
	const sqlSelectCookies = `SELECT "id","name","domain","path","duration","vendor","type","description","access_time","source" FROM "cookies" WHERE "app_id"=$1 ORDER BY "type"`
	rows, err := dal.db.Query(sqlSelectCookies, appID)
	if err != nil {
		utils.DebugPrintln("SelectCookiesByAppID", err)
	}
	defer rows.Close()
	cookies := []*models.Cookie{}
	for rows.Next() {
		cookie := &models.Cookie{AppID: appID}
		_ = rows.Scan(&cookie.ID, &cookie.Name, &cookie.Domain, &cookie.Path, &cookie.Duration, &cookie.Vendor, &cookie.Type, &cookie.Description, &cookie.AccessTime, &cookie.Source)
		cookies = append(cookies, cookie)
	}
	return cookies
}

func (dal *MyDAL) InsertCookie(cookie *models.Cookie) error {
	const sqlInsertCookie = `INSERT INTO "cookies"("id","app_id","name","domain","path","duration","vendor","type","description","access_time","source") VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
	_, err := dal.db.Exec(sqlInsertCookie, cookie.ID, cookie.AppID, cookie.Name, cookie.Domain, cookie.Path, cookie.Duration, cookie.Vendor, cookie.Type, cookie.Description, cookie.AccessTime, cookie.Source)
	return err
}

func (dal *MyDAL) UpdateCookie(cookie *models.Cookie) error {
	const sqlUpdateCookie = `UPDATE "cookies" SET "name"=$1,"domain"=$2,"path"=$3,"duration"=$4,"vendor"=$5,"type"=$6,"description"=$7,"access_time"=$8,"source"=$9 WHERE "id"=$10`
	_, err := dal.db.Exec(sqlUpdateCookie, cookie.Name, cookie.Domain, cookie.Path, cookie.Duration, cookie.Vendor, cookie.Type, cookie.Description, cookie.AccessTime, cookie.Source, cookie.ID)
	return err
}

func (dal *MyDAL) DeleteCookieByID(id int64) error {
	const sqlDelCookie = `DELETE FROM "cookies" WHERE "id"=$1`
	_, err := dal.db.Exec(sqlDelCookie, id)
	return err
}

func (dal *MyDAL) SelectCookieByID(id int64) (*models.Cookie, error) {
	cookie := models.Cookie{
		ID: id,
	}
	const sqlSelectCookies = `SELECT "app_id","name","domain","path","duration","vendor","type","description","access_time","source" FROM "cookies" WHERE "id"=$1`
	err := dal.db.QueryRow(sqlSelectCookies, id).Scan(&cookie.AppID, &cookie.Name, &cookie.Domain, &cookie.Path, &cookie.Duration, &cookie.Vendor, &cookie.Type, &cookie.Description, &cookie.AccessTime, &cookie.Source)
	return &cookie, err
}
