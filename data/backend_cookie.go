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
	const sqlCreateTableIfNotExistsCookies = `CREATE TABLE IF NOT EXISTS "cookies"("id" bigserial PRIMARY KEY, "app_id" bigint, "name" VARCHAR(256) NOT NULL, "path" VARCHAR(256), "vendor" VARCHAR(256) NOT NULL, "type" bigint, "description" VARCHAR(512), "access_time" bigint, "source" VARCHAR(512))`
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsCookies)
	return err
}

// SelectCookies ...
func (dal *MyDAL) SelectCookiesByAppID(appID int64) []*models.Cookie {
	const sqlSelectCookies = `SELECT "id","name","path","vendor","type","description","access_time","source" FROM "cookies" WHERE "app_id"=$1 ORDER BY "type"`
	rows, err := dal.db.Query(sqlSelectCookies, appID)
	if err != nil {
		utils.DebugPrintln("SelectCookiesByAppID", err)
	}
	defer rows.Close()
	cookies := []*models.Cookie{}
	for rows.Next() {
		cookie := &models.Cookie{AppID: appID}
		_ = rows.Scan(&cookie.ID, &cookie.Name, &cookie.Path, &cookie.Vendor, &cookie.Type, &cookie.Description, &cookie.AccessTime, &cookie.Source)
		cookies = append(cookies, cookie)
	}
	return cookies
}

func (dal *MyDAL) InsertNewCookie(cookie *models.Cookie) error {
	const sqlInsertCookie = `INSERT INTO "cookies"("id","app_id","name","path","vendor","type","description","access_time","source") VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	if cookie.ID == 0 {
		cookie.ID = utils.GenSnowflakeID()
	}
	_, err := dal.db.Exec(sqlInsertCookie, cookie.ID, cookie.AppID, cookie.Name, cookie.Path, cookie.Vendor, cookie.Type, cookie.Description, cookie.AccessTime, cookie.Source)
	return err
}
