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
	const sqlCreateTableIfNotExistsCookies = `CREATE TABLE IF NOT EXISTS "cookies"("id" bigserial PRIMARY KEY, "app_id" bigint, "name" VARCHAR(256) NOT NULL, "vendor" VARCHAR(256) NOT NULL, "type" bigint)`
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsCookies)
	return err
}

// SelectCookies ...
func (dal *MyDAL) SelectCookiesByAppID(appID int64) []*models.Cookie {
	const sqlSelectCookies = `SELECT "id","name","vendor","type" FROM "cookies" WHERE "app_id"=$1 ORDER BY "type"`
	rows, err := dal.db.Query(sqlSelectCookies, appID)
	if err != nil {
		utils.DebugPrintln("SelectCookiesByAppID", err)
	}
	defer rows.Close()
	cookies := []*models.Cookie{}
	for rows.Next() {
		cookie := &models.Cookie{AppID: appID}
		_ = rows.Scan(&cookie.ID, &cookie.Name, &cookie.Vendor, &cookie.Type)
		cookies = append(cookies, cookie)
	}
	return cookies
}
