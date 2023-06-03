/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2023-06-03 12:18:07
 */

package data

import (
	"janusec/models"
	"janusec/utils"
)

// CreateTableIfNotExistsCookieRefs ...
func (dal *MyDAL) CreateTableIfNotExistsCookieRefs() error {
	const sqlCreateTableIfNotExistsCookieRefs = `CREATE TABLE IF NOT EXISTS "cookie_refs"("id" bigserial PRIMARY KEY, "name" VARCHAR(256) NOT NULL, "vendor" VARCHAR(256), "type" bigint, "description" VARCHAR(512), "operation" bigint)`
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsCookieRefs)
	return err
}

// SelectCookieRefs ...
func (dal *MyDAL) SelectCookieRefs() []*models.CookieRef {
	const sqlSelectCookieRefs = `SELECT "id","name","vendor","type","description","operation" FROM "cookie_refs" ORDER BY "type"`
	rows, err := dal.db.Query(sqlSelectCookieRefs)
	if err != nil {
		utils.DebugPrintln("SelectCookieRefsByAppID", err)
	}
	defer rows.Close()
	cookie_refs := []*models.CookieRef{}
	for rows.Next() {
		cookieRef := &models.CookieRef{}
		_ = rows.Scan(&cookieRef.ID, &cookieRef.Name, &cookieRef.Vendor, &cookieRef.Type, &cookieRef.Description, &cookieRef.Operation)
		cookie_refs = append(cookie_refs, cookieRef)
	}
	return cookie_refs
}

func (dal *MyDAL) InsertCookieRef(cookieRef *models.CookieRef) error {
	const sqlInsertCookie = `INSERT INTO "cookie_refs"("id","name","vendor","type","description","operation") VALUES($1,$2,$3,$4,$5,$6)`
	_, err := dal.db.Exec(sqlInsertCookie, cookieRef.ID, cookieRef.Name, cookieRef.Vendor, cookieRef.Type, cookieRef.Description, cookieRef.Operation)
	return err
}

func (dal *MyDAL) UpdateCookieRef(cookieRef *models.CookieRef) error {
	const sqlUpdateCookie = `UPDATE "cookie_refs" SET "name"=$1,"vendor"=$2,"type"=$3,"description"=$4,"operation"=$5 WHERE "id"=$6`
	_, err := dal.db.Exec(sqlUpdateCookie, cookieRef.Name, cookieRef.Vendor, cookieRef.Type, cookieRef.Description, cookieRef.Operation, cookieRef.ID)
	return err
}

func (dal *MyDAL) DeleteCookieRefByID(id int64) error {
	const sqlDelCookie = `DELETE FROM "cookie_refs" WHERE "id"=$1`
	_, err := dal.db.Exec(sqlDelCookie, id)
	return err
}

func (dal *MyDAL) SelectCookieRefByID(id int64) (*models.CookieRef, error) {
	cookieRef := models.CookieRef{
		ID: id,
	}
	const sqlSelectCookieRefs = `SELECT "name","vendor","type","description","operation" FROM "cookie_refs" WHERE "id"=$1`
	err := dal.db.QueryRow(sqlSelectCookieRefs, id).Scan(&cookieRef.Name, &cookieRef.Vendor, &cookieRef.Type, &cookieRef.Description, &cookieRef.Operation)
	return &cookieRef, err
}

func (dal *MyDAL) SelectCookieRefsCount() int64 {
	var count int64
	const sqlSelectCookieRefsCount = `SELECT COUNT(1) FROM "cookie_refs"`
	err := dal.db.QueryRow(sqlSelectCookieRefsCount).Scan(&count)
	if err != nil {
		utils.DebugPrintln("SelectCookieRefsCount QueryRow", err)
	}
	return count
}
