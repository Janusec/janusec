/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2020-05-17 22:40:35
 * @Last Modified: U2, 2020-05-17 22:40:35
 */

package data

import "janusec/models"

// CreateTableIfNotExistsTOTP init table
func (dal *MyDAL) CreateTableIfNotExistsTOTP() error {
	const sqlCreateTableIfNotExistsTOTP = `CREATE TABLE IF NOT EXISTS totp(id bigserial PRIMARY KEY, uid varchar(128), totp_key varchar(128), totp_verified boolean)`
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsTOTP)
	return err
}

// GetTOTPIDByUID return id
/*
func (dal *MyDAL) GetTOTPIDByUID(uid string) (id int64, err error) {
	const sqlGetTOTP = `select id from totp where uid=$1`
	err = dal.db.QueryRow(sqlGetTOTP, uid).Scan(&id)
	return id, err
}
*/

// GetTOTPItemByUID return object
func (dal *MyDAL) GetTOTPItemByUID(uid string) (*models.TOTP, error) {
	var totpItem = new(models.TOTP)
	const sqlGetTOTP = `select id,uid,totp_key,totp_verified from totp where uid=$1`
	err := dal.db.QueryRow(sqlGetTOTP, uid).Scan(&totpItem.ID, &totpItem.UID, &totpItem.TOTPKey, &totpItem.TOTPVerified)
	return totpItem, err
}

// InsertTOTPItem insert new totp item
func (dal *MyDAL) InsertTOTPItem(uid string, totpKey string, totpVerified bool) (id int64, err error) {
	const sqlInsertTOTP = `insert into totp(uid,totp_key,totp_verified) values($1,$2,$3) RETURNING id`
	err = dal.db.QueryRow(sqlInsertTOTP, uid, totpKey, totpVerified).Scan(&id)
	return id, err
}

// UpdateTOTPVerified set verified
func (dal *MyDAL) UpdateTOTPVerified(totpVerified bool, id int64) error {
	const sqlUpdateTOTP = `UPDATE totp SET totp_verified=$1 WHERE id=$2`
	_, err := dal.db.Exec(sqlUpdateTOTP, totpVerified, id)
	return err
}
