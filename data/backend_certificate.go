/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:24:23
 * @Last Modified: U2, 2018-07-14 16:24:23
 */

package data

import (
	"crypto/x509"
	"encoding/pem"

	"janusec/models"
	"janusec/utils"
)

const (
	sqlCreateTableIfNotExistsCertificates = `CREATE TABLE IF NOT EXISTS "certificates"("id" bigserial primary key,"common_name" VARCHAR(256) not null,"pub_cert" VARCHAR(16384) not null,"priv_key" bytea not null,"expire_time" bigint,"description" VARCHAR(256))`
	sqlSelectCertificates                 = `SELECT "id","common_name","pub_cert","priv_key","expire_time","description" FROM "certificates"`
	sqlInsertCertificate                  = `INSERT INTO "certificates"("common_name","pub_cert","priv_key","expire_time","description") VALUES($1,$2,$3,$4,$5) RETURNING "id"`
	sqlUpdateCertificate                  = `UPDATE "certificates" SET "common_name"=$1,"pub_cert"=$2,"priv_key"=$3,"expire_time"=$4,"description"=$5 WHERE "id"=$6`
	sqlDeleteCertificate                  = `DELETE FROM "certificates" WHERE "id"=$1`
)

// CreateTableIfNotExistsCertificates ...
func (dal *MyDAL) CreateTableIfNotExistsCertificates() error {
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsCertificates)
	return err
}

// SelectCertificates ...
func (dal *MyDAL) SelectCertificates() []*models.DBCertItem {
	rows, err := dal.db.Query(sqlSelectCertificates)
	if err != nil {
		utils.DebugPrintln("SelectCertificates", err)
	}
	defer rows.Close()
	var dbCerts = []*models.DBCertItem{}
	for rows.Next() {
		dbCert := &models.DBCertItem{}
		_ = rows.Scan(&dbCert.ID, &dbCert.CommonName,
			&dbCert.CertContent, &dbCert.EncryptedPrivKey,
			&dbCert.ExpireTime, &dbCert.Description)
		dbCerts = append(dbCerts, dbCert)
	}
	return dbCerts
}

// InsertCertificate ...
func (dal *MyDAL) InsertCertificate(commonName string, certContent string, encryptedPrivKey []byte, expireTime int64, description string) (newID int64) {
	err := dal.db.QueryRow(sqlInsertCertificate, commonName, certContent, encryptedPrivKey, expireTime, description).Scan(&newID)
	if err != nil {
		utils.DebugPrintln("InsertCertificate", err)
	}
	return newID
}

// UpdateCertificate ...
func (dal *MyDAL) UpdateCertificate(commonName string, certContent string, encryptedPrivKey []byte, expireTime int64, description string, id int64) error {
	stmt, _ := dal.db.Prepare(sqlUpdateCertificate)
	defer stmt.Close()
	_, err := stmt.Exec(commonName, certContent, encryptedPrivKey, expireTime, description, id)
	if err != nil {
		utils.DebugPrintln("UpdateCertificate", err)
	}
	return err
}

// DeleteCertificate by id
func (dal *MyDAL) DeleteCertificate(certID int64) error {
	stmt, _ := dal.db.Prepare(sqlDeleteCertificate)
	defer stmt.Close()
	_, err := stmt.Exec(certID)
	if err != nil {
		utils.DebugPrintln("DeleteCertificate", err)
	}
	return err
}

// GetCertificateExpiryTime ...
func GetCertificateExpiryTime(certPem string) int64 {
	block, _ := pem.Decode([]byte(certPem))
	if block == nil {
		//fmt.Println("GetCertificateExpiryTime: failed to parse certificate PEM")
		return 0
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		utils.DebugPrintln("GetCertificateExpiryTime", err)
		return 0
	}
	return cert.NotAfter.Unix()
}
