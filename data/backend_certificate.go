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

	"../models"
	"../utils"
)

const (
	sqlCreateTableIfNotExistsCertificates = `CREATE TABLE IF NOT EXISTS certificates(id bigserial primary key,common_name varchar(256) not null,pub_cert varchar(16384) not null,priv_key bytea not null,expire_time bigint,description varchar(256))`
	sqlSelectCertificates                 = `SELECT id,common_name,pub_cert,priv_key,expire_time,description FROM certificates`
	sqlInsertCertificate                  = `INSERT INTO certificates(common_name,pub_cert,priv_key,expire_time,description) VALUES($1,$2,$3,$4,$5) RETURNING id`
	sqlUpdateCertificate                  = `UPDATE certificates SET common_name=$1,pub_cert=$2,priv_key=$3,expire_time=$4,description=$5 WHERE id=$6`
	sqlDeleteCertificate                  = `DELETE FROM certificates WHERE id=$1`
)

func (dal *MyDAL) CreateTableIfNotExistsCertificates() error {
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsCertificates)
	return err
}

func (dal *MyDAL) SelectCertificates() []*models.DBCertItem {
	rows, err := dal.db.Query(sqlSelectCertificates)
	utils.CheckError("SelectCertificates", err)
	defer rows.Close()
	var db_certs []*models.DBCertItem
	for rows.Next() {
		db_cert := new(models.DBCertItem)
		err = rows.Scan(&db_cert.ID, &db_cert.CommonName,
			&db_cert.CertContent, &db_cert.EncryptedPrivKey,
			&db_cert.ExpireTime, &db_cert.Description)
		db_certs = append(db_certs, db_cert)
	}
	return db_certs
}

func (dal *MyDAL) InsertCertificate(common_name string, cert_content string, encrypted_priv_key []byte, expire_time int64, description string) (new_id int64) {
	err := dal.db.QueryRow(sqlInsertCertificate, common_name, cert_content, encrypted_priv_key, expire_time, description).Scan(&new_id)
	utils.CheckError("InsertCertificate", err)
	return new_id
}

func (dal *MyDAL) UpdateCertificate(common_name string, cert_content string, encrypted_priv_key []byte, expire_time int64, description string, id int64) error {
	stmt, err := dal.db.Prepare(sqlUpdateCertificate)
	defer stmt.Close()
	_, err = stmt.Exec(common_name, cert_content, encrypted_priv_key, expire_time, description, id)
	utils.CheckError("UpdateCertificate", err)
	return err
}

func (dal *MyDAL) DeleteCertificate(cert_id int64) error {
	stmt, err := dal.db.Prepare(sqlDeleteCertificate)
	defer stmt.Close()
	_, err = stmt.Exec(cert_id)
	utils.CheckError("DeleteCertificate", err)
	return err
}

func GetCertificateExpiryTime(cert_pem string) int64 {
	block, _ := pem.Decode([]byte(cert_pem))
	if block == nil {
		//fmt.Println("GetCertificateExpiryTime: failed to parse certificate PEM")
		return 0
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	utils.CheckError("GetCertificateExpiryTime", err)
	if err != nil {
		return 0
	}
	return cert.NotAfter.Unix()
}
