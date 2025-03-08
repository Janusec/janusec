/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2023-06-04 16:00
 */

package data

import (
	"janusec/models"
	"janusec/utils"
)

// CreateTableIfNotExistsDNSRecords ...
func (dal *MyDAL) CreateTableIfNotExistsDNSRecords() error {
	const sqlCreateTableIfNotExistsDNSRecords = `CREATE TABLE IF NOT EXISTS "dns_records"("id" BIGINT PRIMARY KEY, "dns_domain_id" BIGINT, "rrtype" BIGINT, "name" VARCHAR(256) NOT NULL, "value" VARCHAR(256), "ttl" BIGINT, "auto" BOOLEAN DEFAULT FALSE, "internal" BOOLEAN DEFAULT FALSE)`
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsDNSRecords)
	return err
}

// SelectDNSRecordsByDomainID ...
func (dal *MyDAL) SelectDNSRecordsByDomainID(dnsDomainID int64) []*models.DNSRecord {
	const sqlSelectDNSRecords = `SELECT "id","rrtype","name","value","ttl","auto","internal" FROM "dns_records" WHERE "dns_domain_id"=$1 ORDER BY "rrtype"`
	rows, err := dal.db.Query(sqlSelectDNSRecords, dnsDomainID)
	if err != nil {
		utils.DebugPrintln("SelectDNSRecords", err)
	}
	defer rows.Close()
	dnsRecords := []*models.DNSRecord{}
	for rows.Next() {
		dnsRecord := &models.DNSRecord{DNSDomainID: dnsDomainID}
		_ = rows.Scan(&dnsRecord.ID, &dnsRecord.Rrtype, &dnsRecord.Name, &dnsRecord.Value, &dnsRecord.TTL, &dnsRecord.Auto, &dnsRecord.Internal)
		dnsRecords = append(dnsRecords, dnsRecord)
	}
	return dnsRecords
}

func (dal *MyDAL) InsertDNSRecord(dnsRecord *models.DNSRecord) error {
	const sqlInsertDNSRecord = `INSERT INTO "dns_records"("id","dns_domain_id","rrtype","name","value","ttl","auto","internal") VALUES($1,$2,$3,$4,$5,$6,$7,$8)`
	_, err := dal.db.Exec(sqlInsertDNSRecord, dnsRecord.ID, dnsRecord.DNSDomainID, dnsRecord.Rrtype, dnsRecord.Name, dnsRecord.Value, dnsRecord.TTL, dnsRecord.Auto, dnsRecord.Internal)
	return err
}

func (dal *MyDAL) UpdateDNSRecord(dnsRecord *models.DNSRecord) error {
	const sqlUpdateDNSRecord = `UPDATE "dns_records" SET "rrtype"=$1,"name"=$2,"value"=$3,"ttl"=$4,"auto"=$5,"internal"=$6 WHERE "id"=$7`
	_, err := dal.db.Exec(sqlUpdateDNSRecord, dnsRecord.Rrtype, dnsRecord.Name, dnsRecord.Value, dnsRecord.TTL, dnsRecord.Auto, dnsRecord.Internal, dnsRecord.ID)
	return err
}

func (dal *MyDAL) DeleteDNSRecordByID(id int64) error {
	const sqlDelDNSRecord = `DELETE FROM "dns_records" WHERE "id"=$1`
	_, err := dal.db.Exec(sqlDelDNSRecord, id)
	return err
}

func (dal *MyDAL) SelectDNSRecordByID(id int64) (*models.DNSRecord, error) {
	dnsRecord := models.DNSRecord{
		ID: id,
	}
	const sqlSelectDNSRecords = `SELECT "dns_domain_id","rrtype","name","value","ttl","auto","internal" FROM "dns_records" WHERE "id"=$1`
	err := dal.db.QueryRow(sqlSelectDNSRecords, id).Scan(&dnsRecord.DNSDomainID, &dnsRecord.Rrtype, &dnsRecord.Name, &dnsRecord.Value, &dnsRecord.TTL, &dnsRecord.Auto, &dnsRecord.Internal)
	return &dnsRecord, err
}
