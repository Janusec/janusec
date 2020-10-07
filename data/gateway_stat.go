/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2020-10-07 09:43:07
 * @Last Modified: U2, 2020-10-07 09:43:07
 */

package data

// CreateTableIfNotExistsStats create statistics table
func (dal *MyDAL) CreateTableIfNotExistsStats() error {
	const sqlCreateTableIfNotExistsStats = `CREATE TABLE IF NOT EXISTS access_stats(id bigserial PRIMARY KEY, app_id bigint, url_path varchar(256), stat_date varchar(16), count bigint, update_time bigint)`
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsStats)
	return err
}
