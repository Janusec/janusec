/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:23:50
 * @Last Modified: U2, 2018-07-14 16:23:50
 */

package data

import (
	"database/sql"
	"fmt"
	"os"
	"strings"

	"github.com/Janusec/janusec/models"
	"github.com/Janusec/janusec/utils"
	_ "github.com/lib/pq"
)

type MyDAL struct {
	db *sql.DB
}

var (
	DAL      *MyDAL
	CFG      *models.Config
	IsMaster bool
	Version  string = "0.9.7"
	NodeKey  []byte
)

func InitDAL() {
	DAL = new(MyDAL)
	var err error
	CFG, err = NewConfig("./config.json")
	utils.CheckError("InitDAL", err)
	if err != nil {
		os.Exit(1)
	}
	IsMaster = (strings.ToLower(CFG.NodeRole) == "master")
	if IsMaster {
		conn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
			CFG.MasterNode.Database.Host,
			CFG.MasterNode.Database.Port,
			CFG.MasterNode.Database.User,
			CFG.MasterNode.Database.Password,
			CFG.MasterNode.Database.DBName)
		DAL.db, err = sql.Open("postgres", conn)
		utils.CheckError("InitDAL sql.Open:", err)
		if err != nil {
			os.Exit(1)
		}
		DAL.db.SetMaxOpenConns(99)
	} else {
		// Init Node Key (Share with master)
		NodeKey = NodeHexKeyToCryptKey(CFG.SlaveNode.NodeKey)
	}
}

func (dal *MyDAL) ExecSQL(sql string) error {
	_, err := dal.db.Exec(sql)
	return err
}

func (dal *MyDAL) ExistColumnInTable(tableName string, columnName string) bool {
	var count int64
	const sql = `select count(1) from information_schema.columns where table_name=$1 and column_name=$2`
	err := dal.db.QueryRow(sql, tableName, columnName).Scan(&count)
	utils.CheckError("ExistColumnInTable QueryRow", err)
	if count > 0 {
		return true
	}
	return false
}
