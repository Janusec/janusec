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

	"janusec/models"
	"janusec/utils"

	// PostgreSQL
	_ "github.com/lib/pq"
	//_ "github.com/mattn/go-sqlite3"
	_ "github.com/glebarez/go-sqlite"
)

// MyDAL used for data access layer
type MyDAL struct {
	db *sql.DB
}

var (
	// DAL is Data Access Layer
	DAL *MyDAL
	// CFG is config
	CFG *models.Config
	// IsPrimary i.e. Is Primary Node
	IsPrimary bool
	// Version of JANUSEC
	Version = "1.4.1"
)

// InitConfig init Data Access Layer
func InitConfig() {
	DAL = &MyDAL{}
	var err error
	CFG, err = NewConfig("./config.json")
	if err != nil {
		utils.DebugPrintln("InitConfig", err)
		os.Exit(1)
	}
	nodeRole := strings.ToLower(CFG.NodeRole)
	if nodeRole != "primary" && nodeRole != "replica" {
		fmt.Printf("Error: node_role %s is not supported, it should be primary or replica, please check config.json \n", nodeRole)
		utils.DebugPrintln("Error: node_role ", nodeRole, " is not supported, it should be primary or replica, please check config.json")
		os.Exit(1)
	}
	IsPrimary = (nodeRole == "primary")
	if IsPrimary {
		switch CFG.PrimaryNode.DatabaseType {
		case "sqlite":
			// SQLite
			conn := "file:./data.sqlite3?_busy_timeout=9999999"
			DAL.db, err = sql.Open("sqlite", conn)
			if err != nil {
				utils.DebugPrintln("InitConfig sql.Open:", err)
				os.Exit(1)
			}
			// Set max conns 1
			DAL.db.SetMaxOpenConns(1)
		default:
			// PostgreSQL
			conn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
				CFG.PrimaryNode.Database.Host,
				CFG.PrimaryNode.Database.Port,
				CFG.PrimaryNode.Database.User,
				CFG.PrimaryNode.Database.Password,
				CFG.PrimaryNode.Database.DBName)
			DAL.db, err = sql.Open("postgres", conn)
			if err != nil {
				utils.DebugPrintln("InitConfig sql.Open:", err)
				os.Exit(1)
			}
			// Check if the User and Password are Correct
			_, err = DAL.db.Query("select 1")
			if err != nil {
				utils.DebugPrintln("InitConfig Failed, Please check the database user and password. Error:", err)
				os.Exit(1)
			}
			// Set max conns 99
			DAL.db.SetMaxOpenConns(99)
		}
	} else {
		// Init Nodes Key for replica node
		NodesKey = NodeHexKeyToCryptKey(CFG.ReplicaNode.NodeKey)
	}
}

// ExecSQL Exec SQL Directly
func (dal *MyDAL) ExecSQL(sql string) error {
	_, err := dal.db.Exec(sql)
	return err
}

// ExistColumnInTable ...
func (dal *MyDAL) ExistColumnInTable(tableName string, columnName string) bool {
	var count int64
	var sql string
	var err error
	switch CFG.PrimaryNode.DatabaseType {
	case "sqlite":
		// SQLite
		// This statement has a bug, if a_uid exists, then uid will be considered as exists
		// sql = `SELECT count(1) FROM sqlite_master WHERE name=? and sql like ?`
		// err = dal.db.QueryRow(sql, tableName, "%"+columnName+"%").Scan(&count)
		sql = fmt.Sprintf(`SELECT count(%s) FROM %s`, columnName, tableName)
		err = dal.db.QueryRow(sql).Scan(&count)
		if err != nil {
			// Not exists
			return false
		}
		return true
	default:
		// PostgreSQL
		sql = `SELECT count(1) FROM information_schema.columns WHERE table_name=$1 AND column_name=$2`
		err = dal.db.QueryRow(sql, tableName, columnName).Scan(&count)
		if err != nil {
			utils.DebugPrintln("PostgreSQL ExistColumnInTable QueryRow", tableName, columnName, err)
		}
		return count > 0
	}
}

// ExistConstraint ...
func (dal *MyDAL) ExistConstraint(tableName string, constraintName string) bool {
	var count int64
	var sql string
	var err error
	switch CFG.PrimaryNode.DatabaseType {
	case "sqlite":
		// SQLite
		// select * from sqlite_master where type='index' and tbl_name='test' and name='uid'
		// For SQLite, create unique index uid on table_name(column1, column2);
		sql = `SELECT count(1) FROM sqlite_master WHERE type='index' AND tbl_name=$1 AND name=$2`
		err = dal.db.QueryRow(sql, tableName, constraintName).Scan(&count)
		if err != nil {
			utils.DebugPrintln("ExistConstraint QueryRow", err)
		}
		return count > 0
	default:
		// PostgreSQL
		sql = `SELECT count(1) FROM information_schema.constraint_column_usage WHERE table_name=$1 and constraint_name=$2`
		err = dal.db.QueryRow(sql, tableName, constraintName).Scan(&count)
		if err != nil {
			utils.DebugPrintln("ExistConstraint QueryRow", err)
		}
		return count > 0
	}
}
