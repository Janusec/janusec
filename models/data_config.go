/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:38:49
 * @Last Modified: U2, 2018-07-14 16:38:49
 */

package models

type Config struct {
	NodeID     int64            `json:"node_id"`
	NodeRole   string           `json:"node_role"`
	MasterNode MasterNodeConfig `json:"master_node"`
	SlaveNode  SlaveNodeConfig  `json:"slave_node"`
}

type MasterNodeConfig struct {
	AdminHTTPListen  string   `json:"admin_http_listen"`
	AdminHTTPSListen string   `json:"admin_https_listen"`
	Database         DBConfig `json:"database"`
}

type SlaveNodeConfig struct {
	NodeKey  string `json:"node_key"`
	SyncAddr string `json:"sync_addr"`
}

type DBConfig struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	DBName   string `json:"dbname"`
}

type EncryptedConfig struct {
	NodeID     int64            `json:"node_id"`
	NodeRole   string           `json:"node_role"`
	MasterNode MasterNodeConfig `json:"master_node"`
	SlaveNode  SlaveNodeConfig  `json:"slave_node"`
}
