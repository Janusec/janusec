/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:23:05
 * @Last Modified: U2, 2018-07-14 16:23:05
 */

package backend

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/http"
	"sync"
	"time"

	"janusec/data"
	"janusec/models"
	"janusec/utils"
)

var (
	dbNodes  = []*models.DBNode{}
	nodesMap = sync.Map{} //map[ip string]*models.Node
)

// LoadNodes ...
func LoadNodes() {
	dbNodes = data.DAL.SelectAllNodes()
	for _, dbNode := range dbNodes {
		node := &models.Node{ID: dbNode.ID, Version: dbNode.Version, LastIP: dbNode.LastIP, LastRequestTime: dbNode.LastRequestTime}
		nodesMap.Store(node.LastIP, node)
	}
}

// GetNodes ...
func GetNodes() ([]*models.DBNode, error) {
	return dbNodes, nil
}

// GetDBNodeByID ...
func GetDBNodeByID(id int64) (*models.DBNode, error) {
	for _, dbNode := range dbNodes {
		if dbNode.ID == id {
			return dbNode, nil
		}
	}
	return nil, errors.New("not found")
}

// GetNodeByIP ...
func GetNodeByIP(ip string, nodeVersion string) *models.Node {
	if node, ok := nodesMap.Load(ip); ok {
		return node.(*models.Node)
	}
	curTime := time.Now().Unix()
	newID := data.DAL.InsertNode(nodeVersion, ip, curTime)
	node := &models.Node{ID: newID, Version: nodeVersion, LastIP: ip, LastRequestTime: curTime}
	dbNode := &models.DBNode{ID: newID, Version: nodeVersion, LastIP: ip, LastRequestTime: curTime}
	nodesMap.Store(ip, node)
	dbNodes = append(dbNodes, dbNode)
	return node
}

// GetDBNodeIndex ...
func GetDBNodeIndex(nodeID int64) int {
	for i := 0; i < len(dbNodes); i++ {
		if dbNodes[i].ID == nodeID {
			return i
		}
	}
	return -1
}

// DeleteNodeByID ...
func DeleteNodeByID(id int64) error {
	dbNode, err := GetDBNodeByID(id)
	nodesMap.Delete(dbNode.LastIP)
	utils.CheckError("DeleteNodeByID", err)
	err = data.DAL.DeleteNodeByID(id)
	i := GetDBNodeIndex(id)
	dbNodes = append(dbNodes[:i], dbNodes[i+1:]...)
	return err
}

/*
func UpdateNode(r *http.Request, param map[string]interface{}) (node *models.DBNode, err error) {
	nodeInterface := param["object"].(map[string]interface{})
	nodeID := int64(nodeInterface["id"].(float64))
	name := nodeInterface["name"].(string)
	if nodeID == 0 {
		keyBytes := data.GenRandomAES256Key()
		hexKey := data.CryptKeyToNodeHexKey(keyBytes)
		srcIP := "unknown"
		nodeVersion := "unknown"
		newID := data.DAL.InsertNode(nodeVersion, srcIP, 0)
		node := &models.Node{ID: newID, Version: nodeVersion, LastIP: srcIP, LastRequestTime: 0}
		dbNode := &models.DBNode{ID: newID, Version: nodeVersion, LastIP: srcIP, LastRequestTime: 0}
		nodesMap.Store(newID, node)
		dbNodes = append(dbNodes, dbNode)
		return dbNode, nil
	} else {
		data.DAL.UpdateNodeName(name, nodeID)
		node := GetNodeByID(nodeID)
		node.Name = name
		dbNode, _ := GetDBNodeByID(nodeID)
		dbNode.Name = name
		return dbNode, nil
	}
}
*/

// IsValidAuthKey ...
func IsValidAuthKey(r *http.Request, param map[string]interface{}) bool {
	authKey := param["auth_key"].(string)
	authBytes, err := hex.DecodeString(authKey)
	if err != nil {
		return false
	}
	decryptedAuthBytes, err := data.DecryptWithKey(authBytes, data.RootKey)
	if err != nil {
		utils.DebugPrintln("IsValidAuthKey DecryptWithKey", err)
		return false
	}
	// check timestamp
	nodeAuth := &models.NodeAuth{}
	err = json.Unmarshal(decryptedAuthBytes, nodeAuth)
	if err != nil {
		utils.DebugPrintln("IsValidAuthKey Unmarshal", err)
	}
	curTime := time.Now().Unix()
	secondsDiff := math.Abs(float64(curTime - nodeAuth.CurTime))
	if secondsDiff > 180.0 {
		return false
	}
	srcIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	nodeVersion := param["node_version"].(string)
	node := GetNodeByIP(srcIP, nodeVersion)
	node.Version = nodeVersion
	node.LastIP = srcIP
	node.LastRequestTime = curTime
	dbNode, err := GetDBNodeByID(node.ID)
	if err != nil {
		utils.DebugPrintln("IsValidAuthKey GetDBNodeByID", err)
	}
	dbNode.Version = nodeVersion
	dbNode.LastIP = srcIP
	dbNode.LastRequestTime = curTime
	err = data.DAL.UpdateNodeLastInfo(nodeVersion, srcIP, curTime, node.ID)
	if err != nil {
		utils.DebugPrintln("IsValidAuthKey UpdateNodeLastInfo", err)
	}
	return true
}
