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

	"github.com/Janusec/janusec/data"
	"github.com/Janusec/janusec/models"
	"github.com/Janusec/janusec/utils"
)

var (
	dbNodes  []*models.DBNode
	nodesMap sync.Map //map[int64]*models.Node
)

func LoadNodes() {
	dbNodes = data.DAL.SelectAllNodes()
	for _, dbNode := range dbNodes {
		key := data.NodeHexKeyToCryptKey(dbNode.EncryptedKey)
		node := &models.Node{ID: dbNode.ID, Key: key, Name: dbNode.Name, Version: dbNode.Version, LastIP: dbNode.LastIP, LastRequestTime: dbNode.LastRequestTime}
		nodesMap.Store(node.ID, node)
	}
}

func GetNodes() ([]*models.DBNode, error) {
	return dbNodes, nil
}

func GetDBNodeByID(id int64) (*models.DBNode, error) {
	for _, dbNode := range dbNodes {
		if dbNode.ID == id {
			return dbNode, nil
		}
	}
	return nil, errors.New("Not found.")
}

func GetNodeByID(id int64) *models.Node {
	if node, ok := nodesMap.Load(id); ok {
		return node.(*models.Node)
	} else {
		return nil
	}
}

func UpdateNode(r *http.Request, param map[string]interface{}) (node *models.DBNode, err error) {
	nodeInterface := param["object"].(map[string]interface{})
	nodeID := int64(nodeInterface["id"].(float64))
	name := nodeInterface["name"].(string)
	if nodeID == 0 {
		keyBytes := data.GenRandomAES256Key()
		hexKey := data.CryptKeyToNodeHexKey(keyBytes)
		srcIP := "unknown"
		nodeVersion := "unknown"
		newID := data.DAL.InsertNode(hexKey, name, nodeVersion, srcIP, 0)
		node := &models.Node{ID: newID, Key: keyBytes, Name: name, Version: nodeVersion, LastIP: srcIP, LastRequestTime: 0}
		dbNode := &models.DBNode{ID: newID, EncryptedKey: hexKey, Name: name, Version: nodeVersion, LastIP: srcIP, LastRequestTime: 0}
		//nodesMap[newID] = node
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

func IsValidAuthKey(r *http.Request, param map[string]interface{}) bool {
	authKey := param["auth_key"].(string)
	authBytes, err := hex.DecodeString(authKey)
	if err != nil {
		return false
	}
	nodeID := int64(param["node_id"].(float64))
	node := GetNodeByID(nodeID)
	decryptedAuthBytes, err := data.DecryptWithKey(authBytes, node.Key)
	utils.CheckError("IsValidAuthKey DecryptWithKey", err)
	if err != nil {
		return false
	}
	// check id and timestamp
	nodeAuth := new(models.NodeAuth)
	err = json.Unmarshal(decryptedAuthBytes, nodeAuth)
	utils.CheckError("IsValidAuthKey Unmarshal", err)

	if nodeAuth.NodeID != nodeID {
		return false
	}
	curTime := time.Now().Unix()
	secondsDiff := math.Abs(float64(curTime - nodeAuth.CurTime))
	if secondsDiff > 180.0 {
		return false
	}
	srcIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	nodeVersion := param["node_version"].(string)
	node.Version = nodeVersion
	node.LastIP = srcIP
	node.LastRequestTime = curTime
	dbNode, err := GetDBNodeByID(nodeID)
	utils.CheckError("IsValidAuthKey GetDBNodeByID", err)
	dbNode.Version = nodeVersion
	dbNode.LastIP = srcIP
	dbNode.LastRequestTime = curTime
	data.DAL.UpdateNodeLastInfo(nodeVersion, srcIP, curTime, nodeID)
	return true
}
