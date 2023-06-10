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
	"hash/fnv"
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
	nodes    = []*models.Node{}
	nodesMap = sync.Map{} //map[ip string]*models.Node
)

// LoadNodes ...
func LoadNodes() {
	nodes = data.DAL.SelectAllNodes()
	for _, node := range nodes {
		nodesMap.Store(node.LastIP, node)
	}
}

// GetNodes ...
func GetNodes() ([]*models.Node, error) {
	return nodes, nil
}

// GetNodeByID ...
func GetNodeByID(id int64) (*models.Node, error) {
	for _, node := range nodes {
		if node.ID == id {
			return node, nil
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
	nodesMap.Store(ip, node)
	nodes = append(nodes, node)
	return node
}

// GetNodeIndex ...
func GetNodeIndex(nodeID int64) int {
	for i := 0; i < len(nodes); i++ {
		if nodes[i].ID == nodeID {
			return i
		}
	}
	return -1
}

// DeleteNodeByID ...
func DeleteNodeByID(id int64) error {
	dbNode, err := GetNodeByID(id)
	if err != nil {
		utils.DebugPrintln("DeleteNodeByID", err)
		return err
	}
	nodesMap.Delete(dbNode.LastIP)
	err = data.DAL.DeleteNodeByID(id)
	i := GetNodeIndex(id)
	nodes = append(nodes[:i], nodes[i+1:]...)
	return err
}

/*
func UpdateNode(r *http.Request, param map[string]interface{}) (node *models.DBNode, err error) {
	nodeInterface := param["object"].(map[string]interface{})
	nodeID := int64(nodeInterface["id"].(string))
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

// IsValidAuthKeyFromReplicaNode check whether the request is from legal replica nodes
func IsValidAuthKeyFromReplicaNode(r *http.Request, param map[string]interface{}) bool {
	authKey := param["auth_key"].(string)
	authBytes, err := hex.DecodeString(authKey)
	if err != nil {
		return false
	}
	decryptedAuthBytes, err := data.DecryptWithKey(authBytes, data.NodesKey)
	if err != nil {
		utils.DebugPrintln("IsValidAuthKey DecryptWithKey", err)
		return false
	}
	// check timestamp
	nodeAuth := &models.AuthTime{}
	err = json.Unmarshal(decryptedAuthBytes, nodeAuth)
	if err != nil {
		utils.DebugPrintln("IsValidAuthKey Unmarshal", err)
	}
	curTime := time.Now().Unix()
	secondsDiff := math.Abs(float64(curTime - nodeAuth.CurTime))
	if secondsDiff > 1800.0 {
		return false
	}
	srcIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	nodeVersion := param["node_version"].(string)
	node := GetNodeByIP(srcIP, nodeVersion)
	node.Version = nodeVersion
	node.LastIP = srcIP
	node.LastRequestTime = curTime
	publicIP := param["public_ip"].(string)
	if len(publicIP) > 0 {
		node.PublicIP = publicIP
	}
	err = data.DAL.UpdateNodeLastInfo(nodeVersion, srcIP, curTime, node.ID)
	if err != nil {
		utils.DebugPrintln("IsValidAuthKey UpdateNodeLastInfo", err)
	}
	return true
}

func GetAvailableNodeIP(srcIP string, isInternal bool) string {
	nodesLen := uint32(len(nodes))
	if nodesLen == 0 {
		// return primary node itself
		primaryIP := data.GetPublicIP()
		return primaryIP
	}
	if nodesLen == 1 {
		if isInternal {
			return nodes[0].LastIP
		} else {
			return nodes[0].PublicIP
		}
	} else {
		// nodesLen > 1
		// According to Hash(IP)
		h := fnv.New32a()
		_, err := h.Write([]byte(srcIP))
		if err != nil {
			utils.DebugPrintln("SelectBackendRoute h.Write", err)
		}
		hashUInt32 := h.Sum32()
		nodeIndex := hashUInt32 % nodesLen
		if isInternal {
			return nodes[nodeIndex].LastIP
		} else {
			return nodes[nodeIndex].PublicIP
		}
	}
}
