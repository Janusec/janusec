/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2020-10-08 08:41:07
 * @Last Modified: U2, 2020-10-08 08:41:07
 */

package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"janusec/data"
	"janusec/models"
	"janusec/utils"
	"net/http"
	"sync"
	"time"
)

var (
	// statMap format: sync.Map[app_id][*sync.Map]
	// key: app_id
	// value: * sync.map[url_path][count]
	statMap sync.Map
)

// InitAccessStat init table
func InitAccessStat() {
	if data.IsPrimary {
		err := data.DAL.CreateTableIfNotExistsAccessStats()
		if err != nil {
			utils.DebugPrintln("InitAccessStat", err)
			return
		}
	}

	// synchronize statMap to database periodically
	statTicker := time.NewTicker(time.Duration(2) * time.Minute)
	now := time.Now()
	statDate := now.Format("20060102")
	expiredTime := now.Unix() - 86400*14
	for range statTicker.C {
		if data.IsPrimary {
			// Clear expired access statistics
			go data.DAL.ClearExpiredAccessStats(expiredTime)
		}
		statMap.Range(func(key, value interface{}) bool {
			appID := key.(int64)
			pathMap := value.(*sync.Map)
			pathMap.Range(func(key, value interface{}) bool {
				urlPath := key.(string)
				delta := value.(int64)
				// Add to database
				go IncAmountToDB(appID, urlPath, statDate, delta, now.Unix())
				// Clear
				pathMap.Delete(urlPath)
				return true
			})
			return true
		})
	}
}

// IncAmountToDB sync to database
func IncAmountToDB(appID int64, urlPath string, statDate string, delta int64, updateTime int64) {
	if data.IsPrimary {
		_ = data.DAL.IncAmount(appID, urlPath, statDate, delta, updateTime)
	} else {
		// Replica Node
		fmt.Println("To Do: IncAmountToDB")
		accessStat := &models.AccessStat{
			AppID:      appID,
			URLPath:    urlPath,
			StatDate:   statDate,
			Delta:      delta,
			UpdateTime: updateTime,
		}
		// RPC IncAmountToDB(accessStat)
		rpcRequest := &models.RPCRequest{
			Action: "inc_stat", Object: accessStat}
		_, err := data.GetRPCResponse(rpcRequest)
		if err != nil {
			utils.DebugPrintln("IncAmountToDB GetRPCResponse", err)
		}
	}
}

// ReplicaIncAccessStat receive RPC request and update to database
func ReplicaIncAccessStat(r *http.Request) error {
	var statReq models.RPCStatRequest
	err := json.NewDecoder(r.Body).Decode(&statReq)
	if err != nil {
		utils.DebugPrintln("ReplicaIncAccessStat Decode", err)
	}
	defer r.Body.Close()

	accessStat := statReq.Object
	if accessStat == nil {
		return errors.New("ReplicaIncAccessStat parse body null")
	}
	return data.DAL.IncAmount(accessStat.AppID, accessStat.URLPath, accessStat.StatDate, accessStat.Delta, accessStat.UpdateTime)
}

// IncAccessStat increase stat count in statMap
func IncAccessStat(appID int64, urlPath string) {
	pathMapI, _ := statMap.LoadOrStore(appID, &sync.Map{})
	pathMap := pathMapI.(*sync.Map)
	countI, _ := pathMap.LoadOrStore(urlPath, int64(0))
	count := countI.(int64) + 1
	pathMap.Store(urlPath, count)
}

// GetAccessStat return access statistics
func GetAccessStat(param map[string]interface{}) (accessStat []int64, err error) {
	appID := int64(param["app_id"].(float64))
	beginTime := time.Now().Add(-13 * 24 * time.Hour)
	for i := 0; i < 14; i++ {
		statDate := beginTime.Add(time.Duration(i) * 24 * time.Hour).Format("20060102")
		count := data.DAL.GetAccessStatByAppIDAndDate(appID, statDate)
		accessStat = append(accessStat, count)
	}
	return accessStat, nil
}

// GetTodayPopularContent return top visited URL Path of today
func GetTodayPopularContent(param map[string]interface{}) (topPaths []models.PopularContent, err error) {
	appID := int64(param["app_id"].(float64))
	statDate := time.Now().Format("20060102")
	topPaths, err = data.DAL.GetPopularContent(appID, statDate)
	return topPaths, err
}
