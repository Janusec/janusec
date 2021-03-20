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
	"janusec/backend"
	"janusec/data"
	"janusec/models"
	"janusec/utils"
	"net/http"
	"net/url"
	"sync"
	"time"
)

var (
	// statMap format: sync.Map[app_id][*sync.Map]
	// key: app_id
	// value: * sync.map[url_path][count]
	statMap = sync.Map{}

	// refererMap format: sync.Map[refererHost][*sync.Map]
	// sync.Map[appID][refererHost][url][clientID][count]
	// key: refererHost, such as: www.janusec.com
	// Table:
	// appID   referer_host      referer_url      clientID    pv      statDate (DB Only)
	// 1       www.janusec.com   /data            SHA(IP+UA)  5       xxx
	// 2       www.google.com    /                SHA(IP+UA)  10      zzz
	/* Example: {
		"1": {"www.janusec.com": {"/data": {"HASH01": 99,	"HASH02": 10} } }
	   }
	*/
	refererMap = sync.Map{}
)

// InitAccessStat init table
func InitAccessStat() {
	if data.IsPrimary {
		err := data.DAL.CreateTableIfNotExistsAccessStats()
		if err != nil {
			utils.DebugPrintln("InitAccessStat AccessStats", err)
			return
		}

		err = data.DAL.CreateTableIfNotExistsRefererStats()
		if err != nil {
			utils.DebugPrintln("InitAccessStat RefererStats", err)
			return
		}
	}

	// synchronize statMap to database periodically
	statTicker := time.NewTicker(time.Duration(1) * time.Minute)
	for range statTicker.C {
		now := time.Now()
		statDate := now.Format("20060102")
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

		refererMap.Range(func(key, value interface{}) bool {
			appID := key.(int64)
			hostMap := value.(*sync.Map)
			hostMap.Range(func(key, value interface{}) bool {
				refererHost := key.(string)
				pathMap := value.(*sync.Map)
				pathMap.Range(func(key, value interface{}) bool {
					refererPath := key.(string)
					clientMap := value.(*sync.Map)
					clientMap.Range(func(key, value interface{}) bool {
						clientID := key.(string)
						count := value.(int64)
						//fmt.Println("Referer:", appID, refererHost, refererPath, clientID, count)
						// Add to database
						go IncRefererStatToDB(appID, refererHost, refererPath, clientID, count)
						// Clear
						clientMap.Delete(clientID)
						return true
					})
					// Clear
					pathMap.Delete(refererPath)
					return true
				})
				hostMap.Delete(refererHost)
				return true
			})
			refererMap.Delete(appID)
			return true
		})

		// check offline destinations
		backend.CheckOfflineDestinations(now.Unix())
		backend.CheckOfflineVipTargets(now.Unix())
	}
}

// IncAmountToDB sync to database
func IncAmountToDB(appID int64, urlPath string, statDate string, delta int64, updateTime int64) {
	if data.IsPrimary {
		_ = data.DAL.IncAmount(appID, urlPath, statDate, delta, updateTime)
	} else {
		// Replica Node
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
func GetTodayPopularContent(param map[string]interface{}) (topPaths []*models.PopularContent, err error) {
	appID := int64(param["app_id"].(float64))
	statDate := time.Now().Format("20060102")
	topPaths, err = data.DAL.GetPopularContent(appID, statDate)
	return topPaths, err
}

// IncRefererStat increase referer statistics
func IncRefererStat(appID int64, referer string, srcIP string, userAgent string) {
	hostMapI, _ := refererMap.LoadOrStore(appID, &sync.Map{})
	refererURL, _ := url.Parse(referer)
	pathMapI, _ := hostMapI.(*sync.Map).LoadOrStore(refererURL.Host, &sync.Map{})
	clientMapI, _ := pathMapI.(*sync.Map).LoadOrStore(referer, &sync.Map{})
	clientID := data.SHA256Hash(srcIP + userAgent)
	clientMap := clientMapI.(*sync.Map)
	countI, _ := clientMap.LoadOrStore(clientID, int64(0))
	count := countI.(int64) + 1
	clientMap.Store(clientID, count)
}

// IncRefererStatToDB increase referer statistics to database
func IncRefererStatToDB(appID int64, host string, path string, clientID string, deltaCount int64) {
	now := time.Now()
	dateTimestamp := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).Unix()
	if data.IsPrimary {
		err := data.DAL.UpdateRefererStat(appID, host, path, clientID, deltaCount, dateTimestamp)
		if err != nil {
			utils.DebugPrintln("IncRefererStatToDB", err)
		}
		return
	}
	// Replica node
	fmt.Println("IncRefererStatToDB Replica node ToDo")
}

// GetRefererHosts ...
func GetRefererHosts(param map[string]interface{}) (topReferers []*models.RefererHost, err error) {
	appID := int64(param["app_id"].(float64))
	now := time.Now()
	statTime := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).Unix() - 86400*14
	topReferers, err = data.DAL.GetRefererHosts(appID, statTime)
	return topReferers, err
}

// GetRefererURLs ...
func GetRefererURLs(param map[string]interface{}) (topRefererURLs []*models.RefererURL, err error) {
	appID := int64(param["app_id"].(float64))
	host := param["host"].(string)
	now := time.Now()
	statTime := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).Unix() - 86400*14
	topRefererURLs, err = data.DAL.GetRefererURLs(appID, host, statTime)
	return topRefererURLs, err
}