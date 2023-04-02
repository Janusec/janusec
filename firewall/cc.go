/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:33:22
 * @Last Modified: U2, 2018-07-14 16:33:22
 */

package firewall

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"janusec/data"
	"janusec/models"
	"janusec/utils"
)

var (
	ccPoliciesList = []*models.CCPolicy{}
	ccPolicies     = sync.Map{} //map[int64]*models.CCPolicy // key: appID==0  Global Policy
	ccCounts       = sync.Map{} //map[int64]*(map[string]*models.ClientStat) // appID, clientID, ClientStat
	ccTickers      = sync.Map{} //map[int64]*time.Ticker
)

// ClearCCStatByClientID clear CC stat by client id
func ClearCCStatByClientID(policyAppID int64, clientID string) {
	if ccCount, ok := ccCounts.Load(policyAppID); ok {
		appCCCount := ccCount.(*sync.Map)
		appCCCount.Delete(clientID)
	}
}

// CCAttackTick CC tick
func CCAttackTick(appID int64) {
	if appCCTicker, ok := ccTickers.Load(appID); ok {
		ccTicker := appCCTicker.(*time.Ticker)
		ccTicker.Stop()
	}
	ccPolicyMap, _ := ccPolicies.Load(appID)
	ccPolicy := ccPolicyMap.(*models.CCPolicy)
	ccTicker := time.NewTicker(time.Duration(ccPolicy.IntervalMilliSeconds) * time.Millisecond)

	ccTickers.Store(appID, ccTicker)
	for range ccTicker.C {
		ccCount, _ := ccCounts.LoadOrStore(appID, &sync.Map{})
		//fmt.Println("CCAttackTick AppID=", appID, time.Now())
		appCCCount := ccCount.(*sync.Map)
		appCCCount.Range(func(key, value interface{}) bool {
			clientID := key.(string)
			stat := value.(*models.ClientStat)
			//fmt.Println("CCAttackTick:", appID, clientID, stat)
			stat.Mutex.Lock()
			defer stat.Mutex.Unlock()
			if stat.IsBadIP {
				stat.RemainSeconds -= ccPolicy.IntervalMilliSeconds / 1000.0
				if stat.RemainSeconds <= 0 {
					appCCCount.Delete(clientID)
				}
				return true
			}
			if stat.QuickCount >= ccPolicy.MaxCount {
				// Trigger high frequency CC
				stat.QuickCount = 0
				stat.IsBadIP = true
				stat.RemainSeconds = ccPolicy.BlockSeconds
				return true
			}
			if stat.SlowCount >= ccPolicy.MaxCount {
				// Trigger low frequency CC
				stat.QuickCount = 0
				stat.SlowCount = 0
				stat.IsBadIP = true
				stat.RemainSeconds = ccPolicy.BlockSeconds
				return true
			}
			// Not CC
			stat.TimeFrameCount++
			if stat.TimeFrameCount >= 15 {
				appCCCount.Delete(clientID)
				return true
			}
			stat.SlowCount += stat.QuickCount
			stat.QuickCount = 0
			return true
		})
	}
}

// GetCCPolicyByAppID get CC policy by app id
func GetCCPolicyByAppID(appID int64) *models.CCPolicy {
	if ccPolicy, ok := ccPolicies.Load(appID); ok {
		return ccPolicy.(*models.CCPolicy)
	}
	ccPolicy, _ := ccPolicies.Load(int64(0))
	return ccPolicy.(*models.CCPolicy)
}

// GetCCPolicies get all CC policies
func GetCCPolicies() ([]*models.CCPolicy, error) {
	return ccPoliciesList, nil
}

// GetCCPolicyRespByAppID get CC policy by app id
func GetCCPolicyRespByAppID(appID int64) (*models.CCPolicy, error) {
	ccPolicy := GetCCPolicyByAppID(appID)
	return ccPolicy, nil
}

// IsCCAttack to judge a request is CC attack, return IsCC, CCPolicy, ClientID, NeedLog
func IsCCAttack(r *http.Request, app *models.Application, srcIP string) (bool, *models.CCPolicy, string, bool) {
	ccPolicy := GetCCPolicyByAppID(app.ID)
	if !ccPolicy.IsEnabled || ccPolicy.Action == models.Action_Pass_400 {
		return false, nil, "", false
	}
	ccAppID := app.ID
	if ccPolicy.AppID == 0 {
		ccAppID = 0 // Important: stat within general policy
	}
	ccCount, _ := ccCounts.LoadOrStore(ccAppID, &sync.Map{})
	appCCCount := ccCount.(*sync.Map)
	preHashContent := srcIP
	if ccPolicy.StatByURL {
		preHashContent += r.URL.Path
	}
	if ccPolicy.StatByUserAgent {
		ua := r.Header.Get("User-Agent")
		preHashContent += ua
	}
	if ccPolicy.StatByCookie {
		cookie := r.Header.Get("Cookie")
		preHashContent += cookie
	}
	clientID := data.SHA256Hash(preHashContent)
	clientIDStat, _ := appCCCount.LoadOrStore(clientID, &models.ClientStat{QuickCount: 0, SlowCount: 0, TimeFrameCount: 0, IsBadIP: false, RemainSeconds: 0})
	clientStat := clientIDStat.(*models.ClientStat)
	clientStat.Mutex.Lock()
	defer clientStat.Mutex.Unlock()
	if clientStat.IsBadIP {
		needLog := false
		if clientStat.QuickCount == 0 {
			clientStat.QuickCount++
			needLog = true
		}
		return true, ccPolicy, clientID, needLog
	}
	clientStat.QuickCount++
	return false, nil, "", false
}

// InitCCPolicy init CC policy
func InitCCPolicy() {
	//var cc_policies_list []*models.CCPolicy
	if data.IsPrimary {
		err := data.DAL.CreateTableIfNotExistsCCPolicy()
		if err != nil {
			utils.DebugPrintln("InitCCPolicy CreateTableIfNotExistsCCPolicy", err)
		}
		existCCPolicy := data.DAL.ExistsCCPolicy()
		if !existCCPolicy {
			err = data.DAL.InsertCCPolicy(0, 100, 6, 900, models.Action_Block_100, true, false, false, true)
			if err != nil {
				utils.DebugPrintln("InitCCPolicy InsertCCPolicy", err)
			}
		}
		ccPoliciesList = data.DAL.SelectCCPolicies()
	} else {
		ccPoliciesList = RPCSelectCCPolicies()
	}
	for _, ccPolicy := range ccPoliciesList {
		ccPolicies.Store(ccPolicy.AppID, ccPolicy)
		//fmt.Println("InitCCPolicy:", ccPolicy.AppID, ccPolicy)
	}
}

// UpdateCCPolicy update CC policy
func UpdateCCPolicy(body []byte, clientIP string, authUser *models.AuthUser) error {
	if !authUser.IsSuperAdmin {
		return errors.New("only super administrators can perform this operation")
	}
	var rpcCCRequest models.APICCPolicyRequest
	if err := json.Unmarshal(body, &rpcCCRequest); err != nil {
		utils.DebugPrintln("UpdateCCPolicy", err)
		return err
	}
	ccPolicy := rpcCCRequest.Object
	isExistedCCPolicy := data.DAL.ExistsCCPolicyByAppID(ccPolicy.AppID)
	if !isExistedCCPolicy {
		// new policy
		err := data.DAL.InsertCCPolicy(ccPolicy.AppID, ccPolicy.IntervalMilliSeconds, ccPolicy.MaxCount, ccPolicy.BlockSeconds, ccPolicy.Action, ccPolicy.StatByURL, ccPolicy.StatByUserAgent, ccPolicy.StatByCookie, ccPolicy.IsEnabled)
		if err != nil {
			return err
		}
		ccPolicies.Store(ccPolicy.AppID, ccPolicy)
		if ccPolicy.IsEnabled {
			go CCAttackTick(ccPolicy.AppID)
		}
		go utils.OperationLog(clientIP, authUser.Username, "Add CC Policy", strconv.FormatInt(ccPolicy.AppID, 10))
	} else {
		// update policy
		err := data.DAL.UpdateCCPolicy(ccPolicy.IntervalMilliSeconds, ccPolicy.MaxCount, ccPolicy.BlockSeconds, ccPolicy.Action, ccPolicy.StatByURL, ccPolicy.StatByUserAgent, ccPolicy.StatByCookie, ccPolicy.IsEnabled, ccPolicy.AppID)
		if err != nil {
			return err
		}
		// start new ccTicker
		if ccPolicy.IsEnabled {
			go CCAttackTick(ccPolicy.AppID)
		}
		go utils.OperationLog(clientIP, authUser.Username, "Update CC Policy", strconv.FormatInt(ccPolicy.AppID, 10))
	}
	data.UpdateFirewallLastModified()
	return nil
}

// DeleteCCPolicyByAppID delete CC policy by app id
func DeleteCCPolicyByAppID(appID int64, clientIP string, authUser *models.AuthUser, adminRequired bool) error {
	if adminRequired && !authUser.IsSuperAdmin {
		return errors.New("only super admin can delete CC policy")
	}
	if appID == 0 {
		return errors.New("global CC policy cannot be deleted")
	}
	err := data.DAL.DeleteCCPolicy(appID)
	if err != nil {
		utils.DebugPrintln("DeleteCCPolicyByAppID DeleteCCPolicy", err)
	}
	ccPolicies.Delete(appID)
	if appCCTicker, ok := ccTickers.Load(appID); ok {
		ccTicker := appCCTicker.(*time.Ticker)
		if ccTicker != nil {
			ccTicker.Stop()
		}
	}
	go utils.OperationLog(clientIP, authUser.Username, "Delete CC Policy by AppID", strconv.FormatInt(appID, 10))
	data.UpdateFirewallLastModified()
	return nil
}
