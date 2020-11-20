/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:33:30
 * @Last Modified: U2, 2018-07-14 16:33:30
 */

package firewall

import (
	"fmt"
	"sync"

	"janusec/data"
	"janusec/models"
	"janusec/utils"
)

var (
	checkPointCheckItemsMap = sync.Map{} //(models.ChkPoint, []*models.CheckItem)
)

// GetCheckItemIndex ...
func GetCheckItemIndex(checkItems []*models.CheckItem, id int64) int {
	for i := 0; i < len(checkItems); i++ {
		if checkItems[i].ID == id {
			return i
		}
	}
	return -1
}

// DeleteCheckItemByIndex ...
func DeleteCheckItemByIndex(source []*models.CheckItem, index int) []*models.CheckItem {
	lastIndex := len(source) - 1
	source[index] = source[lastIndex]
	return source[:lastIndex]
}

// GetCheckPointMapByCheckItemID ...
func GetCheckPointMapByCheckItemID(checkItem *models.CheckItem, toBeDelete bool) (hitCheckPoint models.ChkPoint, checkPointCheckItems []*models.CheckItem, index int) {
	if toBeDelete {
		// check_point of check_item will not changed.
		if value, ok := checkPointCheckItemsMap.Load(checkItem.CheckPoint); ok {
			checkPointCheckItems = value.([]*models.CheckItem)
			for i, checkPointCheckItem := range checkPointCheckItems {
				if checkPointCheckItem.ID == checkItem.ID {
					hitCheckPoint = checkItem.CheckPoint
					index = i
					break
				}
			}
		}
	} else {
		// to be update
		checkPointCheckItemsMap.Range(func(key, value interface{}) bool {
			checkPoint := key.(models.ChkPoint)
			checkPointCheckItems = value.([]*models.CheckItem)
			for i, checkPointCheckItem := range checkPointCheckItems {
				if checkPointCheckItem.ID == checkItem.ID {
					hitCheckPoint = checkPoint
					index = i
					return false
				}
			}
			return true
		})
	}
	//utils.DebugPrintln("GetCheckPointAndIndexFromMapByCheckItemID, old hit_check_point", hitCheckPoint, index)
	return hitCheckPoint, checkPointCheckItems, index
}

// AddCheckItemToMap ...
func AddCheckItemToMap(checkItem *models.CheckItem) {
	//fmt.Println("AddCheckItemToMap", check_item)
	value, _ := checkPointCheckItemsMap.LoadOrStore(checkItem.CheckPoint, []*models.CheckItem{})
	checkpointCheckItems := value.([]*models.CheckItem)
	checkpointCheckItems = append(checkpointCheckItems, checkItem)
	checkPointCheckItemsMap.Store(checkItem.CheckPoint, checkpointCheckItems)

}

// UpdateCheckItemToMap ...
func UpdateCheckItemToMap(checkItem *models.CheckItem) {
	hitCheckPoint, checkPointCheckItems, index := GetCheckPointMapByCheckItemID(checkItem, false)
	checkPointCheckItems = DeleteCheckItemByIndex(checkPointCheckItems, index)
	if checkItem.CheckPoint == hitCheckPoint {
		// check point not changed
		//fmt.Println("UpdateCheckItemToMap check point not changed")
		checkPointCheckItems = append(checkPointCheckItems, checkItem)
		checkPointCheckItemsMap.Store(hitCheckPoint, checkPointCheckItems)
	} else {
		//fmt.Println("UpdateCheckItemToMap check point changed, new check point: ", check_item.CheckPoint)
		// save old check point
		checkPointCheckItemsMap.Store(hitCheckPoint, checkPointCheckItems)
		// add new check point
		value, _ := checkPointCheckItemsMap.LoadOrStore(checkItem.CheckPoint, []*models.CheckItem{})
		checkPointCheckItems = value.([]*models.CheckItem)
		checkPointCheckItems = append(checkPointCheckItems, checkItem)
		checkPointCheckItemsMap.Store(checkItem.CheckPoint, checkPointCheckItems)

	}
}

// LoadCheckItems ...
func LoadCheckItems() {
	for _, groupPolicy := range groupPolicies {
		var checkItems []*models.CheckItem
		var dbCheckItems []*models.DBCheckItem
		var err error
		if data.IsPrimary {
			dbCheckItems, err = data.DAL.SelectCheckItemsByGroupID(groupPolicy.ID)
			utils.CheckError("LoadCheckItems", err)
			for _, dbCheckItem := range dbCheckItems {
				var keyName = ""
				if dbCheckItem.KeyName.Valid {
					keyName = dbCheckItem.KeyName.String
				}
				checkItem := &models.CheckItem{
					ID:            dbCheckItem.ID,
					CheckPoint:    dbCheckItem.CheckPoint,
					Operation:     dbCheckItem.Operation,
					KeyName:       keyName,
					RegexPolicy:   dbCheckItem.RegexPolicy,
					GroupPolicyID: groupPolicy.ID,
					GroupPolicy:   groupPolicy,
				}
				groupPolicy.CheckItems = append(groupPolicy.CheckItems, checkItem)
				value, _ := checkPointCheckItemsMap.LoadOrStore(checkItem.CheckPoint, []*models.CheckItem{})
				checkpointCheckItems := value.(([]*models.CheckItem))
				checkpointCheckItems = append(checkpointCheckItems, checkItem)
				checkPointCheckItemsMap.Store(checkItem.CheckPoint, checkpointCheckItems)
			}
		} else {
			//fmt.Println("LoadCheckItems Replica Node group_policy:", group_policy)
			checkItems = groupPolicy.CheckItems
			for _, checkItem := range checkItems {
				//fmt.Println("LoadCheckItems", group_policy.ID, check_item)
				checkItem.GroupPolicy = groupPolicy
				checkItem.GroupPolicyID = groupPolicy.ID
				groupPolicy.CheckItems = append(groupPolicy.CheckItems, checkItem)
				value, _ := checkPointCheckItemsMap.LoadOrStore(checkItem.CheckPoint, []*models.CheckItem{})
				checkpointCheckItems := value.(([]*models.CheckItem))
				checkpointCheckItems = append(checkpointCheckItems, checkItem)
				checkPointCheckItemsMap.Store(checkItem.CheckPoint, checkpointCheckItems)
			}
		}
	}
}

// ContainsCheckItemID ...
func ContainsCheckItemID(checkItems []*models.CheckItem, checkItemID int64) bool {
	for _, checkItem := range checkItems {
		if checkItem.ID == checkItemID {
			return true
		}
	}
	return false
}

// UpdateCheckItems ...
func UpdateCheckItems(groupPolicy *models.GroupPolicy, checkItems []*models.CheckItem) error {
	for _, checkItem := range groupPolicy.CheckItems {
		// delete outdated check_items from DB
		if !ContainsCheckItemID(checkItems, checkItem.ID) {
			//fmt.Println("UpdateCheckItems Delete CheckItem ID:", check_item.ID)
			err := data.DAL.DeleteCheckItemByID(checkItem.ID)
			if err != nil {
				utils.DebugPrintln("UpdateCheckItems DeleteCheckItemByID", err)
			}
			hitCheckPoint, checkPointCheckItems, index := GetCheckPointMapByCheckItemID(checkItem, true)
			checkPointCheckItems = DeleteCheckItemByIndex(checkPointCheckItems, index)
			checkPointCheckItemsMap.Store(hitCheckPoint, checkPointCheckItems)
		}
	}
	var newCheckItems = []*models.CheckItem{}
	for _, checkItem := range checkItems {
		// add new check_items to DB and group_policy
		if checkItem.ID == 0 {
			checkItemID, _ := data.DAL.InsertCheckItem(checkItem.CheckPoint, checkItem.Operation, checkItem.KeyName, checkItem.RegexPolicy, groupPolicy.ID)
			checkItem.ID = checkItemID
			checkItem.GroupPolicyID = groupPolicy.ID
			checkItem.GroupPolicy = groupPolicy
			AddCheckItemToMap(checkItem)
		} else {
			err := data.DAL.UpdateCheckItemByID(checkItem.CheckPoint, checkItem.Operation, checkItem.KeyName, checkItem.RegexPolicy, groupPolicy.ID, checkItem.ID)
			if err != nil {
				utils.DebugPrintln("UpdateCheckItems UpdateCheckItemByID", err)
			}
			UpdateCheckItemToMap(checkItem)
		}
		newCheckItems = append(newCheckItems, checkItem)
	}
	groupPolicy.CheckItems = newCheckItems
	DebugTranverseCheckItems()
	return nil
}

// DeleteCheckItemsByGroupPolicy ...
func DeleteCheckItemsByGroupPolicy(groupPolicy *models.GroupPolicy) error {
	for _, checkItem := range groupPolicy.CheckItems {
		//fmt.Println("DeleteCheckItemsByGroupPolicy, check_item:", check_item)
		if value, ok := checkPointCheckItemsMap.Load(checkItem.CheckPoint); ok {
			checkpointCheckItems := value.([]*models.CheckItem)
			i := GetCheckItemIndex(checkpointCheckItems, checkItem.ID)
			//fmt.Println("DeleteCheckItemsByGroupPolicy", i)
			checkpointCheckItems = DeleteCheckItemByIndex(checkpointCheckItems, i)
			//checkpoint_check_items = append(checkpoint_check_items[:i], checkpoint_check_items[i+1:]...)
			checkPointCheckItemsMap.Store(checkItem.CheckPoint, checkpointCheckItems)
		}
		err := data.DAL.DeleteCheckItemByID(checkItem.ID)
		if err != nil {
			utils.DebugPrintln("DeleteCheckItemsByGroupPolicy DeleteCheckItemByID", err)
		}
	}
	return nil
}

// DebugTranverseCheckItems ...
func DebugTranverseCheckItems() {
	if utils.Debug == false {
		return
	}
	checkPointCheckItemsMap.Range(func(key, value interface{}) bool {
		checkPoint := key.(models.ChkPoint)
		//fmt.Println("DebugTranverseCheckItems CheckPoint:", check_point)
		checkPointCheckItems := value.([]*models.CheckItem)
		for _, checkPointCheckItem := range checkPointCheckItems {
			fmt.Println("DebugTranverseCheckItems check_point:", checkPoint, "checkPointCheckItem:", checkPointCheckItem)
		}
		return true
	})
}
