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

	"github.com/Janusec/janusec/data"
	"github.com/Janusec/janusec/models"
	"github.com/Janusec/janusec/utils"
)

var (
	check_items_map sync.Map //(models.ChkPoint, []*models.CheckItem)
)

func GetCheckItemIndex(check_items []*models.CheckItem, id int64) int {
	for i := 0; i < len(check_items); i++ {
		if check_items[i].ID == id {
			return i
		}
	}
	return -1
}

func DeleteCheckItemByIndex(source []*models.CheckItem, index int) []*models.CheckItem {
	last_index := len(source) - 1
	source[index] = source[last_index]
	return source[:last_index]
}

func GetCheckPointMapByCheckItemID(check_item *models.CheckItem, to_be_delete bool) (hit_check_point models.ChkPoint, check_point_check_items []*models.CheckItem, index int) {
	if to_be_delete {
		// check_point of check_item will not changed.
		if value, ok := check_items_map.Load(check_item.CheckPoint); ok {
			check_point_check_items = value.([]*models.CheckItem)
			for i, check_point_check_item := range check_point_check_items {
				if check_point_check_item.ID == check_item.ID {
					hit_check_point = check_item.CheckPoint
					index = i
					break
				}
			}
		}
	} else {
		// to be update
		check_items_map.Range(func(key, value interface{}) bool {
			check_point := key.(models.ChkPoint)
			check_point_check_items = value.([]*models.CheckItem)
			for i, check_point_check_item := range check_point_check_items {
				if check_point_check_item.ID == check_item.ID {
					hit_check_point = check_point
					index = i
					return false
				}
			}
			return true
		})
	}
	utils.DebugPrintln("GetCheckPointAndIndexFromMapByCheckItemID, old hit_check_point", hit_check_point, index)
	return hit_check_point, check_point_check_items, index
}

func AddCheckItemToMap(check_item *models.CheckItem) {
	//fmt.Println("AddCheckItemToMap", check_item)
	value, _ := check_items_map.LoadOrStore(check_item.CheckPoint, []*models.CheckItem{})
	checkpoint_check_items := value.([]*models.CheckItem)
	checkpoint_check_items = append(checkpoint_check_items, check_item)
	check_items_map.Store(check_item.CheckPoint, checkpoint_check_items)

}

func UpdateCheckItemToMap(check_item *models.CheckItem) {
	hit_check_point, check_point_check_items, index := GetCheckPointMapByCheckItemID(check_item, false)
	check_point_check_items = DeleteCheckItemByIndex(check_point_check_items, index)
	if check_item.CheckPoint == hit_check_point {
		// check point not changed
		//fmt.Println("UpdateCheckItemToMap check point not changed")
		check_point_check_items = append(check_point_check_items, check_item)
		check_items_map.Store(hit_check_point, check_point_check_items)
	} else {
		//fmt.Println("UpdateCheckItemToMap check point changed, new check point: ", check_item.CheckPoint)
		// save old check point
		check_items_map.Store(hit_check_point, check_point_check_items)
		// add new check point
		value, _ := check_items_map.LoadOrStore(check_item.CheckPoint, []*models.CheckItem{})
		check_point_check_items = value.([]*models.CheckItem)
		check_point_check_items = append(check_point_check_items, check_item)
		check_items_map.Store(check_item.CheckPoint, check_point_check_items)

	}
}

func LoadCheckItems() {
	for _, group_policy := range group_policies {
		var check_items []*models.CheckItem
		var err error
		if data.IsMaster {
			check_items, err = data.DAL.SelectCheckItemsByGroupID(group_policy.ID)
			utils.CheckError("LoadCheckItems", err)
		} else {
			//fmt.Println("LoadCheckItems Slave Node group_policy:", group_policy)
			check_items = group_policy.CheckItems
		}

		for _, check_item := range check_items {
			//fmt.Println("LoadCheckItems", group_policy.ID, check_item)
			check_item.GroupPolicy = group_policy
			check_item.GroupPolicyID = group_policy.ID
			group_policy.CheckItems = append(group_policy.CheckItems, check_item)
			value, _ := check_items_map.LoadOrStore(check_item.CheckPoint, []*models.CheckItem{})
			checkpoint_check_items := value.(([]*models.CheckItem))
			checkpoint_check_items = append(checkpoint_check_items, check_item)
			check_items_map.Store(check_item.CheckPoint, checkpoint_check_items)
		}
	}
}

func ContainsCheckItemID(check_items []*models.CheckItem, check_item_id int64) bool {
	for _, check_item := range check_items {
		if check_item.ID == check_item_id {
			return true
		}
	}
	return false
}

func UpdateCheckItems(group_policy *models.GroupPolicy, check_items []*models.CheckItem) error {
	for _, check_item := range group_policy.CheckItems {
		// delete outdated check_items from DB
		if !ContainsCheckItemID(check_items, check_item.ID) {
			//fmt.Println("UpdateCheckItems Delete CheckItem ID:", check_item.ID)
			data.DAL.DeleteCheckItemByID(check_item.ID)
			hit_check_point, check_point_check_items, index := GetCheckPointMapByCheckItemID(check_item, true)
			check_point_check_items = DeleteCheckItemByIndex(check_point_check_items, index)
			check_items_map.Store(hit_check_point, check_point_check_items)
		}
	}
	var new_check_items []*models.CheckItem
	for _, check_item := range check_items {
		// add new check_items to DB and group_policy
		if check_item.ID == 0 {
			check_item_id, _ := data.DAL.InsertCheckItem(check_item.CheckPoint, check_item.Operation, check_item.KeyName, check_item.RegexPolicy, group_policy.ID)
			check_item.ID = check_item_id
			check_item.GroupPolicyID = group_policy.ID
			check_item.GroupPolicy = group_policy
			AddCheckItemToMap(check_item)
		} else {
			data.DAL.UpdateCheckItemByID(check_item.CheckPoint, check_item.Operation, check_item.KeyName, check_item.RegexPolicy, group_policy.ID, check_item.ID)
			UpdateCheckItemToMap(check_item)
		}
		new_check_items = append(new_check_items, check_item)
	}
	group_policy.CheckItems = new_check_items
	/*
		for _, check_item := range group_policy.CheckItems {
			fmt.Println("UpdateCheckItems", check_item)
		}
	*/
	DebugTranverseCheckItems()
	return nil
}

func DeleteCheckItemsByGroupPolicy(group_policy *models.GroupPolicy) error {
	for _, check_item := range group_policy.CheckItems {
		//fmt.Println("DeleteCheckItemsByGroupPolicy, check_item:", check_item)
		if value, ok := check_items_map.Load(check_item.CheckPoint); ok {
			checkpoint_check_items := value.([]*models.CheckItem)
			i := GetCheckItemIndex(checkpoint_check_items, check_item.ID)
			//fmt.Println("DeleteCheckItemsByGroupPolicy", i)
			checkpoint_check_items = DeleteCheckItemByIndex(checkpoint_check_items, i)
			//checkpoint_check_items = append(checkpoint_check_items[:i], checkpoint_check_items[i+1:]...)
			check_items_map.Store(check_item.CheckPoint, checkpoint_check_items)
		}
		data.DAL.DeleteCheckItemByID(check_item.ID)
	}
	return nil
}

func DebugTranverseCheckItems() {
	if utils.Debug == false {
		return
	}
	check_items_map.Range(func(key, value interface{}) bool {
		check_point := key.(models.ChkPoint)
		//fmt.Println("DebugTranverseCheckItems CheckPoint:", check_point)
		check_point_check_items := value.([]*models.CheckItem)
		for _, check_point_check_item := range check_point_check_items {
			fmt.Println("DebugTranverseCheckItems check_point:", check_point, "check_point_check_item:", check_point_check_item)
		}
		return true
	})
}
