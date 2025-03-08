/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2023-06-03 12:40:38
 */

package backend

import (
	"encoding/json"
	"errors"
	"janusec/data"
	"janusec/models"
	"janusec/utils"
	"regexp"
	"strings"
)

var (
	cookieRefs []*models.CookieRef
)

func LoadCookieRefs() {
	cookieRefs = cookieRefs[0:0]
	if data.IsPrimary {
		cookieRefs = data.DAL.SelectCookieRefs()
	} else {
		// Replica
		rpcCookieRefs := RPCSelectCookieRefs()
		if rpcCookieRefs != nil {
			cookieRefs = rpcCookieRefs
		}
	}
}

func GetCookieRefs() []*models.CookieRef {
	return cookieRefs
}

func UpdateCookieRef(body []byte, clientIP string, authUser *models.AuthUser) (*models.CookieRef, error) {
	var rpcCookieRefRequest models.APICookieRefRequest
	if err := json.Unmarshal(body, &rpcCookieRefRequest); err != nil {
		utils.DebugPrintln("UpdateCookieRef", err)
		return nil, err
	}
	cookieRef := rpcCookieRefRequest.Object
	if cookieRef.ID == 0 {
		// new cookieRef
		cookieRef.ID = utils.GenSnowflakeID()
		data.DAL.InsertCookieRef(cookieRef)
		cookieRefs = append(cookieRefs, cookieRef)
		go utils.OperationLog(clientIP, authUser.Username, "Add CookieRef", cookieRef.Name)
	} else {
		// update
		err := data.DAL.UpdateCookieRef(cookieRef)
		if err != nil {
			utils.DebugPrintln("UpdateCookieRef", err)
		}
		// update cookieRef pointer cookieRefs
		UpdateCookieRefs(cookieRef)
		go utils.OperationLog(clientIP, authUser.Username, "Update CookieRef", cookieRef.Name)
	}
	return cookieRef, nil
}

func DeleteCookieRef(cookieRefID int64, clientIP string, authUser *models.AuthUser) error {
	cookieRef, err := data.DAL.SelectCookieRefByID(cookieRefID)
	if err != nil {
		return err
	}
	err = data.DAL.DeleteCookieRefByID(cookieRef.ID)
	if err != nil {
		utils.DebugPrintln("DeleteCookieRef ", err)
		return err
	}
	err = DeleteCookieRefFromCookieRefs(cookieRef)
	if err != nil {
		utils.DebugPrintln("DeleteCookieRefFromCookieRefs", err)
	}
	go utils.OperationLog(clientIP, authUser.Username, "Delete CookieRef", cookieRef.Name)
	return nil
}

func UpdateCookieRefs(cookieRef *models.CookieRef) {
	for i, obj := range cookieRefs {
		if obj.ID == cookieRef.ID {
			cookieRefs[i] = cookieRef
		}
	}
}

func DeleteCookieRefFromCookieRefs(cookieA *models.CookieRef) error {
	for i, cookie := range cookieRefs {
		if cookie.ID == cookieA.ID {
			cookieRefs = append(cookieRefs[:i], cookieRefs[i+1:]...)
			return nil
		}
	}
	return errors.New("cookieRef not found")
}

func GetCookieRefByName(name string) *models.CookieRef {
	for _, cookieRef := range cookieRefs {
		switch cookieRef.Operation {
		case models.CookieOperation_EqualsString:
			if cookieRef.Name == name {
				return cookieRef
			}
		case models.CookieOperation_BeginWithString:
			if strings.Index(name, cookieRef.Name) == 0 {
				return cookieRef
			}
		case models.CookieOperation_RegexMatch:
			hit, err := regexp.MatchString(cookieRef.Name, name)
			if err != nil {
				utils.DebugPrintln("CookieRef MatchString", err)
			}
			if hit {
				return cookieRef
			}
		}
	}
	return nil
}

// RPCSelectCookieRefs ...
func RPCSelectCookieRefs() []*models.CookieRef {
	rpcRequest := &models.RPCRequest{Action: "get_cookie_refs", Object: nil}
	resp, err := data.GetRPCResponse(rpcRequest)
	if err != nil {
		utils.DebugPrintln("RPCSelectCookieRefs GetResponse", err)
		return nil
	}
	rpcApps := &models.RPCCookieRefs{}
	err = json.Unmarshal(resp, rpcApps)
	if err != nil {
		utils.DebugPrintln("RPCSelectCookieRefs Unmarshal", err)
		return nil
	}
	cookieRefs := rpcApps.Object
	return cookieRefs
}

func InitCookieRefs() {
	count := data.DAL.SelectCookieRefsCount()
	if count == 0 {
		cookieRef := &models.CookieRef{
			ID:          utils.GenSnowflakeID(),
			Name:        "_ga",
			Vendor:      "Google",
			Type:        models.Cookie_Analytics,
			Description: "Google Analytics",
			Operation:   models.CookieOperation_EqualsString,
		}
		data.DAL.InsertCookieRef(cookieRef)

		cookieRef = &models.CookieRef{
			ID:          utils.GenSnowflakeID(),
			Name:        "_gid",
			Vendor:      "Google",
			Type:        models.Cookie_Analytics,
			Description: "Google Analytics",
			Operation:   models.CookieOperation_EqualsString,
		}
		data.DAL.InsertCookieRef(cookieRef)

		cookieRef = &models.CookieRef{
			ID:          utils.GenSnowflakeID(),
			Name:        "_gat",
			Vendor:      "Google",
			Type:        models.Cookie_Analytics,
			Description: "Google Analytics",
			Operation:   models.CookieOperation_EqualsString,
		}
		data.DAL.InsertCookieRef(cookieRef)

		cookieRef = &models.CookieRef{
			ID:          utils.GenSnowflakeID(),
			Name:        "AMP_TOKEN",
			Vendor:      "Google",
			Type:        models.Cookie_Analytics,
			Description: "Google Analytics",
			Operation:   models.CookieOperation_EqualsString,
		}
		data.DAL.InsertCookieRef(cookieRef)

		cookieRef = &models.CookieRef{
			ID:          utils.GenSnowflakeID(),
			Name:        "__utm",
			Vendor:      "Google",
			Type:        models.Cookie_Analytics,
			Description: "Google Analytics",
			Operation:   models.CookieOperation_BeginWithString,
		}
		data.DAL.InsertCookieRef(cookieRef)

		cookieRef = &models.CookieRef{
			ID:          utils.GenSnowflakeID(),
			Name:        "_gac_",
			Vendor:      "Google",
			Type:        models.Cookie_Marketing,
			Description: "Google Ads",
			Operation:   models.CookieOperation_BeginWithString,
		}
		data.DAL.InsertCookieRef(cookieRef)
	}
}
