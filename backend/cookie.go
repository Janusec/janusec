/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2023-05-28 15:16:38
 */

package backend

import (
	"encoding/json"
	"fmt"
	"janusec/data"
	"janusec/models"
	"janusec/utils"
	"math"
	"net/http"
	"time"
)

func GetCookiesByAppID(appID int64) []*models.Cookie {
	app, err := GetApplicationByID(appID)
	if err != nil {
		utils.DebugPrintln("GetCookiesByAppID", err)
		return []*models.Cookie{}
	}
	return app.Cookies
}

func ExistsCookie(app *models.Application, name string) (bool, *models.Cookie) {
	for _, cookie := range app.Cookies {
		if cookie.Name == name {
			return true, cookie
		}
	}
	return false, nil
}

func UpdateCookie(body []byte, clientIP string, authUser *models.AuthUser) (*models.Cookie, error) {
	var rpcCookieRequest models.APICookieRequest
	if err := json.Unmarshal(body, &rpcCookieRequest); err != nil {
		utils.DebugPrintln("UpdateCookie", err)
		return nil, err
	}
	cookie := rpcCookieRequest.Object
	app, _ := GetApplicationByID(cookie.AppID)
	if cookie.ID == 0 {
		// new cookie
		cookie.ID = utils.GenSnowflakeID()
		data.DAL.InsertCookie(cookie)

		app.Cookies = append(app.Cookies, cookie)
		go utils.OperationLog(clientIP, authUser.Username, "Add Cookie", cookie.Name)
	} else {
		// update
		err := data.DAL.UpdateCookie(cookie)
		if err != nil {
			utils.DebugPrintln("UpdateCookie", err)
		}
		// update cookie pointer in app.Cookies
		UpdateAppCookies(app, cookie)
		go utils.OperationLog(clientIP, authUser.Username, "Update Cookie", cookie.Name)
	}
	data.UpdateBackendLastModified()
	return cookie, nil
}

// UpdateAppCookies refresh the object in the list
func UpdateAppCookies(app *models.Application, cookie *models.Cookie) {
	for i, obj := range app.Cookies {
		if obj.ID == cookie.ID {
			app.Cookies[i] = cookie
		}
	}
}

func GetCookieRetention(httpCookie *http.Cookie) string {
	cookieRetentionMinutes := math.Ceil(time.Until(httpCookie.Expires).Minutes())
	if cookieRetentionMinutes > (24 * 60) {
		// days
		return fmt.Sprintf("%d days", int64(cookieRetentionMinutes)/(24*60))
	}
	if cookieRetentionMinutes > (60) {
		// hours
		return fmt.Sprintf("%.2f hours", cookieRetentionMinutes/(60))
	}
	// minutes
	return fmt.Sprintf("%.2f minutes", cookieRetentionMinutes)
}
