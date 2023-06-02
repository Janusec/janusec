/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2023-05-28 15:16:38
 */

package backend

import (
	"encoding/json"
	"errors"
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

func GetCookieDuration(httpCookie *http.Cookie) string {
	cookieDurationMinutes := math.Ceil(time.Until(httpCookie.Expires).Minutes())
	if cookieDurationMinutes > (24 * 60) {
		// days
		return fmt.Sprintf("%d days", int64(cookieDurationMinutes)/(24*60))
	}
	if cookieDurationMinutes > (60) {
		// hours
		return fmt.Sprintf("%.2f hours", cookieDurationMinutes/(60))
	}
	// minutes
	return fmt.Sprintf("%.2f minutes", cookieDurationMinutes)
}

func DeleteCookie(cookieID int64, clientIP string, authUser *models.AuthUser) error {
	cookie, err := data.DAL.SelectCookieByID(cookieID)
	if err != nil {
		return err
	}
	err = data.DAL.DeleteCookieByID(cookie.ID)
	if err != nil {
		utils.DebugPrintln("DeleteCookie ", err)
		return err
	}
	app, err := GetApplicationByID(cookie.AppID)
	if err != nil {
		utils.DebugPrintln("DeleteCookie GetApp", err)
	}
	err = DeleteCookieFromAppCookies(app, cookie)
	if err != nil {
		utils.DebugPrintln("DeleteCookieFromAppCookies", err)
	}
	go utils.OperationLog(clientIP, authUser.Username, "Delete Cookie", cookie.Name)
	data.UpdateBackendLastModified()
	return nil
}

func DeleteCookieFromAppCookies(app *models.Application, cookieA *models.Cookie) error {
	for i, cookie := range app.Cookies {
		if cookie.ID == cookieA.ID {
			app.Cookies = append(app.Cookies[:i], app.Cookies[i+1:]...)
			return nil
		}
	}
	return errors.New("cookie not found")
}
