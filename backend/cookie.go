/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2023-05-28 15:16:38
 */

package backend

import (
	"janusec/models"
	"janusec/utils"
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
