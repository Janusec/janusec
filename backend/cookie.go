/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2023-05-28 15:16:38
 */

package backend

import (
	"janusec/data"
	"janusec/models"
)

func GetCookiesByAppID(appID int64) []*models.Cookie {
	return data.DAL.SelectCookiesByAppID(appID)
}
