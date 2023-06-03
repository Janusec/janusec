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

func DeleteCookiesByApp(app *models.Application) {
	data.DAL.DeleteCookiesByAppID(app.ID)
	app.Cookies = nil
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

func HandleResponseCookies(resp *http.Response, app *models.Application, reqURI string, optConsentValue int64) {
	allHttpCookies := append(resp.Request.Cookies(), resp.Cookies()...)
	for _, httpCookie := range allHttpCookies {
		exists, cookie := ExistsCookie(app, httpCookie.Name)
		if !exists {
			cookieVendor := ""
			cookieType := models.Cookie_Unclassified
			cookieDesc := ""
			// first check relevant CookieRef and update Vendor, Type, and Description
			cookieRef := GetCookieRefByName(httpCookie.Name)
			if cookieRef != nil {
				cookieVendor = cookieRef.Vendor
				cookieType = cookieRef.Type
				cookieDesc = cookieRef.Description
			}
			cookie := &models.Cookie{
				ID:          utils.GenSnowflakeID(),
				AppID:       app.ID,
				Name:        httpCookie.Name,
				Domain:      httpCookie.Domain,
				Path:        httpCookie.Path,
				Duration:    GetCookieDuration(httpCookie),
				Vendor:      cookieVendor,
				Type:        cookieType,
				Description: cookieDesc,
				AccessTime:  time.Now().Unix(),
				Source:      reqURI,
			}
			err := data.DAL.InsertCookie(cookie)
			if err != nil {
				utils.DebugPrintln("InsertCookie", err)
			}
			app.Cookies = append(app.Cookies, cookie)
			if optConsentValue == 0 {
				// user not set and not permit by default
				if !app.EnableUnclassified {
					// Remove cookie when Unclassified Cookie not permitted
					DeleteResponseCookie(resp, httpCookie)
				}
			} else if (optConsentValue & int64(models.Cookie_Unclassified)) == 0 {
				// user has not give consent for unclassified cookies
				DeleteResponseCookie(resp, httpCookie)
			}
		} else {
			// cookie exists in database
			if optConsentValue == 0 {
				// when user has not confirmed his choice
				switch cookie.Type {
				case models.Cookie_Functional:
					if !app.EnableFunctional {
						DeleteResponseCookie(resp, httpCookie)
					}
				case models.Cookie_Analytics:
					if !app.EnableAnalytics {
						DeleteResponseCookie(resp, httpCookie)
					}
				case models.Cookie_Marketing:
					if !app.EnableMarketing {
						DeleteResponseCookie(resp, httpCookie)
					}
				case models.Cookie_Unclassified:
					if !app.EnableUnclassified {
						// Remove cookie when Unclassified Cookie not permitted
						DeleteResponseCookie(resp, httpCookie)
					}
				}
			} else {
				// user has confirmed his choice
				switch cookie.Type {
				case models.Cookie_Functional:
					if (optConsentValue & int64(models.Cookie_Functional)) == 0 {
						DeleteResponseCookie(resp, httpCookie)
					}
				case models.Cookie_Analytics:
					if (optConsentValue & int64(models.Cookie_Analytics)) == 0 {
						DeleteResponseCookie(resp, httpCookie)
					}
				case models.Cookie_Marketing:
					if (optConsentValue & int64(models.Cookie_Marketing)) == 0 {
						DeleteResponseCookie(resp, httpCookie)
					}
				case models.Cookie_Unclassified:
					if (optConsentValue & int64(models.Cookie_Unclassified)) == 0 {
						DeleteResponseCookie(resp, httpCookie)
					}
				}
			}
		}
	}
}

func DeleteResponseCookie(resp *http.Response, httpCookie *http.Cookie) {
	httpCookie.MaxAge = -1
	httpCookie.Value = ""
	resp.Header.Add("Set-Cookie", httpCookie.String())
}

func InitAppConsentCookie(appID int64) {
	count := data.DAL.SelectCookiesCount(appID)
	if count == 0 {
		cookie := &models.Cookie{
			ID:          utils.GenSnowflakeID(),
			AppID:       appID,
			Name:        "CookieOptConsent",
			Domain:      "",
			Path:        "/",
			Duration:    "365 days",
			Vendor:      "JANUSEC",
			Type:        models.Cookie_Necessary,
			Description: "Cookie Management",
			Source:      "/",
		}
		data.DAL.InsertCookie(cookie)

	}
}
