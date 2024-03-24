/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:21:38
 * @Last Modified: U2, 2018-07-14 16:21:38
 */

package backend

import (
	"encoding/json"
	"errors"
	"hash/fnv"
	"net/http"
	"path/filepath"
	"strings"
	"sync"

	"janusec/data"
	"janusec/firewall"
	"janusec/models"
	"janusec/utils"
)

// Apps i.e. all web applications
var Apps = []*models.Application{}

// SelectDestination deprecated from v0.9.8
/*
func SelectDestination(app *models.Application) string {
	destLen := len(app.Destinations)
	var dest *models.Destination
	if destLen == 1 {
		dest = app.Destinations[0]
	} else if destLen > 1 {
		ns := time.Now().Nanosecond()
		destIndex := ns % len(app.Destinations)
		dest = app.Destinations[destIndex]
	}
	//utils.DebugPrintln("SelectDestination", dest)
	return dest.Destination
}
*/

// SelectBackendRoute will replace SelectDestination
func SelectBackendRoute(app *models.Application, r *http.Request, srcIP string) *models.Destination {
	routePath := utils.GetRoutePath(r.URL.Path)
	var dests []*models.Destination
	hit := false
	if routePath != "/" {
		// First check /abc/
		valueI, ok := app.Route.Load(routePath)
		if ok {
			hit = true
			dests = valueI.([]*models.Destination)
		}
	}

	if !hit {
		// Second check .php
		ext := filepath.Ext(r.URL.Path)
		valueI, ok := app.Route.Load(ext)
		// Third check /
		if !ok {
			valueI, ok = app.Route.Load("/")
		}
		if !ok {
			// lack of route /
			return nil
		}
		dests = valueI.([]*models.Destination)
	}

	// get online destinations
	var onlineDests = []*models.Destination{}
	for _, dest := range dests {
		dest.Mutex.Lock()
		defer dest.Mutex.Unlock()
		if dest.Online {
			onlineDests = append(onlineDests, dest)
		}
	}

	destLen := uint32(len(onlineDests))
	if destLen == 0 {
		return nil
	}
	var dest *models.Destination
	if destLen == 1 {
		dest = onlineDests[0]
	} else if destLen > 1 {
		// According to Hash(IP+UA)
		h := fnv.New32a()
		_, err := h.Write([]byte(srcIP + r.UserAgent()))
		if err != nil {
			utils.DebugPrintln("SelectBackendRoute h.Write", err)
		}
		hashUInt32 := h.Sum32()
		destIndex := hashUInt32 % destLen
		dest = onlineDests[destIndex]
	}
	if dest.RouteType == models.ReverseProxyRoute {
		if dest.RequestRoute != dest.BackendRoute {
			r.URL.Path = strings.Replace(r.URL.Path, dest.RequestRoute, dest.BackendRoute, 1)
		}
	}
	return dest
}

// GetApplicationByID ...
func GetApplicationByID(appID int64) (*models.Application, error) {
	for _, app := range Apps {
		if app.ID == appID {
			return app, nil
		}
	}
	return nil, errors.New("not found")
}

// GetWildDomainName ...
func GetWildDomainName(domain string) string {
	index := strings.Index(domain, ".")
	if index > 0 {
		wildDomain := "*" + domain[index:]
		return wildDomain
	}
	return ""
}

// GetApplicationByDomain ...
func GetApplicationByDomain(domain string) *models.Application {
	if domainRelation, ok := DomainsMap.Load(domain); ok {
		app := domainRelation.(models.DomainRelation).App //DomainsMap[domain].App
		return app
	}
	wildDomain := GetWildDomainName(domain) // *.janusec.com
	if domainRelation, ok := DomainsMap.Load(wildDomain); ok {
		domainRelation2 := domainRelation.(models.DomainRelation)
		app := domainRelation2.App //DomainsMap[domain].App
		DomainsMap.Store(domain, models.DomainRelation{App: app, Cert: domainRelation2.Cert, Redirect: false, Location: ""})
		return app
	}
	return nil
}

// LoadApps ...
func LoadApps() {
	Apps = Apps[0:0]
	if data.IsPrimary {
		dbApps := data.DAL.SelectApplications()
		for _, dbApp := range dbApps {
			app := &models.Application{ID: dbApp.ID,
				Name:           dbApp.Name,
				InternalScheme: dbApp.InternalScheme,
				RedirectHTTPS:  dbApp.RedirectHTTPS,
				HSTSEnabled:    dbApp.HSTSEnabled,
				WAFEnabled:     dbApp.WAFEnabled,
				ShieldEnabled:  dbApp.ShieldEnabled,
				ClientIPMethod: dbApp.ClientIPMethod,
				Description:    dbApp.Description,
				Destinations:   []*models.Destination{},
				Route:          sync.Map{},
				OAuthRequired:  dbApp.OAuthRequired,
				SessionSeconds: dbApp.SessionSeconds,
				Owner:          dbApp.Owner,
				CSPEnabled:     dbApp.CSPEnabled,
				CSP:            dbApp.CSP,
				CacheEnabled:   dbApp.CacheEnabled,
				// extends from v1.4.1pro
				CookieMgmtEnabled:  dbApp.CookieMgmtEnabled,
				ConciseNotice:      dbApp.ConciseNotice,
				NecessaryNotice:    dbApp.NecessaryNotice,
				FunctionalNotice:   dbApp.FunctionalNotice,
				EnableFunctional:   dbApp.EnableFunctional,
				AnalyticsNotice:    dbApp.AnalyticsNotice,
				EnableAnalytics:    dbApp.EnableAnalytics,
				MarketingNotice:    dbApp.MarketingNotice,
				EnableMarketing:    dbApp.EnableMarketing,
				UnclassifiedNotice: dbApp.UnclassifiedNotice,
				EnableUnclassified: dbApp.EnableUnclassified,
				CustomHeaders:      GetCustomHeaders(dbApp.CustomHeaders),
			}
			// Load Cookies of each App
			InitAppConsentCookie(app.ID)
			app.Cookies = data.DAL.SelectCookiesByAppID(app.ID)

			Apps = append(Apps, app)
		}
	} else {
		// Replica
		rpcApps := RPCSelectApplications()
		if rpcApps != nil {
			Apps = rpcApps
		}
	}
}

// GetCustomHeaders convert string to slice, "HeaderA:ValueA||HeaderB:ValueB" --> [{},{}]
func GetCustomHeaders(customHeaders string) []*models.CustomHeader {
	resultHeaders := []*models.CustomHeader{}
	if len(customHeaders) == 0 {
		return resultHeaders
	}
	singleLineHeaders := strings.Split(customHeaders, "||")
	for _, singleLineHeader := range singleLineHeaders {
		keyValue := strings.Split(singleLineHeader, ":")
		customHeader := &models.CustomHeader{
			Key:   keyValue[0],
			Value: strings.Join(keyValue[1:], ":"),
		}
		resultHeaders = append(resultHeaders, customHeader)
	}
	return resultHeaders
}

// GetCustomHeadersString convert slice to string, [{},{}] --> "HeaderA:ValueA||HeaderB:ValueB"
func GetCustomHeadersString(customHeaders []*models.CustomHeader) string {
	var headersStr string
	for _, customHeader := range customHeaders {
		if len(headersStr) > 0 {
			headersStr += "||"
		}
		headersStr += customHeader.Key + ":" + customHeader.Value
	}
	return headersStr
}

// LoadDestinations ...
func LoadDestinations() {
	for _, app := range Apps {
		app.Destinations = data.DAL.SelectDestinationsByAppID(app.ID)
		for _, dest := range app.Destinations {
			routeI, ok := app.Route.Load(dest.RequestRoute)
			var route []*models.Destination
			if ok {
				route = routeI.([]*models.Destination)
			}
			route = append(route, dest)
			app.Route.Store(dest.RequestRoute, route)
		}
	}
}

// LoadRoute ...
func LoadRoute() {
	for _, app := range Apps {
		for _, dest := range app.Destinations {
			routeI, ok := app.Route.Load(dest.RequestRoute)
			var route []*models.Destination
			if ok {
				route = routeI.([]*models.Destination)
			}
			route = append(route, dest)
			app.Route.Store(dest.RequestRoute, route)
		}
	}
}

// LoadAppDomainNames ...
func LoadAppDomainNames() {
	for _, app := range Apps {
		for _, domain := range Domains {
			if domain.AppID == app.ID {
				app.Domains = append(app.Domains, domain)
			}
		}
	}
}

// GetApplications ...
func GetApplications(authUser *models.AuthUser) ([]*models.Application, error) {
	if authUser.IsAppAdmin || authUser.IsSuperAdmin {
		return Apps, nil
	}
	myApps := []*models.Application{}
	for _, app := range Apps {
		if app.Owner == authUser.Username {
			myApps = append(myApps, app)
		}
	}
	return myApps, nil
}

// UpdateDestinations ...
func UpdateDestinations(app *models.Application, destinations []*models.Destination) {
	for _, dest := range app.Destinations {
		// delete outdated destinations from DB
		if !ContainsDestinationID(destinations, dest.ID) {
			app.Route.Delete(dest.RequestRoute)
			err := data.DAL.DeleteDestinationByID(dest.ID)
			if err != nil {
				utils.DebugPrintln("DeleteDestinationByID", err)
			}
		}
	}
	var newDestinations = []*models.Destination{}
	for _, destination := range destinations {
		if strings.HasPrefix(destination.RequestRoute, "/") && !strings.HasSuffix(destination.RequestRoute, "/") {
			destination.RequestRoute = strings.Trim(destination.RequestRoute, " ") + "/"
		}
		if strings.HasPrefix(destination.BackendRoute, "/") && !strings.HasSuffix(destination.BackendRoute, "/") {
			destination.BackendRoute = strings.Trim(destination.BackendRoute, " ") + "/"
		}
		var err error
		if destination.ID == 0 {
			// new
			destination.ID, err = data.DAL.InsertDestination(int64(destination.RouteType), destination.RequestRoute, destination.BackendRoute, destination.Destination, destination.PodsAPI, destination.PodPort, app.ID, destination.NodeID)
			if err != nil {
				utils.DebugPrintln("InsertDestination", err)
			} else {
				destination.Online = true
				newDestinations = append(newDestinations, destination)
			}
		} else {
			// update
			err = data.DAL.UpdateDestinationNode(int64(destination.RouteType), destination.RequestRoute, destination.BackendRoute, destination.Destination, destination.PodsAPI, destination.PodPort, app.ID, destination.NodeID, destination.ID)
			if err != nil {
				utils.DebugPrintln("UpdateDestinationNode", err)
			} else {
				destination.Online = true
				newDestinations = append(newDestinations, destination)
			}
		}
	}
	app.Destinations = newDestinations

	// Update Route Map
	app.Route.Range(func(key, value interface{}) bool {
		app.Route.Delete(key)
		return true
	})
	for _, dest := range app.Destinations {
		routeI, ok := app.Route.Load(dest.RequestRoute)
		var route []*models.Destination
		if ok {
			route = routeI.([]*models.Destination)
		}
		route = append(route, dest)
		app.Route.Store(dest.RequestRoute, route)
	}
}

// UpdateAppDomains ...
func UpdateAppDomains(app *models.Application, domains []*models.Domain) {
	newDomains := []*models.Domain{}
	for _, domain := range domains {
		domain = UpdateDomain(app, domain)
		newDomains = append(newDomains, domain)
	}
	for _, oldDomain := range app.Domains {
		if !ContainsDomainID(domains, oldDomain.ID) {
			DomainsMap.Delete(oldDomain.Name)
			err := data.DAL.DeleteDomainByDomainID(oldDomain.ID)
			if err != nil {
				utils.DebugPrintln("UpdateAppDomains DeleteDomainByDomainID", err)
			}
		}
	}
	app.Domains = newDomains
}

// UpdateApplications refresh the object in the list
func UpdateApplications(app *models.Application) {
	for i, obj := range Apps {
		if obj.ID == app.ID {
			Apps[i] = app
		}
	}
}

// UpdateApplication ...
func UpdateApplication(body []byte, clientIP string, authUser *models.AuthUser) (*models.Application, error) {
	var rpcAppRequest models.APIApplicationRequest
	if err := json.Unmarshal(body, &rpcAppRequest); err != nil {
		utils.DebugPrintln("UpdateApplication", err)
		return nil, err
	}
	app := rpcAppRequest.Object
	customHeaders := GetCustomHeadersString(app.CustomHeaders)
	if app.ID == 0 {
		// new application
		app.ID = data.DAL.InsertApplication(app.Name, app.InternalScheme, app.RedirectHTTPS, app.HSTSEnabled, app.WAFEnabled, app.ShieldEnabled, app.ClientIPMethod, app.Description, app.OAuthRequired, app.SessionSeconds, app.Owner, app.CSPEnabled, app.CSP, app.CacheEnabled, customHeaders, app.CookieMgmtEnabled, app.ConciseNotice, app.NecessaryNotice, app.FunctionalNotice, app.EnableFunctional, app.AnalyticsNotice, app.EnableAnalytics, app.MarketingNotice, app.EnableMarketing, app.UnclassifiedNotice, app.EnableUnclassified)
		Apps = append(Apps, app)
		go utils.OperationLog(clientIP, authUser.Username, "Add Application", app.Name)
	} else {
		err := data.DAL.UpdateApplication(app.Name, app.InternalScheme, app.RedirectHTTPS, app.HSTSEnabled, app.WAFEnabled, app.ShieldEnabled, app.ClientIPMethod, app.Description, app.OAuthRequired, app.SessionSeconds, app.Owner, app.CSPEnabled, app.CSP, app.CacheEnabled, customHeaders, app.CookieMgmtEnabled, app.ConciseNotice, app.NecessaryNotice, app.FunctionalNotice, app.EnableFunctional, app.AnalyticsNotice, app.EnableAnalytics, app.MarketingNotice, app.EnableMarketing, app.UnclassifiedNotice, app.EnableUnclassified, app.ID)
		if err != nil {
			utils.DebugPrintln("UpdateApplication", err)
		}
		// update app pointer in apps
		UpdateApplications(app)
		go utils.OperationLog(clientIP, authUser.Username, "Update Application", app.Name)
	}
	UpdateDestinations(app, app.Destinations)
	UpdateAppDomains(app, app.Domains)
	data.UpdateBackendLastModified()
	return app, nil
}

// GetApplicationIndex ...
func GetApplicationIndex(appID int64) int {
	for i := 0; i < len(Apps); i++ {
		if Apps[i].ID == appID {
			return i
		}
	}
	return -1
}

// DeleteDestinationsByApp ...
func DeleteDestinationsByApp(appID int64) {
	err := data.DAL.DeleteDestinationsByAppID(appID)
	if err != nil {
		utils.DebugPrintln("DeleteDestinationsByAppID", err)
	}
}

// DeleteApplicationByID ...
func DeleteApplicationByID(appID int64, clientIP string, authUser *models.AuthUser) error {
	app, err := GetApplicationByID(appID)
	if err != nil {
		return err
	}
	DeleteDomainsByApp(app)
	DeleteDestinationsByApp(appID)
	DeleteCookiesByApp(app)
	err = firewall.DeleteCCPolicyByAppID(appID, clientIP, authUser, false)
	if err != nil {
		utils.DebugPrintln("DeleteApplicationByID DeleteCCPolicyByAppID", err)
	}
	err = data.DAL.DeleteApplication(appID)
	if err != nil {
		utils.DebugPrintln("DeleteApplicationByID DeleteApplication", err)
		return err
	}
	i := GetApplicationIndex(appID)
	Apps = append(Apps[:i], Apps[i+1:]...)
	go utils.OperationLog(clientIP, authUser.Username, "Delete Application", app.Name)
	data.UpdateBackendLastModified()
	return nil
}
