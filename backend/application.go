/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:21:38
 * @Last Modified: U2, 2018-07-14 16:21:38
 */

package backend

import (
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
			}
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
	if authUser.IsAppAdmin {
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
func UpdateDestinations(app *models.Application, destinations []interface{}) {
	//fmt.Println("ToDo UpdateDestinations")
	for _, dest := range app.Destinations {
		// delete outdated destinations from DB
		if !InterfaceContainsDestinationID(destinations, dest.ID) {
			app.Route.Delete(dest.RequestRoute)
			err := data.DAL.DeleteDestinationByID(dest.ID)
			if err != nil {
				utils.DebugPrintln("DeleteDestinationByID", err)
			}
		}
	}
	var newDestinations = []*models.Destination{}
	for _, destinationInterface := range destinations {
		// add new destinations to DB and app
		destMap := destinationInterface.(map[string]interface{})
		destID := int64(destMap["id"].(float64))
		routeType := int64(destMap["route_type"].(float64))
		requestRoute := strings.TrimSpace(destMap["request_route"].(string))
		backendRoute := strings.TrimSpace(destMap["backend_route"].(string))
		destDest := strings.TrimSpace(destMap["destination"].(string))
		podsAPI := strings.TrimSpace(destMap["pods_api"].(string))
		podPort := strings.TrimSpace(destMap["pod_port"].(string))
		appID := app.ID //int64(destMap["appID"].(float64))
		nodeID := int64(destMap["node_id"].(float64))
		var err error
		if destID == 0 {
			destID, err = data.DAL.InsertDestination(routeType, requestRoute, backendRoute, destDest, podsAPI, podPort, appID, nodeID)
			if err != nil {
				utils.DebugPrintln("InsertDestination", err)
			}
		} else {
			err = data.DAL.UpdateDestinationNode(routeType, requestRoute, backendRoute, destDest, podsAPI, podPort, appID, nodeID, destID)
			if err != nil {
				utils.DebugPrintln("UpdateDestinationNode", err)
			}
		}
		dest := &models.Destination{
			ID:           destID,
			RouteType:    models.RouteType(routeType),
			RequestRoute: requestRoute,
			BackendRoute: backendRoute,
			Destination:  destDest,
			PodsAPI:      podsAPI,
			PodPort:      podPort,
			AppID:        appID,
			NodeID:       nodeID,
			Online:       true,
		}
		newDestinations = append(newDestinations, dest)
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
func UpdateAppDomains(app *models.Application, appDomains []interface{}) {
	newAppDomains := []*models.Domain{}
	//newDomainNames := []string{}
	for _, domainMap := range appDomains {
		domain := UpdateDomain(app, domainMap)
		newAppDomains = append(newAppDomains, domain)
		//newDomainNames = append(newDomainNames, domain.Name)
	}
	for _, oldDomain := range app.Domains {
		if !InterfaceContainsDomainID(appDomains, oldDomain.ID) {
			DomainsMap.Delete(oldDomain.Name)
			err := data.DAL.DeleteDomainByDomainID(oldDomain.ID)
			if err != nil {
				utils.DebugPrintln("UpdateAppDomains DeleteDomainByDomainID", err)
			}
		}
	}
	app.Domains = newAppDomains
}

// UpdateApplication ...
func UpdateApplication(param map[string]interface{}, clientIP string, authUser *models.AuthUser) (*models.Application, error) {
	application := param["object"].(map[string]interface{})
	appID := int64(application["id"].(float64))
	appName := application["name"].(string)
	internalScheme := application["internal_scheme"].(string)
	redirectHTTPS := application["redirect_https"].(bool)
	hstsEnabled := application["hsts_enabled"].(bool)
	wafEnabled := application["waf_enabled"].(bool)
	shieldEnabled := application["shield_enabled"].(bool)
	ipMethod := models.IPMethod(application["ip_method"].(float64))
	var description string
	var ok bool
	if description, ok = application["description"].(string); !ok {
		description = ""
	}
	oauthRequired := application["oauth_required"].(bool)
	sessionSeconds := int64(application["session_seconds"].(float64))
	cspEnabled := application["csp_enabled"].(bool)
	var csp string
	if csp, ok = application["csp"].(string); !ok {
		csp = ""
	}
	cacheEnabled := application["cache_enabled"].(bool)
	owner := application["owner"].(string)
	var app *models.Application
	if appID == 0 {
		// new application
		newID := data.DAL.InsertApplication(appName, internalScheme, redirectHTTPS, hstsEnabled, wafEnabled, shieldEnabled, ipMethod, description, oauthRequired, sessionSeconds, owner, cspEnabled, csp, cacheEnabled)
		app = &models.Application{
			ID: newID, Name: appName,
			InternalScheme: internalScheme,
			//Destinations:   []*models.Destination{},
			Route:          sync.Map{},
			Domains:        []*models.Domain{},
			RedirectHTTPS:  redirectHTTPS,
			HSTSEnabled:    hstsEnabled,
			WAFEnabled:     wafEnabled,
			ShieldEnabled:  shieldEnabled,
			ClientIPMethod: ipMethod,
			Description:    description,
			OAuthRequired:  oauthRequired,
			SessionSeconds: sessionSeconds,
			Owner:          owner,
			CSPEnabled:     cspEnabled,
			CSP:            csp,
			CacheEnabled:   cacheEnabled}
		Apps = append(Apps, app)
		go utils.OperationLog(clientIP, authUser.Username, "Add Application", app.Name)
	} else {
		app, _ = GetApplicationByID(appID)
		if app != nil {
			err := data.DAL.UpdateApplication(appName, internalScheme, redirectHTTPS, hstsEnabled, wafEnabled, shieldEnabled, ipMethod, description, oauthRequired, sessionSeconds, owner, cspEnabled, csp, cacheEnabled, appID)
			if err != nil {
				utils.DebugPrintln("UpdateApplication", err)
			}
			app.Name = appName
			app.InternalScheme = internalScheme
			app.RedirectHTTPS = redirectHTTPS
			app.HSTSEnabled = hstsEnabled
			app.WAFEnabled = wafEnabled
			app.ShieldEnabled = shieldEnabled
			app.ClientIPMethod = ipMethod
			app.Description = description
			app.OAuthRequired = oauthRequired
			app.SessionSeconds = sessionSeconds
			app.Owner = owner
			app.CSPEnabled = cspEnabled
			app.CSP = csp
			app.CacheEnabled = cacheEnabled
			go utils.OperationLog(clientIP, authUser.Username, "Update Application", app.Name)
		} else {
			return nil, errors.New("application not found")
		}
	}
	destinations := application["destinations"].([]interface{})
	UpdateDestinations(app, destinations)
	appDomains := application["domains"].([]interface{})
	UpdateAppDomains(app, appDomains)
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
