/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:38:30
 * @Last Modified: U2, 2018-07-14 16:38:30
 */

package gateway

import (
	"bytes"
	"html/template"
	"net/http"

	"github.com/Janusec/janusec/models"
)

// GenerateBlockPage ...
func GenerateBlockPage(w http.ResponseWriter, hitInfo *models.HitInfo) {
	tmpl := template.New("Janusec")
	tmpl, _ = tmpl.Parse(blockHTML)
	w.WriteHeader(403)
	tmpl.Execute(w, hitInfo)
}

// GenerateBlockConcent ...
func GenerateBlockConcent(hitInfo *models.HitInfo) []byte {
	tmpl := template.New("Janusec")
	tmpl, _ = tmpl.Parse(blockHTML)
	buf := new(bytes.Buffer)
	tmpl.Execute(buf, hitInfo)
	return buf.Bytes()
}

var blockHTML = `<!DOCTYPE html>
<html>
<head>
<title>403 Forbidden</title></head>
<body bgcolor="white">
<center><h1>
<a href="http://www.janusec.com" target="_blank">
<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAM8AAAA2CAMAAAEgxQ0qAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAGwUExURaampr+/v39/f////4eHh5mZmaWlpampqaenp5+fn5eXl6+vr5OTk7m5udvb2+Pj4+/v7/v7+wAAAA4ODicnJ0dHR29vb9/f38vLy4WFhTk5ORoaGhQUFDExMVVVVc/Pz4+Pj9PT0+3t7f39/Zubm+np6QwMDJ2dnQgICAYGBrOzsyEhIQUFBQICAgkJCUVFRcHBwQsLCyMjI/Pz8xAQEFdXV62trcfHx7W1tbe3t0NDQxsbG2tra93d3fHx8ff3942NjZWVlXl5eRkZGYmJiaGhodfX11lZWc3NzYCAgGVlZQ0NDQQEBF5eXuHh4YODg3h4eBgYGFJSUmRkZDg4OAcHB+vr6+fn5xISEisrKzAwML29vdXV1fn5+aurq4aGhj09PVRUVGlpaRMTEzIyMioqKlFRUX19ffX19Q8PDygoKLu7u8PDw9HR0dnZ2SwsLBEREYuLi+Xl5YGBgZGRkVhYWB4eHsXFxXp6ekRERHZ2drGxsSYmJm1tbXt7e0hISAoKCkFBQWBgYKOjo3BwcEJCQsnJySQkJD4+Pj8/P0ZGRhcXFyUlJXJyciIiIgAAANbEhrwAAACQdFJOU///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////AANl54cAAAAJcEhZcwAAFxEAABcRAcom8z8AAAloSURBVFhHxVlLcusqEE2V5PJUpZFG2Yk3kJEWcWeeaJpNeM3vfLobJOfjm+S+HIiABvpHg5DzdD5iuV6dn87rAUPi6TyOwzqAsg6sjMM8zDP/0LWOaCNP6rhg+HxhP7quYoFeTsZ0UqOLozMN40rqPG9muK4jxY8s8CAP4U75VH25PnFCj5gCPIED2tBykRHDPIXu6gJ7DM4u6H55QQ+6qGEYha7xlROeN1CeMOV6QSfIVJ6aF8PQfR1dWAXi3r1HxMAenEQnmNkBcA0cdw+uFr2mzgUr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" 
alt="Janusec Application Gateway" 
title="Janusec Application Gateway, an application security solutions which provides WAF (Web Application Firewall), unified web administration, certificate protection, and scalable load balancing." >
</a>
</h1></center>
<hr>
<center>Reason: {{.VulnName}}, Policy ID: {{.PolicyID}}, by Janusec Application Gateway</center>
</body>
</html>
`
