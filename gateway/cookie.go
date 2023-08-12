/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2023-05-27 20:11:10
 */

package gateway

import (
	"fmt"
	"strings"

	"golang.org/x/net/html"
)

const cookieStyle = `<style>
  #JanusecCookieOptIcon {
    position: fixed;
    left: 20px;
    bottom: 20px;
    width: 40px;
    height: 40px;   
    z-index: 9999;
  }

  #JanusecCookieOptIcon button {
    width: 100%;
    height: 100%;
    font-size: 24px;
    color: #ffffff;
    background-color: #007bff;
    border: none;
    border-radius: 10px;
    cursor: pointer;
    opacity: 0.3;
  }

  #JanusecCookieOptWindow {
    position: fixed;
    top: 120px;
    left: 50%;
    padding: 0;
    margin-left: -400px;
    z-index: 9999;
    width: 800px;
    background-color: #FFFFFF;
    border: 2px solid #e0e0e0;
    opacity: 1;
 }
 
  #JanusecCookieOptWindow div,p,span {
    text-align: left;
  }

 .janusec-cookie-title-line {
    margin-top: 10px;
    padding: 5px 0;
    padding: 5px;
 }

 .janusec-cookie-window-title {
    font-size: 20px;
 }

 .janusec-btn-cookie-window-close {
	  float: right;
    border: none;
    font-size: 16px;
	  background-color: #FCFCFC;
 }

 .janusec-cookie-outer-container {
    margin: 0 10px;
	  /* clear float */
	  overflow: hidden;
 }

 .janusec-cookie-div-container {
	/* clear float */
	overflow: hidden;
 }

 .janusec-cookie-common-text {
	color: #808080;
  font-size: 12px;
 }
 
 .janusec-btn-cookie-save {
    padding: 10px;
    color: #ffffff;
    border: solid 1px #F5F5F5;
    background-color: #007bff;
 }
 
 .janusec-cookie-window-footer {
    display: block;
    float: none;
    background-color: #f0f0f0;
    text-align: right;
    padding: 5px;
 }
 
 .janusec-cookie-tab {
   float: left;
   border: 1px solid #c0c0c0;
   width: 25%;
   height: 300px;
 }
 
 .janusec-cookie-tab button {
   display: block;
   background-color: inherit;
   color: black;
   padding: 22px 16px;
   width: 100%;
   height: 60px;
   border: none;
   outline: none;
   text-align: left;
   cursor: pointer;
   transition: 0.3s;
   font-size: 14px;
 }
 
 .janusec-cookie-tab button:hover {
   background-color: #ddd;
 }
 
 .janusec-cookie-tab button.active {
   background-color: #f0f0f0;
 }
 
 .janusec-cookie-tabcontent {
   float: left;
   padding: 0px 12px;
   border: 1px solid #c0c0c0;
   width: 75%;
   border-left: 1px solid #e0e0e0;
   height: 300px;
   overflow: scroll;
 }

 .janusec-cookie-preference-table {
  width: 100%;  
  font-size: 10px;
  border-collapse: collapse;
  border: none;
 }

 .janusec-cookie-preference-table th,td {  
  border: dotted 1px;
  padding: 2px;
 }

 .janusec-btn-confirm {
	float: right;
	padding: 10px;
  color: #ffffff;
  border: solid 1px #F5F5F5;
  background-color: #007bff;
 }

 .janusec-cookie-type-line {
	margin: 10px 0;
 }

 .janusec-txt-always-on {
	float: right;
	color: #007bff;
 }

 .txt-janusec-logo {
  color: #007bff;
 }

.janusec-cookie-switch-box {
	float: right;
  width: 40px;
}

.janusec-cookie-switch-box .switch {
    display: none;
}

.janusec-cookie-switch-box label {
    position: relative;
    display: block;
    margin: 1px;
    height: 20px;
    cursor: pointer;
}

.janusec-cookie-switch-box label::before {
    content: '';
    position: absolute;
    top: 50%;
    left: 50%;
    margin-top: -8px;
    margin-left: -8px;
    width: 16px;
    height: 16px;
    border-radius: 100%;
    background-color: #fff;
    box-shadow: 1px 1px 1px 1px rgba(0, 0, 0, 0.06);
    -webkit-transform: translateX(-9px);
    -moz-transform: translateX(-9px);
    transform: translateX(-9px);
    -webkit-transition: all 0.3s ease;
    -moz-transition: all 0.3s ease;
    transition: all 0.3s ease;
}

.janusec-cookie-switch-box .switch:checked~label::before {
    -webkit-transform: translateX(9px);
    -moz-transform: translateX(9px);
    transform: translateX(9px);
}

.janusec-cookie-switch-box label::after {
    content: "";
    display: block;
    border-radius: 10px;
    height: 20px;
    background-color: #dcdfe6;
    -webkit-transition: all 0.3s ease;
    -moz-transition: all 0.3s ease;
    transition: all 0.3s ease;
}

.janusec-cookie-switch-box .switch:checked~label::after {
    background-color: #007bff;
}

.janusec-cookie-div-container * {
  box-sizing: border-box
}

 </style>`

const cookieIconTmpl = `
<div id="JanusecCookieOptIcon">
    <button onclick="toggleCookieOptWindow()">C</button>
</div>`

const cookieWindowTmpl = `
<div id="JanusecCookieOptWindow">
<div class="janusec-cookie-outer-container">
  <div class="janusec-cookie-title-line">
    <span class="janusec-cookie-window-title">Cookie Preferences</span>
    <span>
      <button class="janusec-btn-cookie-window-close" onclick="closeCookieOptWindow()">×</button>
    </span>
  </div>
  <p class="janusec-cookie-common-text">
    {{ .App.ConciseNotice }} For more detailed information about the cookies we use, see our 
    <a href="{{ .App.LongNoticeLink }}" target="_blank">cookies notice</a>.
  </p>
	<div>
		<button class="janusec-btn-cookie-save" onclick="rejectAllCookies()">Reject all Cookies</button>
		<span>&nbsp;&nbsp;&nbsp;&nbsp;</span>
		<button class="janusec-btn-cookie-save" onclick="acceptAllCookies()">Accept all Cookies</button>
	</div>
	<hr>
	<div class="janusec-cookie-div-container">
		<div class="janusec-cookie-tab">
			<button class="tablinks" onclick="openCookieTab(event, 'Necessary')" id="defaultOpen">Necessary Cookies</button>
      <button class="tablinks" onclick="openCookieTab(event, 'Functional')">Functional Cookies</button>
			<button class="tablinks" onclick="openCookieTab(event, 'Analytics')">Analytics Cookies</button>
			<button class="tablinks" onclick="openCookieTab(event, 'Marketing')">Marketing Cookies</button>
      <button class="tablinks" onclick="openCookieTab(event, 'Unclassified')">Unclassified Cookies</button>
		</div>
		
		<div id="Necessary" class="janusec-cookie-tabcontent">
			<div class="janusec-cookie-type-line">
			<span>Necessary Cookies</span>
			<span class="janusec-txt-always-on">Always On</span>
			</div>
			<p class="janusec-cookie-common-text">{{ .App.NecessaryNotice }}</p>
      <table class="janusec-cookie-preference-table">
      <tr> <th>Name</th> <th>Domain</th> <th>Path</th> <th>Duration</th> <th>Vendor</th> <th>Description</th> </tr>
      {{ range .App.Cookies }}
          {{ if (eq .Type 1) }}
          <tr> <td>{{ .Name }}</td>  <td>{{ .Domain }}</td> <td>{{ .Path }}</td> <td>{{ .Duration }}</td> <td>{{ .Vendor }}</td> <td>{{ .Description }}</td> </tr>
          {{ end }}
      {{ end }}
      </table>
		</div>

    <div id="Functional" class="janusec-cookie-tabcontent">
		  <div class="janusec-cookie-type-line">
			<span>Functional Cookies</span>
			<span>
			<div class="janusec-cookie-switch-box">
				<input id="functionalPermit" type="checkbox" class="switch" />
				<label for="functionalPermit"></label>
			</div>
			</span>
			</div>
			<p class="janusec-cookie-common-text">{{ .App.FunctionalNotice }}</p> 
      <table class="janusec-cookie-preference-table">
      <tr> <th>Name</th> <th>Domain</th> <th>Path</th> <th>Duration</th> <th>Vendor</th> <th>Description</th> </tr>
      {{ range .App.Cookies }}
          {{ if (eq .Type 2) }}
          <tr> <td>{{ .Name }}</td>  <td>{{ .Domain }}</td> <td>{{ .Path }}</td> <td>{{ .Duration }}</td> <td>{{ .Vendor }}</td> <td>{{ .Description }}</td> </tr>
          {{ end }}
      {{ end }}
      </table>
		</div>
		
		<div id="Analytics" class="janusec-cookie-tabcontent">
		  <div class="janusec-cookie-type-line">
			<span>Analytics Cookies</span>
			<span>
			<div class="janusec-cookie-switch-box">
				<input id="analyticsPermit" type="checkbox" class="switch" />
				<label for="analyticsPermit"></label>
			</div>
			</span>
			</div>
			<p class="janusec-cookie-common-text">{{ .App.AnalyticsNotice }}</p> 
      <table class="janusec-cookie-preference-table">
      <tr> <th>Name</th> <th>Domain</th> <th>Path</th> <th>Duration</th> <th>Vendor</th> <th>Description</th> </tr>
      {{ range .App.Cookies }}
          {{ if (eq .Type 4) }}
          <tr> <td>{{ .Name }}</td>  <td>{{ .Domain }}</td> <td>{{ .Path }}</td> <td>{{ .Duration }}</td> <td>{{ .Vendor }}</td> <td>{{ .Description }}</td> </tr>
          {{ end }}
      {{ end }}
      </table>
		</div>
		
		<div id="Marketing" class="janusec-cookie-tabcontent">
			<div class="janusec-cookie-type-line">
			<span>Marketing Cookies</span>
			<span>
			<div class="janusec-cookie-switch-box">
				<input id="marketingPermit" type="checkbox" class="switch" />
				<label for="marketingPermit"></label>
			</div>
			</span>
			</div>
			<p class="janusec-cookie-common-text">{{ .App.MarketingNotice }}</p>
      <table class="janusec-cookie-preference-table">
      <tr> <th>Name</th> <th>Domain</th> <th>Path</th> <th>Duration</th> <th>Vendor</th> <th>Description</th> </tr>
      {{ range .App.Cookies }}
          {{ if (eq .Type 8) }}
          <tr> <td>{{ .Name }}</td>  <td>{{ .Domain }}</td> <td>{{ .Path }}</td> <td>{{ .Duration }}</td> <td>{{ .Vendor }}</td> <td>{{ .Description }}</td> </tr>
          {{ end }}
      {{ end }}
      </table>
		</div>

    <div id="Unclassified" class="janusec-cookie-tabcontent">
			<div class="janusec-cookie-type-line">
			<span>Unclassified Cookies</span>
			<span>
			<div class="janusec-cookie-switch-box">
				<input id="unclassifiedPermit" type="checkbox" class="switch" />
				<label for="unclassifiedPermit"></label>
			</div>
			</span>
			</div>
			<p class="janusec-cookie-common-text">{{ .App.UnclassifiedNotice }}</p>
      <table class="janusec-cookie-preference-table">
      <tr> <th>Name</th> <th>Domain</th> <th>Path</th> <th>Duration</th> <th>Vendor</th> <th>Description</th> </tr>
      {{ if .UnclassifiedEnabled }}
        {{ range .App.Cookies }}
            {{ if (eq .Type 512) }}
            <tr> <td>{{ .Name }}</td>  <td>{{ .Domain }}</td> <td>{{ .Path }}</td> <td>{{ .Duration }}</td> <td>{{ .Vendor }}</td> <td>{{ .Description }}</td> </tr>
            {{ end }}
        {{ end }}
      {{ end }}
      </table>
		</div>

	</div>
	<div class="janusec-cookie-div-container">
	<br>
		<button class="janusec-btn-confirm" onclick="saveCookiePreference()">Confirm My Choice</button>
	</div>
</div>
<br>
<div class="janusec-cookie-window-footer">
	<small><span>Powered by </span><span class="txt-janusec-logo">JANUSEC</span></small>
</div>
<script>
function toggleCookieOptWindow() {
  var display = document.getElementById("JanusecCookieOptWindow").style.display;
  if(display=='none') {
    document.getElementById("JanusecCookieOptWindow").style.display = 'block';
  } else {
    document.getElementById("JanusecCookieOptWindow").style.display = 'none';
  }
}

function openCookieTab(evt, cookieTab) {
  var i, cookieTabContent, tablinks;
  cookieTabContent = document.getElementsByClassName("janusec-cookie-tabcontent");
  for (i = 0; i < cookieTabContent.length; i++) {
    cookieTabContent[i].style.display = "none";
  }
  tablinks = document.getElementsByClassName("tablinks");
  for (i = 0; i < tablinks.length; i++) {
    tablinks[i].className = tablinks[i].className.replace(" active", "");
  }
  document.getElementById(cookieTab).style.display = "block";
  evt.currentTarget.className += " active";
}

function getCookie(cname) {
  const name = cname + "=";
  const ca = document.cookie.split(";");
  for(let i=0; i<ca.length; i++)
  {
      const c = ca[i].trim();
      if (c.indexOf(name)===0) return c.substring(name.length,c.length);
  }
  return "";
}

function setCookie(cname,cvalue,exdays){
  const d = new Date();
  d.setTime(d.getTime()+(exdays*24*60*60*1000));
  const expires = "expires=" + d.toUTCString();
  document.cookie = cname + "=" + cvalue + "; " + expires;
}

function closeCookieOptWindow() {
  document.getElementById("JanusecCookieOptWindow").style.display = "none";
}

function initCookieOptValue() {
  var optConsent = +getCookie("CookieOptConsent");
  if(optConsent==0) {
    document.getElementById("JanusecCookieOptWindow").style.display = "block";
    {{ if .App.EnableFunctional }}
    document.getElementById("functionalPermit").checked = true;
    {{ end }}
    {{ if .App.EnableAnalytics }}
    document.getElementById("analyticsPermit").checked = true;
    {{ end }}
    {{ if .App.EnableMarketing }}
    document.getElementById("marketingPermit").checked = true;
    {{ end }}
    {{ if .App.EnableUnclassified }}
    document.getElementById("unclassifiedPermit").checked = true;
    {{ end }}
    return;
  }
  if((optConsent & 2)>0) {
    document.getElementById("functionalPermit").checked = true;
  }
  if((optConsent & 4)>0) {
    document.getElementById("analyticsPermit").checked = true;
  }
  if((optConsent & 8)>0) {
    document.getElementById("marketingPermit").checked = true;
  }
  if((optConsent & 512)>0) {
    document.getElementById("unclassifiedPermit").checked = true;
  }
  closeCookieOptWindow();
}

function saveCookiePreference() {
  // initial:0, necessary: 1, functional: 2, analytics: 4, marketing: 8;
  var optConsent = 1;
  var functionalPermit = document.getElementById("functionalPermit").checked;
  if(functionalPermit) optConsent += 2;
  var analyticsPermit = document.getElementById("analyticsPermit").checked;
  if(analyticsPermit) optConsent += 4;
  var marketingPermit = document.getElementById("marketingPermit").checked;
  if(marketingPermit) optConsent += 8;
  var unclassifiedPermit = document.getElementById("unclassifiedPermit").checked;
  if(unclassifiedPermit) optConsent += 512;
  setCookie("CookieOptConsent", optConsent, 365);
  closeCookieOptWindow();
}

function rejectAllCookies() {
  document.getElementById("functionalPermit").checked = false;
  document.getElementById("analyticsPermit").checked = false;
  document.getElementById("marketingPermit").checked = false;
  document.getElementById("unclassifiedPermit").checked = false;
  setCookie("CookieOptConsent", 1, 365);
  closeCookieOptWindow();
}

function acceptAllCookies() {
  document.getElementById("functionalPermit").checked = true;
  document.getElementById("analyticsPermit").checked = true;
  document.getElementById("marketingPermit").checked = true;
  document.getElementById("unclassifiedPermit").checked = true;
  setCookie("CookieOptConsent", 1+2+4+8+512, 365);
  closeCookieOptWindow();
}

// Get the element with id="defaultOpen" and click on it
document.getElementById("defaultOpen").click();
initCookieOptValue();
</script>
</div>`

func getNodeByData(node *html.Node, data string) *html.Node {
	if node.Type == html.ElementNode && node.Data == data {
		return node
	}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		childNode := getNodeByData(child, data)
		if childNode != nil {
			return childNode
		}
	}
	return nil
}

func ConvertStringToHTMLNode(text string, labelData string) *html.Node {
	labelNode, err := html.Parse(strings.NewReader(text))
	if err != nil {
		fmt.Println("html.Parse error", err)
	}
	labelNode2 := getNodeByData(labelNode, labelData)
	labelNode2.Parent = nil
	return labelNode2
}
