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
    margin-left: -300px;
    z-index: 9999;
    width: 600px;
    background-color: #FFFFFF;
    border: 2px solid #e0e0e0;
    opacity: 1;
 }
 
  #JanusecCookieOptWindow div,p,span {
    text-align: left;
  }

 .cookie-title-line {
    margin-top: 10px;
    padding: 5px 0;
 }

 .cookie-window-title {
    font-size: 16px;
 }

 .btn-cookie-window-close {
	float: right;
    border: none;
    font-size: 16px;
	background-color: #FCFCFC;
 }

 .cookie-outer-container {
    margin: 0 10px;
	/* clear float */
	overflow: hidden;
 }

 .cookie-div-container {
	/* clear float */
	overflow: hidden;
 }

 .common-text {
	color: #808080;
  font-size: 12px;
 }
 
 .btn-cookie-save {
    padding: 10px;
    color: #ffffff;
    border: solid 1px #F5F5F5;
    background-color: #007bff;
 }
 
 .cookie-window-footer {
    display: block;
    float: none;
    background-color: #f0f0f0;
    text-align: right;
    padding: 5px;
 }
 
 * {
    box-sizing: border-box
 }
 
 .cookie-tab {
   float: left;
   border: 1px solid #c0c0c0;
   width: 30%;
   height: 300px;
 }
 
 .cookie-tab button {
   display: block;
   background-color: inherit;
   color: black;
   padding: 22px 16px;
   width: 100%;
   border: none;
   outline: none;
   text-align: left;
   cursor: pointer;
   transition: 0.3s;
   font-size: 14px;
 }
 
 .cookie-tab button:hover {
   background-color: #ddd;
 }
 
 .cookie-tab button.active {
   background-color: #f0f0f0;
 }
 
 .tabcontent {
   float: left;
   padding: 0px 12px;
   border: 1px solid #c0c0c0;
   width: 70%;
   border-left: 1px solid #e0e0e0;
   height: 300px;
 }

 .btn-confirm {
	float: right;
	padding: 10px;
  color: #ffffff;
  border: solid 1px #F5F5F5;
  background-color: #007bff;
 }

 .cookie-type-line {
	margin: 10px 0;
 }

 .txt-always-on {
	float: right;
	color: #007bff;
 }

 .txt-janusec-logo {
  color: #007bff;
 }

 /* toggle button */

 .switch-box {
	float: right;
  width: 40px;
}

.switch-box .switch {
    display: none;
}

.switch-box label {
    position: relative;
    display: block;
    margin: 1px;
    height: 20px;
    cursor: pointer;
}

.switch-box label::before {
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

.switch-box .switch:checked~label::before {
    -webkit-transform: translateX(9px);
    -moz-transform: translateX(9px);
    transform: translateX(9px);
}

.switch-box label::after {
    content: "";
    display: block;
    border-radius: 10px;
    height: 20px;
    background-color: #dcdfe6;
    -webkit-transition: all 0.3s ease;
    -moz-transition: all 0.3s ease;
    transition: all 0.3s ease;
}

.switch-box .switch:checked~label::after {
    background-color: #007bff;
}

/* end toggle button */

 </style>`

const cookieIconTmpl = `
<div id="JanusecCookieOptIcon">
    <button onclick="toggleCookieOptWindow()">C</button>
</div>`

const cookieWindowTmpl = `
<div id="JanusecCookieOptWindow">
<div class="cookie-outer-container">
  <div class="cookie-title-line">
    <span class="cookie-window-title">Cookie Preference</span>
    <span>
      <button class="btn-cookie-window-close" onclick="closeCookieOptWindow()">×</button>
    </span>
  </div>
  <p class="common-text">
    {{ .ConciseNotice }} For more detailed information about the cookies we use, see our 
    <a href="{{ .LongNoticeLink }}" target="_blank">cookies notice</a>.
  </p>
	<div>
		<button class="btn-cookie-save" onclick="rejectAllCookies()">Reject all Cookies</button>
		<span>&nbsp;&nbsp;&nbsp;&nbsp;</span>
		<button class="btn-cookie-save" onclick="acceptAllCookies()">Accept all Cookies</button>
	</div>
	<hr>
	<div class="cookie-div-container">
		<div class="cookie-tab">
			<button class="tablinks" onclick="openCookieTab(event, 'Necessary')" id="defaultOpen">Necessary Cookies</button>
			<button class="tablinks" onclick="openCookieTab(event, 'Analytics')">Analytics Cookies</button>
			<button class="tablinks" onclick="openCookieTab(event, 'Marketing')">Marketing Cookies</button>
      <button class="tablinks" onclick="openCookieTab(event, 'Unclassified')">Unclassified Cookies</button>
		</div>
		
		<div id="Necessary" class="tabcontent">
			<div class="cookie-type-line">
			<span>Necessary Cookies</span>
			<span class="txt-always-on">Always On</span>
			</div>
			<p class="common-text">{{ .NecessaryNotice }}</p>
		</div>
		
		<div id="Analytics" class="tabcontent">
		  <div class="cookie-type-line">
			<span>Analytics Cookies</span>
			<span>
			<div class="switch-box">
				<input id="analyticsPermit" type="checkbox" class="switch" />
				<label for="analyticsPermit"></label>
			</div>
			</span>
			</div>
			<p class="common-text">{{ .AnalyticsNotice }}</p> 
		</div>
		
		<div id="Marketing" class="tabcontent">
			<div class="cookie-type-line">
			<span>Marketing Cookies</span>
			<span>
			<div class="switch-box">
				<input id="marketingPermit" type="checkbox" class="switch" />
				<label for="marketingPermit"></label>
			</div>
			</span>
			</div>
			<p class="common-text">{{ .MarketingNotice }}</p>
		</div>

    <div id="Unclassified" class="tabcontent">
			<div class="cookie-type-line">
			<span>Unclassified Cookies</span>
			<span>
			<div class="switch-box">
				<input id="unclassifiedPermit" type="checkbox" class="switch" />
				<label for="unclassifiedPermit"></label>
			</div>
			</span>
			</div>
			<p class="common-text">{{ .UnclassifiedNotice }}</p>
		</div>

	</div>
	<div class="cookie-div-container">
	<br>
		<button class="btn-confirm" onclick="saveCookiePreference()">Confirm My Choice</button>
	</div>
</div>
<br>
<div class="cookie-window-footer">
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
  var i, tabcontent, tablinks;
  tabcontent = document.getElementsByClassName("tabcontent");
  for (i = 0; i < tabcontent.length; i++) {
    tabcontent[i].style.display = "none";
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
  console.log("optConsent", optConsent);
  if(optConsent==0) {
    document.getElementById("JanusecCookieOptWindow").style.display = "block";
    {{ if .EnableAnalytics }}
    document.getElementById("analyticsPermit").checked = true;
    {{ end }}
    {{ if .EnableMarketing }}
    document.getElementById("marketingPermit").checked = true;
    {{ end }}
    {{ if .EnableUnclassified }}
    document.getElementById("unclassifiedPermit").checked = true;
    {{ end }}
    return;
  }
  if((optConsent & 2)>0) {
    document.getElementById("analyticsPermit").checked = true;
  }
  if((optConsent & 4)>0) {
    document.getElementById("marketingPermit").checked = true;
  }
  if((optConsent & 512)>0) {
    document.getElementById("unclassifiedPermit").checked = true;
  }
  closeCookieOptWindow();
}

function saveCookiePreference() {
  // initial:0, necessary: 1, analytics: 2, marketing: 4;
  var optConsent = 1;
  var analyticsPermit = document.getElementById("analyticsPermit").checked;
  if(analyticsPermit) optConsent += 2;
  var marketingPermit = document.getElementById("marketingPermit").checked;
  if(marketingPermit) optConsent += 4;
  var unclassifiedPermit = document.getElementById("unclassifiedPermit").checked;
  if(unclassifiedPermit) optConsent += 512;
  setCookie("CookieOptConsent", optConsent, 365);
  closeCookieOptWindow();
}

function rejectAllCookies() {
  document.getElementById("analyticsPermit").checked = false;
  document.getElementById("marketingPermit").checked = false;
  document.getElementById("unclassifiedPermit").checked = false;
  setCookie("CookieOptConsent", 1, 365);
  closeCookieOptWindow();
}

function acceptAllCookies() {
  document.getElementById("analyticsPermit").checked = true;
  document.getElementById("marketingPermit").checked = true;
  document.getElementById("unclassifiedPermit").checked = true;
  setCookie("CookieOptConsent", 1+2+4+512, 365);
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
