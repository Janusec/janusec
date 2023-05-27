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
 .janusec-cookie-preference {
    position: fixed;
    top: 120px;
    left: 50%;
    padding: 0;
    margin-left: -300px;
    z-index: 9999;
    width: 600px;
    background-color: #FFFFFF;
    border: 1px solid #e0e0e0;
    opacity: 1;
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
 }
 
 .btn-cookie-preference {
    padding: 10px;
    color: #ffffff;
    border: solid 1px #F5F5F5;
    background-color: #6699DD;
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
   border: 1px solid #ccc;
   width: 30%;
   height: 220px;
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
   border: 1px solid #ccc;
   width: 70%;
   border-left: 1px solid #f5f5f5;
   height: 300px;
 }

 .btn-confirm {
	float: right;
	padding: 10px;
    color: #ffffff;
    border: solid 1px #303030;
    background-color: #6699DD;
 }

 .cookie-type-line {
	margin: 10px 0;
 }

 .txt-always-on {
	float: right;
	color: #6699DD;
 }
 /* toggle button */

 .switch-box {
	float: right;
    width: 40px;
}
.switch-box .switch {
    /* 隐藏checkbox默认样式 */
    display: none;
}
.switch-box label {
    /* 通过label扩大点击热区 */
    position: relative;
    display: block;
    margin: 1px;
    height: 20px;
    cursor: pointer;
}
.switch-box label::before {
    /* before设置前滚动小圆球 */
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
    /* 通过transform、transition属性控制元素过渡进而形成css3动画 */
    -webkit-transform: translateX(-9px);
    -moz-transform: translateX(-9px);
    transform: translateX(-9px);
    -webkit-transition: all 0.3s ease;
    -moz-transition: all 0.3s ease;
    transition: all 0.3s ease;
}
.switch-box .switch:checked~label::before {
    /* 语义：被选中的类名为"switch"元素后面的label元素里的伪类元素，进行更改css样式 */
    /* 形成伪类结构选择器：":"冒号加布尔值"checked" */
    /* " Ele1 ~ Ele2 "波浪号在css的作用：连接的元素必须有相同的父元素，选择出现在Ele1后的Ele2（但不必跟在Ele1，也就是说可以并列）  */
    -webkit-transform: translateX(9px);
    -moz-transform: translateX(9px);
    transform: translateX(9px);
}
.switch-box label::after {
    /* after设置滚动前背景色 */
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
    background-color: #6699DD;
}
/* end toggle button */
 </style>`

const cookieDiv = `
<div #JanusecCookie class="janusec-cookie-preference">
<div class="cookie-outer-container">
    <div class="cookie-title-line">
    <span class="cookie-window-title">Cookie Preference</span>
	<span><button class="btn-cookie-window-close">×</button></span>
    </div>
	<p class="common-text">We use necessary cookies to make our site work. We'd also like to set analytics cookies that help us make
		improvements by measuring how you use the site. These will be set only if you accept.
		For more detailed information about the cookies we use, see our cookies policy.</p>
	<div>
		<button class="btn-cookie-preference">Reject all cookies</button>
		<span>&nbsp;&nbsp;&nbsp;&nbsp;</span>
		<button class="btn-cookie-preference">Accept all cookies</button>
	</div>
	<hr>
	<div class="cookie-div-container">
		<div class="cookie-tab">
			<button class="tablinks" onclick="openCity(event, 'Necessary')" id="defaultOpen">Necessary Cookies</button>
			<button class="tablinks" onclick="openCity(event, 'Analytics')">Analytics Cookies</button>
			<button class="tablinks" onclick="openCity(event, 'Marketing')">Marketing Cookies</button>
		</div>
		
		<div id="Necessary" class="tabcontent">
			<div class="cookie-type-line">
			<span>Necessary Cookies</span>
			<span class="txt-always-on">Always On</span>
			</div>
			<p class="common-text">Necessary cookies enable core functionality such as security, network management, and accessibility. You
			may disable these by changing your browser settings, but this may affect how the website functions.
		</p>
		</div>
		
		<div id="Analytics" class="tabcontent">
		    <div class="cookie-type-line">
			<span>Analytics Cookies</span>
			<span>
			<div class="switch-box">
				<input id="switchButton" type="checkbox" class="switch" />
				<label for="switchButton"></label>
			</div>
			</span>
			</div>
			<p class="common-text">These cookies allow us to count visits and traffic sources so we can measure and improve the performance of our site. They help us to know which pages are the most and least popular and see how visitors move around the site. All information these cookies collect is aggregated and therefore anonymous. However, the third parties providing these services, they will process your personal data in order to provide the aggregated data.</p> 
		</div>
		
		<div id="Marketing" class="tabcontent">
			<div class="cookie-type-line">
			<span>Marketing Cookies</span>
			<span>
			<div class="switch-box">
				<input id="switchButton2" type="checkbox" class="switch" />
				<label for="switchButton2"></label>
			</div>
			</span>
			</div>
			<p class="common-text">These cookies are set by our advertising partners. They are used to build a profile of your interests and show relevant ads on other websites. They do not store directly personal information, but are based on uniquely identifying your browser and internet device. Additionally, the third parties setting these cookies may link your personal data with your browsing behaviour if you are logged into their services at the time.</p>
		</div>
	</div>
	<div class="cookie-div-container">
	<br>
		<button class="btn-confirm">Confirm My Choice</button>
	</div>
</div>
<br>
<div class="cookie-window-footer">
	<small>Powered by JANUSEC</small>
</div>
<script>
function openCity(evt, cityName) {
  var i, tabcontent, tablinks;
  tabcontent = document.getElementsByClassName("tabcontent");
  for (i = 0; i < tabcontent.length; i++) {
    tabcontent[i].style.display = "none";
  }
  tablinks = document.getElementsByClassName("tablinks");
  for (i = 0; i < tablinks.length; i++) {
    tablinks[i].className = tablinks[i].className.replace(" active", "");
  }
  document.getElementById(cityName).style.display = "block";
  evt.currentTarget.className += " active";
}

// Get the element with id="defaultOpen" and click on it
document.getElementById("defaultOpen").click();
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
