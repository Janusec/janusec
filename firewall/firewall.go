/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:33:51
 * @Last Modified: U2, 2018-07-14 16:33:51
 */

package firewall

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/Janusec/janusec/models"
	"github.com/Janusec/janusec/utils"
)

var staticSuffix []string = []string{".js", ".css", ".png", ".jpg", ".gif", ".bmp"}

func IsStaticResource(url string) bool {
	if strings.Contains(url, "?") {
		return false
	}
	for _, suffix := range staticSuffix {
		if strings.HasSuffix(url, suffix) {
			return true
		}
	}
	return false
}

func UnEscapeRawValue(rawQuery string) string {
	rawQuery = strings.Replace(rawQuery, "%%", "%25%", -1)
	rawQuery = strings.Replace(rawQuery, "%'", "%25'", -1)
	rawQuery = strings.Replace(rawQuery, `%"`, `%25"`, -1)
	re := regexp.MustCompile(`%$`)
	rawQuery = re.ReplaceAllString(rawQuery, `%25`)
	decodeQuery, err := url.QueryUnescape(rawQuery)
	utils.CheckError("UnEscapeRawValue", err)
	decodeQuery = PreProcessString(decodeQuery)
	//fmt.Println("UnEscapeRawValue decodeQuery", decodeQuery)
	return decodeQuery
}

func IsRequestHitPolicy(r *http.Request, appID int64, srcIP string) (bool, *models.GroupPolicy) {
	if r.Method == "GET" && IsStaticResource(r.URL.Path) {
		return false, nil
	}
	//fmt.Println("IsForbiddenRequest")
	ctxMap := r.Context().Value("groupPolicyHitValue").(*sync.Map)

	// ChkPoint_Host
	matched, policy := IsMatchGroupPolicy(ctxMap, appID, r.Host, models.ChkPointHost, "", false)
	if matched == true {
		return matched, policy
	}

	// ChkPoint_IPAddress
	matched, policy = IsMatchGroupPolicy(ctxMap, appID, srcIP, models.ChkPointIPAddress, "", false)
	if matched == true {
		return matched, policy
	}

	// ChkPoint_Method
	matched, policy = IsMatchGroupPolicy(ctxMap, appID, r.Method, models.ChkPointMethod, "", false)
	if matched == true {
		return matched, policy
	}

	// ChkPoint_URLPath
	matched, policy = IsMatchGroupPolicy(ctxMap, appID, r.URL.Path, models.ChkPointURLPath, "", false)
	if matched == true {
		return matched, policy
	}
	// ChkPoint_URLQuery
	if len(r.URL.RawQuery) > 0 {
		//decode_query := UnEscapeRawValue(r.URL.RawQuery)
		//fmt.Println("decode_query:", decode_query)
		matched, policy = IsMatchGroupPolicy(ctxMap, appID, r.URL.RawQuery, models.ChkPointURLQuery, "", true)
		if matched == true {
			return matched, policy
		}
	}

	// ChkPoint_ParameterCount

	bodyBuf, _ := ioutil.ReadAll(r.Body)
	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBuf))
	contentType := r.Header.Get("Content-Type")

	mediaType, mediaParams, _ := mime.ParseMediaType(contentType)
	if strings.HasPrefix(mediaType, "multipart/form-data") {
		// ChkPoint_UploadFileExt
		r.ParseMultipartForm(1024)
		for _, filesHeader := range r.MultipartForm.File {
			for _, fileHeader := range filesHeader {
				fileExtension := filepath.Ext(fileHeader.Filename) // .php
				matched, policy = IsMatchGroupPolicy(ctxMap, appID, fileExtension, models.ChkPointUploadFileExt, "", false)
				if matched == true {
					return matched, policy
				}
			}
		}

		// Multipart Content
		body1 := ioutil.NopCloser(bytes.NewBuffer(bodyBuf))
		multiReader := multipart.NewReader(body1, mediaParams["boundary"])
		for {
			p, err := multiReader.NextPart()
			if err == io.EOF {
				break
			}
			partContent, err := ioutil.ReadAll(p)
			//fmt.Println("part_content=", string(part_content))
			matched, policy = IsMatchGroupPolicy(ctxMap, appID, string(partContent), models.ChkPointGetPostValue, "", true)
			if matched == true {
				return matched, policy
			}
		}
	} else if strings.HasPrefix(mediaType, "application/json") {
		var params interface{}
		err := json.Unmarshal(bodyBuf, &params)
		utils.CheckError("IsRequestHitPolicy Unmarshal", err)
		matched, policy := IsJsonValueHitPolicy(ctxMap, appID, params)
		if matched == true {
			return matched, policy
		}
	} else {
		r.ParseForm()
	}

	params := r.Form // include GET/POST/ Multipart non-File , but not include json

	//fmt.Println("IsRequestHitPolicy params:", params, "count:", len(params))
	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBuf))
	for key, values := range params {
		//fmt.Println("IsRequestHitPolicy param", key, ":", values)
		// ChkPoint_GetPostKey
		matched, policy = IsMatchGroupPolicy(ctxMap, appID, key, models.ChkPointGetPostKey, "", false)
		if matched == true {
			return matched, policy
		}

		for _, value := range values {
			if isDigit, err := IsMatch(`^\d{1,5}$`, value); err == nil {
				if isDigit {
					continue
				}
			}
			// ChkPoint_ValueLength
			valueLength := strconv.Itoa(len(value))
			matched, policy = IsMatchGroupPolicy(ctxMap, appID, valueLength, models.ChkPointValueLength, "", false)
			if matched == true {
				return matched, policy
			}
			// ChkPoint_GetPostValue
			matched, policy = IsMatchGroupPolicy(ctxMap, appID, value, models.ChkPointGetPostValue, "", true)
			//fmt.Println("ChkPoint_GetPostValue:", value2, matched)
			if matched == true {
				return matched, policy
			}
		}

	}

	// ChkPoint_Cookie
	cookies := r.Cookies()
	for _, cookie := range cookies {
		// ChkPoint_CookieKey
		matched, policy = IsMatchGroupPolicy(ctxMap, appID, cookie.Name, models.ChkPointCookieKey, "", false)
		if matched == true {
			return matched, policy
		}
		// ChkPoint_CookieValue
		//value := UnEscapeRawValue(cookie.Value)
		//fmt.Println("CookieValue:", value)
		matched, policy = IsMatchGroupPolicy(ctxMap, appID, cookie.Value, models.ChkPointCookieValue, "", true)
		if matched == true {
			return matched, policy
		}
	}

	// ChkPoint_UserAgent
	matched, policy = IsMatchGroupPolicy(ctxMap, appID, r.UserAgent(), models.ChkPointUserAgent, "", false)
	if matched == true {
		return matched, policy
	}

	// ChkPoint_ContentType media_type
	matched, policy = IsMatchGroupPolicy(ctxMap, appID, mediaType, models.ChkPointContentType, "", false)
	if matched == true {
		return matched, policy
	}

	// ChkPoint_Header
	for header_key, header_values := range r.Header {
		// ChkPoint_HeaderKey
		matched, policy = IsMatchGroupPolicy(ctxMap, appID, header_key, models.ChkPointHeaderKey, "", false)
		if matched == true {
			return matched, policy
		}
		// ChkPoint_HeaderValue
		for _, header_value := range header_values {

			//header_value = UnEscapeRawValue(header_value)
			matched, policy = IsMatchGroupPolicy(ctxMap, appID, header_value, models.ChkPointHeaderValue, header_key, false)
			//fmt.Println("ChkPoint_HeaderValue", header_key, header_value, matched)
			if matched == true {
				return matched, policy
			}
		}
	}

	// ChkPoint_Proto
	matched, policy = IsMatchGroupPolicy(ctxMap, appID, r.Proto, models.ChkPointUserAgent, "", false)
	if matched == true {
		return matched, policy
	}

	return false, nil
}

func IsResponseHitPolicy(resp *http.Response, app_id int64) (bool, *models.GroupPolicy) {
	ctxMap := resp.Request.Context().Value("groupPolicyHitValue").(*sync.Map)
	// ChkPoint_ResponseStatusCode
	matched, policy := IsMatchGroupPolicy(ctxMap, app_id, strconv.Itoa(resp.StatusCode), models.ChkPointResponseStatusCode, "", false)
	//fmt.Println("IsResponseHitPolicy ResponseStatusCode", matched)
	if matched == true {
		return matched, policy
	}
	// ChkPoint_ResponseHeaderKey
	for header_key, header_values := range resp.Header {
		// ChkPoint_ResponseHeaderKey
		matched, policy = IsMatchGroupPolicy(ctxMap, app_id, header_key, models.ChkPointResponseHeaderKey, "", false)
		if matched == true {
			return matched, policy
		}
		// ChkPoint_ResponseHeaderValue
		for _, header_value := range header_values {
			matched, policy = IsMatchGroupPolicy(ctxMap, app_id, header_value, models.ChkPointResponseHeaderValue, header_key, false)
			//fmt.Println("ChkPoint_ResponseHeaderValue", header_key, header_value, matched)
			if matched == true {
				return matched, policy
			}
		}
	}
	// ChkPoint_ResponseBodyLength
	body_length := strconv.FormatInt(resp.ContentLength, 10)
	matched, policy = IsMatchGroupPolicy(ctxMap, app_id, body_length, models.ChkPointResponseBodyLength, "", false)
	//fmt.Println("IsResponseHitPolicy ChkPoint_ResponseBodyLength", matched)
	if matched == true {
		return matched, policy
	}
	// ChkPoint_ResponseBody
	body_buf, _ := ioutil.ReadAll(resp.Body)
	resp.Body = ioutil.NopCloser(bytes.NewBuffer(body_buf))
	defer resp.Body.Close()
	body1 := string(body_buf)
	matched, policy = IsMatchGroupPolicy(ctxMap, app_id, body1, models.ChkPointResponseBody, "", false)
	//fmt.Println("IsResponseHitPolicy ChkPoint_ResponseBody", matched)
	if matched == true {
		return matched, policy
	}

	// Not hit any policy
	return false, nil
}

func IsJsonValueHitPolicy(ctxMap *sync.Map, app_id int64, value interface{}) (bool, *models.GroupPolicy) {
	value_kind := reflect.TypeOf(value).Kind()
	switch value_kind {
	case reflect.String:
		value2 := value.(string)
		matched, policy := IsMatchGroupPolicy(ctxMap, app_id, value2, models.ChkPointGetPostValue, "", true)
		if matched == true {
			return matched, policy
		}
	case reflect.Map:
		value2 := value.(map[string]interface{})
		for _, sub_value := range value2 {
			matched, policy := IsJsonValueHitPolicy(ctxMap, app_id, sub_value)
			if matched == true {
				return matched, policy
			}
		}
	case reflect.Slice:
		value2 := value.([]interface{})
		for _, sub_value := range value2 {
			matched, policy := IsJsonValueHitPolicy(ctxMap, app_id, sub_value)
			if matched == true {
				return matched, policy
			}
		}
	}
	return false, nil
}
