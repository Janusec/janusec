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

	"../models"
	"../utils"
)

var static_suffix []string = []string{".js", ".css", ".png", ".jpg", ".gif", ".bmp"}

func IsStaticResource(url string) bool {
	if strings.Contains(url, "?") {
		return false
	}
	for _, suffix := range static_suffix {
		if strings.HasSuffix(url, suffix) {
			return true
		}
	}
	return false
}

func UnEscapeRawValue(raw_query string) string {
	raw_query = strings.Replace(raw_query, "%%", "%25%", -1)
	raw_query = strings.Replace(raw_query, "%'", "%25'", -1)
	raw_query = strings.Replace(raw_query, `%"`, `%25"`, -1)
	re := regexp.MustCompile(`%$`)
	raw_query = re.ReplaceAllString(raw_query, `%25`)
	decode_query, err := url.QueryUnescape(raw_query)
	utils.CheckError("UnEscapeRawValue", err)
	decode_query = PreProcessString(decode_query)
	//fmt.Println("UnEscapeRawValue decode_query", decode_query)
	return decode_query
}

func IsRequestHitPolicy(r *http.Request, app_id int64, src_ip string) (bool, *models.GroupPolicy) {
	if r.Method == "GET" && IsStaticResource(r.URL.Path) {
		return false, nil
	}
	//fmt.Println("IsForbiddenRequest")
	ctxMap := r.Context().Value("group_policy_hit_value").(*sync.Map)

	// ChkPoint_Host
	matched, policy := IsMatchGroupPolicy(ctxMap, app_id, r.Host, models.ChkPoint_Host, "", false)
	if matched == true {
		return matched, policy
	}

	// ChkPoint_IPAddress
	matched, policy = IsMatchGroupPolicy(ctxMap, app_id, src_ip, models.ChkPoint_IPAddress, "", false)
	if matched == true {
		return matched, policy
	}

	// ChkPoint_Method
	matched, policy = IsMatchGroupPolicy(ctxMap, app_id, r.Method, models.ChkPoint_Method, "", false)
	if matched == true {
		return matched, policy
	}

	// ChkPoint_URLPath
	matched, policy = IsMatchGroupPolicy(ctxMap, app_id, r.URL.Path, models.ChkPoint_URLPath, "", false)
	if matched == true {
		return matched, policy
	}
	// ChkPoint_URLQuery
	if len(r.URL.RawQuery) > 0 {
		//decode_query := UnEscapeRawValue(r.URL.RawQuery)
		//fmt.Println("decode_query:", decode_query)
		matched, policy = IsMatchGroupPolicy(ctxMap, app_id, r.URL.RawQuery, models.ChkPoint_URLQuery, "", true)
		if matched == true {
			return matched, policy
		}
	}

	// ChkPoint_ParameterCount

	body_buf, _ := ioutil.ReadAll(r.Body)
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body_buf))
	content_type := r.Header.Get("Content-Type")

	media_type, media_params, _ := mime.ParseMediaType(content_type)
	//fmt.Println("media_type=", media_type)
	if strings.HasPrefix(media_type, "multipart/form-data") {
		// ChkPoint_UploadFileExt
		r.ParseMultipartForm(1024)
		for _, files_header := range r.MultipartForm.File {
			for _, file_header := range files_header {
				file_extension := filepath.Ext(file_header.Filename) // .php
				matched, policy = IsMatchGroupPolicy(ctxMap, app_id, file_extension, models.ChkPoint_UploadFileExt, "", false)
				if matched == true {
					return matched, policy
				}
			}
		}

		// Multipart Content
		body1 := ioutil.NopCloser(bytes.NewBuffer(body_buf))
		multi_reader := multipart.NewReader(body1, media_params["boundary"])
		for {
			p, err := multi_reader.NextPart()
			if err == io.EOF {
				break
			}
			part_content, err := ioutil.ReadAll(p)
			//fmt.Println("part_content=", string(part_content))
			matched, policy = IsMatchGroupPolicy(ctxMap, app_id, string(part_content), models.ChkPoint_GetPostValue, "", true)
			if matched == true {
				return matched, policy
			}
		}
	} else if strings.HasPrefix(media_type, "application/json") {
		var params interface{}
		err := json.Unmarshal(body_buf, &params)
		utils.CheckError("IsRequestHitPolicy Unmarshal", err)
		matched, policy := IsJsonValueHitPolicy(ctxMap, app_id, params)
		if matched == true {
			return matched, policy
		}
	} else {
		r.ParseForm()
	}

	params := r.Form // include GET/POST/ Multipart non-File , but not include json

	//fmt.Println("IsRequestHitPolicy params:", params, "count:", len(params))
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body_buf))
	for key, values := range params {
		//fmt.Println("IsRequestHitPolicy param", key, ":", values)
		// ChkPoint_GetPostKey
		matched, policy = IsMatchGroupPolicy(ctxMap, app_id, key, models.ChkPoint_GetPostKey, "", false)
		if matched == true {
			return matched, policy
		}

		for _, value := range values {
			if is_digit, err := IsMatch(`^\d{1,5}$`, value); err == nil {
				//fmt.Println("is_digit:", is_digit)
				if is_digit {
					continue
				}
			}
			// ChkPoint_ValueLength
			value_length := strconv.Itoa(len(value))
			matched, policy = IsMatchGroupPolicy(ctxMap, app_id, value_length, models.ChkPoint_ValueLength, "", false)
			//fmt.Println("ChkPoint_ValueLength:", value_length, matched)
			if matched == true {
				return matched, policy
			}
			// ChkPoint_GetPostValue
			//value2 := UnEscapeRawValue(value)
			matched, policy = IsMatchGroupPolicy(ctxMap, app_id, value, models.ChkPoint_GetPostValue, "", true)
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
		matched, policy = IsMatchGroupPolicy(ctxMap, app_id, cookie.Name, models.ChkPoint_CookieKey, "", false)
		if matched == true {
			return matched, policy
		}
		// ChkPoint_CookieValue
		//value := UnEscapeRawValue(cookie.Value)
		//fmt.Println("CookieValue:", value)
		matched, policy = IsMatchGroupPolicy(ctxMap, app_id, cookie.Value, models.ChkPoint_CookieValue, "", true)
		if matched == true {
			return matched, policy
		}
	}

	// ChkPoint_UserAgent
	matched, policy = IsMatchGroupPolicy(ctxMap, app_id, r.UserAgent(), models.ChkPoint_UserAgent, "", false)
	if matched == true {
		return matched, policy
	}

	// ChkPoint_ContentType media_type
	matched, policy = IsMatchGroupPolicy(ctxMap, app_id, media_type, models.ChkPoint_ContentType, "", false)
	if matched == true {
		return matched, policy
	}

	// ChkPoint_Header
	for header_key, header_values := range r.Header {
		// ChkPoint_HeaderKey
		matched, policy = IsMatchGroupPolicy(ctxMap, app_id, header_key, models.ChkPoint_HeaderKey, "", false)
		if matched == true {
			return matched, policy
		}
		// ChkPoint_HeaderValue
		for _, header_value := range header_values {

			//header_value = UnEscapeRawValue(header_value)
			matched, policy = IsMatchGroupPolicy(ctxMap, app_id, header_value, models.ChkPoint_HeaderValue, header_key, false)
			//fmt.Println("ChkPoint_HeaderValue", header_key, header_value, matched)
			if matched == true {
				return matched, policy
			}
		}
	}

	// ChkPoint_Proto
	matched, policy = IsMatchGroupPolicy(ctxMap, app_id, r.Proto, models.ChkPoint_UserAgent, "", false)
	if matched == true {
		return matched, policy
	}

	return false, nil
}

func IsResponseHitPolicy(resp *http.Response, app_id int64) (bool, *models.GroupPolicy) {
	ctxMap := resp.Request.Context().Value("group_policy_hit_value").(*sync.Map)
	// ChkPoint_ResponseStatusCode
	matched, policy := IsMatchGroupPolicy(ctxMap, app_id, strconv.Itoa(resp.StatusCode), models.ChkPoint_ResponseStatusCode, "", false)
	//fmt.Println("IsResponseHitPolicy ResponseStatusCode", matched)
	if matched == true {
		return matched, policy
	}
	// ChkPoint_ResponseHeaderKey
	for header_key, header_values := range resp.Header {
		// ChkPoint_ResponseHeaderKey
		matched, policy = IsMatchGroupPolicy(ctxMap, app_id, header_key, models.ChkPoint_ResponseHeaderKey, "", false)
		if matched == true {
			return matched, policy
		}
		// ChkPoint_ResponseHeaderValue
		for _, header_value := range header_values {
			matched, policy = IsMatchGroupPolicy(ctxMap, app_id, header_value, models.ChkPoint_ResponseHeaderValue, header_key, false)
			//fmt.Println("ChkPoint_ResponseHeaderValue", header_key, header_value, matched)
			if matched == true {
				return matched, policy
			}
		}
	}
	// ChkPoint_ResponseBodyLength
	body_length := strconv.FormatInt(resp.ContentLength, 10)
	matched, policy = IsMatchGroupPolicy(ctxMap, app_id, body_length, models.ChkPoint_ResponseBodyLength, "", false)
	//fmt.Println("IsResponseHitPolicy ChkPoint_ResponseBodyLength", matched)
	if matched == true {
		return matched, policy
	}
	// ChkPoint_ResponseBody
	body_buf, _ := ioutil.ReadAll(resp.Body)
	resp.Body = ioutil.NopCloser(bytes.NewBuffer(body_buf))
	defer resp.Body.Close()
	body1 := string(body_buf)
	matched, policy = IsMatchGroupPolicy(ctxMap, app_id, body1, models.ChkPoint_ResponseBody, "", false)
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
		matched, policy := IsMatchGroupPolicy(ctxMap, app_id, value2, models.ChkPoint_GetPostValue, "", true)
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
