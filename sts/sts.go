/*
* MIT License
*
* Copyright (c) 2017 Ryan
*
* Permission is hereby granted, free of charge, to any person obtaining a copy of
* this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
 */

/*
* Revision History
*     Initial: 2017/08/07          Sun Anxiang
 */

package sts

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/satori/go.uuid"

	"aliyun-sts-go-sdk/general"
)

// 请求返回的结构体，没有使用，返回的是字节流切片
type AssumeRoleResponse struct {
	AssumedRoleUser   AssumeRole
	RequireId         string
	Credentials       Credential
}

type AssumeRole struct {
	Arn               string
	AssumedRoleUserId string
}

type Credential struct {
	AccessKeyId       string
	AccessKeySecret   string
	Expiration        string
	SecurityToken     string
}

// 构造带有签名的请求URL
func GenerateSignatureUrl() (string, error) {
	// 构造不带签名的请求URL
	assumeUrl := "SignatureVersion=1.0"
	assumeUrl += "&Format=JSON"
	assumeUrl += "&Timestamp=" + url.QueryEscape(time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	assumeUrl += "&RoleArn=" + url.QueryEscape(general.RoleAcs)
	assumeUrl += "&RoleSessionName=client"
	assumeUrl += "&AccessKeyId=" + general.TempKey
	assumeUrl += "&SignatureMethod=HMAC-SHA1"
	assumeUrl += "&Version=2015-04-01"
	assumeUrl += "&Action=AssumeRole"
	assumeUrl += "&SignatureNonce=" + uuid.NewV4().String()
	assumeUrl += "&DurationSeconds=" + general.DurationSeconds

	// 解析成V type
	signToString, err := url.ParseQuery(assumeUrl)
	if err != nil {
		return "", err
	}

	// URL顺序化
	result := signToString.Encode()

	// 拼接
	StringToSign := "GET" + "&" + "%2F" + "&" + url.QueryEscape(result)

	// HMAC
	hashSign := hmac.New(sha1.New, []byte(general.TempSecret+"&"))
	hashSign.Write([]byte(StringToSign))

	// 生成signature
	strResult := base64.StdEncoding.EncodeToString(hashSign.Sum(nil))

	// Url 添加signature
	assumeUrl = general.StsEndpoint + assumeUrl + "&Signature=" + url.QueryEscape(strResult)

	return assumeUrl, nil
}

// 请求构造好的URL,获得授权信息
func GetStsResponse(url string) ([]byte, error) {
	// var result AssumeRoleResponse

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, err
}
