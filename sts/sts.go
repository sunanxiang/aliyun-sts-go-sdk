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
*     Initial: 2017/08/08          Sun Anxiang
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
)

type AliyunStsClient struct {
	ChildAccountKeyId    string
	ChildAccountSecret string
	RoleAcs            string
}

func NewStsClient(key, secret, roleAcs string) *AliyunStsClient {
	return &AliyunStsClient{
		ChildAccountKeyId:    key,
		ChildAccountSecret: secret,
		RoleAcs:            roleAcs,
	}
}

func (cli *AliyunStsClient) GenerateSignatureUrl(sessionName, durationSeconds string) (string, error) {
	assumeUrl := "SignatureVersion=1.0"
	assumeUrl += "&Format=JSON"
	assumeUrl += "&Timestamp=" + url.QueryEscape(time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	assumeUrl += "&RoleArn=" + url.QueryEscape(cli.RoleAcs)
	assumeUrl += "&RoleSessionName=" + sessionName
	assumeUrl += "&AccessKeyId=" + cli.ChildAccountKeyId
	assumeUrl += "&SignatureMethod=HMAC-SHA1"
	assumeUrl += "&Version=2015-04-01"
	assumeUrl += "&Action=AssumeRole"
	assumeUrl += "&SignatureNonce=" + uuid.NewV4().String()
	assumeUrl += "&DurationSeconds=" + durationSeconds

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
	hashSign := hmac.New(sha1.New, []byte(cli.ChildAccountSecret+"&"))
	hashSign.Write([]byte(StringToSign))

	// 生成signature
	signature := base64.StdEncoding.EncodeToString(hashSign.Sum(nil))

	// Url 添加signature
	assumeUrl = "https://sts.aliyuncs.com/?" + assumeUrl + "&Signature=" + url.QueryEscape(signature)

	return assumeUrl, nil
}

// 请求构造好的URL,获得授权信息
// TODO: 安全认证 HTTPS
func (cli *AliyunStsClient) GetStsResponse(url string) ([]byte, error) {
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

	return body, err
}
