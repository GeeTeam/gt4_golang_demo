package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
)

// geetest 公钥
const CAPTCHA_ID string = "647f5ed2ed8acb4be36784e01556bb71"

// geetest 密钥
const CAPTCHA_KEY string = "b09a7aafbfd83f73b35a9b530d0337bf"

// geetest 服务地址
const API_SERVER string = "http://gcaptcha4.geetest.com"

// geetest 验证接口
const URL = API_SERVER + "/validate" + "?captcha_id=" + CAPTCHA_ID

//  index.html
func index(response http.ResponseWriter, req *http.Request) {
	html_response, err := template.ParseFiles("static/index.html")
	if err == nil {
		html_response.Execute(response, "")
	}
}

// login post请求处理
func login(writer http.ResponseWriter, request *http.Request) {
	if request.Method != "GET" {
		writer.WriteHeader(405)
		return
	}
	// 前端传回的数据
	datas := request.URL.Query()
	lot_number := datas["lot_number"][0]
	captcha_output := datas["captcha_output"][0]
	pass_token := datas["pass_token"][0]
	gen_time := datas["gen_time"][0]
	// 生成签名
	// 生成签名使用标准的hmac算法，使用用户当前完成验证的流水号lot_number作为原始消息message，使用客户验证私钥作为key
	// 采用sha256散列算法将message和key进行单向散列生成最终的 “sign_token” 签名
	sign_token := hmac_encode(CAPTCHA_KEY, lot_number)

	// 向极验转发前端数据 + “sign_token” 签名
	form_data := make(url.Values)
	form_data["lot_number"] = []string{lot_number}
	form_data["captcha_output"] = []string{captcha_output}
	form_data["pass_token"] = []string{pass_token}
	form_data["gen_time"] = []string{gen_time}
	form_data["sign_token"] = []string{sign_token}
	// 发起post
	resp, err := http.PostForm(URL, form_data)
	if err != nil {
		fmt.Println("接口错误: ")
		fmt.Println(err)
		return
	}

	res_json, _ := ioutil.ReadAll(resp.Body)

	// 根据极验返回的用户验证状态, 网站主进行自己的业务逻辑
	var geetest_res map[string]interface{}
	if err := json.Unmarshal([]byte(res_json), &geetest_res); err == nil {
		result := geetest_res["result"]
		if result == "success" {
			fmt.Println("验证通过")
			writer.Write([]byte("success"))
		} else {
			fmt.Println("验证失败")
			writer.Write([]byte("fail"))
		}
	}
}

// hmac-sha256 加密：  CAPTCHA_KEY,lot_number
func hmac_encode(key string, data string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

func main() {
	http.HandleFunc("/", index)
	http.HandleFunc("/login", login)
	http.ListenAndServe(":8001", nil)
}
