package main
//author 周旭鑫
import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"gopkg.in/ini.v1"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)
type Lists []string
var (
	ipServer IpServer
	AccessKeyId = ""
	AccessKeySecret = ""
	BaseUrl = "http://alidns.aliyuncs.com/?"
	//AccessKeyId = "testid"
	//AccessKeySecret = "testsecret"
	DomainList map[string]Lists
	wg sync.WaitGroup
)
type Appkey struct{
	AccessKeyId string `ini:"AccessKeyId"`
	AccessKeySecret string `ini:"AccessKeySecret"`
}
type IpServer struct{
	Url string `ini:"url"`
}
type Domain struct{
	Name string `ini:"name"`
}
type RR struct{
	R string `ini:"r"`
}


type Pair struct {
	Key string
	Value string
}
type PairList []Pair

func (p PairList) Swap(i,j int){
	p[i],p[j] = p[j],p[i]
}

func (p PairList) Len() int{
	return len(p)
}
func (p PairList) Less(i,j int) bool{
	return p[i].Key < p[j].Key
}

func SortMapByKey( m map[string]string) PairList  {
	p := make(PairList,0,len(m))
	for k,v := range m{
		p = append(p,Pair{k,v})
	}
	sort.Sort(p)
	return p
}

func LoadIni()  {
	cfg,err := ini.Load("domain.ini")
	if err != nil{
		panic(err)
	}

	//获取AccessKeyId,AccessKeySecret
	AppkeyStruct := Appkey{}
	err = cfg.Section("appkey").MapTo(&AppkeyStruct)
	if err != nil{
		panic(err)
	}
	AccessKeyId = AppkeyStruct.AccessKeyId
	AccessKeySecret = AppkeyStruct.AccessKeySecret

    err = cfg.Section("ipserver").MapTo(&ipServer)
	if err != nil{
		panic(err)
	}

	domainStruct := Domain{}
	err = cfg.Section("domain").MapTo(&domainStruct)
	if err != nil{
		panic(err)
	}
	domains := strings.Split(domainStruct.Name,",")
	for _,domain := range domains{
		rr := RR{}
		err = cfg.Section(domain).MapTo(&rr)
		if err != nil{
			log.Fatal(err)
		}else{
			rrList  := strings.Split(rr.R,",")
			DomainList[domain] = rrList
		}
	}
}

func main()  {
	DomainList = make(map[string]Lists,0)

	ticker := time.NewTicker(time.Second * 10)
	//ticker.Stop()
	for t := range ticker.C {
		go func() {
			fmt.Println(t)
			Run()
			fmt.Println("")
		}()
	}
	//AddDomainRecord("aa","zusux.com","175.8.31.166")
	//DescribeDomainRecord("zusux.com")
	//DeleteSubDomainRecords("www","zusux.com")
}

func Run(){
	//获取配置
	LoadIni()
	//获取ip
	ip := GetCurrentIp()
	ip = strings.Trim(ip,"\n")
	fmt.Println("获取ip:",ip)
	if ip != ""{
		for domain,subList := range DomainList{
			fmt.Println("处理域名:",domain)
			//获取域名记录
			dr,err := DescribeDomainRecord(domain)
			if err != nil{
				fmt.Println("获取记录错误:",err)
				continue
			}
			for _,rr  := range subList{
				if rr != ""{
					//查找
					flag := false
					for _,rv := range dr.Record{
						if rv.RR == rr && domain == rv.DomainName{
							if strings.EqualFold(rv.Value,ip){
								flag = true
								//相等 不操作
							}else{
								fmt.Println("删除RR:",rv.RR," 记录ip:",rv.Value)
								//不相等 删除
								DeleteDomainRecord(rv.RecordId)
							}
						}
					}
					if !flag{
						//添加
						fmt.Println("添加:",rr," ",domain," ",ip)
						AddDomainRecord(rr,domain,ip)
					}
				}
			}
		}
	}
}

//添加解析记录
func AddDomainRecord(RR,DomainName,Ip string)  {
	mapData := make(map[string]string)
	mapData["Format"] = "JSON"
	mapData["Version"] = "2015-01-09"
	mapData["AccessKeyId"] = AccessKeyId
	mapData["SignatureMethod"] = "HMAC-SHA1"
	mapData["Timestamp"] = url.QueryEscape(time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	mapData["SignatureVersion"] = "1.0"
	mapData["SignatureNonce"] = RandString(64)

	mapData["Action"] = "AddDomainRecord"
	mapData["DomainName"] = DomainName
	mapData["RR"] = RR
	mapData["Type"] = "A"
	mapData["Value"] = url.QueryEscape(Ip)
	res := SortMapByKey(mapData)
	query := GetQueryString(res)
	url := BaseUrl + query
	body,err := HttpGet(url)
	if err != nil{
		fmt.Println(err)
	}else{
		fmt.Println("添加:",body)
	}
}

//更新解析记录
func UpdateDomainRecord(RR,RecordId,Ip string)  {
	mapData := make(map[string]string)
	mapData["Format"] = "JSON"
	mapData["Version"] = "2015-01-09"
	mapData["AccessKeyId"] = AccessKeyId
	mapData["SignatureMethod"] = "HMAC-SHA1"
	mapData["Timestamp"] = url.QueryEscape(time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	mapData["SignatureVersion"] = "1.0"
	mapData["SignatureNonce"] = RandString(64)

	mapData["Action"] = "UpdateDomainRecord"
	mapData["RecordId"] = RecordId
	mapData["RR"] = RR
	mapData["Type"] = "A"
	mapData["Value"] = url.QueryEscape(Ip)
	res := SortMapByKey(mapData)
	query := GetQueryString(res)
	url := BaseUrl + query
	body,err := HttpGet(url)
	if err != nil{
		fmt.Println(err)
	}else{
		fmt.Println("更新:",body)
	}
}

type Record struct{
	RR string
	DomainName string
	Value string
	RecordId string
}
type  DomainRecords struct{
	Record []Record
}
type DomainRecordsRes struct{
	TotalCount int
	PageSize int
	PageNumber int
	DomainRecords DomainRecords
}

//列出解析记录
func DescribeDomainRecord(DomainName string) (dr DomainRecords,err error) {
	SignatureNonce := RandString(64)
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	//DomainName = "example.com"
	//SignatureNonce := "f59ed6a9-83fc-473b-9cc6-99c95df3856e"
	//timestamp := "2016-03-24T16:41:54Z"
	mapData := make(map[string]string)
	mapData["Format"] = "JSON"
	//mapData["Format"] = "XML"
	mapData["Version"] = "2015-01-09"
	mapData["AccessKeyId"] = AccessKeyId
	mapData["SignatureMethod"] = "HMAC-SHA1"
	mapData["Timestamp"] = url.QueryEscape(timestamp)
	mapData["SignatureVersion"] = "1.0"
	mapData["SignatureNonce"] = SignatureNonce
	mapData["Action"] = "DescribeDomainRecords"
	mapData["DomainName"] = DomainName
	res := SortMapByKey(mapData)
	query := GetQueryString(res)
	url := BaseUrl + query
	body,err := HttpGet(url)
	if err != nil{
		fmt.Println(err)
	}else{
		resRecord := DomainRecordsRes{}
		json.Unmarshal([]byte(body),&resRecord)
		dr = resRecord.DomainRecords
	}
	return
}

//删除子域名解析记录
func DeleteSubDomainRecords(RR,DomainName string){
	mapData := make(map[string]string)
	mapData["Format"] = "JSON"
	mapData["Version"] = "2015-01-09"
	mapData["AccessKeyId"] = AccessKeyId
	mapData["SignatureMethod"] = "HMAC-SHA1"
	mapData["Timestamp"] = url.QueryEscape(time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	mapData["SignatureVersion"] = "1.0"
	mapData["SignatureNonce"] = RandString(64)

	mapData["Action"] = "DeleteSubDomainRecords"
	mapData["DomainName"] = DomainName
	mapData["RR"] = RR
	res := SortMapByKey(mapData)
	query := GetQueryString(res)
	url := BaseUrl + query
	body,err := HttpGet(url)
	if err != nil{
		fmt.Println(err)
	}else{
		fmt.Println("删除:",body)
	}
}

//删除解析记录
func DeleteDomainRecord(RecordId string){
	mapData := make(map[string]string)
	mapData["Format"] = "JSON"
	mapData["Version"] = "2015-01-09"
	mapData["AccessKeyId"] = AccessKeyId
	mapData["SignatureMethod"] = "HMAC-SHA1"
	mapData["Timestamp"] = url.QueryEscape(time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	mapData["SignatureVersion"] = "1.0"
	mapData["SignatureNonce"] = RandString(64)

	mapData["Action"] = "DeleteDomainRecord"
	mapData["RecordId"] = RecordId
	res := SortMapByKey(mapData)
	query := GetQueryString(res)
	url := BaseUrl + query
	body,err := HttpGet(url)
	if err != nil{
		fmt.Println(err)
	}else{
		fmt.Println("删除:",body)
	}
}


//获取querystring
func GetQueryString(res PairList) string{
	mystrArr := make([]string,0)
	for _,v := range res{
		mystrArr = append(mystrArr,v.Key+"="+v.Value)
	}
	mystr := strings.Join(mystrArr,"&")
	signStr := url.QueryEscape(mystr)
	signStr = "GET&%2F&"+signStr

	signature:= GetSignature(signStr,AccessKeySecret+"&")
	query := mystr+"&Signature="+signature
	return query
}

//获取随机数
func RandString(n int, allowedChars ...[]rune) string {
	t := fmt.Sprint(time.Now().Unix())
	defaultLetters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	var letters []rune
	if len(allowedChars) == 0 {
		letters = defaultLetters
	} else {
		letters = allowedChars[0]
	}
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	res := string(b)
	res = strings.Replace(res,res[0:10],t,1)
	return res
}


//获取签名
func GetSignature(str,key string) string {
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write([]byte(str))
	uEnc := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	uEnc = url.QueryEscape(uEnc)
	return uEnc
}

//请求网络
func HttpGet(url string) (string,error){
	resp,err := http.Get(url)
	if err != nil{
		return "",err
	}
	defer resp.Body.Close()
	body,err := ioutil.ReadAll(resp.Body)
	if err != nil{
		return "",err
	}
	if resp.StatusCode  == 200 {
		return string(body),nil
	}else{
		return "",errors.New("请求异常:"+string(body))
	}
}

//获取当前ip
func GetCurrentIp() string {

	ip,err := HttpGet(ipServer.Url)
	if err != nil{
		fmt.Println(err)
		return ""
	}
	return ip
}