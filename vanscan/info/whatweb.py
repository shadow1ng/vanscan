#! /usr/bin/env python
#coding=utf-8
#whatweb cms指纹识别api示例
#http://whatweb.bugscaner.com/
#进行json压缩传输,经测试,压缩后可节省将近5-10倍的宽带
import requests
import zlib
import json

def bugscanerapi(url):
    response = requests.get(url,verify=False)
    #上面的代码可以随意发挥,只要获取到response即可
    #下面的代码您无需改变，直接使用即可
    print("whatweb",url)
    whatweb_dict = {"url":response.url,"text":response.text,"headers":dict(response.headers)}
    whatweb_dict = json.dumps(whatweb_dict)
    whatweb_dict = whatweb_dict.encode()
    whatweb_dict = zlib.compress(whatweb_dict)
    data = {"info":whatweb_dict}
    request=requests.post("http://whatweb.bugscaner.com/api.go",files=data)
    result= request.json()
    return result
def bugscanerapi2(url):
    API="http://whatweb.bugscaner.com/what.go"
    data={"url":url,"location_capcha":"no"}
    req=requests.post(API,data=data)
    print(req.text)
    return(req.text)
def tidesecapi(url):
    API="http://finger.tidesec.net/home/index/index"
    data={"target":url}
    
    
def yunsee( url):
        #API = 'http://api.yunsee.cn/[自行修改此处]'
        #payload = {'level': '2', 'url': url}
        API=  'http://www.yunsee.cn/home/getInfo'
        data={"type":"webinfo","url":url}
        try:
            req = requests.post(API, data=data, timeout=30,verify=False)
            code = json.loads(req.text)['code']
            if code == 1:
                info = json.loads(req.text)['res']
                print("云溪识别==",info)
                return info
            if code ==0 :
                mess=json.loads(req.text)['mess']
                print("云溪识别==",mess)
                return mess
        except Exception as e:
            print(e)
            return None


def run(url):
    # print("whatweb run!!",url)
    # print(request.text)
    request = whatweb(url)
    result= request.json()
    return result

#bugscanerapi2("https://aliyun.bugscaner.com")

# if __name__ == '__main__':
#     request = whatweb("https://aliyun.bugscaner.com")
#     #request = whatweb("http://testphp.vulnweb.com")
#     print(u"今日识别剩余次数")
#     print(request.headers["X-RateLimit-Remaining"])
#     print(u"识别结果")
#     print(request.json())