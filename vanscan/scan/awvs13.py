# ! usr/bin/env python
#  -*- coding: utf-8 -*-
import requests, json
import requests.packages.urllib3.exceptions
import time
from django.shortcuts import render,redirect
from django.http import HttpResponse,JsonResponse
from django.views.decorators.csrf import csrf_exempt
requests.packages.urllib3.disable_warnings()
Auth = "xxxxxxxxxxxxxxxxxxx"
API = 'https://xxxx:xxx/api/v1'



headers = {
    'X-Auth': Auth,
    'content-type': 'application/json'  
}
cookie={
    "ui_session":Auth

}
proxies={
    'http':'http://127.0.0.1:8080',
    'https':'https://127.0.0.1:8080'
}

proxies = None

#查看扫描目标列表
def getscans():
    #print('getscans')
    try:
        req = requests.get(API + '/scans', headers=headers,cookies=cookie, verify=False,timeout=10)#,proxies=proxies)
        scans = json.loads(req.text)
        #print(scans)
        scan_list = []
        for scan in scans['scans']:
            date=scan["current_session"]['start_date'][:10]
            vul_counts=scan["current_session"]["severity_counts"]
            scan_session_id=scan["current_session"]["scan_session_id"]
            scanid = scan['scan_id']
            address = scan['target']['address']
            description = scan['target']['description']
            status = scan['current_session']['status'].replace('aborted', '已取消').replace('processing', '进行中').replace('completed','已完成').replace('queued','就绪中').replace('aborting','取消中')
            scan_dict = {'scanid': scanid, 'address': address, 'description': description, 'status': status,'date':date,"name": "漏洞扫描","vul_counts":vul_counts,"scan_session_id":scan_session_id}
            scan_list.append(scan_dict)
        return scan_list
    except Exception as e:
        print(e)
        return None

#查看任务详情
@csrf_exempt
def get_vluns(request):
    if request.method == 'POST':
        res = json.loads(request.body)
        scan_id=res['scan_id']
        scan_session_id=res['scan_session_id']
        r = requests.get(API+"/scans/"+scan_id+"/results/"+scan_session_id+"/vulnerabilities",headers=headers,cookies=cookie,verify=False)
        req = json.loads(r.text)['vulnerabilities']
        return HttpResponse(json.dumps(req))

#批量添加目标
@csrf_exempt
def moreadd(request):
    if request.method == 'POST':
        targets=[]
        res=json.loads(request.body)
        target=res["target"].split('\n')
        groups=res["groups"]
        level=res["level"]
        if level=='high':
            level='11111111-1111-1111-1111-111111111112'
        else:
            level='11111111-1111-1111-1111-111111111111'
        for num in range(len(target)):
            targets.append({"address":target[num],"description":""})
        data={'targets':targets,'groups':groups}
        r = requests.post(url=API + '/targets/add', timeout=10,verify=False, headers=headers, cookies=cookie,data=json.dumps(data))#,proxies=proxies)
        if r.status_code == 200:
            req=json.loads(r.text)
            for target in req['targets']:
                target_id =  target['target_id']
                data='{"profile_id":"%s","ui_session_id":"66666666666666666666666666666666","incremental":false,"schedule":{"disable":false,"start_date":null,"time_sensitive":false},"target_id":"%s"}' %(level,target_id)
                try:
                    r = requests.post(url=API + '/scans', timeout=10,verify=False, cookies=cookie,headers=headers, data=data)#,proxies=proxies)
                    if r.status_code == 201:
                        pass
                    else:
                        return HttpResponse(0)
                except Exception as e:
                    print(e)  
            return HttpResponse('添加成功')  
        return HttpResponse("添加失败")

#查看漏洞详情
@csrf_exempt
def get_vulinfo(request):
    if request.method == 'POST':
        res = json.loads(request.body)
        vuln_id=res['vuln_id']
        scan_id=res["scanid"]
        session_id=res["session_id"]
        try:
            r = requests.get(API+'/scans/'+scan_id+'/results/'+session_id+'/vulnerabilities/'+vuln_id, headers=headers,cookies=cookie,verify=False)#,proxies=proxies)
            req = json.loads(r.text)
            print(req)
            return HttpResponse(json.dumps(req))
        except Exception as e:
            print(e)
            return HttpResponse(e)
        








def getgroups():    
    try:
        r = requests.get(API+'/target_groups?l=20', headers=headers,cookies=cookie,verify=False)#,proxies=proxies)
        req = json.loads(r.text)
        groups=[]
        for name in req['groups']:
            group={'name':name['name'],'id':name['group_id']}
            groups.append(group)
        return groups
    except Exception as e:
        print(e)
        return None

@csrf_exempt
def del_scan(request):
    if request.method == 'POST':
        scan_id =json.loads(request.body)['scan_id']
        req = requests.delete(API + '/scans/' + scan_id,cookies=cookie, headers=headers, verify=False)
        if req.status_code == 204:
            return HttpResponse("删除成功")
        else:
            return HttpResponse("删除失败")

@csrf_exempt
def stop_scan(request):
    if request.method == 'POST':
        scan_id =json.loads(request.body)['scan_id']
        req = requests.post(API + '/scans/' + scan_id + '/abort' ,headers=headers,cookies=cookie,verify=False)#,proxies=proxies)
        if req.status_code == 204:
            return HttpResponse("停止成功")
        else:
            return HttpResponse("停止失败")

@csrf_exempt
def Presentation(request):
    if request.method == 'POST':
        scan_id =json.loads(request.body)['scan_id']
        print("开始导出")
        if bg(scan_id):
            print("导出成功")
            return HttpResponse('导出成功')
        else:
            print("导出失败")
            return HttpResponse('导出失败')
#生成
def bg(scanid):
    #生成报告
    try:
        data = {'template_id': '11111111-1111-1111-1111-111111111115','source': {'list_type': 'scans', 'id_list': [scanid]}}
        r = requests.post(url=API + '/reports', timeout=10,verify=False, headers=headers,cookies=cookie, data=json.dumps(data))
        if r.status_code == 201:
            download(r.headers['Location'])
            return True
        else:
            return False
    except Exception as e:
        print(e)

def download(path):
    # 下载报告
    try:
        r = requests.get(url=API.replace('/api/v1', '') + path,
                         timeout=10, verify=False, headers=headers,cookies=cookie)
        response = json.loads(r.text)
        report_id = response['report_id']
        target = response['source']['description']
        print('[-] 报告生成中...')
        # 等待报告生成
        while True:
            time.sleep(5)
            _r = requests.get(API+'/reports/' + report_id,headers=headers,cookies=cookie,
                             verify=False)
            name = json.loads(_r.text)['source']['description'].replace(';','')
            if json.loads(_r.text)['status'] == 'completed':
                downurl=(json.loads(_r.text)['download'][1])   #0=html ,1=pdf
                print("报告下载链接:",API.replace('/api/v1', '')+downurl)
                res = requests.get(API.replace('/api/v1', '')+downurl, verify=False, timeout=10, headers=headers,cookies=cookie)
                if res.status_code == 200:
                    print('[-] OK, 报告下载成功.')
                    name = name.replace(':','_').replace('/','_')
                    with open('报告'+'/'+name+time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime()) + '.pdf', 'wb') as f:
                        f.write(res.content)
                    break
    except Exception as e:
        print(e)