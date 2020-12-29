from django.shortcuts import render
from django.http import HttpResponse,JsonResponse
from scan.scan import *
from django.views.generic import View
from info import whatweb
import scan.awvs13 as awvs13
import requests, json



def index(request):
    return render(request,'index.html')

def Scan(request):
    data='{"date":"2020-03-10","host":"127.0.0.1","fenlei":"漏洞扫描"}'
    return HttpResponse(data)


class Whatweb(View):
    def post(self, request):
        return HttpResponse('whatweb')
    def get(self, request):
        domain = "http://test.vulnweb.com"
        info = whatweb.bugscanerapi(domain)
        info2= whatweb.bugscanerapi2(domain)
        #yun = whatweb.yunsee(domain)
        print((info,info2))
        msg = '查询失败，请检查域名是否有效，如果是第一次查询请等两分钟后再查下试试'
        return HttpResponse((info,'\n6666666\n',info2))
        #return render(request, 'whatweb.html', context={'form': self.form,'msg':domain ,'info': info,'info2': info2,"yun":yun})

class Awvs13(View):
    def get(self, request):
        return render(request,'awvs13.html')
    def info(self):
        scan_list = awvs13.getscans()
        groups=awvs13.getgroups()
        return JsonResponse({"scan_list":scan_list,"groups":groups},safe=False)
   