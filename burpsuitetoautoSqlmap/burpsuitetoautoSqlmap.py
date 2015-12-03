#!/usr/bin/env python
#coding=utf8
''''' 
Created on 2015-11-22
@author: Mr.x
Email: coolxia@foxmail.com
burpsuite结合autoSqlmap用，自动检测burpsuite proxy中的url
需要jython2.7b4支持
'''
from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IRequestInfo

import re
import urllib2
import urllib
# Class BurpExtender (Required) contaning all functions used to interact with Burp Suite API

print 'Mr.x'

#autoSqlmap proxy setting
#autoSqlmap_proxy = {'http' : 'http://127.0.0.1:8888/'}
autoSqlmap_proxy = {'http' : 'http://127.0.0.1:8888/'}
#your test host list
sniffer_host = ['192.168.31.254','m.haijincang.com']
#filte file list 
filter_file = ['.css', '.js', '.jpg', '.jpeg', '.gif', '.png', '.bmp', '.html', '.htm', '.swf', '.svg']

class BurpExtender(IBurpExtender, IHttpListener):

	# define registerExtenderCallbacks: From IBurpExtender Interface 
	def registerExtenderCallbacks(self, callbacks):
	
		# keep a reference to our callbacks object (Burp Extensibility Feature)
		self._callbacks = callbacks
		# obtain an extension helpers object (Burp Extensibility Feature)
		# http://portswigger.net/burp/extender/api/burp/IExtensionHelpers.html
		self._helpers = callbacks.getHelpers()
		# set our extension name that will display in Extender Tab
		self._callbacks.setExtensionName("proxy autoSqlmap")
		# register ourselves as an HTTP listener
		callbacks.registerHttpListener(self)
		
	# define processHttpMessage: From IHttpListener Interface 
	def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
		
		# determine what tool we would like to pass though our extension:
		#print toolFlag
		#if toolFlag == 64: #if tool is repeater
		if toolFlag == 4 or toolFlag == 8: #if tool 4 is Proxy Tab 8 is Spider
			# determine if request or response:
			if messageIsRequest:#only handle responses
				request = messageInfo.getRequest()
				#get Response from IHttpRequestResponse instance
				analyzedResponse = self._helpers.analyzeRequest(request) # returns IResponseInfo
				#print analyzedResponse
				headers = analyzedResponse.getHeaders()
				trg_url = messageInfo.getUrl()
				trg_url = str(trg_url)
				method = analyzedResponse.getMethod()
				
				body = request[analyzedResponse.getBodyOffset():]
				body_string = body.tostring()
				
				############# Get Request Head ################
				
				headers_arr = {'User-Agent':'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.6) Gecko/20091201 Firefox/3.5.6'}
				
				for columns in headers:
					#print columns # 优化获取headers算法
					if columns.find(": ") > 0:
						key_value = columns.split(': ')
						key = key_value[0]
						value = key_value[1]
						if key == "Host":
							trg_host = value
						else:
							headers_arr[key] = value
						
				#print headers_arr
				
				############# Request filters ################
				
				#if Request host not in sniffer_host the process 
				if trg_host not in sniffer_host : return
				
				c_trg_url = trg_url.split('?')
				for f in filter_file:
					if c_trg_url[0].endswith(f) == True : 
						return
				
				############# Request to proxy ################
				
				try:
					proxy = urllib2.ProxyHandler(autoSqlmap_proxy)
					opener = urllib2.build_opener(proxy)
					urllib2.install_opener(opener)
					
					#http请求拼接
					if method == 'GET':
						req = urllib2.Request(url=trg_url,headers=headers_arr)
					elif method == 'POST':
						req = urllib2.Request(url=trg_url, data=str(body_string), headers=headers_arr)
					response = urllib2.urlopen(req)
					
					print '%s %s' %(method,trg_url)
				except Exception,e:
					print "[!] ERR:%s"%e
				
				
				
				
				
				
				
				
				
				
				
				
				
				
				
				
				
