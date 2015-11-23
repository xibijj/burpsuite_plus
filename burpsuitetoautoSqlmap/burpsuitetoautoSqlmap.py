#!/usr/bin/env python
#coding=utf8
''''' 
Created on 2015-11-22
@author: Mr.x
Email: coolxia [AT] foxmail.com
burpsuite结合autoSqlmap用，自动检测burpsuite proxy中的url是否存在Sqli注入漏洞
需要jython2.7b4支持
'''
from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IRequestInfo

#import re
import urllib2
#import requests
# Class BurpExtender (Required) contaning all functions used to interact with Burp Suite API

print 'Mr.x'

#autoSqlmap proxy setting
autoSqlmap_proxy = {'http' : 'http://1.1.1.1:8888/'}
#your test host list
sniffer_host = ['1.1.1.1','test.cn']
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
		#if toolFlag == 64: #if tool 64 is repeater
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
					#print columns
					if columns.find("Referer") == 0:
						referer = columns.replace('Referer: ','')
						headers_arr['Referer'] = referer
					elif columns.find("Cookie") == 0:
						cookie = columns.replace('Cookie: ','')
						headers_arr['Cookie'] = cookie
					elif columns.find("Content-Type") == 0:
						content_type = columns.replace('Content-Type: ','')
						headers_arr['Content-Type'] = content_type
					elif columns.find("Host") == 0:
						host = columns.replace('Host: ','')
						
				#print headers_arr
				#print trg_url
				
				############# Request filters ################
				
				#if Request host not in sniffer_host the process 
				if host not in sniffer_host : return
				
				for f in filter_file:
					if trg_url.endswith(f) == True : 
						return
				
				############# Request to proxy ################
				
				#print "go proxy"
				
				proxy = urllib2.ProxyHandler(autoSqlmap_proxy)
				opener = urllib2.build_opener(proxy)
				urllib2.install_opener(opener)
				if method == 'GET':
					req = urllib2.Request(url=trg_url,headers=headers_arr)
				elif method == 'POST':
					req = urllib2.Request(url=trg_url, data=str(body_string), headers=headers_arr)
				response = urllib2.urlopen(req)
				
				#print response.read()
				print '%s %s' %(method,trg_url)
				
				
