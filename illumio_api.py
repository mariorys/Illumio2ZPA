#!/usr/bin/python3
#(c) Mario.Rys@mondigroup.com 2022/2023

from __future__ import print_function

import sys

from dataclasses import replace
from hashlib import blake2b
import socket
import sys


import json
import requests
import time

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import sqlite3
import re

import ipaddress
import os


#def eprint(*args, **kwargs):
#    print(*args, file=sys.stderr, **kwargs)

class IllumioApi:
    CACHE={}
    
    def __init__(self,config,DEBUGSQL=False):
        self.DEBUGSQL=DEBUGSQL
        if self.DEBUGSQL == True:
            #keep a copy of the old DB, make sure all old data is gone
            if os.path.exists("illumio-prev.db"):
                os.remove("illumio-prev.db")
            if os.path.exists("illumio.db"):
                os.rename("illumio.db","illumio-prev.db")
            self.inMemSQLconn=sqlite3.connect('illumio.db')
        else:
            self.inMemSQLconn=sqlite3.connect(':memory:')


        self.CONFIG=config
        self.RuleTableCreate()
        self.WorkloadTableCreate()
        self.IplTableCreate()
        self.DNSTableCreate()
        self.TableClean()

        self.WorkloadTableFill()
        self.IplTableFill()
    
    def TableClean(self):
        cursor=self.inMemSQLconn.cursor()
        table="delete from  workloads"
        cursor.execute(table)
        table="delete from ipl"
        cursor.execute(table)
        table="delete from  rules"
        cursor.execute(table)
        table="delete from  dns"
        cursor.execute(table)

    def DNSTableCreate(self):
        cursor=self.inMemSQLconn.cursor()
        table="""
            CREATE TABLE IF NOT EXISTS dns (
                    name text,
                    ip text,
                    site text
                    )
        """
        cursor.execute(table)
        
    def RuleTableCreate(self):
        cursor=self.inMemSQLconn.cursor()
        table="""
            CREATE TABLE IF NOT EXISTS rules (
                    name text,
                    provider_ip text,
                    consumer_name text,
                    port int,
                    to_port int,
                    proto int,
                    adminRule bool
                    )
        """
        cursor.execute(table)

    def WorkloadTableCreate(self):
        cursor=self.inMemSQLconn.cursor()
        table="""
            CREATE TABLE IF NOT EXISTS workloads (
                    href text,
                    public_ip text,
                    hostname text,
                    name text,
                    ip text,
                    role text,
                    app text,
                    env text,
                    loc text)
        """
        cursor.execute(table)

    def get_ip_type(self,address):
        try:
            ip = ipaddress.ip_address(address)

            if isinstance(ip, ipaddress.IPv4Address):
                #print("{} is an IPv4 address".format(address))
                return 4
            elif isinstance(ip, ipaddress.IPv6Address):
                #print("{} is an IPv6 address".format(address))
                return 6
        except ValueError:
            #print("{} is an invalid IP address".format(address))
            return 0        


    def WorkloadTableFill(self):
        workloads=self.get_Workloads()
        app=""
        role=""
        env=""
        loc=""
        cursor=self.inMemSQLconn.cursor()
        for wl in workloads:
            if wl['deleted'] == True:
                next
            for label in wl['labels']:
                labelData=(self.get_LabelsByHref(label['href']))
                if labelData['key'] == 'app':
                    app=labelData['value']
                if labelData['key'] == 'role':
                    role=labelData['value']
                if labelData['key'] == 'loc':
                    loc=labelData['value']
                if labelData['key'] == 'env':
                    env=labelData['value']
            for interface in wl['interfaces']:
                ip=interface['address']

                sql="insert into workloads (href, public_ip, ip, hostname, name, app, role, env, loc) VALUES (?,?,?,?,?,?,?,?,?)"

                skipIP=False
                for invalidIpRange in self.CONFIG['invalidIpRanges']:
                    if self.get_ip_type(ip)  != 4:
                        skipIP=True
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(invalidIpRange):
                        skipIP=True
                if skipIP==False:
                    cursor.execute(sql,[wl['href'],wl['public_ip'],ip,wl['hostname'],wl['name'],app,role,env,loc])

    def WorkloadTableQuery(self,scope):
        cursor=self.inMemSQLconn.cursor()
        sql="select * from workloads where  "

        r=[]
        e=[]
        l=[]
        a=[]

        for item in scope:
            if item == None:
                return []
            if item.startswith('R-'):
                r.append(item)
            elif item.startswith('E-'):
                e.append(item)
            elif item.startswith('L-'):
                l.append(item)
            elif '{' in item:
                pass
            else:
                a.append(item)
        
        sql=sql+self.sqlHack('role',r)
        sql=sql+self.sqlHack('env' ,e)
        sql=sql+self.sqlHack('loc' ,l)
        sql=sql+self.sqlHack('app' ,a)
        sql=sql[:-4]

        rows=cursor.execute(sql)
        return rows

    def sqlHack(self,name,arr):
        sql=""
        if len(arr) > 0:
            sql=sql+f''' ( '''
            if len(arr) > 1:
                for item in arr:
                    sql=sql+f''' {name} =  '{item}' or '''
                sql=sql[:-4]
            else:
                sql=sql+f''' {name} =  '{arr[0]}' '''
            sql=sql+f''' ) and '''
        return sql

    def IplTableCreate(self):
        cursor=self.inMemSQLconn.cursor()
        table="""
            CREATE TABLE IF NOT EXISTS ipl (
                name text,
                ip text
                )
            """
        cursor.execute(table)

    def DNSTableFill(self,ARecords,NoneBut=False):
        sql="insert into dns (name, ip ) VALUES (?,?)"
        cursor=self.inMemSQLconn.cursor()
        for record in ARecords:
            cursor.execute(sql,record)
        cursor.execute('commit')
        self.DNSTableFillUp(NoneBut)

    def LookupIPL(self,ip):
        cursor=self.inMemSQLconn.cursor()
        sqlIPL="select ip,name from IPL"
        IPLs=cursor.execute(sqlIPL)
        prevMask=0
        site=None
        for IPL in IPLs:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(IPL[0]):
                n = ipaddress.ip_network(IPL[0])
                mask=int(n.netmask)
                if mask >prevMask:
                    site=IPL[1]
        return site

    def regexp(self,expr, item):
        reg = re.compile(expr)
        return reg.search(item) is not None            

    def DNSTableFillUp(self,NoneBut=False):
        cursor=self.inMemSQLconn.cursor()
        sqlDNSUpdate='update DNS set site=? where IP= ?'
        sqlDNS="select name,ip from DNS order by ip"

        cursor.execute(sqlDNS)
        rows=cursor.fetchall()

        for cleanUpNameRegex in self.CONFIG['IPLCleanUpNameRegex']:
            regex=re.compile(cleanUpNameRegex)

            for row in rows:
                if regex.match(row[0]):
                    sqlCleanUp="delete from DNS where name = ?"
                    cursor.execute(sqlCleanUp,[row[0]])
        #cursor.execute('commit')
        #exit()
        
        if NoneBut != False:
            sqlDNS="delete from ipl where name not like ?"
            cursor.execute(sqlDNS,NoneBut)


        if self.dnsIPL==True:
            prefix='Looking up IP in IPL'
            l=len(rows)
            i=0
            self.printProgressBar(i,l, prefix=prefix, suffix='Complete', length=50)
            for row in rows:
                i+=1
                self.printProgressBar(i,l, prefix=prefix, suffix='Complete', length=50)
                site=self.LookupIPL(row[1])
                cursor.execute(sqlDNSUpdate,[site,row[1]])
            
        
        #ipls
        sqlIPL=f'''insert into ipl (name,ip) VALUES (?,?)'''
        #workloads
        sqlWLInsert="insert into workloads select href, public_ip, hostname, name, ? , role, app, env, loc from workloads where ip = ?"
        #the dns entries with sites
        sqlDNS="select site,ip,name from DNS order by ip"
        cursor.execute(sqlDNS)
        rows=cursor.fetchall()
        
        #trace SQL
        #if self.DEBUGSQL == True:
        #    self.inMemSQLconn.set_trace_callback(print)
        #trace SQL
        
        l=len(rows)
        prefix='Updating FQDN in '
        if self.dnsIPL==True:
            prefix=prefix+'IPLs '
        if self.dnsWL==True:
            prefix=prefix+'workloads '
        i=0
        self.printProgressBar(i,l, prefix=prefix, suffix='Complete', length=50)
        for row in rows:
            i+=1
            self.printProgressBar(i,l, prefix=prefix, suffix='Complete', length=50)
            if self.dnsIPL==True and row[0] != None and row[0] != 'None':
                cursor.execute(sqlIPL,[row[0],row[2]])
            if self.dnsWL==True:
                cursor.execute(sqlWLInsert,[row[2].lower(),row[1]])
        if self.DEBUGSQL == True and i>0:
            cursor.execute('commit')

        for cleanUpSite in self.CONFIG['IPLCleanUpSite']:
            sqlCleanUp="delete from ipl where lower(name) like lower(?)"
            cursor.execute(sqlCleanUp,[cleanUpSite])
        for cleanUpName in self.CONFIG['IPLCleanUpName']:
            sqlCleanUp="delete from ipl where lower(ip) like lower(?)"
            cursor.execute(sqlCleanUp,[cleanUpName])


            
        cursor.execute('commit')

    def IplTableFill(self):
        cursor=self.inMemSQLconn.cursor()
        ipls=self.getPolicyObjectIPList()
        sqlIPL=f'''insert into ipl (name,ip) VALUES (?,?)'''
        for ipl in ipls:
            if ipls[ipl]!=True:
                for ips in ipls[ipl]['ip_ranges']:
                    if ips['exclusion']==False:
                        cursor.execute(sqlIPL,[ipls[ipl]['name'],ips['from_ip']])
        
    def IplTableQuery(self,scope):
        cursor=self.inMemSQLconn.cursor()
        sql="select * from ipl where "
        for item in scope:
            sql=sql+f''' name = '{item}' or '''        
        sql=sql[:-4]
        rows=cursor.execute(sql)
        return rows

    def IplTableDump(self):
        cursor=self.inMemSQLconn.cursor()
        sql="select * from ipl order by name"
        rows=cursor.execute(sql)
        return rows
    
    def http_request_auth_async(self,URL, PARAMS={}):
        URL=self.CONFIG['api_protocol']+"://"+self.CONFIG['api_node']+":"+str(self.CONFIG['api_port'])+"/api/v2/"+URL

        HEADERS = {'Content-Type': 'application/json', 'Accept': 'application/json', 'Prefer': 'respond-async'}
        # sending get request and saving the response as response object
        r = requests.get(url = URL, headers=HEADERS, params = PARAMS,verify=False, auth=(self.CONFIG['api_user'], self.CONFIG['api_key']))
        
        return {'headers':r.headers, 'content':r.content }

    def http_request_auth(self,URL, PARAMS={}):
        URL=self.CONFIG['api_protocol']+"://"+self.CONFIG['api_node']+":"+str(self.CONFIG['api_port'])+"/api/v2/"+URL

        HEADERS = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        # sending get request and saving the response as response object
        r = requests.get(url = URL, headers=HEADERS, params = PARAMS,verify=False, auth=(self.CONFIG['api_user'], self.CONFIG['api_key']))
        try:
            content=json.loads(r.content)
        except:
            #print("empty response")
            content={}
        return content

    def http_request_auth_post(self,URL, DATA={}, PARAMS={}):
        URL=self.CONFIG['api_protocol']+"://"+self.CONFIG['api_node']+":"+str(self.CONFIG['api_port'])+"/api/v2/"+URL

        HEADERS = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        # sending get request and saving the response as response object
        r = requests.post(url = URL, headers=HEADERS, data = json.dumps(DATA), params = PARAMS,verify=False, auth=(self.CONFIG['api_user'], self.CONFIG['api_key']))
        try:
            content=json.loads(r.content)
        except:
            content={r.content}
        return content

    def http_request_put_auth(self,URL, DATA={}, PARAMS={}):
        URL=self.CONFIG['api_protocol']+"://"+self.CONFIG['api_node']+":"+str(self.CONFIG['api_port'])+"/api/v2/"+URL

        HEADERS = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        # sending get request and saving the response as response object
        r = requests.put(url = URL, headers=HEADERS, data = json.dumps(DATA), params = PARAMS,verify=False, auth=(self.CONFIG['api_user'], self.CONFIG['api_key']))
        try:
            content=json.loads(r.content)
        except:
            content={}
        return content

    def http_request_delete_auth(self,URL, PARAMS={}):
        URL=self.CONFIG['api_protocol']+"://"+self.CONFIG['api_node']+":"+str(self.CONFIG['api_port'])+"/api/v2/"+URL

        HEADERS = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        # sending get request and saving the response as response object
        r = requests.delete(url = URL, headers=HEADERS, data={}, params = PARAMS,verify=False, auth=(CONFIG['api_user'], self.CONFIG['api_key']))
        try:
            content=json.loads(r.content)
        except:
            content={}
        return content

    #################
    # request URLs  #
    #################
    def get_IpList(self):
        url="/orgs/"+str(self.CONFIG['api_orgid'])+"/sec_policy/draft/ip_lists"
        IpList=self.http_request_auth(url)
        #data_logger.debug("get_IpList")
        ret = sorted(IpList, key=lambda k: k['name'])
        return ret
    def create_IpList(self,dict):
        url="/orgs/"+str(self.CONFIG['api_orgid'])+"/sec_policy/draft/ip_lists"
        #data_logger.info("create_IpList: "+str(dict))
        return (self.http_request_auth_post(url,dict))
    def create_Workload(self,dict):
        url="/orgs/"+str(self.CONFIG['api_orgid'])+"/workloads"
        #data_logger.info("create_Workload: "+str(dict))
        return (self.http_request_auth_post(url,dict))
    def create_Label(self,key,value):
        url="/orgs/"+str(self.CONFIG['api_orgid'])+"/labels/"
        dict={ "key":key,"value":value}
        #data_logger.info("create_Label: "+str(key)+":"+str(value))
        return (self.http_request_auth_post(url,dict))
    def update_Workload(self,hrefWorkload,dict):
        #url="/orgs/"+str(self.CONFIG['api_orgid'])+"/workloads"
        #data_logger.info("update_Workload: "+hrefWorkload+'==>'+str(dict))
        return (self.http_request_put_auth(hrefWorkload,dict))
    def delete_Workload(self,hrefWorkload):
        #url="/orgs/"+str(self.CONFIG['api_orgid'])+"/workloads"
        #data_logger.info("update_Workload: "+hrefWorkload+'==>'+str(dict))
        return (self.http_request_delete_auth(hrefWorkload))
    def create_Service(self,dataDict):
        url="/orgs/"+str(self.CONFIG['api_orgid'])+"/sec_policy/draft/services"
        #data_logger.info("create_Service: "+dataDict['name'])
        return (self.http_request_auth_post(url,dataDict))
    ##async job handler
    def job_handler(self,url):
        job_data=self.http_request_auth_async(url)
        try:
            if job_data['headers']['Status'] == '202 Accepted':
                return self.job_read(job_data['headers']['Location'],int(job_data['headers']['Retry-After']))
        except:
            print (job_data)
    def job_read(self,location,retry):
        print ("Waiting for job to be finished")
        time.sleep(retry)
        job_status=self.http_request_auth(location)
        if job_status['status']!='done':
            return self.job_read(location,retry)
        else:
            return self.job_result_get(job_status['result']['href'])

    def job_result_get(self,location):
        return self.http_request_auth(location)


    ##GET

    def get_Users(self,id="",refresh=False):
        if 'users' in self.CACHE and refresh==False:
            return self.CACHE['users']
        else:
            url="/users/"+str(id)
            Users=self.http_request_auth(url)
            #data_logger.debug("get_IpList")
            ret=[]
            if 'id' in Users:
                Users=[Users,]
            ret = sorted(Users, key=lambda k: k['id'])
            self.CACHE['users']=ret
            return ret

    def get_Labels(self,refresh=False):
        if 'labels' in self.CACHE and refresh==False:
            return self.CACHE['labels']
        else:
            url="/orgs/"+str(self.CONFIG['api_orgid'])+"/labels/"
            Labels=self.http_request_auth(url)
            #data_logger.debug("get_Labels")
            if 'key' in Labels:
                Labels=[Labels,]
            self.CACHE['labels'] = Labels
            return Labels

    def get_Workloads(self,refresh=False):
        if 'workloads' in self.CACHE and refresh==False:
            return self.CACHE['workloads']
        else:
            url="/orgs/"+str(self.CONFIG['api_orgid'])+"/workloads/"
            #workloads=self.http_request_auth(url)
            workloads=self.job_handler(url)
            #data_logger.debug("get_Workloads")
            if 'key' in workloads:
                workloads=[workloads,]
            self.CACHE['workloads'] = workloads
            return workloads

    def get_Agent(self,id,refresh=False):
        url="/orgs/"+str(self.CONFIG['api_orgid'])+"/agents/"+id
        agent=self.http_request_auth(url)
        #data_logger.debug("get_Agent "+id)
        return agent


    ###################
    # helpers         #
    ###################
    
    def validIP(self,ip):
        if ip==None:
            return False
        ip=ip.split('/')
        try:
            socket.inet_aton(ip[0])
            if len(ip) < 2:
                ip.append('32')
            if len(ip) > 2:
                return False
            if int(ip[1]) >=0 and int(ip[1]) <= 32:
                ip=('/').join(ip)
                return True
            else:
                return False
        except socket.error:
            # Not legal
            return False


    def getUserbyID(self,id):
        U= (self.get_Users())
        for u in U:
            if u['id'] == id:
                return u
        return {'username':'unknown', 'id':id}

    def getLabelbyKeyValue(self,key,value,refresh=False):
        U= (self.get_Labels(refresh))
        for u in U:
            if u['key'].lower() == key.lower() and u['value'].lower() == value.lower():
                return u
        #return {'key':'unknown', 'value':'unknown'}
        self.create_Label(key,value)
        return self.getLabelbyKeyValue(key,value,True)

    def get_LabelsByHref(self,href):
        Labels=self.get_Labels()
        for label in Labels:
            if label['href']==href:
                return label

    def getWorkloadByName(self,name,refresh=False):
        U= (self.get_Workloads(refresh))
        for u in U:
            ##Unmanaged are named via Name
            ##Managed are named via hostname
            if u['name']!=None:
                if u['name'].lower() == name.lower():
                    return u
            if u['hostname']!=None:
                if u['hostname'].lower() == name.lower():
                    return u
        return False

    def getWorkloadsByName(self,name,refresh=False):
        U= (self.get_Workloads(refresh))
        R=[]
        for u in U:
            ##Unmanaged are named via Name
            ##Managed are named via hostname
            if u['name']!=None:
                if u['name'].lower() == name.lower():
                    R.append(u)
            if u['hostname']!=None:
                if u['hostname'].lower() == name.lower():
                    R.append(u)
        return R

    def check_WorkloadExists(self,name):
        wn= self.getWorkloadByName(name)
        return wn

    def getIpListNice(self):
        list = self.get_IpList()
        for i in list:
            uID= (int(i['created_by']['href'].replace('/users/','')))
            i['created_by']=self.getUserbyID(uID)['username']

            uID= (int(i['updated_by']['href'].replace('/users/','')))
            i['updated_by']=self.getUserbyID(uID)['username']
        return list



    def getAgentsFromWorkloads(self,listDict):
        if 'agents' in self.CACHE:
            return self.CACHE['agents']
        else:
            self.CACHE['agents']=[]
            for dict in listDict:
                if '/agents/' in dict['created_by']['href']:
                    self.CACHE['agents'].append(dict['created_by']['href'].replace('/orgs/'+str(self.CONFIG['api_orgid'])+'/agents/',''))
                if '/agents/' in dict['updated_by']['href']:
                    self.CACHE['agents'].append(dict['updated_by']['href'].replace('/orgs/'+str(self.CONFIG['api_orgid'])+'/agents/',''))
            self.CACHE['agents']=list(dict.fromkeys(self.CACHE['agents']))
            return self.CACHE['agents']

    def getAgentsReplaceWorkloads(self,listDict):
        if 'agents' in self.CACHE:
            return self.CACHE['agents']
        else:
            self.CACHE['agents']=[]
            for dict in listDict:
                if '/agents/' in dict['created_by']['href']:
                    self.CACHE['agents'].append(dict['created_by']['href'].replace('/orgs/'+str(self.CONFIG['api_orgid'])+'/agents/',''))
                if '/agents/' in dict['updated_by']['href']:
                    self.CACHE['agents'].append(dict['updated_by']['href'].replace('/orgs/'+str(self.CONFIG['api_orgid'])+'/agents/',''))
            self.CACHE['agents']=list(dict.fromkeys(self.CACHE['agents']))
            return self.CACHE['agents']


    def labelHref2Name(self,labels):
        labelNew={'app':None,'role':None,'env':None,'loc':None}
        labelNewSorted=[]
        for label in (labels):
            labelTemp=(self.get_LabelsByHref(label['href']))
            labelNew[labelTemp['key']]=labelTemp['value']
        return labelNew

    def get_WorkloadsByID(self,id):
        #print ("WORKLOAD LOOKUP ")
        data=self.get_Workloads()
        for item in data:
            if id==item['href']:
                return item

    def replaceRuleItemsPC(self,item):
        if 'label' in item:
            return self.get_LabelsByHref(item['label']['href'])['value']
        elif 'actors' in item:
            return item['actors']
        elif 'ip_list' in item:
            return self.getPolicyObjectIPList(item['ip_list']['href'])['name']
        else:
            pass
            #print (item)

    def resolveScope(self,scopeList):
        itemList=[]
        self.WorkloadTableQuery(scopeList)

        return itemList

    def resolveScopeIP(self,scopeList):
        itemList=[]
        rows=self.WorkloadTableQuery(scopeList)
        for row in rows:
            itemList.append(row[4])
        rows=self.IplTableQuery(scopeList)
        for row in rows:
            itemList.append(row[1])
        return {'labels': scopeList, 'ip':itemList}


    def replaceRuleItemsSVC(self,svcList):        
        if 'href' in svcList:
            svc = self.getPolicyObjectServices(svcList['href'])
            if 'windows_services' in svc:
                newSVC={'name':svc['name'],'ports':svc['windows_services']}
            elif 'service_ports' in svc:
                newSVC={'name':svc['name'],'ports':svc['service_ports']}
        if 'port' in svcList:
            newSVC={'name':'Ports','ports':[svcList]}
        
        return newSVC

    def replaceRuleItems(self,rule):
        itemlist=list(self.CACHE['scope'])
        for item in rule['providers']:
            itemlist.append(self.replaceRuleItemsPC(item))
        for item in rule['providers']:
            if 'workload' in item:
                wl = self.get_WorkloadsByID(item['workload']['href'])
                if wl != None:
                    for interface in wl['interfaces']:
                        itemlist.append(interface['address'])

        rule['providers']=self.resolveScopeIP(itemlist)
        itemlist=[]
        for item in rule['consumers']:
            itemlist.append(self.replaceRuleItemsPC(item))
        for item in rule['consumers']:
            if 'workload' in item:
                wl = self.get_WorkloadsByID(item['workload']['href'])
                for interface in wl['interfaces']:
                    itemlist.append(interface['address'])

        rule['consumers']=self.resolveScopeIP(itemlist)
        itemlist=[]
        for item in rule['ingress_services']:
            itemlist.append(self.replaceRuleItemsSVC(item))
        rule['ingress_services']=itemlist
        itemlist=[]
            #return self.get_WorkloadsByID(item['workload']['href'])

        return rule

    def getPolicyObjectIPList(self,listId=""):
        if 'iplist' in self.CACHE:
            if listId=="":
                if 'all' in self.CACHE['iplist']:
                   return self.CACHE['iplist']
                else:
                    url="/orgs/"+str(self.CONFIG['api_orgid'])+"/sec_policy/draft/ip_lists"
                    iplist=self.job_handler(url)
                    for iplist in iplist:
                        listId=iplist['href']
                        self.CACHE['iplist'][listId]=iplist
                    self.CACHE['iplist']['all']=True
                    return self.CACHE['iplist']
            else:
                if listId in self.CACHE['iplist']:
                    return self.CACHE['iplist'][listId]
                else:
                    self.CACHE['iplist'][listId]=self.http_request_auth(listId)
                    return self.CACHE['iplist'][listId]
        else:
            self.CACHE['iplist']={}
            return self.getPolicyObjectIPList(listId)

    def getPolicyObjectServices(self,serviceId=""):
        if 'services' in self.CACHE:
            if serviceId=="":
                if 'all' in self.CACHE['services']:
                   return self.CACHE['services']
                else:
                    url="/orgs/"+str(self.CONFIG['api_orgid'])+"/sec_policy/draft/services"
                    services=self.job_handler(url)
                    for service in services:
                        serviceId=service['href']
                        self.CACHE['services'][serviceId]=service
                    self.CACHE['services']['all']=True
                    return self.CACHE['services']
            else:
                if serviceId in self.CACHE['services']:
                    return self.CACHE['services'][serviceId]
                else:
                    self.CACHE['services'][serviceId]=self.http_request_auth(serviceId)
                    return self.CACHE['services'][serviceId]
        else:
            self.CACHE['services']={}
            return self.getPolicyObjectServices(serviceId)


    def getRuleSet(self,rulesetId=""):
        if 'rulesets' in self.CACHE:
            if rulesetId=="":
                if 'all' in self.CACHE['rulesets']:
                   return self.CACHE['rulesets']
                else:
                    url="/orgs/"+str(self.CONFIG['api_orgid'])+"/sec_policy/draft/rule_sets"
                    rulesets=self.job_handler(url)
                    for ruleset in rulesets:
                        rulesetId=ruleset['href']
                        self.CACHE['rulesets'][rulesetId]=ruleset
                    self.CACHE['rulesets']['all']=True
                    return self.CACHE['rulesets']
            else:
                if rulesetId in self.CACHE['rulesets']:
                    #return self.CACHE['rulesets'][rulesetId]
                    return {rulesetId:self.CACHE['rulesets'][rulesetId]}
                else:
                    self.CACHE['rulesets'][rulesetId]=self.http_request_auth(rulesetId)
                    #return self.CACHE['rulesets'][rulesetId]
                    return {rulesetId:self.CACHE['rulesets'][rulesetId]}

        else:
            self.CACHE['rulesets']={}
            return self.getRuleSet(rulesetId)

    def getRule(self,ruleId=""):
        if 'rules' in self.CACHE:
            if ruleId=="":
                if 'all' in self.CACHE['rules']:
                   return self.CACHE['rules']
                else:
                    url="/orgs/"+str(self.CONFIG['api_orgid'])+"/sec_policy/draft/sec_rules"
                    rules=self.job_handler(url)
                    for rule in rules:
                        ruleId=rule['href']
                        self.CACHE['rules'][ruleId]=rule
                    self.CACHE['rules']['all']=True
                    return self.CACHE['rules']
            else:
                if ruleId in self.CACHE['rules']:
                    return self.CACHE['rules'][ruleId]
                else:
                    self.CACHE['rules'][ruleId]=self.http_request_auth(ruleId)
                    return self.CACHE['rules'][ruleId]
        else:
            self.CACHE['rules']={}
            return self.getRule(ruleId)


    def ruleClean(self):
        cursor=self.inMemSQLconn.cursor()
        sql="delete from rules"
        rows=cursor.execute(sql)
        
    def ruleCondense(self,data):
        sql_ruleinsert="insert into rules (name, provider_ip, consumer_name, port,to_port, proto, adminrule) VALUES (?,?,?,?,?,?,?)"
        returnList=[]
        cursor=self.inMemSQLconn.cursor()
        if 'all' in data:
            del data['all']
        import pprint
        

        for ruleset in data:
            fqdns=[]
            self.CACHE['scope']=[] #used to hand over scope to other routines
            for scopes in data[ruleset]['scopes']:
                for scope in scopes:
                    self.CACHE['scope'].append(self.replaceRuleItemsPC(scope))
            #if data[ruleset]['description'] != None:
            #    for line in data[ruleset]['description'].split('\n'):
            #        if 'dns' in line.lower():
            #            #print (line)
            #            line_arr=line.split(":")
            #            #print (line_arr)
            #            for name in line_arr[1].split(","):
            #                fqdns.append(name.strip())
            #print (self.CACHE['scope'])
            for rule in data[ruleset]['rules']:
                b_IsAdminRule=False
                if rule['enabled']==False:
                    next 
                if rule['unscoped_consumers']:
                    rule=self.replaceRuleItems(rule)
                    SHOW=False
                    if None in rule['consumers']['labels']:
                        rule['consumers']['labels'].remove(None)
                    ZscalerWantedConsumers=[]
                    for i in rule['consumers']['labels']:
                        for wanted in self.CONFIG['ZscalerWantedConsumers']:
                             if wanted in i:
                                SHOW=True
                                for skip in self.CONFIG['RuleIgnore']:
                                    if skip == data[ruleset]['name']:
                                        SHOW=False
                                for unwanted in self.CONFIG['ZscalerUnwantedConsumers']:
                                    if unwanted in i:
                                        SHOW=False
                                    

                    if SHOW==True:
                        #print (rule['providers']['ip'])
                        if len (fqdns) > 0:
                            rule['providers']['ip']=rule['providers']['ip']+fqdns
                            #print (rule['providers']['ip'])
                        for ports in rule['ingress_services']:
                            #print("\t",end="")
                            #print (ports)
                            b_IsAdminRule=False
                            #print (ports['ports'])
                            for portItem in ports['ports']:
                                if not 'port' in portItem:
                                    portItem['port']=-1
                                if not 'to_port' in portItem:
                                    portItem['to_port']=portItem['port']
                                for adminPort in self.CONFIG['adminPorts']:
                                    if portItem['port'] == adminPort:
                                        #print (str(portItem['port'])+" is adminPort")
                                        b_IsAdminRule=True
                                #print (portItem)
                                
                                for provIP in rule['providers']['ip']:
                                    cursor.execute(sql_ruleinsert,[data[ruleset]['name'],provIP,','.join(ZscalerWantedConsumers),portItem['port'],portItem['to_port'],portItem['proto'],b_IsAdminRule])
                                    
                    
        cursor.execute("commit")
        #sql="select distinct name || IIF(adminrule==0,'','_admin'), group_concat(DISTINCT provider_ip) as provider_ip, group_concat(DISTINCT consumer_name) as consumer_name, group_concat(DISTINCT port ||','|| proto) as port, adminrule from rules group by name, adminrule"
        #sql="select distinct name || case when adminrule==0 then '' else '_admin' end, group_concat(DISTINCT provider_ip) as provider_ip, group_concat(DISTINCT consumer_name) as consumer_name, group_concat(DISTINCT port ||','|| to_port ||','|| proto) as port, adminrule from rules group by name, adminrule"
        # ignore "FTP highport exclusion rules from 1024-65535"
        sql="select distinct name || case when adminrule==0 then '' else '_admin' end, group_concat(DISTINCT provider_ip) as provider_ip, group_concat(DISTINCT consumer_name) as consumer_name, group_concat(DISTINCT port ||','|| to_port ||','|| proto) as port, adminrule from rules where not (port = 1024 and to_port = 65535) group by name, adminrule"
        rows=cursor.execute(sql)
        for row in rows:
            returnList.append(row)
        return returnList

    def WorkloadList(self,attribList=[]):
        WorkLoads=self.get_Workloads()
        #print (WorkLoads)
        #agentList=self.getAgentsFromWorkloads(WorkLoads)

        #agentData=self.get_Agent(agentList[0])
        
        removeList=[]
        for i in range(0,5):
            if len(attribList) > 0:
                for item in WorkLoads[i].keys():
                    if not item in attribList and item not in removeList:
                        removeList.append(item)

        #print (WorkLoads[0])
        wlReturn=[]
        for workload in WorkLoads:
            workload['labels']=self.labelHref2Name(workload['labels'])
            for removeItem in removeList:
                if removeItem in workload:
                    workload.pop(removeItem)            
            wlReturn.append(workload)
        return wlReturn


    def AgentList(self,attribList=[]):
        WorkLoads=self.get_Workloads()
        print (WorkLoads)
        agentList=self.getAgentsFromWorkloads(WorkLoads)

        agentData=self.get_Agent(agentList[0])
        removeList=[]
        if len(attribList) > 0:
            for item in agentData.keys():
                if not item in attribList:
                    removeList.append(item)

        
        for agent in agentList:
            print (agent)
            agentData=self.get_Agent(agent)
            
            worksheet_name = agentData['hostname']+'_'+agent
            #print (worksheet_name)
            #worksheet_services = workbook.add_worksheet(worksheet_name[:30])
            labelNew={'app':None,'role':None,'env':None,'loc':None}
            labelNewSorted=[]
            for label in (agentData['labels']):
                labelTemp=(self.get_LabelsByHref(label['href']))
                labelNew[labelTemp['key']]=labelTemp['value']
            
            for removeItem in removeList:
                agentData.pop(removeItem)
            
            agentData['labels']=labelNew
            
            print (agentData)


    ###################
    # code            #
    ###################
            
    def checkVEN(self,hostname):
        try:
            agent=self.get_Agent(hostname)
            print ({'hostname':agent['hostname'],'status':agent['status'],'online':agent['online'],'last_hearbeat_on':agent['last_heartbeat_on']})
        except ValueError:
            print (self.getWorkloadByName(hostname)['updated_by']['href'])
            

    def printProgressBar (self,iteration, total, prefix = '', suffix = '', decimals = 1, length = 100, fill = '█', autosize = False):
        """
        Call in a loop to create terminal progress bar
        @params:
            iteration   - Required  : current iteration (Int)
            total       - Required  : total iterations (Int)
            prefix      - Optional  : prefix string (Str)
            suffix      - Optional  : suffix string (Str)
            decimals    - Optional  : positive number of decimals in percent complete (Int)
            length      - Optional  : character length of bar (Int)
            fill        - Optional  : bar fill character (Str)
            autosize    - Optional  : automatically resize the length of the progress bar to the terminal window (Bool)
        """
        try:
            percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
        except:
            percent= ("{0:." + str(decimals) + "f}").format(100 * (0))
        styling = '%s |%s| %s%% %s' % (prefix, fill, percent, suffix)
        if autosize:
            cols, _ = shutil.get_terminal_size(fallback = (length, 1))
            length = cols - len(styling)
        try:
            filledLength = int(length * iteration // total)
        except:
            filledLength = 0
        bar = fill * filledLength + '-' * (length - filledLength)
        print('\r%s' % styling.replace(fill, bar), end = '\r')
        # Print New Line on Complete
        if iteration == total: 
            print()