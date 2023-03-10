#!/usr/bin/python3
#(c) Mario.Rys@mondigroup.com 2022/2023

# illumio2ZPA
# Treat Illumio as source of truth for creating / updating the list of applications in ZPA which are then used to allow access to these applications remotely.
# Applications are created on ZPA based on the scope in a rule with the rule-name in Ilumio as well as applications per “interesting IP List” to allow IP based access –
# in addition to circumvent the missing DNS resolution of internal IP addresses the local AD DNS is dumped and mapped accordingly to the workload and IPL data. 
# Additional filtering is applied to remove unwanted FQDN entries before uploading to ZPA.
#
# 0.9  ignore "active FTP highport exclusion rules from 1024-65535" - hardcoded in illumio_api
#      minor bugfixes
#      major speed improvements if we have to retry an IPL update / insert
# 0.91 optimized service port additions / updates: identify and remove overlaps, convert output to ranges [ port 3301,3302,3303, 2998-3302 -> 2998-3303 ]
# 0.92 copy the ZPA ruleset as CSV for documentation purposes (only app and SAML attribute)
#      add logging to a file
# 0.93 fixed error checkOverlappingPorts where the last Port in the list was omitted
# 
# 


import json
from urllib import response

from illumio_api import IllumioApi
from pyzscaler import ZPA
import re
#https://pyzscaler.readthedocs.io/en/latest/zs/zpa/app_segments.html

import ipaddress

import os
import sys
import time
import restfly

from dnsdump import *
from cryptography.fernet import Fernet

import csv
import logging 

il=None
zpa=None
zpa_servergroupList=None
zpa_app_segments=None
zpa_segmentgroupList=None

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

#now we will Create and configure logger 
logging.basicConfig(filename="illumio2zpa.log", 
					format='%(asctime)s %(message)s', 
					filemode='w') 
#Let us Create an object 
logger=logging.getLogger() 
#Now we are going to Set the threshold of logger to DEBUG 
logger.setLevel(logging.INFO) 


def printNLog(msg,end=False):
    global logger
    logger.info(msg) 
    if end:
        print (msg,end)
    else:
        print (msg)

def IL_cleanupInvalidInterfaces(config,interfaces):
    retInterfaces=[]
    for ip in interfaces:
        skipIP=False
        for invalidIpRange in config['invalidIpRanges']:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(invalidIpRange):
                skipIP=True
        if skipIP==False:
            retInterfaces.append(ip)
    return retInterfaces

def flatten(d,sep="_"):
    import collections

    obj = collections.OrderedDict()

    def recurse(t,parent_key=""):
        
        if isinstance(t,list):
            for i in range(len(t)):
                recurse(t[i],parent_key + sep + str(i) if parent_key else str(i))
        elif isinstance(t,dict):
            for k,v in t.items():
                recurse(v,parent_key + sep + k if parent_key else k)
        else:
            obj[parent_key] = t

    recurse(d)

    return obj
def IL_getRuleset(ARecords,DEBUGSQL=False,dnsIPL=True,dnsWL=True):
    global il
    with open('il_config.json') as f:
        config = json.load(f)


    il=IllumioApi(config,DEBUGSQL=DEBUGSQL)
    il.dnsIPL=dnsIPL
    il.dnsWL=dnsWL
    il.DNSTableFill(ARecords) #NoneBut would allow to "just fill one IPL" in case of emergency updates 
    
    data=il.getRuleSet()

    returnList=il.ruleCondense(data)    
    return returnList


def ZPA_addAppPerRule(rules,DefaultServerGroupCC='AT',DefaultServerGroupName='Dynamic_Path_Selector',ContainerName="IllumioApps",sleeptime=0.1,zpa_servergroupList=False,zpa_app_segments=False,zpa_segmentgroupList=False):
    global DEBUG
    global zpa
    with open('zpa_config.json') as f:
        zpa_CONFIG = json.load(f)
    if zpa==None:
        zpa = ZPA(client_id=zpa_CONFIG['client_id'], client_secret=zpa_CONFIG['client_secret'], customer_id=zpa_CONFIG['customer_id'])
    
    if zpa_segmentgroupList==False:
        zpa_servergroupList=zpa.server_groups.list_groups()
    if zpa_app_segments==False:
        zpa_app_segments=zpa.app_segments.list_segments()
    if zpa_segmentgroupList==False:
        zpa_segmentgroupList=zpa.segment_groups.list_groups()

    for rule in rules:

        r_name=rule[0]
        r_prov=rule[1]
        r_cons=rule[2]
        r_port_list_str=rule[3]
        #r_port_list_str=r_port_list_str.replace(',514','')
        r_port_list=r_port_list_str.split(',')
        
        
        for server_group in zpa_servergroupList:
            #default server 
            if DefaultServerGroupCC==server_group['app_connector_groups'][0]['country_code']:
                if DefaultServerGroupName == server_group['name']:
                    server_group_ids=server_group['id']
            if server_group['app_connector_groups'][0]['country_code'] in r_name:
                server_group_ids=server_group['id']

        ZPA_AppName='Il_'+r_name


        tcp_ports_update=[]
        udp_ports_update=[]

        for id in range(0, int(len(r_port_list)/3)):
            r_port=int(r_port_list[id*3])
            r_toport=int(r_port_list[id*3+1])
            r_prot=int(r_port_list[id*3+2])


            if r_prot==6:
                tcp_ports_update.append([r_port,r_toport])

            if r_prot==17:
                udp_ports_update.append([r_port,r_toport])

        #port optimizer        
        tcp_ports_update=checkOverlappingPorts(tcp_ports_update)
        if len(tcp_ports_update)>0:
            tcp_ports_add = [val for sublist in tcp_ports_update for val in sublist]
        else:
            tcp_ports_add=[]
        udp_ports_update=checkOverlappingPorts(udp_ports_update)
        if len(udp_ports_update)>0:
            udp_ports_add = [val for sublist in udp_ports_update for val in sublist]
        else:
            udp_ports_add = []

        #skip if no serivce is exposed in the rule
        if len (tcp_ports_update) == 0 and len(udp_ports_update) == 0:
            continue

        #create a Container segment group to satisfy Zscaler
        AppSegmentGroupExists=False
        AppSegmentGrpAddApplication=True
        for segment_group in zpa_segmentgroupList:
            if ContainerName == segment_group['name']:
                segment_group_id=segment_group['id']
                AppSegmentGroupExists=True
                        
        if AppSegmentGroupExists==False:
            printNLog ("Adding segment group "+ContainerName)
            segment_group=zpa.segment_groups.add_group(ContainerName,True)
            segment_group_id=segment_group['id']
            zpa_segmentgroupList=zpa.segment_groups.list_groups()
        if len(tcp_ports_update) == 0 and len(udp_ports_update)==0:
            printNLog ("Skipping segment "+ZPA_AppName)
            next


        b_AppExists=False
        for app_segment in zpa_app_segments:
            if ZPA_AppName == app_segment['name']:
                b_AppExists=True
                app_id=app_segment['id']

        r_prov=r_prov.split(",")
        if DEBUG:
            printNLog (ZPA_AppName,r_prov,segment_group_id,tcp_ports_add,udp_ports_add,r_cons,server_group_ids) 
            continue
        if b_AppExists == False:    
            printNLog ("ZPA_addAppPerRule:Adding app_segment "+ZPA_AppName)
            try:
                add_segment=zpa.app_segments.add_segment(
                        name=ZPA_AppName,
                        domain_names=r_prov,
                        segment_group_id=segment_group_id,
                        tcp_ports=tcp_ports_add,
                        udp_ports=udp_ports_add,
                        description=r_cons,
                        server_group_ids=[server_group_ids])
                printNLog ("\tDone")#, sleeping "+str(sleeptime)+" seconds not to overload ZPA")
                time.sleep(sleeptime)
            except restfly.errors.BadRequestError as err:
                retVal=restFlyHandler(err)
                if retVal != None:
                    for app_segment in zpa_app_segments:
                        if retVal['retry'].lower().strip() == app_segment['name'].lower().strip() and len(app_segment['domain_names'])>0 :
                            printNLog ("Removing IPs/ranges of "+app_segment['name']+" ")
                            newIPList=[]
                            for new in r_prov:
                                skip=False
                                for existing in app_segment['domain_names']:
                                    if new == existing:
                                        skip=True
                                        printNLog ("\t skip "+existing)
                                if skip==False:
                                    newIPList.append(new)
                            printNLog ("\n retrying")
                            l_tmp=list(rule)
                            l_tmp[1]=','.join(newIPList)
                            rule=tuple(l_tmp)
                            ZPA_addAppPerRule([rule],DefaultServerGroupCC,DefaultServerGroupName,ContainerName,sleeptime,zpa_servergroupList,zpa_app_segments,zpa_segmentgroupList)
                #print (ZPA_AppName,r_prov,segment_group_id,tcp_ports_add,udp_ports_add,r_cons,server_group_ids)
            except restfly.errors.ForbiddenError:
                ZPA_addAppPerRule(rule,DefaultServerGroupCC,DefaultServerGroupName,ContainerName,sleeptime,zpa_servergroupList,zpa_app_segments,zpa_segmentgroupList)
        else:
            printNLog ("ZPA_addAppPerRule:Updating app_segment "+ZPA_AppName)
            try:
                update_segment=zpa.app_segments.update_segment(segment_id=app_id,
                    name=ZPA_AppName,
                    domain_names=r_prov,
                    segment_group_id=segment_group_id,
                    tcp_ports=tcp_ports_update,
                    udp_ports=udp_ports_update,
                    description=r_cons,
                    server_group_ids=[server_group_ids])
                #eprintNLog (update_segment)
                printNLog ("\tDone")#, sleeping "+str(sleeptime)+" seconds not to overload ZPA")
            except restfly.errors.BadRequestError as err:
                retVal=restFlyHandler(err)
                if retVal != None:
                    for app_segment in zpa_app_segments:
                        if retVal['retry'].lower().strip() == app_segment['name'].lower().strip() and len(app_segment['domain_names'])>0:
                            printNLog ("Removing IPs/ranges of "+app_segment['name']+" ")
                            newIPList=[]
                            for new in r_prov:
                                skip=False
                                for existing in app_segment['domain_names']:
                                    if new == existing:
                                        #printNLog ("skip")
                                        skip=True
                                        printNLog ("\t skip "+existing)
                                if skip==False:
                                    newIPList.append(new)
                            printNLog ("\n retrying")
                            l_tmp=list(rule)
                            l_tmp[1]=','.join(newIPList)
                            rule=tuple(l_tmp)
                            ZPA_addAppPerRule([rule],DefaultServerGroupCC,DefaultServerGroupName,ContainerName,sleeptime,zpa_servergroupList,zpa_app_segments,zpa_segmentgroupList)
                #printNLog (ZPA_AppName,r_prov,segment_group_id,tcp_ports_update,udp_ports_update,r_cons,server_group_ids)
            except restfly.errors.ForbiddenError:
                ZPA_addAppPerRule([rule],DefaultServerGroupCC,DefaultServerGroupName,ContainerName,sleeptime,zpa_servergroupList,zpa_app_segments,zpa_segmentgroupList)


def ZPA_delete_ILApps():
    with open('zpa_config.json') as f:
        zpa_CONFIG = json.load(f)
    zpa = ZPA(client_id=zpa_CONFIG['client_id'], client_secret=zpa_CONFIG['client_secret'], customer_id=zpa_CONFIG['customer_id'])
    
    printNLog ("Getting ZPA App Segments")
    zpa_app_segments=zpa.app_segments.list_segments()
    printNLog ("Getting ZPA App SegmentGroups")
    zpa_segmentgroupList=zpa.segment_groups.list_groups()

    for zpa_app_segment in zpa_app_segments:
        if 'Il_' in zpa_app_segment['name']:
            printNLog ("Removing segment "+zpa_app_segment['name'])
            try:
                printNLog(zpa.app_segments.delete_segment(zpa_app_segment['id']))
            except restfly.errors.BadRequestError as err:
                restFlyHandler(err)

            

def IL_getCleanWorkloads():
    il=IllumioApi()
    
    with open('il_config.json') as f:
        il.CONFIG = json.load(f)

    attribList=[
        'uid',
        'labels',
        'hostname',
        'online',
        'interfaces',
        'name'
    ]
    wl=il.WorkloadList(attribList)
    
    AppSegments={}
    for w in wl:
        ips=[]
        for interface in w['interfaces']:
            #printNLog (interface['address'])
            if ':' in interface['address']:
                continue
            ips.append(interface['address'])
        
        w['interfaces']=ips
        #printNLog (w)
        if w['hostname'] == None or w['hostname'] == '' :
            #w['name'] = w['hostname']
            continue
        if il.validIP(w['hostname']):
            continue
        
        #skip Apps we don't want to publish automagically
        AppNameNew=w['labels']['app']
        AppNameNew=re.sub('[^\-_\ A-Za-z0-9 ]+','', AppNameNew)
        SkipApp=False
        for ServiceIgnore in il.CONFIG['ServiceIgnore']:
            if AppNameNew==ServiceIgnore:
                SkipApp=True
        if SkipApp==True:
            continue
        
        
        for ServiceBySite in il.CONFIG['ServiceBySite']: #some service we distinguish by site, others we don't care as globally
            if ServiceBySite==AppNameNew:
                AppNameNew=w['labels']['app']+'_'+w['labels']['loc'].lstrip('L-') #get rid of the L- marker in the location
        if not AppNameNew in AppSegments:
            AppSegments[AppNameNew]=[]
        w['interfaces']=IL_cleanupInvalidInterfaces(il.CONFIG,w['interfaces'])
        AppSegments[AppNameNew].append({w['hostname']:w['interfaces']})
        
    
    return AppSegments

def ZPA_addIPL():
    global il
    match = re.compile("^(IPL-\w\w)-([a-zA-Z0-9_/ ]+)-([a-zA-Z0-9/_ ]+)(-(.*))?")
    IPLs={}

    for row in il.IplTableDump():
        matches=match.match(row[0])
        if matches: #and 'IPL-ZA' in row[0]
            tmp=matches.groups()
            if tmp[3] and tmp[3].upper()=='OT':
                IPLName=tmp[0]+'-'+tmp[1]+'-'+tmp[2]+'-'+tmp[3]
            else:
                IPLName=tmp[0]+'-'+tmp[1]+'-'+tmp[2]
            if not IPLName in IPLs:
                IPLs[IPLName]=[]
            skipIP=False
            for range in IPLs[IPLName]:
                try:
                    if ipaddress.ip_network(row[1]) in ipaddress.ip_network(range):
                        skipIP=True
                except:
                    pass
            if skipIP==False:
                    IPLs[IPLName].append(row[1])


    for IPL in IPLs:
        if len(IPLs[IPL]) > 0:
            ZPA_addItem([IPL,IPLs[IPL],IPL])


def ZPA_addItem(rule,DefaultServerGroupCC='AT',DefaultServerGroupName='Dynamic_Path_Selector',ContainerName="IllumioIPLs",sleeptime=0.1,retry=False):
    global zpa
    global zpa_servergroupList
    global zpa_app_segments
    global zpa_segmentgroupList
    with open('zpa_config.json') as f:
        zpa_CONFIG = json.load(f)
    if zpa == None:
        zpa = ZPA(client_id=zpa_CONFIG['client_id'], client_secret=zpa_CONFIG['client_secret'], customer_id=zpa_CONFIG['customer_id'])


    if zpa_servergroupList == None:
        printNLog ("getting servergroup")
        zpa_servergroupList=zpa.server_groups.list_groups()
    if zpa_app_segments==None:
        printNLog ("getting segments")
        zpa_app_segments=zpa.app_segments.list_segments()
    if zpa_segmentgroupList == None:
        printNLog ("getting segment group list")
        zpa_segmentgroupList=zpa.segment_groups.list_groups()

    r_name=rule[0]
    r_prov=rule[1]
    r_cons=rule[2]

    if isinstance(r_prov, str):
        r_prov=r_prov.split(",")


    for server_group in zpa_servergroupList:
        #default server 
        if DefaultServerGroupCC==server_group['app_connector_groups'][0]['country_code']:
            if DefaultServerGroupName == server_group['name']:
                server_group_ids=server_group['id']
        if server_group['app_connector_groups'][0]['country_code'] in r_name:
            server_group_ids=server_group['id']

    ZPA_AppName='Il_'+r_name
    ZPA_AppName=re.sub(r'[^A-Za-z0-9 _-]',' ', ZPA_AppName).strip()
    r_cons=ZPA_AppName # hack fix names 

    tcp_ports_add=[1,52,54,65535]
    udp_ports_add=[1,52,54,65535]
    tcp_ports_update=[[1,52],[54,65535]]
    udp_ports_update=[[1,52],[54,65535]]


    #create a Container segment group to satisfy Zscaler
    AppSegmentGroupExists=False
    AppSegmentGrpAddApplication=True
    for segment_group in zpa_segmentgroupList:
        if ContainerName == segment_group['name']:
            segment_group_id=segment_group['id']
            AppSegmentGroupExists=True
    if AppSegmentGroupExists==False:
        printNLog ("Adding segment group "+ContainerName)
        segment_group=zpa.segment_groups.add_group(ContainerName,True)
        segment_group_id=segment_group['id']
        zpa_segmentgroupList=zpa.segment_groups.list_groups()


    #add or update app_segment
    b_AppExists=False
    for app_segment in zpa_app_segments:
        #printNLog (ZPA_AppName,app_segment['name'])
        if ZPA_AppName.lower().strip() == app_segment['name'].lower().strip() and len(app_segment['domain_names'])>0 :
            b_AppExists=True
            app_id=app_segment['id']

    
    if b_AppExists == False :
        try:
            printNLog ("ZPA_addItem:Adding app_segment "+ZPA_AppName)
            add_segment=zpa.app_segments.add_segment(
                    name=ZPA_AppName,
                    domain_names=r_prov,
                    segment_group_id=segment_group_id,
                    tcp_ports=tcp_ports_add,
                    udp_ports=udp_ports_add,
                    description=r_cons,
                    server_group_ids=[server_group_ids])

            #printNLog (add_segment)
            printNLog ("\tDone")#, sleeping "+str(sleeptime)+" seconds not to overload ZPA")
            time.sleep(sleeptime)
        except restfly.errors.BadRequestError as err:
            retVal=restFlyHandler(err)
            if retVal != None:
                for app_segment in zpa_app_segments:
                    if retVal['retry'].lower().strip() == app_segment['name'].lower().strip() and len(app_segment['domain_names'])>0 :
                        printNLog ("Removing IPs/ranges of "+app_segment['name']+" ")
                        newIPList=[]
                        for new in r_prov:
                            skip=False
                            for existing in app_segment['domain_names']:
                                #printNLog ("."+new+"-"+existing+".")
                                #if str(new.strip(),"ascii") == str(existing.strip(), "ascii") :
                                if new == existing:
                                    skip=True
                                    printNLog (existing,end=", ")
                            if skip==False:
                                newIPList.append(new)
                        printNLog ("\n retrying")
                        l_tmp=list(rule)
                        l_tmp[1]=','.join(newIPList)
                        rule=tuple(l_tmp)
                        ZPA_addItem(rule,DefaultServerGroupCC,DefaultServerGroupName,ContainerName,sleeptime,True)
                        return
            printNLog (ZPA_AppName,r_prov,segment_group_id,tcp_ports_add,udp_ports_add,r_cons,server_group_ids)
        except restfly.errors.ForbiddenError:
            ZPA_addItem(rule,DefaultServerGroupCC,DefaultServerGroupName,ContainerName,sleeptime,True)
        except restfly.errors.TooManyRequestsError:
            printNLog (".")
            time.sleep(sleeptime)
            ZPA_addItem(rule,DefaultServerGroupCC,DefaultServerGroupName,ContainerName,sleeptime,True)
    else:
        printNLog ("ZPA_addItem:Updating app_segments "+ZPA_AppName)
        try:
            update_segment=zpa.app_segments.update_segment(segment_id=app_id,
                name=ZPA_AppName,
                domain_names=r_prov,
                segment_group_id=segment_group_id,
                tcp_ports=tcp_ports_update,
                udp_ports=udp_ports_update,
                description=r_cons,
                icmp_access_type='PING',
                server_group_ids=[server_group_ids])
            #printNLog (update_segment)
            printNLog ("\tDone")#, sleeping "+str(sleeptime)+" seconds not to overload ZPA")
            time.sleep(sleeptime)
        except restfly.errors.BadRequestError as err:
            retVal=restFlyHandler(err)
            if retVal != None:
                for app_segment in zpa_app_segments:
                    if retVal['retry'].lower().strip() == app_segment['name'].lower().strip() and len(app_segment['domain_names'])>0 :
                        printNLog ("Removing IPs/ranges of "+app_segment['name']+" ")
                        newIPList=[]
                        skipped=False
                        for new in r_prov:
                            skip=False
                            for existing in app_segment['domain_names']:
                                #printNLog ("."+new+"-"+existing+".")
                                #if str(new.strip(),"ascii") == str(existing.strip(), "ascii") :
                                if new == existing:
                                    skipped=True
                                    skip=True
                                    printNLog ("\t skip "+existing)
                            if skip==False:
                                newIPList.append(new)
                        printNLog ("\n retrying")
                        l_tmp=list(rule)
                        l_tmp[1]=','.join(newIPList)
                        rule=tuple(l_tmp)
                        if skipped==True:
                            ZPA_addItem(rule,DefaultServerGroupCC,DefaultServerGroupName,ContainerName,sleeptime,True)
                        return
            printNLog (ZPA_AppName,len(r_prov),r_prov,segment_group_id,tcp_ports_update,udp_ports_update,r_cons,server_group_ids,True)
        except restfly.errors.ForbiddenError:
            ZPA_addItem(rule,DefaultServerGroupCC,DefaultServerGroupName,ContainerName,sleeptime,True)

from codecs import encode, decode

def restFlyHandler(err):
    err=(f"{err=}")
    m = re.search("\[(\d+): (\w+)\] (.*) body=b(.*)\'",err)
    if m:
        #code=m.group(1)
        body=m.group(4)
        body = decode(encode(body, 'latin-1', 'backslashreplace'), 'unicode-escape').replace('\\n','\n').replace("'","")

        message=json.loads(body)
        return handleRestIssues(message['id'],message['reason'])

def handleRestIssues(id,reason):
    printNLog ('\tFailed\t',end='')
    if id =="tcp.portrange.invalid":
        if 'TCP ports overlaps with port range of the application' in reason:
            segment=reason.split(':')[1].lstrip()
            return {'retry':segment}
        else:
            printNLog (reason)

    elif id == 'resource.duplicate':
        printNLog (reason)

    elif id == 'read.message.failed':
        printNLog (reason)
    elif id == 'tcp.portrange.invalid':
        printNLog (reason)
    else:
        printNLog (id)
        printNLog (reason)

def removeUnwantedZones(zones):
    cleanUpZones=[]
    unwanted=['arpa','RootDNSServers', 'TrustAnchors', '_msdcs', 'RootDNSServers']
    for z in zones:
        wanted=True
        for u in unwanted:      
            if u in z:
                wanted=False
        if wanted==True:
            cleanUpZones.append(z)
    return cleanUpZones


def getDNSDataConfig(invalidateConfigg=False):
    
    CONFIGFILE='dns_config.json'
    if os.path.exists(CONFIGFILE) and invalidateConfigg==False:
        with open(CONFIGFILE) as f:
            config = json.load(f)
            cipher_suite = Fernet(config['cipher_key'])
            config['user']=cipher_suite.decrypt(config['user']).decode("utf-8")
            config['password']=cipher_suite.decrypt(config['password']).decode("utf-8")
            return config
    else:
        config={}
        config['cipher_key']=Fernet.generate_key().decode("utf-8")
        cipher_suite = Fernet(config['cipher_key'])
        
        config['host']=input('DC to query:                    ')
        config['DNSServerIP']=input('NS to query for DNS lookup:     ')
        config['user']=cipher_suite.encrypt(bytes(input('Username (include the domain\):'),'ascii')).decode("utf-8")
        config['password']=cipher_suite.encrypt(bytes(getpass.getpass(),'ascii')).decode("utf-8")
        with open(CONFIGFILE, 'w') as outfile:
            json.dump(config, outfile)
        config['user']=cipher_suite.decrypt(config['user']).decode("utf-8")
        config['password']=cipher_suite.decrypt(config['password']).decode("utf-8")
        
        return config

def getDNSData(minAmount=10000):
    config=getDNSDataConfig()

    dns=dnsdump(host=config['host'],user=config['user'],password=config['password'],DNSServerIP=config['DNSServerIP'])
    zones=dns.read(return_zones=True)
    zones=removeUnwantedZones(zones)
    ARecords=[]
    Ahash={}
    CRecords=[]
    outfile = codecs.open('records.csv', 'w', 'utf-8')
    outfile.write('type,name,value\n')
    for zone in zones:
        records=dns.read(zone=zone,resolve=True,dns_tcp=False)
        for r in records:
            outfile.write('{type},{name},{value}\n'.format(**r))
            if r['name'] != '@' and not '._sites' in r['name'] and not '._tcp' in r['name'] and not '._udp' in r['name'] and not 'dnszones.' in r['name']:
                if r['type'] == 'A':
                    if r['name'][-1] == '.':
                        ARecords.append([r['name'][0:-1],r['value']])
                    elif zone in r['name']:
                        ARecords.append([r['name'],r['value']])
                    else:
                        ARecords.append([r['name']+'.'+zone,r['value']])
                if r['type'] == 'CNAME':
                    if r['name'][-1] == '.':
                        CRecords.append([r['name'][0:-1],r['value']])
                    elif zone in r['name']:
                        CRecords.append([r['name'],r['value']])
                    else:
                        CRecords.append([r['name']+'.'+zone,r['value']])
    for A in ARecords:
        Ahash[A[0]]=A[1].lower()

    PrevLen=0
    while len(CRecords) > 0 and len(CRecords) != PrevLen:
        PrevLen=len(CRecords)
        retryCname=[]
        for CNAME in CRecords:
            if CNAME[1][-1] == '.':
                CNAME[1]=CNAME[1][0:-1]
            try:
                ARecords.append([CNAME[0],Ahash[CNAME[1]].lower()])
            except:
                printNLog ("retry for CNAME "+CNAME[0])
                retryCname.append(CNAME)
        CRecords=retryCname
    
    if len(ARecords) < minAmount:
        printNLog ("amount of DNS records below expected value of "+str(minAmount))
        exit()
    return ARecords

def ZPA_GetPolicy(type="access",sleeptime=0.1):
    global zpa
    global zpa_servergroupList
    global zpa_app_segments
    global zpa_segmentgroupList
    with open('zpa_config.json') as f:
        zpa_CONFIG = json.load(f)
    if zpa == None:
        zpa = ZPA(client_id=zpa_CONFIG['client_id'], client_secret=zpa_CONFIG['client_secret'], customer_id=zpa_CONFIG['customer_id'])

    
    policySet=zpa.policies.list_rules(type)

    csv=[['id','name','rule','rule_order_id','policy']]
    csv=[]
    
    for policy in policySet:
        csvRow={}
        csvRow['id']=policy.id
        csvRow['name']=policy.name
        csvRow['rule_order']=policy.rule_order
        csvRow['operator']=policy.operator
        for condition in policy.conditions:
            csvRow['APP']=[]
            csvRow['SAML']=[]
            for operand in condition.operands:
                if operand.object_type == 'APP':
                    csvRow['APP'].append(operand.object_type+'='+operand.name)
                if operand.object_type == 'SAML':
                    csvRow['SAML'].append(operand.name+'='+operand.rhs)
        csv.append(csvRow)
    timestr = time.strftime("%Y%m%d-%H%M")
    
    csvWriter('policy-'+str(timestr)+'.csv',csv)

def csvWriter(fname,dict):
    with open(fname, 'w', newline='',  encoding='utf-8') as csv_data:
        # create the csv writer object
        csvwriter = csv.writer(csv_data)
        count = 0
        for d in dict:
            if count == 0:
                header = d.keys()
                csvwriter.writerow(header)
                count += 1
            csvwriter.writerow(d.values())
        csv_data.close()


def checkOverlappingPorts(portList):
    #clumsy tool to check for overlapping ranges
    mySet=set()
    for port,to_port in portList:
        if port == to_port:
            mySet.add(port)
        for i in range(port,to_port+1):
            mySet.add(i)

    retArr=[]
    start=-99
    end=-99
    prev=-99
    if len(portList)==1:
        return portList
    ADDED=False
    for item in sorted(mySet):
        #printNLog (item)
        if start == -99:
            if ADDED==True:
                retArr.append([start,end])
            start=item
            end=item
            prev=item
            continue            
        if item - 1 == prev:
            end=item
            prev=item
            continue
        else:
            retArr.append([start,end])
            #printNLog (lower,higher)
            start=item
            end=item
            prev=item
    
    if start != -99 and end != -99:
        retArr.append([start,end])        
    return retArr



def main():
    global DEBUG
    #Rules are a list of
    # provider IPs
    # Consumer Labels (so they can be assigned somehow)
    # serivces (that need to be open for the providers)
    ## we create the objects and write into the description the intended sources as per illumio


    #DEBUGSQL=Truecreate a SQLite database on disk for troubleshooting purposes; False keeps the database in memory only
    #MinAmountDnsRecords - if the count of records is below this number the upload process is halted with an error message to avoid "cleaning" FQDNs from Zscaler Private Access 
    #DEBUG=False
    DEBUGSQL=True
    MinAmountDnsRecords=10000

    #print (checkOverlappingPorts([[1550,1552],[3257,3257],[3256,3256],[3255,3255],[3254,3254],[3253,3253],[3252,3252],[3250,3250],[3251,3251],[3260,3262],[3350,3357],[4852,4852],[4851,4851],[4850,4850],[4854,4854],[4855,4855],[4856,4856],[8050,8057],[7450,7457],[3950,3950],[3952,3952],[3650,3652],[8150,8152],[8250,8252],[50013,59814],[3289,3289],[3254,3254],[3256,3256],[3252,3252],[3255,3255],[3355,3355],[3352,3352],[3356,3356],[3354,3354],[4852,4852],[8054,8054],[8056,8056],[8052,8052],[8055,8055],[7455,7455],[7452,7452],[7456,7456],[7454,7454],[3650,3650],[3662,3662],[8050,8050],[8162,8162],[7450,7450],[8262,8262],[31241,31242],[51213,51213],[55513,55513],[55213,55213],[55613,55613],[55413,55413],[51214,51214],[55514,55514],[55214,55214],[55614,55614],[55414,55414],[31213,31213],[31215,31215]]))
    #exit()
    if DEBUG:
        ARecords=[]
        rules=IL_getRuleset(ARecords,DEBUGSQL,dnsIPL=False,dnsWL=False)
    else:
        ARecords=getDNSData(MinAmountDnsRecords)
        rules=IL_getRuleset(ARecords,DEBUGSQL)
    
    ZPA_addAppPerRule(rules)
    ZPA_addIPL()
    
    ZPA_GetPolicy()


class RedirectStdStreams(object):
    def __init__(self, stdout=None, stderr=None):
        self._stdout = stdout or sys.stdout
        self._stderr = stderr or sys.stderr

    def __enter__(self):
        self.old_stdout, self.old_stderr = sys.stdout, sys.stderr
        self.old_stdout.flush(); self.old_stderr.flush()
        sys.stdout, sys.stderr = self._stdout, self._stderr

    def __exit__(self, exc_type, exc_value, traceback):
        self._stdout.flush(); self._stderr.flush()
        sys.stdout = self.old_stdout
        sys.stderr = self.old_stderr


DEBUG=False

if __name__ == '__main__':
    if DEBUG==None or DEBUG==False:
        devnull = open('error.log', 'w')
        with RedirectStdStreams(stderr=devnull):
            main()
    else:
        main()
