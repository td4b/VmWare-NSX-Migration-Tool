# -*- coding: utf-8 -*-
"""
Created on Sat Mar  3 10:36:06 2018

@author: Thomas West
"""

import getpass
import requests
import xmltodict, json
import re
import sys
from ansible_vault import Vault

# disable insecure SSL warning if interface is set up with a self signed cert.
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# vCenter SDK Bindingds & Modules.
from pyVim.connect import SmartConnect, Disconnect
import ssl

# Get the pre-shared key for decrypting the Sensitive login data.
pswd = getpass.getpass("Please enter the Script migration tool password: ")
vault = Vault(pswd)

# Get login info from configuration file for NSX API.
data = vault.load(open('login.yaml').read())

nsxhostname, nsxusr, nsxpw = data['NSX']['hostname'],data['NSX']['username'],data['NSX']['password']
vchostname, vcusr, vcpw = data['vCenter']['hostname'],data['vCenter']['username'],data['vCenter']['password']

s = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
s.verify_mode = ssl.CERT_NONE

c = SmartConnect(host=vchostname, user=vcusr, pwd=vcpw, sslContext=s)
 
print("Executed at System Time: " + str(c.CurrentTime()))

datacenter = c.content.rootFolder.childEntity[0]
vms = datacenter.vmFolder.childEntity

# Build the MOID map.
# VM methods - vCenter
moidmap = {}
for i in vms:
   moidmap[i.name] = str(i).split(":")[1][:-1]

## Core-NSX Methods

# Security Tag Methods

def getmoid(name):
    return moidmap[name]

# Initial Tag Creation Methods.

def getstag(name,description):
    def createtag(name):
        rheaders = {'Content-Type': 'text/xml'}
        host = nsxhostname + '/api/2.0/services/securitytags/tag'
        payload = '''
        <securityTag>
        <objectTypeName>SecurityTag</objectTypeName>
        <type><typeName>SecurityTag</typeName></type>
        <name>{}</name>
        <description>{}</description>
        <extendedAttributes/>
        </securityTag> 
        '''.format(name,description)
        r = requests.post(host, payload, auth = (nsxusr,nsxpw), verify=False, headers= rheaders)
        try:
            o = xmltodict.parse(r.text)
            result = json.dumps(o) 
            jsons = json.loads(result)
            print(jsons['error'])
        except:
            "Continue"
            
        return r.text
    
    rheaders = {'Content-Type': 'text/xml'}
    host = nsxhostname + '/api/2.0/services/securitytags/tag'
    r = requests.get(host, auth = (nsxusr,nsxpw), verify=False, headers= rheaders)
    
    o = xmltodict.parse(r.text)
    result = json.dumps(o) 
    jsons = json.loads(result)['securityTags']['securityTag']
    tagmap = {}
    for i in jsons:
        tagmap[i['name']] = i['objectId']
    
    if name in tagmap:
        return tagmap[name]
    else:
        ids = createtag(name)
        print("Failed to find tag, creating the Tag: " + name + " ID: " + ids)
        return ids

def getallsectags():
    rheaders = {'Content-Type': 'text/xml'}
    host = nsxhostname + '/api/2.0/services/securitytags/tag'
    r = requests.get(host, auth = (nsxusr,nsxpw), verify=False, headers= rheaders)
    tags = []
    try:
        o = xmltodict.parse(r.text)
        result = json.dumps(o) 
        jsons = json.loads(result)['securityTags']['securityTag']
        for i in jsons:
            try:
                # Find only preformatted Standard System Tags.
                if i['name'].split("-")[0] == "ST":
                    tags.append(i['name'])
            except:
                continue          
        return tags
    except:
        'continue'

# Gets a specific Tag.
def gettag(name):
    rheaders = {'Content-Type': 'text/xml'}
    host = nsxhostname + '/api/2.0/services/securitytags/tag'
    r = requests.get(host, auth = (nsxusr,nsxpw), verify=False, headers= rheaders)
    o = xmltodict.parse(r.text)
    result = json.dumps(o) 
    jsons = json.loads(result)['securityTags']['securityTag']
    tagmap = {}
    for i in jsons:
        tagmap[i['name']] = [i['objectId'],i['description']]
    if name in tagmap:
        return tagmap[name][0] , tagmap[name][1]
    else:
        print("Error Getting Security Tag")
            
def applytag(sectagid,vmoid):
    rheaders = {'Content-Type': 'text/xml'}
    host = nsxhostname + '/api/2.0/services/securitytags/tag/{}/vm/{}'.format(sectagid,vmoid)
    r = requests.put(host, auth = (nsxusr,nsxpw), verify=False, headers= rheaders)
    return r.text 

# Firewall Section Methods.
    
def createsection(name):
    rheaders = {'Content-Type': 'text/xml'}
    host = nsxhostname + '/api/4.0/firewall/globalroot-0/config/layer3sections'
    payload = '''
    <section name="{}">
    </section>
    '''.format(name)
    r = requests.post(host, payload, auth = (nsxusr,nsxpw), verify=False, headers= rheaders)
    return r.text

def movesection(name,secid,etag,conf):
    rheaders = {'Content-Type': 'text/xml', 'if-Match': etag}
    host = nsxhostname + '/api/4.0/firewall/globalroot-0/config/layer3sections/' + secid + '?action=revise&operation=insert_before_default'
    m = re.search('<sections>(.+?)<\/sections>',conf)
    payload = m.group(1)
    r = requests.post(host, payload, auth = (nsxusr,nsxpw), verify=False, headers= rheaders)
    return print("Firewall Section Created: " + name +"ID: " + secid + str(r.status_code))

def getfwconfig(section_name):
    rheaders = {'Content-Type': 'application/xml'}
    uri = '/api/4.0/firewall/globalroot-0/config/layer3sections?name=' + section_name
    host = nsxhostname + uri
    r = requests.get(host, auth= (nsxusr, nsxpw), verify=False, headers= rheaders)
    return r.text, r.headers, r.status_code

# Look for the section ID, if one is not found from Origin then create a new baseline section.
def secid(configuration):
    o = xmltodict.parse(configuration)
    result = json.dumps(o) 
    jsons = json.loads(result)
    try:
        val = jsons['sections']['section']['@id']
        return val
    except:
        'continue'
  
# payload contains XML formatted Firewall Rules for the scope deployment.
def postsection(payload, etag, secid):
    rheaders = {'Content-Type': 'text/xml', 'if-Match': etag}
    host = nsxhostname + '/api/4.0/firewall/globalroot-0/config/layer3sections/' + secid + '/rules'
    r = requests.post(host, payload, auth = (nsxusr,nsxpw), verify=False, headers= rheaders)
    return print("Created Firewall Section, Status Code: " + str(r.status_code))

def createpolicies(secID,ETag,rulename,sgid,types):
      
    baseconf = '''
    <name>{}</name>
    <action>allow</action>
    <appliedToList><appliedTo>
    <name>DISTRIBUTED_FIREWALL</name>
    <value>DISTRIBUTED_FIREWALL</value>
    <type>DISTRIBUTED_FIREWALL</type>
    <isValid>true</isValid>
    </appliedTo></appliedToList>
    <sectionId>{}</sectionId>
    '''.format(rulename,secID)
    baseconf = "".join(baseconf.split())

    if types == 'source':
        source = '''
        <source>
        <value>{}</value>
        <type>SecurityGroup</type>
        <isValid>true</isValid>
        </source>
        </sources>
        '''.format(sgid)
        baseconf += '''<sources excluded="false">''' + "".join(source.split())
    
    if types == 'destination':
        destination = '''
        <destination>
        <value>{}</value>
        <type>IPSet</type>
        <isValid>true</isValid>
        </destination>
        </destinations>
        '''.format(sgid)
        baseconf += '''<destinations excluded="false">''' + "".join(destination.split())
        
    # After Loop Close out the configuration and push to NSX.
    end = '''
    <direction>inout</direction>
    <packetType>any</packetType>
    </rule>
   
    '''
    baseconf += "".join(end.split())
    baseconf = '''<?xml version="1.0" encoding="UTF-8"?><rule disabled="enabled" logged="true">''' + baseconf
    
    return baseconf
    
# Security Group Methods.
    
def getsg():    
    rheaders = {'Content-Type': 'application/xml'}
    host = nsxhostname + '/api/2.0/services/securitygroup/scope/globalroot-0'
    r = requests.get(host, auth = (nsxusr,nsxpw), verify=False, headers= rheaders)
    try:
        o = xmltodict.parse(r.text)
        result = json.dumps(o) 
        jsons = json.loads(result)
        print(jsons)
    except:
        print("Error Reading Security Group Configuration.")
        
def createsg(name,description,sectagid):
    payload = '''
    <securitygroup>
    <objectId></objectId>
    <objectTypeName></objectTypeName>
    <revision>0</revision>
    <type>
    <typeName></typeName>
    </type>
    <name>{}</name>
	 <description>{}</description>
	 <member>
    <objectId>{}</objectId>
    <objectTypeName>SecurityTag</objectTypeName>
    <revision>0</revision>
    <type>
    <typeName>SecurityTag</typeName>
    </type>
    <clientHandle/>
    <extendedAttributes/>
    <isUniversal>false</isUniversal>
    <universalRevision>0</universalRevision>
    </member>
    </securitygroup>
    '''.format(name,description,sectagid)
    rheaders = {'Content-Type': 'application/xml'}
    host = nsxhostname + '/api/2.0/services/securitygroup/bulk/globalroot-0'
    r = requests.post(host, payload, auth = (nsxusr,nsxpw), verify=False, headers= rheaders)
    if r.status_code == 201:
        print("Security Group Created: " + r.text + " | Sectag Member: " + sectagid)
        return r.text


def main(x):
        
    # Main Program Loop.
    f = open("vms.csv","r")
    data = f.read()
    f.close()
    
    apps = []
    for i in data.split("\n"):
        s = i[:-1].split(",")
        apps.append(s)
    
    length = len(apps) 
    for i in range(1,length-1):
        
        try:
            stname = "ST-" + apps[i][0]
            vmoid = getmoid(apps[i][2])
            description = apps[i][1].replace(" ", "")
            sectagid = getstag(stname,description)
            applytag(sectagid,vmoid)
            print("Tagging Successful | VM: " +  apps[i][2] + " ID: " + vmoid + " | SecTAG: " + stname)
        except:
            print("** Tagging Process Failed | VM (" + apps[i][2] + ") | May not be local to current set vcenter server **")
    
    tags = getallsectags()
    
    # Add in Security Group Cleanup methods here -> Query SG first.
    if x == 1:
        for i in tags:
            tagid, description = gettag(i)
            ampsid = i.split("-")[1]
            ASG = "SG-" + ampsid
            AppSection = "AppID-" + ampsid
            
            createsection(AppSection)
            conf, headers, code = getfwconfig(AppSection)
            secID = secid(conf)
            ETag = headers["ETag"]
            sgID = createsg(ASG,description,tagid)
            
            print("Generating Baseline Policies...")
            # Create Outbound Baseline Application Policy.
            sourceconf = createpolicies(secID,ETag,str(AppSection) + "-OUT",sgID,"source")
            postsection(sourceconf,ETag,secID)
            
            # Retrive ETag update for next Policy Creation.
            conf, headers, code = getfwconfig(AppSection)
            secID = secid(conf)
            ETag = headers["ETag"]
            
            # Apply the Inbound Policy Set.
            destconf = createpolicies(secID,ETag,str(AppSection) + "-IN",sgID,"destination")
            postsection(destconf,ETag,secID)
            
             # Retrive ETag update for moving the section.
            conf, headers, code = getfwconfig(AppSection)
            secID = secid(conf)
            ETag = headers["ETag"]
            
            # move section before the default Policy.
            movesection(AppSection, secID, ETag, conf)
        
    Disconnect(c)
    
if __name__ == "__main__":
    banner = '**Secure System Migration Tool**'
    process = input(banner + "\nType (yes) - to continue or (no) to break: ")
    
    if process == "yes":
        policy = input("Generate Baseline Security Policies? (yes or no): ")
        print()
        if policy == "yes":
            main(1)
        if policy == "no":
            main(0)
        else:
            print("Exiting..")
            sys.exit()   
        
    else:
        print("No or Invalid Input Declared, Exiting...")
        sys.exit()
        
    

        
    
