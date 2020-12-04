#!/usr/bin/env python
#
#

import getopt
import getpass
import sys
import os
import requests
import urllib3
import json
import readline

if sys.version_info < (3, 0):
    from urllib import urlencode
else:
    from urllib.parse import urlencode

def usage():
    print("NetApp StorageGRID CLI")
    print("Usage: " + sys.argv[0] + " [-l] [-v] [-o bucket/object] [-a admin_node_host]")
    print("")
    print("-h  Print this message")
    print("-o  Lookup object bucket/object_name")
    print("-a  Hostname or IP address of the admin node")
    print("-l  Prompt for username and password, login and save auth token")

def myinput(prompt, prefill):

    def hook():
        readline.insert_text(prefill)
        readline.redisplay()
    readline.set_pre_input_hook(hook)
    result = input(prompt)
    readline.set_pre_input_hook()
    return result

def formatSize(bytes):

    if bytes >= 1125899906842624:
        unit = "PiB"
        divisor = 1125899906842624
    elif bytes >= 1099511627776:
        unit = "TiB"
        divisor = 1099511627776
    elif bytes >= 1073741824:
        unit = "GiB"
        divisor = 1073741824
    elif bytes >= 1048576:
        unit = "MiB"
        divisor = 1048576
    elif bytes >= 1024:
        unit = "KiB"
        divisor = 1024
    else:
        unit = "bytes"
        divisor = 1

    quantity = bytes / divisor
    quantity = round(quantity, 1)
    print_str = str(quantity) + ' ' + str(unit)

    return print_str

class parse_args:

    def __init__(self):

        self.arglist = []
        self.objectPath = None
        self.adminNode = None
        self.verboseFlag = False
        self.loginFlag = False
        self.formatFlag = False
        self.argCount = 0

    def parse(self):
        options, remainder = getopt.getopt(sys.argv[1:], 'fhvlo:a:', self.arglist)

        self.argCount = len(options)
        for opt, arg in options:
            if opt in ('-o', '--object'):
                self.objectPath = arg
            elif opt in ('-a', '--adminnode'):
                self.adminNode = arg
            elif opt in ('-v', '--verbose'):
                self.verboseFlag = True
            elif opt in ('-l', '--login'):
                self.loginFlag = True
            elif opt in ('-f', '--format'):
                self.formatFlag = True
            elif opt in ('-h', '--help'):
                usage()
                sys.exit(0)
            else:
                usage()
                sys.exit(1)

class auth_token:

    def __init__(self, argclass):

        self.argset = argclass
        self.adminNode = self.argset.adminNode
        self.verboseFlag = self.argset.verboseFlag
        self.formatFlag = self.argset.formatFlag
        self.authToken = None
        self.homeDir = os.environ.get('HOME')
        self.authPath = self.homeDir + '/.storagegrid'
        self.authFile = self.authPath + '/auth'

    def genToken(self):

        username = myinput("Username: ", "root")
        username = username.rstrip("\n")

        password = getpass.getpass()
        password = password.rstrip("\n")

        post_data = {}
        headers = {'accept': 'application/json', 'Content-Type': 'application/json'}
        url = 'https://' + self.adminNode + '/api/v3/authorize'
        post_data.update({ 'username' : username })
        post_data.update({ 'password' : password })
        post_data.update({'cookie': 'false'})
        post_data.update({'csrfToken': 'false'})
        json_post = json.dumps(post_data)

        response = requests.post(url, data=json_post, headers=headers, verify=False)
        try:
            json_data = json.loads(response.text)
        except ValueError:
            print("Error: API call failed")
            print(response.text)
            sys.exit(1)

        for key in json_data:
            if key == "message":
                print("Login failed: %s" % json_data[key]['text'])
                sys.exit(1)
            if key == "data":
                self.authToken = json_data[key]
                if self.verboseFlag:
                    print("Access Token: %s" % json_data[key])
                if (not os.path.exists(self.authPath)):
                    try:
                        os.mkdir(self.authPath)
                    except OSError as e:
                        print("Error: can not create auth directory: %s" % str(e))
                        sys.exit(1)
                try:
                    with open(self.authFile, 'w') as authFile:
                        authFile.write(self.authToken)
                    authFile.close()
                except OSError as e:
                    print("Could not write auth file: %s" % str(e))
                    sys.exit(1)

    def readToken(self):

        authFile = open(self.authFile, "r")

        self.authToken = authFile.readline()
        self.authToken = self.authToken.rstrip("\n")

        authFile.close()

class storagegrid:

    def __init__(self, auth):

        self.token = auth
        self.authToken = self.token.authToken
        self.adminName = self.token.adminNode
        self.verboseFlag = self.token.verboseFlag
        self.formatFlag = self.token.formatFlag

    def objectLookup(self, lookup):

        headers = {}
        post_data = {}

        headers.update({ 'accept' : 'application/json' })
        headers.update({ 'Content-Type' : 'application/json' })
        headers.update({ 'Authorization' : 'Bearer ' + self.authToken })

        url = 'https://' + self.adminName + '/api/v3/grid/object-metadata'

        post_data.update({ 'maxSegments' : '100' })
        post_data.update({ 'consistency' : 'read-after-new-write' })
        post_data.update({ 'objectId': lookup })
        json_post = json.dumps(post_data)

        response = requests.post(url, data=json_post, headers=headers, verify=False)
        self.object_data = json.loads(response.text)

    def getGridTopology(self):

        headers = {}

        headers.update({ 'accept' : 'application/json' })
        headers.update({ 'Authorization' : 'Bearer ' + self.authToken })

        url = 'https://' + self.adminName + '/api/v3/grid/health/topology?depth=node'

        response = requests.get(url, headers=headers, verify=False)
        self.grid_data = json.loads(response.text)

        node_list = {}
        site_name = ''
        grid_name = ''
        for key in self.grid_data:
            if key == "status":
                if self.grid_data[key] != "success":
                    print("Error: Can not get grid topology: %s" % self.grid_data['message']['text'])
                    if self.verboseFlag:
                        print(json.dumps(self.grid_data, indent=2))
                    sys.exit(1)
            if key == "data":
                for subkey in self.grid_data[key]:
                    if subkey == "name":
                        grid_name = self.grid_data[key][subkey]
                    if subkey == "children":
                        for x in range(len(self.grid_data[key][subkey])):
                            for childkey in self.grid_data[key][subkey][x]:
                                if childkey == "name":
                                    site_name = self.grid_data[key][subkey][x][childkey]
                                if childkey == "children":
                                    for y in range(len(self.grid_data[key][subkey][x][childkey])):
                                        node_entry = { self.grid_data[key][subkey][x][childkey][y]['id'] : {} }
                                        node_entry[self.grid_data[key][subkey][x][childkey][y]['id']].update({ 'name' : self.grid_data[key][subkey][x][childkey][y]['name'] })
                                        node_entry[self.grid_data[key][subkey][x][childkey][y]['id']].update({ 'site' : site_name })
                                        node_list.update(node_entry)

        self.grid_node_list = node_list
        self.grid_name = grid_name

    def objectList(self, lookup):

        self.objectLookup(lookup)
        self.getGridTopology()

        objlocation = []
        objsegtype = []
        objname = ''
        objsize = ''
        objrep = ''
        objbucket = ''

        if self.verboseFlag:
            print(json.dumps(self.object_data, indent=2))
        else:
            for key in self.object_data:
                if key == "data":
                    for subkey in self.object_data[key]:
                        if subkey == "name":
                            objname = self.object_data[key][subkey]
                        if subkey == "objectSizeBytes":
                            objsize = formatSize(self.object_data[key][subkey])
                        if subkey == "container":
                            objbucket = self.object_data[key][subkey]
                        if subkey == "locations":
                            for x in range(len(self.object_data[key][subkey])):
                                if self.object_data[key][subkey][x]['type'] == "erasureCoded":
                                    objrep = "EC"
                                    for y in range(len(self.object_data[key][subkey][x]['fragments'])):
                                        objlocation.append(self.grid_node_list[self.object_data[key][subkey][x]['fragments'][y]['nodeId']]['name'])
                                        objsegtype.append(self.object_data[key][subkey][x]['fragments'][y]['type'])
                                if self.object_data[key][subkey][x]['type'] == "replicated":
                                    objrep = "Copy"
                                    objlocation.append(self.grid_node_list[self.object_data[key][subkey][x]['nodeId']]['name'])
                                    objsegtype.append("copy")

            if self.formatFlag:
                print("%s,%s,%s,%s," % (objbucket, objname, objsize, objrep), end='')
                for x in range(len(objlocation)):
                    if x == len(objlocation) - 1:
                        print("%s,%s" % (objsegtype[x], objlocation[x]))
                    else:
                        print("%s,%s," % (objsegtype[x], objlocation[x]), end='')
            else:
                print("[%s]/%s %s %s " % (objbucket, objname, objsize, objrep), end='')
                for x in range(len(objlocation)):
                    print("%s => %s " % (objsegtype[x], objlocation[x]), end='')
                print("")

def main():

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    runargs = parse_args()
    runargs.parse()

    myToken = auth_token(runargs)

    if runargs.loginFlag:
        myToken.genToken()
    else:
        myToken.readToken()

    myGrid = storagegrid(myToken)

    if runargs.objectPath:
        myGrid.objectList(runargs.objectPath)

if __name__ == '__main__':

    try:
        main()
    except SystemExit as e:
        if e.code == 0:
            os._exit(0)
        else:
            os._exit(e.code)