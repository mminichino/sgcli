#!/usr/bin/env python
#
#

import getopt
import getpass
import sys
import os
import re
import requests
import urllib3
import json
import readline
import datetime
import threading
import signal
import queue
import boto3
import botocore
from botocore.config import Config

if sys.version_info < (3, 0):
    from urllib import urlencode
else:
    from urllib.parse import urlencode

def usage():
    print("NetApp StorageGRID CLI")
    print("Usage: " + sys.argv[0] + " [-l] [-v] [-d] [-g] [-f] [-o bucket/object] [-a admin_node_host] [-e end_point] [-n node_search] [-p profile] [-t threads]")
    print("")
    print("-h  Print this message")
    print("-o  Lookup object bucket/object_name")
    print("-a  Hostname or IP address of the admin node")
    print("-l  Prompt for username and password, login and save auth token")
    print("-e  Endpoint for bucket operations")
    print("-p  AWS profile for authentication ($HOME/.aws/credentials")
    print("-f  Format listing output in CSV format")
    print("-n  Limit results by node name")
    print("-g  Display Grid Node metrics")
    print("-t  Threads (32 by default)")
    print("-d  Debug")

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

def signal_handler(signal,frame):

    print("")
    print("Interrupt caught, exiting.")
    sys.exit(0)

class parse_args:

    def __init__(self):

        self.arglist = []
        self.objectPath = None
        self.adminNode = None
        self.awsProfile = None
        self.searchNode = None
        self.endPoint = None
        self.verboseFlag = False
        self.loginFlag = False
        self.formatFlag = False
        self.debugFlag = False
        self.gridMetrics = False
        self.argCount = 0
        self.threadCount = 32

    def parse(self):
        options, remainder = getopt.getopt(sys.argv[1:], 'gdfhvlo:a:p:n:e:t:', self.arglist)

        self.argCount = len(options)
        for opt, arg in options:
            if opt in ('-o', '--object'):
                self.objectPath = arg
            elif opt in ('-a', '--adminnode'):
                self.adminNode = arg
            elif opt in ('-p', '--profile'):
                self.awsProfile = arg
            elif opt in ('-n', '--node'):
                self.searchNode = arg
            elif opt in ('-e', '--endpoint'):
                self.endPoint = arg
            elif opt in ('-t', '--threads'):
                try:
                    self.threadCount = int(arg)
                except ValueError as e:
                    print("Threads must be a number.")
                    sys.exit(1)
            elif opt in ('-v', '--verbose'):
                self.verboseFlag = True
            elif opt in ('-l', '--login'):
                self.loginFlag = True
            elif opt in ('-f', '--format'):
                self.formatFlag = True
            elif opt in ('-d', '--debug'):
                self.debugFlag = True
            elif opt in ('-g', '--gridmetrics'):
                self.gridMetrics = True
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
        self.debugFlag = self.argset.debugFlag
        self.formatFlag = self.argset.formatFlag
        self.gridMetrics = self.argset.gridMetrics
        self.searchNode = self.argset.searchNode
        self.threadCount = self.argset.threadCount
        self.authToken = None
        self.homeDir = os.environ.get('HOME')
        self.authPath = self.homeDir + '/.storagegrid'
        self.authFile = self.authPath + '/auth'
        self.awsProfile = self.argset.awsProfile
        self.endPoint = self.argset.endPoint

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
                    lines = []
                    if os.path.isfile(self.authFile):
                        with open(self.authFile, "r") as authFile:
                            lines = authFile.readlines()
                        authFile.close()
                    with open(self.authFile, 'w') as authFile:
                        auth_entry = self.adminNode + ':' + self.authToken + '\n'
                        authFile.write(auth_entry)
                        for line in lines:
                            if not re.search(self.adminNode, line):
                                authFile.write(line)
                    authFile.close()
                except OSError as e:
                    print("Could not write auth file: %s" % str(e))
                    sys.exit(1)

    def readToken(self):

        admin_node = self.adminNode
        with open(self.authFile, "r") as authFile:
            for line in authFile:
                line = line.rstrip("\n")
                split_line = line.split(':', 1)
                if split_line[0] == admin_node:
                    self.authToken = split_line[1]
                    self.adminNode = split_line[0]

        authFile.close()
        if not self.authToken:
            print("Auth token not found. Please login first.")
            sys.exit(1)

class storagegrid:

    def __init__(self, auth):

        self.token = auth
        self.authToken = self.token.authToken
        self.adminName = self.token.adminNode
        self.verboseFlag = self.token.verboseFlag
        self.debugFlag = self.token.debugFlag
        self.gridMetrics = self.token.gridMetrics
        self.formatFlag = self.token.formatFlag
        self.searchNode = self.token.searchNode
        self.endPoint = self.token.endPoint
        self.threadCount = self.token.threadCount
        self.awsProfile = self.token.awsProfile
        self.bucketObjects = []
        self.getGridTopology()
        self.awsConfig = Config(
            retries={
                'max_attempts': 10,
                'mode': 'standard'
            }
        )

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
        object_data = json.loads(response.text)

        return object_data

    def getGridTopology(self):

        headers = {}

        headers.update({ 'accept' : 'application/json' })
        headers.update({ 'Authorization' : 'Bearer ' + self.authToken })

        url = 'https://' + self.adminName + '/api/v3/grid/health/topology?depth=node'

        response = requests.get(url, headers=headers, verify=False)
        self.grid_data = json.loads(response.text)

        if self.debugFlag:
            print(json.dumps(self.grid_data, indent=2))

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

    def objectList(self, lookup, node=None):

        objlocation = []
        objsite = []
        objsegtype = []
        objname = ''
        objsize = ''
        objrep = ''
        objbucket = ''
        objtime = None
        objfmttime = ''
        object_data = self.objectLookup(lookup)

        if 'message' in object_data:
            print("Error: %s" % object_data['message']['text'])
            sys.exit(1)

        if self.verboseFlag:
            print(json.dumps(object_data, indent=2))
        else:
            if 'data' in object_data:
                objname = object_data['data']['name']
                objsize = object_data['data']['objectSizeBytes']
                objbucket = object_data['data']['container']
                objmodtime = object_data['data']['modifiedTime']
                objtime = datetime.datetime.strptime(objmodtime, '%Y-%m-%dT%H:%M:%S.%fZ')
                objfmttime = objtime.strftime("%m/%d/%y %I:%M%p")
                for x in range(len(object_data['data']['locations'])):
                    if object_data['data']['locations'][x]['type'] == "erasureCoded":
                        objrep = "EC"
                        for y in range(len(object_data['data']['locations'][x]['fragments'])):
                            objlocation.append(self.grid_node_list[object_data['data']['locations'][x]['fragments'][y]['nodeId']]['name'])
                            objsite.append(self.grid_node_list[object_data['data']['locations'][x]['fragments'][y]['nodeId']]['site'])
                            objsegtype.append(object_data['data']['locations'][x]['fragments'][y]['type'])
                    if object_data['data']['locations'][x]['type'] == "replicated":
                        objrep = "Replicated"
                        objlocation.append(self.grid_node_list[object_data['data']['locations'][x]['nodeId']]['name'])
                        objsite.append(self.grid_node_list[object_data['data']['locations'][x]['nodeId']]['site'])
                        objsegtype.append("copy")

            if self.searchNode:
                if self.searchNode not in objlocation:
                    return

            if self.formatFlag:
                print("%s,%s,%s,%s,%s," % (objbucket, objname, objsize, objtime.timestamp(), objrep), end='')
                for x in range(len(objlocation)):
                    if x == len(objlocation) - 1:
                        print("%s,%s,%s" % (objsegtype[x], objsite[x], objlocation[x]))
                    else:
                        print("%s,%s,%s," % (objsegtype[x], objsite[x], objlocation[x]), end='')
            else:
                print("%s/%s %s %s %s " % (objbucket, objname, formatSize(objsize), objfmttime, objrep), end='')
                for x in range(len(objlocation)):
                    print("%s > [%s]/%s " % (objsegtype[x], objsite[x], objlocation[x]), end='')
                print("")

    def list_object_thread(self, obj_pattern, bucket_name, q):

        try:
            if self.awsProfile:
                thread_s3session = boto3.Session(profile_name=self.awsProfile,)
            else:
                thread_s3session = boto3.Session(profile_name="default",)
        except botocore.exceptions.ProfileNotFound as e:
            print("Error: %s" % str(e))
            sys.exit(1)

        thread_s3 = thread_s3session.client('s3', endpoint_url=self.endPoint, verify=False, config=self.awsConfig)

        try:
            bucket_region = thread_s3.get_bucket_location(Bucket=bucket_name)
            self.bucketRegion = bucket_region
        except RecursionError as e:
            print("Error: connection to %s failed." % self.endPoint)
            sys.exit(1)

        try:
            kwargs = {'Bucket': bucket_name}
            while True:
                block = thread_s3.list_objects_v2(**kwargs)
                for obj_entry in block['Contents']:
                    if re.search(obj_pattern, obj_entry['Key']):
                        q.put(obj_entry)
                if block['IsTruncated']:
                    kwargs['ContinuationToken'] = block['NextContinuationToken']
                else:
                    break
        except (botocore.exceptions.ClientError, botocore.exceptions.EndpointConnectionError) as e:
            print("Error: can not connect to bucket %s: %s" % (bucket_name,str(e)))
            sys.exit(1)

        q.put(None)
        return

    def listBucket(self, lookup):

        bucket_name, obj_pattern = lookup.split('/')
        obj_pattern = re.sub('\*', '.+', obj_pattern)
        obj_pattern = '^' + obj_pattern + '$'
        thread_set = []
        thread_stat = []
        threads = self.threadCount
        q = queue.Queue()

        for i in range(threads):
            thread_stat.append(0)
            thread_set.append(0)

        list_thread = threading.Thread(target=self.list_object_thread, args=(obj_pattern, bucket_name, q,))
        list_thread.start()

        for obj_entry in iter(q.get, None):

            if not obj_entry:
                break

            thread_found = 0
            while True:
                for x in range(threads):
                    if thread_stat[x] == 0:
                        thread_found = 1
                        thread_stat[x] = 1
                        thread_set[x] = threading.Thread(target=self.objectList,
                                                         args=(bucket_name + '/' + obj_entry['Key'],))
                        thread_set[x].start()
                        break
                if thread_found == 1:
                    break
                else:
                    for y in range(threads):
                        if thread_stat[y] == 1:
                            if not thread_set[y].is_alive():
                                thread_stat[y] = 0

        list_thread.join()

        for y in range(threads):
            if thread_stat[y] == 1:
                thread_set[y].join()

    def gridStatus(self):

        headers = {}

        headers.update({ 'accept' : 'application/json' })
        headers.update({ 'Authorization' : 'Bearer ' + self.authToken })

        url = 'https://' + self.adminName + '/api/v3/grid/metric-query?query=storagegrid_storage_utilization_total_space_bytes&timeout=120s'

        response = requests.get(url, headers=headers, verify=False)
        self.grid_total_space = json.loads(response.text)

        url = 'https://' + self.adminName + '/api/v3/grid/metric-query?query=storagegrid_storage_utilization_usable_space_bytes&timeout=120s'

        response = requests.get(url, headers=headers, verify=False)
        self.grid_usable_space = json.loads(response.text)

        if self.debugFlag:
            print(json.dumps(self.grid_total_space, indent=2))
            print(json.dumps(self.grid_usable_space, indent=2))

        self.getGridTopology()

        print("%s %s %s %s" % (str("Node").ljust(20),
                                 str("Total Space").ljust(14),
                                 str("Free Space").ljust(14),
                                 str("Used Percent")))

        for x in range(len(self.grid_total_space['data']['result'])):
            node_site = self.grid_node_list[self.grid_total_space['data']['result'][x]['metric']['node_id']]['site']
            node_name = self.grid_node_list[self.grid_total_space['data']['result'][x]['metric']['node_id']]['name']
            node_total = self.grid_total_space['data']['result'][x]['value'][1]
            node_usable = self.grid_usable_space['data']['result'][x]['value'][1]
            node_pct_full = int(node_usable) / int(node_total)
            node_pct_full = round(100 - (node_pct_full * 100))
            print_name = node_site + '/' + node_name

            print("%s %s %s %d%%" % (str(print_name).ljust(20),
                                     str(formatSize(int(node_total))).ljust(14),
                                     str(formatSize(int(node_usable))).ljust(14),
                                     node_pct_full))

def main():

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    signal.signal(signal.SIGINT, signal_handler)

    runargs = parse_args()
    runargs.parse()

    myToken = auth_token(runargs)

    if runargs.loginFlag:
        myToken.genToken()
    else:
        myToken.readToken()

    myGrid = storagegrid(myToken)

    if runargs.gridMetrics:
        myGrid.gridStatus()
        sys.exit(0)

    if runargs.endPoint and runargs.objectPath:
        myGrid.listBucket(runargs.objectPath)
    elif runargs.objectPath:
        myGrid.objectList(runargs.objectPath)

if __name__ == '__main__':

    try:
        main()
    except SystemExit as e:
        if e.code == 0:
            os._exit(0)
        else:
            os._exit(e.code)