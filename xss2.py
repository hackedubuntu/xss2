#!/usr/bin/env python
import mechanize
import sys
import argparse
import logging
import requests
import codecs
import random

br = mechanize.Browser()  # initiating the browser

br.set_handle_robots(False)
br.set_handle_refresh(False)

if sys.platform.startswith('win'):
    br.addheaders = [
        ('User-agent',
         'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36')
    ]
elif sys.platform.startswith("darwin"):
    br.addheaders = [
        ('User-agent',
         'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1 Safari/605.1.15')
    ]

payloads = []

parser = argparse.ArgumentParser()
parser.add_argument('-u', action='store', dest='url',
                    help='The URL to analyze')
parser.add_argument('-n', action='store', dest='numberOfPayloads',type=int,
                    help='Number of Payloads from payload.txt')
parser.add_argument('-p', action='store_true', dest='openclose',
                    help='Show Information (just type -p)')
parser.add_argument('-d', action='store_true', dest='dork',
                    help='Scan With Google Dork (just type -d)')
parser.add_argument('-f', action='store', dest='file',
                    help='Select a file. Default is payload.txt')
parser.add_argument('-o', action='store', dest='control_name',
                    help='To describe control name for form')
parser.add_argument('-e', action='store_true', dest='compOn',
                    help='Enable comprehensive scan')
parser.add_argument('-v', action='store_true', dest='verbose',
                    help='Enable verbose logging')
parser.add_argument('-c', action='store', dest='cookies',
                    help='Space separated list of cookies',
                    nargs='+', default=[])
results = parser.parse_args()

file = str(results.file).split(".")

if file[-1].lower() == "txt":
    with open(results.file, "r", encoding="utf8") as pyld:
        payload = pyld.readlines()
        lines = len(payload)
        if (results.numberOfPayloads == None):
            for pay in pyld.readlines():
                payloads.append(pay.strip("\n"))
        elif (int(results.numberOfPayloads) in range(lines)):
            for i in range(int(results.numberOfPayloads)):
                payloads.append(payload[i])
elif results.file == None or file[-1].lower() != "txt":
    with open("payload.txt", "r", encoding="utf8") as pyld:
        payload = pyld.readlines()
        lines = len(payload)
        if (results.numberOfPayloads is None):
            for pay in pyld.readlines():
                payloads.append(pay.strip("\n"))
        elif (int(results.numberOfPayloads) in range(lines)):
            for i in range(int(results.numberOfPayloads)):
                payloads.append(payload[random.randint(0,lines)])

payloads = list(set(payloads))

blacklist = []

dorks = []

with open("sample_google_dorks.txt","r",encoding="utf8") as f:
    for x in f.readlines():
        dorks.append(x.strip("\n"))

with open("not_allowed_extensions.txt", "r", encoding="utf8") as ext:
    e = ext.readlines()
    lines = len(e)
    if lines > 1:
        for pay in e:
            blacklist.append(pay.strip("\n"))
    else:
        blacklist = ['png', 'jpg', 'jpeg', 'mp3', 'mp4', 'avi', 'gif', 'svg','pdf']

xssLinks = []            # TOTAL CROSS SITE SCRIPTING FINDINGS


class color:
    @staticmethod
    def log(lvl, msg):
        logger.log(lvl, msg)


if results.openclose:
    print("""
    XSS2 ==>> A Modified Version of XssPy of Faizan Ahmad

    Modified by @hackedubuntu

    !!! Use with Python3 not in Python2 (Original XssPy was in Python2)

    usage: xss2.py [-h] [-u url] [-n payloadnumber] [-p] [-d] [-f file]
               [-o controlname] [-e] [-v] [-c cookies [cookies ...]]

    optional arguments:
      -h, --help                show this help message and exit
      -u url                    The URL to analyze
      -n payloadnumber          Number of Payloads from payload.txt
      -p                        Show Information (just type -p)
      -d                        Scan With Google Dork (just type -d)
      -f file                   Select a file. Default is payload.txt
      -o controlname            To describe control name for form
      -e                        Enable comprehensive scan
      -v                        Enable verbose logging
      -c cookies [cookies ...]  Space separated list of cookies

    """)



logger = logging.getLogger(__name__)
lh = logging.StreamHandler()  # Handler for the logger
logger.addHandler(lh)
formatter = logging.Formatter('[%(asctime)s] %(message)s', datefmt='%H:%M:%S')
lh.setFormatter(formatter)


logger.setLevel(logging.DEBUG if results.verbose else logging.INFO)


def testPayload2(link, payload):
    for dork in dorks:
        regex = link.find(dork)
        if regex > 0:
            a = regex + len(dork)
            req = requests.get(link[:a] + str(payload))
            print("!!!submitted in testPayload2!!!")
            if payload in req.read():
                color.log(logging.DEBUG, '\n===================[XSS found!]===================')
                report = " ".join(link, payload)
                print(report)
                xssLinks.append(report)
    br.back()


def testPayload(payload, p, link):
    br.form[p] = str.encode(payload)
    br.submit()
    print("!!!submitted!!!")
    if payload in br.response().read():
        color.log(logging.DEBUG, '\n===================[XSS found!]===================')
        report = " ".join(link, p, payload)
        print(report)
        xssLinks.append(report)
    br.back()


def initializeAndFind():

    if not results.url:    # if the url has been passed or not
        color.log(logging.INFO, '[-]Url not provided correctly')
        return []

    firstDomains = []    # list of domains
    allURLS = []
    allURLS.append(str(results.url))    # just one url at the moment
    largeNumberOfUrls = []    # in case one wants to do comprehensive search

    # doing a short traversal if no command line argument is being passed
    color.log(logging.INFO, '[+]Doing a short traversal.')
    for smallurl in allURLS:
    # Test HTTPS/HTTP compatibility. Prefers HTTPS but defaults to
    # HTTP if any errors are encountered
        try:
            test = requests.get(smallurl)
            if (test.status_code == 200):
                url = test.url
        except:
            url = requests.get("http://www." + smallurl)
            url = url.url
        try:
            br.open(url)
            if results.cookies is not None:
                for cookie in results.cookies:
                    color.log(logging.INFO, f'[+]Adding cookie: {cookie}')
                    br.set_cookie(cookie)
            color.log(logging.INFO, '[+]Finding all the links of the website: ' + str(url))
            for link in br.links():        # finding the links of the website
                if smallurl in str(link.absolute_url):
                    firstDomains.append(str(link.absolute_url))
            firstDomains = list(set(firstDomains))
        except:
            pass
        color.log(logging.INFO, '[+]Number of links to test are: ' + str(len(firstDomains)))
        if results.compOn:
            color.log(logging.INFO, '[+]Doing a comprehensive traversal.This may take a while')
            for link in firstDomains:
                try:
                    br.open(link)
                    # going deeper into each link and finding its links
                    for newlink in br.links():
                        if smallurl in str(newlink.absolute_url):
                            largeNumberOfUrls.append(newlink.absolute_url)
                except:
                    pass
            firstDomains = list(set(firstDomains + largeNumberOfUrls))
            
            color.log(logging.INFO, '[+]Total Number of links to test have become: ' + str(len(firstDomains)))
    return firstDomains


def findxss(firstDomains):
    # starting finding XSS
    color.log(logging.INFO, '[+]Started finding XSS')
    if firstDomains:    # if there is atleast one link
        for link in firstDomains:
            blacklisted = False
            d = [link.find(x) for x in blacklist]
            if True in d:
                print("[-]Not a good url to test")
                blacklisted = True
                continue
            if not blacklisted:
                try:
                    if br.open(link):
                        params = br.forms()[0]    # our form
                        br.select_form(nr=0)    # submit the first form
                        for p in params.controls:
                            par = str(p)
                            # submit only those forms which require text
                            if 'TextControl' in par:
                                for payload in payloads:
                                    testPayload(payload,p.name,str(link))
                        for payload in payloads:
                            testPayload2(payload=payload,link=link)
                except KeyboardInterrupt:
                    exit()
                except:
                    pass
        color.log(logging.DEBUG, '[+++]The following links are vulnerable: ')
        for link in xssLinks:        # print all xss findings
            color.log(logging.DEBUG, '\t' + link)
    else:
        color.log(logging.INFO, '\t[-]No link found, exiting')
# calling the function
firstDomains = initializeAndFind()
findxss(firstDomains)