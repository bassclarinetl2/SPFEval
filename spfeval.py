#!/usr/bin/python
# Copyright 2015 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This is not an official Google product.
"""spfeval.py:
Pulls and explictitly parses the SPF record, (including recursions due to
includes) of a given domain as well as checking if a given domain is in said SPF
record.\n"""

__author__ = 'Will Heid <bassclarinetl2@gmail.com>'
__copyright__ = 'Copyright 2015, Google, Inc.'
__license__ = 'Apache 2'
__version__ = '1.0.0'
import sys
import dns.resolver  # dnspython required
import netaddr


masterlist = []  # list to hold our discovered ip addresses


def evaltxtrec(domain):  # function to evaluate TXT records
  # get the txt records for the domain given on the command line at execution
  txtrecords = dns.resolver.query(domain, 'TXT')

  # filter out other TXT records if present
  for rdata in txtrecords:
    if 'v=spf1' in rdata.to_text():
      spfrecord = rdata.to_text()

    # remove the spf ver text and the leading double quote
    spfrecord = spfrecord.lstrip("\"v=spf1 ")
    # remove the indicator from the end of the record and the double quote
    spfrecord = spfrecord[0:-6]

    # breakdown the txt record into individual parts based on whitespace
    spfentrylist = spfrecord.split(' ')

    # Iterate through each SPF entry
    for item in spfentrylist:
      # IPv4 Entries
      if 'ip4' in item:  # find actual ipv4 addresses/cidr range
        itemstore = item.lstrip('ip4:')
        # find and validate single ipv4 address
        if '/' not in item:
          isvalidip4 = netaddr.valid_ipv4(itemstore)
          if isvalidip4 is True:
            # assuming ip valid, store in masterlist
            masterlist.append(itemstore)
        else:
          masterlist.append(itemstore)  # store cidr range in masterlist

      # IPv6 Entries
      elif 'ip6' in item:  # find actual ipv6 addresses/cidr range
        itemstore = item.lstrip('ip6:')
        # find and validate single ipv6 address
        if '/' not in item:
          isvalidip6 = netaddr.valid_ip6(itemstore)
          if isvalidip6 is True:
            # assuming ip valid, store in masterlist
            masterlist.append(itemstore)
        else:
          masterlist.append(itemstore)  # store cidr in masterlist
      # A/AAAA records
      elif 'a' in item:  # according to RFC 7208 'a' also includes AAAA records
        if 'a:' in item:  # find domain of 'A' record
          itemstore = item.lstrip('a:')

          # Only record A record ip if one is returned
          if evalarec(itemstore) is not None:
            masterlist.append(evalarec(itemstore))
          # Only record 'AAAA' IP if one is returned
          elif evalaaaarec(itemstore) is not None:
            masterlist.append(evalaaaarec(itemstore))
        else:
          # Per RFC 7208 single a evaluates to a record of domain with the txt
          # record
          itemstore = item.lstrip('a')
          if evalarec(domain) is not None:
            masterlist.append(evalarec(domain))

      # MX Records -
      elif 'mx' in item:
        if 'mx:' in item:
          itemstore = item.lstrip('mx:')
          evalmxrec(itemstore)
        # mx as mechanism without domain implies get mx record of domain for
        # which the spf record exists
        else:
          evalmxrec(domain)

      # PTR
      # RFC 7208 specifies that PTR records should not be used therefore not
      # evaluated
      elif 'ptr:' in item:
        print ('The ptr mechanism SHOULD NOT be published according to RFC '
               '7208.  Please concider removing it.')
      # Exists
      elif 'exists' in item:  # exists not evaluated as occurence is rare
        print 'The exists mechanism is not supported by this tool.'

      # Include - get other domain and iterate
      elif 'include:' in item:
        itemstore = item.lstrip('include:')
      #	print 'iteration %s' %itemstore
        evaltxtrec(itemstore)


def isinsubnet(x):  # use netaddr to evaluate if given ip in subnet
  for item in masterlist:

    # check if given ip is in the masterlist
    iprange = netaddr.all_matching_cidrs(x, [item])

    if iprange is not False:  # if ip is in masterlist return yes
      return 'Yes'
  if iprange is False:
    return 'No'  # if ip is not in masterlist return no.


def evalarec(x):  # pull a records and check for validity
  # print 'evalaquery: %s' %x

  try:  # attempt to pull A records for given domain
    arecords = dns.resolver.query(x, 'A')
  except dns.resolver.NoAnswer:  # handle error if no record
    arecords = ''
    print 'no A records for %s' % x
  for rdata in arecords:
    ipaddr = rdata.to_text()  # convert query to text for validation

    isvalidipv4 = netaddr.valid_ipv4(ipaddr)  # validate address
    if isvalidipv4 is True:
      return ipaddr  # return ipv4 address of A record
    else:
      pass


def evalaaaarec(x):  # pull aaaa rec and check for validity
  try:  # attempt to lookup AAAA record for given domain
    aaaarecords = dns.resolver.query(x, 'AAAA')
  except dns.resolver.NoAnswer:  # handle error if no record
    aaaarecords = ''
    print 'no AAAA records for %s' % x
  for rdata in aaaarecords:
    ipaddr = rdata.to_text()  # convert query to text for validation
    isvalidipv6 = netaddr.valid_ipv6(ipaddr)
    if isvalidipv6 is True:  # validate address
      return ipaddr  # return ipv6 address of AAAA record
    else:
      pass


def evalmxrec(x):  # pull mx records
  try:  # attempt to pull MX records
    mxrecords = dns.resolver.query(x, 'MX')
  except dns.resolver.NoAnswer:  # handle error if no record
    mxrecords = ''
  for rdata in mxrecords:
    domainref = rdata.to_text()  # convert query to text for validation
    # remove superfluous text from beginning of query answer
    domainref = domainref.lstrip(
        '<bound method MX.to_text of <DNS IN MX rdata: ')
    # shift starting index one character to the right
    domainrefindex = domainref.index(' ') + 1
    # redefine string to remove MX priority
    domainref = domainref[domainrefindex:len(domainref)]
    domainref = domainref.rstrip('.')  # remove '.' from end of string

# check for both ipv4 (A) and ipv6 (AAAA) addresses
    # only add ip to master list if one is returned
    if evalarec(domainref) is not None:
      masterlist.append(evalarec(domainref))
    # only add ip to master list if one is returned
    if evalaaaarec(domainref) is not None:
      masterlist.append(evalaaaarec(domainref))
## primary code##
evaltxtrec(sys.argv[1])  # get and evaluate list of ip addresses in SPF record
# check if IP address given is in list of IP addresses
subnetyn = isinsubnet(sys.argv[2])
# Provide feedback on whether given IP address is in the record
if subnetyn == 'Yes':
  print 'IP %s is in the SPF record.' % sys.argv[2]
elif subnetyn == 'No':
  print 'IP %s is not in the SPF record.' % sys.argv[2]

