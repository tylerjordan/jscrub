__copyright__ = "Copyright 2018 Tyler Jordan"
__version__ = "0.1.1"
__email__ = "tjordan@juniper.net"

import datetime
import platform
import os, sys
import netaddr
import argparse

from utility import *

from prettytable import PrettyTable
from pprint import pprint
from os import path
from operator import itemgetter
from netaddr import IPAddress, IPNetwork
from sys import stdout

# Paths
mypwd = ''
myuser = ''
port = 22
include_list = []
exclude_list = []

def detect_env():
    """ Purpose: Detect OS and create appropriate path variables
    :param: None
    :return: None
    """
    """
    global iplist_dir

    dir_path = os.path.dirname(os.path.abspath(__file__))
    if platform.system().lower() == "windows":
        print "Environment Windows!"
        iplist_dir = os.path.join(dir_path, "data\\iplists")

    else:
        print "Environment Linux/MAC!"
        iplist_dir = os.path.join(dir_path, "data/iplists")

    # Statically defined files and logs
    template_file = os.path.join(dir_path, template_dir, "Template.conf")
    """

# This method populates two list dictionaries with the ipmap contents
def load_ipmap():
    global exclude_list
    global include_list
    if ipmap_file:
        line_list = txt_to_list(ipmap_file)
        print "IPMAP FILE: {0}".format(ipmap_file)
        # Get include info
        on_include = False
        # Loop over ipmap file and create an exclude list and include listdict
        for line in line_list:
            # Check if there is text on this line...
            if line:
                # Check for "INCLUDE" text...
                if "INCLUDE" in line:
                    on_include = True
                # If we are in INCLUDE section...
                elif on_include:
                    src_dest = line.split(",")
                    src_ip = src_dest[0].split("/")
                    dest_ip = src_dest[1].split("/")
                    dest_split = src_dest[1].split("/")
                    include_list.append({"src_ip": src_ip[0], "dest_ip": dest_ip[0], "mask": dest_split[1]})
                # If we are in EXCLUDE section...
                else:
                    if not "EXCLUDE" in line:
                        exclude_list.append(line)
    else:
        print "IPMAP FILE: NOT DEFINED"
    # Print exclude list
    print "Exclude List: {0}".format(exclude_list)
    # Print include list
    print "Include List: {0}".format(include_list)


# Function for scrubbing a file
# How this scrub function works:
# 1. Find all ipv4 terms in a line of text
# 2. Search for existing replacements, if they don't exist, create new ones
# 3. Create substrings of the remaining text
def scrub_file(input_file):
    # Regexs
    ipv4_regex = re.compile("([1][0-9][0-9]|[2][5][0-5]|[2][0-4][0-9]|[1][0-9][0-9]|[0-9][0-9]|[0-9])"
                                "\.([1][0-9][0-9]|[2][5][0-5]|[2][0-4][0-9]|[1][0-9][0-9]|[0-9][0-9]|[0-9])"
                                "\.([1][0-9][0-9]|[2][5][0-5]|[2][0-4][0-9]|[1][0-9][0-9]|[0-9][0-9]|[0-9])"
                                "\.([1][0-9][0-9]|[2][5][0-5]|[2][0-4][0-9]|[1][0-9][0-9]|[0-9][0-9]|[0-9])"
                                "(\/([8]|[9]|1[0-9]|2[0-9]|3[0-1]))?")
    ipv6_regex = re.compile("(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:)"
                            "{1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:)"
                            "{1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4})"
                            "{1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:"
                            "((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4})"
                            "{0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9])"
                            "{0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:)"
                            "{1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9])"
                            "{0,1}[0-9]))")
    regexs = [ipv4_regex, ipv6_regex]

    # Load targeted scrub file into a list
    line_list = txt_to_list(input_file)
    # Check for content using provided regexs
    if line_list:
        for line in line_list:
            #print "Beginning Line: {0}\n".format(line)
            for regex in regexs:
                new_line = ""
                #print "Start Line: {0}".format(line)
                # Get the start and end indexes for ipv4 addresses
                indicies = [[m.start(),m.end()] for m in regex.finditer(line)]
                # Create default start and end indicies
                frag_start = 0
                frag_end = len(line)
                # Loop over indicies
                for ipindex in indicies:
                    # This adds the line segment before the ip
                    new_line += line[frag_start:ipindex[0]]
                    # This adds the replacement ip
                    get_replacement_ip(str(line[ipindex[0]:ipindex[1]]))
                    new_line += "100.100.1.1"
                    # Update the frag_start to last index
                    frag_start = ipindex[1]
                # Check if we still have some text after the last ip. If no matches were made this simply add the entire
                # line unchanged
                if frag_start < frag_end:
                    new_line += line[frag_start:frag_end]
                # Change line to the "modified" line
                line = new_line
                #print "Modified Line: {0}\n".format(line)

# Checks the provided IP against an optional list of IPs or creates a random one
def get_replacement_ip(raw_ip):
    masked = False
    targ_mask = "32"
    targ_ip = raw_ip

    # Determine if this is a masked IP, assume /32 if no mask
    print "-"*60
    if ":" in raw_ip:
        targ_mask = "128"
        print "Target IP: {0} assigned Mask: {1}.".format(targ_ip, targ_mask)
        return "fe80::feeb:daed"
    elif "/" in raw_ip:
        masked = True
        targ_mask = raw_ip.split("/")[1]
        targ_ip = raw_ip.split("/")[0]
        print "Target IP: {0} with Mask: {1}".format(targ_ip, targ_mask)
    else:
        print "Target IP: {0} assigned Mask: {1}.".format(targ_ip, targ_mask)

    # Matching procedure
    if not is_excluded(targ_ip):
        mydict = is_included(targ_ip)
        # This executes if is_included returns a match
        if mydict:
            print "Match IP: {0} | Dest IP: {1} | Mask: {2}".format(mydict['src_ip'], mydict['dest_ip'], mydict['mask'])
            # This succeeds if the match was exact, meaning an exact IP match, no changes in ipmap needed, return the
            # exact match.
            if 'ip' in mydict['match'] and 'net' in mydict['match']:
                print "Analysis: IP and Network Match!\n"
                if masked:
                    return mydict['dest_ip'] + "/" + mydict['mask']
                else:
                    return mydict['dest_ip']
            # This succeeds if the match was exact, but a corresponding network does not exist, create it.
            elif 'ip' in mydict['match']:
                print "Analysis: IP ONLY Match!\n"
                # Check if the mask is different and if the provided mask is reliable
                if targ_mask != mydict['mask'] and masked:
                    # Change entry to reflect provided mask
                    mydict = change_dict(include_list, 'src_ip', mydict['src_ip'], 'mask', targ_mask)
            # This succeeds if the network was matched, only need to create an entry for the exact IP
            elif 'net' in mydict['match']:
                print "Analysis: Network ONLY Match!\n"
            # This executes if the match was not exact, meaning, we need an entry for this IP
            else:
                print "Analysis: ERROR - Should not execute, this value is invalid: {0}\n".format(mydict['match'])
        # This executes if is_included doesn't return a match, an unmatched entry!
        else:
            print "Analysis: No IPs Matched: {0}\n".format(targ_ip)
    else:
        print "Analysis: Matched an Excluded IP or Network: {0}\n".format(targ_ip)

# Modify a term in the defined dictionary within a list of dictionaries
# The match term/val are to identify the correct dictionary only
# The chg term/val are the key/value to change in the identified dictionary
def change_dict(list_dict, match_term, match_val, chg_term, chg_val):
    for mydict in list_dict:
        for k, v in mydict.iteritems():
            if k == match_term and v == match_val:
                print "Matched this dictionary: {0}".format(mydict)
                mydict.update({chg_term: chg_val})
    return list_dict

# Check for IP in the list
def is_excluded(ip):
    # Loop over exclude IPs
    matched = False
    for exc_ip in exclude_list:
        # If a match on the IP is made, this IP will be skipped
        if IPAddress(ip) in IPNetwork(exc_ip):
            matched = True
            #print "MATCHED: {0} with: {1}".format(ip, exc_ip)
    return matched

# Check included, if false, create new entry , if true, return the dictionary match
def is_included(targ_ip):
    # Loop over include IPs
    mymatch = {}
    match_list = []
    for inc_ip in include_list:
        # If a match on the IP is made, we will finish scanning options to see if a more closer match exists
        targ_net = IPNetwork(targ_ip + "/" + inc_ip['mask']).network
        dest_ip = IPAddress(inc_ip['src_ip'])
        # This matches the IP. If this match is made immediately return it, a network match should preceed an IP match
        # assuming the ipmap file is sorted according to mask (least specific to most specific).
        if targ_ip == inc_ip['src_ip']:
            match_list.append('ip')
            inc_ip['match'] = match_list
            return inc_ip
        # This matches the network. If this match is made continue scanning in case an IP match exists
        if targ_net == dest_ip:
            match_list.append('net')
            inc_ip['match'] = match_list
            mymatch = inc_ip
    return mymatch

# START OF SCRIPT #
if __name__ == '__main__':
    try:
        detect_env()
    except Exception as err:
        print "Problem detecting OS type..."
        quit()
    # Argument Parser
    # User will either provide an input_file or a folder structure to walk through and scrub all files.
    parser = argparse.ArgumentParser()
    parser.add_argument("input_file", type=str, help="input ASCII-formatted filename")
    parser.add_argument("-i", "--ipmap_file", type=str, help="ipmap support files")
    args = parser.parse_args()

    # Input arguments
    input_file = args.input_file
    ipmap_file = args.ipmap_file

    # IPMAP List Dictionary
    # - IPs will have IP address and mask
    # - Sorted least specific to most specific IP
    # src_ip,dest_ip
    # 10.10.10.0/24,20.20.20.0/24
    # 10.10.10.1/32,20.20.20.1/32

    # Main Program Loop
    print "input_file: {0}".format(input_file)
    print "ipmap_file: {0}".format(ipmap_file)
    print "Starting Main Program Loop"
    try:
        # Run this if the argument is a directory...
        if os.path.isdir(input_file):
            pass
        # Otherwise, this is a file...
        else:
            if ipmap_file:
                # This loads the global include and exclude list dictionaries
                load_ipmap()
            # Run the scrub function
            scrub_file(input_file)
            quit()
    except KeyboardInterrupt:
        print 'Exiting...'
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)