__copyright__ = "Copyright 2018 Tyler Jordan"
__version__ = "0.1.1"
__email__ = "tjordan@juniper.net"

import datetime
import platform
import os
import netaddr
import argparse

from utility import *

from prettytable import PrettyTable
from pprint import pprint
from os import path
from operator import itemgetter
from netaddr import IPAddress, IPNetwork

# Paths
mypwd = ''
myuser = ''
port = 22

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
# Function for scrubbing a file
# How this scrub function works:
# 1. Find all ipv4 terms in a line of text
# 2. Search for existing replacements, if they don't exist, create new ones
# 3. Create substrings of the remaining text
def scrub_file(input_file, ipmap_file=None, term_file=None):
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

    # Load source map file, if specified...
    line_list = txt_to_list(input_file)
    exclude_list = []
    include_list = []
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
                    get_replacement_ip(str(line[ipindex[0]:ipindex[1]]), include_list, exclude_list)
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
def get_replacement_ip(raw_ip, include_list, exclude_list):
    masked = False
    mask = "32"
    ip = raw_ip
    ipmasked = raw_ip + "/" + mask
    # Determine if this is a masked IP, assume /32 if no mask
    print "-"*60
    if ":" in raw_ip:
        print "IP: {0} is an IPv6 address.".format(raw_ip)
        mask = "128"
        return "fe80::feeb:daed"
    elif "/" in raw_ip:
        print "IP: {0} is masked.".format(raw_ip)
        masked = True
        ipmasked = raw_ip
        mask = raw_ip.split("/")[1]
        ip = raw_ip.split("/")[0]
    else:
        print "IP: {0} is NOT masked.".format(raw_ip)
    print "Mask: {0}".format(mask)

    # Matching procedure
    if not is_excluded(exclude_list, ip):
        mydict = is_included(include_list, ipmasked)
        # This executes if is_included returns a match
        if mydict:
            print "IP: {0} - Returned: {1}".format(ip, mydict)
            # This executes if the match was exact, meaning, no new entries are required
            if ipmasked == mydict['src_ip']:
                if masked:
                    return mydict['src_ip'] + "/" + mydict['mask']
                else:
                    return mydict['src_ip']
            # This executes if the match was not exact, meaning, we need an entry for this IP
            else:
                pass
        # This executes if is_included doesn't return a match, an unmatched entry!
        else:
            print "IP: {0} - Unmatched IP".format(ip)
    else:
        print "IP: {0} - Matched Exclude".format(ip)

# Check for IP in the list
def is_excluded(exclude_list, ip):
    # Loop over exclude IPs
    matched = False
    for exc_ip in exclude_list:
        # If a match on the IP is made, this IP will be skipped
        if IPAddress(ip) in IPNetwork(exc_ip):
            matched = True
            #print "MATCHED: {0} with: {1}".format(ip, exc_ip)
    return matched

# Check included, if false, create new entry , if true, return the dictionary match
def is_included(include_list, ipmasked):
    # Loop over include IPs
    mymatch = {}
    for inc_ip in include_list:
        # If a match on the IP is made, we will finish scanning options to see if a more closer match exists
        if IPNetwork(ipmasked) in IPNetwork(inc_ip['src_ip'] + "/" + inc_ip['mask']):
            #print "MATCHED: {0} with: {1}".format(ipmasked, inc_ip["src_ip"])
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
    ipmap_ld = []

    # Main Program Loop
    print "input_file: {0}".format(input_file)
    print "ipmap_file: {0}".format(ipmap_file)
    print "Starting Main Program Loop"
    try:
        # Load the ipmap file into a list dictionary, if it exists...
        if ipmap_file:
            ipmap_ld = csvListDict(ipmap_file)

        # Run this if the argument is a directory...
        if os.path.isdir(input_file):
            pass
        # Otherwise, this is a file...
        else:
            # Run the scrub function
            scrub_file(input_file, ipmap_file)
            quit()
    except KeyboardInterrupt:
        print 'Exiting...'
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)