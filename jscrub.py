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
from random import randrange

# Paths
mypwd = ''
myuser = ''
port = 22
textmap_list = []
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

# Provide a mask as a string and get the number of network octets
def get_net_octets(mask):
    net_octets = 0
    if 0 < int(mask) <= 15:
        net_octets = 1
    elif 16 <= int(mask) <= 23:
        net_octets = 2
    elif 24 <= int(mask) <= 31:
        net_octets = 3
    elif int(mask) == 32:
        net_octets = 4

    return net_octets

# Creates an IP using a network ip/mask or just mask
# /0 - /7 -> Not defined
# /8 - /15 -> Randomize 1st octet, keep last 3
# /16 - /23 -> Randomize first 2 octets, keep last 2
# /24 - /31 -> Randomize first 3 octets, keep last 1
# /32 -> Randomize all octets
#
# If a network is provided, the network portion of the IP address will be used.
# If a network is not provided, the network will be randomly generated.
def generate_ip(pop_dest_ip, pop_dest_mask, fs_ip, fs_mask):
    not_valid = True
    net_octets = 0
    new_ip = ''
    pop_net = get_net_octets(pop_dest_mask)
    fs_net = get_net_octets(fs_mask)
    pop_octets = pop_dest_ip.split(".")
    fs_octets = fs_ip.split(".")
    octets = {'octet0': '0', 'octet1': '0', 'octet2': '0', 'octet3': '0'}
    # Perform this loop until we have a valid / non-duplicate IP address
    while not_valid:
        if pop_net == 3:
            octets['octet0'] == pop_octets[0]
            octets['octet1'] == pop_octets[1]
            octets['octet2'] == pop_octets[2]
            if fs_net == 4:
                octets['octet3'] == fs_octets[3]
        elif pop_net == 2:
            octets['octet0'] == pop_octets[0]
            octets['octet1'] == pop_octets[1]
            if fs_net == 3:
                octets['octet2'] == str(randrange(1, 256))
                octets['octet3'] == fs_octets[3]
            elif fs_net == 4:
                octets['octet2'] == str(randrange(1, 256))
                octets['octet3'] == str(randrange(1, 256))
        elif pop_net == 1:
            octets['octet0'] == pop_octets[0]
            if fs_net == 2:
                octets['octet1'] == str(randrange(1, 256))
                octets['octet2'] == fs_octets[2]
                octets['octet3'] == fs_octets[3]
            elif fs_net == 3:
                octets['octet1'] == str(randrange(1, 256))
                octets['octet2'] == str(randrange(1, 256))
                octets['octet3'] == fs_octets[3]
            elif fs_net == 4:
                octets['octet1'] == str(randrange(1, 256))
                octets['octet2'] == str(randrange(1, 256))
                octets['octet3'] == str(randrange(1, 256))
        new_ip = ".".join([octets['octet0'], ['octet2'], ['octet3'], ['octet4']])
        #if not is_excluded(ip):
        not_valid = False
    return new_ip

# Creates an IP
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
                # Return masked or unmasked depending on calling requirement
                if masked: return mydict['dest_ip'] + "/" + mydict['mask']
                else: return mydict['dest_ip']
            # This succeeds if the match was exact, but a corresponding network does not exist, create it.
            elif 'ip' in mydict['match']:
                print "Analysis: IP ONLY Match!\n"
                # Check if the target mask is smaller than existing, replace if this is the case
                if targ_mask < mydict['mask']:
                    # Change entry to reflect provided mask
                    mydict = change_dict(include_list, 'src_ip', mydict['src_ip'], 'mask', targ_mask)
                # Return masked or unmasked depending on calling requirement
                if masked: return mydict['dest_ip'] + "/" + targ_mask
                else: return mydict['dest_ip']
            # This succeeds if the network was matched, only need to create an entry for the exact IP
            elif 'net' in mydict['match']:
                # Create new IP entry, need to use the network portion of the dest_ip and host portion of targ_ip
                new_ip = generate_ip(mydict['mask'], targ_ip, mydict['dest_ip'])
                print "Analysis: Network ONLY Match!\n"
                # Add the new IP to the include_list
                newdict = {'src_ip': targ_ip, 'mask': mydict['mask'], 'dest_ip': new_ip}
                include_list.append(newdict)
                # Return masked or unmasked depending on calling requirement
                if masked: return mydict['dest_ip'] + "/" + targ_mask
                else: return mydict['dest_ip']
            # This executes if the match was not exact, meaning, we need an entry for this IP
            else:
                print "Analysis: ERROR - Should not execute, this value is invalid: {0}\n".format(mydict['match'])
                exit()
        # This executes if is_included doesn't return a match, an unmatched entry!
        else:
            print "Analysis: No IPs Matched: {0}\n".format(targ_ip)
            # Create new IP
            new_ip = generate_ip(targ_mask, targ_ip)
            print "Generated IP: {0}".format(new_ip)
            # Add new IP to the include_list
            newdict = {'src_ip': targ_ip, 'mask': targ_mask, 'dest_ip': new_ip}
            include_list.append(newdict)
            # If the IP address is a host address, create a network address
            ip_list = list(IPNetwork(targ_ip + "/" + targ_mask))
            print "Network List: {0}".format(ip_list)
            if targ_mask != '32' or ip_list[0] != IPAddress(targ_ip):
                print "This IP is not a network address or 32 mask. Create a network address for this IP..."
                new_net = generate_ip(targ_mask, targ_ip, new_ip)
                newdict = {'src_ip': ip_list[0], 'mask': targ_mask, 'dest_ip': new_net}
                print "newdict: {0}".format(newdict)
            # Return masked or unmasked depending on calling requirement
            if masked: return new_ip + "/" + targ_mask
            else: return new_ip
            """
            Targ_IP: 10.106.137.201
            Targ_Mask: 32
            Src_IP: 10.106.137.200
            Dest_IP: 22.12.32.200
            Mask: 29
            """
    else:
        print "Analysis: Matched an Excluded IP or Network: {0}\n".format(targ_ip)
        # Return masked or unmasked depending on calling requirement
        if masked:
            return targ_ip + "/" + targ_mask
        else:
            return targ_ip
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

# This function removes the excluded IPs and returns a list of IPs
def remove_excluded_ips(ip_list):
    # Filtered List
    filtered_list = []
    # Loop over the list lines
    for ip in ip_list:
        matched = False
        # Loop over the excluded IPs
        for exc_ip in exclude_list:
            # Check if the target ip matches or is under the excluded ip
            if IPNetwork(ip) in IPNetwork(exc_ip):
                print "Matched List Term: {0} to Exclude Term: {1}".format(ip, exc_ip)
                matched = True
        if not matched:
            print "-- No Match Found for: {0}".format(ip)
            if "/" in ip:
                filtered_list.append(ip)
            else:
                filtered_list.append(ip + "/32")
    return filtered_list

# This method populates two list dictionaries with the ipmap contents
def load_ipmap():
    global exclude_list
    global textmap_list
    if ipmap_file:
        line_list = txt_to_list(ipmap_file)
        print "IPMAP FILE: {0}".format(ipmap_file)
        # Get include info
        on_textmap = False
        # Loop over ipmap file and create an exclude list and include listdict
        for line in line_list:
            # Check if there is text on this line...
            if line:
                # Check for "INCLUDE" text...
                if "TEXT-MAPPING" in line:
                    on_textmap = True
                # If we are in INCLUDE section...
                elif on_textmap:
                    text_map = line.split(",")
                    src_text = text_map[0]
                    dest_text = text_map[1]
                    textmap_list.append({"src_text": src_text, "dest_text": dest_text})
                # If we are in EXCLUDE section...
                else:
                    if not "EXCLUDE" in line:
                        exclude_list.append(line)
    else:
        print "IPMAP FILE: NOT DEFINED"
    # Print exclude list
    print "Exclude List: {0}".format(exclude_list)
    # Print include list
    print "Textmap List: {0}".format(textmap_list)


# Function for scrubbing a file
# How this scrub function works:
# 1. Find all ipv4 terms in a line of text
# 2. Search for existing replacements, if they don't exist, create new ones
# 3. Create substrings of the remaining text
def extract_file_ips(input_file):
    # Regexs
    ipv4_regex = re.compile("([1][0-9][0-9]|[2][5][0-5]|[2][0-4][0-9]|[1][0-9][0-9]|[0-9][0-9]|[0-9])"
                                "\.([1][0-9][0-9]|[2][5][0-5]|[2][0-4][0-9]|[1][0-9][0-9]|[0-9][0-9]|[0-9])"
                                "\.([1][0-9][0-9]|[2][5][0-5]|[2][0-4][0-9]|[1][0-9][0-9]|[0-9][0-9]|[0-9])"
                                "\.([1][0-9][0-9]|[2][5][0-5]|[2][0-4][0-9]|[1][0-9][0-9]|[0-9][0-9]|[0-9])"
                                "(\/([8]|[9]|1[0-9]|2[0-9]|3[0-2]))?")
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
    # Create list of interesting items
    capture_ld = []
    # Load targeted scrub file into a list
    line_list = txt_to_list(input_file)
    # Check for content using provided regexs
    print "Starting scan of {0}:".format(input_file)
    if line_list:
        for line in line_list:
            for regex in regexs:
                #print "Start Line: {0}".format(line)
                # Get the start and end indexes for captured regex terms
                indicies = [[m.start(),m.end()] for m in regex.finditer(line)]
                # Create default start and end indicies
                frag_start = 0
                frag_end = len(line)
                # Loop over indicies
                for ipindex in indicies:
                    '''
                    # This adds the line segment before the ip
                    new_line += line[frag_start:ipindex[0]]
                    # This runs the function for finding the correct IP or creating one using provided file content
                    new_line += get_replacement_ip(str(line[ipindex[0]:ipindex[1]]))
                    '''
                    ip = str(line[ipindex[0]:ipindex[1]])
                    print "\tMatched: {0}".format(ip)
                    # Add interesting term to the list
                    capture_ld.append(ip)
                    # Update the frag_start to last index
                    frag_start = ipindex[1]
                '''
                # Check if we still have some text after the last ip. If no matches were made this simply add the entire
                # line unchanged
                if frag_start < frag_end:
                    new_line += line[frag_start:frag_end]
                # Change line to the "modified" line
                line = new_line
                #print "Modified Line: {0}\n".format(line)
                '''
        print "Completed scan of {0}".format(input_file)
    # If it failed to read or convert the file
    else:
        print "ERROR: Unable to convert file to list: {0}".format(input_file)
    # Remove duplicates and return the capture interesting terms
    return list(set(capture_ld))

# This function sorts a list dictionary by a certain key's value, can also reverse the sort order
def process_capture_list(capture_list):
    ld = []
    new_ld = []
    # Remove the "excluded" ips first
    removed_list = remove_excluded_ips(capture_list)

    # Convert list to list of dictionaries
    for raw_ip in removed_list:
        if "/" in raw_ip:
            exp_ip = raw_ip.split("/")
            mydict = {'ip': exp_ip[0], 'mask': exp_ip[1]}
        else:
            mydict = {'ip': raw_ip, 'mask': '32'}
        ld.append(mydict)

    # Sort by mask
    ld = sorted(ld, key=itemgetter('mask'), reverse=False)

    ip_list = []
    # Remove duplicate ips
    for mydict in ld:
        if mydict['ip'] not in ip_list:
            new_ld.append(mydict)
            ip_list.append(mydict['ip'])
        else:
            print "Found duplicate ip: {0} mask: {1} !!!".format(mydict['ip'], mydict['mask'])

    # Return
    return new_ld

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
    capture_ld = []
    try:
        # Run this if the argument is a directory...
        if os.path.isdir(input_file):
            pass
        # Otherwise, this is a file...
        else:
            if ipmap_file and input_file:
                # Load the exclude list dictionary
                load_ipmap()
                # Load the input file
                capture_list = extract_file_ips(input_file)

                # Process the list (remove excluded IPs, sort)
                print "Start File Processing..."
                fs_ld = process_capture_list(capture_list)
                print "Ending File Processing"
                pprint(fs_ld)

                # Populated List Dictionary
                pop_ld = []
                # Loop over the content from file
                matched = False
                fs_ip_mask = ''
                pop_ip_mask = ''
                pop_ip_dict = {'dest_ip': '', 'mask': '', 'src_ip': ''}
                for fs_ip in fs_ld:
                    if pop_ld:
                        # Loop over the populated map list dictionary
                        for pop_ip in pop_ld:
                            fs_ip_mask = fs_ip['ip'] + "/" + fs_ip['mask']
                            pop_ip_mask = pop_ip['src_ip'] + "/" + pop_ip['mask']
                            # See if the ipmap table has a matching IP
                            if IPNetwork(fs_ip_mask) in IPNetwork(pop_ip_mask):
                                matched = True
                                print "Matched {0} is a part of [1}".format(fs_ip_mask, pop_ip_mask)
                                pop_ip_dict = pop_ip
                        # Run this if a match was made
                        if matched:
                            print "-> Closest match to {0} is {1}".format(fs_ip_mask, pop_ip_mask)
                            new_ip = get_replacement_ip(pop_ip['dest_ip'], pop_ip['mask'], fs_ip['ip'], fs_ip['mask'])
                            print "-> Replacement IP is {0}".format(new_ip)


                #f_ld.sort(key=lambda x: (x['src_ip'], x['mask']))
                #pprint(f_ld)
                # Iterate over the list
                quit()
            # Run this if the ipmap_file or input_file is not valid
            else:
                print "Please check the input files!"
                sys.exit(0)
    except KeyboardInterrupt:
        print 'Exiting...'
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)