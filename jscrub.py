__copyright__ = "Copyright 2019 Tyler Jordan"
__version__ = "1.0.1"
__email__ = "tjordan@juniper.net"


import argparse
import ntpath
import platform
import os
import re

from operator import itemgetter
from random import randrange, randint, choice
from sys import stdout
from pprint import pprint
from netaddr import IPNetwork, valid_ipv6

# Global Variables
host_ld = []
network_ld = []

# Global Lists
textmap_list = []
regexmap_list = []
exclude_list = []

# Global Directories
search_dir = ''
scrub_dir = ''
dir_path = ''


def detect_env():
    """ Purpose: Detect OS and create appropriate path variables
    :param: None
    :return: None
    """
    global search_dir
    global scrub_dir
    global dir_path

    dir_path = os.path.dirname(os.path.abspath(__file__))
    if platform.system().lower() == "windows":
        # print "Environment Windows!"
        search_dir = os.path.join(dir_path, "unscrubbed")
        scrub_dir = os.path.join(dir_path, "scrubbed_files")

    else:
        # print "Environment Linux/MAC!"
        search_dir = os.path.join(dir_path, "unscrubbed")
        scrub_dir = os.path.join(dir_path, "scrubbed_files")

# Creates text file from a list
def list_to_txt(dest_file, src_list):
    text_config = ""
    try:
        # Overwrites an existing file, if there is one
        with open(dest_file, 'w') as text_config:
            for line in src_list:
                text_config.write("{0}\n".format(line))
    except Exception as err:
        print "Error writing list to file. ERROR: {0}".format(err)
        return False
    else:
        return True

# Creates list from a text file
def txt_to_list(txt_file):
    command_list = []
    try:
        with open(txt_file) as f:
            command_list = f.read().splitlines()
    except Exception as err:
        print "Error turning file into list. ERROR: {0}".format(err)
        return False
    else:
        return command_list

# Modify a term in the defined dictionary within a list of dictionaries
# The match term/val are to identify the correct dictionary only
# The chg term/val are the key/value to change in the identified dictionary
def change_dict(list_dict, match_term, match_val, chg_term, chg_val):
    for mydict in list_dict:
        for k, v in mydict.iteritems():
            if k == match_term and v == match_val:
                # print "Matched this dictionary: {0}".format(mydict)
                mydict.update({chg_term: chg_val})
    return list_dict


# This function removes any of the excluded IPs and returns a list of IPs
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
                # print "Matched List Term: {0} to Exclude Term: {1}".format(ip, exc_ip)
                matched = True
        # If the IP was not matched, add it to the filtered list
        if not matched:
            filtered_list.append(ip)

    return filtered_list


# Method for asking a Y/N question, return True or False
def getTFAnswer(question):
    answer = False
    while not answer:
        print ""
        ynanswer = raw_input(question + '(y/n): ')
        print ""
        if ynanswer == 'Y' or ynanswer == 'y':
            answer = True
            return answer
        elif ynanswer == 'N' or ynanswer == 'n':
            answer = False
            return answer
        else:
            print "Bad Selection"


# This method populates two list dictionaries with the ipmap contents
def load_ipmap():
    global exclude_list
    global textmap_list
    global regexmap_list
    if ipmap_file:
        line_list = txt_to_list(ipmap_file)
        # print "IPMAP FILE: {0}".format(ipmap_file)
        # Get include info
        on_exclude = False
        on_textmap = False
        on_regexmap = False
        # Loop over ipmap file and create an exclude list and include listdict
        for line in line_list:
            # Check if there is text on this line...
            if line:
                # Check for "INCLUDE" text...
                if "EXCLUDE" in line:
                    on_exclude = True
                elif "TEXT-MAPPING" in line:
                    on_textmap = True
                    on_exclude = False
                elif "TEXT-REGEX" in line:
                    on_regexmap = True
                    on_textmap = False
                # If we are in INCLUDE section...
                elif on_exclude:
                    exclude_list.append(line)
                elif on_textmap:
                    text_map = line.split(",")
                    src_text = text_map[0]
                    dest_text = text_map[1]
                    textmap_list.append({"src_text": src_text, "dest_text": dest_text})
                elif on_regexmap:
                    regex_map = line.split(",")
                    src_regex = regex_map[0]
                    dest_regex = regex_map[1]
                    regexmap_list.append({"src_regex": src_regex, "dest_regex": dest_regex})
                # This should not execute
                else:
                    pass
    else:
        print "IPMAP FILE: NOT DEFINED"
        exit(0)


# Function for extracting the IPs from the input files
def extract_file_ips(input_files):
    # Regexs
    # This IPv4 expression will match an IP and masks from /8 to /32.
    # If the mask is more than 2 digits long, it will only match the IP octets. "(?!\d)"
    ipv4_regex = re.compile("(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}"
                            "([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])"
                            "(\/(8|9|1[0-9]|2[0-9]|3[0-2]))?(?!\d)")

    ipv6_regex = re.compile("(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:)"
                            "{1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:)"
                            "{1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4})"
                            "{1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:"
                            "((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4})"
                            "{0,4}%[0-9a-zA-Z]{?}|::(ffff(:0{1,4}){?}:){?}((25[0-5]|(2[0-4]|1{?}[0-9])"
                            "{?}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{?}[0-9]){?}[0-9])|([0-9a-fA-F]{1,4}:)"
                            "{1,4}:((25[0-5]|(2[0-4]|1{?}[0-9]){?}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{?}[0-9])"
                            "{?}[0-9]))(\/([1][0-1][0-9]|[1][2][0-8]|[0-9][0-9]))?")

    regexs = [ipv4_regex, ipv6_regex]
    # Create list of interesting items
    capture_list = []
    print ""
    for input_file in input_files:
        print "\tProcessing File: {0}".format(ntpath.basename(input_file))
        # Load targeted scrub file into a list
        line_list = txt_to_list(input_file)
        # Check for content using provided regexs
        # print "Starting scan of {0}:".format(input_file)
        if line_list:
            for line in line_list:
                for regex in regexs:
                    # print "Start Line: {0}".format(line)
                    # Get the start and end indexes for captured regex terms
                    indicies = [[m.start(), m.end()] for m in regex.finditer(line)]
                    # Create default start and end indicies
                    frag_start = 0
                    frag_end = len(line)
                    # Loop over indicies
                    for ipindex in indicies:
                        ip = str(line[ipindex[0]:ipindex[1]])
                        # print "\tMatched: {0}".format(ip)
                        # Add a "/32" suffix to IPv4 and "/128" suffix to IPv6
                        # If an IP already has a mask, keep it, otherwise add a host mask
                        if "/" in ip:
                            capture_list.append(ip)
                        elif ":" in ip:
                            capture_list.append(ip + "/128")
                        else:
                            capture_list.append(ip + "/32")
                        # Update the frag_start to last index
                        frag_start = ipindex[1]
                        # print "Completed scan of {0}".format(input_file)
        # If it failed to read or convert the file
        else:
            print "ERROR: Unable to convert file to list: {0}".format(input_file)
    # Remove duplicates and return the capture interesting terms
    return list(set(capture_list))


# This function replaces the IPs in the input_file using the map_ld
# Try to make this function replace text using textmap and regexmap
def replace_ips(input_file):
    # Create list of interesting items
    capture_list = []
    # Load targeted scrub file into a list
    line_list = txt_to_list(input_file)
    # Sort the host_ld
    sort_host_ld()
    # Check for content using provided regexs
    # print "Starting scan of {0}:".format(input_file)
    if line_list:
        line_count = 0
        #print "File: {0} | Lines: {1}".format(input_file, str(len(line_list)))
        # Loop over list of lines
        for line in line_list:
            line_count += 1
            #print "\tLine: {0}".format(line_count)
            new_line = ''
            not_matched = True
            # Loop over textmap
            for text_d in textmap_list:
                if text_d['src_text'] in line:
                    new_line = re.sub(text_d['src_text'], "{{" + text_d['dest_text'] + "}}", line)
                    not_matched = False
                    line = new_line
            # Loop over regexmap
            for regex_d in regexmap_list:
                if re.search(regex_d['src_regex'], line):
                    #print "Matched: {0}".format(line)
                    new_line = re.sub(regex_d['src_regex'], "{{" + regex_d['dest_regex'] + "}}", line)
                    not_matched = False
                    line = new_line
            # Loop over the host replacement list dictionary
            for host_d in host_ld:
                if str(host_d['hs_ip'].ip) in line:
                    new_line = re.sub(str(host_d['hs_ip'].ip), str(host_d['ls_ip'].ip), line)
                    # print "\tReplacing: {0} with {1}".format(map_d['hs_ip'], map_d['ls_ip'])
                    not_matched = False
                    line = new_line
            # Loop over the network replacement list dictionary
            for network_d in network_ld:
                if str(network_d['hs_ip'].ip) in line:
                    new_line = re.sub(str(network_d['hs_ip'].ip), str(network_d['ls_ip'].ip), line)
                    # print "\tReplacing: {0} with {1}".format(map_d['hs_ip'], map_d['ls_ip'])
                    not_matched = False
                    line = new_line
            # If there were no IPs or replacments in the file, this will execute
            if not_matched:
                new_line = line
            # print "New Line: {0}".format(new_line)
            # Add replaced line to list
            capture_list.append(new_line)

            # print "Completed scan of {0}".format(input_file)
    # If it failed to read or convert the file
    else:
        print "ERROR: Unable to convert file to list: {0}".format(input_file)
    # Return the capture interesting terms
    return capture_list

# Process for sorting the IP list dictionaries (most specific to least specific)
def sort_network_ld():
    global network_ld
    raw_ld = network_ld
    network_ld = []
    # Convert list to list of dictionaries
    if raw_ld:
        for raw_dict in raw_ld:
            #print "Unsorted IP: {0}".format(raw_dict['hs_ip'])
            idx = 0
            # If the list has entries already, loop over the list to find the correct slot
            if network_ld:
                ip_not_added = True
                # Loop over the ip list
                for network_dict in network_ld:
                    #print "\tSorted IP: {0} Index: {1}".format(network_dict['hs_ip'], str(idx))
                    # If the unsorted mask is larger than current sorted mask
                    if raw_dict['hs_ip'].prefixlen >= network_dict['hs_ip'].prefixlen:
                        #print "\t\tIncoming prefix ({0}) is >= to ({1})".format(raw_dict['hs_ip'].prefixlen,
                        #                                                           network_dict['hs_ip'].prefixlen)
                        ip_not_added = False
                        network_ld.insert(idx, raw_dict)
                        #print "\t\t\tAdding Unsorted IP to Index: {0}".format(str(idx))
                        break
                    # Increments the index number for list
                    #print "\t[Increment Index]"
                    idx += 1
                # If the IP wasn't added, usually because its mask is smaller than the rest of IPs
                if ip_not_added:
                    #print "Highest Mask in list: {0}".format(raw_dict['hs_ip'].prefixlen)
                    network_ld.append(raw_dict)
                    #print "\t\t\tAdding Unsorted IP to end of List"
            # If the list is empty, just add the first IP
            else:
                #print "Adding Unsorted IP to empty List"
                network_ld.append(raw_dict)
    # No entries to sort
    else:
        #print "\nNo entries to sort."
        pass
    # Sort by mask
    # ld = sorted(ld, key=itemgetter('mask'), reverse=False)


# Process for sorting the IP list dictionaries (most specific to least specific)
# Secondarily sorts fourth octet preferring higher digit octet numbers 3 > 2 > 1
def sort_host_ld():
    global host_ld
    raw_ld = host_ld
    host_ld = []
    #print "*****************************************"
    # Convert list to list of dictionaries
    if raw_ld:
        #pprint(raw_ld)
        for raw_dict in raw_ld:
            #print "Unsorted IP: {0}".format(raw_dict['hs_ip'])
            idx = 0
            # If the list has entries already, loop over the list to find the correct slot
            if host_ld:
                ip_not_added = True
                # Loop over the ip list
                for host_dict in host_ld:
                    raw_len = octet_4_len(raw_dict['hs_ip'])
                    host_len = octet_4_len(host_dict['hs_ip'])
                    #print "\tSorted IP: {0} Index: {1}".format(network_dict['hs_ip'], str(idx))
                    # If 4th octet of the incoming prefix is greater than or equal to this IP, insert it
                    if raw_len >= host_len:
                        #print "\t\tIncoming ip ({0}) is >= to ({1})".format(raw_len, host_len)
                        ip_not_added = False
                        host_ld.insert(idx, raw_dict)
                        #print "\t\t\tAdding Unsorted IP to Index: {0}".format(str(idx))
                        break
                    # Increments the index number for list
                    #print "\t[Increment Index]"
                    idx += 1
                # If the IP wasn't added, usually because its mask is smaller than the rest of IPs
                if ip_not_added:
                    #print "Highest Mask in list: {0}".format(raw_dict['hs_ip'].prefixlen)
                    host_ld.append(raw_dict)
                    #print "\t\t\tAdding Unsorted IP to end of List"
            # If the list is empty, just add the first IP
            else:
                #print "Adding Unsorted IP to empty List"
                host_ld.append(raw_dict)
        #exit(0)
    # No entries to sort
    else:
        #print "\nNo entries to sort."
        pass
    # Sort by mask
    # ld = sorted(ld, key=itemgetter('mask'), reverse=False)

# Get the length of the fourth octet for the sort mechanism
def octet_4_len(ip_net):
    # Get the fourth octet out of this IP
    octets = str(ip_net.ip).split(".")
    # Return the length of the fourth octet
    return int(len(octets[3]))


# This function sorts a list dictionary by a certain key's value, can also reverse the sort order
def process_capture_list(capture_list):
    sorted_ips = []
    new_ld = []
    # Remove the "excluded" ips first
    filtered_list = remove_excluded_ips(capture_list)

    # Convert list to list of dictionaries
    for raw_ip in filtered_list:
        new_ip = IPNetwork(raw_ip)
        #print "New IP: {0}".format(new_ip)
        idx = 0
        # If the list has entries already, loop over the list to find the correct slot
        if sorted_ips:
            ip_not_added = True
            # Loop over the ip list
            for list_ip in sorted_ips:
                #print "\tidx: {0} List IP: {1}".format(str(idx), list_ip)
                # Check if these IPs are the same (different mask)
                if new_ip.ip != list_ip.ip:
                    # If the mask is larger than this IP
                    if new_ip.prefixlen <= list_ip.prefixlen:
                        ip_not_added = False
                        sorted_ips.insert(idx, new_ip)
                        #print "\tAdding New IP: {0}".format(new_ip)
                        break
                # If they are the same IP, choose the IP with the lowest mask
                else:
                    #print "\tDuplicate IPs: {0} | {1}".format(new_ip, list_ip)
                    if new_ip.prefixlen < list_ip.prefixlen:
                        print "\tRemoving existing IP, adding new IP"
                        sorted_ips.pop(idx)
                        sorted_ips.insert(idx, new_ip)
                # Increments the index number for list
                idx += 1
            # If the IP wasn't added
            #print "Passing 'ip_not_added' CHECK"
            if ip_not_added:
                #print "Highest Mask in list: {0}".format(new_ip.prefixlen)
                sorted_ips.append(new_ip)
        # If the list is empty, just add the first IP
        else:
            #print "Added the first IP"
            sorted_ips.append(new_ip)

    # Sort by mask
    # ld = sorted(ld, key=itemgetter('mask'), reverse=False)
    #print "********* WHOLE LIST **************"
    #pprint(sorted_ips)

    # Return
    return sorted_ips


# This gets the status of each octet, according to CIDR rules
def get_host_octets(new_ip):
    mask = int(new_ip.prefixlen)
    octets = str(new_ip.ip).split(".")
    rand_net = ''
    # Determine the type attribute for octet1
    octet0_type = ''
    if 1 <= mask <= 7:
        octet0_type = 'nethost'
        net_list = get_net_list(new_ip, idx=0)
        rand_net = choice(net_list)
    elif 8 <= mask <= 32:
        octet0_type = 'net'

    # Determine the type attribute for octet2
    octet1_type = ''
    if 1 <= mask <= 8:
        octet1_type = 'host'
    elif 9 <= mask <= 15:
        octet1_type = 'nethost'
        net_list = get_net_list(new_ip, idx=1)
        #print "Net List"
        #print net_list
        rand_net = choice(net_list)
    elif 16 <= mask <= 32:
        octet1_type = 'net'

    # Determine the type attribute for octet3
    octet2_type = ''
    if 1 <= mask <= 16:
        octet2_type = 'host'
    elif 17 <= mask <= 23:
        octet2_type = 'nethost'
        net_list = get_net_list(new_ip, idx=2)
        rand_net = choice(net_list)
    elif 24 <= mask <= 32:
        octet2_type = 'net'

    # Determine the type attribute for octet4
    octet3_type = ''
    if 1 <= mask <= 24 or mask == 32:
        octet3_type = 'host'
    elif 25 <= mask <= 31:
        octet3_type = 'nethost'
        net_list = get_net_list(new_ip, idx=3)
        rand_net = choice(net_list)

    # Create dictionary for list
    ip_info = {'octet0': {'val': octets[0], 'type': octet0_type},
               'octet1': {'val': octets[1], 'type': octet1_type},
               'octet2': {'val': octets[2], 'type': octet2_type},
               'octet3': {'val': octets[3], 'type': octet3_type},
               'rand_net': str(rand_net)}

    # Return this info
    return ip_info


# Create a network list from a netaddr IPNetwork object
def get_net_list(new_ip, idx):
    nets = get_net_size(new_ip, idx)
    i = 0
    net_list = []
    while i < 256:
        net_list.append(i)
        i += nets
    return net_list


# Returns the net size octet
def get_net_size(new_ip, idx):
    #print "Index: {0} | Type: {1}".format(idx, type(idx))
    #print "IP Broacast: {0} | IP Network: {1}".format(str(new_ip.broadcast), str(new_ip.network))
    if new_ip.broadcast:
        nets = int(str(new_ip.broadcast).split('.')[int(idx)]) - int(str(new_ip.network).split('.')[int(idx)]) + 1
    else:
        nets = 1
    return nets


# Converts a base 10 number to base 16
def frm(x, b):
    """
    Converts given number x, from base 10 to base b 
    x -- the number in base 10
    b -- base to convert
    """
    assert(x >= 0)
    assert(1< b < 37)
    r = ''
    import string
    while x > 0:
        r = string.printable[x % b] + r
        x //= b
    return r


# Well-known IPv6 addresses (ignore these)
# ::            - 0:0:0:0:0:0:0:0
# ::/0          - 0:0:0:0:0:0:0:0
# ::#           - 0:0:0:0:0:0:0:#
# ::#/128       - 0:0:0:0:0:0:0:#
# Translate the following
# - If "::"s are found in the address and they aren't the well-known above. Need to...
# 1. capture octets on either side (using split for "::")
# 2. create random octets, reassemble address
# 3. check that the entry is unique
# 3a. If octet is "ffff", keep it that way
# 4. apply to mapping ld
# - If "::"s are NOT found, break out all octets (using split on ":")
def generate_ipv6(hs_ip, hs_mask, map_ld=[]):
    print "Old IP: {0} | Mask: {1}".format(hs_ip, hs_mask)
    new_ip = ""
    new_octet = ""
    first_loop = True
    # Check for double octet
    if "::" in hs_ip:
        # Format IP
        double_octet = re.split("::", hs_ip)
        first_part = double_octet[0].split(":")
        second_part = double_octet[1].split(":")
        # Loop over first group of IP fragments
        for octet in first_part:
            if not first_loop:
                new_ip += ":"
            else:
                first_loop = False
            if octet != "ffff":
                new_octet = frm(randint(0, 16**4), 16)
            else:
                new_octet = "ffff"
            new_ip += new_octet
        # Loop over second group of IP fragments
        new_ip += "::"
        for octet in second_part:
            if not first_loop:
                new_ip += ":"
            else:
                first_loop = False
            if octet != "ffff":
                new_octet = frm(randint(0, 16**4), 16)
            else:
                new_octet = "ffff"
            new_ip += new_octet
    # If no double octet, do a standard replace
    else:
        octets = hs_ip.split(":")
        for octet in octets:
            if not first_loop:
                new_ip += ":"
            else:
                first_loop = False
            if octet != "ffff":
                new_octet = frm(randint(0, 16**4), 16)
            else:
                new_octet = "ffff"
            new_ip += new_octet
    print "New IP: {0} | Mask: {1}".format(new_ip, hs_mask)
    # Return the created IP
    return new_ip


def generate_random_ipv4(cap_oct, octets):
    # Get first octet
    if cap_oct['octet0']['type'] == 'net':
        octets[0] = str(randrange(1, 254))
    elif cap_oct['octet0']['type'] == 'nethost':
        octets[0] = cap_oct['rand_net']
    # print "Oct0: {0}".format(octets[0])

    # Get second octet
    if cap_oct['octet1']['type'] == 'net':
        octets[1] = str(randrange(1, 254))
    elif cap_oct['octet1']['type'] == 'nethost':
        octets[1] = cap_oct['rand_net']
    elif cap_oct['octet1']['type'] == 'host':
        octets[1] = '0'

    # Get third octet
    if cap_oct['octet2']['type'] == 'net':
        octets[2] = str(randrange(1, 254))
    elif cap_oct['octet2']['type'] == 'nethost':
        octets[2] = cap_oct['rand_net']
    elif cap_oct['octet2']['type'] == 'host':
        octets[2] = '0'

    # Get fourth octet
    if cap_oct['octet3']['type'] == 'nethost':
        octets[3] = cap_oct['rand_net']
    elif cap_oct['octet3']['type'] == 'host':
        octets[3] = '0'

    return octets

# If a network is provided, the network portion of the IP address will be used.
# cap_ip: The IP from the text document in it's non-scrubbed form
# map_ip: The IP from the map database, the LS IP
def generate_ipv4(cap_ip, map_ip='', match='none'):
    #print "\n***** Arguments Provided *****"
    ip_unverified = True
    dup_count = 0

    octets = ['0', '0', '0', '0']
    #stdout.write(" | Match: {0} | ".format(match))
    #stdout.write(".")
    # Run this loop until we have a unique IP
    while ip_unverified:
        ip_unverified = False
        # Create the capture and ip dictionaries, need these in the loops for random network selection
        # print "cap_ip:  {0}/{1}".format(cap_ip.ip, cap_ip.prefixlen)
        cap_oct = get_host_octets(cap_ip)
        cap_mask = cap_ip.prefixlen

        if map_ip:
            # print "map_ip:  {0}/{1}".format(map_ip.ip, map_ip.prefixlen)
            map_oct = get_host_octets(map_ip)
            map_mask = map_ip.prefixlen

        # IP Creation Matches
        # If there's an exact (network) match, we want to make an exact host match (if IP is a host address)
        if (match == 'exact' or match == 'exact_net') and map_ip:
            # First octet
            if cap_oct['octet0']['type'] == 'net':
                octets[0] = map_oct['octet0']['val']
            elif cap_oct['octet0']['type'] == 'nethost':
                octets[0] = map_oct['rand_net']
            # Second octet
            if cap_oct['octet1']['type'] == 'net':
                octets[1] = map_oct['octet1']['val']
            elif cap_oct['octet1']['type'] == 'nethost':
                # If the network is correct, we just need a random number for this octet...
                if match == 'exact_net':
                    rand_net = int(map_oct['octet1']['val'])
                # if the network is not established, we need to generate a new net and host
                else:
                    # This is the randomly chosen number for the fake network
                    rand_net = int(map_oct['rand_net'])
                # Get the size of this network
                rand_range = get_net_size(map_ip, idx=1)
                # Create a random host IP using the chosen network and host range
                octets[1] = str(randrange(rand_net, ((rand_net + rand_range) - 1)))
            elif cap_oct['octet1']['type'] == 'host':
                octets[1] = cap_oct['octet1']['val']
            # Third Octet
            if cap_oct['octet2']['type'] == 'net':
                octets[2] = map_oct['octet2']['val']
            elif cap_oct['octet2']['type'] == 'nethost':
                # If the network is correct, we just need a random number for this octet...
                if match == 'exact_net':
                    rand_net = int(map_oct['octet2']['val'])
                # if the network is not established, we need to generate a new net and host
                else:
                    # This is the randomly chosen number for the fake network
                    rand_net = int(map_oct['rand_net'])
                rand_range = get_net_size(map_ip, idx=2)
                # Create a random host IP using the chosen network and host range
                octets[2] = str(randrange(rand_net, ((rand_net + rand_range) - 1)))
            elif cap_oct['octet2']['type'] == 'host':
                octets[2] = cap_oct['octet2']['val']
            # Fourth Octet
            if cap_oct['octet3']['type'] == 'nethost':
                # If the network is correct, we just need a random number for this octet...
                if match == 'exact_net':
                    rand_net = int(map_oct['octet1']['val'])
                # if the network is not established, we need to generate a new net and host
                else:
                    # This is the randomly chosen number for the fake network
                    rand_net = int(map_oct['rand_net'])
                rand_range = get_net_size(map_ip, idx=3)
                # Create a random host IP using the chosen network and host range
                octets[3] = str(randrange(rand_net, ((rand_net + rand_range) - 1)))
            elif cap_oct['octet3']['type'] == 'host':
                if cap_mask == 32:
                    octets[3] = str(randrange(1,254))
                else:
                    octets[3] = cap_oct['octet3']['val']
        # Must be a network IP
        # If there's a partial (network) match, we want to make an exact network match
        elif match == 'partial' and map_ip:
            #print "Rand Net: {0}".format(cap_oct['rand_net'])
            # Create the IP...
            # If the captured mask is less than 16 bits, we can use the first octet (8 bits) of the matched IP
            # First octet possibilities...
            octets[0] = map_oct['octet0']['val']
            # Fourth octet possibilities...
            if cap_oct['octet3']['type'] == 'nethost':
                octets[3] = cap_oct['rand_net']
            elif cap_oct['octet3']['type'] == 'host':
                octets[3] = '0'
            # Check for mask specific possibilities...
            if cap_mask < 16:
                # Second octet options...
                if cap_oct['octet1']['type'] == 'nethost':
                    octets[1] = cap_oct['rand_net']
                elif cap_oct['octet1']['type'] == 'host':
                    octets[1] = '0'
                # Third octet options...
                if cap_oct['octet2']['type'] == 'nethost':
                    octets[2] = cap_oct['rand_net']
                elif cap_oct['octet2']['type'] == 'host':
                    octets[2] = '0'
            # If the captured mask is less than 24 bits, we can use the first two octets (16 bits) of the matched IP
            elif cap_mask < 24:
                octets[1] = map_oct['octet1']['val']
                # Third octet options...
                if cap_oct['octet2']['type'] == 'nethost':
                    octets[2] = cap_oct['rand_net']
                elif cap_oct['octet2']['type'] == 'host':
                    octets[2] = '0'
            # If the captured mask is more than 24 bits, we can use the first three octets (24 bits) of the matched IP
            else:
                octets[1] = map_oct['octet1']['val']
                octets[2] = map_oct['octet2']['val']
        # This should match networks which match
        elif match == 'partial-net' and map_ip:
            pass
        # If no match has been made, we want to make a general network match...
        # This creates the inital network for the match to build on.
        else:
            octets = generate_random_ipv4(cap_oct, octets)

        # Combine octets into an IPv4 address
        try:
            new_ip = IPNetwork(".".join(octets) + "/" + str(cap_mask))
        except Exception as err:
            ip_unverified = True
        # If IP format is valid
        else:
            # If there has been 5 duplicates, create a random network IP
            if dup_count == 10:
                octets = generate_random_ipv4(cap_oct, octets)
                new_ip = IPNetwork(".".join(octets) + "/" + str(cap_mask))
                print "\nDuplicate Error, Created Random Mapping - {0} | New IP: {1}".format(one_dict, new_ip)
                ip_unverified = False

            # Check network_ld for duplicates
            if network_ld:
                for one_dict in network_ld:
                    if one_dict['ls_ip'].ip == new_ip.ip and one_dict['ls_ip'].prefixlen == new_ip.prefixlen:
                        ip_unverified = True
                        #print "Duplicated Network IP - Existing: {0} | New: {1}/{2}".format(one_dict, new_ip.ip, new_ip.prefixlen)
                        dup_count += 1
                        break
            # Check host_ld for duplicates
            if host_ld:
                for one_dict in host_ld:
                    if one_dict['ls_ip'].ip == new_ip.ip  and one_dict['ls_ip'].prefixlen == new_ip.prefixlen:
                        ip_unverified = True
                        #print "Duplicate Host IP - Existing: {0} | New: {1}/{2}".format(one_dict, new_ip.ip, new_ip.prefixlen)
                        break

    # Return the newly created IP
    return new_ip


# Check if this IP is in the IP mapping dictionary
def check_host_ld(map_ld, cap_ip):
    results = {'match': 'none', 'ip': ''}
    if map_ld:
        for map_ip in map_ld:
            # Check for an exact match of IPs
            if cap_ip.ip == map_ip['hs_ip'].ip:
                #print "Exact Host Match: {0} matches {1}".format(cap_ip.ip, map_ip['hs_ip'].ip)
                results['match'] = 'exact'
                results['ip'] = map_ip['ls_ip']
                break
    return results


# Check if this IP is in the NET mapping dictionary
def check_net_ld(cap_ip):
    # The dictionary of terms to return
    results = {'match': 'none', 'ip': '', 'net': False}
    # Check if this IP is a network or host IP
    is_network = False
    if cap_ip.ip == cap_ip.network and cap_ip.prefixlen < 32: is_network = True
    # Check for list dictionary and loop over the entries
    if network_ld:
        for map_net in network_ld:
            # If this is a network IP...
            if is_network:
                results['net'] = True
            # This is true if both networks are exactly the same, perfect match
            if cap_ip == map_net['hs_ip']:
                results['match'] = "exact"
                results['ip'] = map_net['ls_ip']
                break
            # This is true if the captured network is contained within the map network
            elif cap_ip in map_net['hs_ip']:
                results['match'] = "partial"
                results['ip'] = map_net['ls_ip']
                break
            # This is true if the captured network does not match
            else:
                pass
    # This should return the longest match because of the sorting
    return results


# Scans the IP list and creates replacement IPs
# Capture LD (cap_ip) are the captured IPs from the document
def populate_ld(ip_list):
    # Loop over the captured ip list
    for cap_ip in ip_list:
        #print("Create Mapping For --> {0}/{1}".format(str(cap_ip.ip), str(cap_ip.prefixlen)))

        # Check if this IP is IPv6 or IPv4
        if valid_ipv6(str(cap_ip.ip)): is_ipv6 = True
        else: is_ipv6 = False

        # Check if this is a host or network address
        #if cap_ip.ip == cap_ip.network and cap_ip.prefixlen < 32: is_network = True
        #else: is_network = False

        # Check if this IP is in the IP mapping dictionary
        exact_match = False
        net_match = False
        net_mapping = True

        # Continue this loop until the original IP is matched
        while net_mapping:
            # Check the IP database to see if this host exists
            host_results = check_host_ld(host_ld, cap_ip)
            # Check if this IP is a IPv6 address
            if is_ipv6:
                new_ip = generate_ipv6(cap_ip, )
                pass
            # Otherwise, its an IPv4 address
            else:
                # If the IP was NOT found in the database
                if host_results['match'] == 'none':

                    # Check the Network database for a network match
                    net_results = check_net_ld(cap_ip)
                    #print "Network LD"
                    #print "**********"
                    #pprint(network_ld)
                    #print "Matched: {0}".format(net_results['ip'])
                    # If an exact match was made with the net map ...
                    if net_results['match'] == "exact":
                        #stdout.write("-> Network Exact Match -> ")
                        # If this IP is a network...
                        if net_results['net']:
                            #print " Matching Network IP"
                            #print "\tNo New Entry Needed!!!"
                            net_mapping = False
                        # If this IP is a host and this network is the correct network
                        else:
                            #print " Matching Host IP"
                            new_ip = generate_ipv4(cap_ip, net_results['ip'], match='exact_net')
                            #print "\tNew Host Entry: {0} -> {1}".format(cap_ip, new_ip)
                            new_entry = {"hs_ip": cap_ip, "ls_ip": new_ip}
                            host_ld.append(new_entry)

                    # If a partial match was made with the net map ...
                    elif net_results['match'] == "partial":
                        #stdout.write("-> Network Partial Match -> ")
                        # If this IP is a network ...
                        if net_results['net'] and cap_ip.prefixlen < 32:
                            #print " Matching Network IP"
                            new_ip = generate_ipv4(cap_ip, net_results['ip'], match='partial')
                            #print "\tNew Network Entry: {0} -> {1}".format(cap_ip, new_ip)
                            new_entry = {"hs_ip": cap_ip, "ls_ip": new_ip}
                            network_ld.append(new_entry)
                            sort_network_ld()
                        # If this IP is a host ...
                        else:
                            # If this IP is a /32 host ...
                            if cap_ip.prefixlen == 32:
                                #print " Matching /32 Host IP"
                                # Create a host address, the first partial match on a /32 will be the closest network match
                                new_ip = generate_ipv4(cap_ip, net_results['ip'], match='exact_net')
                                # Add this new host IP to the host list dictionary
                                #print "\tNew Host Entry: {0} -> {1}".format(cap_ip, new_ip)
                                new_entry = {"hs_ip": cap_ip, "ls_ip": new_ip}
                                host_ld.append(new_entry)
                            # If this IP is a non-/32 host ...
                            else:
                                #print " Matching Non/32 Host IP"
                                # Create a new network address using the matching address
                                new_ip = generate_ipv4(cap_ip, net_results['ip'], match='partial')
                                # Check if this IP is a new network or a host ...
                                if new_ip.prefixlen == cap_ip.prefixlen and new_ip.network != new_ip.ip:
                                    #print "\tNew Host Entry: {0} -> {1}".format(cap_ip, new_ip)
                                    new_entry = {"hs_ip": cap_ip, "ls_ip": new_ip}
                                    host_ld.append(new_entry)
                                # Otherwise, this is a partial match still...
                                else:
                                    masked_ip = str(cap_ip.network) + "/" + str(cap_ip.prefixlen)
                                    netip = IPNetwork(masked_ip)
                                    #print "\tNew Network Entry: {0} -> {1}".format(netip, new_ip)
                                    new_entry = {"hs_ip": netip, "ls_ip": new_ip}
                                    network_ld.append(new_entry)
                                    sort_network_ld()

                    # This should only execute on the first pass when the LD has nothing to match against
                    elif net_results['match'] == "none":
                        #print "\tHost None Match!"
                        # Create a new network address with the nearest classful address
                        new_ip = ''
                        top_net = "0.0.0.0/0"
                        octets = str(cap_ip.ip).split('.')
                        if cap_ip.prefixlen < 16:
                            #print "\tCreating a Class A Network!"
                            # Create a /8 network for this IP
                            top_net = octets[0] + ".0.0.0/8"
                        elif cap_ip.prefixlen < 24:
                            #print "\tCreating a Class B Network!"
                            # Create a /16 network for this IP
                            top_net = octets[0] + "." + octets[1] + ".0.0/16"
                        else:
                            #print "\tCreating a Class C Network!"
                            # Create a /24 network for any other IPs
                            top_net = octets[0] + "." + octets[1] + "." + octets[2] + ".0/24"
                        # Generate the new mapping
                        new_ip = generate_ipv4(IPNetwork(top_net), match='none')
                        new_entry = {"hs_ip": IPNetwork(top_net), "ls_ip": new_ip}
                        network_ld.append(new_entry)
                        sort_network_ld()
                        #print "Network_LD"
                        #pprint(network_ld)
                # If the IP was found...
                elif host_results['match'] == 'exact':
                    #print " .......... {0} -> {1} Complete!".format(cap_ip.ip,  host_results['ip'])
                    #stdout.write("|")
                    net_mapping = False
        #print "\n- Popluate Function Complete -"

# START OF SCRIPT #
if __name__ == '__main__':
    try:
        detect_env()
    except Exception as err:
        print "Problem detecting OS type..."
        quit()
    # Argument Parser
    # User will either provide an input_file or a folder structure to walk through and scrub all text-based files.
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', action='store', dest='input_file', help='input file or folder')
    parser.add_argument('-i', action='store', dest='ipmap_file', help='ipmap support file')
    args = parser.parse_args()

    # Input arguments
    input_file = os.path.join(dir_path, args.input_file)
    ipmap_file = os.path.join(dir_path, args.ipmap_file)

    # Main Program Loop
    print "********************************************"
    print "*       ASCII File Scrubbing Utility       *"
    print "********************************************"
    print " Input File: {0}".format(input_file)
    print " IPMap File: {0}".format(ipmap_file)
    print "********************************************"
    print "##############################"
    print "# Starting Main Program Loop #"
    print "##############################\n"
    capture_ld = []
    try:
        # Run this if the argument is a directory...
        file_list = []
        if os.path.isdir(input_file):
            txt_ext = [".log", ".txt", ".conf"]
            print "#############################"
            print "# Text Files to be Scrubbed #"
            print "#############################\n"
            for root, directories, filenames in os.walk(input_file):
                for directory in directories:
                    # print os.path.join(root, directory)
                    pass
                for filename in filenames:
                    # print os.path.join(root, filename)
                    if filename.endswith(tuple(txt_ext)):
                        print "- {0}".format(filename)
                        file_list.append(os.path.join(root, filename))
                        # pprint(file_list)
        # Run this if argument is a file
        else:
            file_list.append(input_file)
            print "- {0}".format(ntpath.basename(input_file))

        if not getTFAnswer("Continue with scrubbing these files"):
            print "Exiting Scrubbing Utility..."
            exit(0)

        # Load the exclude list dictionary
        print "\n######################"
        print "# Create IP Mappings #"
        print "######################\n"
        stdout.write("-> Loading exclude list dictionary ... ")
        load_ipmap()
        print "Done!"
        # Collect the IPs from the text file(s) and put into a list
        stdout.write("-> Extracting IPs from the text file(s) ... ")
        if file_list:
            capture_list = extract_file_ips(file_list)
        else:
            print "No files defined for scrubbing!"
            exit(0)

        # Process the list (remove excluded IPs, sorts, converts to list of dictionaries, removes duplicates)
        stdout.write("-> Processing the IP list ... ")
        ip_list = process_capture_list(capture_list)
        print "Done!"

        # Create Map List Dictionary
        stdout.write("-> Creating IP mappings ")
        map_ld = populate_ld(ip_list)
        print " Done!"

        # Loop over the files to be scrubbe
        print "\n##############################"
        print "# Scrubbing Individual Files #"
        print "##############################\n"
        for input_file in file_list:
            # Perform Replacement Function
            print "-> Processing file: {0}".format(ntpath.basename(input_file))

            # Replace IPs
            stdout.write("\t-> Replacing targeted IPs ... ")
            replaced_list = replace_ips(input_file)
            print "Done!"
            #pprint(network_ld)
            #print "HOSTS:"
            #pprint(host_ld)

            # Create File From Results List
            orig_filename = ntpath.basename(input_file)
            myfile = os.path.join(scrub_dir, "[SCRUB]-" + orig_filename)
            stdout.write("\t-> Writing File ... ")
            if list_to_txt(myfile, replaced_list):
                print "Done!"
            else:
                print "Failed: Conversion to text file failed!".format(myfile)
    except KeyboardInterrupt:
        print 'Exiting...'
        exit(0)

    else:
        print "\n############################"
        print "# Completed Scrubbing Task #"
        print "############################"
        exit(0)
