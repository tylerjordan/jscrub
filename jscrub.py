__copyright__ = "Copyright 2018 Tyler Jordan"
__version__ = "0.1.1"
__email__ = "tjordan@juniper.net"

import argparse
import ntpath

from operator import itemgetter
from random import randrange, randint
from sys import stdout
from netaddr import IPAddress, IPNetwork
from utility import *
from pprint import pprint

# Global Lists
textmap_list = []
regexmap_list = []
exclude_list = []

# Global Directories
search_dir = ''
scrub_dir = ''


def detect_env():
    """ Purpose: Detect OS and create appropriate path variables
    :param: None
    :return: None
    """
    global search_dir
    global scrub_dir

    dir_path = os.path.dirname(os.path.abspath(__file__))
    if platform.system().lower() == "windows":
        # print "Environment Windows!"
        search_dir = os.path.join(dir_path, "search_folder")
        scrub_dir = os.path.join(dir_path, "scrubbed_files")

    else:
        # print "Environment Linux/MAC!"
        search_dir = os.path.join(dir_path, "search_folder")
        scrub_dir = os.path.join(dir_path, "scrubbed_files")

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
        sys.exit(0)
        # Print exclude list
        # print "Exclude List: {0}".format(exclude_list)
        # Print include list
        # print "Textmap List: {0}".format(textmap_list)


# Function for extracting the IPs from the input files
def extract_file_ips(input_files):
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
                            "{0,1}[0-9]))(\/([1][0-1][0-9]|[1][2][0-8]|[0-9][0-9]))?")
    regexs = [ipv4_regex, ipv6_regex]
    # Create list of interesting items
    capture_list = []
    for input_file in input_files:
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
def replace_ips(input_files, map_ld):
    # Create list of interesting items
    capture_list = []
    # Load targeted scrub file into a list
    line_list = txt_to_list(input_file)
    # Check for content using provided regexs
    # print "Starting scan of {0}:".format(input_file)
    if line_list:
        # Loop over list of lines
        for line in line_list:
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
            # Loop over the replacement list dictionary
            for map_d in map_ld:
                if map_d['hs_ip'] in line:
                    new_line = re.sub(map_d['hs_ip'], map_d['ls_ip'], line)
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
    #print "Capture List:"
    #pprint(capture_list)
    return capture_list


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
        elif ":" in raw_ip:
            mydict = {'ip': raw_ip, 'mask': '128'}
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
            # print "Found duplicate ip: {0} mask: {1} !!!".format(mydict['ip'], mydict['mask'])
            pass
    # Return
    return new_ld


# Provide a mask as a string and get the number of network octets
# Creates an IP using a network ip/mask or just mask
# /0 - /7 -> Not defined
# /8 - /15 -> Randomize 1st octet, keep last 3
# /16 - /23 -> Randomize first 2 octets, keep last 2
# /24 - /31 -> Randomize first 3 octets, keep last 1
# /32 -> Randomize all octets
#
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


# If a network is provided, the network portion of the IP address will be used.
# LS_IP: Low side IP, from map database
# LS_MASK: Low side mask, from map database
# HS_IP: High side IP, captured IP
# HS_MASK: High side mask, captured MASK
# MAP_LD: The map database
def generate_ipv4(ls_ip, ls_mask, map_ld=[], hs_ip=0, hs_mask=0):
    # print "ls_ip: {0}".format(ls_ip)
    # print "ls_mask: {0}".format(ls_mask)
    # print "hs_ip: {0}".format(hs_ip)
    # print "hs_mask: {0}".format(hs_mask)
    not_valid = True
    new_ip = ''
    ls_net = get_net_octets(ls_mask)
    ls_octets = ls_ip.split(".")
    # print "LS OCTETS: {0}".format(ls_octets)
    if hs_ip:
        hs_net = get_net_octets(hs_mask)
        hs_octets = hs_ip.split(".")
    octets = ['0', '0', '0', '0']
    # Perform this loop until we have a valid / non-duplicate IP address
    while not_valid:
        # The following IF/ELSE use
        if hs_ip:
            if ls_net == 3:
                octets[0] = ls_octets[0]
                octets[1] = ls_octets[1]
                octets[2] = ls_octets[2]
                if hs_net == 4:
                    octets[3] = hs_octets[3]
            elif ls_net == 2:
                octets[0] = ls_octets[0]
                octets[1] = ls_octets[1]
                if hs_net == 3:
                    octets[2] = str(randrange(1, 254))
                    octets[3] = hs_octets[3]
                elif hs_net == 4:
                    octets[2] = str(randrange(1, 254))
                    octets[3] = str(randrange(1, 254))
            elif ls_net == 1:
                octets[0] = ls_octets[0]
                if hs_net == 2:
                    octets[1] = str(randrange(1, 254))
                    octets[2] = hs_octets[2]
                    octets[3] = hs_octets[3]
                elif hs_net == 3:
                    octets[1] = str(randrange(1, 254))
                    octets[2] = str(randrange(1, 254))
                    octets[3] = hs_octets[3]
                elif hs_net == 4:
                    octets[1] = str(randrange(1, 254))
                    octets[2] = str(randrange(1, 254))
                    octets[3] = str(randrange(1, 254))
            # Completely random address
            elif ls_net == 0:
                octets[0] = str(randrange(1, 254))
                octets[1] = str(randrange(1, 254))
                octets[2] = str(randrange(1, 254))
                octets[3] = str(randrange(1, 254))
        # Execute this if no partial match is made
        else:
            if ls_net == 3 or ls_net == 4:
                octets[0] = str(randrange(1, 254))
                octets[1] = str(randrange(1, 254))
                octets[2] = str(randrange(1, 254))
                octets[3] = ls_octets[3]
            elif ls_net == 2:
                octets[0] = str(randrange(1, 254))
                octets[1] = str(randrange(1, 254))
                octets[2] = ls_octets[2]
                octets[3] = ls_octets[3]
            elif ls_net == 1:
                octets[0] = str(randrange(1, 254))
                octets[1] = ls_octets[2]
                octets[2] = ls_octets[2]
                octets[3] = ls_octets[3]
        # Combine the octets
        new_ip = ".".join(octets)
        # print "NEW IP: {0}".format(new_ip)
        # Make sure the IP is not an excluded IP or a existing map substitution
        not_valid = False
        if map_ld:
            # print "MAP_LD:"
            # pprint(map_ld)
            for map_ip in map_ld:
                if new_ip == map_ip['ls_ip']:
                    # print "Duplicate IP created, {0} trying again...".format(new_ip)
                    not_valid = True
            for exc_ip in exclude_list:
                if new_ip == exc_ip:
                    # print "Created excluded IP, {0} trying again...".format(new_ip)
                    not_valid = True
    return new_ip


# Scans the IP list and creates replacement IPs
def populate_ld(capture_ld):
    # Populated List Dictionary
    map_ld = []
    is_ipv6 = False
    # Loop over the high side list dictionary
    for cap_ip in capture_ld:
        # Check if this IP is IPv6 or IPv4
        #print "Scanning: {0}".format(cap_ip['ip'])
        if ":" in cap_ip['ip']:
            is_ipv6 = True
        else:
            is_ipv6 = False
        # Loop over the content from file
        exact_match = False
        net_match = False
        stars = "*" * 30
        # print "\n{1} {0} [START] {1}".format(cap_ip['ip'], stars)
        # Execute this if we have entries in the map_ld
        if map_ld:
            map_d = {}
            # Loop over the populated map list dictionary
            for map_ips in map_ld:
                hs_ip_mask = map_ips['hs_ip'] + "/" + map_ips['mask']
                cap_ip_mask = cap_ip['ip'] + "/" + cap_ip['mask']
                # Check if this is an exact match
                if cap_ip_mask == hs_ip_mask:
                    exact_match = True
                    print "Exact Match: {0} is an exact match of {1}".format(cap_ip_mask, hs_ip_mask)
                    break
                # Compare high side IPs from the map_ld and capture_ld
                elif IPNetwork(cap_ip_mask) in IPNetwork(hs_ip_mask):
                    net_match = True
                    print "Network Match: {0} is a subnet of {1}".format(cap_ip_mask, hs_ip_mask)
                    map_d = {'ls_ip': map_ips['ls_ip'], 'ls_mask': map_ips['mask'], 'cap_ip': cap_ip['ip'],
                             'cap_mask': cap_ip['mask']}
            # Run this if a match was made...
            if exact_match:
                print "No changeds needed!"
            elif net_match:
                ls_ip_mask = map_d['ls_ip'] + "/" + map_d['ls_mask']
                cap_ip_mask = map_d['cap_ip'] + "/" + map_d['cap_mask']
                # print "-> Using Low-side Address: {0}".format(ls_ip_mask)
                if is_ipv6:
                    new_ip = generate_ipv6(map_d['ls_ip'], map_d['ls_mask'], map_ld, map_d['cap_ip'],
                                           map_d['cap_mask'])
                else:
                    new_ip = generate_ipv4(map_d['ls_ip'], map_d['ls_mask'], map_ld, map_d['cap_ip'],
                                         map_d['cap_mask'])
                # print "-> New Mapping is: HS_IP: {0} Mask: {1} LS_IP: {2}".format(map_d['cap_ip'],
                #                                                                  map_d['cap_mask'], new_ip)
                map_dict = {'ls_ip': new_ip, 'mask': map_d['cap_mask'], 'hs_ip': map_d['cap_ip']}
                map_ld.append(map_dict)
                # quit()
            # Run this if no match was found. Create an IP and add it to the map_ld
            else:
                if is_ipv6:
                    new_ip = generate_ipv6(cap_ip['ip'], cap_ip['mask'], map_ld=map_ld)
                else:
                    # print "-> No match found"
                    new_ip = generate_ipv4(cap_ip['ip'], cap_ip['mask'], map_ld=map_ld)
                    # print "-> New Mapping is: HS_IP: {0} Mask: {1} LS_IP: {2}".format(cap_ip['ip'],
                    #                                                                  cap_ip['mask'], new_ip)
                map_dict = {'ls_ip': new_ip, 'mask': cap_ip['mask'], 'hs_ip': cap_ip['ip']}
                map_ld.append(map_dict)
        # If there are no entries in map_ld, create a new entry
        else:
            if is_ipv6:
                new_ip = generate_ipv6(cap_ip['ip'], cap_ip['mask'], map_ld=map_ld)
            else:
                # print "-> No entries in map database"
                new_ip = generate_ipv4(cap_ip['ip'], cap_ip['mask'], map_ld=map_ld)
                # print "-> New Mapping is: HS_IP: {0} Mask: {1} LS_IP: {2}".format(cap_ip['ip'], cap_ip['mask'],
                #                                                                  new_ip)
            map_dict = {'ls_ip': new_ip, 'mask': cap_ip['mask'], 'hs_ip': cap_ip['ip']}
            map_ld.append(map_dict)
                # print "{1} {0} [END] {1}\n".format(cap_ip['ip'], stars)
    # Return map list dictionary
    return map_ld


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
            print "#############"
            print "# File List #"
            print "#############"
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

        # Load the exclude list dictionary
        print "********************************************"
        stdout.write("-> Loading exclude list dictionary ... ")
        load_ipmap()
        print "Done!"
        # Collect the IPs from the text file(s) and put into a list
        stdout.write("-> Extracting IPs from the text file(s) ... ")
        capture_list = extract_file_ips(file_list)
        print "Done!"

        # Process the list (remove excluded IPs, sorts, converts to list of dicionaries, removes duplicates)
        stdout.write("-> Processing the IP list ... ")
        capture_ld = process_capture_list(capture_list)
        print "Done!"

        # Create Map List Dictionary
        stdout.write("-> Creating IP mappings ... ")
        map_ld = populate_ld(capture_ld)
        print "Done!"
        print "********************************************\n"

        # Loop over the files to be scrubbe
        print "##############################"
        print "# Scrubbing Individual Files #"
        print "##############################"
        for input_file in file_list:
            # Perform Replacement Function
            print "-> Processing file: {0}".format(input_file)

            # Replace IPs
            stdout.write("\t-> Replacing targeted IPs ... ")
            replaced_list = replace_ips(input_file, map_ld)
            print "Done!"

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
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
    else:
        print "\n############################"
        print "# Completed Scrubbing Task #"
        print "############################"
        sys.exit(0)
