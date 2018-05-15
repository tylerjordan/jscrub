# File: utility.py
# Author: Tyler Jordan
# Modified: 2/23/2018
# Purpose: Assist CBP engineers with Juniper configuration tasks

import sys, re, os, csv
import fileinput
import glob
import math
import paramiko  # https://github.com/paramiko/paramiko for -c -mc -put -get
import subprocess
import datetime
import platform
import operator
import time

from os import listdir
from os.path import isfile, join, exists
from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from jnpr.junos.exception import ConnectError
from jnpr.junos.exception import LockError
from jnpr.junos.exception import UnlockError
from jnpr.junos.exception import ConfigLoadError
from jnpr.junos.exception import CommitError
from ncclient import manager  # https://github.com/ncclient/ncclient
from ncclient.transport import errors
from sys import stdout

# --------------------------------------
# ANSWER METHODS
#--------------------------------------
# Method for asking a question that has a single answer, returns answer
def getOptionAnswer(question, options):
    answer = ""
    loop = 0
    while not answer:
        print "\n" + question + ':\n'
        options.append('Quit')
        for option in options:
            loop += 1
            print '[' + str(loop) + '] -> ' + option
        answer = raw_input('\nYour Selection: ')
        print "*" * 50
        try:
            if int(answer) >= 1 and int(answer) <= loop:
                index = int(answer) - 1
                if options[index] == 'Quit':
                    return False
                else:
                    return options[index]
        except Exception as err:
            print "Invalid Entry - ERROR: {0}".format(err)
        else:
            print "Bad Selection"
        answer = ""
        loop = 0

# Method for asking a question that can have multiple answers, returns list of answers
def getOptionMultiAnswer(question, options):
    answer_str = ""
    loop = 0
    while not answer_str and options:
        print "\n" + question + ':\n'
        for option in options:
            loop += 1
            print '[' + str(loop) + '] -> ' + option
        answer_str = raw_input('\nYour Selections: ')
        print "*" * 50
        try:
            answer_list = []
            index_list = answer_str.split(",")
            for answer in index_list:
                index = int(answer) - 1
                answer_list.append(options[index])
            return answer_list
        except Exception as err:
            print "Invalid Entry - ERROR: {0}".format(err)
        else:
            print "Bad Selection"
        answer_str = ""
        loop = 0

# Method for asking a question that has a single answer, returns answer index
def getOptionAnswerIndex(question, options):
    answer = ""
    loop = 0
    while not answer:
        print "\n" + question + ':\n'
        for option in options:
            loop += 1
            print '[' + str(loop) + '] -> ' + option
        answer = raw_input('\nYour Selection: ')
        print "*" * 50
        try:
            if int(answer) >= 1 and int(answer) <= loop:
                return answer
        except Exception as err:
            print "Invalid Entry - ERROR: {0}".format(err)
        else:
            print "Bad Selection"
        answer = ""
        loop = 0

# Method for asking a user input question
def getInputAnswer(question):
    answer = ""
    while not answer:
        answer = raw_input(question + ': ')
    return answer

# Method for asking a user input question that can have multiple answers
def getMultiInputAnswer(question):
    answer_list = []
    answer = "placeholder"
    while answer:
        answer = raw_input(question + ': ')
        if answer:
            answer_list.append(answer)
    return answer_list

# Method for asking a Y/N question
def getYNAnswer(question):
    answer = ""
    while not answer:
        print ""
        answer = raw_input(question + '(y/n): ')
        print ""
        if answer == 'Y' or answer == 'y':
            answer = 'y'
        elif answer == 'N' or answer == 'n':
            answer = 'n'
        else:
            print "Bad Selection"
            answer = ""
    return answer

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

# Return list of files from a directory with an optional extension filter
def getFileList(mypath, ext_filter=False):
    tmpList = []
    fileList = []
    if exists(mypath):
        if ext_filter:
            pattern = mypath + '*.' + ext_filter
            # Sorts the files by modification time
            tmpList = sorted([x for x in glob.glob(pattern)], key=os.path.getmtime, reverse=True)
        else:
            tmpList = sorted([x for x in glob.glob(mypath + '*')], key=os.path.getmtime, reverse=True)
        #except Exception as err:
        #    print "Error accessing files {0} - ERROR: {1}".format(mypath, err)
        for f in tmpList:
            fileList.append(f[len(mypath):])
    else:
        print "Path: {0} does not exist!".format(mypath)
    return fileList

# Method for requesting IP address target
def getTarget():
    print 64*"="
    print "= Scan Menu" + 52*" " + "="
    print 64*"="
    # Loop through the IPs from the file "ipsitelist.txt"
    loop = 0
    list = {};
    for line in fileinput.input('ipsitelist.txt'):
        # Print out all the IPs/SITEs
        loop += 1
        ip,site = line.split(",")
        list[str(loop)] = ip;
        print '[' + str(loop) + '] ' + ip + ' -> ' + site.strip('\n')

    print "[c] Custom IP"
    print "[x] Exit"
    print "\n"

    response = ""
    while not response:
        response = raw_input("Please select an option: ")
        if response >= "1" and response <= str(loop):
            return list[response]
        elif response == "c":
            capturedIp = ""
            while not capturedIp:
                capturedIp = raw_input("Please enter an IP: ")
                return capturedIp
        elif response == "x":
            response = "exit"
            return response
        else:
            print "Bad Selection"

# This function creates a list of IPs from the IP
def extract_ips(ip):
    iplist = []
    ip_mask_regex = re.compile("^([1][0-9][0-9].|^[2][5][0-5].|^[2][0-4][0-9].|^[1][0-9][0-9].|^[0-9][0-9].|^[0-9].)"
                               "([1][0-9][0-9].|[2][5][0-5].|[2][0-4][0-9].|[1][0-9][0-9].|[0-9][0-9].|[0-9].)"
                               "([1][0-9][0-9].|[2][5][0-5].|[2][0-4][0-9].|[1][0-9][0-9].|[0-9][0-9].|[0-9].)"
                               "([1][0-9][0-9]|[2][5][0-5]|[2][0-4][0-9]|[1][0-9][0-9]|[0-9][0-9]|[0-9])"
                               "/([8]|[9]|1[0-9]|2[0-9]|3[0-1])$")
    ip_only_regex = re.compile("^([1][0-9][0-9].|^[2][5][0-5].|^[2][0-4][0-9].|^[1][0-9][0-9].|^[0-9][0-9].|^[0-9].)"
                               "([1][0-9][0-9].|[2][5][0-5].|[2][0-4][0-9].|[1][0-9][0-9].|[0-9][0-9].|[0-9].)"
                               "([1][0-9][0-9].|[2][5][0-5].|[2][0-4][0-9].|[1][0-9][0-9].|[0-9][0-9].|[0-9].)"
                               "([1][0-9][0-9]|[2][5][0-5]|[2][0-4][0-9]|[1][0-9][0-9]|[0-9][0-9]|[0-9])$")
    if ip_mask_regex.match(ip):
        try:
            n1 = ipaddress.ip_network(ip)
        except ValueError as err:
            print "Invalid IP address - skipping {0}".format(ip)
            return iplist
        else:
            for one_ip in n1.hosts():
                print "Adding IP: {0}".format(one_ip)
                iplist.append(str(one_ip))
    elif ip_only_regex.match(ip):
        print "Adding single IP: {0}".format(ip)
        iplist.append(ip)
    else:
        print "Invalid IP Format: {0} ... Ignoring".format(ip)

    return iplist

# Removes duplicates and sorts IPs intelligently
def check_sort(ip_list):
    # First remove all duplicates
    checked = []
    for ip in ip_list:
        if ip not in checked:
            checked.append(ip)

    # Sorting function
    for i in range(len(checked)):
        checked[i] = "%3s.%3s.%3s.%3s" % tuple(checked[i].split("."))
    checked.sort()
    for i in range(len(checked)):
        checked[i] = checked[i].replace(" ", "")

    return checked

# Converts listDict to CSV file
def listDictCSV(myListDict, filePathName, keys):
    addKeys = True
    if (os.path.isfile(filePathName)):
        addKeys = False
    try:
        f = open(filePathName, 'a')
    except Exception as err:
        print "Failure opening file in append mode - ERROR: {0}".format(err)
        print "Be sure {0} isn't open in another program.".format(filePathName)
    else:
        if addKeys:
            #Write all the headings in the CSV
            for akey in keys[:-1]:							# Runs for every element, except the last
                f.write(akey + ",")							# Writes most elements
            f.write(keys[-1])								# Writes last element
            f.write("\n")

        for part in myListDict:
            for bkey in keys[:-1]:
                #print "BKey: " + bkey + "  Value: " + part[bkey]
                f.write(str(part[bkey]) + ",")
            f.write(str(part[keys[-1]]))
            f.write("\n")
        f.close()
        #print "\nCompleted appending to CSV."

# Adds a dictionary to a CSV file
def dictCSV(myDict, filePathName, keys):
    addKeys = True
    if (os.path.isfile(filePathName)):
        addKeys = False
    try:
        f = open(filePathName, 'a')
    except Exception as err:
        print "Failure opening file in append mode - ERROR: {0}".format(err)
        print "Be sure {0} isn't open in another program.".format(filePathName)
    else:
        if addKeys:
            #Write all the headings in the CSV
            for akey in keys[:-1]:							# Runs for every element, except the last
                f.write(akey + ",")							# Writes most elements
            f.write(keys[-1])								# Writes last element
            f.write("\n")

        for key in keys[:-1]:
            f.write(str(myDict[key]) + ",")
        f.write(str(myDict[keys[-1]]))
        f.write("\n")
        f.close()
        #print "\nCompleted appending to CSV."

# Converts CSV file to listDict. First line is considered column headers.
def csvListDict(fileName, keys=''):
    myListDict = []
    try:
        with open(fileName) as myfile:
            firstline = True
            for line in myfile:
                if firstline:
                    if not keys:
                        keys = "".join(line.split()).split(',')
                    firstline = False
                else:
                    values = "".join(line.split()).split(',')
                    myListDict.append({keys[n]:values[n] for n in range(0,len(keys))})
    except Exception as err:
        print "Failure converting CSV to listDict - ERROR: {0}".format(err)
    else:
        print "File Import Complete!"
    return myListDict

# Converts CSV file to Dictionary
def csv_to_dict(filePathName):
    input_file = csv.DictReader(open(filePathName))
    for row in input_file:
        pass
    return row

# Takes a text string and creates a top level heading
def topHeading(raw_text, margin):
    head_length = len(raw_text)
    equal_length = head_length + 6

    heading = " " * margin + "+" + "=" * equal_length + "+\n" + \
              " " * margin + "|   " + raw_text + "   |\n" + \
              " " * margin + "+" + "=" * equal_length + "+"

    return heading

# Takes a string and creates a sub heading
def subHeading(raw_text, margin):
    head_length = len(raw_text)
    dash_length = head_length + 2

    heading = " " * margin + "o" + "-" * dash_length + "o\n" + \
              " " * margin + "| " + raw_text + " |\n" + \
              " " * margin + "o" + "-" * dash_length + "o" + "\n"

    return heading

# Takes a string and adds stars to either side
def starHeading(raw_text, head_len):
    heading = ""
    heading += "*" * head_len + "\n"
    if raw_text > head_len:
        half_text_len = int(math.ceil(len(raw_text) / 2))
        half_head_len = int(head_len / 2)
        start_text = half_head_len - half_text_len
        # Create heading
        heading += " " * start_text + raw_text + "\n"
    else:
        heading += raw_text + "\n"
    heading += "*" * head_len + "\n"

    return heading

# Return a specifically formatted timestamp
def get_now_time():
    """ Purpose: Create a formatted timestamp

    :return:            -   String of the timestamp in "YYYY-MM-DD_HHMM" format
    """
    now = datetime.datetime.now()
    return now.strftime("%Y-%m-%d_%H%M")

# Print output to the screen and a log file (either a list or string)
def screen_and_log(statement, file_list):
    # Print to screen
    stdout.write(statement)
    stdout.flush()
    # Print to log
    if type(file_list) is list:
        for log in file_list:
            log_only(statement, log)
    else:
        log_only(statement, file_list)

# Append output to log file only
def log_only(statement, logfile):
    # Print to log
    #print "Log File: {0}".format(logfile)
    try:
        logobj = open(logfile, 'a')
    except Exception as err:
        print "Error opening log file {0}".format(err)
    else:
        logobj.write(statement)
        logobj.close()

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

# Creates a string from a text file
def txt_to_string(src_file):
    # Create a string of the configuration file
    command_file = ""
    try:
        with open(src_file) as f:
            command_file = f.read()
    except Exception as err:
        print "Problems extracting commands from file. ERROR: {0}".format(err)
        return False
    else:
        return command_file

# Pings the provided IP and returns True/False, works on Windows or Linux/Mac
def ping(ip):
    """ Purpose: Determine if an IP is pingable
    :param ip: IP address of host to ping
    :return: True if ping successful
    """
    with open(os.devnull, 'w') as DEVNULL:
        try:
            # Check for Windows or Linux/MAC
            ping_param = "-n" if platform.system().lower() == "windows" else "-c"
            subprocess.check_call(
                ['ping', ping_param, '3', ip],
                stdout=DEVNULL,
                stderr=DEVNULL
            )
            return True
        except subprocess.CalledProcessError:
            return False

# Import variables into config file