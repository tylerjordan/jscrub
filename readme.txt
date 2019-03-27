Program: jscrub.py
Author: Tyler Jordan (tjordan@juniper.net)
Python: 2.7
Python Library Requirements: argparse, ntpath, netaddr
Tested Platforms: Windows/Linux/JunOS (running 16.1)

File Structure:
jscrub.py  --> the Python script 
readme.txt --> this readme file
ipmap.txt  --> the file that controls excluded text, text-mappings, and text-regexs
[scrubbed_files]  --> the directory where scrubbed files will be placed

Description: A python program that can scrub text-based files, such as logs or configurations. The scrubber is capable of scrubbing IPv4/v6 addresses, password hashes, other regex terms, and keywords. It replaces IPv4 formatted addresses with random addressing, but attempts to maintain the consistency of the file. The IPv6 replacement performs a random replacement. It can replace specific text strings with defined replacements and, using regular expressions, perform replacements of text strings that match a regular expression. 

Single File Scrub: The program can scrub a single file placed in the root of the script directory. It can scrub any ASCII plain-text files with ".log", ".txt", and ".conf" extensions. It can be easily modified for other extensions as well. The program does not modified the supplied files, but creates new "scrubbed" files in the directory "scrubbed_files". A "[SCRUB]-" prefix is added to files to denote that they have been scrubbed.  

Recursive Scrub: The program can also scan a directory structure recursively and scrub files. It will drill down into a directory structure and attempt to scrub any files with the appoproiate file extensions.

How To Use:

On a server/workstation:
------------------------
To Scrub a Single File:
Syntax: python jscrub.py -i <ipmap_file> -s <text_file>

> python jscrub.py -i ipmap.txt -s test.txt

To Scrub an entire directory recursively:
Syntax: python jscrub.py -i <ipmap_file> -s <directory> 

> python jscrub.py -i ipmap.txt -s search_folder


On a Juniper running JunOS 16.1 or later:
-----------------------------------------
	1. Transfer script files to Juniper directory: /var/db/scripts/op

	2. Add the following configuration to the Juniper:
		system scripts op file jscrub.py
		system scripts op file jscrub.py arguments i description "The IPMAP file"
		system scripts op file jscrub.py arguments s description "The input file or directory"
		system scripts language python

	3. Run script from the CLI:
		user@host> op jscrub.py i <ipmap_file> s <text_file>


Script Output:
--------------
The script will place all scrubbed files in the "scrubbed_files" directory located at the root of the script.

IPMAP File Format:
------------------
The ipmap file contains a list of excluded IP addresses, located under 'EXCLUDE' . These IP addresses and any addresses that fall within their subnets will NOT be manipulated. There are a number of predefined IPs in the default ipmap file which include well-known IPs and ranges.

Under the 'EXCLUDE' list is the 'TEXT-MAPPING' section which contains the keywords and their replacements. Each line represents a text string that will be removed and its replacement. The first term is the text that will be removed and the second term is the text that is to take its place.

Under the 'TEXT-MAPPING' list is the 'TEXT-REGEX' section which contains regular expressions for matching. It works similar to the 'TEXT-MAPPING' section, the regex matches text with the first term and replaces with the text in the second term.

IPMAP Example:
--------------
EXCLUDE
0.0.0.0/8
100.64.0.0/10
127.0.0.0/8
169.254.0.0/16
172.16.0.0/12
192.0.0.0/24
192.0.2.0/24
192.168.0.0/16
198.18.0.0/15
198.51.100.0/24
203.0.113.0/24
224.0.0.0/3
255.0.0.0/8

TEXT-MAPPING
USER-DATA,VLAN1
SERVER-VLAN,VLAN2

TEXT-REGEX
"\$\d\$.*",HASH
