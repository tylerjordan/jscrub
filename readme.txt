Program: jscrub.py
Author: Tyler Jordan (tjordan@juniper.net)
Python: 2.7
Python Library Requirements: argparse, ntpath, netaddr
Tested Platforms: Windows/Linux/JunOS (running 16.1) 

Description: A python program that can scrub text-based files, such as logs or configurations. The scrubbing is capable of scrubbing IPv4/v6 addresses, password hashes, other regex terms, and keywords. The IPv4 replacement creates a random replacement, but attempts to maintain the consistency of the file. The IPv6 replacement performs a random replacement.

Target: The target of this program is to scrub text file, logs, and configurations that contain classified information, rendering them unclassified and capable of further troubleshooting by unclassified people.

Recursive Scrub: The program will scan a directory structure recursively and process any files with ".log", ".txt", and ".conf" file extensions. Additional extensions can be added as needed. The program does not modify the actual classified files. The scrubbed contents is placed in a file by the same name with a "[SCRUB]-" prefix.

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

Required File Formats (IPMAP):

The ipmap file contains a list of excluded IP addresses, located under 'EXCLUDE' . These IP addresses and any addresses that fall within their subnets will NOT be manipulated. There are a number of predefined IPs in the default ipmap file which include well-known IPs and ranges.

Under the 'EXCLUDE' list is the 'TEXT-MAPPING' section which contains the keywords and their replacements. Each line represents a text string that will be removed and its replacement. The first term is the text that will be removed and the second term is the text that is to take its place.

Under the 'TEXT-MAPPING' list is the 'TEXT-REGEX' section which contains regular expressions for matching. It works similar to the 'TEXT-MAPPING' section, the regex matches text with the first term and replaces with the text in the second term.

