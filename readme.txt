Program: jscrub.py
Author: Tyler Jordan
Python: 2.7
Lib Requirements: argparse, ntpath, netaddr, utility (included)
Tested Platforms: Windows/Linux/JunOS (running 16.1) 

Description: A python program that can scrub text-based files, such as logs or configurations. The scrubbing is capable of scrubbing IPv4/v6 addresses, password hashes, other regex terms, and keywords.

Target: The target of this program is to scrub text file, logs, and configurations that contain classified information, rendering them unclassified and capable of further troubleshooting by unclassified people.

Recursive Scrub: The program will scan a directory structure recursively and process any files with ".log", ".txt", and ".conf" file extensions. Additional extensions can be added as needed. The program does not modify the actual classified files. The scrubbed contents is placed in a file by the same name with a "[SCRUB]-" prefix.

How To Use:

To Scrub a Single File:
Syntax: python jscrub.py -ipmap <ipmap_file> -file <text_file>

> python jscrub.py -ipmap ipmap.txt -file test.txt

To Scrub an entire directory recursively:
Syntax: python jscrub.py -ipmap <ipmap_file> -file <directory> 

> python jscrub.py -ipmap ipmap.txt -file search_folder

On a Juniper running JunOS 16.1 or later:

	1. Transfer script files to Juniper directory: /var/db/scripts/op

	2. Add the following configuration to the Juniper:
		system scripts op file jscrub.py arguments file
		system scripts op file jscrub.py arguments ipmap
		system scripts language python

	3. Run script from the CLI:
		user@host> op jscrub.py ipmap <ipmap_file> file <text_file>


Script Output:

The script will place all scrubbed files in the "scrubbed_files" directory located in the root of the script.

Required File Formats (IPMAP):

The ipmap file contains a list of excluded IP addresses, located under 'EXCLUDE' . These IP addresses and any addresses that fall within their subnets will NOT be manipulated. There are a number of predefined IPs in the default ipmap file which include well-known IPs and ranges.

Under the 'EXCLUDE' list is the 'TEXT-MAPPING' section which contains the keywords and their replacements. Each line represents a text string that will be removed and its replacement. The first term is the text that will be removed and the second term is the text that is to take its place.

Under the 'TEXT-MAPPING' list is the 'TEXT-REGEX'