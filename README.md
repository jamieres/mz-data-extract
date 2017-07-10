# MZ-Data-Extract
MZ-Data-Extract is a simple tool that you can use for collect relevant data of Portable Executable (PE) files that can be used for Intel during a line of research related with malware. All information collected can be used for Intel purposes. It support PE 32bits and 64bits for executables files type EXE, DLL, SYS, SCR, CPL, MSI, COM and at the moment just work in *NIX-Based distros.

This tool should always be accompanied by the file "packerdb.txt" to work. If you try to get information from a file that is not MZ and/or don't use the mentioned file together with the tool, you will see the following message in red color: "It isn't a PE file or missing file packerdb.txt. Please, check it and try again."
Please check accordingly.

For historical information about this tool please read file "CHANGELOG". 
For samples tested information please read file "FILES_TESTED_TODO".
For know wath information you can obtain with this tools please read file "REPORT_EXAMPLE".

Usage syntaxis is: ./mzde.py [filepath]

** Requires:
-->> First, remember run the following commands:
# apt-get update 
# apt-get upgrade
# apt-get install python-pip

Then just run "requirements.txt" file using the command -->> pip install -r requirements.txt

But if you prefer to install the packages separately, follow the instructions for each case:

* PEfile: https://github.com/erocarrera/pefile 
# apt-get install python-pefile 

* Magic: https://pypi.python.org/pypi/python-magic
# pip install python-magic

* SSDeep: http://ssdeep.sourceforge.net
# pip install ssdeep

* FuzzyHashLib: https://pypi.python.org/pypi/fuzzyhashlib
# pip install fuzzyhashlib

  -->> This package is required for get SDHash data, but if you have any problem with package install process, can install SDHash separately:
    * SDHash: https://pypi.python.org/pypi/sdhash
    # pip install sdhash
        
      -->> Maybe you need install requires distributions for SDHash separately. Please use following commands:
        # pip install NumPy or visit https://pypi.python.org/pypi/numpy
        # pip install SciPy or visit https://pypi.python.org/pypi/scipy
        # pip install Pillow

***** By default, SDHash option is disabled because the string is too long. If you want to know this data, please uncomment the line 83, or line "print Fore.WHITE + Style.NORMAL + "SDHash: %s" % Style.DIM + fuzzyhashlib.sdhash(data).hexdigest()" and save change.
***** Fuzzy-Hash Algorithms just show data, this process don't compare files. 
 
* Bitstring: https://github.com/scott-griffiths/bitstring
# apt-get install python-bitstring

* argparser: https://code.google.com/archive/p/argparse/
# apt-get install python-argparse

* colorama: https://pypi.python.org/pypi/colorama/
# apt-get install python-colorama

DISCLAIMER: This tool was written for internal and personal use and tested, at the moment, just under Ubuntu 16.04. Please use the tool at your own risk.

AUTHOR: Jorge (Pistus) Mieres
Email: jamieres-[at]-gmail-[dot]-com. 
Twitter: @jorgemieres
