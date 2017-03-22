# mz-data-extract
MZ-Data-Extract is a simple tool that you can use for collect relevant data of Portable Executable (PE) files that can be used for Intel during a line of research related with malware. All information collected can be used for Intel purposes. It support PE 32bits and 64bits for executables files type EXE, DLL, SYS, SCR, CPL, MSI, COM and at the moment just work in *NIX-Based distros.***

The fisrt version (0.1) was released in September 24, 2016 by Jorge (Pistus) Mieres - jamieres@gmail.com. For historical information about this tool please read file "CHANGELOG".

Usage syntaxis is: ./mzde.py [filepath]

Just testing under Ubuntu 16.04

## *** This tool was written for internal and personal use. Please use the tool at your own risk.

##### Requires #####
First, remember run the command sudo apt-get update for update the operating system and then install following packages:

PEfile
For install PEfile (Python PE parsing module) you can be downloaded it from https://github.com/erocarrera/pefile or run the following command sudo apt-get install python-pefile.

SSDeep
For install SSDeep you can download the package from http://ssdeep.sourceforge.net/ or run following command sudo apt-get install ssdeep.

Bitstring
For install Bitstrings you can download it from https://github.com/scott-griffiths/bitstring or run the command sudo apt-get install python-bitstring.

argparser
Download it from https://code.google.com/archive/p/argparse/ or run the command sudo apt-get install python-argparse

colorama
Download it from https://pypi.python.org/pypi/colorama/ or run the command sudo apt-get install python-colorama.
