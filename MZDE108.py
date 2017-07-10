#!/usr/bin/env python
# -*- coding: utf-8 -*-

__description__ = 'MZ-Data-Extract is a simple tool that you can use for collect relevant data of Portable Executable (PE) files that can be used for Intel during a line of research related with malware.'
__version__ = '1.0.8'
__author__ = 'Jorge (Pistus) Mieres'
__contact__ = 'jamieres-[at]-gmail-[dot]-com'

"""
Requires:
See README file.

Changelog:
2017/04/07 v1.0.6
2017/06/27 v1.0.7

2017/07/07 v1.0.8
=> Add SdHash information (uncomment line option).
=> Rewrite Filetype and Mimetype data extraction.

** For complete reference about history of this tool please real file "CHANGELOG".
"""

import sys,os,re,subprocess,datetime,time,shlex,stat,magic,colorama,hashlib,binascii,ssdeep,nilsimsa,fuzzyhashlib,bz2,string,bitstring,struct,pefile,peutils,argparse
from colorama import Fore, Back, Style, init
from pefile import PE, PEFormatError
from time import gmtime, strftime
from hashlib import sha256
from bz2 import compress
from struct import pack
init()

try:
  filename = sys.argv[1]
  pe = pefile.PE(filename)
  packer = peutils.SignatureDatabase('packerdb.txt')
  fdata = magic.Magic(mime=True, uncompress=True)

except:
        print(Fore.RED + "It isn't a PE file or missing file packerdb.txt. Please, check it and try again.")
        sys.exit(1)

else:
  filename = sys.argv[1]

with open(filename, "rb") as s:
      r = s.read()

over = pe.get_overlay_data_start_offset()
raw = pe.write()
data = open(sys.argv[1], "rb").read()
printable = set(string.printable)
file_stats = os.stat(filename)
ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
ep_ad = ep + pe.OPTIONAL_HEADER.ImageBase
ssd = ssdeep.hash(data)
magic = magic.from_file(sys.argv[1])
mimetype = fdata.from_file(sys.argv[1])
NETINT = open(filename, 'rb')
PDB = open(filename, 'rb')
hosts= open(filename,'r').readlines()
adbg = ['AddVectoredExceptionHandler','CheckRemoteDebuggerPresent','CloseHandle','DbgBreakPoint','DbgUiRemoteBreakin','DebugActiveProcess','FindWindow','GenerateConsoleCtrlEvent','GetLocalTime','GetSystemTime','GetTickCount','GetWindowThreadProcessId','HideThreadFromDebugger','IsDebugged','IsDebuggerPresent','NtClose','NtGlobalFlag','NtQueryObject','NtQueryPerformanceCounter','NtQuerySystemInformation','NtSetInformationThread','ObsidianGUI','OutputDebugString','Process32First','Process32Next','QueryInformationProcess','QueryPerformanceCounter','ReadTEB','RemoveVectoredExceptionHandler','RockDebugger','SetConsoleCtrlHandler','SetInformationThread','SetThreadContext','SetUnhandledExceptionFilter','TerminateProcess','UnhandledExceptionFilter','UnhandledExceptionFilter','WinDbgFrameClass', 'ZwQueryInformationProcess','Zeta Debugger','ZwQueryInformation','ZwQuerySystemInformation','ZwSetInformationThread','timeGetTime','vbaExceptHandler','GetThreadContext','SetThreadContext','NtContinue','Trap flag','timeGetTime','rdtsc','ZwDebugActiveProcess']
avm = {"Red Pill":"\x0f\x01\x0d\x00\x00\x00\x00\xc3","VirtualPC trick":"\x0f\x3f\x07\x0b","VMCheck.dll":"\x45\xC7\x00\x01","VMCheck.dll for VirtualPC":"\x0f\x3f\x07\x0b\xc7\x45\xfc\xff\xff\xff\xff","Bochs & QEmu CPUID Trick":"\x44\x4d\x41\x63","Torpig VMM Trick": "\xE8\xED\xFF\xFF\xFF\x25\x00\x00\x00\xFF\x33\xC9\x3D\x00\x00\x00\x80\x0F\x95\xC1\x8B\xC1\xC3","Torpig (UPX) VMM Trick": "\x51\x51\x0F\x01\x27\x00\xC1\xFB\xB5\xD5\x35\x02\xE2\xC3\xD1\x66\x25\x32\xBD\x83\x7F\xB7\x4E\x3D\x06\x80\x0F\x95\xC1\x8B\xC1\xC3","Virtual Box":"VBox","VBoxVideo.sys":"VBoxVideo.sys","VIRTUALBOX":"VIRTUALBOX","Xen":"XenVMM","XenVMMXenVMM":"XenVMMXenVMM","xennet.sys":"xennet.sys","VMware":"WMvare","VMware trick":"VMXh","VMTools":"VMTools","VMMEMCTL":"VMMEMCTL","vmx_svga.sys":"vmx_svga.sys","vmmouse.sys":"vmmouse.sys","vmsrvc.exe":"vmsrvc.exe","vmtoolsd.exe":"vmtoolsd.exe","vmusrvc.exe":"vmusrvc.exe","vmwaretray.exe":"vmwaretray.exe","VmRemoteGuest.exe":"VmRemoteGuest.exe","QEMU":"QEMU","Ven_Red_Hat&Prod_VirtIO":"Ven_Red_Hat&Prod_VirtIO","DiskVBOX":"DiskVBOX","DiskVirtual":"DiskVirtual","Wine String Artifact (wine_get_unix_file_name)":"wine_get_unix_file_name","KVMKVMKVM":"KVMKVMKVM","prl hyperv":"prl hyperv","Microsoft Hv":"Microsoft Hv","HARDWARE\\Description\\System":"HARDWARE\\Description\\System","HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0":"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0","SOFTWARE\\Oracle\\VirtualBox Guest Additions":"SOFTWARE\\Oracle\\VirtualBox Guest Additions","SOFTWARE\\VMware, Inc.\\VMware Tools":"SOFTWARE\\VMware, Inc.\\VMware Tools","\VMware\VMware Tools":"\VMware\VMware Tools","VirtualMachine":"VirtualMachine","vmicheartbeat":"vmicheartbeat","vmwareuser.exe":"vmwareuser.exe","vmwaretray.exe":"vmwaretray.exe","vmdebug":"vmdebug","vboxservice.exe":"vboxservice.exe","vboxtray.exe":"vboxtray.exe","VBoxMouse":"VBoxMouse","VBoxGuest":"VBoxGuest","VBoxSF":"VBoxSF",}
malreg = ["HKEY_CURRENT_USER","HKEY_CLASSES_ROOT","HKEY_LOCAL_MACHINE","autorun.inf","HKLM_SOFTWARE_MICROSOFT_WINDOWS_CURRENTVERSION_RUN"]
file_info = {"fsize": round((file_stats [stat.ST_SIZE] / 1024) /1024.0, 3),}

print Fore.BLUE + Style.BRIGHT + "\n### File Characterization"
print "-------------------------"
print Fore.WHITE + Style.NORMAL + "  Filename: " + Style.DIM + str(sys.argv[1])
print Fore.WHITE + Style.NORMAL + "  Filepath: " + Style.DIM + str(os.path.realpath(sys.argv[1]))
print Fore.WHITE + Style.NORMAL + "  Filesize: " + Style.DIM + str(os.path.getsize(sys.argv[1])) + " bytes", (Fore.GREEN + "(%(fsize)s Megabytes)" % file_info)
print Fore.WHITE + Style.NORMAL + "  Filetype: " + Style.DIM + magic
print Fore.WHITE + Style.NORMAL + "  Mimetype: " + Style.DIM + mimetype
print 
print Fore.WHITE + Style.NORMAL + "  DLL file (Dynamic-Link Library): ", Style.DIM + str(pe.is_dll())
print Fore.WHITE + Style.NORMAL + "  EXE file (Executable): ", Style.DIM + str(pe.is_exe())
print Fore.WHITE + Style.NORMAL + "  SYS file (System): ", Style.DIM + str(pe.is_driver())
print Fore.BLUE + Style.BRIGHT + "\n  ## Fingerprint Information"
print Fore.WHITE + Style.NORMAL + "  MD5: " + Style.DIM + hashlib.md5(data).hexdigest()
print Fore.WHITE + Style.NORMAL + "  Sha1: " + Style.DIM + hashlib.sha1(data).hexdigest()
print Fore.WHITE + Style.NORMAL + "  Sha256: " + Style.DIM + hashlib.sha256(data).hexdigest()
print Fore.WHITE + Style.NORMAL + "  Sha512: " + Style.DIM + hashlib.sha512(data).hexdigest()
print Fore.BLUE + Style.BRIGHT + "\n    # Fuzzy-Hash Algorithm"
print Fore.WHITE + Style.NORMAL + "    SSDeep: " + Style.DIM + ssd
print Fore.WHITE + Style.NORMAL + "    ImpHASH: %s" % Style.DIM + pe.get_imphash()
#print Fore.WHITE + Style.NORMAL + "    SDHash: %s" % Style.DIM + fuzzyhashlib.sdhash(data).hexdigest()


print Fore.BLUE + Style.BRIGHT + "\n  ## Header & Packer Technique"
def parseheader(header):
  fields = struct.unpack("<HHHHHHHHHHHHHH", header)
  signature = "".join([chr(fields[0] & 0xFF), chr(fields[0] >> 8)])
  print Fore.WHITE + Style.NORMAL + "  Signature: %s" % Style.DIM + signature

if __name__ == "__main__": 
  parser = argparse.ArgumentParser()
  parser.add_argument("filename")
  args = parser.parse_args()
  filename = args.filename
  f = open(filename, "r")
  header = f.read(0x1C)
  parseheader(header)

packer = peutils.SignatureDatabase('packerdb.txt')
matches = packer.match_all(pe, ep_only = True)
print Fore.WHITE + Style.NORMAL + "  Packer/Compiler: " + Style.DIM + str(matches)

print Fore.BLUE + Style.BRIGHT + "\n\n### Advanced Information for Intel"
print "----------------------------------"
print Fore.WHITE + Style.NORMAL + "  TimeStamp:", Style.DIM + str(datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)) 
print Fore.WHITE + Style.NORMAL + "  EntryPoint: " + Style.DIM + hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
print Fore.WHITE + Style.NORMAL + "  EntryPoint Address: " + Style.DIM + "0x%07x" % ep_ad

print Fore.BLUE + Style.BRIGHT + "\n  ## Properties Information"
if hasattr(pe, 'VS_VERSIONINFO'):
  if hasattr(pe, 'FileInfo'):
    for entry in pe.FileInfo:
      if hasattr(entry, 'StringTable'):
        for st_entry in entry.StringTable:
          for str_entry in st_entry.entries.items():
	     print Fore.WHITE + Style.NORMAL + "  " + str_entry[0] + ': ' + Style.DIM + str_entry[1]

print Fore.BLUE + Style.BRIGHT + "\n  ## Classic Autorun.inf file Data"
def autorun_info():
        for line in hosts:
                for calls in malreg:
                        if re.search(calls, line):
                                print Fore.WHITE + Style.NORMAL + "  " + calls,line
def acheck():
	autorun_info()
acheck()

print Fore.BLUE + Style.BRIGHT + "\n  ## URL/IP Information"
def ab(stream):
    found_str = ""
    while True:
        data = stream.read(1024*4)
        if not data:
            break
        for char in data:
            if char in printable:
                found_str += char
            elif len(found_str) >= 4:
                yield found_str
                found_str = ""
            else:
                found_str = ""

def cd():

		for found_str in ab(NETINT):
			print found_str
		PEtoStr.close()

esomalint = 0
for found_str in ab(NETINT):
			url = re.findall("((http|ftp|mailto|telnet|ssh)(s){0,1}\:\/\/[\w|\/|\.|\#|\?|\&|\=|\-|\%]+)+", found_str, re.IGNORECASE | re.MULTILINE)
			if url:
				print Fore.WHITE + Style.NORMAL + "  " + url[0][0]
				esomalint = esomalint + 1

print Fore.BLUE + Style.BRIGHT + "\n  ## PDB full pathway data"
esomalint2 = 0
for found_str in ab(PDB):
   pistuspdb = re.findall(r"(\D*\w*\s*\S*\W*\.(pdb))+", found_str, re.IGNORECASE | re.MULTILINE | re.DOTALL | re.UNICODE | re.VERBOSE)

   if pistuspdb:
	print Fore.WHITE + Style.NORMAL + "  " + pistuspdb[0][0]
        esomalint2 = esomalint2 + 1

print Fore.BLUE + Style.BRIGHT + "\n\n### Detected possible Evasion-Techniques/Maneuvers commonly used by malware"
print "---------------------------------------------------------------------------"
print Fore.BLUE + Style.BRIGHT + "  ## Anti-Debugging Techniques Founded"
for dbg in pe.DIRECTORY_ENTRY_IMPORT:
		for imp in dbg.imports:
			if (imp.name != None) and (imp.name != ""):
				for anti in adbg:
					if imp.name.startswith(anti):
						print "  %s %s" % (Fore.RED + Style.NORMAL + hex(imp.address), imp.name)

print Fore.BLUE + Style.BRIGHT + "\n  ## Anti-VirtualMachine Techniques Founded"
with open(filename,"rb") as f:
    buf = f.read()
    for trick in avm:
        pos = buf.find(avm[trick])
        if pos > -1:
	     print ("  " + Fore.RED + Style.NORMAL + "0x%x %s") % (pos, trick)

print Fore.BLUE + Style.BRIGHT + "\n\n  ## Sections Information"
print Fore.BLUE + Style.NORMAL + "\t============================================================================================================"
print Fore.WHITE + "\tSection\t   VirtualAddress\tVirtualSize\tSizeofRawData\tCharacteristics\t  Suspicious"
print Fore.BLUE + "\t============================================================================================================"
for section in pe.sections:
			section.get_entropy()
			if section.SizeOfRawData == 0 or (section.get_entropy() > 0 and section.get_entropy() < 1) or section.get_entropy() > 9:
				suspicious = Fore.RED + Style.NORMAL + "Possible Malicious Action"
			else:
				suspicious = Fore.GREEN + Style.NORMAL + ""

			print Fore.WHITE + Style.NORMAL + "\t%s\t   %s\t\t%s\t\t%s\t\t%s\t  %s" % (section.Name, hex(section.VirtualAddress),hex(section.Misc_VirtualSize),section.SizeOfRawData,hex(section.Characteristics),suspicious)
			print "\tMD5:",section.get_hash_md5()
print Fore.BLUE + Style.NORMAL + "\t============================================================================================================\n"
print Fore.BLUE + Style.BRIGHT + "### Import/Export Address Table Information"
print "-------------------------------------------"
print Fore.BLUE + Style.BRIGHT + "\n  ## Import Address Table"
i = 1
for entry in pe.DIRECTORY_ENTRY_IMPORT:
                bool = 1  
                print Fore.BLUE + Style.BRIGHT + "     " + entry.dll
                for imp in entry.imports:
                        if bool:
                                print Fore.WHITE + Style.NORMAL + "\t", Fore.MAGENTA + hex(imp.address), Fore.WHITE + str(imp.name), 
                                bool = 0
                        else:
                                sys.stdout.write("%s%s%s%s" % ("\n\t", Fore.MAGENTA + hex(imp.address)," ", Fore.WHITE + str(imp.name))) 
                i += 1
		print

print Fore.BLUE + Style.BRIGHT + "\n\n  ## Export Address Table"
try:
  for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    print Fore.MAGENTA + Style.NORMAL + "\t", hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), Fore.WHITE + Style.NORMAL + exp.name, exp.ordinal
except:
	print Fore.YELLOW + Style.DIM + "     ** No data in this section **"

print Fore.BLUE + Style.BRIGHT + "\n\n  ## Appended Data (Overlay)"
def CIC(expression):
    if callable(expression):
        return expression()
    else:
        return expression

def IFF(expression, valueTrue, valueFalse):
    if expression:
        return CIC(valueTrue)
    else:
        return CIC(valueFalse)

def NumberOfBytesHumanRepresentation(value):
    if value <= 1024:
        return '%s bytes' % value
    elif value < 1024 * 1024:
        return '%.1f KB' % (float(value) / 1024.0)
    elif value < 1024 * 1024 * 1024:
        return '%.1f MB' % (float(value) / 1024.0 / 1024.0)
    else:
        return '%.1f GB' % (float(value) / 1024.0 / 1024.0 / 1024.0)

if over == None:
        print Fore.YELLOW + Style.DIM + "     ** No data in this section ** " 

else:
        print Fore.BLUE + Style.BRIGHT + "   # Appended Data: " 
        print Fore.WHITE + Style.NORMAL + "  Offset: " + Style.DIM + "0x%08x" % over
        overlaySize = len(raw[over:])
        print Fore.WHITE + Style.NORMAL + "  Size: " + Style.DIM + "0x%08x [%s] %.2f%%" % (overlaySize, NumberOfBytesHumanRepresentation(overlaySize), float(overlaySize) / float(len(raw)) * 100.0)
        print Fore.WHITE + Style.NORMAL + "  MD5: " + Style.DIM + "%s" % hashlib.md5(raw[over:]).hexdigest()
	print Fore.WHITE + Style.NORMAL + "  SHA1: " + Style.DIM + "%s" % hashlib.sha1(raw[over:]).hexdigest()
        print Fore.WHITE + Style.NORMAL + "  SHA256: " + Style.DIM + "%s" % hashlib.sha256(raw[over:]).hexdigest()
        
        overlayMagic = raw[over:][:4]
        if type(overlayMagic[0]) == int:
            overlayMagic = "".join([chr(b) for b in overlayMagic])
        print Fore.WHITE + Style.NORMAL + "  Magic: " + Style.DIM + "%s %s" % (binascii.b2a_hex(overlayMagic), "".join([IFF(ord(b) >= 32, b, ".") for b in overlayMagic]))

        print Fore.BLUE + Style.BRIGHT + "\n   # Without Appended Data:"
        print Fore.WHITE + Style.NORMAL + "  MD5: " + Style.DIM + "%s" % hashlib.md5(raw[:over]).hexdigest()
        print Fore.WHITE + Style.NORMAL + "  SHA1: " + Style.DIM + "%s" % hashlib.sha1(raw[:over]).hexdigest()
        print Fore.WHITE + Style.NORMAL + "  SHA256: " + Style.DIM + "%s" % hashlib.sha256(raw[:over]).hexdigest()

print Fore.BLUE + Style.DIM + "\n###############################################################\t"
print Fore.BLACK + Style.BRIGHT + "\t  Malware" + Fore.BLUE + Style.NORMAL + "Intelligence" + Fore.WHITE + Style.NORMAL + "\twww.malwareint.com"
print Fore.YELLOW + Style.DIM + "   Analysis date: " + strftime("%A, %B %d, %Y [%I:%M:%S %p]\n", gmtime())

