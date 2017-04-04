#!/usr/bin/env python
# -*- coding: utf-8 -*-

__description__ = 'MZ-Data-Extract is a simple tool that you can use for collect relevant data of Portable Executable (PE) files that can be used for Intel during a line of research related with malware.'
__version__ = '1.0.5'
__date__ = 'September 21, 2016 (first release [v0.1])'
__author__ = 'Jorge (Pistus) Mieres'
__contact__ = 'jamieres@gmail.com'

"""
Requires:
See file called README.

Changelog:
2016/11/06 v1.0.3
2016/11/10 v1.0.4

2017/04/03 v1.0.5
=> Rewrited code structure.
=> Add ImportHash (via FireEye: https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html)
=> Rewrited "Embedded File Information" code.

** For complete reference about history of this tool please real file "CHANGELOG".
"""

import sys,os,re,subprocess,datetime,time,shlex,stat,colorama,hashlib,binascii,ssdeep,bz2,string,bitstring,struct,pefile,peutils,argparse
from colorama import Fore, Back, Style, init
from pefile import PE, PEFormatError
from time import gmtime, strftime
from hashlib import sha256
from bz2 import compress
from struct import pack
init()

try:
  packer = peutils.SignatureDatabase('packerdb.txt')

except:
	print(Fore.RED + "Missing file: packerdb.txt")
	sys.exit()

if len(sys.argv) != 2:
  init(autoreset=True)
  print Fore.BLUE + "MZ-Data-Extract is a simple tool that you can use for collect relevant data of Portable Executable (PE) files that can be used for Intel during a line of research related with malware. \nError, bugs or comments please write me to jamieres@gmail.com.\n"
  print Fore.WHITE + Back.MAGENTA + Style.BRIGHT + "Usage: mzde.py [filepath]"
  sys.exit()

else:
  filename = sys.argv[1]

with open(filename, "rb") as s:
      r = s.read()

pe = pefile.PE(filename)
over = pe.get_overlay_data_start_offset()
raw = pe.write()
file_name = sys.argv[1]
data = open(sys.argv[1], "rb").read()
printable = set(string.printable)
file_stats = os.stat(file_name)
ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
ep_ad = ep + pe.OPTIONAL_HEADER.ImageBase
ssd = ssdeep.hash(data)
# cmd = shlex.split("file --mime-type {0}".format(file_name))
# result = subprocess.check_output(cmd)
# mimetype = result.split()[-1]
magic = subprocess.check_output(["file", "-b", file_name])
mimetype = subprocess.check_output(["file", "--mime-type", "-b", file_name])
NETINT = open(file_name, 'rb')
adbg = ['AddVectoredExceptionHandler','CheckRemoteDebuggerPresent','CloseHandle','DbgBreakPoint','DbgUiRemoteBreakin','DebugActiveProcess','FindWindow','GenerateConsoleCtrlEvent','GetLocalTime','GetSystemTime','GetTickCount','GetWindowThreadProcessId','HideThreadFromDebugger','IsDebugged','IsDebuggerPresent','NtClose','NtGlobalFlag','NtQueryObject','NtQueryPerformanceCounter','NtQuerySystemInformation','NtSetInformationThread','ObsidianGUI','OutputDebugString','Process32First','Process32Next','QueryInformationProcess','QueryPerformanceCounter','ReadTEB','RemoveVectoredExceptionHandler','RockDebugger','SetConsoleCtrlHandler','SetInformationThread','SetThreadContext','SetUnhandledExceptionFilter','TerminateProcess','UnhandledExceptionFilter','UnhandledExceptionFilter','WinDbgFrameClass', 'ZwQueryInformationProcess','Zeta Debugger','ZwQueryInformation','ZwQuerySystemInformation','ZwSetInformationThread','timeGetTime','vbaExceptHandler','GetThreadContext','SetThreadContext','NtContinue','Trap flag','timeGetTime','rdtsc','ZwDebugActiveProcess']
avm = {"Red Pill":"\x0f\x01\x0d\x00\x00\x00\x00\xc3",
"VirtualPC trick":"\x0f\x3f\x07\x0b",
"VMCheck.dll":"\x45\xC7\x00\x01",
"VMCheck.dll for VirtualPC":"\x0f\x3f\x07\x0b\xc7\x45\xfc\xff\xff\xff\xff",
"Bochs & QEmu CPUID Trick":"\x44\x4d\x41\x63",
"Torpig VMM Trick": "\xE8\xED\xFF\xFF\xFF\x25\x00\x00\x00\xFF\x33\xC9\x3D\x00\x00\x00\x80\x0F\x95\xC1\x8B\xC1\xC3",
"Torpig (UPX) VMM Trick": "\x51\x51\x0F\x01\x27\x00\xC1\xFB\xB5\xD5\x35\x02\xE2\xC3\xD1\x66\x25\x32\xBD\x83\x7F\xB7\x4E\x3D\x06\x80\x0F\x95\xC1\x8B\xC1\xC3",
"Virtual Box":"VBox",
"VBoxVideo.sys":"VBoxVideo.sys",
"VIRTUALBOX":"VIRTUALBOX",
"Xen":"XenVMM",
"XenVMMXenVMM":"XenVMMXenVMM",
"xennet.sys":"xennet.sys",
"VMware":"WMvare",
"VMware trick":"VMXh",
"VMTools":"VMTools",
"VMMEMCTL":"VMMEMCTL",
"vmx_svga.sys":"vmx_svga.sys",
"vmmouse.sys":"vmmouse.sys",
"vmsrvc.exe":"vmsrvc.exe",
"vmtoolsd.exe":"vmtoolsd.exe",
"vmusrvc.exe":"vmusrvc.exe",
"vmwaretray.exe":"vmwaretray.exe",
"VmRemoteGuest.exe":"VmRemoteGuest.exe",
"QEMU":"QEMU",
"Ven_Red_Hat&Prod_VirtIO":"Ven_Red_Hat&Prod_VirtIO",
"DiskVBOX":"DiskVBOX",
"DiskVirtual":"DiskVirtual",
"KVMKVMKVM":"KVMKVMKVM",
"prl hyperv":"prl hyperv",
"Microsoft Hv":"Microsoft Hv",
"HARDWARE\\Description\\System":"HARDWARE\\Description\\System",
"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0":"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
"SOFTWARE\\Oracle\\VirtualBox Guest Additions":"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
"SOFTWARE\\VMware, Inc.\\VMware Tools":"SOFTWARE\\VMware, Inc.\\VMware Tools",
"\VMware\VMware Tools":"\VMware\VMware Tools",
"VirtualMachine":"VirtualMachine",
"vmicheartbeat":"vmicheartbeat",
"vmwareuser.exe":"vmwareuser.exe",
"vmwaretray.exe":"vmwaretray.exe",
"vmdebug":"vmdebug",
"vboxservice.exe":"vboxservice.exe",
"vboxtray.exe":"vboxtray.exe",
"VBoxMouse":"VBoxMouse",
"VBoxGuest":"VBoxGuest",
"VBoxSF":"VBoxSF",
          }
dllh = {
"sbiedll.dll":"sbiedll.dll",
"dbghelp.dll":"dbghelp.dll",
"api_log.dll":"api_log.dll",
"dir_watch.dll":"dir_watch.dll",
"pstorec.dll":"pstorec.dll",
"vmcheck.dll":"vmcheck.dll",
"wpespy.dll":"wpespy.dll",
"dir_watch.dll":"dir_watch.dll",
"tracer.dll":"tracer.dll",
"SbieDll.dll":"SbieDll.dll",
"APIOverride.dll":"APIOverride.dll",
"NtHookEngine.dll":"NtHookEngine.dll",
"api_log.dll":"api_log.dll",
"LOG_API.DLL":"LOG_API.DLL",
"LOG_API32.DLL":"LOG_API32.DLL",
          }
kdrd = {"kbruta.sys":"kbruta.sys","TBM.sys":"TBM.sys",}
aav = {
"avcuf32.dll":"avcuf32.dll",
"BgAgent.dll":"BgAgent.dll",
"guard32.dll":"guard32.dll",
"wl_hook.dll":"wl_hook.dll",
"QOEHook.dll":"QOEHook.dll",
"a2hooks32.dll":"a2hooks32.dll",
"bdsnm.sys":"bdsnm.sys",
"bdsflt.sys":"bdsflt.sys",
"ggc.sys":"ggc.sys",
"catflt.sys":"catflt.sys",
"wsnf.sys":"wsnf.sys",
"llio.sys":"llio.sys",
"mscank.sys":"mscank.sys",
"EMLTDI.SYS":"EMLTDI.SYS",
"vsdatant.sys":"vsdatant.sys",
"360Box.sys":"360Box.sys",
"360Box64.sys":"360Box64.sys",
"360Camera.sys":"360Camera.sys",
"360Camera64.sys":"360Camera64.sys",
"360SelfProtection.sys":"360SelfProtection.sys",
"360AntiHacker.sys":"360AntiHacker.sys",
"360AntiHacker64.sys":"360AntiHacker64.sys",
"360AvFlt.sys":"360AvFlt.sys",
"pctNdis.sys":"pctNdis.sys",
"pctNdisLW64.sys":"pctNdisLW64.sys",
"360AvFlt.sys":"360AvFlt.sys",
"360FsFlt.sys":"360FsFlt.sys",
"K7Sentry.sys":"K7Sentry.sys",
"K7FWFilt.sys":"K7FWFilt.sys",
"K7TdiHlp.sys":"K7TdiHlp.sys",
"tpsec.sys":"tpsec.sys",
"pwipf6.sys":"pwipf6.sys",
"mwfsmflt.sys":"mwfsmflt.sys",
"ProcObsrvesx.sys":"ProcObsrvesx.sys",
"bdfsfltr.sys":"bdfsfltr.sys",
"econceal.sys":"econceal.sys",
"ffsmon.sys":"ffsmon.sys",
"fildds.sys":"fildds.sys",
"filmfd.sys":"filmfd.sys",
"filppd.sys":"filppd.sys",
"kl1.sys":"kl1.sys",
"klif.sys":"klif.sys",
"kltdi.sys":"kltdi.sys",
"kneps.sys":"kneps.sys",
"klkbdflt.sys":"klkbdflt.sys",
"klmouflt.sys":"klmouflt.sys",
"GDBehave.sys":"GDBehave.sys",
"GDNdisIc.sys":"GDNdisIc.sys",
"gdwfpcd64.sys":"gdwfpcd64.sys",
"gdwfpcd32.sys":"gdwfpcd32.sys",
"ABFLT.sys":"ABFLT.sys",
"aswMonFlt.sys":"aswMonFlt.sys",
"aswRvrt.sys":"aswRvrt.sys",
"aswRdr2.sys":"aswRdr2.sys",
"aswVmm.sys":"aswVmm.sys",
"aswNdisFlt.sys":"aswNdisFlt.sys",
"aswSnx.sys":"aswSnx.sys",
"aswSP.sys":"aswSP.sys",
"aswStm.sys":"aswStm.sys",
"avnetflt.sys":"avnetflt.sys",
"avkmgr.sys":"avkmgr.sys",
"avipbb.sys":"avipbb.sys",
"avgntflt.sys":"avgntflt.sys",
"EpfwLWF.sys":"EpfwLWF.sys",
"epfwwfp.sys":"epfwwfp.sys",
"eamonm.sys":"eamonm.sys",
"ehdrv.sys":"ehdrv.sys",
"epfw.sys":"epfw.sys",
"eelam.sys":"eelam.sys",
"Bfilter.sys":"Bfilter.sys",
"Bfmon.sys":"Bfmon.sys",
"Bhbase.sys":"Bhbase.sys",
"avgdiskx.sys":"avgdiskx.sys",
"avgidsdriverlx.sys":"avgidsdriverlx.sys",
"avgtdix.sys":"avgtdix.sys",
"avgunivx.sys":"avgunivx.sys",
          }
file_info = {
   "fsize": round((file_stats [stat.ST_SIZE] / 1024) /1024.0, 3),
   "f_lm": time.strftime("%m.%d.%Y [%I:%M:%S %p]",time.localtime(file_stats[stat.ST_MTIME])),
   "f_la": time.strftime("%m.%d.%Y [%I:%M:%S %p]",time.localtime(file_stats[stat.ST_ATIME])),
   "f_ct": time.strftime("%m.%d.%Y [%I:%M:%S %p]",time.localtime(file_stats[stat.ST_CTIME]))
}
print Fore.BLUE + Style.BRIGHT + "\n### File Characterization"
print "-------------------------"
print Fore.WHITE + Style.NORMAL + "  Filename: " + Style.DIM + str(sys.argv[1])
print Fore.WHITE + Style.NORMAL + "  Filepath: " + Style.DIM + str(os.path.realpath(sys.argv[1]))
print Fore.WHITE + Style.NORMAL + "  Filesize: " + Style.DIM + str(os.path.getsize(sys.argv[1])) + " bytes", (Fore.GREEN + "(%(fsize)s Megabytes)" % file_info)
print Fore.WHITE + Style.NORMAL + "  Mimetype: " + Style.DIM + mimetype
print Fore.WHITE + Style.NORMAL + "  Filetype: " + Style.DIM + magic
print Fore.WHITE + Style.NORMAL + "  DLL file (Dynamic-Link Library): ", Style.DIM + str(pe.is_dll())
print Fore.WHITE + Style.NORMAL + "  EXE file (Executable): ", Style.DIM + str(pe.is_exe())
print Fore.WHITE + Style.NORMAL + "  SYS file (System): ", Style.DIM + str(pe.is_driver())
print Fore.BLUE + Style.BRIGHT + "\n  ## Manipulation Data"
print Fore.WHITE + Style.NORMAL + "  Last Modified: " + Style.DIM + "%(f_lm)s" % file_info + Fore.GREEN + "   " + time.asctime(time.localtime(file_stats[stat.ST_MTIME]))
print Fore.WHITE + Style.NORMAL + "  Last Accessed: " + Style.DIM + "%(f_la)s" % file_info + Fore.GREEN + "   " + time.asctime(time.localtime(file_stats[stat.ST_ATIME]))
print Fore.WHITE + Style.NORMAL + "  Creation Time: " + Style.DIM + "%(f_ct)s" % file_info + Fore.GREEN + "   " + time.asctime(time.localtime(file_stats[stat.ST_CTIME]))
print Fore.BLUE + Style.BRIGHT + "\n  ## Fingerprint Information"
print Fore.WHITE + Style.NORMAL + "  MD5: " + Style.DIM + hashlib.md5(data).hexdigest()
print Fore.WHITE + Style.NORMAL + "  Sha1: " + Style.DIM + hashlib.sha1(data).hexdigest()
print Fore.WHITE + Style.NORMAL + "  Sha256: " + Style.DIM + hashlib.sha256(data).hexdigest()
print Fore.WHITE + Style.NORMAL + "  Sha512: " + Style.DIM + hashlib.sha512(data).hexdigest()
print Fore.BLUE + Style.BRIGHT + "\n    # Fuzzy-Hash Algorithm"
print Fore.WHITE + Style.NORMAL + "    SSDeep: " + Style.DIM + ssd

def pehash(pe_file):
    if isinstance(pe_file, PE):
        exe = pe_file

    else:
        try:
            exe = PE(pe_file, fast_load=True)
        except PEFormatError as exc:
            logging.error("Exception in pefile.PE('%s') - %s", pe_file, exc)
            return

    def align_down_p2(number):
        return 1 << (number.bit_length() - 1) if number else 0

    def align_up(number, boundary_p2):
        assert not boundary_p2 & (boundary_p2 - 1), \
            "Boundary '%d' is not a power of 2" % boundary_p2
        boundary_p2 -= 1
        return (number + boundary_p2) & ~ boundary_p2

    def get_dirs_status():
        dirs_status = 0
        for idx in range(min(exe.OPTIONAL_HEADER.NumberOfRvaAndSizes, 16)):
            if exe.OPTIONAL_HEADER.DATA_DIRECTORY[idx].VirtualAddress:
                dirs_status |= (1 << idx)
        return dirs_status

    def get_complexity():
        complexity = 0
        if section.SizeOfRawData:
            complexity = (len(compress(section.get_data())) *
                          7.0 /
                          section.SizeOfRawData)
            complexity = 8 if complexity > 7 else int(round(complexity))
        return complexity

    characteristics_mask = 0b0111111100100011
    data_directory_mask = 0b0111111001111111
    data = [pack("> H", exe.FILE_HEADER.Characteristics & characteristics_mask),
            pack("> H", exe.OPTIONAL_HEADER.Subsystem),
            pack("> I", align_down_p2(exe.OPTIONAL_HEADER.SectionAlignment)),
            pack("> I", align_down_p2(exe.OPTIONAL_HEADER.FileAlignment)),
            pack("> Q", align_up(exe.OPTIONAL_HEADER.SizeOfStackCommit, 4096)),
            pack("> Q", align_up(exe.OPTIONAL_HEADER.SizeOfHeapCommit, 4096)),
            pack("> H", get_dirs_status() & data_directory_mask)]

    for section in exe.sections:
        data += [
            pack("> I", align_up(section.VirtualAddress, 512)),
            pack("> I", align_up(section.SizeOfRawData, 512)),
            pack("> B", section.Characteristics >> 24),
            pack("> B", get_complexity())]

    if not isinstance(pe_file, PE):
        exe.close()
    data_sha256 = sha256("".join(data)).hexdigest()
    return data_sha256

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(0)
    print Fore.WHITE + Style.NORMAL + "    peHASH: " + Style.DIM + pehash(sys.argv[1])

def totalhash(file_path=None, pe=None, file_data=None, hasher=None, raise_on_error=False):
    if not pe:

        try:
            if file_data:
                exe = pefile.PE(data=file_data)
            elif file_path:
                exe = pefile.PE(file_path)
            else:
                if raise_on_error:
                    raise Exception("Arguments provided is not valid")
                return None

        except Exception as e:
            if raise_on_error:
                raise
            else:
                return None
    else:
        exe = pe

    try:
        img_chars = bitstring.BitArray(hex(exe.FILE_HEADER.Characteristics))
        img_chars = bitstring.BitArray(bytes=img_chars.tobytes())
        img_chars_xor = img_chars[0:8] ^ img_chars[8:16]
        pehash_bin = bitstring.BitArray(img_chars_xor)
        sub_chars = bitstring.BitArray(hex(exe.FILE_HEADER.Machine))
        sub_chars = bitstring.BitArray(bytes=sub_chars.tobytes())
        sub_chars_xor = sub_chars[0:8] ^ sub_chars[8:16]
        pehash_bin.append(sub_chars_xor)
        stk_size = bitstring.BitArray(hex(exe.OPTIONAL_HEADER.SizeOfStackCommit))
        stk_size_bits = string.zfill(stk_size.bin, 32)
        stk_size = bitstring.BitArray(bin=stk_size_bits)
        stk_size_xor = stk_size[8:16] ^ stk_size[16:24] ^ stk_size[24:32]
        stk_size_xor = bitstring.BitArray(bytes=stk_size_xor.tobytes())
        pehash_bin.append(stk_size_xor)
        hp_size = bitstring.BitArray(hex(exe.OPTIONAL_HEADER.SizeOfHeapCommit))
        hp_size_bits = string.zfill(hp_size.bin, 32)
        hp_size = bitstring.BitArray(bin=hp_size_bits)
        hp_size_xor = hp_size[8:16] ^ hp_size[16:24] ^ hp_size[24:32]
        hp_size_xor = bitstring.BitArray(bytes=hp_size_xor.tobytes())
        pehash_bin.append(hp_size_xor)

        for section in exe.sections:
            sect_va =  bitstring.BitArray(hex(section.VirtualAddress))
            sect_va = bitstring.BitArray(bytes=sect_va.tobytes())
            sect_va_bits = sect_va[8:32]
            pehash_bin.append(sect_va_bits)
            sect_rs =  bitstring.BitArray(hex(section.SizeOfRawData))
            sect_rs = bitstring.BitArray(bytes=sect_rs.tobytes())
            sect_rs_bits = string.zfill(sect_rs.bin, 32)
            sect_rs = bitstring.BitArray(bin=sect_rs_bits)
            sect_rs = bitstring.BitArray(bytes=sect_rs.tobytes())
            sect_rs_bits = sect_rs[8:32]
            pehash_bin.append(sect_rs_bits)
            sect_chars =  bitstring.BitArray(hex(section.Characteristics))
            sect_chars = bitstring.BitArray(bytes=sect_chars.tobytes())
            sect_chars_xor = sect_chars[16:24] ^ sect_chars[24:32]
            pehash_bin.append(sect_chars_xor)
            address = section.VirtualAddress
            size = section.SizeOfRawData
            raw = exe.write()[address+size:]

            if size == 0: 
                kolmog = bitstring.BitArray(float=1, length=32)
                pehash_bin.append(kolmog[0:8])
                continue

            bz2_raw = bz2.compress(raw)
            bz2_size = len(bz2_raw)
            k = bz2_size / size
            kolmog = bitstring.BitArray(float=k, length=32)
            pehash_bin.append(kolmog[0:8])

        if not hasher:
            hasher = hashlib.sha1()
        hasher.update(pehash_bin.tobytes())
        return hasher

    except Exception as e:
        if raise_on_error:
            raise
        else:
            return None

def totalhash_hex(file_path=None, pe=None, file_data=None, hasher=None, raise_on_error=False):

    hd = totalhash(file_path, pe, file_data, hasher, raise_on_error)

    if hd:
        return hd.hexdigest()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(0)
    print Fore.WHITE + Style.NORMAL + "    TotalHASH: " + Style.DIM + totalhash_hex(pe=pe)
# http://www.garykessler.net/library/file_sigs.html
print Fore.WHITE + Style.NORMAL + "    ImpHASH: %s" % Style.DIM + pe.get_imphash()

print Fore.BLUE + Style.BRIGHT + "\n  ## Header & Packing Technique"
def parseheader(header):
  fields = struct.unpack("<HHHHHHHHHHHHHH", header)
  signature = "".join([chr(fields[0] & 0xFF), chr(fields[0] >> 8)])
  print Fore.WHITE + Style.NORMAL + "  Signature: %s" % Style.DIM + signature

if __name__ == "__main__": 
  parser = argparse.ArgumentParser("Provide a file to read header from")
  parser.add_argument("filename")
  args = parser.parse_args()
  filename = args.filename
  f = open(filename, "r")
  header = f.read(0x1C)
  parseheader(header)
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

print Fore.BLUE + Style.BRIGHT + "\n\n  ## URL Information"
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

else:
	if esomalint == 0:
		print Fore.YELLOW + Style.DIM + "   ** No data in this section **"

print Fore.BLUE + Style.BRIGHT + "\n\n  ## Embedded File Information"
NETINT = open(file_name, 'rb')
esomalint = 0
for found_str in ab(NETINT):
   jam = re.findall("(\w*\.(sys|log|txt|dat|db|3gp|ini|inf|xml|doc|rtf|xls|ppt|exe|cpl|pas|bat|pdf|swf|jpg|jpeg|bmp|gif|ico|php|asp|aspx|cgi|htm|css|pdb|zip|rar|sfx|cab|nfo|bat|pif|lnk|scr|py|tmp))+", found_str, re.IGNORECASE | re.MULTILINE)

   if jam:
	print Fore.WHITE + Style.NORMAL + "  " + jam[0][0]
        esomalint = esomalint + 1

else:
	if esomalint == 0:
		print Fore.YELLOW + Style.DIM + "   ** No embeddedd files founded **"
print Fore.RED + Style.BRIGHT + "\n\n**** You should discard from this list the files that are displayed in the URL section."

print Fore.BLUE + Style.BRIGHT + "\n\n### Advanced Technical Information"
print "----------------------------------"
print Fore.BLUE + Style.BRIGHT + "  ## Anti-Debugging Techniques Founded"
if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
	print "No found suspicious API"
for dbg in pe.DIRECTORY_ENTRY_IMPORT:
		for imp in dbg.imports:
			if (imp.name != None) and (imp.name != ""):
				for anti in adbg:
					if imp.name.startswith(anti):
						print "  %s %s" % (Fore.RED + Style.NORMAL + hex(imp.address), imp.name)

print Fore.BLUE + Style.BRIGHT + "\n  ## Anti-VirtualMachine Tricks Founded"
with open(filename,"rb") as f:
    buf = f.read()
    for trick in avm:
        pos = buf.find(avm[trick])
        if pos > -1:
	     print ("  " + Fore.RED + Style.NORMAL + "0x%x %s") % (pos, trick)
print Fore.BLUE + Style.BRIGHT + "\n  ## DLL Hooking Strings Founded"
with open(filename,"rb") as f:
    buf = f.read()
    for trick in dllh:
        pos = buf.find(dllh[trick])
        if pos > -1:
	     print Fore.WHITE + ("\t0x%x %s" % (pos, trick))

print Fore.BLUE + Style.BRIGHT + "\n  ## Kernel Driver Check Founded"
with open(filename,"rb") as f:
    buf = f.read()
    for trick in kdrd:
        pos = buf.find(kdrd[trick])
        if pos > -1:
	     print Fore.WHITE + ("\t0x%x %s" % (pos, trick))

print Fore.BLUE + Style.BRIGHT + "\n  ## Anti-AV Tricks Founded"
with open(filename,"rb") as f:
    buf = f.read()
    for trick in aav:
        pos = buf.find(aav[trick])
        if pos > -1:
	     print Fore.WHITE + ("\t0x%x %s" % (pos, trick))
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
print Fore.BLUE + Style.NORMAL + "\t============================================================================================================"
print Fore.BLUE + Style.BRIGHT + "\n\n  ## Import Address Table"
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

