'''
 
Author : Debasish Mandal
Blog :http://www.debasish.in/
Twitter : https://twitter.com/debasishm89
 
A mutation based user mode (ring3) dumb in-memory IOCTL Fuzzer/Logger.
This script attach it self to any given process and hooks DeviceIoControl!Kernel32 API and
try to log or fuzz all I/O Control code I/O Buffer pointer, I/O buffer length that
process sends to any Kernel driver.


'''
try:
	import utils
except ImportError:
	print 'Could not import utils,Get it from https://github.com/OpenRCE/paimei'
import pydbg
from pydbg import *
from pydbg.defines import *
import random
import math
import ConfigParser
import sys
#Write these values in stack when size to be fuzzed
fuzzed_size = ['\x00\x00\x00\x00','\xff\xff\xff\xff','\x00\x00\xff\xff','\xff\xff\x00\x00']
logfile_path = 'c:\\ioctllog.xml'

def formatit(s):
    buff = ''
    for i in range(0,len(s)):
        if i%2 == 0:
            buff += '\\x'
        buff += s[i]
    return buff
def fuzzit(buf):
        fuzzpercent = float(0.05)
        b = list(buf)
        numwrites=random.randrange(math.ceil((float(len(buf))) * fuzzpercent))+1
        for j in range(numwrites):
                rbyte = random.randrange(256)
                rn = random.randrange(len(buf))
                b[rn] = '%c'%(rbyte)
        c=''.join(b)
        return c
def startlog():
        f = open(logfile_path,'w')
        f.write('<?xml version="1.0" encoding="windows-1251" ?><ioctllog>')
        f.close()
def writelog(data):
        f = open(logfile_path,'a')
        f.write(data)
        f.close()
def sniff( dbg, args ):
        '''
        BOOL WINAPI DeviceIoControl(
          _In_         HANDLE hDevice,
          _In_         DWORD dwIoControlCode,
          _In_opt_     LPVOID lpInBuffer,
          _In_         DWORD nInBufferSize,
          _Out_opt_    LPVOID lpOutBuffer,
          _In_         DWORD nOutBufferSize,
          _Out_opt_    LPDWORD lpBytesReturned,
          _Inout_opt_  LPOVERLAPPED lpOverlapped
        );
        esp+4 -> 0 -> HANDLE hDevice
        esp+8 -> 1 -> DWORD dwIoControlCode
        esp+12-> 2 -> LPVOID lpInBuffer
        esp+16-> 3 -> DWORD nInBufferSize
        esp+20-> 4 -> LPVOID lpOutBuffer pointer
        esp+24-> 5 -> DWORD nOutBufferSize
        ..
        ..
        '''
        log = "\n<ioentry>"
        log += '\n<iocode>' +  hex(args[1]) + '</iocode>'
	print '[+] IOCTL Code : ',hex(args[1])
        esp = dbg.context.Esp
        if fuzz_in_size:
                log+= '\n<inbufsize>' + hex(args[3]) + '</inbufsize>'
                print '[+] Actual In-Buffer Size :',hex(args[3])
                fsz = random.choice(fuzzed_size)
                log+= '\n<fuzzinbufsize>' + fsz + '</fuzzinbufsize>'
                print '[+] Fuzzed In-Buffer Size :' , fsz
                dbg.write_process_memory( esp+0x10, fsz, 4)
        else:
                log+= '\n<inbufsize>' + hex(args[3]) + '</inbufsize>'
                print '[+] Logging Mode : In-Buffer Size : ',hex(args[3])
        if fuzz_op_size:
                log+= '\n<outbufsize>' + hex(args[5]) + '</outbufsize>'
                print '[+] Actual Out-Buffer Size :',hex(args[5])
                fsz = random.choice(fuzzed_size)
                log+= '\n<fuzzoutbufsize>' + fsz + '</fuzzoutbufsize>'
                print '[+] Fuzzed Out-Buffer Size :' , fsz
                dbg.write_process_memory( esp+0x18, fsz, 4)
        else:
                log+= '\n<outbufsize>' + hex(args[5]) + '</outbufsize>'
                print '[+] Logging Mode : Out-Buffer Size : ',hex(args[5])
	input_buffer = dbg.read_process_memory(args[2], int(args[3]))
        if fuzz_input:
                fuzzed_data = fuzzit(input_buffer)
                log += '\n<inbuffdata>' + fuzzed_data.encode('hex') + '</inbuffdata>'
                log += '\n<fuzzinbuffdata>' + formatit(fuzzed_data.encode('hex')) + '</fuzzinbuffdata>'
                print '[+] Fuzzed Input-Buffer Data :',fuzzed_data.encode('hex')
        else:
                fuzzed_data = input_buffer
                log += '\n<inbuffdata>' + formatit(fuzzed_data.encode('hex')) + '</inbuffdata>'
                print '[+] Logging Mode : Input-Buffer Data :',fuzzed_data.encode('hex')
        try:
                dbg.write_process_memory( args[2], fuzzed_data, int(args[3]))	#Writing fuzzed data into memory
        except Exception, e:
                log += '\n[+] Error : Cannot Write Fuzzed Data into memory!!'
                print '[+] Error : Cannot Write Fuzzed Data into memory!!'
        log += '</ioentry>'
	print '\n\n'+'*'*50
	if target_ioctl == "*":
                writelog(log)
        else:
                if args[1] == target_ioctl:
                        writelog(log)
                else:
                        print '[+] Skipping'
	return DBG_CONTINUE
def parseconfig():
	global proc_name,fuzz_input,fuzz_in_size,fuzz_op_size,target_ioctl
	config = ConfigParser.ConfigParser()
	try:
		config.read(sys.argv[1])
		proc_name = config.get('IOCTLFuzzerConfig', 'ProcessName', 0) 
		if_fuzz_input = config.get('IOCTLFuzzerConfig', 'FuzzInput', 0) 
		if if_fuzz_input == "True":
			fuzz_input = True
		else:
			fuzz_input = False
		if_fuzz_in_size = config.get('IOCTLFuzzerConfig', 'FuzzInSize', 0)
		if if_fuzz_in_size == "True":
			fuzz_in_size = True
		else:
			fuzz_in_size = False
		if_fuzz_op_size = config.get('IOCTLFuzzerConfig', 'FuzzOutSize', 0)
		if if_fuzz_op_size == "True":
			fuzz_op_size = True
		else:
			fuzz_op_size = False
		try:
			target_ioctl = int(config.get('IOCTLFuzzerConfig', 'IoctlCodeToLog', 0),16)
		except Exception,e:
			target_ioctl = "*"
		print '\t[*]Process to Hook :',proc_name
		print '\t[*]Fuzz input buffer:',if_fuzz_input
		print '\t[*]Fuzz input size :',if_fuzz_input
		print '\t[*]Fuzz output buffer size :',if_fuzz_op_size
		print '\t[*] IOCTL to Log ',target_ioctl
		raw_input('[+] If above informations are corrects press enter to continue')
	except Exception,e:
		print '[+] Error Reading/Parsing Config file'
		print '[+] Usage :python iofuzz.py ioconfig.conf'
		exit()
def main():
	parseconfig()
	startlog()
	dbg = pydbg()
	hooks = utils.hook_container()
	for (pid,name) in dbg.enumerate_processes():
		if name == proc_name:
			print '[+] Attaching to ',proc_name
			try:
				dbg.attach(pid)
			except Exception,e:
				print '[Error] Cannot Attach to process ',proc_name,pid
				exit()
	hook_address = dbg.func_resolve_debuggee("kernel32.dll","DeviceIoControl")
	hooks.add( dbg, hook_address, 8, sniff, None )
	dbg.run()
if __name__ == '__main__':
        main()
