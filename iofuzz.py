'''

iofuzz.py
Author : Debasish Mandal
Blog : http://www.debasish.in/

This fuzzer attaches it self to given user mode process and hooks DeviceIoControl!Kernel32. 
After that,when DeviceIoControl is get called by the process it fuzzes the input/output buffer 
content etc inside memory and at the same time logs actual buffer and mutated buffer length / content 
in a log file. This log file is helpful when reproducing bugs triggered by this fuzzer. 

This tool can operates in three modes: 

1. Sniffing Mode - Capture Phase 
2. Passive Fuzzing Mode - In-memory Fuzzing Mode 
3. Active Fuzzing Mode - Direct operation I/O to Target device driver. 


'''

import optparse
import re
import random
import math
from random import randrange,randint
try:
	from ctypes import *
	from ctypes import wintypes
except ImportError:
	'[Error] Could not import ctype'
try:
	from win32api import GetLastError;(kernel32,ntdll) = (windll.kernel32,windll.ntdll)
	from win32con import NULL,FILE_SHARE_READ,FILE_SHARE_WRITE,OPEN_EXISTING
	from win32file import INVALID_HANDLE_VALUE
except ImportError:
	print '[Error] Could not import pywin32.Get it from http://sourceforge.net/projects/pywin32/'
try:
	import utils
except ImportError:
	print '[Error]Could not import utils,Get it from https://github.com/OpenRCE/paimei'
try:
	import pydbg
	from pydbg import *
	from pydbg.defines import *
except ImportError:
	print '[Error] Could not import pydbg. Get it from https://github.com/OpenRCE/pydbg'
from datetime import datetime
import signal
import sys
 
 
class CMDOptions:
	'''
		Although optparse has very nice help banner printing options, still I just wanted to customize the help banner little bit.Nothing else :)
	'''
	def show_passive_help(self):
		print '''
		When --mode="passive" (in-memory fuzzing mode)
			Mandatory switches:
			--process (ProcessName to attach and Its mandatory option)
			Optional Switches:
			--ioctl (Code to log / log all iocode) Ex. --ioctl=0xbadfood or by default it will fuzz all iocodes inside memory!
		'''
	def show_active_help(self):
		print '''
		When --mode="active" (Send IOCTL direct to target device given)
			Mandatory switches:
			--device (Target device name Its mandatory option)
			--inputlog (Input log collected after iofuzz sniffer, inputlog.txt and Its mandatory option)
			Example : --mode="active" --device="MyDevice" --inputlog="iofuzz_2014_03_23_22_47_10.log" --fuzzinlen --fuzzinbuff			
			Optional Switches:
			--fuzzinbuff (Fuzz input buffer content False by default)
			--fuzzinlen (Fuzz input buffer length False by default)
			--fuzzoutlen (Fuzz input buffer length False by default)
			--sizelimit (Length size limit 100,200 etc etc default is 10K)
			--ioctl (Code to log / log all iocode) Ex. --ioctl=0xbadfood by default it will fuzz all iocodes
		'''
	def show_sniff_help(self):
 
		print '''
		When --mode="sniff" (silently log all device IO control request)
			Mandatory switches:
			--process (Process Name to attach with) Example : --mode="sniff" --process="notepad.exe"
			Optional Switches:
			--ioctl (Code to log / log all iocode) Ex. --ioctl=0xbadfood or --ioctl="*"
		'''
	def cmd_option(self):
		'''
		Parse Options
		'''
		global mode,log_path,fuzzinbuff,fuzzinlen,fuzzoutlen,size_limit,process,device
		fuzzinbuff = False
		fuzzoutlen = False
		fuzzinlen = False
		size_limit = 10000
		global input_log_path,ioctl,run_time
		parser = optparse.OptionParser()
		parser.add_option('--mode', type="string", dest='mode')
		parser.add_option('--process', type="string", dest='process')
		parser.add_option('--device', type="string", dest='device')
		### boolian ######
		parser.add_option('--fuzzinbuff', dest='fuzzinbuff',default=False,action="store_true")
		parser.add_option('--fuzzinlen', dest='fuzzinlen',default=False,action="store_true")
		parser.add_option('--fuzzoutlen', dest='fuzzoutlen',default=False,action="store_true")
		#### helper options ####
		parser.add_option('--sizelimit', type="int", dest='size_limit')
		parser.add_option('--inputlog', type="string", dest='input_log_path')
		parser.add_option('--ioctlcode', type="int", dest='ioctl')
		(opts, args) = parser.parse_args()
		mode = opts.mode
		if mode == "passive":
			mandatories = ['process']
			for m in mandatories:
		        	if not opts.__dict__[m]:
		                	print "[+] Error!! You have missed a mandatory option of mode : ", mode
		                	self.show_passive_help()
		                	exit(-1)
			if opts.fuzzinbuff:
				fuzzinbuff = True
			if opts.fuzzoutlen:
				fuzzoutlen = True
			if opts.fuzzinlen:
				fuzzinlen = True
			if opts.ioctl:
				ioctl = int(opts.ioctl)
			else:
				ioctl = "*"
			if opts.size_limit:
				size_limit = opts.size_limit
			process = opts.process
			print "Mode:",mode,"Process:",process,"Fuzz input buffer:",fuzzinbuff,"Fuzz output length:",fuzzoutlen,"Fuzz input length:",fuzzinlen,"Ioctl:",ioctl,"Max buffer length limit",size_limit
			raw_input('[+] Press Enter to continue..')
		elif mode == "active":
			mandatories = ['input_log_path','device']
		        for m in mandatories:
		                if not opts.__dict__[m]:
		                        print "[+] Error!! You have missed a mandatory option of mode : ", mode
		                        self.show_active_help()
		                        exit(-1)
			if opts.fuzzinbuff:
				fuzzinbuff = True
			if opts.fuzzoutlen:
				fuzzoutlen = True
			if opts.fuzzinlen:
				fuzzinlen = True
			if opts.ioctl:
				ioctl = int(opts.ioctl)
			else:
				ioctl = "*"
			if opts.size_limit:
				size_limit = opts.size_limit
			device = opts.device
			input_log_path = opts.input_log_path
			#if opts.fuzzinlen and opts.fuzzinbuff:
			#	print '[Error] Please choose any one of --fuzzinlen or --fuzzinbuff switch at a time'
			#	exit()			
			print "[+] Mode",mode,"Input Log Path:",input_log_path,"Device Name:",device,"Fuzz input buffer:",fuzzinbuff,"Fuzz output length:",fuzzoutlen,"Fuzz input length:",fuzzinlen,"Ioctl:",ioctl,"Max buffer length limit",size_limit
			raw_input('[+] Press Enter to continue..')
		elif mode == "sniff":
			mandatories = ['process']
		        for m in mandatories:
		                if not opts.__dict__[m]:
		                        print "[+] Error!! You have missed a mandatory option Example \n$./iofuzz.py --mode <active / passive /sniff>"
		                        self.show_sniff_help()
		                        exit(-1)
			#log = opts.log
			process = opts.process
			if opts.ioctl:
				ioctl = int(opts.ioctl)
			else:
				ioctl = "*"
			print '[+] Mode:',mode,"Process Name:",process
			raw_input('[+] Press Enter to continue..')
 
		else:
			print '''[+] Invalid or no mode name given. \nExample $./iofuzz.py --mode <active / passive /sniff>
				passive => (In-memory fuzzing mode)
				active => (Send IOCTL direct to target device given)
				sniffer => (Silently log all device IO control request by hooking Kernel32!DeviceIoControl())
				'''
			exit()
class HelperFunctions:
	def startlog(self,logfile_path):
		f = open(logfile_path,'w')
		f.write('<ioctllog mode="'+ mode +'">')
		f.close()
	def exit_gracefully(self,signum, frame):
		signal.signal(signal.SIGINT, original_sigint)
		try:
			if raw_input("Really want to stop? (y/n)> ").lower().startswith('y'):
				sys.exit(1)
		except KeyboardInterrupt:
			hookobj.removehook()
			print("Ok ok, quitting")
			sys.exit(1)
		signal.signal(signal.SIGINT, exit_gracefully)
	def addtolog(self,ioctl,input_buffer,output_buffer_len,out_buff_address):
		log = '<ioentry>'
		log += '<iocode>' + hex(ioctl) +'</iocode>'
		log += '<inbuffer>'+ input_buffer + '</inbuffer>'
		log += '<outlen>' + hex(output_buffer_len) +'</outlen>'
		log += '<outpointer>' + hex(out_buff_address) + '</outpointer>'
		log += '</ioentry>'
		f = open(log_name,'a')
		f.write(log)
		f.close()
		
class Fuzzing:
	'''
	This class is responsible for all fuzzing operations.(generation and mutation)
	'''
	#Generation Based fuzzing
	def get_long_buffer(self):
		total_cases = 2
		case = randrange(total_cases)
		if case == 0:
			#send back long strings 
			chars = ['A','O','Z','!','@','#','$','^','*','+','\\','<','>','?','`','~','\"',"\\'",'%','%s','%d','%x','%u','%p','\xff','\x00']
			return chars[randrange(0,26)]*randrange(0,5000)
		if case == 1:
			#send back dwords
			dw = ['\x00\x00\x00\x00','\xFF\xFF\xFF\xFF','\xFF\xFF\x00\x00','\x00\x00\xFF\xFF']
			return (random.choice(dw))*randrange(0,10000)
		if case == 2:
			random_byte = random.randrange(256)
			return hex(random_byte)[2:].decode('hex')*randint(0,5000)
	#######################################################################
	'''
	This if for output buffer size and address !
	'''
	def get_long_len(self):
		return randrange(0x0000,0xFFFF)
	def get_address(self):
		ad_case = randrange(0,1)
		if ad_case == 0:
			return randrange(0x00000000,0x7FFFFFFF)
		if ad_case == 1:
			return randrange(0x80000000,0xFFFFFFFF)
	##############################################################
	def dumbo(self,buf):
		'''
		Dumbest fuzzer in the whole universe for sure!!!
		'''
		if len(buf) == 0:
			return ""
		percent = float(0.05)
		b = list(buf)
		num2write=random.randrange(math.ceil((float(len(buf))) * percent))+1
		for j in range(num2write):
			random_byte = random.randrange(256)
			random_offset = random.randrange(len(buf))
			b[random_offset] = '%c'%(random_byte)
		final=''.join(b)
		return final
	def dwordfuzz(self,buff):
		'''
		Fuzz only DWORDs of given buffer!!
		'''
		if len(buff) == 0:
			return ""		
		dwords = ['\x00\x00\x00\x00','\xff\xff\xff\xff','\x00\x00\xff\xff','\xff\xff\x00\x00','\x00\x00\x01\x00']
		dword_buff = [buff[i:i+4] for i in range(0, len(buff), 4)]
		rand_offset = randrange(len(dword_buff))
		dword_buff[rand_offset] = dwords[randrange(0,len(dwords))]
		return ''.join(dword_buff)
	def fuzzit(self,buff):
		'''
		It decides which of above defined fuzzer to be used depending on the choosen options!!
		'''
		if fuzzinlen and mode != "passive":
			'''
			Its sometime too risky to write long data inside memory. It may corrupt existing data structure.
			So for passive mode only mutation based approach will be used.
			'''
			#Check if buffer length can be manipulated or not 
			return self.get_long_buffer()
		else:
			#Length cannot be manipulated then use dumbo() or dwordfuzz()
			lot = randint(0,1)
			if lot == 0:
				return self.dwordfuzz(buff)
			if lot == 1:
				return self.dumbo(buff)
				
class SendIoctl:
	'''
	This Class is responsible for doing all direct I/O operations to target device.
	Thanks for levle his work saved lot of my time.
	https://github.com/levle/Kfuzz
	'''
	def sendioctl(self,device,ioctl,input_buffer,output_buf_poi,output_len):
		f = open('lastio.log','w')
		DeviceIoControl = windll.ntdll.ZwDeviceIoControlFile
		input_size = len(input_buffer)
		handle = kernel32.CreateFileA("\\\\.\\"+device,FILE_SHARE_WRITE|FILE_SHARE_READ,0,None,OPEN_EXISTING,0,None)
		handleMap = kernel32.CreateFileMappingA(INVALID_HANDLE_VALUE,NULL,0x40,0,input_size,NULL)
		address = kernel32.MapViewOfFileEx(handleMap,0x2|0x4|0x8,0,0,input_size,NULL)
		kernel32.WriteProcessMemory(-1,address,input_buffer,input_size,byref(c_int(0)))
		print '[*] Device: '+str(device)+' Handle: '+hex(handle)+' IOCTL: '+hex(ioctl)+' Buffer(in) Poi: '+hex(address)+' Length: '+hex(input_size)+' Buffer(out): '+hex(output_buf_poi)+' Length: '+hex(output_len)
		log = '<device>'+ device +'</device><ioctl>'+ ioctl +'</ioctl><inputbuff>'+ input_buffer +'</inputbuff><outbufpoi>'+ output_buf_poi +'</outbufpoi><outputlen>'+ output_len +'</outputlen>'
		f.write(log)
		f.close()
		ret = DeviceIoControl(handle,NULL,NULL,NULL,byref(c_ulong()),ioctl,address,input_size,output_buf_poi,output_len)
		if not ret:
			raise IOError('DeviceIoControl() failed!')
		kernel32.CloseHandle(handle)
		kernel32.UnmapViewOfFile(address)
class HooknSniff:
	'''
	This class is responsible for actual Hook operation and it changes all DeviceIoControl params on the fly!!
	'''
	def sniff( self,dbg, args ):
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
		esp+C->  2 -> LPVOID lpInBuffer
		esp+10-> 3 -> DWORD nInBufferSize
		esp+14-> 4 -> LPVOID lpOutBuffer pointer
		esp+18-> 5 -> DWORD nOutBufferSize
		..
		..
		'''
		in_size = args[3]
		in_buff_poi = args[2]
		input_buffer = dbg.read_process_memory(in_buff_poi, int(in_size))
		output_buffer_poi = args[4]
		io_code = args[1]
		out_size = args[5]
		esp = dbg.context.Esp
		print '[+] Intercepted IOCTL Code :',hex(io_code)
		if mode == "passive":
			if ioctl != "*":
				#operate on given ioctl
				if args[1] == ioctl:
					if fuzzinbuff:
						fuzzed  = fuzz.fuzzit(input_buffer)
						length = len(fuzzed)
						a = '{0:08X}'.format(length)
						dbg.write_process_memory( esp+0x10, a.decode('hex'), 4)
						dbg.write_process_memory( args[2], fuzzed, len(fuzzed))
					else:
						fuzzed = input_buffer
					long_length = fuzz.get_long_len()
					a = '{0:08X}'.format(long_length)
					dbg.write_process_memory( esp+0x18, a.decode('hex'), 4)
					rand_addr = addfuzz.get_address()
					b = '{0:08X}'.format(rand_addr)	#convert int to string represent a 32bit Hex number
					raw_length = b.decode('hex')
					dbg.write_process_memory( esp+0x14, raw_length, 4)
					helper.addtolog(io_code,fuzzed,long_length,rand_addr)
				else:
					print '[+] Skipping IOCTL..',hex(args[1])
			else:
				if fuzzinbuff:
					fuzzed  = fuzz.fuzzit(input_buffer)
					length  = len(fuzzed)
					a = '{0:08X}'.format(length)
					dbg.write_process_memory( esp+0x10, a.decode('hex')[::-1], 4)
					dbg.write_process_memory( args[2], fuzzed, len(fuzzed))
				else:
					#Dont fuzz input buffer content
					fuzzed = input_buffer
				#Long out put size out put buffer len
				long_out_length = fuzz.get_long_len()
				a = '{0:08X}'.format(long_out_length)
				dbg.write_process_memory( esp+0x18,a.decode('hex')[::-1], 4)
				#Write an absurd address in output buffer address
				rand_addr = fuzz.get_address()
				a = '{0:08X}'.format(rand_addr)	#convert int to string represent a 32bit Hex number
				raw_length = a.decode('hex')
				dbg.write_process_memory( esp+0x14, raw_length[::-1], 4)
				helper.addtolog(io_code,fuzzed,long_out_length,rand_addr)
		if mode == "sniff":
			#sniffing mode
			if ioctl == "*":
				helper.addtolog(io_code,input_buffer,out_size,output_buffer_poi)
			else:
				if args[1] == ioctl:
					#Log only this one
					helper.addtolog(io_code,input_buffer,out_size,output_buffer_poi)
				else:
					print '[+] Not logging',hex(args[1])
		print '\n\n'+'*'*50
		return DBG_CONTINUE
	def removehook(dbg):
		#remove_hook_and deattach debugger
		print '[+] Rmeoving DeviceIoControlHook'
		hooks.remove( dbg, hook_address)
		dbg.detach()
if __name__ == "__main__":
	cmd = CMDOptions()
	cmd.cmd_option()
	global helper
	helper = HelperFunctions()
	global fuzz
	fuzz = Fuzzing()
	global original_sigint
	original_sigint = signal.getsignal(signal.SIGINT)
	signal.signal(signal.SIGINT, helper.exit_gracefully)
	global log_name
	log_name = 'iofuzz_'+datetime.now().strftime("%Y_%m_%d_%H_%M_%S")+".log"
	helper.startlog(log_name)
	if mode == "passive" or mode == "sniff":
		global dbg
		dbg = pydbg()
		global hooks
		hooks = utils.hook_container()
		for (pid,name) in dbg.enumerate_processes():
			if name == process:
				print '[+] Attaching to ',process
				try:
					dbg.attach(pid)
				except Exception,e:
					print '[Error] Cannot Attach to process ',process,pid
					exit()
				global hook_address
				hook_address = dbg.func_resolve_debuggee("kernel32.dll","DeviceIoControl")
				hookobj = HooknSniff()
				hooks.add( dbg, hook_address, 8, hookobj.sniff, None )
				dbg.run()
	else:
		ioobj = SendIoctl()
		print '[+] Reading iocltl log file..',input_log_path
		f = open(input_log_path,'rb')
		xml_data = f.read()
		f.close()
		match = re.findall('<ioentry>(.*?)</ioentry>',xml_data)
		if not len(match):
			print '[Error] Make sure provided log is correctly formatted!!'
			exit()
		while 1:
			io = random.choice(match)
			iocode = re.findall('<iocode>(.*?)</iocode>',io)
			in_buff_data = re.findall('<inbuffer>(.*?)</inbuffer>',io)
			if ioctl == "*":
				if fuzzinbuff:
					fuzzed_data = fuzz.fuzzit(in_buff_data[0])	
				else:
					fuzzed_data = in_buff_data[0]
				out_address = fuzz.get_address()
				out_len = fuzz.get_long_len()
				ioobj.sendioctl(device,int(iocode[0],16),fuzzed_data,out_address,out_len)
			else:
				if int(iocode[0],16) == ioctl:
					if fuzzinbuff:
						fuzzed_data = fuzz.fuzzit(in_buff_data[0])
					else:
						fuzzed_data = in_buff_data[0]
					out_address = fuzz.get_address()
					out_len = fuzz.get_long_len()
					ioobj.sendioctl(device,int(iocode[0],16),fuzzed_data,out_address,out_len)
				else:
					pass
