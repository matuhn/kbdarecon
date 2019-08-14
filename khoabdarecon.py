#!/usr/bin/env python3
import os
import sys
import platform
import time
ver = platform.python_version()

if (ver <= '3'):
        print("\033[91m This isn't compatible with python2 use python 3.x\033[00m")
        sys.exit(1)

import argparse
import concurrent.futures

parser = argparse.ArgumentParser(description="""\033[93m[~] Domain status code checker by khoabda
									https://matuhn.github.io\033[00m""")

group = parser.add_mutually_exclusive_group()
												#Taking arguments from CLI
parser.add_argument("-cV","--checkVerbose", help="check verbose (status code + dig domain)",action="store_true")

parser.add_argument("-cO","--output", help="write active domains in new file" ,metavar='out-file')

parser.add_argument("-t","--threads", help="number of concurrent threads" ,type=int,metavar="threads")

group.add_argument("-cF","--file", help="File which consist domains(sub.example.com) for checking",metavar="input file")

group.add_argument("-cU","--url", help="single domain check",metavar="URL")

parser.add_argument("-eF","--extract", help="extract IP from file" ,metavar="extract IP")

parser.add_argument("-eO","--outputExtract", help="output IP to a new file after extract" ,metavar="output IP")

parser.add_argument("-sF","--scanF", help="scan all port file of ip" ,metavar="scan port")

parser.add_argument("-sO","--scanO", help="scan all port file of ip" ,metavar="scan port and output to file")

args = parser.parse_args()

verbose = args.checkVerbose
file = args.file
url = args.url
output = args.output
threads = args.threads
extract = args.extract
out_extract = args.outputExtract
scan = args.scanF
out_scan = args.scanO

if output:
	os.popen("rm -f "+output)
if out_extract:
	os.popen("rm -f "+out_extract)
if out_scan:
	os.popen("rm -f "+out_scan)
										#Just A fancy banner!
print("""\033[91m
#    # #    #  ####    ##   #####  #####    ##   #####  ######  ####   ####  #    # 
#   #  #    # #    #  #  #  #    # #    #  #  #  #    # #      #    # #    # ##   # 
####   ###### #    # #    # #####  #    # #    # #    # #####  #      #    # # #  # 
#  #   #    # #    # ###### #    # #    # ###### #####  #      #      #    # #  # # 
#   #  #    # #    # #    # #    # #    # #    # #   #  #      #    # #    # #   ## 
#    # #    #  ####  #    # #####  #####  #    # #    # ######  ####   ####  #    # \033[00m

					\033[93m v1.0 By khoabda\033[00m
""")


if verbose:
	print("\033[93m[~] Verbosity is enabled..\033[00m")

if not threads:										#default number of threads
	threads = 20

t = time.time()

def curlForStatus(domain):
								#This function will make request to domain
	checkStatus = "curl -I " + domain + " -s -m 15 --write-out %{http_code} --output /dev/null"
	checkIp = "dig +short " + domain

	statusCode = os.popen(checkStatus).read().rstrip()
	ipDomain = os.popen(checkIp).read().rstrip()

	# Maybe can dig many ip, so use \n despite of " "
	result = ipDomain+"\n"+statusCode

	return result

def getIP(InputFilePath):

	getIPV4 = "grep -E -o \"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\" "+InputFilePath
	listIPV4 = os.popen(getIPV4).read()
	return listIPV4

def check(data,domain):
	data = data.split("\n")
	#1 domain can have different ip after dig 
	if verbose:
		if (data[len(data)-1] == "000"):
			print("\033[91m[~] ",data[len(data)-1] , "\n	[-] ", domain[:-1] , " is DOWN \033[00m")
		elif (data[len(data)-1] == "200"):
			if output:
				print("\033[92m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is ALIVE \033[00m")
				print("\033[92m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is ALIVE \033[00m", file =open(output, "a"))
			else:
				print("\033[92m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is ALIVE \033[00m")
		elif (data[len(data)-1] == "301"):
			if output:
				print("\033[34m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is MOVED PERMANENTLY \033[00m")
				print("\033[34m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is MOVED PERMANENTLY \033[00m", file =open(output, "a"))
			else:
				print("\033[34m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is MOVED PERMANENTLY \033[00m")
		elif (data[len(data)-1] == "302"):
			if output:
				print("\033[34m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is MOVED TEMPORARILY \033[00m")
				print("\033[34m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is MOVED TEMPORARILY \033[00m", file =open(output, "a"))
			else:
				print("\033[34m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is MOVED TEMPORARILY \033[00m")
		elif (data[len(data)-1] == "400"):
			if output:
				print("\033[33m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is BAD REQUEST \033[00m")
				print("\033[33m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is BAD REQUEST \033[00m", file =open(output, "a"))
			else:
				print("\033[33m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is BAD REQUEST \033[00m")
		elif (data[len(data)-1] == "403"):
			if output:
				print("\033[33m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is NEED AUTHORIZED \033[00m")
				print("\033[33m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is NEED AUTHORIZED \033[00m", file =open(output, "a"))
			else:
				print("\033[33m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is NEED AUTHORIZED \033[00m")
		elif (data[len(data)-1] == "404"):
			if output:
				print("\033[33m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is NOT FOUND \033[00m")
				print("\033[33m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is NOT FOUND \033[00m", file =open(output, "a"))
			else:
				print("\033[33m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is NOT FOUND \033[00m")
		elif (data[len(data)-1] == "405"):
			if output:
				print("\033[33m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is METHOD NOT ALLOWED \033[00m")
				print("\033[33m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is METHOD NOT ALLOWED \033[00m", file =open(output, "a"))
			else:
				print("\033[33m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is METHOD NOT ALLOWED \033[00m")
		elif (data[len(data)-1] == "500"):
			if output:
				print("\033[36m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is INTERNAL SERVER ERROR \033[00m")
				print("\033[36m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is INTERNAL SERVER ERROR \033[00m", file =open(output, "a"))
			else:
				print("\033[36m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is INTERNAL SERVER ERROR \033[00m")
		elif (data[len(data)-1] == "501"):
			if output:
				print("\033[36m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is NOT IMPLEMENTED \033[00m")
				print("\033[36m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is NOT IMPLEMENTED \033[00m", file =open(output, "a"))
			else:
				print("\033[36m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is NOT IMPLEMENTED \033[00m")
		elif (data[len(data)-1] == "502"):
			if output:
				print("\033[36m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is BAD GATEWAY \033[00m")
				print("\033[36m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is BAD GATEWAY \033[00m", file =open(output, "a"))
			else:
				print("\033[36m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is BAD GATEWAY \033[00m")
		elif (data[len(data)-1] == "503"):
			if output:
				print("\033[36m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is SERVICE UNAVAILABLE \033[00m")
				print("\033[36m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is SERVICE UNAVAILABLE \033[00m", file =open(output, "a"))
			else:
				print("\033[36m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is SERVICE UNAVAILABLE \033[00m")
		else:
			if output:
				print("\033[00m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is <NOT YET IMPLEMENTED THIS STATUS CODE> \033[00m")
				print("\033[00m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is <NOT YET IMPLEMENTED THIS STATUS CODE> \033[00m", file =open(output, "a"))
			else:
				print("\033[00m[~] ",data[len(data)-1] , "\n 	[+]  DIG Domain: ",data[0:(len(data)-1)],"\n 	[+] ", domain[:-1] , " is <NOT YET IMPLEMENTED THIS STATUS CODE> \033[00m")
	else:
		if (data[len(data)-1] == "000"):
			print("\033[91m[!] Domain " , domain[:-1] ," is DOWN \033[00m")
		else:
			print("\033[92m[~] Domain " , domain[:-1] , " is ALIVE \033[00m")
			if output:
				with open(output,"a") as output_file:						#Writing output to new file
					output_file.write(domain)

def nmap(ipAddress):
	import nmap
	nm = nmap.PortScanner()
	nm.scan(ipAddress)
	for host in nm.all_hosts():
		if out_scan:
			print('----------------------------------------------------')
			print('----------------------------------------------------',file =open(out_scan, "a"))
			print('Host : %s (%s)' % (host, nm[host].hostname()))
			print('Host : %s (%s)' % (host, nm[host].hostname()),file =open(out_scan, "a"))
			print('State : %s' % nm[host].state())
			print('State : %s' % nm[host].state(),file =open(out_scan, "a"))
			for proto in nm[host].all_protocols():
				print('----------')
				print('----------',file =open(out_scan, "a"))
				print('Protocol : %s' % proto)
				print('Protocol : %s' % proto,file =open(out_scan, "a"))
				lport = nm[host][proto].keys()
				for port in lport:
					print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))
					print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']),file =open(out_scan, "a"))

		else:
			print('----------------------------------------------------')
			print('Host : %s (%s)' % (host, nm[host].hostname()))
			print('State : %s' % nm[host].state())
			for proto in nm[host].all_protocols():
				print('----------')
				print('Protocol : %s' % proto)
				lport = nm[host][proto].keys()
				for port in lport:
					print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))

if file:

	if os.path.isfile(file):
		num_domains = 0

		with open(file,"r") as f:
			for domain in f:
				num_domains += 1
		f.close()

		print("\033[92m[~] Total number of domains found in the file are: ", num_domains,"\033[00m")

		with open(file,"r") as f:

			pool = concurrent.futures.ThreadPoolExecutor(max_workers=threads)

		#Start the load operations and mark each future with its domain

			futures = {pool.submit(curlForStatus,domain[:-1]):domain for domain in f}

			for future in concurrent.futures.as_completed(futures):
				domain = futures[future]

				try:
					data = future.result()

					check(data,domain)

				except Exception as exc:

					print('%r generated an exception: %s' % (domain, exc))

	else:
		print("\033[91m[!] File not found..\033[00m")
		sys.exit(1)

if url:													#For single domain check
	check = "curl -I " + url + " -s -m 15 --write-out %{http_code} --output /dev/null/"

	answer = os.popen(check)

	if answer.read() == "000":
		print("\033[91m[!] Host ", url, " is down\033[00m")

	else:
		if verbose:
			print("\033[92m[~] Host ", url, "is live with status code: ",answer.read(),"\033[00m")
		else:
			print("\033[92m[~] Host ", url, "is live\033[00m")

if extract:
	if os.path.isfile(extract):
		listIP = getIP(extract)
		print ("\033[92m[~]",listIP)
		if out_extract:
			with open("temp.txt","w") as out_extract_file:						#Writing output to new file
				out_extract_file.write(listIP)
				
			lines_seen = set()
			for line in open("temp.txt", "r"):
				if line not in lines_seen:
					with open(out_extract,"a") as out_file:
						out_file.write(line)
					lines_seen.add(line)

	else:
		print("\033[91m[!] File not found..\033[00m")
		sys.exit(1)

if scan:
	ipList = ""
	if os.path.isfile(scan):
		num_ip = 0

		with open(scan,"r") as f:
			for ip in f:
				num_ip += 1
		f.close()

		print("\033[92m[~] Total number of ip found in the file are: ", num_ip,"\033[00m")

		with open(scan,"r") as f:
			for ip in f:
				ipList += str(ip).rstrip()
				ipList += " "

		nmap(ipList)
		

	else:
		print("\033[91m[!] File not found..\033[00m")
		sys.exit(1)
print("\033[93m[~] Total time taken: " , time.time() -t , "\033[00m")



