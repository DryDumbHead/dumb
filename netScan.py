import eel
from scapy.all import *
import ipaddress
from threading import Thread
from tkinter import filedialog
import json
from modules import hostDiscovery as hd ,PortScan as ps


PortScanResult = []
NetworkHosts = {}
Timeout = 5
@eel.expose
def performPortScan(ips, scan_type = "TCP_SYN", t_ports = [80,21,22], dst_timeout= 2,network=None):
	res = {}
	for dst_ip in ips:
		writeMsg("Port Scan for {} started".format(str(dst_ip)))
		ports = {}
		open_ports = []
		filtered_ports = []
		closed_ports = []
		open_filtered_ports = []
		for dst_port in t_ports:
			if scan_type == 'TCP_SYN': result = ps.tcp_connect_scan(dst_ip,dst_port,dst_timeout)
			elif scan_type == 'TCP_SYN_S': result = ps.stealth_scan(dst_ip,dst_port,dst_timeout)
			elif scan_type == 'XMAS': result = ps.xmas_scan(dst_ip,dst_port,dst_timeout)
			elif scan_type == 'FIN': result = ps.fin_scan(dst_ip,dst_port,dst_timeout)
			elif scan_type == 'NULL': result = ps.null_scan(dst_ip,dst_port,dst_timeout)
			elif scan_type == 'WINDOW': result = ps.window_scan(dst_ip,dst_port,dst_timeout)
			elif scan_type == 'UDP': result = ps.udp_scan(dst_ip,dst_port,dst_timeout)
#			if (dst_port % 3) : 
#				result = 'Open'
#			elif(dst_port % 2):
#				result = "Closed"
			
			if result == "Closed":
				closed_ports.append(dst_port)
			elif result == "Open":
				open_ports.append(dst_port)
			elif result == "Filtered":
				filtered_ports.append(dst_port)
			elif result == "Open|Filtered":
				open_filtered_ports.append(dst_port)
		writeMsg("Port Scan for {} completed: {} Open Ports".format(str(dst_ip),len(open_ports)))
		OS = OS_scan(dst_ip)
#		OS = "Windows"
		ports["Open"] = open_ports
		ports["Closed"] = closed_ports
		ports["Filtered"] = filtered_ports
		ports["Open|Filtered"] = open_filtered_ports
		if network != dst_ip:
			res[str(network)] = {str(dst_ip):{"ports": ports, "OS":OS }}
			NetworkHosts[str(network)]["ActiveHosts"][str(dst_ip)]={"ports": ports,"OS":OS}
			updateScanSummary()
		if  network == dst_ip:
			res[str(dst_ip)] = {str(dst_ip):{"ports": ports}}
			NetworkHosts[str(dst_ip)] = {"ActiveHosts":{str(dst_ip):{"ports": ports,"OS":OS}}}
			updateScanSummary()
		addPortScanResult(res)
		

		



@eel.expose
def performHostDiscovery(target_net,scan_type = 'ECHO',dst_timeout = 5):
	
	if not scan_type in ['ECHO','TIME_STAMP','TCP_SYN','TCP_ACK']:
		return
	res ={}
	activeHost = {}
	
	hosts = list(ipaddress.ip_network(target_net))
	writeMsg("Host Discovery Started for {}".format(target_net))
	threads = [None] * len(hosts)
	results = [None] * len(hosts)
	for i in range(len(threads)):
		if scan_type == 'ECHO':
			threads[i] = Thread(target=hd.send_icmp,args=(hosts[i], results, i,8))
		if scan_type == 'TIME_STAMP':
			threads[i] = Thread(target=hd.send_icmp,args=(hosts[i], results, i,13))
		if scan_type == 'TCP_SYN':
			threads[i] = Thread(target = hd.tcp_syn_ping, args=(hosts[i], results,i, dst_timeout, 80) )
		if scan_type == 'TCP_ACK':
			threads[i] = Thread(target=hd.tcp_ack_ping, args=(hosts[i], results,i,dst_timeout,80))
		
		if scan_type != 'ARP':
			threads[i].start()

	if scan_type != 'ARP':
		for i in range(len(threads)):
			threads[i].join()
	# elif scan_type == 'ARP':
	# 	send_arp_req(target_net):

	# for dst_ip in hosts:
	# 	if scan_type == 'TCP_SYN':
	# 		result = hd.tcp_syn_ping(dst_ip,dst_timeout,dst_port=80)
	# 	elif scan_type == 'TCP_ACK':
	# 		result = hd.tcp_ack_ping(dst_ip,dst_timeout,dst_port=80)
	# 	elif scan_type == 'ECHO':
	# 		result = hd.send_icmp(dst_ip,icmp_type = 8 )
	# 	elif scan_type == 'TIME_STAMP':
	# 		result = hd.send_icmp(dst_ip,icmp_type = 13 )

#		result = 'Active'		
	
	hosts_found = [i for i in results if i is not None]
	writeMsg("||Host Discovery Finished for {}|| {} hosts identified".format(target_net,len(hosts_found)))
	for dst_ip in hosts_found:
		activeHost[str(dst_ip)] = {"ports":{},"OS":""}
		addActiveHost(str(dst_ip))
	res['ScanType']	= scan_type
	res['ActiveHosts'] = activeHost
	
	NetworkHosts[str(target_net)]= res
	return NetworkHosts
	
	


def OS_scan(dist_ip ):
	try:
		os_spec = { 'Linux/Unix 2.2-2.4 >':255,
					'Linux/Unix 2.0.x kernel':64,
					'Windows 98':32,
					'Windows':128,
					'AIX ': 60,
					'AIX 3.2, 4.1': 255,
					'BSDI BSD/OS 3.1 and 4.0': 255,
					'Compa Tru64 v5.0': 64,
					'Cisco ': 254,
					'Foundry ': 64,
					'FreeBSD 3.4, 4.0': 255,
					'FreeBSD 5': 64,
					'HP-UX 10.2': 255,
					'HP-UX 11': 255,
					'Irix 6.5.3, 6.5.8': 255,
					'juniper ': 64,
					'MPE/IX (HP) ': 200,
					'Linux 2.0.x kernel': 64,
					'Linux 2.2.14 kernel': 255,
					'Linux 2.4 kernel': 255,
					'Linux Red Hat 9': 64,
					'MacOS/MacTCP X (10.5.6)': 64,
					'NetBSD ': 255,
					'Netgear FVG318 ': 64,
					'OpenBSD 2.6 & 2.7': 255,
					'OpenVMS 07.01.2002': 255,
					'Solaris 2.5.1, 2.6, 2.7, 2.8': 255,
					'Stratus TCP_OS': 255,
					'Stratus STCP': 60,
					'SunOS 5.7': 255,
					'Ultrix V4.2 – 4.5': 255,
					'Windows 98': 32,
					'Windows 98, 98 SE': 128,
					'Windows NT 4 WRKS SP 3, SP 6a': 128,
					'Windows NT 4 Server SP4': 128,
					'Windows ME': 128,
					'Windows 2000 pro': 128,
					'Windows 2000 family': 128,
					'Windows XP': 128,
					'Windows Vista': 128,
					'Windows 7': 128,
					'Windows Server 2008': 128,
					'Windows 10': 128
				}
		pkg = IP(dst=dist_ip,ttl=128)/ICMP()
		
		ans = sr1(pkg,retry=5,timeout=3,inter=1,verbose=0)
		
		try:
			target_ttl = ans.ttl
		except:
			return "Host did not respond"
		os_str =""
		for os in os_spec:
			if target_ttl == os_spec[os] :
				return os
				#os_str = os_str + str(os)
				#print(os_str)
		#return os_str
	except:
		return "Unknown"
@eel.expose
def exportNetworkHosts():
	file_path = filedialog.asksaveasfilename()
	file = open(file_path,"w")
	json.dump(NetworkHosts, file)
	file.close()
	writeMsg("exported to {}".format(file_path))

def updateScanSummary():
	eel.updateNetwork(NetworkHosts)


def addActiveHost(ip):
	eel.appendActiveHost(ip)
	


def addPortScanResult(data):
	PortScanResult.append(data)
	eel.appendPortResult(data)
	

def writeMsg(msg):
	eel.setMessage(str(msg))


if __name__ == '__main__':
	eel.init("web")
	
	
	eel.start("index.html")