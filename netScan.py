import eel
from scapy.all import *
import ipaddress
from threading import Thread
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
		os_ttl = {'Linux/Unix 2.2-2.4 >':255,'Linux/Unix 2.0.x kernel':64,'Windows 98':32,'Windows':128}
		pkg = IP(dst=dist_ip,ttl=128)/ICMP()
		
		ans, _ = sr1(pkg,retry=5,timeout=3,inter=1,verbose=0)
		
		try:
			target_ttl = ans[0][1].ttl
		except:
			return "Host did not respond"

		for ttl in os_ttl:
			if target_ttl == os_ttl[ttl]:
				return ttl
	except:
		return "Unknown"

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