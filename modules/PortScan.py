from scapy.all import *
def tcp_connect_scan(dst_ip,dst_port,dst_timeout):
	src_port = RandShort()
	tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=dst_timeout)
	if(str(type(tcp_connect_scan_resp))=="<type 'NoneType'>"):
		return "Closed"
	elif(tcp_connect_scan_resp.haslayer(TCP)):
		if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
			send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=dst_timeout)
			return "Open"
		elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
			return "Closed"
	else:
		return "CHECK"


def stealth_scan(dst_ip,dst_port,dst_timeout):
	src_port = RandShort()
	stealth_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=dst_timeout)
	if(str(type(stealth_scan_resp))=="<type 'NoneType'>"):
		return "Filtered"
	elif(stealth_scan_resp.haslayer(TCP)):
		if(stealth_scan_resp.getlayer(TCP).flags == 0x12):
			send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="R"),timeout=dst_timeout)
			return "Open"
		elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
			return "Closed"
	elif(stealth_scan_resp.haslayer(ICMP)):
		if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
			return "Filtered"
	else:
		return "CHECK"


def xmas_scan(dst_ip,dst_port,dst_timeout):
	xmas_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="FPU"),timeout=dst_timeout)
	if (str(type(xmas_scan_resp))=="<type 'NoneType'>"):
		return "Open|Filtered"
	elif(xmas_scan_resp.haslayer(TCP)):
		if(xmas_scan_resp.getlayer(TCP).flags == 0x14):
			return "Closed"
	elif(xmas_scan_resp.haslayer(ICMP)):
		if(int(xmas_scan_resp.getlayer(ICMP).type)==3 and int(xmas_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
			return "Filtered"
	else:
		return "CHECK"


def fin_scan(dst_ip,dst_port,dst_timeout):
	fin_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="F"),timeout=dst_timeout)
	if (str(type(fin_scan_resp))=="<type 'NoneType'>"):
		return "Open|Filtered"
	elif(fin_scan_resp.haslayer(TCP)):
		if(fin_scan_resp.getlayer(TCP).flags == 0x14):
			return "Closed"
	elif(fin_scan_resp.haslayer(ICMP)):
		if(int(fin_scan_resp.getlayer(ICMP).type)==3 and int(fin_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
			return "Filtered"
	else:
		return "CHECK"


def null_scan(dst_ip,dst_port,dst_timeout):
	null_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags=""),timeout=dst_timeout)
	if (str(type(null_scan_resp))=="<type 'NoneType'>"):
		return "Open|Filtered"
	elif(null_scan_resp.haslayer(TCP)):
		if(null_scan_resp.getlayer(TCP).flags == 0x14):
			return "Closed"
	elif(null_scan_resp.haslayer(ICMP)):
		if(int(null_scan_resp.getlayer(ICMP).type)==3 and int(null_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
			return "Filtered"
	else:
		return "CHECK"


def ack_flag_scan(dst_ip,dst_port,dst_timeout):
	ack_flag_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="A"),timeout=dst_timeout)
	if (str(type(ack_flag_scan_resp))=="<type 'NoneType'>"):
		return "Stateful firewall present\n(Filtered)"
	elif(ack_flag_scan_resp.haslayer(TCP)):
		if(ack_flag_scan_resp.getlayer(TCP).flags == 0x4):
			return "No firewall\n(Unfiltered)"
	elif(ack_flag_scan_resp.haslayer(ICMP)):
		if(int(ack_flag_scan_resp.getlayer(ICMP).type)==3 and int(ack_flag_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
			return "Stateful firewall present\n(Filtered)"
	else:
		return "CHECK"


def window_scan(dst_ip,dst_port,dst_timeout):
	window_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="A"),timeout=dst_timeout)
	if (str(type(window_scan_resp))=="<type 'NoneType'>"):
		return "No response"
	elif(window_scan_resp.haslayer(TCP)):
		if(window_scan_resp.getlayer(TCP).window == 0):
			return "Closed"
		elif(window_scan_resp.getlayer(TCP).window > 0):
			return "Open"
	else:
		return "CHECK"


def udp_scan(dst_ip,dst_port,dst_timeout):
	udp_scan_resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout)
	if (str(type(udp_scan_resp))=="<type 'NoneType'>"):
		retrans = []
		for count in range(0,3):
			retrans.append(sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout))
		for item in retrans:
			if (str(type(item))!="<type 'NoneType'>"):
				udp_scan(dst_ip,dst_port,dst_timeout)
		return "Open|Filtered"
	elif (udp_scan_resp.haslayer(UDP)):
		return "Open"
	elif(udp_scan_resp.haslayer(ICMP)):
		if(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code)==3):
			return "Closed"
		elif(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code) in [1,2,9,10,13]):
			return "Filtered"
	else:
		return "CHECK"