from scapy.all import *
def tcp_syn_ping(dst_ip,dst_timeout,dst_port=80):
	src_port = RandShort()
	tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=dst_timeout)
	if(str(type(tcp_connect_scan_resp))=="<type 'NoneType'>"):
		return "No response"
	elif(tcp_connect_scan_resp.haslayer(TCP)):
		if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
			send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=dst_timeout)
			return "Alive"
		elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
			return "Alive"



def tcp_ack_ping(dst_ip,dst_timeout,dst_port = 80 ):
	src_port = RandShort()
	tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="A"),timeout=dst_timeout)
	if(str(type(tcp_connect_scan_resp))=="<type 'NoneType'>"):
		return "No response"
	elif(tcp_connect_scan_resp.haslayer(TCP)):
		if (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
			return "Alive"



def send_icmp(target,icmp_type = 8 ):
	icmp_resp = sr(IP(dst=target)/ICMP( type = icmp_type),timeout=3, retry=2,verbose=0)
	if(str(type(icmp_resp))=="<type 'NoneType'>"):
		return "No response"
	elif(tcp_connect_scan_resp.haslayer(ICMP)):
		return "Alive"




""" def arp_request(network):
	arp_res = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network),timeout=2)
	return(arp_res.summary(lambda (s,r): r.sprintf("%Ether.src% %ARP.psrc%") )) """
	
