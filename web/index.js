
var NetworkData = {}
var base_ip = ""
var hostScanType = "ECHO"
var portScanType = "TCP_SYN"
var timeout = 5;
const ipformat = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const netformat = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  
const commonOpenPorts = [20,21,22,25,53,80,110,143,443,8080,8000]

function appendActiveHost(ip){
  activeHosts.push(ip)
  portsToScan = commonPorts;
  eel.performPortScan([ip],portScanType,portsToScan, timeout,base_ip)	
}

function appendPortResult(data){
  for (d in data){
      for (ip in data[d]){
        ports = data[d][ip]["ports"];
        NetworkData[d]["ActiveHosts"][ip]["ports"] = ports;
      }
  }
  displaytable(NetworkData)
}

function triggerHostScan(networkIP){
	activeHosts = []
	eel.performHostDiscovery(networkIP,'ECHO',3)(function (netData){
		updateNetwork(netData)
	})
}


function setMessage(msg){
	console.log(msg)
}

function scan(){
	// var selectedIndex = document.getElementById("HostScanType").selectedIndex;
	// hostScanType = document.getElementById("HostScanType").item(selectedIndex).value;
	// var selectedIndex = document.getElementById("PortScanType").selectedIndex;
	// PortScanType = document.getElementById("PortScanType").item(selectedIndex).value;
	
	if (base_ip.match(ipformat)){
		portScan()
	}
	else if( base_ip.match(netformat)){
		hostScan()
	}
}
function hostScan(){
	base_ip = document.getElementById('targetAdd').value;
	triggerHostScan(base_ip);
}

function triggerportsScan(ips,portsToScan){
	ips = []
	ips = base_ip.split(",")
	eel.performPortScan(ipList,hostScanType,portsToScan, timeout,base_ip);
}
function portScan(){
	ips = document.getElementById('targetAdd').value;
	portsToScan = commonPorts;
	triggerportsScan(ips,portsToScan);
}

function updateNetwork(Data){
	NetworkData = Data
	displaytable(NetworkData)
}
function displaytable(Data){
	var displayTable = document.getElementById("resultTable");
	displayTable.querySelectorAll('tbody').forEach((tbody, i) => {
		displayTable.removeChild(tbody)
		})
	for (net in Data){
		var tbody = document.createElement('tbody');
		
		var tr = document.createElement('tr');
		tr.innerHTML = "<th scope='row'>" + net + "</th>";              //{network_ip:{...}}
		tbody.appendChild(tr);
		displayTable.appendChild(tbody);
		
		for (ip in Data[net]["ActiveHosts"]){        //{network_ip:{ActiveHosts:{host_ip:{}}}}
			
			var host = Data[net]["ActiveHosts"][ip]; 
			
			tr = document.createElement('tr');
			tr.setAttribute("ondblclick",("rowSelected('"+ net +"','"+ ip +"')"));
			tr.innerHTML = "<td>" + ip +"</td>" +
							"<td>"+ host["OS"] +"</td>";             //{network_ip:{"ActiveHosts":{host_ip:{"OS"}}}}
			//for (p in host["ports"]){                       //{network_ip:{ActiveHosts:{host_ip:{"ports":{port_status}}}}}
				var arr = host["ports"]["Open"]; 
				var ports = "";
				for (i in arr){ 
					if (ports ===""){
						ports = arr[i];
					}
					else{
						ports = ports + "," + arr[i];
					}
				} 
				tr.innerHTML = tr.innerHTML + "<td>" + ports + "</tr>";
				var arr = host["ports"]["Closed"]; 
				var ports = "";
				for (i in arr){ 
					if (ports ===""){
						ports = arr[i];
					}
					else{
						ports = ports + "," + arr[i];
					}
				} 
				tr.innerHTML = tr.innerHTML + "<td>" + ports + "</tr>";
			//} 
			tbody.appendChild(tr);
		}

	}
	
}

function rowSelected(net, ip){
	displayHostDetail(net,ip);
}

function displayHostDetail(net,ip){
	const host = NetworkData[net]["ActiveHosts"][ip];
	const open_ports = host["ports"]["Open"];
	const closed_ports = host["ports"]["Closed"];
	const filtered_ports = host["ports"]["Filtered"];
	const open_filtered_ports = host["ports"]["Open|Filtered"];

	document.getElementById("detail_card").style.visibility = "visible";
	
	const detail_host_ip = document.getElementById("detail_host_ip");
	const detail_net = document.getElementById("detail_net");
	const detail_os_icon = document.getElementById("detail_os_icon");
	const detail_os = document.getElementById("detail_os");
	const detail_open_ports = document.getElementById("detail_open_ports");
	const detail_closed_ports = document.getElementById("detail_closed_ports");
	const detail_filtered_ports = document.getElementById("detail_filtered_ports");
	const detail_open_filtered_ports = document.getElementById("detail_open_filtered_ports");
	
	detail_open_ports.value = "";
	detail_closed_ports.value = "";
	detail_filtered_ports.value = "";
	detail_open_filtered_ports.value = "";
	
	detail_os.value = host["OS"];
	detail_host_ip.innerText = ip;
	detail_net.innerText = net;
	

	for (p in open_ports){
		if (detail_open_ports.value == "")
			detail_open_ports.value =  open_ports[p];
		else
			detail_open_ports.value = detail_open_ports.value + "," + open_ports[p];
	}

	for (p in closed_ports){
		if (detail_closed_ports.valuet == "")
			detail_closed_ports.valuet =  closed_ports[p];
		else
			detail_closed_ports.value = detail_closed_ports.value + "," + closed_ports[p];
	}

	for (p in filtered_ports){
		if (detail_filtered_ports.value == "")
			detail_filtered_ports.value =  filtered_ports[p];
		else
			detail_filtered_ports.value = detail_filtered_ports.value + "," + filtered_ports[p];
	}

	for (p in open_filtered_ports){
		if (detail_open_filtered_ports.value == "")
			detail_open_filtered_ports.value =  open_filtered_ports[p];
		else
			detail_open_filtered_ports.value = detail_open_filtered_ports.value + "," + open_filtered_ports[p];
	}

}

function checkip(){
  base_ip = document.getElementById('targetAdd').value;
  
  if (base_ip.match(ipformat)|| base_ip.match(netformat)){
	if ( base_ip.match(ipformat)){
		document.getElementById("HostScanType").disabled=true;
		document.getElementById("targetHelp").innerText= "You entered an host IP, only Port Scan will be performed";
	}
	else if(base_ip.match(netformat)){
		document.getElementById("HostScanType").disabled=false;
		document.getElementById("targetHelp").innerText= "You entered an network IP, Host Discovery &  Port Scan will be performed";
	}
	document.getElementById("PortScanType").disabled=false;
	document.getElementById("scanbtn").disabled=false;
  }
  else{
	document.getElementById("targetHelp").innerText= "Invalid IP Address";
	document.getElementById("PortScanType").disabled=true;
	document.getElementById("scanbtn").disabled=true;
	document.getElementById("HostScanType").disabled=true;
  }
  
}
 eel.expose(appendActiveHost);
 eel.expose(setMessage);
 eel.expose(appendPortResult);
 eel.expose(updateNetwork);
