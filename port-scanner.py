import argparse
import ipaddress

from scapy.all import *


class AddressChecker(argparse.Action):
	
	def __call__(self, parser, namespace, values, option_string=None):

		address = values

		if ',' in address:
			all_addresses = []
			addresses = address.split(',')
			for a in addresses:
				if '/' in a:
					try:
						network = ipaddress.ip_network(a)
					except:
						parser.error("Invalid IP network " + a)

					for addr in network:
						all_addresses.append(str(addr))


				elif '-' in a:

					start_ip = None
					end_ip = None
					range_of_addresses = a.split('-')
					if len(range_of_addresses) > 2:
						parser.error("Invalid range " + a)

					try:
						start_ip = ipaddress.ip_address(range_of_addresses[0])
						end_ip = ipaddress.ip_address(range_of_addresses[1])
					except:
						parser.error("Invalid IP address in " + a)

					if start_ip > end_ip:
						parser.error("Invalid range " + a)

					while start_ip <= end_ip: 
						all_addresses.append(str(start_ip))
						start_ip += 1

				else:
					try:
						ipaddress.ip_address(a)
					except:
						parser.error("Invalid IP address " + a)
					all_addresses.append(a)

				setattr(namespace, self.dest, all_addresses)			



		elif '/' in address:
			try:
				network = ipaddress.ip_network(address)
			except:
				parser.error("Invalid IP network " + address)

			all_addresses = []
			for addr in network:
				all_addresses.append(str(addr))
			setattr(namespace, self.dest, all_addresses)

		elif '-' in address:
			all_addresses = []
			start_ip = None
			end_ip = None
			addresses = address.split('-')
			if len(addresses) > 2:
				parser.error("Invalid range " + address)

			try:
				start_ip = ipaddress.ip_address(addresses[0])
				end_ip = ipaddress.ip_address(addresses[1])
			except:
				parser.error("Invalid IP address in " + address)

			if start_ip > end_ip:
				parser.error("Invalid range " + address)

			while start_ip <= end_ip: 
				all_addresses.append(str(start_ip))
				start_ip += 1

			setattr(namespace, self.dest, all_addresses)

		else:
			file = None
			all_addresses = []
			try:
				ipaddress.ip_address(address)
				all_addresses.append(address)
			except:
				try:
					file = open(address, 'r')
				except:
					parser.error("Invalid IP address or file " + address)

				addresses = file.readlines()
				
				for a in addresses:
					try:
						ipaddress.ip_address(a.strip())
					except:	
						parser.error("Invalid IP address " + a.strip() + " in " + address)
					all_addresses.append(a.strip())
			
				

			setattr(namespace, self.dest, all_addresses)
					


class CheckPorts(argparse.Action):


	def __call__(self, parser, namespace, values, option_string=None):
		port = values
		if ',' in port:

			all_ports = []
			ports = port.split(',')
			for p in ports:
				if '-' in p:
					ranges = p.split('-')
					if len(ranges) > 2:
						parser.error("Invalid range " + port)
					try:
						if int(ranges[0]) > int(ranges[1]) or int(ranges[1]) > 65535:
							parser.error("Invalid range " + port)
					except:
						parser.error("Invalid range " + port)

					all_ports.extend(range(int(ranges[0]), int(ranges[1]) + 1))
				else:
					try:
						int(p)
						all_ports.append(int(p))
					except:
						parser.error("Must be an integer " + p)

			setattr(namespace, self.dest, all_ports)

		elif '-' in port:

			all_ports = []
			ranges = port.split('-')
			if len(ranges) > 2:
				parser.error("Invalid range " + port)
			try:
				if int(ranges[0]) > int(ranges[1]) or int(ranges[1]) > 65535:
					parser.error("Invalid range " + port)
			except:
				parser.error("Invalid range " + port)			
	
			all_ports.extend(range(int(ranges[0]), int(ranges[1]) + 1))
			setattr(namespace, self.dest, all_ports)

		else:
			try:
				int(port)
			
				setattr(namespace, self.dest, port)
			except:
				parser.error("Invalid port " + port)



def ICMP_scan(ips, ports):
	default_timeout = 2

	ans, unans = sr(IP(dst=ips)/ICMP(), timeout=default_timeout) 
	return ans.summary(lambda (s,r): r.sprintf("%IP.src% is alive") )

def TCP_scan(ips, ports):
	default_timeout = 2

	res, unans = sr( IP(dst=ips)
                /TCP(flags="S", dport=ports, sport=RandShort()), timeout=default_timeout )
	return res.nsummary( lfilter=lambda (s,r): (r.haslayer(TCP) and (r.getlayer(TCP).flags & 2)) )

def UDP_scan(ips, ports):
	default_timeout = 2

	res, unans = sr( IP(dst=ips)
                /UDP(flags="S", dport=ports, sport=RandShort()), timeout=default_timeout )
	return res.nsummary( lfilter=lambda (s,r): (r.haslayer(UDP)) )


def produce_report(results):
	return "<p>" + results + "</p>"


def main():
	parser = argparse.ArgumentParser(description='Port-Scanner using Scapy')

	parser.add_argument('-t', '--type', default='tcp', choices=['tcp', 'udp', 'icmp'], help='Type of scan to be run')
	parser.add_argument('-a', '--address', action=AddressChecker, help='Host to scan')
	parser.add_argument('-p', '--port', action=CheckPorts, help='Port to scan')
	parser.add_argument('-o', '--output', help='Html file for results')
	parser.add_argument('-g', '--gui', action='store_true', help='Starts gui, cannot be used with other tags')

	args = parser.parse_args()
	if args.gui and (args.address or args.port or args.output):
		parser.error("--gui flag cannot be used with other arguments")

	if (args.address and not args.port) or (args.port and not args.address):
		parser.error("Must have both ports and addresses")

	print(args.type)
	print(args.address)
	print(args.port)

	results = None

	if type == 'tcp':
		results = TCP_scan(args.address, args.port)
	elif type == 'udp':
		results = UDP_scan(args.address, args.port)
	elif type == 'icmp':
		results = ICMP_scan(args.address, args.port)

	formatted_results = produce_report(results)



if __name__ == "__main__":
	main()
