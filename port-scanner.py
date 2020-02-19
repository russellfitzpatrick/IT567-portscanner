import argparse
import ipaddress

#from scapy.all import *
from tkinter import *


class GUI:

	def __init__(self, master):
		self.master = master
#		self.initUI()

#	def initUI(self):
		self.master.title("Port Scanner")
#		self.master.pack(fill=BOTH, expand=True)

		self.addresses = StringVar(self.master)
		self.ports = StringVar(self.master)
		self.output_file = StringVar(self.master)
		self.result_text = StringVar(self.master)

		self.addresses.trace("w", self.myfunction)
		self.ports.trace("w", self.myfunction)
		self.output_file.trace("w", self.myfunction)

		frame1 = Frame(self.master)
		frame1.pack(fill=X)

		lbl = Label(frame1, text= "Best Port Scanner", font=("Arial Bold", 25))
		lbl.pack(padx=5, pady=5)


		frame2 = Frame(self.master)
		frame2.pack(fill=X)

		lbl_ipaddress = Label(frame2, text="Input an IP Address, subnet or range", width=36)

		ipaddress = Entry(frame2,width=40, textvariable=self.addresses)

		lbl_ipaddress.pack(side=LEFT, padx=5, pady=5)
		ipaddress.pack(fill=X, padx=5, expand=True)


		frame3 = Frame(self.master)
		frame3.pack(fill=X)

		lbl_port = Label(frame3, text="Input a port or a range", width=36)

		port = Entry(frame3,width=40, textvariable=self.ports)

		lbl_port.pack(side=LEFT, padx=5, pady=5)
		port.pack(fill=X, padx=5, expand=True)



		frame4 = Frame(self.master)
		frame4.pack(fill=X)

		lbl_output = Label(frame4, text="Output file", width=36)

		output = Entry(frame4, width=40, textvariable=self.output_file)

		lbl_output.pack(side=LEFT, padx=5, pady=5)
		output.pack(fill=X, padx=5, expand=True)



		frame5 = Frame(self.master)
		frame5.pack(fill=X, pady=10)

		lbl_scan = Label(frame5, text="Type of scan to be run", width=36)

		self.selected = IntVar()
		self.selected.set(1)


		frame6 = Frame(frame5)
		lbl_scan.pack(side=LEFT, padx=5, pady=5)
		frame6.pack(fill=X, padx=5)

		rad1 = Radiobutton(frame6,text='TCP', value=1, variable=self.selected)
		rad2 = Radiobutton(frame6,text='UDP', value=2, variable=self.selected)
		rad3 = Radiobutton(frame6,text='ICMP', value=3, variable=self.selected)

		rad1.pack( side=TOP )
		rad2.pack( side=TOP )
		rad3.pack( side=TOP )

		frame7 = Frame(self.master)
		frame7.pack(fill=X)

		self.btn = Button(frame7, text="Scan", state='disabled', command=self.clicked)
		self.btn.pack(side=LEFT, padx=5, pady=10)

		frame8 = Frame(self.master)
		frame8.pack(fill=BOTH, expand=True)

		lbl_results = Label(frame8, text="Results")
		lbl_results.pack(side=TOP, anchor=N, padx=5, pady=5)

		self.results = Text(frame8, state='disabled')
		self.results.pack(fill=BOTH, pady=5, padx=5, expand=True)



	def update_text(self, new_text):
		self.results.configure(state='normal')
		self.results.delete("1.0", END)
		self.results.insert(END, new_text)
		self.results.configure(state='disabled')



	def clicked(self):
		self.update_text('Running scan')
		error, addresses = Parse_addresses(self.addresses.get())
		if error:
			self.update_text(addresses)
		error, ports = Parse_ports(self.ports.get())
		if error:
			self.update_text(ports)

		option = self.selected.get()
		if option == 1:
			results = TCP_scan(addresses, ports)
		elif option == 2:
			results = UDP_scan(addresses, ports)
		elif option == 3:
			results = ICMP_scan(addresses, ports)



	def myfunction(self, *args):
		x = self.addresses.get()
		y = self.ports.get()
		z = self.output_file.get()
		if x and y and z:
			self.btn.config(state='normal')
		else:
			self.btn.config(state='disabled')





class AddressChecker(argparse.Action):

	def __call__(self, parser, namespace, values, option_string=None):

		address = values

		error, addresses = Parse_addresses(address)
		if error:
			parser.error(addresses)
		setattr(namespace, self.dest, addresses)



def Parse_addresses(address):
	if ',' in address:
		all_addresses = []
		addresses = address.split(',')
		for a in addresses:
			if '/' in a:
				try:
					network = ipaddress.ip_network(a)
				except:
					return True, "Invalid IP network " + a

				for addr in network:
					all_addresses.append(str(addr))


			elif '-' in a:

				start_ip = None
				end_ip = None
				range_of_addresses = a.split('-')
				if len(range_of_addresses) > 2:
					return True, "Invalid range " + a
				try:
					start_ip = ipaddress.ip_address(range_of_addresses[0])
					end_ip = ipaddress.ip_address(range_of_addresses[1])
				except:
					return True, "Invalid IP address in " + a

				if start_ip > end_ip:
					return True, "Invalid range " + a

				while start_ip <= end_ip:
					all_addresses.append(str(start_ip))
					start_ip += 1

			else:
				try:
					ipaddress.ip_address(a)
				except:
					return True, "Invalid IP address " + a
				all_addresses.append(a)

			return False, all_addresses



	elif '/' in address:
		try:
			network = ipaddress.ip_network(address)
		except:
			return True, "Invalid IP network " + address

		all_addresses = []
		for addr in network:
			all_addresses.append(str(addr))
		return False, all_addresses

	elif '-' in address:
		all_addresses = []
		start_ip = None
		end_ip = None
		addresses = address.split('-')
		if len(addresses) > 2:
			return True, "Invalid range " + address

		try:
			start_ip = ipaddress.ip_address(addresses[0])
			end_ip = ipaddress.ip_address(addresses[1])
		except:
			return True, "Invalid IP address in " + address

		if start_ip > end_ip:
			return True, "Invalid range " + address

		while start_ip <= end_ip:
			all_addresses.append(str(start_ip))
			start_ip += 1

		return False, all_addresses

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
				return True, "Invalid IP address or file " + address

			addresses = file.readlines()

			for a in addresses:
				try:
					ipaddress.ip_address(a.strip())
				except:
					return True, "Invalid IP address " + a.strip() + " in " + address
				all_addresses.append(a.strip())



		return False, all_addresses





class CheckPorts(argparse.Action):


	def __call__(self, parser, namespace, values, option_string=None):
		port = values
		error, ports = Parse_ports(port)
		if error:
			parser.error(ports)
		setattr(namespace, self.dest, ports)


def Parse_ports(port):
	if ',' in port:

		all_ports = []
		ports = port.split(',')
		for p in ports:
			if '-' in p:
				ranges = p.split('-')
				if len(ranges) > 2:
					return True, "Invalid range " + port
				try:
					if int(ranges[0]) > int(ranges[1]) or int(ranges[1]) > 65535:
						return True, "Invalid range " + port
				except:
					return True, "Invalid range " + port

				all_ports.extend(range(int(ranges[0]), int(ranges[1]) + 1))
			else:
				try:
					int(p)
					all_ports.append(int(p))
				except:
					return True, "Must be an integer " + p

		return False, all_ports

	elif '-' in port:

		all_ports = []
		ranges = port.split('-')
		if len(ranges) > 2:
			return True, "Invalid range " + port
		try:
			if int(ranges[0]) > int(ranges[1]) or int(ranges[1]) > 65535 or int(ranges[0]) < 1:
				return True, "Invalid range " + port
		except:
			return True, "Invalid range " + port

		all_ports.extend(range(int(ranges[0]), int(ranges[1]) + 1))
		return False, all_ports

	else:
		try:
			int(port)

			if int(port) > 65535 or int(port) < 1:
				return True, "Invalid port " + port

			return False, port
		except:
			return True, "Invalid port " + port




def ICMP_scan(ips, ports):
	default_timeout = 2

	ans, unans = sr(IP(dst=ips)/ICMP(), timeout=default_timeout)
#	return ans.summary(lambda (s,r): r.sprintf("%IP.src% is alive") )

def TCP_scan(ips, ports):
	default_timeout = 2

	res, unans = sr( IP(dst=ips)
                /TCP(flags="S", dport=ports, sport=RandShort()), timeout=default_timeout )
#	return res.nsummary( lfilter=lambda (s,r): (r.haslayer(TCP) and (r.getlayer(TCP).flags & 2)) )

def UDP_scan(ips, ports):
	default_timeout = 2

	res, unans = sr( IP(dst=ips)
                /UDP(flags="S", dport=ports, sport=RandShort()), timeout=default_timeout )
#	return res.nsummary( lfilter=lambda (s,r): (r.haslayer(UDP)) )


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

	if args.gui:
		window = Tk()
		window.geometry('1000x750')
		app = GUI(window)
		window.mainloop()

	if args.type == 'tcp':
		results = TCP_scan(args.address, args.port)
	elif args.type == 'udp':
		results = UDP_scan(args.address, args.port)
	elif args.type == 'icmp':
		results = ICMP_scan(args.address, args.port)

	formatted_results = produce_report(results)



if __name__ == "__main__":
	main()
