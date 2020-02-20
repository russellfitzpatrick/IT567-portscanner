import argparse
import ipaddress

from scapy.all import *
from tkinter import *

# A class for building and operating the GUI

class GUI:

    #Produces the actual GUI
    def __init__(self, master):
        self.master = master

        self.master.title("Port Scanner")

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

        self.selected = StringVar()
        self.selected.set('tcp')


        frame6 = Frame(frame5)
        lbl_scan.pack(side=LEFT, padx=5, pady=5)
        frame6.pack(fill=X, padx=5)

        rad1 = Radiobutton(frame6,text='TCP', value='tcp', variable=self.selected)
        rad2 = Radiobutton(frame6,text='UDP', value='udp', variable=self.selected)
        rad3 = Radiobutton(frame6,text='ICMP', value='icmp', variable=self.selected)
        rad4 = Radiobutton(frame6,text='Trace', value='trace', variable=self.selected)

        rad1.pack( side=TOP )
        rad2.pack( side=TOP )
        rad3.pack( side=TOP )
        rad4.pack( side=TOP )

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


#This is for convenience to update the results text box with the results

    def update_text(self, new_text):
        self.results.configure(state='normal')
        self.results.delete("1.0", END)
        self.results.insert(END, new_text)
        self.results.configure(state='disabled')


#This runs the scan when the button is clicked

    def clicked(self):
        self.update_text('Running scan')
        error, addresses = Parse_addresses(self.addresses.get())
        if error:
            self.update_text(addresses)
        error, ports = Parse_ports(self.ports.get())
        if error:
            self.update_text(ports)

        results = None
        html = None
        option = self.selected.get()
        if option == 'tcp':
            html, results = TCP_scan(addresses, ports)
        elif option == 'udp':
            html, results = UDP_scan(addresses, ports)
        elif option == 'icmp':
            html, results = ICMP_scan(addresses, ports)
        elif option == 'trace':
            html, results = TraceRoute(addresses, ports)

        produce_report(option, html, self.output_file.get())

        self.update_text(results)

#Enables the button if all the inputs are filled

    def myfunction(self, *args):
        x = self.addresses.get()
        y = self.ports.get()
        z = self.output_file.get()
        if x and y and z:
            self.btn.config(state='normal')
        else:
            self.btn.config(state='disabled')



#This is needed by argparse to parse the addresses given on the command line.

class AddressChecker(argparse.Action):

    def __call__(self, parser, namespace, values, option_string=None):

        address = values

        error, addresses = Parse_addresses(address)
        if error:
            parser.error(addresses)
        setattr(namespace, self.dest, addresses)


#Largest function. It just takes the IP address input an parses it into a list of IPs. This can be a comma-separated list, a subnet, a range or one IP address, or any combination of those.

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
        output_file = None
        all_addresses = []
        try:
            ipaddress.ip_address(address)
            all_addresses.append(address)
        except:
            try:
                output_file = open(address, 'r')
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



#This is just an action that is needed by argparse to parse the commandline results.

class CheckPorts(argparse.Action):


    def __call__(self, parser, namespace, values, option_string=None):
        port = values
        error, ports = Parse_ports(port)
        if error:
            parser.error(ports)
        setattr(namespace, self.dest, ports)


#This takes the input and parses it. It checks for ranges or comma separated lists. It creates a list of all the ports and ranges provided

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

            return False, [int(port)]
        except:
            return True, "Invalid port " + port



#Simple ICMP echo scan. Takes a list of IPs and runs a ping sweep on them. Ports not necessary here.

def ICMP_scan(ips, ports):
    default_timeout = 2

    ans, unans = sr(IP(dst=ips)/ICMP(), timeout=default_timeout)
    ans.summary(lambda r: r[1].sprintf("%IP.src% is alive") )

    html = """<tr>
        <th>IP Address</th>
        <th>Is Alive</th>
    </tr>
    """

    result = ""
    for res,na in ans:
        html += "<tr><td>{}</td><td>Yes</td></tr>".format(na.src)
        result += "{} is alive\n".format(na.src)

    return html, result

#TCP Syn port scan. Takes a list of IPs and ports to scan

def TCP_scan(ips, ports):
    default_timeout = 2

    res, unans = sr( IP(dst=ips)
            /TCP(flags="S", dport=ports, sport=RandShort()), timeout=default_timeout )
    res.filter( lambda r: (r[1].haslayer(TCP) and (r[1].getlayer(TCP).flags & 2)) ).make_table(lambda s: (s[0].dst, s[0].dport, "Open"))
    html = """    <tr>
        <th>IP Address</th>
        <th>Open Ports</th>
    </tr>
    """
    result = ""
    results = {}
    for (na,ans) in res:
        if ans.haslayer(TCP) and ans.getlayer(TCP).flags & 2:
            if not na.dst in results:
                results[na.dst] = []
            results[na.dst].append(na.dport)

    for x, y in results.items():
        html += """<tr>
        <th rowspan='{}'>{}</th> 
        """.format(len(y), x)

        result += "Results for {}\n".format(x)

        for port in y:
            html += """<td>{}</td></tr><tr>""".format(port)
            result += "{} is open\n".format(port)

        html += "</tr>"

    return html, result

#UDP port scan. Not very reliable. Takes a list of ips and ports to scan

def UDP_scan(ips, ports):
    default_timeout = 2

    res, unans = sr( IP(dst=ips)
            /UDP(dport=ports, sport=RandShort()), timeout=default_timeout )
    res.nsummary( )

    html = """    <tr>
        <th>IP Address</th>
        <th>Potentially Open Ports</th>
    </tr>
    """
    result = ""

    results = {}
    
    for ans, na in res:
        if na.haslayer(UDP) and not na.haslayer(ICMP):
            if not na.dst in results:
                results[na.dst] = []
            results[na.dst].append(na.dport)
    for ans, na in unans:
        if not na.dst in results:
            results[na.dst] = []
        results[na.dst].append(na.dport)
    for x, y in results.items():
        html += """<tr>
        <th> rowspan='{}'>{}</th>
        """.format(len(y), x)

        result += "Results for {}\n".format(x)

        for port in y:
            html += """<td>{}</td></tr><tr>""".format(port)
            result += "{} is potentially open\n".format(port)

        html += "</tr>"
    


    return html, result

#Traceroute scan. Needs only one port and IP address

def TraceRoute(ips, ports):
    ans, unans = sr(IP(dst=ips[0],ttl=(1,10))/TCP(dport=ports[0], flags='S'))

    ans.summary()

    result = ""
    html = """    <tr>
        <th>IP Address</th>
        <th>Response</th>
        <th>TTL</th>
    </tr>
    """
    ttl = 1
    for res,na in ans:
        result += na.sprintf("%IP.src%\t{ICMP:%ICMP.type%}\t{TCP:%TCP.flags%}\n")
        html += "<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(na[IP].src, na[TCP].flags, ttl)
        ttl += 1

    return html, result


#Final formatting for the HTML Report

def produce_report(scan, results, output_file):
    html_doc = """<html>
    <head>
    <title>Report</title>
    <style>
table, th, td {
  border: 1px solid black;
}
</style>
    </head>
    <body>
    <h1>%s Scan Results</h1>
    <table id='reportTable' cellpadding='10'>
    %s
    </table>
    </body>
    </html>
    """
    html_doc = html_doc % (scan, results)

    f = open(output_file, 'w')
    f.write(html_doc)
    f.close()


def main():
    
#Creates the argparser which parses the command line

    parser = argparse.ArgumentParser(description='Port-Scanner using Scapy')

    parser.add_argument('-t', '--type', default='tcp', choices=['tcp', 'udp', 'icmp', 'trace'], help='Type of scan to be run')
    parser.add_argument('-a', '--address', action=AddressChecker, help='Host to scan')
    parser.add_argument('-p', '--port', action=CheckPorts, help='Port to scan')
    parser.add_argument('-o', '--output', help='Html file for results')
    parser.add_argument('-g', '--gui', action='store_true', help='Starts gui, cannot be used with other tags')

#Error checking. A lot happens in the parsers

    args = parser.parse_args()
    if args.gui and (args.address or args.port or args.output):
        parser.error("--gui flag cannot be used with other arguments")

#Starts the GUI if that is what is specified
    if args.gui:
        window = Tk()
        window.geometry('1000x750')
        app = GUI(window)
        window.mainloop()


    if args.type == 'trace' and (len(args.address) > 1 or len(args.port) > 1):
        parser.error("Only one address and port allowed with traceroute")

    if not args.address:
        parser.error("Addresses are needed")
    if (args.address and not args.port) and (args.type != 'icmp' and args.type != 'trace'):
        parser.error("Must have both ports and addresses " + args.type + " scan")

#Checks which scan to do and returns the results. These will also show the results on the command line

    results = None
    html = None

    if args.type == 'tcp':
        html, results = TCP_scan(args.address, args.port)
    elif args.type == 'udp':
        html, results = UDP_scan(args.address, args.port)
    elif args.type == 'icmp':
        html, results = ICMP_scan(args.address, args.port)
    elif args.type == 'trace':
        html, results = TraceRoute(args.address, args.port)

#Produces the html file if specified

    if args.output:
        produce_report(args.type, html, args.output)



if __name__ == "__main__":
    main()
