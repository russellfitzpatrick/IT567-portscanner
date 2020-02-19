# IT567-portscanner

Must be run with python3!!!

Run using the following command:

python3 port-scanner.py

The following are the flags to use:

      -h: Help text
      -g: Starts GUI. Cannot be used with any other flags. Does not take input
      -t: The type of scan to run. Defaults to tcp. Options are tcp, udp, icmp, trace
      -a: IP Address option. Can be a single IP Address, comma-separated IP Addresses (192.168.1.1,192.168.1.2), a range (192.168.1.1-192.168.1.2), a subnet (192.168.1.0/24), or a file with each IP addresses on a new line
      -p: Port option. Can be a single port, a comma-separated port list (22,80), or a range (22-1024)
      -o: Output file. If you want to produce an html file, designate the file here
      
  TCP will run a SYN port scan.
  UDP will run a UDP port scan.
  ICMP will run a ICMP echo scan to each host.
  Trace will run a traceroute with a ttl of 10.
  
  To run the scan through the GUI, all fields will need to be filled. The results will also be displayed on the GUI.
  
