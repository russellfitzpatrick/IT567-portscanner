from tkinter import *
 
window = Tk()
 
window.title("Best Port Scanner")
 
window.geometry('1000x750')

lbl = Label(window, text= "Best Port Scanner", font=("Arial Bold", 25))

lbl.grid(column=1, row=0)
 
lbl_ipaddress = Label(window, text="Input an IP Address or a range (e.g. 192.168.1.0-192.168.1.255 or 192.168.1.0/24)")
 
lbl_ipaddress.grid(column=1, row=1)
 
ipaddress = Entry(window,width=40)
 
ipaddress.grid(column=2, row=1)

lbl_port = Label(window, text="Input a port or a range (e.g. 22-80)")
 
lbl_port.grid(column=1, row=2)
 
port = Entry(window,width=40)
 
port.grid(column=2, row=2)


lbl_scan = Label(window, text="Type of scan to be run")
 
lbl_scan.grid(column=1, row=3)


selected = IntVar()
 
rad1 = Radiobutton(window,text='TCP', value=1, variable=selected)
 
rad2 = Radiobutton(window,text='UDP', value=2, variable=selected)
 
rad3 = Radiobutton(window,text='ICMP', value=3, variable=selected)

rad1.grid(column=2, row=3)
 
rad2.grid(column=2, row=3)
 
rad3.grid(column=2, row=3)

 
def clicked():
 
    lbl_ipaddress.configure(text="Button was clicked !!")
 
btn = Button(window, text="Scan", command=clicked)
 
btn.grid(column=1, row=4)
 
window.mainloop()