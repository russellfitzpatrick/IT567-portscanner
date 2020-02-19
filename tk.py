from tkinter import *

window = Tk()

window.title("Port Scanner")
window.geometry('1000x750')

frame1 = Frame(window)
frame1.pack(fill=X)

lbl = Label(frame1, text= "Best Port Scanner", font=("Arial Bold", 25))
lbl.pack(padx=5, pady=5)


frame2 = Frame(window)
frame2.pack(fill=X)

lbl_ipaddress = Label(frame2, text="Input an IP Address, subnet or range", width=36)

ipaddress = Entry(frame2,width=40)

lbl_ipaddress.pack(side=LEFT, padx=5, pady=5)
ipaddress.pack(fill=X, padx=5, expand=True)


frame3 = Frame(window)
frame3.pack(fill=X)

lbl_port = Label(frame3, text="Input a port or a range", width=36)

port = Entry(frame3,width=40)

lbl_port.pack(side=LEFT, padx=5, pady=5)
port.pack(fill=X, padx=5, expand=True)



frame4 = Frame(window)
frame4.pack(fill=X)

lbl_output = Label(frame4, text="Output file", width=36)

output = Entry(frame4, width=40)

lbl_output.pack(side=LEFT, padx=5, pady=5)
output.pack(fill=X, padx=5, expand=True)



frame5 = Frame(window)
frame5.pack(fill=X, pady=10)

lbl_scan = Label(frame5, text="Type of scan to be run", width=36)

selected = IntVar()
selected.set(1)


frame6 = Frame(frame5)
lbl_scan.pack(side=LEFT, padx=5, pady=5)
frame6.pack(fill=X, padx=5)

rad1 = Radiobutton(frame6,text='TCP', value=1, variable=selected)
rad2 = Radiobutton(frame6,text='UDP', value=2, variable=selected)
rad3 = Radiobutton(frame6,text='ICMP', value=3, variable=selected)

rad1.pack( side=TOP )
rad2.pack( side=TOP )
rad3.pack( side=TOP )

def clicked():

    lbl_ipaddress.configure(text="Button was clicked !!")

frame7 = Frame(window)
frame7.pack(fill=X)

btn = Button(frame7, text="Scan", command=clicked)
btn.pack(side=LEFT, padx=5, pady=10)


frame8 = Frame(window)
frame8.pack(fill=BOTH, expand=True)

lbl_results = Label(frame8, text="Results")
lbl_results.pack(side=TOP, anchor=N, padx=5, pady=5)

results = Text(frame8, state='disabled')
results.pack(fill=BOTH, pady=5, padx=5, expand=True)


window.mainloop()
