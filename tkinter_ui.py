import Tkinter



def get():

    print E1.get()

    text_area.insert(Tkinter.INSERT, E1.get())

    text_area.insert(Tkinter.INSERT, "\n\n\n")




top = Tkinter.Tk()
text_area = Tkinter.Text()

text_area.pack(side = Tkinter.TOP)
L1 = Tkinter.Label(top, text="Enter handle")
L1.pack( side = Tkinter.LEFT)

E1 = Tkinter.Entry(top, bd =5, width = 100)

E1.pack(side = Tkinter.RIGHT)

button = Tkinter.Button(top, text="Send Message!",command = get)
button.pack(side = Tkinter.RIGHT)
top.mainloop()