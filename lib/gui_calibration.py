import os
import tkinter as tk
from tkinter import filedialog
from lib.calibration import Calibration
from lib.gui_common import *

def inputbox(question, default=None, title="Input", parent=None, bttxt="Ok"):
	d = tk.Toplevel(parent)
	d.title(title)
	tk.Label(d, text=question).pack()
	e = tk.Entry(d, width=50)
	if(default): e.insert(0, default)
	e.pack()
	tk.Button(d, text=bttxt, command=d.quit).pack()
	d.mainloop()
	v = e.get()
	d.destroy()
	return v

class CAL_editor_win(tk.Toplevel):
	def __init__(self, parent=None):
		tk.Toplevel.__init__(self, parent)
		self.title("Calibration CRC")
		self.resizable(0, 0)

		# Menu
		menubar = tk.Menu(self)
		menu = tk.Menu(menubar, tearoff=0)
		menu.add_command(label="Open", command=self.open)
		menu.add_command(label="Save as...", command=self.save)
		menu.add_separator()
		menu.add_command(label="Exit", command=self.destroy)
		menubar.add_cascade(label="File", menu=menu)
		menu = tk.Menu(menubar, tearoff=0)
		menu.add_command(label="Search CRC in T4e program", command=self.wh_search)
		menu.add_command(label="Modify signature to match CRC", command=self.wh_modify_crc)
		menubar.add_cascade(label="White", menu=menu)
		menu = tk.Menu(menubar, tearoff=0)
		menu.add_command(label="Lock", command=self.bl_lock)
		menu.add_command(label="Unlock", command=self.bl_unlock)
		menu.add_command(label="Update CRC", command=self.bl_update_crc)
		menubar.add_cascade(label="Black", menu=menu)
		self.config(menu=menubar)

		# Infos
		self.txt = tk.Text(self, height=12, width=64, state=tk.DISABLED)
		self.txt.pack()

		# Backend
		self.cal = Calibration()
		self.updateText()

	def updateText(self, evt=None):
		self.txt.config(state=tk.NORMAL)
		self.txt.delete('1.0', tk.END)
		self.txt.insert(tk.END, str(self.cal))
		self.txt.config(state=tk.DISABLED)

	@try_msgbox_decorator
	def open(self):
		answer = filedialog.askopenfilename(
			parent = self,
			initialdir = os.getcwd(),
			initialfile = "calrom.bin",
			title = please_select_file,
			filetypes = bin_file
		)
		if(answer):
			self.cal.read_file(answer)
			self.updateText()

	@try_msgbox_decorator
	def save(self):
		answer = filedialog.asksaveasfilename(
			parent = self,
			initialdir = os.getcwd(),
			initialfile = "calrom.bin",
			title = please_select_file,
			filetypes = bin_file
		)
		if(answer):
			self.cal.write_file(answer)

	@try_msgbox_decorator
	def wh_search(self):
		answer = filedialog.askopenfilename(
			parent = self,
			initialdir = os.getcwd(),
			title = please_select_file,
			filetypes = bin_file
		)
		if(answer):
			offset = self.cal.wh_search_crc_cmpli(answer)
			if(offset < 0): msg = "CRC cmplwi not found!"
			else: msg = "CRC cmplwi offset: "+hex(offset)
			messagebox.showinfo(
				master=self,
				title="T4e CRC cmplw offset!",
				message=msg
			)

	@try_msgbox_decorator
	def wh_modify_crc(self):
		desc = inputbox(
			"Give a description (date excluded).\nThe date will be automatically choose to match the given CRC",
			self.cal.get_desc().split(maxsplit=2)[0],
			"Description",
			self
		)
		crc = inputbox(
			"Target CRC",
			hex(self.cal.wh_compute_crc()),
			"CRC",
			self
		)
		self.cal.wh_modify_crc(desc+" ", int(crc, 0))
		self.updateText()

	@try_msgbox_decorator
	def bl_lock(self):
		self.cal.bl_lock()
		self.updateText()

	@try_msgbox_decorator
	def bl_unlock(self):
		self.cal.bl_unlock()
		self.updateText()

	@try_msgbox_decorator
	def bl_update_crc(self):
		self.cal.bl_set_crc(self.cal.bl_compute_crc())
		self.updateText()

