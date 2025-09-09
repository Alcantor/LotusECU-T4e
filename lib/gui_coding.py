import os
import tkinter as tk
from tkinter import filedialog, simpledialog
from lib.coding import Coding
from lib.gui_common import *

class COD_editor_win(tk.Toplevel):
	def __init__(self, prefs, parent=None):
		tk.Toplevel.__init__(self, parent)
		self.title("T6 Coding")
		self.resizable(0, 0)
		self.grab_set()
		self.prefs = prefs

		# Menu
		menubar = tk.Menu(self)
		menu = tk.Menu(menubar, tearoff=0)
		menu.add_command(label="Open", command=self.open)
		menu.add_command(label="Save as...", command=self.save)
		menu.add_separator()
		menu.add_command(label="Exit", command=self.destroy)
		menubar.add_cascade(label="File", menu=menu)
		menu = tk.Menu(menubar, tearoff=0)
		menu.add_command(label="Update CRC", command=self.update_crc)
		self.menu_edit = menu
		menubar.add_cascade(label="Edit", menu=menu)
		self.config(menu=menubar)

		# Backend
		self.cod = Coding()

		# Options
		o_frame = tk.LabelFrame(self, text="Options")
		o_frame.pack(side=tk.LEFT)
		self.options = [None]*len(Coding.options)
		for i in range(len(Coding.options)):
			o = Coding.options[i]
			r = i//2
			c = i%2*2
			label = tk.Label(o_frame, text=o[2])
			label.grid(row=r, column=c)
			if(o[3] != None):
				e = ttk.Combobox(o_frame, state="readonly", values=o[3])
				e.bind("<<ComboboxSelected>>", self.on_change)
				self.options[i] = e
			else:
				v = tk.StringVar()
				self.options[i] = v
				e = tk.Entry(o_frame, textvariable = v)
				e.bind("<FocusOut>", self.on_change)
			e.grid(row=r, column=c+1)

		# Results
		r_frame = tk.LabelFrame(self, text="Results")
		r_frame.pack(side=tk.LEFT)
		self.r_items = (
			("VIN", lambda: self.cod.get_vin()),
			("MODEL", lambda: self.cod.get_model()),
			("CRC", lambda: f"0x{self.cod.compute_crc():04X}"),
			("Stored CRC", lambda: f"0x{self.cod.get_crc():04X}"),
			("Variant (Big Endian)", lambda: f"0x{self.cod.get_variant():016X}"),
			("Variant (Lotus Tools)", lambda: f"0x{self.cod.get_variant_lotus():016X}"),
			("Variant (Little Endian)", lambda: f"0x{self.cod.get_variant_little():016X}")
		)
		self.results = [None]*len(self.r_items)
		for i in range(len(self.r_items)):
			label = tk.Label(r_frame, text=self.r_items[i][0])
			label.grid(row=i, column=0)
			v = tk.StringVar()
			self.results[i] = v
			e = tk.Entry(r_frame, textvariable=v, width=32)
			e.configure(state='readonly')
			e.grid(row=i, column=1)

		self.update_options()
		self.update_results()

	def update_options(self):
		variant = self.cod.get_variant()
		for i in range(len(Coding.options)):
			o = Coding.options[i]
			value = (variant >> o[0]) & o[1]
			if(o[3] != None):
				self.options[i].current(value)
			else:
				self.options[i].set(value)

	def update_results(self):
		for i in range(len(self.r_items)):
			self.results[i].set(self.r_items[i][1]())

	@try_msgbox_decorator
	def on_change(self, event):
		variant = 0
		for i in range(len(Coding.options)):
			o = Coding.options[i]
			if(o[3] != None):
				value = self.options[i].current()
			else:
				value = int(self.options[i].get()) & o[1]
				self.options[i].set(value) # Write back the masked value
			variant |= (value << o[0])
		self.cod.set_variant(variant)
		self.update_results()

	@try_msgbox_decorator
	def open(self):
		answer = filedialog.askopenfilename(
			parent = self,
			initialdir = self.prefs['PATH']['bin'],
			initialfile = "coding.bin",
			title = please_select_file,
			filetypes = bin_file
		)
		if(answer):
			self.prefs['PATH']['bin'] = os.path.dirname(answer)
			self.cod.read_file(answer)
			self.update_options()
			self.update_results()

	@try_msgbox_decorator
	def save(self):
		answer = filedialog.asksaveasfilename(
			parent = self,
			initialdir = self.prefs['PATH']['bin'],
			initialfile = "coding.bin",
			title = please_select_file,
			filetypes = bin_file
		)
		if(answer):
			self.prefs['PATH']['bin'] = os.path.dirname(answer)
			self.cod.write_file(answer)

	@try_msgbox_decorator
	def update_crc(self):
		self.cod.set_crc(self.cod.compute_crc())
		self.update_results()
