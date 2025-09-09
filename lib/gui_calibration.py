import os
import tkinter as tk
from tkinter import filedialog, simpledialog
from lib.calibration import Calibration
from lib.gui_common import *

class CAL_editor_win(tk.Toplevel):
	def __init__(self, prefs, parent=None):
		tk.Toplevel.__init__(self, parent)
		self.title("Calibration CRC")
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
		self.variant = tk.IntVar()
		for i in range(0, len(Calibration.offsets)):
			menu.add_radiobutton(
				label=Calibration.offsets[i][0],
				value=i,
				variable=self.variant,
				command=self.change
			)
		menubar.add_cascade(label="Variant", menu=menu)
		menu = tk.Menu(menubar, tearoff=0)
		menu.add_command(label="Search CRC in T4e program", command=self.search)
		menu.add_command(label="Modify signature to match CRC", command=self.match_crc)
		menu.add_command(label="Modify generic VIN to match CRC", command=self.match_crc2)
		menu.add_separator()
		menu.add_command(label="Update CRC", command=self.update_crc)
		menu.add_separator()
		menu.add_command(label="Lock", command=self.lock)
		menu.add_command(label="Unlock", command=self.unlock)
		self.menu_edit = menu
		menubar.add_cascade(label="Edit", menu=menu)
		menu = tk.Menu(menubar, tearoff=0)
		menu.add_command(label="Shrink to size", command=self.shrink)
		menu.add_command(label="Extend to 64kb", command=self.ext64)
		menubar.add_cascade(label="Size", menu=menu)
		self.config(menu=menubar)

		# Infos
		self.txt = tk.Text(self, height=10, width=64, state=tk.DISABLED)
		self.txt.pack()

		# Backend
		self.cal = Calibration()
		self.update()

	def update(self):
		states = {True: "normal", False: "disable"}
		s = self.cal.desc == self.cal.crc_data[:32]
		self.menu_edit.entryconfig("Modify signature to match CRC", state=states[s])
		s = self.cal.crc_data[-22:-19] == b"SCC"
		self.menu_edit.entryconfig("Modify generic VIN to match CRC", state=states[s])
		s = self.cal.crc != None
		self.menu_edit.entryconfig("Update CRC", state=states[s])
		s = self.cal.magic != None and self.cal.is_unlocked()
		self.menu_edit.entryconfig("Lock", state=states[s])
		s = self.cal.magic != None and not self.cal.is_unlocked()
		self.menu_edit.entryconfig("Unlock", state=states[s])
		self.txt.config(state=tk.NORMAL)
		self.txt.delete('1.0', tk.END)
		self.txt.insert(tk.END, str(self.cal))
		self.txt.config(state=tk.DISABLED)

	@try_msgbox_decorator
	def open(self):
		answer = filedialog.askopenfilename(
			parent = self,
			initialdir = self.prefs['PATH']['bin'],
			initialfile = "calrom.bin",
			title = please_select_file,
			filetypes = bin_file
		)
		if(answer):
			self.prefs['PATH']['bin'] = os.path.dirname(answer)
			self.cal.read_file(answer)
			try:
				i = self.cal.detect()
				self.variant.set(i)
			except:
				self.cal.map(self.variant.get())
				raise
			finally:
				self.update()

	@try_msgbox_decorator
	def save(self):
		answer = filedialog.asksaveasfilename(
			parent = self,
			initialdir = self.prefs['PATH']['bin'],
			initialfile = "calrom.bin",
			title = please_select_file,
			filetypes = bin_file
		)
		if(answer):
			self.prefs['PATH']['bin'] = os.path.dirname(answer)
			self.cal.write_file(answer)

	@try_msgbox_decorator
	def change(self):
		self.cal.map(self.variant.get())
		self.update()

	@try_msgbox_decorator
	def search(self):
		answer = filedialog.askopenfilename(
			parent = self,
			initialdir = self.prefs['PATH']['bin'],
			initialfile = "prog.bin",
			title = please_select_file,
			filetypes = bin_file
		)
		if(answer):
			self.prefs['PATH']['bin'] = os.path.dirname(answer)
			offset = self.cal.search_crc_cmpli(answer)
			if(offset == None): msg = "CRC cmplwi not found!"
			else: msg = f"CRC cmplwi offset: 0x{offset:06X}"
			messagebox.showinfo(
				master = self,
				title = "T4e CRC cmplw offset!",
				message = msg
			)

	@try_msgbox_decorator
	def match_crc(self):
		desc = simpledialog.askstring(
			"Description",
			"Give a description (date excluded).\nThe date will be automatically choose to match the given CRC",
			parent = self,
			initialvalue = self.cal.get_desc().split(maxsplit=2)[0]
		)
		self.grab_set()
		if(desc == None): return
		crc = simpledialog.askstring(
			"CRC",
			"Target CRC",
			parent = self,
			initialvalue = hex(self.cal.compute_crc())
		)
		self.grab_set()
		if(crc == None): return
		self.cal.match_crc(desc+" ", int(crc, 0))
		self.update()

	@try_msgbox_decorator
	def match_crc2(self):
		crc = simpledialog.askstring(
			"CRC",
			"Target CRC",
			parent = self,
			initialvalue = hex(self.cal.get_crc())
		)
		self.grab_set()
		if(crc == None): return
		self.cal.match_crc2(int(crc, 0))
		self.update()
		tk.messagebox.showinfo(
			parent = self,
			title = "Generic VIN",
			message = "The new generic VIN is:\n\n"+self.cal.get_generic_vin()
		)

	@try_msgbox_decorator
	def update_crc(self):
		self.cal.set_crc(self.cal.compute_crc())
		self.update()

	@try_msgbox_decorator
	def lock(self):
		self.cal.lock()
		self.update()

	@try_msgbox_decorator
	def unlock(self):
		self.cal.unlock()
		self.update()

	@try_msgbox_decorator
	def shrink(self):
		self.cal.resize_file(self.cal.size)
		self.update()

	@try_msgbox_decorator
	def ext64(self):
		self.cal.resize_file(0x10000)
		self.update()
