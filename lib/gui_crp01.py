import os
import tkinter as tk
from tkinter import filedialog
from lib.crp01 import CRP01
from lib.gui_fileprogress import FileProgress_widget
from lib.gui_common import *
from lib.crp01_uploader import CRP01_uploader

crp01_file = [("Lotus CRP 01 file", "*.CRP *.crp")]
srec_file = [("Motorola S-Record file", "*.SREC *.srec")]

class CRP01_editor_win(tk.Toplevel):
	def __init__(self, prefs, parent=None):
		tk.Toplevel.__init__(self, parent)
		self.title('CRP01 Editor')
		self.resizable(0, 0)
		self.grab_set()
		self.prefs = prefs

		# Menu
		menubar = tk.Menu(self)
		menu = tk.Menu(menubar, tearoff=0)
		menu.add_command(label="New", command=self.new)
		menu.add_command(label="Open", command=self.open)
		menu.add_command(label="Save as...", command=self.save)
		menu.add_separator()
		menu.add_command(label="Exit", command=self.destroy)
		menubar.add_cascade(label="File", menu=menu)
		menu = tk.Menu(menubar, tearoff=0)
		menu.add_command(label="Remove Bootloader", command=self.remove_boot)
		menu.add_separator()
		menu.add_command(label="Remove Calibration", command=self.remove_cal)
		menu.add_command(label="Export BIN Calibration", command=self.export_cal)
		menu.add_command(label="Import BIN Calibration", command=self.import_cal)
		menu.add_separator()
		menu.add_command(label="Remove Program", command=self.remove_prog)
		menu.add_command(label="Export BIN Program", command=self.export_prog)
		menu.add_command(label="Import BIN Program", command=self.import_prog)
		menu.add_separator()
		menu.add_command(label="Export SREC", command=self.export_srec)
		menu.add_command(label="Import SREC", command=self.import_srec)
		menubar.add_cascade(label="Edit", menu=menu)
		menu = tk.Menu(menubar, tearoff=0)
		self.variant = tk.IntVar()
		for i in range(0, len(CRP01.variants)):
			menu.add_radiobutton(
				label=CRP01.variants[i][0],
				value=i,
				variable=self.variant,
				command=self.new
			)
		menubar.add_cascade(label="Variant", menu=menu)
		self.config(menu=menubar)

		# Infos
		self.txt = tk.Text(self, height=21, width=45, state=tk.DISABLED)
		self.txt.pack()

		# Backend
		self.crp = CRP01()
		self.updateText()

	def updateText(self, evt=None):
		self.txt.config(state=tk.NORMAL)
		self.txt.delete('1.0', tk.END)
		self.txt.insert(tk.END, str(self.crp))
		self.txt.config(state=tk.DISABLED)

	@try_msgbox_decorator
	def new(self):
		self.crp = CRP01(self.variant.get())
		self.updateText()

	@try_msgbox_decorator
	def open(self):
		answer = filedialog.askopenfilename(
			parent = self,
			initialdir = self.prefs['PATH']['crp01'],
			title = please_select_file,
			filetypes = crp01_file
		)
		if(answer):
			self.prefs['PATH']['crp01'] = os.path.dirname(answer)
			self.crp = CRP01(self.variant.get())
			self.crp.read_file(answer)
			self.updateText()

	@try_msgbox_decorator
	def save(self):
		answer = filedialog.asksaveasfilename(
			parent = self,
			initialdir = self.prefs['PATH']['crp01'],
			title = please_select_file,
			filetypes = crp01_file
		)
		if(answer):
			self.prefs['PATH']['crp01'] = os.path.dirname(answer)
			self.crp.write_file(answer)

	@try_msgbox_decorator
	def remove_boot(self):
		self.crp.data.subpackets.delete(0x00000, 0x10000)
		self.crp.data.update_header()
		self.updateText()

	def remove_cal(self):
		v = CRP01.variants[self.variant.get()]
		self.crp.data.subpackets.delete(v[3], v[4])
		self.crp.data.update_header()
		self.updateText()

	def remove_prog(self):
		v = CRP01.variants[self.variant.get()]
		self.crp.data.subpackets.delete(v[5], v[6])
		self.crp.data.update_header()
		self.updateText()

	@try_msgbox_decorator
	def export_srec(self):
		answer = filedialog.asksaveasfilename(
			parent = self,
			initialdir = self.prefs['PATH']['srec'],
			initialfile = self.crp.desc+".SREC",
			title = please_select_file,
			filetypes = srec_file
		)
		if(answer):
			self.prefs['PATH']['srec'] = os.path.dirname(answer)
			self.crp.data.subpackets.export_srec(answer, self.crp.desc)

	@try_msgbox_decorator
	def import_srec(self):
		answer = filedialog.askopenfilename(
			parent = self,
			initialdir = self.prefs['PATH']['srec'],
			initialfile = "T4.SREC",
			title = please_select_file,
			filetypes = srec_file
		)
		if(answer):
			self.prefs['PATH']['srec'] = os.path.dirname(answer)
			self.crp.desc = self.crp.data.subpackets.import_srec(answer)[:11]
			self.crp.data.update_header()
			self.updateText()

	@try_msgbox_decorator
	def export_cal(self):
		answer = filedialog.asksaveasfilename(
			parent = self,
			initialdir = self.prefs['PATH']['bin'],
			initialfile = "calrom.bin",
			title = please_select_file,
			filetypes = bin_file
		)
		if(answer):
			self.prefs['PATH']['bin'] = os.path.dirname(answer)
			v = CRP01.variants[self.variant.get()]
			self.crp.data.subpackets.export_bin(answer, v[3], v[4])

	@try_msgbox_decorator
	def import_cal(self):
		answer = filedialog.askopenfilename(
			parent = self,
			initialdir = self.prefs['PATH']['bin'],
			initialfile = "calrom.bin",
			title = please_select_file,
			filetypes = bin_file
		)
		if(answer):
			self.prefs['PATH']['bin'] = os.path.dirname(answer)
			v = CRP01.variants[self.variant.get()]
			self.crp.data.subpackets.import_bin(answer, v[3])
			self.crp.data.update_header()
			self.updateText()

	@try_msgbox_decorator
	def export_prog(self):
		answer = filedialog.asksaveasfilename(
			parent = self,
			initialdir = self.prefs['PATH']['bin'],
			initialfile = "prog.bin",
			title = please_select_file,
			filetypes = bin_file
		)
		if(answer):
			self.prefs['PATH']['bin'] = os.path.dirname(answer)
			v = CRP01.variants[self.variant.get()]
			self.crp.data.subpackets.export_bin(answer, v[5], v[6])

	@try_msgbox_decorator
	def import_prog(self):
		answer = filedialog.askopenfilename(
			parent = self,
			initialdir = self.prefs['PATH']['bin'],
			initialfile = "prog.bin",
			title = please_select_file,
			filetypes = bin_file
		)
		if(answer):
			self.prefs['PATH']['bin'] = os.path.dirname(answer)
			v = CRP01.variants[self.variant.get()]
			self.crp.data.subpackets.import_bin(answer, v[5])
			self.crp.data.update_header()
			self.updateText()

class CRP01_uploader_win(tk.Toplevel):
	def __init__(self, prefs, parent=None):
		tk.Toplevel.__init__(self, parent)
		self.title('CRP01 Uploader')
		self.resizable(0, 0)
		self.grab_set()
		self.protocol("WM_DELETE_WINDOW", self.on_closing)
		self.run_task = False
		self.prefs = prefs

		self.com_device = SelectCOM_widget(prefs, self)
		self.com_device.pack(fill=tk.X)

		up_frame = tk.LabelFrame(self, text="CRP01 Flashing")
		up_frame.pack(fill=tk.X)

		self.p = FileProgress_widget(up_frame)
		self.p.pack()

		btn_frame = tk.Frame(up_frame)
		btn_frame.pack()
		self.btn_load = tk.Button(btn_frame, text="Load file", command=self.load_crp)
		self.btn_load.pack(side=tk.LEFT)
		self.btn_flash = tk.Button(btn_frame, text="Flash", command=self.flash_crp, state=tk.DISABLED)
		self.btn_flash.pack(side=tk.LEFT)

		# Backend
		self.crp = CRP01(None)

	def lock_buttons_decorator(func):
		def wrapper(self):
			self.btn_load['state'] = tk.DISABLED
			self.btn_flash['state'] = tk.DISABLED
			func(self)
			self.btn_load['state'] = tk.NORMAL
			self.btn_flash['state'] = tk.NORMAL
		return wrapper

	@try_msgbox_decorator
	def load_crp(self):
		answer = filedialog.askopenfilename(
			parent = self,
			initialdir = self.prefs['PATH']['crp01'],
			title = please_select_file,
			filetypes = crp01_file
		)
		if(answer):
			initialdir = self.prefs['PATH']['crp01'],
			self.p.log(f"Load {answer}")
			self.crp.read_file(answer)
			self.p.log(f" -> {self.crp.desc}")
			self.btn_flash['state'] = tk.NORMAL

	def on_closing(self):
		if(not self.run_task): self.destroy()
		else: self.run_task = False

	def waitmore(self):
		self.update()
		if(not self.run_task): raise Exception("Terminated by user")

	@lock_buttons_decorator
	@try_msgbox_decorator
	def flash_crp(self):
		up = CRP01_uploader(self.p)
		up.open_com(self.com_device.get_port())
		self.run_task = True
		try:
			up.bootstrap(self.crp, ui_cb=self.waitmore)
		finally:
			self.run_task = False
			up.close_com()

