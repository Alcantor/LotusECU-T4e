import os
import tkinter as tk
from tkinter import filedialog
from lib.crp05 import CRP05
from lib.gui_fileprogress import FileProgress_widget
from lib.gui_common import *
from lib.crp05_uploader import CRP05_uploader

crp05_file = [("Lotus CRP 05 file", "*.CRP *.crp")]
srec_file = [("Motorola S-Record file", "*.SREC *.srec")]

class CRP05_editor_win(tk.Toplevel):
	def __init__(self, parent=None):
		tk.Toplevel.__init__(self, parent)
		self.title('CRP05 Editor')
		self.resizable(0, 0)
		self.grab_set()

		# Menu
		menubar = tk.Menu(self)
		menu = tk.Menu(menubar, tearoff=0)
		menu.add_command(label="New T4", command=self.new_t4)
		menu.add_command(label="New T4e", command=self.new_t4e)
		menu.add_command(label="Open", command=self.open)
		menu.add_command(label="Save as...", command=self.save)
		menu.add_separator()
		menu.add_command(label="Exit", command=self.destroy)
		menubar.add_cascade(label="File", menu=menu)
		menu = tk.Menu(menubar, tearoff=0)
		menu.add_command(label="Remove S0 (Bootloader)", command=lambda:self.remove(0x00000, 0x10000))
		menu.add_separator()
		menu.add_command(label="Remove S1-S6 (T4 Program)", command=lambda:self.remove(0x10000, 0x60000))
		menu.add_command(label="Remove S7 (T4 Calibration)", command=lambda:self.remove(0x70000, 0x10000))
		menu.add_separator()
		menu.add_command(label="Remove S1 (T4e Calibration)", command=lambda:self.remove(0x10000, 0x10000))
		menu.add_command(label="Remove S2-S7 (T4e Program)", command=lambda:self.remove(0x20000, 0x60000))
		menu.add_separator()
		menu.add_command(label="Export SREC", command=self.export_srec)
		menu.add_command(label="Import SREC", command=self.import_srec)
		menu.add_separator()
		menu.add_command(label="Export BIN S7 (T4 Calibration)", command=lambda:self.export_bin("calrom.bin", 0x70000, 0x10000))
		menu.add_command(label="Import BIN S7 (T4 Calibration)", command=lambda:self.import_bin("calrom.bin", 0x70000))
		menu.add_command(label="Export BIN S1-S6 (T4 Program)", command=lambda:self.export_bin("prog.bin", 0x10000, 0x60000))
		menu.add_command(label="Import BIN S1-S6 (T4 Program)", command=lambda:self.import_bin("prog.bin", 0x10000))
		menu.add_separator()
		menu.add_command(label="Export BIN S1 (T4e Calibration)", command=lambda:self.export_bin("calrom.bin", 0x10000, 0x10000))
		menu.add_command(label="Import BIN S1 (T4e Calibration)", command=lambda:self.import_bin("calrom.bin", 0x10000))
		menu.add_command(label="Export BIN S2-S7 (T4e Program)", command=lambda:self.export_bin("prog.bin", 0x20000, 0x60000))
		menu.add_command(label="Import BIN S2-S7 (T4e Program)", command=lambda:self.import_bin("prog.bin", 0x20000))
		menubar.add_cascade(label="Edit", menu=menu)
		self.config(menu=menubar)

		# Infos
		self.txt = tk.Text(self, height=21, width=45, state=tk.DISABLED)
		self.txt.pack()

		# Backend
		self.crp = CRP05()
		self.updateText()

	def updateText(self, evt=None):
		self.txt.config(state=tk.NORMAL)
		self.txt.delete('1.0', tk.END)
		self.txt.insert(tk.END, str(self.crp))
		self.txt.config(state=tk.DISABLED)

	@try_msgbox_decorator
	def new_t4(self):
		self.crp = CRP05(for_t4e=False)
		self.updateText()

	@try_msgbox_decorator
	def new_t4e(self):
		self.crp = CRP05(for_t4e=True)
		self.updateText()

	@try_msgbox_decorator
	def open(self):
		answer = filedialog.askopenfilename(
			parent = self,
			initialdir = os.getcwd(),
			title = please_select_file,
			filetypes = crp05_file
		)
		if(answer):
			self.crp.read_file(answer)
			self.updateText()

	@try_msgbox_decorator
	def save(self):
		answer = filedialog.asksaveasfilename(
			parent = self,
			initialdir = os.getcwd(),
			title = please_select_file,
			filetypes = crp05_file
		)
		if(answer):
			self.crp.write_file(answer)

	@try_msgbox_decorator
	def remove(self, offset, size):
		self.crp.data.subpackets.delete(offset, size)
		self.crp.data.update_header()
		self.updateText()

	@try_msgbox_decorator
	def export_srec(self):
		answer = filedialog.asksaveasfilename(
			parent = self,
			initialdir = os.getcwd(),
			initialfile = self.crp.desc+".SREC",
			title = please_select_file,
			filetypes = srec_file
		)
		if(answer):
			self.crp.data.subpackets.export_srec(answer, self.crp.desc)

	@try_msgbox_decorator
	def import_srec(self):
		answer = filedialog.askopenfilename(
			parent = self,
			initialdir = os.getcwd(),
			initialfile = "T4.SREC",
			title = please_select_file,
			filetypes = srec_file
		)
		if(answer):
			self.crp.desc = self.crp.data.subpackets.import_srec(answer)[:11]
			self.crp.data.update_header()
			self.updateText()

	@try_msgbox_decorator
	def export_bin(self, name, offset, size):
		answer = filedialog.asksaveasfilename(
			parent = self,
			initialdir = os.getcwd(),
			initialfile = name,
			title = please_select_file,
			filetypes = bin_file
		)
		if(answer):
			self.crp.data.subpackets.export_bin(answer, offset, size)

	@try_msgbox_decorator
	def import_bin(self, name, offset):
		answer = filedialog.askopenfilename(
			parent = self,
			initialdir = os.getcwd(),
			initialfile = name,
			title = please_select_file,
			filetypes = bin_file
		)
		if(answer):
			self.crp.data.subpackets.import_bin(answer, offset)
			self.crp.data.update_header()
			self.updateText()

class CRP05_uploader_win(tk.Toplevel):
	def __init__(self, config, parent=None):
		tk.Toplevel.__init__(self, parent)
		self.title('CRP05 Uploader')
		self.resizable(0, 0)
		self.grab_set()
		self.protocol("WM_DELETE_WINDOW", self.on_closing)
		self.run_task = False

		self.com_device = SelectCOM_widget(config, self)
		self.com_device.pack(fill=tk.X)

		up_frame = tk.LabelFrame(self, text="CRP05 Flashing")
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
		self.crp = CRP05(is_encrypted=True)

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
			initialdir = os.getcwd(),
			title = please_select_file,
			filetypes = crp05_file
		)
		if(answer):
			self.p.log("Load "+answer)
			self.crp.read_file(answer)
			self.p.log(" -> "+self.crp.desc)
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
		up = CRP05_uploader(self.p)
		up.open_com(self.com_device.get_port())
		self.run_task = True
		try:
			up.bootstrap(self.crp, ui_cb=self.waitmore)
		finally:
			self.run_task = False
			up.close_com()

