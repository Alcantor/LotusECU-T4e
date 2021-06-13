#!/usr/bin/python3

import os
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from lib.crp05 import CRP05

crp05_file = [("Lotus CRP 05 file", "*.CRP *.crp")]
bin_file = [("Raw binary file", "*.BIN *.bin *.cpt")]
srec_file = [("Motorola S-Record file", "*.SREC *.srec")]

class CRP05_window():
	def __init__(self, master):
		self.master = master
		master.title('CRP05 Editor')
		master.resizable(0, 0)

		# Menu
		menubar = tk.Menu(master)
		filemenu = tk.Menu(menubar, tearoff=0)
		filemenu.add_command(label="New T4", command=self.new_t4)
		filemenu.add_command(label="New T4e", command=self.new_t4e)
		filemenu.add_command(label="Open", command=self.open)
		filemenu.add_command(label="Save as...", command=self.save)
		filemenu.add_separator()
		filemenu.add_command(label="Exit", command=master.destroy)
		menubar.add_cascade(label="File", menu=filemenu)
		filemenu = tk.Menu(menubar, tearoff=0)
		filemenu.add_command(label="Remove S0 (Bootloader)", command=self.remove_bootldr)
		filemenu.add_separator()
		filemenu.add_command(label="Remove S1-S6 (T4 Program)", command=self.remove_t4_prog)
		filemenu.add_command(label="Remove S7 (T4 Calibration)", command=self.remove_t4_cal)
		filemenu.add_separator()
		filemenu.add_command(label="Remove S1 (T4e Calibration)", command=self.remove_t4e_cal)
		filemenu.add_command(label="Remove S2-S7 (T4e Program)", command=self.remove_t4e_prog)
		filemenu.add_separator()
		filemenu.add_command(label="Export SREC", command=self.export_srec)
		filemenu.add_command(label="Import SREC", command=self.import_srec)
		filemenu.add_separator()
		filemenu.add_command(label="Export BIN S7 (T4 Calibration)", command=self.export_t4_cal)
		filemenu.add_command(label="Import BIN S7 (T4 Calibration)", command=self.import_t4_cal)
		filemenu.add_separator()
		filemenu.add_command(label="Export BIN S1 (T4e Calibration)", command=self.export_t4e_cal)
		filemenu.add_command(label="Import BIN S1 (T4e Calibration)", command=self.import_t4e_cal)
		menubar.add_cascade(label="Edit", menu=filemenu)
		master.config(menu=menubar)

		# Infos
		self.txt = tk.Text(master, height=21, width=45, state=tk.DISABLED)
		self.txt.pack()

		# Backend
		self.crp = CRP05()
		self.updateText()

	def updateText(self, evt=None):
		self.txt.config(state=tk.NORMAL)
		self.txt.delete('1.0', tk.END)
		self.txt.insert(tk.END, str(self.crp))
		self.txt.config(state=tk.DISABLED)

	def try_msgbox_decorator(func):
		def wrapper(self):
			try:
				func(self)
			except Exception as e:
				messagebox.showerror(
					parent = self.master,
					master = self.master,
					title = "Error!",
					message = str(e)
				)
		return wrapper

	@try_msgbox_decorator
	def new_t4(self):
		self.crp = CRP05(False)
		self.updateText()

	@try_msgbox_decorator
	def new_t4e(self):
		self.crp = CRP05(True)
		self.updateText()

	@try_msgbox_decorator
	def open(self):
		answer = filedialog.askopenfilename(
			parent = self.master,
			initialdir = os.getcwd(),
			title = "Please select a file:",
			filetypes = crp05_file
		)
		if(answer):
			self.crp.read_file(answer)
			self.updateText()

	@try_msgbox_decorator
	def save(self):
		answer = filedialog.asksaveasfilename(
			parent = self.master,
			initialdir = os.getcwd(),
			title = "Please select a file:",
			filetypes = crp05_file
		)
		if(answer):
			self.crp.write_file(answer)

	@try_msgbox_decorator
	def remove_bootldr(self):
		self.crp.data.subpackets.delete(0x00000, 0x10000)
		self.crp.data.update_header()
		self.updateText()

	@try_msgbox_decorator
	def remove_t4_prog(self):
		self.crp.data.subpackets.delete(0x10000, 0x60000)
		self.crp.data.update_header()
		self.updateText()

	@try_msgbox_decorator
	def remove_t4_cal(self):
		self.crp.data.subpackets.delete(0x70000, 0x10000)
		self.crp.data.update_header()
		self.updateText()

	@try_msgbox_decorator
	def remove_t4e_cal(self):
		self.crp.data.subpackets.delete(0x10000, 0x10000)
		self.crp.data.update_header()
		self.updateText()

	@try_msgbox_decorator
	def remove_t4e_prog(self):
		self.crp.data.subpackets.delete(0x20000, 0x60000)
		self.crp.data.update_header()
		self.updateText()

	@try_msgbox_decorator
	def export_srec(self):
		answer = filedialog.asksaveasfilename(
			parent = self.master,
			initialdir = os.getcwd(),
			initialfile = self.crp.desc+".SREC",
			title = "Please select a file:",
			filetypes = srec_file
		)
		if(answer):
			self.crp.data.subpackets.export_srec(answer, self.crp.desc)

	@try_msgbox_decorator
	def import_srec(self):
		answer = filedialog.askopenfilename(
			parent = self.master,
			initialdir = os.getcwd(),
			initialfile = "T4.SREC",
			title = "Please select a file:",
			filetypes = srec_file
		)
		if(answer):
			self.crp.desc = self.crp.data.subpackets.import_srec(answer)[:11]
			self.crp.data.update_header()
			self.updateText()

	@try_msgbox_decorator
	def export_t4_cal(self):
		answer = filedialog.asksaveasfilename(
			parent = self.master,
			initialdir = os.getcwd(),
			initialfile = "calrom.bin",
			title = "Please select a file:",
			filetypes = bin_file
		)
		if(answer):
			self.crp.data.subpackets.export_bin(answer, 0x70000, 0x10000)

	@try_msgbox_decorator
	def import_t4_cal(self):
		answer = filedialog.askopenfilename(
			parent = self.master,
			initialdir = os.getcwd(),
			initialfile = "calrom.bin",
			title = "Please select a file:",
			filetypes = bin_file
		)
		if(answer):
			self.crp.data.subpackets.import_bin(answer, 0x70000)
			self.crp.data.update_header()
			self.updateText()

	@try_msgbox_decorator
	def export_t4e_cal(self):
		answer = filedialog.asksaveasfilename(
			parent = self.master,
			initialdir = os.getcwd(),
			initialfile = "calrom.bin",
			title = "Please select a file:",
			filetypes = bin_file
		)
		if(answer):
			self.crp.data.subpackets.export_bin(answer, 0x10000, 0x10000)

	@try_msgbox_decorator
	def import_t4e_cal(self):
		answer = filedialog.askopenfilename(
			parent = self.master,
			initialdir = os.getcwd(),
			initialfile = "calrom.bin",
			title = "Please select a file:",
			filetypes = bin_file
		)
		if(answer):
			self.crp.data.subpackets.import_bin(answer, 0x10000)
			self.crp.data.update_header()
			self.updateText()

