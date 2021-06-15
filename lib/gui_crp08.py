#!/usr/bin/python3

import os
import tkinter as tk
from tkinter import filedialog
from lib.crp08 import CRP08
from lib.gui_fileprogress import FileProgress_widget
from lib.gui_common import *
from lib.crp08_uploader import CRP08_uploader

crp08_file = [("Lotus CRP 08 file", "*.CRP *.crp")]

class CRP08_editor_win(tk.Toplevel):
	def __init__(self, parent=None):
		tk.Toplevel.__init__(self, parent)
		self.title('CRP08 Editor')
		self.resizable(0, 0)

		# Menu
		menubar = tk.Menu(self)
		filemenu = tk.Menu(menubar, tearoff=0)
		filemenu.add_command(label="New", command=self.new)
		filemenu.add_command(label="Open", command=self.open)
		filemenu.add_command(label="Save as...", command=self.save)
		filemenu.add_separator()
		filemenu.add_command(label="Exit", command=self.destroy)
		menubar.add_cascade(label="File", menu=filemenu)
		filemenu = tk.Menu(menubar, tearoff=0)
		filemenu.add_command(label="Remove", command=self.remove)
		filemenu.add_separator()
		filemenu.add_command(label="Export BIN", command=self.export)
		filemenu.add_command(label="Import BIN - T4E Calibration", command=self.import_t4e_cal)
		filemenu.add_command(label="Import BIN - T4E Program", command=self.import_t4e_prog)
		menubar.add_cascade(label="Edit", menu=filemenu)
		self.config(menu=menubar)

		# List
		self.lb = tk.Listbox(self, height=5, width=45)
		self.lb.bind('<<ListboxSelect>>', self.updateText)
		self.lb.pack()

		# Infos
		self.txt = tk.Text(self, height=16, width=45, state=tk.DISABLED)
		self.txt.pack()

		# Backend
		self.crp = CRP08()

	def updateList(self, evt=None):
		# Clear and re-fill the list
		self.lb.delete(0, tk.END)
		for name in self.crp.chunks[0].toc_values[0]:
			self.lb.insert(tk.END, name)
		# Clear the text
		self.txt.config(state=tk.NORMAL)
		self.txt.delete('1.0', tk.END)
		self.txt.config(state=tk.DISABLED)

	def updateText(self, evt=None):
		if(len(self.lb.curselection()) == 0): return
		self.txt.config(state=tk.NORMAL)
		self.txt.delete('1.0', tk.END)
		i = self.lb.curselection()[0]
		self.txt.insert(tk.END, str(self.crp.chunks[i+1]))
		self.txt.config(state=tk.DISABLED)

	@try_msgbox_decorator
	def new(self):
		self.crp = CRP08()
		self.updateList()

	@try_msgbox_decorator
	def open(self):
		answer = filedialog.askopenfilename(
			parent = self,
			initialdir = os.getcwd(),
			title = please_select_file,
			filetypes = crp08_file
		)
		if(answer):
			self.crp.read_file(answer)
			self.updateList()

	@try_msgbox_decorator
	def save(self):
		answer = filedialog.asksaveasfilename(
			parent = self,
			initialdir = os.getcwd(),
			title = please_select_file,
			filetypes = crp08_file
		)
		if(answer):
			self.crp.write_file(answer)

	@try_msgbox_decorator
	def remove(self):
		i = self.lb.curselection()[0]
		self.crp.del_chunk(i+1)
		self.updateList()

	@try_msgbox_decorator
	def export(self):
		i = self.lb.curselection()[0]
		answer = filedialog.asksaveasfilename(
			parent = self,
			initialdir = os.getcwd(),
			initialfile = self.crp.chunks[0].toc_values[0][i],
			title = please_select_file,
			filetypes = bin_file
		)
		if(answer):
			self.crp.chunks[i+1].data.export_bin(answer)

	@try_msgbox_decorator
	def import_t4e_cal(self):
		answer = filedialog.askopenfilename(
			parent = self,
			initialdir = os.getcwd(),
			initialfile = "calrom.bin",
			title = please_select_file,
			filetypes = bin_file
		)
		if(answer):
			self.crp.add_t4e_cal(answer)
			self.updateList()

	@try_msgbox_decorator
	def import_t4e_prog(self):
		answer = filedialog.askopenfilename(
			parent = self,
			initialdir = os.getcwd(),
			initialfile = "calrom.bin",
			title = please_select_file,
			filetypes = bin_file
		)
		if(answer):
			self.crp.add_t4e_prog(answer)
			self.updateList()


class CRP08_uploader_win(tk.Toplevel):
	def __init__(self, parent=None):
		tk.Toplevel.__init__(self, parent)
		self.title('CRP08 Uploader')
		self.resizable(0, 0)

		self.can_device = SelectCAN_widget(self, False)
		self.can_device.pack(fill=tk.X)

		up_frame = tk.LabelFrame(self, text="CRP08 Flashing")
		up_frame.pack(fill=tk.X)

		self.p = FileProgress_widget(up_frame)
		self.p.pack()

		btn_frame = tk.Frame(up_frame)
		btn_frame.pack()
		tk.Button(btn_frame, text="Load file", command=self.load_crp).pack(side=tk.LEFT)
		tk.Button(btn_frame, text="Flash", command=self.flash_crp).pack(side=tk.LEFT)

		# Backend
		self.crp = CRP08(True)

	@try_msgbox_decorator
	def load_crp(self):
		answer = filedialog.askopenfilename(
			parent = self,
			initialdir = os.getcwd(),
			title = please_select_file,
			filetypes = crp08_file
		)
		if(answer):
			self.p.log("Load "+answer)
			self.crp.read_file(answer)
			for name in self.crp.chunks[0].toc_values[0]:
				self.p.log(" -> "+name)

	@try_msgbox_decorator
	def flash_crp(self):
		CRP08_uploader(self.can_device.get_interface(), self.can_device.get_channel(), self.p).bootstrap(self.crp)

