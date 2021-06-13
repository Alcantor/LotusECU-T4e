#!/usr/bin/python3

import os
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from lib.crp08 import CRP08

crp08_file = [("Lotus CRP 08 file", "*.CRP *.crp")]
bin_file = [("Raw binary file", "*.BIN *.bin *.cpt")]

class CRP08_window():
	def __init__(self, master):
		self.master = master
		master.title('CRP08 Editor')
		master.resizable(0, 0)

		# Menu
		menubar = tk.Menu(master)
		filemenu = tk.Menu(menubar, tearoff=0)
		filemenu.add_command(label="New", command=self.new)
		filemenu.add_command(label="Open", command=self.open)
		filemenu.add_command(label="Save as...", command=self.save)
		filemenu.add_separator()
		filemenu.add_command(label="Exit", command=master.destroy)
		menubar.add_cascade(label="File", menu=filemenu)
		filemenu = tk.Menu(menubar, tearoff=0)
		filemenu.add_command(label="Remove", command=self.remove)
		filemenu.add_separator()
		filemenu.add_command(label="Export BIN", command=self.export)
		filemenu.add_command(label="Import BIN - T4E Calibration", command=self.import_t4e_cal)
		filemenu.add_command(label="Import BIN - T4E Program", command=self.import_t4e_prog)
		menubar.add_cascade(label="Edit", menu=filemenu)
		master.config(menu=menubar)

		# List
		self.lb = tk.Listbox(master, height=5, width=45)
		self.lb.bind('<<ListboxSelect>>', self.updateText)
		self.lb.pack()

		# Infos
		self.txt = tk.Text(master, height=16, width=45, state=tk.DISABLED)
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
	def new(self):
		self.crp = CRP08()
		self.updateList()

	@try_msgbox_decorator
	def open(self):
		answer = filedialog.askopenfilename(
			parent = self.master,
			initialdir = os.getcwd(),
			title = "Please select a file:",
			filetypes = crp08_file
		)
		if(answer):
			self.crp.read_file(answer)
			self.updateList()

	@try_msgbox_decorator
	def save(self):
		answer = filedialog.asksaveasfilename(
			parent = self.master,
			initialdir = os.getcwd(),
			title = "Please select a file:",
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
			parent = self.master,
			initialdir = os.getcwd(),
			initialfile = self.crp.chunks[0].toc_values[0][i],
			title = "Please select a file:",
			filetypes = bin_file
		)
		if(answer):
			self.crp.chunks[i+1].data.export_bin(answer)

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
			self.crp.add_t4e_cal(answer)
			self.updateList()

	@try_msgbox_decorator
	def import_t4e_prog(self):
		answer = filedialog.askopenfilename(
			parent = self.master,
			initialdir = os.getcwd(),
			initialfile = "calrom.bin",
			title = "Please select a file:",
			filetypes = bin_file
		)
		if(answer):
			self.crp.add_t4e_prog(answer)
			self.updateList()

