#!/usr/bin/python3

import os
import tkinter as tk
from tkinter import ttk
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
		self.lb = tk.Listbox(master)
		self.lb.bind('<<ListboxSelect>>', self.updateText)
		self.lb.pack()

		# Infos
		self.txt = tk.Text(root, height=20, width=50)
		self.txt.pack()

		# Backend
		self.crp = CRP08()

	def updateList(self, evt=None):
		self.lb.delete(0, tk.END)
		for name in self.crp.chunks[0].toc_values[0]:
			self.lb.insert(tk.END, name)
		self.updateText(evt)

	def updateText(self, evt=None):
		self.txt.delete('1.0', tk.END)
		if(len(self.lb.curselection()) > 0):
			i = self.lb.curselection()[0]
			self.txt.insert(tk.END, str(self.crp.chunks[i+1]))

	def new(self):
		self.crp = CRP08()
		self.updateList()

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

	def save(self):
		answer = filedialog.asksaveasfilename(
			parent = self.master,
			initialdir = os.getcwd(),
			title = "Please select a file:",
			filetypes = crp08_file
		)
		if(answer):
			self.crp.write_file(answer)

	def remove(self):
		if(len(self.lb.curselection()) > 0):
			i = self.lb.curselection()[0]
			self.crp.del_chunk(i+1)
			self.updateList()

	def export(self):
		if(len(self.lb.curselection()) > 0):
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

root = tk.Tk()
app = CRP08_window(root)
root.mainloop()
