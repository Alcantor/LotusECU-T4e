#!/usr/bin/python3

import os
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox
from bin2crp import CRP08

crp08_file = [("Lotus CRP 08 File", "*.CRP")]

class CRP08_window():
	def __init__(self, master):
		self.master = master
		master.title('CRP08 Editor')
		master.resizable(0, 0)

		# Menu
		menubar = tk.Menu(master)
		filemenu = tk.Menu(menubar, tearoff=0)
		filemenu.add_command(label="Open", command=self.open)
		menubar.add_cascade(label="File", menu=filemenu)
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
		for name in self.crp.chunks[0].values[0]:
			self.lb.insert(tk.END, name)

	def updateText(self, evt=None):
		i = self.lb.curselection()[0]
		self.txt.delete('1.0', tk.END)
		self.txt.insert(tk.END, str(self.crp.chunks[i+1]))

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

root = tk.Tk()
app = CRP08_window(root)
root.mainloop()
