import tkinter as tk
from tkinter import ttk
from lib.fileprogress import FileProgress

class FileProgress_widget(tk.Frame, FileProgress):
	def __init__(self, parent=None, log_size=5):
		tk.Frame.__init__(self, parent)
		self.lb = tk.Listbox(self, height=log_size, width=45)
		self.lb.pack(fill=tk.X)
		self.pb = ttk.Progressbar(self, orient=tk.HORIZONTAL, mode='determinate')
		self.pb.pack(fill=tk.X)
		self.log_size = log_size

	def log(self, msg):
		self.lb.insert(tk.END, msg)
		if(self.lb.size() > self.log_size):
			self.lb.delete(0, 0)
		self.update()

	def progress_start(self, total_size):
		self.pb['value'] = 0
		self.pb['maximum'] = total_size

	def progress(self, chunk_size):
		self.pb['value'] += chunk_size
		self.update()

	def progress_end(self):
		self.pb['value'] = self.pb['maximum']
		self.update()

