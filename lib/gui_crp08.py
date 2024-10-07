import os
import tkinter as tk
from tkinter import filedialog
from lib.crp08 import CRP08
from lib.gui_fileprogress import FileProgress_widget
from lib.gui_common import *
from lib.crp08_uploader import CRP08_uploader

crp08_file = [("Lotus CRP 08 file", "*.CRP *.crp")]

class CRP08_editor_win(tk.Toplevel):
	def __init__(self, prefs, parent=None):
		tk.Toplevel.__init__(self, parent)
		self.title('CRP08 Editor')
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
		menu.add_command(label="Remove", command=self.remove)
		menu.add_separator()
		menu.add_command(label="Export BIN", command=self.export)
		menu.add_command(label="Import BIN - Calibration", command=self.import_cal)
		menu.add_command(label="Import BIN - Program", command=self.import_prog)
		menubar.add_cascade(label="Edit", menu=menu)
		menu = tk.Menu(menubar, tearoff=0)
		self.variant = tk.IntVar()
		for i in range(0, len(CRP08.variants)):
			menu.add_radiobutton(
				label=CRP08.variants[i][0],
				value=i,
				variable=self.variant,
				#command=self.change
			)
		menubar.add_cascade(label="Variant", menu=menu)
		self.config(menu=menubar)

		# List
		self.lb = tk.Listbox(self, height=5)
		self.lb.bind('<<ListboxSelect>>', self.updateText)
		self.lb.pack(fill=tk.X)

		# Infos
		self.txt = tk.Text(self, height=17, width=45, state=tk.DISABLED)
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
			initialdir = self.prefs['PATH']['crp08'],
			title = please_select_file,
			filetypes = crp08_file
		)
		if(answer):
			self.prefs['PATH']['crp08'] = os.path.dirname(answer)
			self.crp.read_file(answer, self.variant.get())
			self.updateList()

	@try_msgbox_decorator
	def save(self):
		answer = filedialog.asksaveasfilename(
			parent = self,
			initialdir = self.prefs['PATH']['crp08'],
			title = please_select_file,
			filetypes = crp08_file
		)
		if(answer):
			self.prefs['PATH']['crp08'] = os.path.dirname(answer)
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
			initialdir = self.prefs['PATH']['bin'],
			initialfile = self.crp.chunks[0].toc_values[0][i],
			title = please_select_file,
			filetypes = bin_file
		)
		if(answer):
			self.prefs['PATH']['bin'] = os.path.dirname(answer)
			self.crp.chunks[i+1].data.export_bin(answer)

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
			self.crp.add_cal(answer, self.variant.get())
			self.updateList()

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
			self.crp.add_prog(answer, self.variant.get())
			self.updateList()

class CRP08_uploader_win(tk.Toplevel):
	def __init__(self, prefs, parent=None):
		tk.Toplevel.__init__(self, parent)
		self.title('CRP08 Uploader')
		self.resizable(0, 0)
		self.grab_set()
		self.protocol("WM_DELETE_WINDOW", self.on_closing)
		self.run_task = False
		self.prefs = prefs

		self.can_device = SelectCAN_widget(prefs, self, False)
		self.can_device.pack(fill=tk.X)

		up_frame = tk.LabelFrame(self, text="CRP08 Flashing")
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
		self.crp = CRP08()
		self.up = None

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
			initialdir = self.prefs['PATH']['crp08'],
			title = please_select_file,
			filetypes = crp08_file
		)
		if(answer):
			self.prefs['PATH']['crp08'] = os.path.dirname(answer)
			self.p.log(f"Load {answer}")
			self.crp.read_file(answer, None)
			for name in self.crp.chunks[0].toc_values[0]:
				self.p.log(f" -> {name}")
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
		up = CRP08_uploader(self.can_device.get_interface(), self.can_device.get_channel(), self.p)
		self.run_task = True
		try:
			up.bootstrap(self.crp, ui_cb=self.waitmore)
		finally:
			self.run_task = False
			up.close_can()

