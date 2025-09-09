#!/usr/bin/python3

import os, configparser
import tkinter as tk
from tkinter import messagebox, ttk
try:
	from lib.gui_crp01 import CRP01_editor_win, CRP01_uploader_win
	from lib.gui_crp08 import CRP08_editor_win, CRP08_uploader_win
	from lib.gui_ltacc import LiveTuningAccess_win
	from lib.gui_calibration import CAL_editor_win
	from lib.gui_coding import COD_editor_win
	from lib.gui_flasher import Flasher_win
except ImportError as e:
	messagebox.showerror(
		master=None,
		title="Python Installation Error!",
		message=str(e)
	)
	raise e

class main_window():
	PREFS_FILE = 'prefs.cfg'
	def __init__(self, master):
		self.master = master
		master.title('Lotus Tools')
		master.resizable(0, 0)
		master.protocol("WM_DELETE_WINDOW", self.on_close)
		master.iconphoto(True, tk.PhotoImage(file="lib/app.png"))
		tk.Button(master, text="CRP01 Editor", height=3, width=20, command=self.open_crp01_editor).pack()
		tk.Button(master, text="CRP08 Editor", height=3, width=20, command=self.open_crp08_editor).pack()
		tk.Button(master, text="CRP01 Uploader\n(K-Line)", height=3, width=20, command=self.open_crp01_uploader).pack()
		tk.Button(master, text="CRP08 Uploader\n(CAN-Bus)", height=3, width=20, command=self.open_crp08_uploader).pack()
		tk.Button(master, text="Live-Tuning Access\n(Unlocked ECU)", height=3, width=20, command=self.open_live_access).pack()
		tk.Button(master, text="Calibration Tool", height=3, width=20, command=self.open_cal_editor).pack()
		tk.Button(master, text="T6 Coding Tool", height=3, width=20, command=self.open_cod_editor).pack()
		tk.Button(master, text="Custom Flasher\n(Stage15)", height=3, width=20, command=self.open_flasher).pack()
		#tk.Button(master, text="ABS EBC430", height=3, width=20, command=self.open_todo).pack()
		self.prefs = configparser.ConfigParser()
		self.prefs.read_file(open(self.PREFS_FILE))
		# White background for read only combobox
		style = ttk.Style()
		style.map('TCombobox', fieldbackground=[('readonly','white')])
	def open_crp01_editor(self):
		CRP01_editor_win(self.prefs, self.master)
	def open_crp08_editor(self):
		CRP08_editor_win(self.prefs, self.master)
	def open_crp01_uploader(self):
		CRP01_uploader_win(self.prefs, self.master)
	def open_crp08_uploader(self):
		CRP08_uploader_win(self.prefs, self.master)
	def open_live_access(self):
		messagebox.showinfo(
			master=self.master,
			title="Info!",
			message="This tool needs a good CAN-Adapter to \"Download\" and \"Verify\" successfully."
		)
		LiveTuningAccess_win(self.prefs, self.master)
	def open_cal_editor(self):
		CAL_editor_win(self.prefs, self.master)
	def open_cod_editor(self):
		COD_editor_win(self.prefs, self.master)
	def open_flasher(self):
		Flasher_win(self.prefs, self.master)
	def on_close(self):
		self.master.destroy()
		with open(self.PREFS_FILE, 'w') as f: self.prefs.write(f)

root = tk.Tk()
main_window(root)
root.mainloop()
