#!/usr/bin/python3

import os, configparser
import tkinter as tk
from tkinter import messagebox
try:
	from lib.gui_crp05 import CRP05_editor_win, CRP05_uploader_win
	from lib.gui_crp08 import CRP08_editor_win, CRP08_uploader_win
	from lib.gui_ltacc import LiveTuningAccess_win
	from lib.gui_calibration import CAL_editor_win
	from lib.gui_flasher import Flasher_win
except ImportError as e:
	messagebox.showerror(
		master=None,
		title="Python Installation Error!",
		message=str(e)
	)
	raise e

class main_window():
	CONFIG_FILE = 'defaults.cfg'
	def __init__(self, master):
		self.master = master
		master.title('Lotus Tools')
		master.resizable(0, 0)
		master.protocol("WM_DELETE_WINDOW", self.on_close)
		master.iconphoto(True, tk.PhotoImage(file="lib/app.png"))
		tk.Button(master, text="CRP05 Editor", height=3, width=20, command=self.open_crp05_editor).pack()
		tk.Button(master, text="CRP08 Editor", height=3, width=20, command=self.open_crp08_editor).pack()
		tk.Button(master, text="CRP05 Uploader\n(K-Line)", height=3, width=20, command=self.open_crp05_uploader).pack()
		tk.Button(master, text="CRP08 Uploader\n(CAN-Bus)", height=3, width=20, command=self.open_crp08_uploader).pack()
		tk.Button(master, text="Live-Tuning Access\n(Unlocked ECU)", height=3, width=20, command=self.open_live_access).pack()
		tk.Button(master, text="Calibration CRC", height=3, width=20, command=self.open_cal_editor).pack()
		tk.Button(master, text="Custom Flasher\n(Stage15)", height=3, width=20, command=self.open_flasher).pack()
		#tk.Button(master, text="ABS EBC430", height=3, width=20, command=self.open_todo).pack()
		self.config = configparser.ConfigParser()
		self.config.read_file(open(self.CONFIG_FILE))
	def open_crp05_editor(self):
		CRP05_editor_win(self.master)
	def open_crp08_editor(self):
		CRP08_editor_win(self.master)
	def open_crp05_uploader(self):
		CRP05_uploader_win(self.config, self.master)
	def open_crp08_uploader(self):
		CRP08_uploader_win(self.config, self.master)
	def open_live_access(self):
		messagebox.showinfo(
			master=self.master,
			title="Info!",
			message="This tool needs a good CAN-Adapter to \"Download\" and \"Verify\" successfully. It will probably fail with slcan devices."
		)
		LiveTuningAccess_win(self.config, self.master)
	def open_cal_editor(self):
		CAL_editor_win(self.master)
	def open_flasher(self):
		Flasher_win(self.config, self.master)
	def on_close(self):
		self.master.destroy()
		with open(self.CONFIG_FILE, 'w') as f: self.config.write(f)

root = tk.Tk()
main_window(root)
root.mainloop()
