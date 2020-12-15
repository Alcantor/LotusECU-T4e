#!/usr/bin/python3

import os
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox
from t4e import ECU_T4E
from flasher import Flasher

binary_file = [("Binary File", "*.bin")]

class ECU_T4E_GUI(ECU_T4E):
	def __init__(self, master):
		self.master = master
		self.progressbar = ttk.Progressbar(master, orient=tk.HORIZONTAL, length=100, mode='determinate')
		self.textEntry = tk.StringVar()
		self.entry = tk.Entry(master, state=tk.DISABLED, textvariable = self.textEntry)

	def log(self, msg):
		self.textEntry.set(msg)
		self.master.update_idletasks()

	def progress(self):
		self.bytes_transfered += 128
		fraction = self.bytes_transfered/self.bytes_total
		self.progressbar['value'] = fraction*100
		self.master.update_idletasks()

	def progress_end(self):
		self.progressbar['value'] = 100
		self.master.update_idletasks()

	def download(self, address, size, filename):
		self.progressbar['value'] = 0
		self.bytes_total = size
		self.bytes_transfered = 0
		super().download(address, size, filename)

	def verify(self, address, filename):
		self.bytes_total = os.path.getsize(filename)
		self.progressbar['value'] = 0
		self.bytes_transfered = 0
		super().verify(address, filename)

	def upload(self, address, filename):
		self.bytes_total = os.path.getsize(filename)
		self.progressbar['value'] = 0
		self.bytes_transfered = 0
		super().upload(address, filename)

class Flasher_GUI(Flasher):
	def __init__(self, master):
		self.master = master
		self.progressbar = ttk.Progressbar(master, orient=tk.HORIZONTAL, length=100, mode='determinate')
		self.textEntry = tk.StringVar()
		self.entry = tk.Entry(master, state=tk.DISABLED, textvariable = self.textEntry)

	def log(self, msg):
		self.textEntry.set(msg)
		self.master.update_idletasks()

	def progress(self):
		self.bytes_transfered += 4
		fraction = self.bytes_transfered/self.bytes_total
		self.progressbar['value'] = fraction*100
		self.master.update_idletasks()

	def progress_end(self):
		self.progressbar['value'] = 100
		self.master.update_idletasks()

	def eraseBlock(self, blocks_desc, blocks_mask):
		self.log("Erase " + blocks_desc)
		self.progressbar['value'] = 0
		super().eraseBlock(blocks_mask)
		self.master.update_idletasks()
		self.progressbar['value'] = 100
		
	def verify(self, address, filename):
		self.bytes_total = os.path.getsize(filename)
		self.progressbar['value'] = 0
		self.bytes_transfered = 0
		super().verify(address, filename)

	def program(self, block_mask, address, filename):
		self.bytes_total = os.path.getsize(filename)
		self.progressbar['value'] = 0
		self.bytes_transfered = 0
		super().program(block_mask, address, filename)

class t4e_window():
	def __init__(self, master):
		self.master = master
		master.title('T4e ECU')
		master.resizable(0, 0)

		t4e_frame = tk.LabelFrame(master, text="T4e ECU Communication (Safe)")
		t4e_frame.grid(column=0, row=0, sticky="EW")
		t4e_frame.grid_columnconfigure(0, weight = 1)

		self.t4e = ECU_T4E_GUI(t4e_frame)
		self.t4e.openCAN("socketcan", "can0")
		self.t4e.progressbar.grid(column=0, row=0, columnspan=4, sticky="EW")
		self.t4e.entry.grid(column=0, row=1, columnspan=4, sticky="EW")

		self.combo_zones = ttk.Combobox(t4e_frame, state="readonly", values = [z[0] for z in ECU_T4E.zones])
		self.combo_zones.current(1)
		self.combo_zones.grid(column=0, row=2, sticky="EW")

		self.button_dl = tk.Button(t4e_frame, text="Download", command=self.download)
		self.button_dl.grid(column=1, row=2)

		self.button_v = tk.Button(t4e_frame, text="Verify", command=self.verify)
		self.button_v.grid(column=2, row=2)

		self.button_ifp = tk.Button(t4e_frame, text="Inject Flasher Program", command=self.inject)
		self.button_ifp.grid(column=0, row=3, columnspan=3, sticky='EW')

		fl_frame = tk.LabelFrame(master, text="CAN Flasher (Not Safe)")
		fl_frame.grid(column=0, row=1, sticky="EW")
		fl_frame.grid_columnconfigure(0, weight = 1)

		self.flasher = Flasher_GUI(fl_frame)
		#self.flasher.openCAN("virtual", 0)
		self.flasher.bus = self.t4e.bus
		self.flasher.progressbar.grid(column=0, row=0, columnspan=4, sticky="EW")
		self.flasher.entry.grid(column=0, row=1, columnspan=4, sticky="EW")

		self.button_vfp = tk.Button(fl_frame, text="Verify Flasher Program", command=self.inject_verify)
		self.button_vfp.grid(column=0, row=2, columnspan=4, sticky='EW')

		self.combo_blocks = ttk.Combobox(fl_frame, state="readonly", values = [b[0] for b in Flasher.blocks])
		self.combo_blocks.current(1)
		self.combo_blocks.grid(column=0, row=3, sticky="EW")

		self.button_e = tk.Button(fl_frame, text="Erase", command=self.erase)
		self.button_e.grid(column=1, row=3)

		self.button_pg = tk.Button(fl_frame, text="Program", command=self.program)
		self.button_pg.grid(column=2, row=3)

		self.button_v2 = tk.Button(fl_frame, text="Verify", command=self.verify2)
		self.button_v2.grid(column=3, row=3)

		self.button_reset = tk.Button(fl_frame, text="Reset ECU", command=self.reset)
		self.button_reset.grid(column=0, row=4, columnspan=4, sticky='EW')

		self.flasher_buttons(tk.DISABLED)

	def t4e_buttons(self, state):
		self.button_dl['state'] = state
		self.button_v['state'] = state
		self.button_ifp['state'] = state

	def flasher_buttons(self, state):
		self.button_e['state'] = state
		self.button_pg['state'] = state
		self.button_v2['state'] = state
		self.button_vfp['state'] = state
		self.button_reset['state'] = state

	def download(self):
		zone = ECU_T4E.zones[self.combo_zones.current()]
		answer = filedialog.asksaveasfilename(
			parent = self.master,
			initialdir = os.getcwd(),
			initialfile = zone[3],
			title = "Please select a file:",
			filetypes = binary_file
		)
		if(answer):
			self.t4e_buttons(tk.DISABLED)
			try:
				self.t4e.download(zone[1], zone[2], answer)
			except Exception as e:
				messagebox.showerror(master=self.master, title="Error!", message=str(e))
			self.t4e_buttons(tk.NORMAL)

	def verify(self):
		zone = ECU_T4E.zones[self.combo_zones.current()]
		answer = filedialog.askopenfilename(
			parent = self.master,
			initialdir = os.getcwd(),
			initialfile = zone[3],
			title = "Please select a file:",
			filetypes = binary_file
		)
		if(answer):
			self.t4e_buttons(tk.DISABLED)
			try:
				self.t4e.verify(zone[1], answer)
			except Exception as e:
				messagebox.showerror(master=self.master, title="Error!", message=str(e))
			self.t4e_buttons(tk.NORMAL)

	def inject(self):
		self.t4e_buttons(tk.DISABLED)
		try:
			self.t4e.inject(0x3FF000, "injection/flasher.bin", 0x3FFFDC)
			self.flasher_buttons(tk.NORMAL)
		except Exception as e:
			messagebox.showerror(master=self.master, title="Error!", message=str(e))
			self.t4e_buttons(tk.NORMAL)

	def erase(self):
		block = Flasher.blocks[self.combo_blocks.current()]
		answer = messagebox.askquestion(
			parent = self.master,
			title = 'Be careful!',
			message = 'Do you really want to erase?\n\n'+block[0]
		)
		if(answer != 'yes'): return
		self.flasher_buttons(tk.DISABLED)
		try:
			self.flasher.eraseBlock(block[0],block[1])
		except Exception as e:
			messagebox.showerror(master=self.master, title="Error!", message=str(e))
		self.flasher_buttons(tk.NORMAL)

	def program(self):
		block = Flasher.blocks[self.combo_blocks.current()]
		answer = messagebox.askquestion(
			parent = self.master,
			title = 'Be careful!',
			message = 'Do you really want to program?\n\n'+block[0]
		)
		if(answer != 'yes'): return
		answer = filedialog.askopenfilename(
			parent = self.master,
			initialdir = os.getcwd(),
			initialfile = block[4],
			title = "Please select a file:",
			filetypes = binary_file
		)
		if(answer):
			self.flasher_buttons(tk.DISABLED)
			try:
				self.flasher.program(block[1], block[2], answer)
			except Exception as e:
				messagebox.showerror(master=self.master, title="Error!", message=str(e))
			self.flasher_buttons(tk.NORMAL)

	def verify2(self):
		block = Flasher.blocks[self.combo_blocks.current()]
		answer = filedialog.askopenfilename(
			parent = self.master,
			initialdir = os.getcwd(),
			initialfile = block[4],
			title = "Please select a file:",
			filetypes = binary_file
		)
		if(answer):
			self.flasher_buttons(tk.DISABLED)
			try:
				self.flasher.verify(block[2], answer)
			except Exception as e:
				messagebox.showerror(master=self.master, title="Error!", message=str(e))
			self.flasher_buttons(tk.NORMAL)

	def inject_verify(self):
		self.flasher_buttons(tk.DISABLED)
		try:
			self.flasher.verify(0x3FF000, "injection/flasher.bin")
		except Exception as e:
			messagebox.showerror(master=self.master, title="Error!", message=str(e))
		self.flasher_buttons(tk.NORMAL)

	def reset(self):
		answer = messagebox.askquestion(
			parent = self.master,
			title = 'Be careful!',
			message = 'Do you really want to reset?'
		)
		if(answer != 'yes'): return
		self.flasher_buttons(tk.DISABLED)
		try:
			self.flasher.resetECU()
			self.t4e_buttons(tk.NORMAL)
		except Exception as e:
			messagebox.showerror(master=self.master, title="Error!", message=str(e))
			self.flasher_buttons(tk.NORMAL)

root = tk.Tk()
app = t4e_window(root)
root.mainloop()
