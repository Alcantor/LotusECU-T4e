#!/usr/bin/python3

import os, can
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox
from t4e import ECU_T4E
from flasher import Flasher
from lib.fileprogress import FileProgress
from lib.gui_crp05 import CRP05_window
from lib.gui_crp08 import CRP08_window

binary_file = [("Binary File", "*.bin")]

class FileProgressGui(FileProgress):
	def __init__(self, master):
		self.master = master
		self.progressbar = ttk.Progressbar(master, orient=tk.HORIZONTAL, length=100, mode='determinate')
		self.textEntry = tk.StringVar()
		self.entry = tk.Entry(master, state=tk.DISABLED, textvariable=self.textEntry)

	def log(self, msg):
		self.textEntry.set(msg)
		self.master.update()

	def progress_start(self, total_size):
		self.progressbar['value'] = 0
		self.bytes_total = total_size
		self.bytes_transfered = 0

	def progress(self, chunk_size):
		self.bytes_transfered += chunk_size
		fraction = self.bytes_transfered/self.bytes_total
		self.progressbar['value'] = fraction*100
		self.master.update()

	def progress_end(self):
		self.progressbar['value'] = 100
		self.master.update()

class t4e_window():
	def __init__(self, master):
		self.master = master
		master.title('T4e ECU')
		master.resizable(0, 0)

		can_frame = tk.LabelFrame(master, text="CAN Device")
		can_frame.grid(column=0, row=0, sticky="EW")
		can_frame.grid_columnconfigure(0, weight = 1)

		self.combo_interface = ttk.Combobox(can_frame, state="readonly", values = ["socketcan", "ixxat", "serial", "slcan"])
		self.combo_interface.current(0)
		self.combo_interface.grid(column=0, row=0, sticky="EW")

		self.string_channel = tk.StringVar()
		self.string_channel.set("can0")
		self.entry_channel = tk.Entry(can_frame, textvariable = self.string_channel)
		self.entry_channel.grid(column=1, row=0, sticky="EW")

		self.combo_speed = ttk.Combobox(can_frame, state="readonly", values = ["white (1 Mb/s)", "black (500 kb/s)"])
		self.combo_speed.current(0)
		self.combo_speed.grid(column=2, row=0, sticky="EW")

		t4e_frame = tk.LabelFrame(master, text="T4e Unlocked ECU Communication (Safe)")
		t4e_frame.grid(column=0, row=1, sticky="EW")
		t4e_frame.grid_columnconfigure(0, weight = 1)

		self.t4e_gui = FileProgressGui(t4e_frame)
		self.t4e = ECU_T4E(None, self.t4e_gui)
		self.t4e_gui.progressbar.grid(column=0, row=0, columnspan=4, sticky="EW")
		self.t4e_gui.entry.grid(column=0, row=1, columnspan=4, sticky="EW")

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
		fl_frame.grid(column=0, row=2, sticky="EW")
		fl_frame.grid_columnconfigure(0, weight = 1)

		self.flasher_gui = FileProgressGui(fl_frame)
		self.flasher = Flasher(None, self.flasher_gui)
		self.flasher_gui.progressbar.grid(column=0, row=0, columnspan=4, sticky="EW")
		self.flasher_gui.entry.grid(column=0, row=1, columnspan=4, sticky="EW")

		self.button_b = tk.Button(fl_frame, text="Bootstrap from Stage 1.5 (60 sec.)", command=self.bootstrap)
		self.button_b.grid(column=0, row=2, columnspan=4, sticky='EW')

		self.button_vfp = tk.Button(fl_frame, text="Verify Flasher Program", command=self.inject_verify)
		self.button_vfp.grid(column=0, row=3, columnspan=4, sticky='EW')

		self.combo_blocks = ttk.Combobox(fl_frame, state="readonly", values = [b[0] for b in Flasher.blocks])
		self.combo_blocks.current(1)
		self.combo_blocks.grid(column=0, row=4, sticky="EW")

		self.button_e = tk.Button(fl_frame, text="Erase", command=self.erase)
		self.button_e.grid(column=1, row=4)

		self.button_pg = tk.Button(fl_frame, text="Program", command=self.program)
		self.button_pg.grid(column=2, row=4)

		self.button_v2 = tk.Button(fl_frame, text="Verify", command=self.verify2)
		self.button_v2.grid(column=3, row=4)

		self.button_reset = tk.Button(fl_frame, text="Reset ECU", command=self.reset)
		self.button_reset.grid(column=0, row=5, columnspan=4, sticky='EW')

		self.flasher_buttons(tk.DISABLED)

	def t4e_buttons(self, state):
		self.button_dl['state'] = state
		self.button_v['state'] = state
		self.button_ifp['state'] = state
		self.button_b['state'] = state

	def flasher_buttons(self, state):
		self.button_e['state'] = state
		self.button_pg['state'] = state
		self.button_v2['state'] = state
		self.button_vfp['state'] = state
		self.button_reset['state'] = state

	def openCAN(self):
		self.combo_interface['state'] = tk.DISABLED
		self.entry_channel['state'] = tk.DISABLED
		self.combo_speed['state'] = tk.DISABLED
		self.bus = can.Bus(
			interface = self.combo_interface.get(),
			channel = self.string_channel.get(),
			can_filters = [{"extended": False, "can_id": 0x7A0, "can_mask": 0x7FF }],
			bitrate = [1000000, 500000][self.combo_speed.current()]
		)
		self.t4e.bus = self.bus
		self.flasher.bus = self.bus
		self.canstrap_file = ["flasher/canstrap-white.bin", "flasher/canstrap-black.bin"][self.combo_speed.current()]

	def closeCAN(self):
		self.combo_interface['state'] = tk.NORMAL
		self.entry_channel['state'] = tk.NORMAL
		self.combo_speed['state'] = tk.NORMAL
		self.bus.shutdown()

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
				self.openCAN()
				self.t4e.download(zone[1], zone[2], answer)
			except Exception as e:
				messagebox.showerror(master=self.master, title="Error!", message=str(e))
			self.closeCAN()
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
				self.openCAN()
				self.t4e.verify(zone[1], answer)
			except Exception as e:
				messagebox.showerror(master=self.master, title="Error!", message=str(e))
			self.closeCAN()
			self.t4e_buttons(tk.NORMAL)

	def inject(self):
		self.t4e_buttons(tk.DISABLED)
		try:
			self.openCAN()
			self.t4e.inject(0x3FF000, self.canstrap_file, 0x3FFFDC)
			self.flasher.canstrap(timeout=1.0)
			# Install the flasher plugin
			self.flasher.upload(0x3FF200, "flasher/plugin_flash.bin")
			self.flasher.plugin(0x3FF200)
			self.flasher_buttons(tk.NORMAL)
		except Exception as e:
			messagebox.showerror(master=self.master, title="Error!", message=str(e))
			self.t4e_buttons(tk.NORMAL)
		self.closeCAN()

	def bootstrap(self):
		self.t4e_buttons(tk.DISABLED)
		self.flasher_buttons(tk.DISABLED)
		try:
			self.openCAN()
			self.flasher.canstrap()
			# Move the flasher to the RAM to be able to reflash the bootloader
			self.flasher.upload(0x3FF000,self.canstrap_file)
			self.flasher.branch(0x3FF000)
			self.flasher.canstrap(1.0)
			self.flasher.upload(0x3FF200,"flasher/plugin_flash.bin")
			self.flasher.plugin(0x3FF200)
			self.flasher.verify(0x3FF000,self.canstrap_file)
			self.flasher.verify(0x3FF200,"flasher/plugin_flash.bin")
			self.flasher_buttons(tk.NORMAL)
		except Exception as e:
			messagebox.showerror(master=self.master, title="Error!", message=str(e))
			self.t4e_buttons(tk.NORMAL)
		self.closeCAN()

	def inject_verify(self):
		self.flasher_buttons(tk.DISABLED)
		try:
			self.openCAN()
			self.flasher.verify(0x3FF000,self.canstrap_file)
			self.flasher.verify(0x3FF200,"flasher/plugin_flash.bin")
		except Exception as e:
			messagebox.showerror(master=self.master, title="Error!", message=str(e))
		self.closeCAN()
		self.flasher_buttons(tk.NORMAL)

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
			self.openCAN()
			self.flasher_gui.log("Erase " + block[0])
			self.flasher.eraseBlock(block[1])
		except Exception as e:
			messagebox.showerror(master=self.master, title="Error!", message=str(e))
		self.closeCAN()
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
				self.openCAN()
				self.flasher.program(block[1], block[2], answer)
			except Exception as e:
				messagebox.showerror(master=self.master, title="Error!", message=str(e))
			self.closeCAN()
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
				self.openCAN()
				self.flasher.verify(block[2], answer)
			except Exception as e:
				messagebox.showerror(master=self.master, title="Error!", message=str(e))
			self.closeCAN()
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
			self.openCAN()
			self.flasher.branch(0x100)
			self.t4e_buttons(tk.NORMAL)
		except Exception as e:
			messagebox.showerror(master=self.master, title="Error!", message=str(e))
			self.flasher_buttons(tk.NORMAL)
		self.closeCAN()

from lib.gui_crp08 import crp08_file
from lib.crp08 import CRP08
test = __import__("t4e-black")

class CRP08_uploader_win():
	def __init__(self, master):
		self.master = master
		master.title('Up')
		master.resizable(0, 0)

		can_frame = tk.LabelFrame(master, text="CAN Device")
		can_frame.pack(fill=tk.X, padx=4, pady=4)

		self.combo_interface = ttk.Combobox(can_frame, state="readonly", values = ["socketcan", "ixxat", "serial", "slcan"])
		self.combo_interface.current(0)
		self.combo_interface.pack(side=tk.LEFT, fill=tk.X)

		self.string_channel = tk.StringVar()
		self.string_channel.set("can0")
		self.entry_channel = tk.Entry(can_frame, textvariable = self.string_channel)
		self.entry_channel.pack(side=tk.LEFT, fill=tk.X, expand=True)

		crp_frame = tk.LabelFrame(master, text="CRP08 File")
		crp_frame.pack(fill=tk.X, padx=4, pady=4)

		self.txt = tk.Text(crp_frame, height=16, width=50, state=tk.DISABLED)
		self.txt.pack()

		self.bt_crp = tk.Button(master, text="Load file", height=3, width=20, command=self.load_crp)
		self.bt_crp.pack()

		self.p = FileProgressGui(master)
		self.p.progressbar.pack(fill=tk.X, pady=10)
		self.p.entry.pack(fill=tk.X)

		# Backend
		self.crp = CRP08(True)

	def openCAN(self):
		self.combo_interface['state'] = tk.DISABLED
		self.entry_channel['state'] = tk.DISABLED
		self.bus = can.Bus(
			interface = self.combo_interface.get(),
			channel = self.string_channel.get(),
			can_filters = [{"extended": False, "can_id": 0x7A0, "can_mask": 0x7FF }],
			bitrate = 500000
		)

	def closeCAN(self):
		self.combo_interface['state'] = tk.NORMAL
		self.entry_channel['state'] = tk.NORMAL
		self.bus.shutdown()

	def updateText(self, evt=None):
		self.txt.config(state=tk.NORMAL)
		self.txt.delete('1.0', tk.END)
		self.txt.insert(tk.END, str(self.crp))
		self.txt.config(state=tk.DISABLED)

	def load_crp(self):
		answer = filedialog.askopenfilename(
			parent = self.master,
			initialdir = os.getcwd(),
			title = "Please select a file:",
			filetypes = crp08_file
		)
		if(answer):
			self.crp.read_file(answer)
			self.updateText()
			self.openCAN()
			test.ECU_T4E_BLACK(self.bus, self.p).bootstrap(self.crp)

class main_window():
	def __init__(self, master):
		self.master = master
		master.title('Lotus Tools')
		master.resizable(0, 0)
		tk.Button(master, text="CRP05 Editor", height=3, width=20, command=self.open_crp05_editor).pack()
		tk.Button(master, text="CRP08 Editor", height=3, width=20, command=self.open_crp08_editor).pack()
		tk.Button(master, text="CRP05 Uploader\n(K-Line)", height=3, width=20, command=self.open_todo).pack()
		tk.Button(master, text="CRP08 Uploader\n(CAN-Bus)", height=3, width=20, command=self.open_crp08_uploader).pack()
		tk.Button(master, text="Live-Tuning Access\n(Unlocked ECU)", height=3, width=20, command=self.open_todo).pack()
		tk.Button(master, text="Calibration CRC", height=3, width=20, command=self.open_todo).pack()
		tk.Button(master, text="Custom Flasher\n(Stage15)", height=3, width=20, command=self.open_todo).pack()
		tk.Button(master, text="ABS EBC430", height=3, width=20, command=self.open_todo).pack()
	def open_crp05_editor(self):
		CRP05_window(tk.Toplevel(self.master))
	def open_crp08_editor(self):
		CRP08_window(tk.Toplevel(self.master))
	def open_crp08_uploader(self):
		CRP08_uploader_win(tk.Toplevel(self.master))
	def open_todo(self):
		messagebox.showerror(master=self.master, title="Error!", message="Work in progress...")

root = tk.Tk()
main_window(root)
t4e_window(tk.Toplevel(root))
root.mainloop()

