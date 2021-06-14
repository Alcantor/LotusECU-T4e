#!/usr/bin/python3

import os, can
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox
from t4e import ECU_T4E
from flasher import Flasher
from lib.gui_crp05 import CRP05_editor_win#, CRP05_uploader_win
from lib.gui_crp08 import CRP08_editor_win, CRP08_uploader_win
from lib.gui_fileprogress import FileProgress_widget
from lib.gui_common import *

class LiveAccess_win(tk.Toplevel):
	def __init__(self, parent=None):
		tk.Toplevel.__init__(self, parent)
		self.title('Live-Tuning Access')
		self.resizable(0, 0)

		self.can_device = SelectCAN_widget(self)
		self.can_device.pack(fill=tk.X)

		t4e_frame = tk.LabelFrame(self, text="Dump")
		t4e_frame.pack(fill=tk.X)

		self.t4e_gui = FileProgress_widget(t4e_frame)
		self.t4e = ECU_T4E(None, self.t4e_gui)
		self.t4e_gui.pack(fill=tk.X)

		btn_frame = tk.Frame(t4e_frame)
		btn_frame.pack(fill=tk.X)

		self.combo_zones = ttk.Combobox(btn_frame, state="readonly", values = [z[0] for z in ECU_T4E.zones])
		self.combo_zones.current(1)
		self.combo_zones.pack(side=tk.LEFT, fill=tk.X, expand=True)

		self.button_dl = tk.Button(btn_frame, text="Download", command=self.download)
		self.button_dl.pack(side=tk.LEFT)

		self.button_v = tk.Button(btn_frame, text="Verify", command=self.verify)
		self.button_v.pack(side=tk.LEFT)

		self.button_ifp = tk.Button(t4e_frame, text="Inject Flasher Program", command=self.inject)
		self.button_ifp.pack(fill=tk.X)

	def t4e_buttons(self, state):
		self.button_dl['state'] = state
		self.button_v['state'] = state
		self.button_ifp['state'] = state
		self.button_b['state'] = state

	@try_msgbox_decorator
	def download(self):
		zone = ECU_T4E.zones[self.combo_zones.current()]
		answer = filedialog.asksaveasfilename(
			parent = self,
			initialdir = os.getcwd(),
			initialfile = zone[3],
			title = "Please select a file:",
			filetypes = bin_file
		)
		if(answer):
			self.t4e_buttons(tk.DISABLED)
			self.openCAN()
			self.t4e.download(zone[1], zone[2], answer)
			self.closeCAN()
			self.t4e_buttons(tk.NORMAL)

	@try_msgbox_decorator
	def verify(self):
		zone = ECU_T4E.zones[self.combo_zones.current()]
		answer = filedialog.askopenfilename(
			parent = self,
			initialdir = os.getcwd(),
			initialfile = zone[3],
			title = "Please select a file:",
			filetypes = bin_file
		)
		if(answer):
			self.t4e_buttons(tk.DISABLED)
			self.openCAN()
			self.t4e.verify(zone[1], answer)
			self.closeCAN()
			self.t4e_buttons(tk.NORMAL)

	@try_msgbox_decorator
	def inject(self):
		self.t4e_buttons(tk.DISABLED)
		self.openCAN()
		self.t4e.inject(0x3FF000, self.canstrap_file, 0x3FFFDC)
		self.flasher.canstrap(timeout=1.0)
		# Install the flasher plugin
		self.flasher.upload(0x3FF200, "flasher/plugin_flash.bin")
		self.flasher.plugin(0x3FF200)
		self.flasher_buttons(tk.NORMAL)
		self.closeCAN()

class Flasher_win(tk.Toplevel):
	def __init__(self, parent=None):
		tk.Toplevel.__init__(self, parent)
		self.title('Flasher')
		self.resizable(0, 0)

		self.can_device = SelectCAN_widget(self)
		self.can_device.pack(fill=tk.X)

		fl_frame = tk.LabelFrame(self, text="CAN Flasher (Not Safe)")
		fl_frame.pack(fill=tk.X)

		self.flasher_gui = FileProgress_widget(fl_frame)
		self.flasher = Flasher(None, self.flasher_gui)
		self.flasher_gui.pack(fill=tk.X)

		self.button_b = tk.Button(fl_frame, text="Bootstrap from Stage 1.5 (60 sec.)", command=self.bootstrap)
		self.button_b.pack(fill=tk.X)

		self.button_vfp = tk.Button(fl_frame, text="Verify Flasher Program", command=self.inject_verify)
		self.button_vfp.pack(fill=tk.X)

		btn_frame = tk.Frame(fl_frame)
		btn_frame.pack(fill=tk.X)

		self.combo_blocks = ttk.Combobox(btn_frame, state="readonly", values = [b[0] for b in Flasher.blocks])
		self.combo_blocks.current(1)
		self.combo_blocks.pack(side=tk.LEFT, fill=tk.X, expand=True)

		self.button_e = tk.Button(btn_frame, text="Erase", command=self.erase)
		self.button_e.pack(side=tk.LEFT)

		self.button_pg = tk.Button(btn_frame, text="Program", command=self.program)
		self.button_pg.pack(side=tk.LEFT)

		self.button_v = tk.Button(btn_frame, text="Verify", command=self.verify)
		self.button_v.pack(side=tk.LEFT)

		self.button_reset = tk.Button(fl_frame, text="Reset ECU", command=self.reset)
		self.button_reset.pack(fill=tk.X)

		self.flasher_buttons(tk.DISABLED)

	def flasher_buttons(self, state):
		self.button_e['state'] = state
		self.button_pg['state'] = state
		self.button_v['state'] = state
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

	@try_msgbox_decorator
	def bootstrap(self):
		self.t4e_buttons(tk.DISABLED)
		self.flasher_buttons(tk.DISABLED)
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
		self.closeCAN()

	@try_msgbox_decorator
	def inject_verify(self):
		self.flasher_buttons(tk.DISABLED)
		self.openCAN()
		self.flasher.verify(0x3FF000,self.canstrap_file)
		self.flasher.verify(0x3FF200,"flasher/plugin_flash.bin")
		self.closeCAN()
		self.flasher_buttons(tk.NORMAL)

	@try_msgbox_decorator
	def erase(self):
		block = Flasher.blocks[self.combo_blocks.current()]
		answer = tk.messagebox.askquestion(
			parent = self,
			title = 'Be careful!',
			message = 'Do you really want to erase?\n\n'+block[0]
		)
		if(answer != 'yes'): return
		self.flasher_buttons(tk.DISABLED)
		self.openCAN()
		self.flasher_gui.log("Erase " + block[0])
		self.flasher.eraseBlock(block[1])
		self.closeCAN()
		self.flasher_buttons(tk.NORMAL)

	@try_msgbox_decorator
	def program(self):
		block = Flasher.blocks[self.combo_blocks.current()]
		answer = tk.messagebox.askquestion(
			parent = self,
			title = 'Be careful!',
			message = 'Do you really want to program?\n\n'+block[0]
		)
		if(answer != 'yes'): return
		answer = filedialog.askopenfilename(
			parent = self,
			initialdir = os.getcwd(),
			initialfile = block[4],
			title = "Please select a file:",
			filetypes = bin_file
		)
		if(answer):
			self.flasher_buttons(tk.DISABLED)
			self.openCAN()
			self.flasher.program(block[1], block[2], answer)
			self.closeCAN()
			self.flasher_buttons(tk.NORMAL)

	@try_msgbox_decorator
	def verify(self):
		block = Flasher.blocks[self.combo_blocks.current()]
		answer = filedialog.askopenfilename(
			parent = self,
			initialdir = os.getcwd(),
			initialfile = block[4],
			title = "Please select a file:",
			filetypes = bin_file
		)
		if(answer):
			self.flasher_buttons(tk.DISABLED)
			self.openCAN()
			self.flasher.verify(block[2], answer)
			self.closeCAN()
			self.flasher_buttons(tk.NORMAL)

	@try_msgbox_decorator
	def reset(self):
		answer = tk.messagebox.askquestion(
			parent = self,
			title = 'Be careful!',
			message = 'Do you really want to reset?'
		)
		if(answer != 'yes'): return
		self.flasher_buttons(tk.DISABLED)
		self.openCAN()
		self.flasher.branch(0x100)
		self.t4e_buttons(tk.NORMAL)
		self.closeCAN()

class main_window():
	def __init__(self, master):
		self.master = master
		master.title('Lotus Tools')
		master.resizable(0, 0)
		tk.Button(master, text="CRP05 Editor", height=3, width=20, command=self.open_crp05_editor).pack()
		tk.Button(master, text="CRP08 Editor", height=3, width=20, command=self.open_crp08_editor).pack()
		tk.Button(master, text="CRP05 Uploader\n(K-Line)", height=3, width=20, command=self.open_todo).pack()
		tk.Button(master, text="CRP08 Uploader\n(CAN-Bus)", height=3, width=20, command=self.open_crp08_uploader).pack()
		tk.Button(master, text="Live-Tuning Access\n(Unlocked ECU)", height=3, width=20, command=self.open_live_access).pack()
		tk.Button(master, text="Calibration CRC", height=3, width=20, command=self.open_todo).pack()
		tk.Button(master, text="Custom Flasher\n(Stage15)", height=3, width=20, command=self.open_flasher).pack()
		tk.Button(master, text="ABS EBC430", height=3, width=20, command=self.open_todo).pack()
	def open_crp05_editor(self):
		CRP05_editor_win(self.master)
	def open_crp08_editor(self):
		CRP08_editor_win(self.master)
	def open_crp08_uploader(self):
		CRP08_uploader_win(self.master)
	def open_live_access(self):
		LiveAccess_win(self.master)
	def open_flasher(self):
		Flasher_win(self.master)
	def open_todo(self):
		messagebox.showerror(master=self.master, title="Error!", message="Work in progress...")

root = tk.Tk()
main_window(root)
root.mainloop()

