import os
import tkinter as tk
from tkinter import filedialog
from lib.flasher import Flasher
from lib.gui_common import *
from lib.gui_fileprogress import FileProgress_widget

class Flasher_win(tk.Toplevel):
	def __init__(self, prefs, parent=None):
		tk.Toplevel.__init__(self, parent)
		self.title('Flasher')
		self.resizable(0, 0)
		self.grab_set()
		self.protocol("WM_DELETE_WINDOW", self.on_closing)
		self.run_task = False
		self.prefs = prefs

		self.can_device = SelectCAN_widget(prefs, self)
		self.can_device.pack(fill=tk.X)

		fl_frame = tk.LabelFrame(self, text="CAN Flasher (Not Safe)")
		fl_frame.pack(fill=tk.X)

		self.fp = FileProgress_widget(fl_frame)
		self.fp.pack(fill=tk.X)

		self.button_b = tk.Button(fl_frame, text="Bootstrap from Stage 1.5 (60 sec.)", command=self.bootstrap)
		self.button_b.pack(fill=tk.X)

		btn_frame = tk.Frame(fl_frame)
		btn_frame.pack(fill=tk.X)

		self.combo_blocks = ttk.Combobox(btn_frame, state="readonly", values = [b[0] for b in Flasher.blocks])
		self.combo_blocks.current(1)
		self.combo_blocks.pack(side=tk.LEFT, fill=tk.X, expand=True)

		self.button_dl = tk.Button(btn_frame, text="Download", command=self.download)
		self.button_dl.pack(side=tk.LEFT)

		self.button_e = tk.Button(btn_frame, text="Erase", command=self.erase)
		self.button_e.pack(side=tk.LEFT)

		self.button_pg = tk.Button(btn_frame, text="Program", command=self.program)
		self.button_pg.pack(side=tk.LEFT)

		self.button_v = tk.Button(btn_frame, text="Verify", command=self.verify)
		self.button_v.pack(side=tk.LEFT)

		self.button_reset = tk.Button(fl_frame, text="Reset ECU", command=self.reset)
		self.button_reset.pack(fill=tk.X)

	def lock_buttons_decorator(func):
		def wrapper(self):
			self.button_dl['state'] = tk.DISABLED
			self.button_b['state'] = tk.DISABLED
			self.button_e['state'] = tk.DISABLED
			self.button_pg['state'] = tk.DISABLED
			self.button_v['state'] = tk.DISABLED
			self.button_reset['state'] = tk.DISABLED
			func(self)
			self.button_dl['state'] = tk.NORMAL
			self.button_b['state'] = tk.NORMAL
			self.button_e['state'] = tk.NORMAL
			self.button_pg['state'] = tk.NORMAL
			self.button_v['state'] = tk.NORMAL
			self.button_reset['state'] = tk.NORMAL
		return wrapper

	def fl_decorator(func):
		def wrapper(self):
			fl = Flasher(self.fp)
			fl.open_can(
				self.can_device.get_interface(),
				self.can_device.get_channel(),
				self.can_device.get_bitrate(),
			)
			try:
				func(self, fl)
			finally:
				fl.close_can()
		return wrapper

	def on_closing(self):
		if(not self.run_task): self.destroy()
		else: self.run_task = False

	def waitmore(self):
		self.update()
		if(not self.run_task): raise Exception("Terminated by user")

	@lock_buttons_decorator
	@try_msgbox_decorator
	@fl_decorator
	def bootstrap(self, fl):
		if(self.can_device.get_bitrate() == 1000000):
			canstrap_file = "flasher/t4e/canstrap-white.bin"
		else:
			canstrap_file = "flasher/t4e/canstrap-black.bin"
		self.run_task = True
		fl.canstrap(ui_cb=self.waitmore)
		self.run_task = False
		# Move the flasher to the RAM to be able to reflash the bootloader
		fl.upload(0x3FF000, canstrap_file)
		fl.branch(0x3FF000)
		fl.canstrap(1)
		fl.upload(0x3FF200, "flasher/t4e/plugin_flash.bin")
		fl.plugin(0x3FF200)
		fl.verify(0x3FF000, canstrap_file)
		fl.verify(0x3FF200, "flasher/t4e/plugin_flash.bin")

	@lock_buttons_decorator
	@try_msgbox_decorator
	@fl_decorator
	def download(self, fl):
		block = Flasher.blocks[self.combo_blocks.current()]
		answer = filedialog.asksaveasfilename(
			parent = self,
			initialdir = self.prefs['PATH']['bin'],
			initialfile = block[4],
			title = "Please select a file:",
			filetypes = bin_file
		)
		if(answer):
			self.prefs['PATH']['bin'] = os.path.dirname(answer)
			fl.download(block[2], block[3], answer)

	@lock_buttons_decorator
	@try_msgbox_decorator
	@fl_decorator
	def erase(self, fl):
		block = Flasher.blocks[self.combo_blocks.current()]
		answer = tk.messagebox.askquestion(
			parent = self,
			title = "Be careful!",
			message = "Do you really want to erase?\n\n"+block[0]
		)
		if(answer != 'yes'): return
		self.fp.log("Erase " + block[0])
		fl.erase_block(block[1])

	@lock_buttons_decorator
	@try_msgbox_decorator
	@fl_decorator
	def program(self, fl):
		block = Flasher.blocks[self.combo_blocks.current()]
		answer = tk.messagebox.askquestion(
			parent = self,
			title = "Be careful!",
			message = "Do you really want to program?\n\n"+block[0]
		)
		if(answer != 'yes'): return
		answer = filedialog.askopenfilename(
			parent = self,
			initialdir = self.prefs['PATH']['bin'],
			initialfile = block[4],
			title = "Please select a file:",
			filetypes = bin_file
		)
		if(answer):
			self.prefs['PATH']['bin'] = os.path.dirname(answer)
			fl.program(block[1], block[2], answer)

	@lock_buttons_decorator
	@try_msgbox_decorator
	@fl_decorator
	def verify(self, fl):
		block = Flasher.blocks[self.combo_blocks.current()]
		answer = filedialog.askopenfilename(
			parent = self,
			initialdir = self.prefs['PATH']['bin'],
			initialfile = block[4],
			title = "Please select a file:",
			filetypes = bin_file
		)
		if(answer):
			self.prefs['PATH']['bin'] = os.path.dirname(answer)
			#fl.verify(block[2], answer)
			crc = fl.prepare_crc()
			crc.do_file(answer)
			crc_file = crc.get() ^ 0xFFFFFFFF
			crc_ecu = fl.compute_crc(block[2], min(block[3], os.path.getsize(answer)))
			fl.plugin(0x3FF200)
			self.fp.log('ECU CRC: 0x%08X' % (crc_ecu))
			self.fp.log('File CRC: 0x%08X' % (crc_file))
			if(crc_ecu != crc_file):
				raise Exception("CRC mismatch!")

	@lock_buttons_decorator
	@try_msgbox_decorator
	@fl_decorator
	def reset(self, fl):
		answer = tk.messagebox.askquestion(
			parent = self,
			title = "Be careful!",
			message = "Do you really want to reset?"
		)
		if(answer != 'yes'): return
		fl.branch(0x100)
