import os
import tkinter as tk
from tkinter import filedialog
from lib.ltacc import LiveTuningAccess
from lib.flasher import Flasher
from lib.gui_common import *
from lib.gui_fileprogress import FileProgress_widget

class LiveTuningAccess_win(tk.Toplevel):
	def __init__(self, config, parent=None):
		tk.Toplevel.__init__(self, parent)
		self.title('Live-Tuning Access')
		self.resizable(0, 0)

		self.can_device = SelectCAN_widget(config, self)
		self.can_device.pack(fill=tk.X)

		lta_frame = tk.LabelFrame(self, text="Dump")
		lta_frame.pack(fill=tk.X)

		self.fp = FileProgress_widget(lta_frame)
		self.fp.pack(fill=tk.X)

		btn_frame = tk.Frame(lta_frame)
		btn_frame.pack(fill=tk.X)

		self.combo_zones = ttk.Combobox(btn_frame, state="readonly", values = [z[0] for z in LiveTuningAccess.zones])
		self.combo_zones.current(1)
		self.combo_zones.pack(side=tk.LEFT, fill=tk.X, expand=True)

		self.button_dl = tk.Button(btn_frame, text="Download", command=self.download)
		self.button_dl.pack(side=tk.LEFT)

		self.button_v = tk.Button(btn_frame, text="Verify", command=self.verify)
		self.button_v.pack(side=tk.LEFT)

		self.button_ifp = tk.Button(lta_frame, text="Inject T4e Custom Flasher Program", command=self.inject)
		self.button_ifp.pack(fill=tk.X)

	def lock_buttons_decorator(func):
		def wrapper(self):
			self.button_dl['state'] = tk.DISABLED
			self.button_v['state'] = tk.DISABLED
			self.button_ifp['state'] = tk.DISABLED
			func(self)
			self.button_dl['state'] = tk.NORMAL
			self.button_v['state'] = tk.NORMAL
			self.button_ifp['state'] = tk.NORMAL
		return wrapper

	def lta_decorator(func):
		def wrapper(self):
			lta = LiveTuningAccess(self.fp)
			lta.open_can(
				self.can_device.get_interface(),
				self.can_device.get_channel(), 
				self.can_device.get_bitrate(),
			)
			try:
				func(self, lta)
			finally:
				lta.close_can()
		return wrapper

	@lock_buttons_decorator
	@try_msgbox_decorator
	@lta_decorator
	def download(self, lta):
		zone = LiveTuningAccess.zones[self.combo_zones.current()]
		answer = filedialog.asksaveasfilename(
			parent = self,
			initialdir = os.getcwd(),
			initialfile = zone[3],
			title = "Please select a file:",
			filetypes = bin_file
		)
		if(answer): lta.download(zone[1], zone[2], answer)

	@lock_buttons_decorator
	@try_msgbox_decorator
	@lta_decorator
	def verify(self, lta):
		zone = LiveTuningAccess.zones[self.combo_zones.current()]
		answer = filedialog.askopenfilename(
			parent = self,
			initialdir = os.getcwd(),
			initialfile = zone[3],
			title = "Please select a file:",
			filetypes = bin_file
		)
		if(answer): lta.verify(zone[1], answer)

	@lock_buttons_decorator
	@try_msgbox_decorator
	@lta_decorator
	def inject(self, lta):		
		if(self.can_device.get_bitrate() == 1000000):
			canstrap_file = "flasher/canstrap-white.bin"
		else:
			canstrap_file = "flasher/canstrap-black.bin"
		lta.upload(0x3FF000, canstrap_file)
		lta.upload(0x3FFF00, "lib/poison.bin")
		fl = Flasher(self.fp)
		fl.bus = lta.bus
		fl.canstrap(timeout=1.0)
		# Install the flasher plugin
		fl.upload(0x3FF200, "flasher/plugin_flash.bin")
		fl.plugin(0x3FF200)
		fl.verify(0x3FF000, canstrap_file)
		fl.verify(0x3FF200, "flasher/plugin_flash.bin")
		tk.messagebox.showinfo(
			parent = self,
			title = "Be careful!",
			message = "Success! You can use the \"Custom Flasher\" now!"
		)

