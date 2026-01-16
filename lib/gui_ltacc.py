import os, importlib, pkgutil
import tkinter as tk
from tkinter import ttk, filedialog, simpledialog
from lib.ltacc import LiveTuningAccess
from lib.flasher import Flasher
from lib.gui_common import *
from lib.gui_fileprogress import FileProgress_widget
from lib.gui_tuner import MapTable, SimpleGauge, TunerWin

# Some constants
BO_BE = 'big'
CHARSET = 'ISO-8859-15'

class LiveTuningAccess_win(tk.Toplevel):
	def __init__(self, prefs, parent=None):
		tk.Toplevel.__init__(self, parent)
		self.title('Live-Tuning Access')
		self.resizable(0, 0)
		self.grab_set()
		self.protocol("WM_DELETE_WINDOW", self.on_closing)
		self.run_task = False
		self.prefs = prefs

		self.can_device = SelectCAN_widget(prefs, self)
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

		self.button_pmt = tk.Button(lta_frame, text="The poor man's live-tuning", command=self.watch)
		self.button_pmt.pack(fill=tk.X)

		self.button_tune = tk.Button(lta_frame, text=">>> Tuner <<<", command=self.tuner)
		self.button_tune.pack(fill=tk.X)

	def lock_buttons_decorator(func):
		def wrapper(self):
			self.button_dl['state'] = tk.DISABLED
			self.button_v['state'] = tk.DISABLED
			self.button_ifp['state'] = tk.DISABLED
			self.button_pmt['state'] = tk.DISABLED
			self.button_tune['state'] = tk.DISABLED
			func(self)
			self.button_dl['state'] = tk.NORMAL
			self.button_v['state'] = tk.NORMAL
			self.button_ifp['state'] = tk.NORMAL
			self.button_pmt['state'] = tk.NORMAL
			self.button_tune['state'] = tk.NORMAL
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
			initialdir = self.prefs['PATH']['bin'],
			initialfile = zone[3],
			title = "Please select a file:",
			filetypes = bin_file
		)
		if(answer):
			self.prefs['PATH']['bin'] = os.path.dirname(answer)
			lta.download(zone[1], zone[2], answer)

	@lock_buttons_decorator
	@try_msgbox_decorator
	@lta_decorator
	def verify(self, lta):
		zone = LiveTuningAccess.zones[self.combo_zones.current()]
		answer = filedialog.askopenfilename(
			parent = self,
			initialdir = self.prefs['PATH']['bin'],
			initialfile = zone[3],
			title = "Please select a file:",
			filetypes = bin_file
		)
		if(answer):
			self.prefs['PATH']['bin'] = os.path.dirname(answer)
			lta.verify(zone[1], answer)

	@lock_buttons_decorator
	@try_msgbox_decorator
	@lta_decorator
	def inject(self, lta):
		if(self.can_device.get_bitrate() == 1000000):
			canstrap_file = "flasher/t4e/canstrap-white.bin"
		else:
			canstrap_file = "flasher/t4e/canstrap-black.bin"
		lta.upload(0x3FF000, canstrap_file)
		lta.upload(0x3FFF00, "lib/poison.bin")
		fl = Flasher(self.fp)
		fl.bus = lta.bus
		fl.canstrap(timeout=1)
		# Install the flasher plugin
		fl.upload(0x3FF200, "flasher/t4e/plugin_flash.bin")
		fl.plugin(0x3FF200)
		fl.verify(0x3FF000, canstrap_file)
		fl.verify(0x3FF200, "flasher/t4e/plugin_flash.bin")
		tk.messagebox.showinfo(
			parent = self,
			title = "Be careful!",
			message = "Success! You can use the \"Custom Flasher\" now!"
		)

	def on_closing(self):
		if(not self.run_task): self.destroy()
		else: self.run_task = False

	def waitmore(self):
		self.update()
		if(not self.run_task): raise Exception("Terminated by user")

	@lock_buttons_decorator
	@try_msgbox_decorator
	@lta_decorator
	def watch(self, lta):
		title = "The poor man's live tuning"
		tk.messagebox.showinfo(
			parent = self,
			title = title,
			message = """This will constantly watch a calibration file on your computer and if changes are detected, it will upload them into your ECU within the next second.

Once everyhing is set up, open the file with RomRaider, make the needed modifications and save the file. As soon as the file is saved, the modifications will be upload to the ECU into the RAM.

Because the changes are in the RAM, everything will be lost after the ECU has shut down. This is for testing with running engine.
"""
		)
		ptrmap = lta.read_ptrmap()
		cal_base = ptrmap[253][0]
		cal_size = int.from_bytes(lta.read_memory(*ptrmap[254]), BO_BE)
		cal_name = str(lta.read_memory(cal_base, 32), CHARSET)
		self.fp.log(f"RAM Calibration 0x{cal_size:04X} bytes @ 0x{cal_base:08X}")
		answer = tk.messagebox.askquestion(
			parent = self,
			title = title,
			message = "Calibration description correct?\n\n"+cal_name
		)
		if(answer != 'yes'): return
		answer = tk.messagebox.askquestion(
			parent = self,
			title = title,
			message = "Should your local file be uploaded first?"
		)
		copy = (answer == 'yes')
		answer = tk.messagebox.askquestion(
			parent = self,
			title = title,
			message = "Should writing be verified?"
		)
		verify = (answer == 'yes')
		answer = filedialog.askopenfilename(
			parent = self,
			initialdir = self.prefs['PATH']['bin'],
			initialfile = LiveTuningAccess.zones[1][3],
			title = "Please select a file:",
			filetypes = bin_file
		)
		if(answer):
			self.prefs['PATH']['bin'] = os.path.dirname(answer)
			self.run_task = True
			lta.watch(cal_base, answer, cal_size, copy, verify, self.waitmore)

	@lock_buttons_decorator
	@try_msgbox_decorator
	@lta_decorator
	def tuner(self, lta):
		import lib.tuner_defs
		modules = sorted((name for _, name, _ in pkgutil.iter_modules(lib.tuner_defs.__path__)))
		for name in modules:
			module = importlib.import_module("lib.tuner_defs."+name)
			try:
				ecudef = module.TunerDefinition(lta)
				self.fp.log(f"Try: {ecudef.name}")
				res = ecudef.check()
			except Exception as e:
				self.fp.log(f" --> {str(e)}")
				res = False
			if(res):
				TunerWin(self.prefs, ecudef, self)
				return
		tk.messagebox.showinfo(
			parent = self,
			title = "Tuner",
			message = "No definition was found for your car. Contact me if you want one."
		)
