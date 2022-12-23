import os
import tkinter as tk
from tkinter import filedialog, simpledialog
from lib.ltacc import LiveTuningAccess
from lib.flasher import Flasher
from lib.gui_common import *
from lib.gui_fileprogress import FileProgress_widget

class askCAL(simpledialog.Dialog):
	def body(self, master):
		tk.Label(master, text="""WARNING: Choose the correct version!

Verify it with an hexadecimal editor! You should find a copy
of "calrom.bin" at the given offset into "calram.bin".

Choosing the wrong RAM offset can cause bad side effects with a running engine!
""").pack()
		self.cb = ttk.Combobox(master, state="readonly", values = [
			"RAM+0x174C - White CroftT4E070 01/11/2005 Lotus EngV0078",
			"RAM+0x18D0 - Black CroftT4E090 14/07/2006 Lotus EngV0091",
			"RAM+0x1330 - White CroftT4E090 14/07/2006 Lotus EngV0091",
			"RAM+0x1330 - White CroftT4E090 14/07/2006 Lotus EngV0093",
			"RAM+0x1324 - White CroftT4E090 27/02/2007 Lotus EngV0097",
			"RAM+0x4000 - White Croft221  2nd Dec  10 Lotus Eng      ",
			"RAM+0x0000 - Caterham CD0MB000    Oct  3 2011 15:26:36000VC",
			"RAM+0x2920 - Lotus T6 T6AIN V000Q 02/01/2014 LotusEng      "
		])
		self.cb.current(0)
		self.cb.pack(fill=tk.X, expand=True)
		self.docopy = tk.IntVar(value=1)
		tk.Checkbutton(master, text="Initial upload", variable=self.docopy).pack()
		self.doverify = tk.IntVar(value=1)
		tk.Checkbutton(master, text="Verify uploads", variable=self.doverify).pack()
		self.base = None
		self.size = None
		self.copy = None
		return master

	def validate(self):
		self.base = [
			0x003F974C,
			0x003F98D0,
			0x003F9330,
			0x003F9330,
			0x003F9324,
			0x00084000,
			0x40000000,
			0x40002920
		][self.cb.current()]
		self.size = [
			0x3CA0,
			0x3CB4,
			0x3CA0,
			0x3C8E,
			0x3C94,
			0x6000,
			0x69A8,
			0x69A8
		][self.cb.current()]
		self.copy = (self.docopy.get() == 1)
		self.verify = (self.doverify.get() == 1)
		return 1

class LiveTuningAccess_win(tk.Toplevel):
	def __init__(self, config, parent=None):
		tk.Toplevel.__init__(self, parent)
		self.title('Live-Tuning Access')
		self.resizable(0, 0)
		self.grab_set()
		self.protocol("WM_DELETE_WINDOW", self.on_closing)
		self.run_task = False

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

		self.button_pmt = tk.Button(lta_frame, text="The poor man's live-tuning", command=self.watch)
		self.button_pmt.pack(fill=tk.X)

	def lock_buttons_decorator(func):
		def wrapper(self):
			self.button_dl['state'] = tk.DISABLED
			self.button_v['state'] = tk.DISABLED
			self.button_ifp['state'] = tk.DISABLED
			self.button_pmt['state'] = tk.DISABLED
			func(self)
			self.button_dl['state'] = tk.NORMAL
			self.button_v['state'] = tk.NORMAL
			self.button_ifp['state'] = tk.NORMAL
			self.button_pmt['state'] = tk.NORMAL
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
		tk.messagebox.showinfo(
			parent = self,
			title = "The poor man's live tuning",
			message = """This will constantly watch a calibration file on your computer and if changes are detected, it will upload them into your ECU within the next second.

Once everyhing is set up, open the file with RomRaider, make the needed modifications and save the file. As soon as the file is saved, the modifications will be upload to the ECU into the RAM.

Because the changes are in the RAM, everything will be lost after the ECU has shut down. This is for testing with running engine.
"""
		)
		cal = askCAL(self, title="The poor man's live tuning");
		self.grab_set()
		if(cal.base == None): return
		answer = filedialog.askopenfilename(
			parent = self,
			initialdir = os.getcwd(),
			initialfile = LiveTuningAccess.zones[1][3],
			title = "Please select a file:",
			filetypes = bin_file
		)
		if(answer):
			self.run_task = True
			lta.watch(cal.base, answer, cal.size, cal.copy, cal.verify, self.waitmore)

