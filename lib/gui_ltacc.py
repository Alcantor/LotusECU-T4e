import os, re
import tkinter as tk
from tkinter import ttk, filedialog, simpledialog
from lib.ltacc import LiveTuningAccess
from lib.flasher import Flasher
from lib.gui_common import *
from lib.gui_fileprogress import FileProgress_widget
from lib.gui_tkmaptable import MapTableEditor, TextGauge

# Some constants
BO_BE = 'big'

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
			"RAM+0x4000 - White K4/T4",
			"RAM+0x0000 - Caterham CD0MB000    Oct  3 2011 15:26:36000VC",
			"RAM+0x27D8 - Caterham C1D3M000____Dec 10 2013 15:47:31V0000",
			"RAM+0x2920 - Lotus T6 T6AIN V000Q 02/01/2014 LotusEng",
			"RAM+0x8658 - T6YAR V000V 23/11/2017 LotusEng"
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
			0x400027D8,
			0x40002920,
			0x40008658
		][self.cb.current()]
		self.size = [
			0x3CA0,
			0x3CB4,
			0x3CA0,
			0x3C8E,
			0x3C94,
			0x6000,
			0x69A8,
			0x69A8,
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
		self.config = config

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

		self.button_tune = tk.Button(lta_frame, text="Tuner (Only Black EngV0091)", command=self.tuner)
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
			initialdir = self.config['PATH']['bin'],
			initialfile = zone[3],
			title = "Please select a file:",
			filetypes = bin_file
		)
		if(answer):
			self.config['PATH']['bin'] = os.path.dirname(answer)
			lta.download(zone[1], zone[2], answer)

	@lock_buttons_decorator
	@try_msgbox_decorator
	@lta_decorator
	def verify(self, lta):
		zone = LiveTuningAccess.zones[self.combo_zones.current()]
		answer = filedialog.askopenfilename(
			parent = self,
			initialdir = self.config['PATH']['bin'],
			initialfile = zone[3],
			title = "Please select a file:",
			filetypes = bin_file
		)
		if(answer):
			self.config['PATH']['bin'] = os.path.dirname(answer)
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
			initialdir = self.config['PATH']['bin'],
			initialfile = LiveTuningAccess.zones[1][3],
			title = "Please select a file:",
			filetypes = bin_file
		)
		if(answer):
			self.config['PATH']['bin'] = os.path.dirname(answer)
			self.run_task = True
			lta.watch(cal.base, answer, cal.size, cal.copy, cal.verify, self.waitmore)

	@lock_buttons_decorator
	@try_msgbox_decorator
	@lta_decorator
	def tuner(self, lta):
		sym = SYMMap("patch/t4e/black91.sym")
		if(lta.read_memory(sym.get_sym_addr("CAL_base")+0x3C8E, 5) != b"Lotus"):
			raise Exception("Unsupported ECU! Contact me!")
		tunable = ({
			'xname': "rpm",
			'read_xdata': lambda: [int(v)*125//4+500 for v in lta.read_memory(sym.get_sym_addr("CAL_inj_efficiency_X_engine_speed"), 32)],
			'yname': "load",
			'read_ydata': lambda: [int(v)*4 for v in lta.read_memory(sym.get_sym_addr("CAL_inj_efficiency_Y_engine_load"), 32)],
			'name': "Efficiency",
			'read_data': lambda: [[int(v)/2 for v in lta.read_memory(sym.get_sym_addr("CAL_inj_efficiency")+(i*32), 32)] for i in range(0,32)],
			'datafmt': "{:.1f}",
			'step': 0.5,
			'write_cell': lambda x,y,value:lta.write_memory(sym.get_sym_addr("CAL_inj_efficiency")+(y*32)+x,int(value*2).to_bytes(1, BO_BE))
		},{
			'xname': "rpm",
			'read_xdata': lambda: [int(v)*125//4+500 for v in lta.read_memory(sym.get_sym_addr("CAL_ign_advance_low_cam_base_X_engine_speed"), 32)],
			'yname': "load",
			'read_ydata': lambda: [int(v)*4 for v in lta.read_memory(sym.get_sym_addr("CAL_ign_advance_low_cam_base_Y_engine_load"), 32)],
			'name': "Ignition Low Cam",
			'read_data': lambda: [[int(v)/4-10 for v in lta.read_memory(sym.get_sym_addr("CAL_ign_advance_low_cam_base")+(i*32), 32)] for i in range(0,32)],
			'datafmt': "{:.1f}",
			'step': 0.25,
			'write_cell': lambda x,y,value:lta.write_memory(sym.get_sym_addr("CAL_ign_advance_low_cam_base")+(y*32)+x,int((value+10)*4).to_bytes(1, BO_BE))
		},{
			'xname': "rpm",
			'read_xdata': lambda: [int(v)*125//4+500 for v in lta.read_memory(sym.get_sym_addr("CAL_ign_advance_high_cam_base_X_engine_speed"), 8)],
			'yname': "load",
			'read_ydata': lambda: [int(v)*4 for v in lta.read_memory(sym.get_sym_addr("CAL_ign_advance_high_cam_base_Y_engine_load"), 8)],
			'name': "Ignition High Cam",
			'read_data': lambda: [[int(v)/4-10 for v in lta.read_memory(sym.get_sym_addr("CAL_ign_advance_high_cam_base")+(i*8), 8)] for i in range(0,8)],
			'datafmt': "{:.1f}",
			'step': 0.25,
			'write_cell': lambda x,y,value:lta.write_memory(sym.get_sym_addr("CAL_ign_advance_high_cam_base")+(y*8)+x,int((value+10)*4).to_bytes(1, BO_BE))
		})
		# For flexfuel patch
		#CAL_base_extra = 0x3FEA60
		#tunable += (dict(tunable[0]), dict(tunable[1]), dict(tunable[2]))
		#tunable[3]['name'] += " Ethanol"
		#tunable[3]['read_data'] = lambda: [[int(v)/2 for v in lta.read_memory(CAL_base_extra+0x07C+(i*32), 32)] for i in range(0,32)]
		#tunable[3]['write_cell'] = lambda x,y,value:lta.write_memory(CAL_base_extra+0x07C+(y*32)+x,int(value*2).to_bytes(1, BO_BE))
		#tunable[4]['name'] += " Ethanol"
		#tunable[4]['read_data'] = lambda: [[int(v)/4-10 for v in lta.read_memory(CAL_base_extra+0x58C+(i*32), 32)] for i in range(0,32)]
		#tunable[4]['write_cell'] = lambda x,y,value:lta.write_memory(CAL_base_extra+0x58C+(y*32)+x,int((value+10)*4).to_bytes(1, BO_BE))
		#tunable[5]['name'] += " Ethanol"
		#tunable[5]['read_data'] = lambda: [[int(v)/4-10 for v in lta.read_memory(CAL_base_extra+0x01C+(i*8), 8)] for i in range(0,8)]
		#tunable[5]['write_cell'] = lambda x,y,value:lta.write_memory(CAL_base_extra+0x01C+(y*8)+x,int((value+10)*4).to_bytes(1, BO_BE))
		tw = TunerWin(
			self.config, tunable,
			lambda: lta.write_memory(sym.get_sym_addr("LEA_knock_retard2"), b'\x00\x00\x00\x00\x00\x00\x00\x00'),
			lambda f: lta.upload_verify(sym.get_sym_addr("CAL_base"), f), # or lta.upload_verify(CAL_base_extra, f+".xtracal"),
			lambda f: lta.download_verify(sym.get_sym_addr("CAL_base"), 0x3CB4, f), # or lta.download_verify(CAL_base_extra, 0x9BC, f+".xtracal"),
			self
		)
		while(tw.is_running):
			speed = int.from_bytes(lta.read_memory(sym.get_sym_addr("engine_speed_2"), 2), BO_BE)
			load = int.from_bytes(lta.read_memory(sym.get_sym_addr("load_1"), 4), BO_BE)
			tipin = int.from_bytes(lta.read_memory(sym.get_sym_addr("injtip_tip_in"), 4), BO_BE)
			tipout = int.from_bytes(lta.read_memory(sym.get_sym_addr("injtip_tip_out"), 4), BO_BE)
			#injtime = int.from_bytes(lta.read_memory(self.sym.get_sym_addr("inj_time_final_1"), 4), BO_BE)
			injtime = int.from_bytes(lta.read_memory(0x304512, 2), BO_BE) # Read directly the TPU Parameter
			stft = int.from_bytes(lta.read_memory(sym.get_sym_addr("inj_time_adj_by_stft"), 2), BO_BE, signed=True)/20
			ltft = int.from_bytes(lta.read_memory(sym.get_sym_addr("inj_time_adj_by_ltft"), 2), BO_BE, signed=True)/20
			tafr = int.from_bytes(lta.read_memory(sym.get_sym_addr("afr_target"), 2), BO_BE)/100
			mafr = int.from_bytes(lta.read_memory(0x304E86, 2), BO_BE)*10/1023+10
			aign = int.from_bytes(lta.read_memory(sym.get_sym_addr("ign_adv_final"), 2), BO_BE, signed=True)/4
			knocks = [int.from_bytes(lta.read_memory(sym.get_sym_addr("LEA_knock_retard2")+i, 2), BO_BE)/655.36 for i in range(0, 8, 2)]
			clt = int.from_bytes(lta.read_memory(sym.get_sym_addr("temp_coolant"), 1), BO_BE)*5/8-40
			macc = int.from_bytes(lta.read_memory(sym.get_sym_addr("maf_accumulated_1"), 4), BO_BE)/1000
			tps = int.from_bytes(lta.read_memory(sym.get_sym_addr("sensor_adc_tps1"), 2), BO_BE)*100/1023
			#eth = int.from_bytes(lta.read_memory(0x3FEA40, 1), BO_BE)/2.55
			tw.update(speed, load, tipin, tipout, injtime, stft, ltft, tafr, mafr, aign, knocks, clt, macc, tps)#, eth)
			if(tw.force_ft0.get()):
				lta.write_memory(sym.get_sym_addr("LEA_ltft_low_adj"), b'\x80')
				lta.write_memory(sym.get_sym_addr("LEA_ltft_high_adj"), b'\x80')
				lta.write_memory(sym.get_sym_addr("inj_time_adj_by_stft"), b'\x00\x00')
			if(tw.force_dt0.get()):
				lta.write_memory(sym.get_sym_addr("LEA_ltft_idle_adj"), b'\x00\x00')
			self.update()

class SYMMap:
	def __init__(self, file):
		self.syms = {}
		r = re.compile("^(.*) = (0x[0-9a-f]*);")
		with open(file,'r') as f:
			for line in f.readlines():
				m = r.match(line)
				if(m): self.syms[m.group(1)] = int(m.group(2), 16)

	def get_sym_addr(self, symbol):
		return self.syms[symbol]

class TunerWin(tk.Toplevel):
	def __init__(self, config, tunable, zeroscaler, impfn, expfn, parent=None):
		tk.Toplevel.__init__(self, parent)
		self.title('Tuner')
		self.resizable(0, 0)
		self.grab_set()
		self.bind('<KeyPress>', self.onKeyPress)
		self.protocol("WM_DELETE_WINDOW", self.on_closing)
		self.is_running = True
		self.config = config
		self.tabControl = ttk.Notebook(self)
		self.m = []
		for t in tunable:
			m = MapTableEditor(self.tabControl, **t)
			m.pack()
			self.m.append(m)
			self.tabControl.add(m, text=t['name'])
		self.tabControl.pack(side=tk.LEFT)

		# Live Variables
		frame_fuel = tk.LabelFrame(self, highlightthickness=2, text="Live-Data Fueling")
		frame_fuel.pack(side=tk.LEFT, anchor=tk.N)

		self.g_speed = TextGauge(frame_fuel, "Engine Speed", "{:d} rpm")
		self.g_load = TextGauge(frame_fuel, "Engine Load", "{:d} mg/str.")

		self.g_tipin = TextGauge(frame_fuel, "Tip In", "{:d} us")
		self.g_tipout = TextGauge(frame_fuel, "Tip Out", "{:d} us")
		self.g_injtime = TextGauge(frame_fuel, "Injection Time", "{:d} us")
		self.g_stft = TextGauge(frame_fuel, "STFT", "{:.1f} %")
		self.g_ltft = TextGauge(frame_fuel, "LTFT", "{:.1f} %")

		self.g_tafr = TextGauge(frame_fuel, "Target AFR", "{:.2f} AFR")
		self.g_mafr = TextGauge(frame_fuel, "Measured AFR", "{:.2f} AFR")
		self.g_dafr = TextGauge(frame_fuel, "Diff AFR", "{:+.2f} AFR")

		self.force_ft0 = tk.IntVar()
		tk.Checkbutton(frame_fuel, text='Zero STFT/LTFT',variable=self.force_ft0).pack()
		self.force_dt0 = tk.IntVar()
		tk.Checkbutton(frame_fuel, text='Zero dead time',variable=self.force_dt0).pack()

		frame_ign = tk.LabelFrame(self, highlightthickness=2, text="Live-Data Ignition")
		frame_ign.pack(side=tk.LEFT, anchor=tk.N)

		self.g_clt = TextGauge(frame_ign, "Coolant", "{:.1f} °C")
		self.g_macc = TextGauge(frame_ign, "MAF Accumulated", "{:.1f} g")
		self.g_tps = TextGauge(frame_ign, "TPS", "{:.1f} %")

		#self.g_eth = TextGauge(frame_ign, "Ethanol", "{:.1f} %")

		self.g_aign = TextGauge(frame_ign, "Adv. Ign", "{:.2f} °")
		self.g_knock1 = TextGauge(frame_ign, "Octane Scaler #1", "{:.1f} %")
		self.g_knock2 = TextGauge(frame_ign, "Octane Scaler #2", "{:.1f} %")
		self.g_knock3 = TextGauge(frame_ign, "Octane Scaler #3", "{:.1f} %")
		self.g_knock4 = TextGauge(frame_ign, "Octane Scaler #4", "{:.1f} %")

		tk.Button(frame_ign, text="Zero Ign. Scaler", command=zeroscaler).pack(fill=tk.X)
		tk.Button(frame_ign, text="Import", command=self.impcal).pack(fill=tk.X)
		tk.Button(frame_ign, text="Export", command=self.expcal).pack(fill=tk.X)
		self.impfn = impfn
		self.expfn = expfn

	def update(self, speed, load, tipin, tipout, injtime, stft, ltft, tafr, mafr, aign, knocks, clt, macc, tps):#, eth):
		for m in self.m: m.update(speed, load)
		self.g_speed.update(speed)
		self.g_load.update(load)
		self.g_tipin.update(tipin)
		self.g_tipout.update(tipout)
		self.g_injtime.update(injtime)
		self.g_stft.update(stft)
		self.g_ltft.update(ltft)
		self.g_tafr.update(tafr)
		self.g_mafr.update(mafr)
		self.g_dafr.update(tafr-mafr)
		self.g_aign.update(aign)
		self.g_knock1.update(knocks[0])
		self.g_knock2.update(knocks[1])
		self.g_knock3.update(knocks[2])
		self.g_knock4.update(knocks[3])
		self.g_clt.update(clt)
		self.g_macc.update(macc)
		self.g_tps.update(tps)
		#self.g_eth.update(eth)

	@try_msgbox_decorator
	def impcal(self):
		answer = filedialog.askopenfilename(
			parent = self,
			initialdir = self.config['PATH']['bin'],
			initialfile = "calrom-tuner.bin",
			title = "Please select a file:",
			filetypes = bin_file
		)
		if(answer):
			self.config['PATH']['bin'] = os.path.dirname(answer)
			self.impfn(answer)
			for m in self.m: m.reload()

	@try_msgbox_decorator
	def expcal(self):
		answer = filedialog.asksaveasfilename(
			parent = self,
			initialdir = self.config['PATH']['bin'],
			initialfile = "calrom-tuner.bin",
			title = "Please select a file:",
			filetypes = bin_file
		)
		if(answer):
			self.config['PATH']['bin'] = os.path.dirname(answer)
			self.expfn(answer)

	@try_msgbox_decorator
	def onKeyPress(self, event):
		i = self.tabControl.index('current')
		if  (event.char == 'q'): self.m[i].inc_cur()
		elif(event.char == 'a'): self.m[i].dec_cur()
		elif(event.char == '+'): self.m[i].inc_sel()
		elif(event.char == '-'): self.m[i].dec_sel()
		elif(event.char == 'e'): self.tabControl.select(0)
		elif(event.char == 'h'): self.tabControl.select(1)
		elif(event.char == 'l'): self.tabControl.select(2)
		else: return
		self.m[i].table.focus_set()

	def on_closing(self):
		self.is_running = False
		self.destroy()

