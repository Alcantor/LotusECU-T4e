import os, re
import tkinter as tk
from tkinter import ttk, filedialog, simpledialog
from lib.ltacc import LiveTuningAccess
from lib.flasher import Flasher
from lib.gui_common import *
from lib.gui_fileprogress import FileProgress_widget
from lib.gui_tkmaptable import MapTableEditor, SimpleGauge

# Some constants
BO_BE = 'big'

# Some constants
BO_BE = 'big'
CHARSET = 'ISO-8859-15'

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
			initialdir = self.config['PATH']['bin'],
			initialfile = LiveTuningAccess.zones[1][3],
			title = "Please select a file:",
			filetypes = bin_file
		)
		if(answer):
			self.config['PATH']['bin'] = os.path.dirname(answer)
			self.run_task = True
			lta.watch(cal_base, answer, cal_size, copy, verify, self.waitmore)

	@lock_buttons_decorator
	@try_msgbox_decorator
	@lta_decorator
	def tuner(self, lta):
		sym = SYMMap("patch/t4e/black91.sym")
		if(lta.read_memory(sym.get_sym_addr("CAL_base")+0x3C8E, 5) != b"Lotus"):
			raise Exception("Unsupported ECU! Contact me!")
		speed = 0
		load = 0
		tunable = ({
			'xname': "rpm",
			'read_xdata': lambda: [int(v)*125//4+500 for v in lta.read_memory(sym.get_sym_addr("CAL_inj_efficiency_X_engine_speed"), 32)],
			'get_xvalue': lambda: speed,
			'yname': "load",
			'read_ydata': lambda: [int(v)*4 for v in lta.read_memory(sym.get_sym_addr("CAL_inj_efficiency_Y_engine_load"), 32)],
			'get_yvalue': lambda: load,
			'name': "Efficiency",
			'read_data': lambda: [[int(v)/2 for v in lta.read_memory(sym.get_sym_addr("CAL_inj_efficiency")+(i*32), 32)] for i in range(0,32)],
			'datafmt': "{:.1f}",
			'step': 0.5,
			'write_cell': lambda x,y,value:lta.write_memory(sym.get_sym_addr("CAL_inj_efficiency")+(y*32)+x,int(value*2).to_bytes(1, BO_BE))
		},{
			'xname': "rpm",
			'read_xdata': lambda: [int(v)*125//4+500 for v in lta.read_memory(sym.get_sym_addr("CAL_ign_advance_low_cam_base_X_engine_speed"), 32)],
			'get_xvalue': lambda: speed,
			'yname': "load",
			'read_ydata': lambda: [int(v)*4 for v in lta.read_memory(sym.get_sym_addr("CAL_ign_advance_low_cam_base_Y_engine_load"), 32)],
			'get_yvalue': lambda: load,
			'name': "Ignition Low Cam",
			'read_data': lambda: [[int(v)/4-10 for v in lta.read_memory(sym.get_sym_addr("CAL_ign_advance_low_cam_base")+(i*32), 32)] for i in range(0,32)],
			'datafmt': "{:.1f}",
			'step': 0.25,
			'write_cell': lambda x,y,value:lta.write_memory(sym.get_sym_addr("CAL_ign_advance_low_cam_base")+(y*32)+x,int((value+10)*4).to_bytes(1, BO_BE))
		},{
			'xname': "rpm",
			'read_xdata': lambda: [int(v)*125//4+500 for v in lta.read_memory(sym.get_sym_addr("CAL_ign_advance_high_cam_base_X_engine_speed"), 8)],
			'get_xvalue': lambda: speed,
			'yname': "load",
			'read_ydata': lambda: [int(v)*4 for v in lta.read_memory(sym.get_sym_addr("CAL_ign_advance_high_cam_base_Y_engine_load"), 8)],
			'get_yvalue': lambda: load,
			'name': "Ignition High Cam",
			'read_data': lambda: [[int(v)/4-10 for v in lta.read_memory(sym.get_sym_addr("CAL_ign_advance_high_cam_base")+(i*8), 8)] for i in range(0,8)],
			'datafmt': "{:.1f}",
			'step': 0.25,
			'write_cell': lambda x,y,value:lta.write_memory(sym.get_sym_addr("CAL_ign_advance_high_cam_base")+(y*8)+x,int((value+10)*4).to_bytes(1, BO_BE))
		})
		gauges = ({
			'name': "Engine Speed",
			'fmt': "{:d} rpm",
			'low': 0,
			'high': 8400,
			'read_data': lambda: speed
		},{
			'name': "Engine Load",
			'fmt': "{:d} mg/str.",
			'low': 60,
			'high': 864,
			'read_data': lambda: load
		},{
			'name': "Coolant",
			'fmt': "{:.1f} °C",
			'low': 20,
			'high': 110,
			'read_data': lambda: int.from_bytes(lta.read_memory(sym.get_sym_addr("temp_coolant"), 1), BO_BE)*5/8-40
		},{
			'name': "Engine air",
			'fmt': "{:.1f} °C",
			'low': 20,
			'high': 70,
			'read_data': lambda: int.from_bytes(lta.read_memory(sym.get_sym_addr("temp_engine_air"), 1), BO_BE)*5/8-40
		},{
			'name': "MAF Accumulated",
			'fmt': "{:.1f} g",
			'low': 0,
			'high': 1000,
			'read_data': lambda: int.from_bytes(lta.read_memory(sym.get_sym_addr("maf_accumulated_1"), 4), BO_BE)/1000
		},{
			'name': "TPS",
			'fmt': "{:.1f} %",
			'low': 0,
			'high': 100,
			'read_data': lambda: int.from_bytes(lta.read_memory(sym.get_sym_addr("sensor_adc_tps1"), 2), BO_BE)*100/1023
		},{
			'name': "Tip In",
			'fmt': "{:d} us",
			'low': 0,
			'high': 900,
			'read_data': lambda: int.from_bytes(lta.read_memory(sym.get_sym_addr("injtip_tip_in"), 4), BO_BE)
		},{
			'name': "Tip Out",
			'fmt': "{:d} us",
			'low': 0,
			'high': 900,
			'read_data': lambda: int.from_bytes(lta.read_memory(sym.get_sym_addr("injtip_tip_out"), 4), BO_BE)
		},{
			'name': "Injection Time",
			'fmt': "{:d} us",
			'low': 0,
			'high': 14285,
			#'read_data': lambda: int.from_bytes(lta.read_memory(self.sym.get_sym_addr("inj_time_final_1"), 4), BO_BE)
			'read_data': lambda: int.from_bytes(lta.read_memory(0x304512, 2), BO_BE) # Read directly the TPU Parameter
		},{
			'name': "Learn Dead Time",
			'fmt': "{:d} us",
			'low': -100,
			'high': 100,
			'read_data': lambda: int.from_bytes(lta.read_memory(sym.get_sym_addr("LEA_ltft_idle_adj"), 2), BO_BE, signed=True)
		},{
			'name': "STFT",
			'fmt': "{:.1f} %",
			'low': -10,
			'high': 10,
			'read_data': lambda: int.from_bytes(lta.read_memory(sym.get_sym_addr("inj_time_adj_by_stft"), 2), BO_BE, signed=True)/20
		},{
			'name': "LTFT",
			'fmt': "{:.1f} %",
			'low': -10,
			'high': 10,
			'read_data': lambda: int.from_bytes(lta.read_memory(sym.get_sym_addr("inj_time_adj_by_ltft"), 2), BO_BE, signed=True)/20
		},{
			'name': "Target AFR",
			'fmt': "{:.2f} AFR",
			'low': 10,
			'high': 20,
			'read_data': lambda: int.from_bytes(lta.read_memory(sym.get_sym_addr("afr_target"), 2), BO_BE)/100
		},{
			'name': "Measured AFR",
			'fmt': "{:.2f} AFR",
			'low': 10,
			'high': 20,
			'read_data': lambda: int.from_bytes(lta.read_memory(0x304E86, 2), BO_BE)*10/1023+10
		},{
			'name': "Adv. Ign",
			'fmt': "{:.2f} °",
			'low': -10,
			'high': 50,
			'read_data': lambda: int.from_bytes(lta.read_memory(sym.get_sym_addr("ign_adv_final"), 2), BO_BE, signed=True)/4
		},{
			'name': "Octane Scaler #1",
			'fmt': "{:.1f} %",
			'low': 0,
			'high': 100,
			'read_data': lambda: int.from_bytes(lta.read_memory(sym.get_sym_addr("LEA_knock_retard2")+0, 2), BO_BE)/655.36
		},{
			'name': "Octane Scaler #2",
			'fmt': "{:.1f} %",
			'low': 0,
			'high': 100,
			'read_data': lambda: int.from_bytes(lta.read_memory(sym.get_sym_addr("LEA_knock_retard2")+2, 2), BO_BE)/655.36
		},{
			'name': "Octane Scaler #3",
			'fmt': "{:.1f} %",
			'low': 0,
			'high': 100,
			'read_data': lambda: int.from_bytes(lta.read_memory(sym.get_sym_addr("LEA_knock_retard2")+4, 2), BO_BE)/655.36
		},{
			'name': "Octane Scaler #4",
			'fmt': "{:.1f} %",
			'low': 0,
			'high': 100,
			'read_data': lambda: int.from_bytes(lta.read_memory(sym.get_sym_addr("LEA_knock_retard2")+6, 2), BO_BE)/655.36
		})
		# For flexfuel patch
		#CAL_base_extra = 0x3FEA20
		#FLEX_base = CAL_base_extra + 0x0C
		#tunable += (dict(tunable[0]), dict(tunable[1]), dict(tunable[2]))
		#tunable[3]['name'] += " Ethanol"
		#tunable[3]['read_data'] = lambda: [[int(v)/2 for v in lta.read_memory(FLEX_base+0x07C+(i*32), 32)] for i in range(0,32)]
		#tunable[3]['write_cell'] = lambda x,y,value:lta.write_memory(FLEX_base+0x07C+(y*32)+x,int(value*2).to_bytes(1, BO_BE))
		#tunable[4]['name'] += " Ethanol"
		#tunable[4]['read_data'] = lambda: [[int(v)/4-10 for v in lta.read_memory(FLEX_base+0x58C+(i*32), 32)] for i in range(0,32)]
		#tunable[4]['write_cell'] = lambda x,y,value:lta.write_memory(FLEX_base+0x58C+(y*32)+x,int((value+10)*4).to_bytes(1, BO_BE))
		#tunable[5]['name'] += " Ethanol"
		#tunable[5]['read_data'] = lambda: [[int(v)/4-10 for v in lta.read_memory(FLEX_base+0x01C+(i*8), 8)] for i in range(0,8)]
		#tunable[5]['write_cell'] = lambda x,y,value:lta.write_memory(FLEX_base+0x01C+(y*8)+x,int((value+10)*4).to_bytes(1, BO_BE))
		#gauges += ({
		#	'name': "Ethanol",
		#	'fmt': "{:.1f} %",
		#	'low': 0,
		#	'high': 85,
		#	'read_data': lambda: int.from_bytes(lta.read_memory(0x3FF410, 1), BO_BE)/2.55
		#},)
		tw = TunerWin(
			self.config, tunable, gauges,
			lambda: lta.write_memory(sym.get_sym_addr("LEA_knock_retard2"), b'\x00\x00\x00\x00\x00\x00\x00\x00'),
			lambda f: lta.upload_verify(sym.get_sym_addr("CAL_base"), f), # or lta.upload_verify(CAL_base_extra, f+".xtracal"),
			lambda f: lta.download_verify(sym.get_sym_addr("CAL_base"), 0x3CB4, f), # or lta.download_verify(CAL_base_extra, 0x9C4, f+".xtracal"),
			self
		)
		while(tw.is_running):
			# Cache speed and load here - There are used mutiple times!
			speed = int.from_bytes(lta.read_memory(sym.get_sym_addr("engine_speed_2"), 2), BO_BE)
			load = int.from_bytes(lta.read_memory(sym.get_sym_addr("load_1"), 4), BO_BE)
			tw.update()
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
	def __init__(self, config, tunable, gauges, zeroscaler, impfn, expfn, parent=None):
		tk.Toplevel.__init__(self, parent)
		self.title('Tuner')
		self.resizable(0, 0)
		self.grab_set()
		self.bind('<KeyPress>', self.onKeyPress)
		self.protocol("WM_DELETE_WINDOW", self.on_closing)
		self.is_running = True
		self.config = config
		f_vertical = tk.Frame(self)
		f_vertical.pack(side=tk.LEFT)
		self.tabControl = ttk.Notebook(f_vertical)
		self.m = []
		for t in tunable:
			m = MapTableEditor(self.tabControl, **t)
			m.pack()
			self.m.append(m)
			self.tabControl.add(m, text=t['name'])
		self.tabControl.pack()

		# Actions
		f_action = tk.LabelFrame(f_vertical, highlightthickness=2, text="Actions")
		f_action.pack(fill=tk.X)
		self.force_ft0 = tk.IntVar()
		tk.Checkbutton(f_action, text='Zero STFT/LTFT',variable=self.force_ft0).pack(side=tk.LEFT)
		self.force_dt0 = tk.IntVar()
		tk.Checkbutton(f_action, text='Zero dead time',variable=self.force_dt0).pack(side=tk.LEFT)
		tk.Button(f_action, text="Zero Ign. Scaler", command=zeroscaler).pack(side=tk.LEFT)
		tk.Button(f_action, text="Import", command=self.impcal).pack(side=tk.LEFT)
		tk.Button(f_action, text="Export", command=self.expcal).pack(side=tk.LEFT)
		self.impfn = impfn
		self.expfn = expfn

		# Live Variables
		f_live = tk.LabelFrame(self, highlightthickness=2, text="Live-Data")
		f_live.pack(side=tk.LEFT)
		self.l = []
		for g in gauges:
			l = SimpleGauge(f_live, **g)
			l.pack()
			self.l.append(l)

	def update(self):
		for m in self.m: m.update()
		for l in self.l: l.update()

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

