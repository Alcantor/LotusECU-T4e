import os, colorsys
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog
from lib.gui_common import *

def hls_to_hex(h,l,s):
	r, g, b = [int(x * 255) for x in colorsys.hls_to_rgb(h,l,s)]
	return f'#{r:02X}{g:02X}{b:02X}'

class MapTable(tk.Canvas):
	CELLW = 40
	CELLH = 20

	def __init__(
		self, parent, name,
		read_data, datafmt, write_cell, step,
		xname, read_xdata, xfmt, read_xvalue,
		yname, read_ydata, yfmt, read_yvalue
	):
		tk.Canvas.__init__(self, parent)

		self.name = name
		self.read_data = read_data
		self.datafmt = datafmt
		self.write_cell = write_cell
		self.step = step

		self.xname = xname
		self.read_xdata = read_xdata
		self.xfmt = xfmt
		self.read_xvalue = read_xvalue

		self.yname = yname
		self.read_ydata = read_ydata
		self.yfmt = yfmt
		self.read_yvalue = read_yvalue

		# Runtime state
		self.xdata = []
		self.ydata = []
		self.data = []

		self.xaxis = []
		self.yaxis = []
		self.cells = []

		self.interpolation = (0, 0, 0, 0, ((1.0, 0.0), (0.0, 0.0)), 0.0)
		self.cursor = ()
		self.selection = [0, 0, 0, 0, None, False]
		self.color_job = None

		self.bind("<Button-1>", self.on_left_click)
		self.bind("<Button-3>", self.on_right_click)
		self.bind("<Motion>", self.on_motion)
		self.bind("<ButtonRelease>", self.on_release)

		self.reload()

	def reload(self):
		self.xdata = self.read_xdata()
		self.ydata = self.read_ydata()
		self.data = self.read_data()
		self.xsize = len(self.xdata)
		self.ysize = len(self.ydata)
		self.delete("all")
		self.config(
			width=(self.xsize+1)*self.CELLW,
			height=(self.ysize+1)*self.CELLH
		)

		# Axis labels
		self.create_line(0, 0, self.CELLW, self.CELLH)
		self.create_text(self.CELLW, 2, anchor=tk.NE, text=self.xname, font='Helvetica 6')
		self.create_text(2, self.CELLH,	anchor=tk.SW, text=self.yname, font='Helvetica 6')

		# X axis
		self.xaxis = [
			self.create_text(
				self.CELLW*(x+1)+self.CELLW//2, 4,
				anchor=tk.N, text=self.xfmt.format(self.xdata[x]),
				font='Helvetica 8'
			) for x in range(self.xsize)
		]

		# Y axis
		self.yaxis = [
			self.create_text(
				self.CELLW//2, self.CELLH*(y+1)+4,
				anchor=tk.N, text=self.yfmt.format(self.ydata[y]),
				font='Helvetica 8'
			) for y in range(self.ysize)
		]

		# Cells
		self.cells = [
			[
				[
					self.create_rectangle(
						self.CELLW*(x+1)+1, self.CELLH*(y+1)+1,
						self.CELLW*(x+2)-1, self.CELLH*(y+2)-1,
						fill='white', outline='#AAAAAA', width=2
					),
					self.create_text(
						self.CELLW*(x+2)-3, self.CELLH*(y+1)+self.CELLH//2+1,
						anchor=tk.E, text=self.datafmt.format(self.data[y][x]),
						font='Helvetica 8 bold'
					)
				] for x in range(self.xsize)
			] for y in range(self.ysize)
		]
		self.color_cells()

	def color_cells(self):
		vmin = vmax = self.data[0][0]
		for y in range(self.ysize):
			for x in range(self.xsize):
				if(self.data[y][x] < vmin): vmin = self.data[y][x]
				if(self.data[y][x] > vmax): vmax = self.data[y][x]
		d = vmax-vmin
		if(d == 0): return # No coloration if all cells are identical.
		q = 0.7/d
		for y in range(self.ysize):
			for x in range(self.xsize):
				self.itemconfigure(
					self.cells[y][x][0],
					fill=hls_to_hex(0.7-((self.data[y][x]-vmin)*q), 0.8, 0.5)
				)

	def color_cells_delayed(self):
		if(self.color_job): self.after_cancel(self.color_job)
		self.color_job = self.after(1000, self.color_cells)

	def draw_cursor(self):
		for i in self.cursor: self.delete(i)
		cx, cy, x2r, y2r, m, res = self.interpolation
		px=self.CELLW*(cx+1)
		py=self.CELLH*(cy+1)
		px2=px+self.CELLW*(x2r+0.5)
		py2=py+self.CELLH*(y2r+0.5)
		width=self.CELLW*min(self.xsize-cx, 2)
		height=self.CELLH*min(self.ysize-cy, 2)
		self.cursor = (
			self.create_rectangle(px, py, px+width, py+height, outline='red', width=4),
			self.create_line(px2, self.CELLH, px2, py, fill="red", width=2),
			self.create_line(self.CELLW, py2, px, py2, fill="red", width=2),
			self.create_line(px2, py+height, px2, (self.ysize+1)*self.CELLH, fill="red", width=2),
			self.create_line(px+width, py2, (self.xsize+1)*self.CELLW, py2, fill="red", width=2)
		)

	def draw_selection(self):
		if(self.selection[4]): self.delete(self.selection[4])
		if(self.selection[0:4] == [0,0,0,0]): return
		px=self.CELLW*(self.selection[0]+1)
		py=self.CELLH*(self.selection[1]+1)
		px2=self.CELLW*(self.selection[2]+1)
		py2=self.CELLH*(self.selection[3]+1)
		self.selection[4] = self.create_rectangle(px, py, px2, py2, outline='blue', width=4)

	def update(self):
		xvalue = self.read_xvalue()
		yvalue = self.read_yvalue()

		# Find X and Y cell
		cx = cy = 0
		#while(cx+1 < self.xsize and self.xdata[cx] == self.xdata[cx+1]):
		#	cx = cx + 1;
		for x in range(cx,self.xsize):
			if(xvalue >= self.xdata[x]): cx = x
			else: break
		#while(cy+1 < self.ysize and self.ydata[cy] == self.ydata[cy+1]):
		#	cy = cy + 1;
		for y in range(cy,self.ysize):
			if(yvalue >= self.ydata[y]): cy = y
			else: break

		# Interpolation ratio
		x2r = y2r = 0.0
		if(cx+1 < self.xsize):
			step = self.xdata[cx+1]-self.xdata[cx]
			diff = xvalue-self.xdata[cx]
			if(diff > 0): x2r = diff/step
		if(cy+1 < self.ysize):
			step = self.ydata[cy+1]-self.ydata[cy]
			diff = yvalue-self.ydata[cy]
			if(diff > 0): y2r = diff/step
		x1r = 1.0 - x2r
		y1r = 1.0 - y2r
		m = ((y1r*x1r, y1r*x2r), (y2r*x1r, y2r*x2r))

		# Compute result value with interpolation
		res = 0.0
		for y in range(2):
			for x in range(2):
				# Avoid index out of bound, by checking m !
				if(m[y][x] != 0.0):
					res += self.data[cy+y][cx+x]*m[y][x]

		# Save all
		self.interpolation = (cx, cy, x2r, y2r, m, res)

		# Update the cursor
		self.draw_cursor()

	def modify_cell(self, x, y, value, relative=True):
		if(x < self.xsize and y < self.ysize):
			if(relative): self.data[y][x] += value
			else: self.data[y][x] = value
			self.itemconfigure(self.cells[y][x][1],
				text=self.datafmt.format(self.data[y][x]))
			self.write_cell(x,y,self.data[y][x])

	def modify_cursor(self, value, algo=0):
		cx, cy, x2r, y2r, m, res = self.interpolation
		if(algo == 0):
			for y in range(2):
				for x in range(2):
					self.modify_cell(cx+x, cy+y, value*m[y][x])
		elif(algo == 1):
			for y in range(2):
				for x in range(2):
					self.modify_cell(cx+x, cy+y, value)
		elif(algo == 2):
			max_value = 0
			mx = my = 0
			for y in range(2):
				for x in range(2):
					if(m[y][x] > max_value):
						max_value = m[y][x]
						mx, my = x, y
			self.modify_cell(cx+mx, cy+my, value)
		self.color_cells_delayed()

	def modify_selection(self, value, relative=True):
		for y in range(self.selection[1], self.selection[3]):
			for x in range(self.selection[0], self.selection[2]):
				self.modify_cell(x, y, value, relative)
		self.color_cells_delayed()

	def on_left_click(self, event):
		self.selection[0] = sorted([0, (event.x//self.CELLW)-1, self.xsize-1])[1]
		self.selection[1] = sorted([0, (event.y//self.CELLH)-1, self.ysize-1])[1]
		self.selection[2] = self.selection[0] + 1
		self.selection[3] = self.selection[1] + 1
		self.selection[5] = True
		self.draw_selection()

	def on_right_click(self, event):
		self.selection[0] = self.selection[2] = 0
		self.selection[1] = self.selection[3] = 0
		self.draw_selection()

	def on_motion(self, event):
		if(self.selection[5]):
			self.selection[2] = sorted([self.selection[0]+1, (event.x//self.CELLW), self.xsize])[1]
			self.selection[3] = sorted([self.selection[1]+1, (event.y//self.CELLH), self.ysize])[1]
			self.draw_selection()

	def on_release(self, event):
		self.selection[5] = False

class SimpleGauge(tk.Canvas):
	def __init__(self, parent, name, read_data, fmt, low, high, font='Helvetica 16'):
		tk.Canvas.__init__(self, parent, width=180, height=30)
		self.create_rectangle(1, 1, 180, 30, fill="white", outline="black", width=1)
		self.colorbar = self.create_rectangle(3, 20, 179, 29, fill="red", width=0)
		self.create_text(3, 3, anchor=tk.NW, justify=tk.LEFT, text=name, font='Helvetica 8')
		self.value = self.create_text(178, 30, anchor=tk.SE, justify=tk.RIGHT, text="---", font=font)
		self.name = name
		self.read_data = read_data
		self.fmt = fmt
		self.low = low
		self.high = high
	def update(self):
		self.data = self.read_data()
		self.itemconfigure(self.value, text=self.fmt.format(self.data))
		ratio = sorted([0, (self.data-self.low)/(self.high-self.low), 1.0])[1]
		self.coords(self.colorbar, 3, 20, 179*ratio, 29)
		self.itemconfigure(self.colorbar, fill=hls_to_hex(0.7-(0.7*ratio), 0.5, 1.0))

class TunerWin(tk.Toplevel):
	def __init__(self, prefs, ecudef, parent=None):
		tk.Toplevel.__init__(self, parent)

		self.prefs = prefs
		self.ecudef = ecudef

		self.title('Tuner')
		self.resizable(0, 0)
		self.grab_set()
		self.bind('<KeyPress>', self.on_key_pressed)
		self.bind("<Destroy>", self.log_close)

		f_left = tk.Frame(self)
		f_left.pack(side=tk.LEFT, fill=tk.Y)

		f_ctrl = tk.Frame(f_left)
		f_ctrl.pack(anchor=tk.W)

		self.tables = ecudef.maps(f_left)
		for m in self.tables: m.pack()

		f_gauges = tk.Frame(self)
		f_gauges.pack(side=tk.LEFT)
		self.gauges = ecudef.gauges(f_gauges)
		for g in self.gauges: g.pack()

		f_cal = tk.LabelFrame(f_ctrl, text="Calibration:")
		f_cal.grid_rowconfigure(0, uniform="ctrl")
		f_cal.grid_rowconfigure(1, uniform="ctrl")
		f_cal.grid_rowconfigure(2, uniform="ctrl")
		f_cal.pack(side=tk.LEFT, padx=4, fill=tk.Y, expand=True)
		tk.Label(f_cal, text=ecudef.name).grid(row=0, column=0, columnspan=2, sticky=tk.W+tk.E)
		self.combo_maps = ttk.Combobox(f_cal, state="readonly", values = [m.name for m in self.tables])
		self.combo_maps.current(0)
		self.combo_maps.grid(row=1, column=0, columnspan=2, sticky=tk.W+tk.E)
		self.combo_maps.bind("<<ComboboxSelected>>", self.on_select)
		tk.Button(f_cal, text="Import", command=self.impcal).grid(row=2, column=0, sticky=tk.W+tk.E)
		tk.Button(f_cal, text="Export", command=self.expcal).grid(row=2, column=1, sticky=tk.W+tk.E)

		vcmd = (self.register(self.is_float))
		f_cur = tk.LabelFrame(f_ctrl, text="ECU Cursor (Red):")
		f_cur.grid_rowconfigure(0, uniform="ctrl")
		f_cur.grid_rowconfigure(1, uniform="ctrl")
		f_cur.grid_rowconfigure(2, uniform="ctrl")
		f_cur.pack(side=tk.LEFT, padx=4, fill=tk.Y, expand=True)
		self.combo_algo = ttk.Combobox(f_cur, state="readonly", values = ["By interpolation", "All 4 cells", "Only 1 cell"])
		self.combo_algo.current(0)
		self.combo_algo.grid(row=0, column=0, columnspan=2, sticky=tk.W+tk.E)
		tk.Label(f_cur, text="Value:").grid(row=1, column=0, sticky=tk.E)
		self.string_step_cur = tk.StringVar()
		tk.Entry(f_cur, width=4, textvariable=self.string_step_cur, validate='all', validatecommand=(vcmd, '%P')).grid(row=1, column=1, sticky=tk.W+tk.E)
		tk.Button(f_cur, text="Add (Key Q)", command=self.inc_cur).grid(row=2, column=0, sticky=tk.W+tk.E)
		tk.Button(f_cur, text="Sub (Key A)", command=self.dec_cur).grid(row=2, column=1, sticky=tk.W+tk.E)

		f_user = tk.LabelFrame(f_ctrl, text="User Selection (Blue):")
		f_user.grid_rowconfigure(0, uniform="ctrl")
		f_user.grid_rowconfigure(1, uniform="ctrl")
		f_user.grid_rowconfigure(2, uniform="ctrl")
		f_user.pack(side=tk.LEFT, padx=4, fill=tk.Y, expand=True)
		tk.Label(f_user, text="Value:").grid(row=0, column=0, sticky=tk.E)
		self.string_step_sel = tk.StringVar()
		tk.Entry(f_user, width=4, textvariable=self.string_step_sel, validate='all', validatecommand=(vcmd, '%P')).grid(row = 0, column = 1, sticky=tk.W+tk.E)
		tk.Button(f_user, text="Set (Key S)", command=self.set_sel).grid(row = 1, column = 0, columnspan=2, sticky=tk.W+tk.E)
		tk.Button(f_user, text="Add (Key +)", command=self.inc_sel).grid(row = 2, column = 0, sticky=tk.W+tk.E)
		tk.Button(f_user, text="Sub (Key -)", command=self.dec_sel).grid(row = 2, column = 1, sticky=tk.W+tk.E)

		f_action = tk.LabelFrame(f_ctrl, text="Special actions")
		f_action.pack(side=tk.LEFT, padx=4, fill=tk.Y, expand=True)
		self.force_ft0 = tk.IntVar()
		tk.Checkbutton(f_action, text='Force fuel trim to 0',variable=self.force_ft0).grid(row = 0, column = 0, sticky=tk.W)
		self.force_os0 = tk.IntVar()
		tk.Checkbutton(f_action, text='Force octane scaler to 0',variable=self.force_os0).grid(row = 1, column = 0, sticky=tk.W)
		self.log_stop = tk.IntVar()
		tk.Checkbutton(f_action, text='Pause CSV log',variable=self.log_stop).grid(row = 2, column = 0, sticky=tk.W)

		self.on_select(None)
		self.log_open()
		self.loop()
		self.wait_window()

	def on_select(self, event):
		current = self.combo_maps.current()
		for i in range(len(self.tables)):
			if(i == current):
				self.tables[i].pack()
			else:
				self.tables[i].pack_forget()
		self.table = self.tables[current]
		step = str(self.table.step)
		self.string_step_sel.set(step)
		self.string_step_cur.set(step)

	def is_float(self, P):
		for c in P:
			if not (c.isdigit() or c == '.'):
				return False
		return True

	def loop(self):
		self.ecudef.loop(self.force_ft0.get(), self.force_os0.get())
		self.table.update()
		for g in self.gauges: g.update()
		if not self.log_stop.get(): self.log_put()
		self.after(50, self.loop)

	@try_msgbox_decorator
	def impcal(self):
		answer = filedialog.askopenfilename(
			parent = self,
			initialdir = self.prefs['PATH']['bin'],
			initialfile = "calrom-tuner.bin",
			title = "Please select a file:",
			filetypes = bin_file
		)
		if(answer):
			self.prefs['PATH']['bin'] = os.path.dirname(answer)
			self.ecudef.impcal(answer)
			for t in self.tables: t.reload()

	@try_msgbox_decorator
	def expcal(self):
		answer = filedialog.asksaveasfilename(
			parent = self,
			initialdir = self.prefs['PATH']['bin'],
			initialfile = "calrom-tuner.bin",
			title = "Please select a file:",
			filetypes = bin_file
		)
		if(answer):
			self.prefs['PATH']['bin'] = os.path.dirname(answer)
			self.ecudef.expcal(answer)

	@try_msgbox_decorator
	def inc_cur(self):
		self.table.modify_cursor(+float(self.string_step_cur.get()), self.combo_algo.current())
	@try_msgbox_decorator
	def dec_cur(self):
		self.table.modify_cursor(-float(self.string_step_cur.get()), self.combo_algo.current())
	@try_msgbox_decorator
	def inc_sel(self):
		self.table.modify_selection(+float(self.string_step_sel.get()))
	@try_msgbox_decorator
	def dec_sel(self):
		self.table.modify_selection(-float(self.string_step_sel.get()))
	@try_msgbox_decorator
	def set_sel(self):
		self.table.modify_selection(float(self.string_step_sel.get()), False)
	def on_key_pressed(self, event):
		if  (event.char == 'q'): self.inc_cur()
		elif(event.char == 'a'): self.dec_cur()
		elif(event.char == '+'): self.inc_sel()
		elif(event.char == '-'): self.dec_sel()
		elif(event.char == 's'): self.set_sel()

	def log_open(self):
		now = datetime.now()
		filename = f"tuner-session-{now.strftime("%Y%m%d%H%M")}.csv"
		self.log_file = open(filename, "w", encoding="utf-8")
		self.log_file.write('Timestamp')
		for g in self.gauges: self.log_file.write(','+g.name)
		self.log_file.write('\n')

	def log_put(self):
		now = datetime.now()
		self.log_file.write(f"{now.strftime("%H:%M:%S")}.{(now.microsecond//1000):03d}")
		for g in self.gauges: self.log_file.write(','+str(g.data))
		self.log_file.write('\n')

	def log_close(self, event):
		self.log_file.close()
		self.destroy()

