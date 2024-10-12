import colorsys
import tkinter as tk
from tkinter import ttk

def hls_to_hex(h,l,s):
	r, g, b = [int(x * 255) for x in colorsys.hls_to_rgb(h,l,s)]
	return f'#{r:02X}{g:02X}{b:02X}'

class MapTable(tk.Canvas):
	CELLW=32
	CELLH=16

	def __init__(self, parent, xname, read_xdata, yname, read_ydata, name, read_data, write_cell=lambda x,y,value:None, xfmt="{:d}", yfmt="{:d}", datafmt="{:d}"):
		self.xdata = read_xdata()
		self.ydata = read_ydata()
		self.data = read_data()
		self.xsize=len(self.xdata)
		self.ysize=len(self.ydata)
		tk.Canvas.__init__(self, parent, width=(self.xsize+1)*self.CELLW, height=(self.ysize+1)*self.CELLH)
		self.create_line(0, 0, self.CELLW, self.CELLH)
		self.create_text(self.CELLW, 2, anchor=tk.NE, justify=tk.RIGHT, text=xname, font=('Helvetica 6'))
		self.create_text(2, self.CELLH, anchor=tk.SW, text=yname,  font=('Helvetica 6'))
		self.xaxis = [self.create_text(self.CELLW*(x+1)+self.CELLW/2, 4, anchor=tk.N, justify=tk.CENTER, text=xfmt.format(self.xdata[x]), font=('Helvetica 8')) for x in range(0,self.xsize)]
		self.yaxis = [self.create_text(self.CELLW/2, self.CELLH*(y+1)+4, anchor=tk.N, justify=tk.CENTER, text=yfmt.format(self.ydata[y]), font=('Helvetica 8')) for y in range(0,self.ysize)]
		self.cells = [[[None] * 2 for _ in range(self.xsize)] for _ in range(self.ysize)]
		for y in range(0,self.ysize):
			for x in range(0,self.xsize):
				px=self.CELLW*(x+1)
				py=self.CELLH*(y+1)
				self.cells[y][x][0] = self.create_rectangle(px+1, py+1, px+self.CELLW-1, py+self.CELLH-1, fill='white', outline='#AAAAAA', width=2)
				self.cells[y][x][1] = self.create_text(px+self.CELLW-3, py+4, anchor=tk.NE, justify=tk.RIGHT, text=datafmt.format(self.data[y][x]), font=('Helvetica 8 bold'))
		self.read_xdata = read_xdata
		self.read_ydata = read_ydata
		self.read_data = read_data
		self.xfmt = xfmt
		self.yfmt = yfmt
		self.datafmt = datafmt
		self.interpolation = (0, 0, 0, 0, ((1.0, 0.0),(0.0, 0.0)), 0.0)
		self.cursor = ()
		self.selection = [0, 0, 0, 0, None, False]
		self.write_cell = write_cell
		self.bind("<Button-1>", self.on_left_click)
		self.bind("<Button-3>", self.on_right_click)
		self.bind('<Motion>', self.on_motion)
		self.bind('<ButtonRelease>', self.on_release)

	def reload(self):
		self.xdata = self.read_xdata()
		self.ydata = self.read_ydata()
		self.data = self.read_data()
		for x in range(0,self.xsize):
			self.itemconfigure(self.xaxis[x], text=self.xfmt.format(self.xdata[x]))
		for y in range(0,self.ysize):
			self.itemconfigure(self.yaxis[y], text=self.yfmt.format(self.ydata[y]))
		for y in range(0,self.ysize):
			for x in range(0,self.xsize):
				self.itemconfigure(self.cells[y][x][1], text=self.datafmt.format(self.data[y][x]))

	def color_cells(self):
		min = max = self.data[0][0]
		for y in range(0,self.ysize):
			for x in range(0,self.xsize):
				if(self.data[y][x] < min): min = self.data[y][x]
				if(self.data[y][x] > max): max = self.data[y][x]
		q = (max-min)/0.7
		if(q == 0): return # No coloration if all cells are identical.
		for y in range(0,self.ysize):
			for x in range(0,self.xsize):
				self.itemconfigure(self.cells[y][x][0], fill=hls_to_hex(0.7-((self.data[y][x]-min)/q), 0.8, 0.5))
		# Interpolation coloration
		#cx, cy, x2r, y2r, m, res = self.interpolation
		#for y in range(0,2):
		#	for x in range(0,2):
		#		# Avoid index out of bound, by checking m !
		#		if(m[y][x] != 0.0):
		#			self.itemconfigure(self.cells[cy+y][cx+x][0], fill=hls_to_hex(0.7-((self.data[y][x]-min)/q), 0.8-m[y][x]/2, 0.5))

	def draw_cursor(self):
		for i in self.cursor: self.delete(i)
		cx, cy, x2r, y2r, m, res = self.interpolation
		px=self.CELLW*(cx+1)
		py=self.CELLH*(cy+1)
		px2=px+self.CELLW*(x2r+0.5)
		py2=py+self.CELLH*(y2r+0.5)
		width=self.CELLW*min(self.xsize-cx, 2)
		heigth=self.CELLH*min(self.ysize-cy, 2)
		self.cursor = (
			self.create_rectangle(px, py, px+width, py+heigth, outline='red', width=4),
			self.create_line(px2, self.CELLH, px2, py, fill="red", width=2),
			self.create_line(self.CELLW, py2, px, py2, fill="red", width=2),
			self.create_line(px2, py+heigth, px2, (self.ysize+1)*self.CELLH, fill="red", width=2),
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

	def do_interpolation(self, xvalue, yvalue):
		# Find X and Y cell
		cx = cy = 0
		while(cx+1 < self.xsize and self.xdata[cx] == self.xdata[cx+1]):
			cx = cx + 1;
		for x in range(cx,self.xsize):
			if(xvalue >= self.xdata[x]): cx = x
			else: break
		while(cy+1 < self.ysize and self.ydata[cy] == self.ydata[cy+1]):
			cy = cy + 1;
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
		for y in range(0, 2):
			for x in range(0, 2):
				# Avoid index out of bound, by checking m !
				if(m[y][x] != 0.0):
					res += self.data[cy+y][cx+x]*m[y][x]

		# Save all
		self.interpolation = (cx, cy, x2r, y2r, m, res)

	def modify_cell(self, x, y, value):
		if(x < self.xsize and y < self.ysize):
			self.data[y][x] += value
			self.itemconfigure(self.cells[y][x][1],
				text=self.datafmt.format(self.data[y][x]))
			self.write_cell(x,y,self.data[y][x])

	def modify_cursor(self, value, algo=0):
		cx, cy, x2r, y2r, m, res = self.interpolation
		if(algo == 0):
			for y in range(0, 2):
				for x in range(0, 2):
					self.modify_cell(cx+x, cy+y, value*m[y][x])
		elif(algo == 1):
			for y in range(0, 2):
				for x in range(0, 2):
					self.modify_cell(cx+x, cy+y, value)
		elif(algo == 2):
			max_value = 0
			mx = my = 0
			for y in range(0, 2):
				for x in range(0, 2):
					if(m[y][x] > max_value):
						max_value = m[y][x]
						mx, my = x, y
			self.modify_cell(cx+mx, cy+my, value)
		self.color_cells()

	def modify_selection(self, value):
		for y in range(self.selection[1], self.selection[3]):
			for x in range(self.selection[0], self.selection[2]):
				self.modify_cell(x, y, value)
		self.color_cells()

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

class MapTableEditor(tk.Frame):
	def __init__(self, parent, xname, read_xdata, get_xvalue, yname, read_ydata, get_yvalue, name, read_data, write_cell=lambda x,y,value:None, xfmt="{:d}", yfmt="{:d}", datafmt="{:d}", step=1.0):
		tk.Frame.__init__(self, parent)
		vcmd = (self.register(self.is_float))
		frame = tk.Frame(self)
		frame.pack(fill=tk.X, anchor=tk.N)
		frame_cur = tk.LabelFrame(frame, text="ECU Cursor")
		frame_cur.pack(side=tk.LEFT)
		self.combo_algo = ttk.Combobox(frame_cur, state="readonly", values = ["By interpolation", "All 4 cells", "Only 1 cell"])
		self.combo_algo.current(0)
		self.combo_algo.pack(side=tk.LEFT)
		self.string_step_cur = tk.StringVar()
		self.string_step_cur.set(str(step))
		tk.Entry(frame_cur, width=4, textvariable=self.string_step_cur, validate='all', validatecommand=(vcmd, '%P')).pack(side=tk.LEFT)
		tk.Button(frame_cur, text="Add (Key Q)", command=self.inc_cur).pack(side=tk.LEFT)
		tk.Button(frame_cur, text="Sub (Key A)", command=self.dec_cur).pack(side=tk.LEFT)
		frame_sel = tk.LabelFrame(frame, text="User Selection")
		frame_sel.pack(side=tk.RIGHT)
		self.string_step_sel = tk.StringVar()
		self.string_step_sel.set(str(step))
		tk.Entry(frame_sel, width=4, textvariable=self.string_step_sel, validate='all', validatecommand=(vcmd, '%P')).pack(side=tk.LEFT)
		tk.Button(frame_sel, text="Add (Key +)", command=self.inc_sel).pack(side=tk.LEFT)
		tk.Button(frame_sel, text="Sub (Key -)", command=self.dec_sel).pack(side=tk.LEFT)
		self.table = MapTable(self, xname, read_xdata, yname, read_ydata, name, read_data, write_cell, xfmt, yfmt, datafmt)
		self.get_xvalue = get_xvalue
		self.get_yvalue = get_yvalue
		self.table.color_cells()
		self.table.pack(anchor=tk.N)
	def is_float(self, P):
		for c in P:
			if not (c.isdigit() or c == '.'):
				return False
		return True
	def inc_cur(self):
		self.table.modify_cursor(+float(self.string_step_cur.get()), self.combo_algo.current())
	def dec_cur(self):
		self.table.modify_cursor(-float(self.string_step_cur.get()), self.combo_algo.current())
	def inc_sel(self):
		self.table.modify_selection(+float(self.string_step_sel.get()))
	def dec_sel(self):
		self.table.modify_selection(-float(self.string_step_sel.get()))
	def update(self):
		self.table.do_interpolation(self.get_xvalue(), self.get_yvalue())
		self.table.draw_cursor()
		self.table.draw_selection()
	def reload(self):
		self.table.reload()
		self.table.color_cells()

class SimpleGauge(tk.Canvas):
	def __init__(self, parent, name, read_data, fmt="{:d}", low=0, high=100):
		tk.Canvas.__init__(self, parent, width=180, height=30)
		self.create_rectangle(1, 1, 180, 30, fill="white", outline="black", width=1)
		self.colorbar = self.create_rectangle(3, 20, 179, 29, fill="red", width=0)
		self.create_text(3, 3, anchor=tk.NW, justify=tk.LEFT, text=name, font=('Helvetica 8'))
		self.value = self.create_text(178, 30, anchor=tk.SE, justify=tk.RIGHT, text="---", font=('Helvetica 16'))
		self.read_data = read_data
		self.fmt = fmt
		self.low = low
		self.high = high
	def update(self):
		v = self.read_data()
		self.itemconfigure(self.value, text=self.fmt.format(v))
		ratio = min((v-self.low)/(self.high-self.low), 1.0)
		self.coords(self.colorbar, 3, 20, 179*ratio, 29)
		self.itemconfigure(self.colorbar, fill=hls_to_hex(0.7-(0.7*ratio), 0.5, 1.0))

class test_window():
	def __init__(self, master):
		self.master = master
		master.title('Map Test')
		master.resizable(0, 0)

		data = lambda: [[x for x in range(32)]]
		m = MapTable(master, "rpm", lambda: [(i+1)*250 for i in range(0, 32)], "load", lambda: [0], "test", data)
		m.do_interpolation(4100,305)
		m.draw_cursor()
		m.color_cells()
		m.pack()

		data = lambda: [[y] for y in range(8)]
		m = MapTable(master, "rpm", lambda: [0], "load", lambda: [(i+1)*80 for i in range(0, 8)], "test", data)
		m.do_interpolation(4100,305)
		m.draw_cursor()
		m.color_cells()
		m.pack()

		data = lambda: [[x*y for x in range(32)] for y in range(32)]
		m = MapTable(master, "rpm", lambda: [(i+1)*250 for i in range(0, 32)], "load", lambda: [(i+1)*20 for i in range(0, 32)], "test", data)
		m.do_interpolation(4100,305)
		m.draw_cursor()
		m.color_cells()
		m.pack()

if __name__ == "__main__":
	root = tk.Tk()
	test_window(root)
	root.mainloop()

