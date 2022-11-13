import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from threading import *

please_select_file = "Please select a file:"
bin_file = [("Raw binary file", "*.BIN *.bin *.cpt")]

def try_msgbox_decorator(func):
	def wrapper(self, *args, **kwargs):
		try:
			func(self, *args, **kwargs)
		except Exception as e:
			messagebox.showerror(
				parent = self,
				master = self,
				title = "Error!",
				message = str(e)
			)
	return wrapper

class SelectCAN_widget(tk.LabelFrame):
	def __init__(self, config, parent=None, with_speed=True):
		tk.LabelFrame.__init__(self, parent, text="CAN Device (CANable Adapter)")
		self.config = config

		self.combo_interface = ttk.Combobox(self, width=14, state="readonly", values=["slcan", "socketcan", "usb2can", "ixxat"])
		self.combo_interface.set(self.config['CANBUS']['interface'])
		self.combo_interface.pack(side=tk.LEFT)

		self.string_channel = tk.StringVar()
		self.string_channel.set(self.config['CANBUS']['channel'])
		self.entry_channel = tk.Entry(self, width=14, textvariable=self.string_channel)
		self.entry_channel.pack(side=tk.LEFT, fill=tk.X, expand=True)

		if(with_speed):
			self.combo_bitrate = ttk.Combobox(self, width=14, state="readonly", values=["white (1 Mb/s)", "black (500 kb/s)"])
			self.combo_bitrate.current(0)
			self.combo_bitrate.pack(side=tk.LEFT)

	def get_interface(self):
		interface = self.combo_interface.get()
		self.config['CANBUS']['interface'] = interface
		return interface

	def get_channel(self):
		channel = self.string_channel.get()
		self.config['CANBUS']['channel'] = channel
		return channel

	def get_bitrate(self):
		return [1000000, 500000][self.combo_bitrate.current()]

class SelectCOM_widget(tk.LabelFrame):
	def __init__(self, config, parent=None):
		tk.LabelFrame.__init__(self, parent, text="COM Device (VAG-COM Adapter)")
		self.config = config

		self.string_port = tk.StringVar()
		self.string_port.set(self.config['COM']['port'])
		self.entry_port = tk.Entry(self, width=14, textvariable=self.string_port)
		self.entry_port.pack(side=tk.LEFT, fill=tk.X, expand=True)

	def get_port(self):
		port = self.string_port.get()
		self.config['COM']['port'] = port
		return port

