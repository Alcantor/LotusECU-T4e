#!/usr/bin/python3

import gi, os, threading
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GLib
from t4e import ECU_T4E

class ECU_T4E_GUI(ECU_T4E):
	def __init__(self):
		self.progressbar = Gtk.ProgressBar()
		self.statusbar = Gtk.Statusbar()
		self.sbcontext = self.statusbar.get_context_id("t4e")

	def log(self, msg):
		 GLib.idle_add(self.statusbar.push, self.sbcontext, msg)

	def progress(self):
		self.bytes_transfered += 128
		self.progressbar.set_fraction(self.bytes_transfered/self.bytes_total)

	def progress_end(self):
		self.statusbar.remove_all(self.sbcontext)

	def download(self, address, size, filename):
		self.bytes_total = size
		self.bytes_transfered = 0
		super().download(address, size, filename)

	def verify(self, address, filename):
		self.bytes_total = os.path.getsize(filename)
		self.bytes_transfered = 0
		super().verify(address, filename)

	def upload(self, address, filename):
		self.bytes_total = os.path.getsize(filename)
		self.bytes_transfered = 0
		super().upload(address, filename)

	def getProgressBar(self):
		return self.progressbar

	def getStatusBar(self):
		return self.statusbar

class t4e_window(Gtk.Window):
	def __init__(self):
		Gtk.Window.__init__(self, title="T4e ECU")
		self.set_border_width(10)
		self.set_resizable(False);

		self.t4e = ECU_T4E_GUI()
		self.t4e.openCAN("can0")

		vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
		self.add(vbox)

		vbox.pack_start(self.t4e.getProgressBar(), True, True, 0)

		button = Gtk.Button.new_with_label("Download Bootloader")
		button.connect("clicked", self.download, (0x000000, 0x10000, "bootldr.bin"))
		vbox.pack_start(button, True, True, 0)

		button = Gtk.Button.new_with_label("Download Calibration")
		button.connect("clicked", self.download, (0x010000, 0x10000, "calrom.bin"))
		vbox.pack_start(button, True, True, 0)

		button = Gtk.Button.new_with_label("Download Prog")
		button.connect("clicked", self.download, (0x020000, 0x60000, "prog.bin"))
		vbox.pack_start(button, True, True, 0)

		button = Gtk.Button.new_with_label("Download DecRAM")
		button.connect("clicked", self.download, (0x2F8000, 0x00800, "decram.bin"))
		vbox.pack_start(button, True, True, 0)

		button = Gtk.Button.new_with_label("Download CalRAM")
		button.connect("clicked", self.download, (0x3F8000, 0x08000, "calram.bin"))
		vbox.pack_start(button, True, True, 0)

		button = Gtk.Button.new_with_label("Inject Flasher")
		button.connect("clicked", self.inject)
		vbox.pack_start(button, True, True, 0)

		vbox.pack_start(self.t4e.getStatusBar(), True, True, 0)

	def display_error(self, title, msg):
		dialog = Gtk.MessageDialog(
			transient_for=self,
			flags=0,
			message_type=Gtk.MessageType.ERROR,
			buttons=Gtk.ButtonsType.OK,
			text=title
		)
		dialog.format_secondary_text(msg)
		dialog.run()
		dialog.destroy()

	def download_thread(self, address, size, filename):
		try:
			self.t4e.download(address, size, filename)
		except Exception as e:
			GLib.idle_add(self.display_error, "Failed to download", str(e))
			
	def download(self, button, userdata):
		dialog = Gtk.FileChooserDialog(
			title="Please choose a file",
			parent=self,
			action=Gtk.FileChooserAction.SAVE,
		)
		dialog.set_filename(userdata[2])
		dialog.set_do_overwrite_confirmation(True);
		dialog.add_buttons(
			Gtk.STOCK_CANCEL,
			Gtk.ResponseType.CANCEL,
			Gtk.STOCK_SAVE,
			Gtk.ResponseType.OK,
		)
		self.add_filters(dialog)
		response = dialog.run()
		if(response == Gtk.ResponseType.OK):
			threading.Thread(
				target=self.download_thread,
				args=(userdata[0], userdata[1], dialog.get_filename())
			).start()
		dialog.destroy()

	def add_filters(self, dialog):
		filter_bin = Gtk.FileFilter()
		filter_bin.set_name("BIN files")
		filter_bin.add_mime_type("application/octet-stream")
		dialog.add_filter(filter_bin)

	def inject_thread(self):
		try:
			self.t4e.inject(0x3FE748, "injection/deadloop.bin", 0x3F8000 + 0x7FDC)
		except Exception as e:
			GLib.idle_add(self.display_error, "Failed to inject", str(e))

	def inject(self, button):
		threading.Thread(
			target=self.inject_thread
		).start()

win = t4e_window()
win.connect("destroy", Gtk.main_quit)
win.show_all()
Gtk.main()
