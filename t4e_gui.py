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

		store_zones = Gtk.ListStore(str, int, int, str)
		for zone in ECU_T4E.zones:
			store_zones.append(zone)

		hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
		vbox.pack_start(hbox, True, True, 0)

		self.combo_zones = Gtk.ComboBox.new_with_model(store_zones)
		renderer_text = Gtk.CellRendererText()
		self.combo_zones.pack_start(renderer_text, True)
		self.combo_zones.add_attribute(renderer_text, "text", 0)
		self.combo_zones.set_active(1)
		hbox.pack_start(self.combo_zones, True, True, 0)

		button = Gtk.Button.new_with_label("Download")
		button.connect("clicked", self.download)
		hbox.pack_start(button, True, True, 0)

		button = Gtk.Button.new_with_label("Verify")
		button.connect("clicked", self.verify)
		hbox.pack_start(button, True, True, 0)

		button = Gtk.Button.new_with_label("Inject Flasher Program")
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

	def threaded_action(self, fnct, params):
		try:
			fnct(*params)
		except Exception as e:
			GLib.idle_add(self.display_error, "Error!", str(e))

	def add_filters(self, dialog):
		filter_bin = Gtk.FileFilter()
		filter_bin.set_name("BIN files")
		filter_bin.add_mime_type("application/octet-stream")
		dialog.add_filter(filter_bin)

	def download(self, button):
		zones = self.combo_zones.get_model()
		zone = zones[self.combo_zones.get_active_iter()]
		dialog = Gtk.FileChooserDialog(
			title="Please choose a file",
			parent=self,
			action=Gtk.FileChooserAction.SAVE,
		)
		dialog.set_filename(zone[3])
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
				target=self.threaded_action,
				args=(self.t4e.download, (zone[1], zone[2], dialog.get_filename()))
			).start()
		dialog.destroy()

	def verify(self, button):
		zones = self.combo_zones.get_model()
		zone = zones[self.combo_zones.get_active_iter()]
		dialog = Gtk.FileChooserDialog(
			title="Please choose a file",
			parent=self,
			action=Gtk.FileChooserAction.OPEN,
		)
		dialog.set_filename(zone[3])
		dialog.add_buttons(
			Gtk.STOCK_CANCEL,
			Gtk.ResponseType.CANCEL,
			Gtk.STOCK_OPEN,
			Gtk.ResponseType.OK,
		)
		self.add_filters(dialog)
		response = dialog.run()
		if(response == Gtk.ResponseType.OK):
			threading.Thread(
				target=self.threaded_action,
				args=(self.t4e.verify, (zone[1], dialog.get_filename()))
			).start()
		dialog.destroy()

	def inject(self, button):
		threading.Thread(
			target=self.threaded_action,
			args=(self.t4e.inject, (0x3FE748, "injection/deadloop.bin", 0x3FFFDC))
		).start()

win = t4e_window()
win.connect("destroy", Gtk.main_quit)
win.show_all()
Gtk.main()
