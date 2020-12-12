#!/usr/bin/python3

import gi, os, threading
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GLib
from t4e import ECU_T4E
from flasher import Flasher

class ECU_T4E_GUI(ECU_T4E):
	def __init__(self):
		self.entry = Gtk.Entry()
		self.entry.set_editable(False)

	def log(self, msg):
		GLib.idle_add(self.entry.set_text, msg)

	def progress(self):
		self.bytes_transfered += 128
		fraction = self.bytes_transfered/self.bytes_total
		GLib.idle_add(self.entry.set_progress_fraction, fraction)

	def progress_end(self):
		GLib.idle_add(self.entry.set_progress_fraction, 1.0)

	def download(self, address, size, filename):
		GLib.idle_add(self.entry.set_progress_fraction, 0)
		self.bytes_total = size
		self.bytes_transfered = 0
		super().download(address, size, filename)

	def verify(self, address, filename):
		GLib.idle_add(self.entry.set_progress_fraction, 0)
		self.bytes_total = os.path.getsize(filename)
		self.bytes_transfered = 0
		super().verify(address, filename)

	def upload(self, address, filename):
		GLib.idle_add(self.entry.set_progress_fraction, 0)
		self.bytes_total = os.path.getsize(filename)
		self.bytes_transfered = 0
		super().upload(address, filename)

	def getProgressBar(self):
		return self.entry

class Flasher_GUI(Flasher):
	def __init__(self):
		self.entry = Gtk.Entry()
		self.entry.set_editable(False)

	def log(self, msg):
		GLib.idle_add(self.entry.set_text, msg)

	def progress(self):
		self.bytes_transfered += 4
		fraction = self.bytes_transfered/self.bytes_total
		GLib.idle_add(self.entry.set_progress_fraction, fraction)

	def progress_end(self):
		GLib.idle_add(self.entry.set_progress_fraction, 1.0)

	def verify(self, address, filename):
		GLib.idle_add(self.entry.set_progress_fraction, 0)
		self.bytes_total = os.path.getsize(filename)
		self.bytes_transfered = 0
		super().verify(address, filename)

	def program(self, address, filename):
		GLib.idle_add(self.entry.set_progress_fraction, 0)
		self.bytes_total = os.path.getsize(filename)
		self.bytes_transfered = 0
		super().upload(address, filename)

	def getProgressBar(self):
		return self.entry

class t4e_window(Gtk.Window):
	def __init__(self):
		Gtk.Window.__init__(self, title="T4e ECU")
		self.set_border_width(10)
		self.set_resizable(False);
		vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

		self.t4e = ECU_T4E_GUI()
		self.t4e.openCAN("can0")
		vbox1 = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
		vbox1.pack_start(self.t4e.getProgressBar(), True, True, 0)
		store_zones = Gtk.ListStore(str, int, int, str)
		for zone in ECU_T4E.zones:
			store_zones.append(zone)
		hbox1 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
		self.combo_zones = Gtk.ComboBox.new_with_model(store_zones)
		renderer_text = Gtk.CellRendererText()
		self.combo_zones.pack_start(renderer_text, True)
		self.combo_zones.add_attribute(renderer_text, "text", 0)
		self.combo_zones.set_active(1)
		hbox1.pack_start(self.combo_zones, True, True, 0)
		self.button_dl = Gtk.Button.new_with_label("Download")
		self.button_dl.connect("clicked", self.download)
		hbox1.pack_start(self.button_dl, True, True, 0)
		self.button_v = Gtk.Button.new_with_label("Verify")
		self.button_v.connect("clicked", self.verify)
		hbox1.pack_start(self.button_v, True, True, 0)
		vbox1.pack_start(hbox1, True, True, 0)
		self.button_ifp = Gtk.Button.new_with_label("Inject Flasher Program")
		self.button_ifp.connect("clicked", self.inject)
		vbox1.pack_start(self.button_ifp, True, True, 0)
		frame_t4e = Gtk.Frame(label="T4e ECU Communication (Safe)")
		frame_t4e.add(vbox1)
		vbox.add(frame_t4e)

		self.flasher = Flasher_GUI()
		#self.flasher.openCAN("can0")
		self.flasher.sock = self.t4e.sock
		vbox2 = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
		vbox2.pack_start(self.flasher.getProgressBar(), True, True, 0)
		store_blocks = Gtk.ListStore(str, int, int, int, str)
		for block in Flasher.blocks:
			store_blocks.append(block)
		hbox2 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
		self.combo_blocks = Gtk.ComboBox.new_with_model(store_blocks)
		renderer_text = Gtk.CellRendererText()
		self.combo_blocks.pack_start(renderer_text, True)
		self.combo_blocks.add_attribute(renderer_text, "text", 0)
		self.combo_blocks.set_active(1)
		hbox2.pack_start(self.combo_blocks, True, True, 0)
		self.button_e = Gtk.Button.new_with_label("Erase")
		self.button_e.connect("clicked", self.erase)
		hbox2.pack_start(self.button_e, True, True, 0)
		self.button_pg = Gtk.Button.new_with_label("Program")
		self.button_pg.connect("clicked", self.program)
		hbox2.pack_start(self.button_pg, True, True, 0)
		self.button_v2 = Gtk.Button.new_with_label("Verify")
		self.button_v2.connect("clicked", self.verify2)
		hbox2.pack_start(self.button_v2, True, True, 0)
		vbox2.pack_start(hbox2, True, True, 0)
		self.button_vfp = Gtk.Button.new_with_label("Verify Flasher Program")
		self.button_vfp.connect("clicked", self.inject_verify)
		vbox2.pack_start(self.button_vfp, True, True, 0)
		self.button_reset = Gtk.Button.new_with_label("Reset ECU")
		self.button_reset.connect("clicked", self.reset)
		vbox2.pack_start(self.button_reset, True, True, 0)
		frame_flasher = Gtk.Frame(label="CAN Flasher (Not Safe)")
		frame_flasher.add(vbox2)
		vbox.add(frame_flasher)
		self.flasher_buttons(False)

		self.add(vbox)

	def t4e_buttons(self, sensitive):
		self.button_dl.set_sensitive(sensitive)
		self.button_v.set_sensitive(sensitive)
		self.button_ifp.set_sensitive(sensitive)

	def flasher_buttons(self, sensitive):
		self.button_e.set_sensitive(sensitive)
		self.button_pg.set_sensitive(sensitive)
		self.button_v2.set_sensitive(sensitive)
		self.button_vfp.set_sensitive(sensitive)
		self.button_reset.set_sensitive(sensitive)

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

	def threaded_action(self, th_fnct, th_params, fnct_success, params_success, \
			fnct_failure, params_failure):
		try:
			th_fnct(*th_params)
			GLib.idle_add(fnct_success, *params_success)
		except Exception as e:
			GLib.idle_add(self.display_error, "Error!", str(e))
			GLib.idle_add(fnct_failure, *params_failure)

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
			self.t4e_buttons(False)
			threading.Thread(
				target=self.threaded_action,
				args=(
					self.t4e.download, (zone[1], zone[2], dialog.get_filename()),
					self.t4e_buttons, (True,),
					self.t4e_buttons, (True,)
				)
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
			self.t4e_buttons(False)
			threading.Thread(
				target=self.threaded_action,
				args=(
					self.t4e.verify, (zone[1], dialog.get_filename()),
					self.t4e_buttons, (True,),
					self.t4e_buttons, (True,)
				)
			).start()
		dialog.destroy()

	def inject(self, button):
		self.t4e_buttons(False)
		threading.Thread(
			target=self.threaded_action,
			args=(
				self.t4e.smart_inject, ("injection/flasher.bin",),
				self.flasher_buttons, (True,),
				self.t4e_buttons, (True,)
			)
		).start()

	def erase(self, button):
		blocks = self.combo_blocks.get_model()
		block = blocks[self.combo_blocks.get_active_iter()]
		self.flasher_buttons(False)
		threading.Thread(
			target=self.threaded_action,
			args=(
				self.flasher.eraseBlock, (block[1],),
				self.flasher_buttons, (True,),
				self.flasher_buttons, (True,)
			)
		).start()

	def program(self, button):
		blocks = self.combo_blocks.get_model()
		block = blocks[self.combo_blocks.get_active_iter()]
		dialog = Gtk.FileChooserDialog(
			title="Please choose a file",
			parent=self,
			action=Gtk.FileChooserAction.OPEN,
		)
		dialog.set_filename(block[4])
		dialog.add_buttons(
			Gtk.STOCK_CANCEL,
			Gtk.ResponseType.CANCEL,
			Gtk.STOCK_OPEN,
			Gtk.ResponseType.OK,
		)
		self.add_filters(dialog)
		response = dialog.run()
		if(response == Gtk.ResponseType.OK):
			self.flasher_buttons(False)
			threading.Thread(
				target=self.threaded_action,
				args=(
					self.flasher.program, (block[1], block[2], dialog.get_filename()),
					self.flasher_buttons, (True,),
					self.flasher_buttons, (True,)
				)
			).start()

	def verify2(self, button):
		blocks = self.combo_blocks.get_model()
		block = blocks[self.combo_blocks.get_active_iter()]
		dialog = Gtk.FileChooserDialog(
			title="Please choose a file",
			parent=self,
			action=Gtk.FileChooserAction.OPEN,
		)
		dialog.set_filename(block[4])
		dialog.add_buttons(
			Gtk.STOCK_CANCEL,
			Gtk.ResponseType.CANCEL,
			Gtk.STOCK_OPEN,
			Gtk.ResponseType.OK,
		)
		self.add_filters(dialog)
		response = dialog.run()
		if(response == Gtk.ResponseType.OK):
			self.flasher_buttons(False)
			threading.Thread(
				target=self.threaded_action,
				args=(
					self.flasher.verify, (block[2], dialog.get_filename()),
					self.flasher_buttons, (True,),
					self.flasher_buttons, (True,)
				)
			).start()
		dialog.destroy()

	def inject_verify(self, button):
		self.flasher_buttons(False)
		threading.Thread(
			target=self.threaded_action,
			args=(
				self.flasher.verify, (0x3FF000, "injection/flasher.bin"),
				self.flasher_buttons, (True,),
				self.flasher_buttons, (True,)
			)
		).start()

	def reset(self, button):
		self.flasher_buttons(False)
		threading.Thread(
			target=self.threaded_action,
			args=(
				self.flasher.resetECU, (),
				self.t4e_buttons, (True,),
				self.flasher_buttons, (True,)
			)
		).start()

win = t4e_window()
win.connect("destroy", Gtk.main_quit)
win.show_all()
Gtk.main()
