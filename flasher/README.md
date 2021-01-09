# MPC Flasher

I've made a modular flasher, for the following reasons:

 - CANstrap should not receive too much update. It's annoying to reflash stage15.
 - Different CANstrap for white (1 Mb/s) and black (500 Kb/s) dashboard but the plugin remain the same.
 - EEPROM Flasher is bulky, so keep it separatly.

*Note: The plugin_eeprom only works when IO has been initialized by main program. It does not work with stage15 yet. The func_eeprom_init.S should make the initialization of the IO for the stage15 but it's a lot of work for a small detail.*
