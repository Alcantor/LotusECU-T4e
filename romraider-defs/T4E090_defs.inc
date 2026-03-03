<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!--
  Lotus T4e ECU RomRaider Definitions
  https://github.com/Alcantor/LotusECU-T4e

  Read the T4E090 Guide (T4E090_guide.pdf) before editing any table.
  It documents the full ECU signal path: load, fuel, ignition, knock,
  idle, VVT/VVL, closed-loop control, OBD, and live tuning access.

  Licensed under Creative Commons Attribution-NonCommercial-ShareAlike 4.0
  International (CC BY-NC-SA 4.0).
  https://creativecommons.org/licenses/by-nc-sa/4.0/
-->
<roms>
 <rom base="T4E090_NOMODEL">
  <romid>
   <xmlid>D120E0030H</xmlid>
   <market>ROW</market>
   <model>Elise 111R/Exige</model>
   <internalidaddress>0x3656</internalidaddress>
   <internalidstring>D120E0030H</internalidstring>
  </romid>
 </rom>
 <rom base="T4E090_NOMODEL">
  <romid>
   <xmlid>C131E6018H</xmlid>
   <market>EU</market>
   <model>Elise S</model>
   <internalidaddress>0x3656</internalidaddress>
   <internalidstring>C131E6018H</internalidstring>
  </romid>
 </rom>
 <rom base="T4E090_NOMODEL">
  <romid>
   <xmlid>C128E6010H</xmlid>
   <market>ROW</market>
   <model>Exige S</model>
   <internalidaddress>0x3656</internalidaddress>
   <internalidstring>C128E6010H</internalidstring>
  </romid>
 </rom>
 <rom base="T4E090_NOMODEL">
  <romid>
   <xmlid>F121E0010H</xmlid>
   <market>FED</market>
   <model>Elise/Exige</model>
   <internalidaddress>0x3656</internalidaddress>
   <internalidstring>F121E0010H</internalidstring>
  </romid>
 </rom>
 <rom base="T4E090_NOMODEL">
  <romid>
   <xmlid>D129E6004H</xmlid>
   <market>FED</market>
   <model>Exige S</model>
   <internalidaddress>0x3656</internalidaddress>
   <internalidstring>D129E6004H</internalidstring>
  </romid>
 </rom>
 <rom base="T4E090">
  <romid>
   <xmlid>T4E090_NOMODEL</xmlid>
   <submodel>2006-2007</submodel>
   <filesize>15508b</filesize>
  </romid>
  <table name="ecu: unlock magic" storageaddress="0x3C8E"/>
  <table name="ecu: CRC stored" storageaddress="0x3C92"/>
 </rom>
</roms>
