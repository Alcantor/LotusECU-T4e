  <table type="2D" name="accusump: open threshold" category="accusump" storagetype="uint8" endian="big" sizex="4" userlevel="1" storageaddress="{CAL_accusump}">
   <scaling category="Bar" units="bar" expression="x*32/1000" to_byte="x*1000/32" format="0.0" fineincrement="0.1" coarseincrement="1" />
   <table type="X Axis" name="engine speed" storagetype="uint8" endian="big" sizex="4" storageaddress="{CAL_accusump_X_engine_speed}">
    <scaling category="RPM" units="rpm" expression="(x*125/4)+500" to_byte="(x-500)*4/125" format="0" fineincrement="32" coarseincrement="100" />
   </table>
   <description>When the oil drop below this pressure threshold, open the accusump.</description>
  </table>
  <table type="2D" name="accusump: maximum open time" category="accusump" storagetype="uint8" endian="big" sizex="1" userlevel="1" storageaddress="{CAL_accusump_max_open_time}">
   <scaling category="Second" units="s" expression="x" to_byte="x" format="0" fineincrement="1" coarseincrement="5" />
   <table type="Static X Axis" name="" sizex="1">
    <data>Maximum open time</data>
   </table>
   <description>Close the accusump after this delay to protected to coil from overheating.</description>
  </table>

