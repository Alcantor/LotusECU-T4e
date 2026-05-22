  <table type="2D" name="sensor: oil temp scaling" category="sensor" storagetype="uint8" endian="big" sizex="33" userlevel="1" storageaddress="{CAL_sensor_oil_temp_scaling}">
   <scaling category="Degree Celsius" units="&#176;C" expression="(x*5/8)-40" to_byte="(x+40)*8/5" format="0.0" fineincrement="0.625" coarseincrement="2" />
   <table type="Static X Axis" name="signal" sizex="33">
    <data>0</data>
    <data>32</data>
    <data>64</data>
    <data>96</data>
    <data>128</data>
    <data>160</data>
    <data>192</data>
    <data>224</data>
    <data>256</data>
    <data>288</data>
    <data>320</data>
    <data>352</data>
    <data>384</data>
    <data>416</data>
    <data>448</data>
    <data>480</data>
    <data>512</data>
    <data>544</data>
    <data>576</data>
    <data>608</data>
    <data>640</data>
    <data>672</data>
    <data>704</data>
    <data>736</data>
    <data>768</data>
    <data>800</data>
    <data>832</data>
    <data>864</data>
    <data>896</data>
    <data>928</data>
    <data>960</data>
    <data>992</data>
    <data>1024</data>
    <scaling category="Volt" units="v" expression="x*5/1023" to_byte="x*1023/5" format="0.00" fineincrement="0.05" coarseincrement="0.2" />
   </table>
   <description>Scaling of the oil temperature sensor.</description>
  </table>
  <table type="2D" name="sensor: oil temperature reactivity" category="sensor" storagetype="uint8" endian="big" sizex="1" userlevel="1" storageaddress="{CAL_sensor_oil_temp_reactivity}">
   <scaling category="Percent" units="%" expression="x*100/256" to_byte="x*256/100" format="0.0" fineincrement="1" coarseincrement="5" />
   <table type="Static X Axis" name="" sizex="1">
    <data>oil temperature reactivity</data>
   </table>
   <description>At every cycle, the sampled oil temperature value is mixed with the previous value.

Formula: value = (100% - REACTIVITY) * previous + REACTIVITY * sample</description>
  </table>
  <table type="2D" name="sensor: oil pressure gain" category="sensor" storagetype="uint16" endian="big" sizex="1" userlevel="1" storageaddress="{CAL_sensor_oil_pressure_gain}">
   <scaling category="Millibar/5v" units="mbar/5volt" expression="x" to_byte="x" format="0" fineincrement="10" coarseincrement="50" />
   <table type="Static X Axis" name="" sizex="1">
    <data>oil pressure gain</data>
   </table>
   <description>Oil pressure sensor gain.</description>
  </table>
  <table type="2D" name="sensor: oil pressure offset" category="sensor" storagetype="int16" endian="big" sizex="1" userlevel="1" storageaddress="{CAL_sensor_oil_pressure_offset}">
   <scaling category="Millibar" units="mbar" expression="x" to_byte="x" format="0" fineincrement="10" coarseincrement="50" />
   <table type="Static X Axis" name="" sizex="1">
    <data>oil pressure offset</data>
   </table>
   <description>Oil pressure sensor offset.</description>
  </table>
  <table type="2D" name="sensor: oil pressure reactivity" category="sensor" storagetype="uint8" endian="big" sizex="1" userlevel="1" storageaddress="{CAL_sensor_oil_pressure_reactivity}">
   <scaling category="Percent" units="%" expression="x*100/256" to_byte="x*256/100" format="0.0" fineincrement="1" coarseincrement="5" />
   <table type="Static X Axis" name="" sizex="1">
    <data>oil pressure reactivity</data>
   </table>
   <description>At every cycle, the sampled oil pressure value is mixed with the previous value.

Formula: value = (100% - REACTIVITY) * previous + REACTIVITY * sample</description>
  </table>
  <table type="2D" name="obd: P0522 threshold" category="obd" storagetype="uint16" endian="big" sizex="1" userlevel="1" storageaddress="{CAL_obd_P0522_threshold}">
   <scaling category="Volt" units="v" expression="x*5/1023" to_byte="x*1023/5" format="0.00" fineincrement="0.05" coarseincrement="0.1" />
   <table type="Static X Axis" name="" sizex="1">
    <data>threshold</data>
   </table>
   <description>P0522: ADC voltage below this threshold triggers oil pressure sensor circuit low fault (sensor shorted to ground).</description>
  </table>
  <table type="2D" name="obd: P0523 threshold" category="obd" storagetype="uint16" endian="big" sizex="1" userlevel="1" storageaddress="{CAL_obd_P0523_threshold}">
   <scaling category="Volt" units="v" expression="x*5/1023" to_byte="x*1023/5" format="0.00" fineincrement="0.05" coarseincrement="0.1" />
   <table type="Static X Axis" name="" sizex="1">
    <data>threshold</data>
   </table>
   <description>P0523: ADC voltage above this threshold triggers oil pressure sensor circuit high fault (sensor shorted to 5V).</description>
  </table>
  <table category="obd" name="obd: P0522 config" sizey="1" storageaddress="{CAL_obd_P0522}" type="Switch" userlevel="1">
   <state data="00" name="Disabled"/>
   <state data="41" name="Type A (1-trip MIL)"/>
   <state data="51" name="Type A (1-trip MIL) + Freeze frame"/>
   <state data="42" name="Type B (2-trip MIL)"/>
   <state data="52" name="Type B (2-trip MIL) + Priority freeze frame (overwrite normal)"/>
   <state data="43" name="Type B (2-trip MIL)"/>
   <state data="53" name="Type B (2-trip MIL) + Freeze frame"/>
   <state data="44" name="Type A (1-trip blinking MIL)"/>
   <state data="54" name="Type A (1-trip blinking MIL) + Priority freeze frame (overwrite normal)"/>
   <description>P0522: Oil Pressure Sensor Circuit Low</description>
  </table>
  <table category="obd" name="obd: P0523 config" sizey="1" storageaddress="{CAL_obd_P0523}" type="Switch" userlevel="1">
   <state data="00" name="Disabled"/>
   <state data="41" name="Type A (1-trip MIL)"/>
   <state data="51" name="Type A (1-trip MIL) + Freeze frame"/>
   <state data="42" name="Type B (2-trip MIL)"/>
   <state data="52" name="Type B (2-trip MIL) + Priority freeze frame (overwrite normal)"/>
   <state data="43" name="Type B (2-trip MIL)"/>
   <state data="53" name="Type B (2-trip MIL) + Freeze frame"/>
   <state data="44" name="Type A (1-trip blinking MIL)"/>
   <state data="54" name="Type A (1-trip blinking MIL) + Priority freeze frame (overwrite normal)"/>
   <description>P0523: Oil Pressure Sensor Circuit High</description>
  </table>

