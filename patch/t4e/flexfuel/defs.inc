  <table type="2D" name="sensor: ethanol temp reactivity" category="sensor" storagetype="uint8" endian="big" sizex="1" userlevel="1" storageaddress="{CAL_sensor_ethanol_temp_reactivity}">
   <scaling category="Percent" units="%" expression="x*100/256" to_byte="x*256/100" format="0.0" fineincrement="1" coarseincrement="5" />
   <table type="Static X Axis" name="" sizex="1">
    <data>reactivity</data>
   </table>
   <description>Sensivity of the fuel temperature sensor.</description>
  </table>
  <table type="2D" name="sensor: ethanol content reactivity" category="sensor" storagetype="uint8" endian="big" sizex="1" userlevel="1" storageaddress="{CAL_sensor_ethanol_content_reactivity}">
   <scaling category="Percent" units="%" expression="x*100/256" to_byte="x*256/100" format="0.0" fineincrement="1" coarseincrement="5" />
   <table type="Static X Axis" name="" sizex="1">
    <data>reactivity</data>
   </table>
   <description>Sensivity of the fuel ethanol content sensor.</description>
  </table>
  <table type="2D" name="sensor: ethanol engine speed limit" category="sensor" storagetype="uint8" endian="big" sizex="1" userlevel="1" storageaddress="{CAL_sensor_ethanol_engine_speed_limit}">
   <scaling category="RPM" units="rpm" expression="(x*125/4)+500" to_byte="(x-500)*4/125" format="0" fineincrement="32" coarseincrement="100" />
   <table type="Static X Axis" name="" sizex="1">
    <data>engine speed limit</data>
   </table>
   <description>When the engine is above this speed limit, stop reading the flexfuel sensor.</description>
  </table>
  <table type="2D" name="sensor: ethanol engine load limit" category="sensor" storagetype="uint8" endian="big" sizex="1" userlevel="1" storageaddress="{CAL_sensor_ethanol_engine_load_limit}">
   <scaling category="Milligram/Stroke" units="mg/stroke" expression="x*4" to_byte="x/4" format="0" fineincrement="4" coarseincrement="20" />
   <table type="Static X Axis" name="" sizex="1">
    <data>engine load limit</data>
   </table>
   <description>When the engine is above this load limit, stop reading the flexfuel sensor.</description>
  </table>
  <table type="2D" name="sensor: ethanol temp fallback" category="sensor" storagetype="uint8" endian="big" sizex="1" userlevel="1" storageaddress="{CAL_sensor_ethanol_temp_fallback}">
   <scaling category="Degree Celsius" units="&#176;C" expression="(x*5/8)-40" to_byte="(x+40)*8/5" format="0.0" fineincrement="0.625" coarseincrement="2" />
   <table type="Static X Axis" name="" sizex="1">
    <data>fallback</data>
   </table>
   <description>Initial fuel temperature value used at startup before the sensor produces a valid reading.</description>
  </table>
  <table type="2D" name="sensor: ethanol content fallback" category="sensor" storagetype="uint8" endian="big" sizex="1" userlevel="1" storageaddress="{CAL_sensor_ethanol_content_fallback}">
   <scaling category="Percent" units="%" expression="x*100/255" to_byte="x*255/100" format="0.0" fineincrement="1" coarseincrement="5" />
   <table type="Static X Axis" name="" sizex="1">
    <data>fallback</data>
   </table>
   <description>Initial ethanol content value used at startup before the sensor produces a valid reading.</description>
  </table>
  <table type="2D" name="ethanol: ign adv adj1" category="ethanol" storagetype="uint8" endian="big" sizex="16" userlevel="1" storageaddress="{CAL_ethanol_ign_adv_adj1}">
   <scaling category="Degree" units="&#176;" expression="(x/4)-32" to_byte="(x+32)*4" format="0.00" fineincrement="0.25" coarseincrement="1.0" />
   <table type="X Axis" name="engine air" storagetype="uint8" endian="big" sizex="16" storageaddress="0x075C">
    <scaling category="Degree Celsius" units="&#176;C" expression="(x*5/8)-40" to_byte="(x+40)*8/5" format="0.0" fineincrement="0.625" coarseincrement="2" />
   </table>
   <description>See "ign: adv adj1" map. For 85% ethanol or defined by scale 1. Do NOT edit Axis.</description>
  </table>
  <table type="3D" name="ethanol: ign adv high cam base" category="ethanol" storagetype="uint8" endian="big" sizex="8" sizey="8" userlevel="1" storageaddress="{CAL_ethanol_ign_adv_high_cam_base}">
   <scaling category="Degree" units="&#176;" expression="(x/4)-10" to_byte="(x+10)*4" format="0.00" fineincrement="0.25" coarseincrement="1.0" />
   <table type="X Axis" name="engine speed" storagetype="uint8" endian="big" sizex="8" storageaddress="0x0A24">
    <scaling category="RPM" units="rpm" expression="(x*125/4)+500" to_byte="(x-500)*4/125" format="0" fineincrement="32" coarseincrement="100" />
   </table>
   <table type="Y Axis" name="engine load" storagetype="uint8" endian="big" sizey="8" storageaddress="0x0A2C">
    <scaling category="Milligram/Stroke" units="mg/stroke" expression="x*4" to_byte="x/4" format="0" fineincrement="4" coarseincrement="20" />
   </table>
   <description>See "ign: adv high cam base" map. For 40% ethanol or defined by scale 2. Do NOT edit Axis.</description>
  </table>
  <table type="2D" name="ethanol: injtip in adj1" category="ethanol" storagetype="uint8" endian="big" sizex="16" userlevel="1" storageaddress="{CAL_ethanol_injtip_in_adj1}">
   <scaling category="Percent" units="%" expression="x*100/128" to_byte="x*128/100" format="0" fineincrement="1" coarseincrement="5" />
   <table type="X Axis" name="engine speed" storagetype="uint8" endian="big" sizex="16" storageaddress="0x08F4">
    <scaling category="RPM" units="rpm" expression="(x*125/4)+500" to_byte="(x-500)*4/125" format="0" fineincrement="32" coarseincrement="100" />
   </table>
   <description>See "injtip: in adj1" map. For 85% ethanol or defined by scale 1. Do NOT edit Axis.</description>
  </table>
  <table type="2D" name="ethanol: injtip out adj1" category="ethanol" storagetype="uint8" endian="big" sizex="16" userlevel="1" storageaddress="{CAL_ethanol_injtip_out_adj1}">
   <scaling category="Percent" units="%" expression="x*100/128" to_byte="x*128/100" format="0" fineincrement="1" coarseincrement="5" />
   <table type="X Axis" name="engine speed" storagetype="uint8" endian="big" sizex="16" storageaddress="0x0954">
    <scaling category="RPM" units="rpm" expression="(x*125/4)+500" to_byte="(x-500)*4/125" format="0" fineincrement="32" coarseincrement="100" />
   </table>
   <description>See "injtip: out adj1" map. For 85% ethanol or defined by scale 1. Do NOT edit Axis.</description>
  </table>
  <table type="3D" name="ethanol: inj efficiency" category="ethanol" storagetype="uint8" endian="big" sizex="32" sizey="32" userlevel="1" storageaddress="{CAL_ethanol_inj_efficiency}">
   <scaling category="Percent" units="%" expression="x*100/200" to_byte="x*200/100" format="0.0" fineincrement="1" coarseincrement="5" />
   <table type="X Axis" name="engine speed" storagetype="uint8" endian="big" sizex="32" storageaddress="0x0BB4">
    <scaling category="RPM" units="rpm" expression="(x*125/4)+500" to_byte="(x-500)*4/125" format="0" fineincrement="32" coarseincrement="100" />
   </table>
   <table type="Y Axis" name="engine load" storagetype="uint8" endian="big" sizey="32" storageaddress="0x0BD4">
    <scaling category="Milligram/Stroke" units="mg/stroke" expression="x*4" to_byte="x/4" format="0" fineincrement="4" coarseincrement="20" />
   </table>
   <description>See: "inj: efficiency" map. For 85% ethanol or defined by scale 1. Do NOT edit Axis.</description>
  </table>
  <table type="3D" name="ethanol: inj time adj3" category="ethanol" storagetype="uint8" endian="big" sizex="16" sizey="16" userlevel="1" storageaddress="{CAL_ethanol_inj_time_adj3}">
   <scaling category="Percent" units="%" expression="x*100/64" to_byte="x*64/100" format="0" fineincrement="1" coarseincrement="5" />
   <table type="X Axis" name="engine load" storagetype="uint8" endian="big" sizex="16" storageaddress="0x11B4">
    <scaling category="Milligram/Stroke" units="mg/stroke" expression="x*4" to_byte="x/4" format="0" fineincrement="4" coarseincrement="20" />
   </table>
   <table type="Y Axis" name="coolant" storagetype="uint8" endian="big" sizey="16" storageaddress="0x11C4">
    <scaling category="Degree Celsius" units="&#176;C" expression="(x*5/8)-40" to_byte="(x+40)*8/5" format="0.0" fineincrement="0.625" coarseincrement="2" />
   </table>
   <description>See: "inj: time adj3" map. For 85% ethanol or defined by scale 1. Do NOT edit Axis.</description>
  </table>
  <table type="2D" name="ethanol: inj time adj cranking" category="ethanol" storagetype="uint8" endian="big" sizex="16" userlevel="1" storageaddress="{CAL_ethanol_inj_time_adj_cranking}">
   <scaling category="Millisecond" units="ms" expression="x*256/1000" to_byte="x*1000/256" format="0.0" fineincrement="0.2" coarseincrement="1" />
   <table type="X Axis" name="coolant" storagetype="uint8" endian="big" sizex="16" storageaddress="0x14C4">
    <scaling category="Degree Celsius" units="&#176;C" expression="(x*5/8)-40" to_byte="(x+40)*8/5" format="0.0" fineincrement="0.625" coarseincrement="2" />
   </table>
   <description>See: "inj: time adj cranking" map. For 85% ethanol or defined by scale 1. Do NOT edit Axis.</description>
  </table>
  <table type="3D" name="ethanol: ign adv low cam base" category="ethanol" storagetype="uint8" endian="big" sizex="32" sizey="32" userlevel="1" storageaddress="{CAL_ethanol_ign_adv_low_cam_base}">
   <scaling category="Degree" units="&#176;" expression="(x/4)-10" to_byte="(x+10)*4" format="0.00" fineincrement="0.25" coarseincrement="1.0" />
   <table type="X Axis" name="engine speed" storagetype="uint8" endian="big" sizex="32" storageaddress="0x1A3C">
    <scaling category="RPM" units="rpm" expression="(x*125/4)+500" to_byte="(x-500)*4/125" format="0" fineincrement="32" coarseincrement="100" />
   </table>
   <table type="Y Axis" name="engine load" storagetype="uint8" endian="big" sizey="32" storageaddress="0x1A5C">
    <scaling category="Milligram/Stroke" units="mg/stroke" expression="x*4" to_byte="x/4" format="0" fineincrement="4" coarseincrement="20" />
   </table>
   <description>See: "ign: adv low cam base" map. For 40% ethanol or defined by scale 2. Do NOT edit Axis.</description>
  </table>
  <table type="2D" name="ethanol: scale 1" category="ethanol" storagetype="uint8" endian="big" sizex="2" userlevel="1" storageaddress="{CAL_ethanol_scale_1_low}">
   <scaling category="Percent" units="%" expression="x*100/255" to_byte="x*255/100" format="0.0" fineincrement="1" coarseincrement="5" />
   <table type="Static X Axis" name="" sizex="2">
    <data>Low</data>
    <data>High</data>
   </table>
   <description>This defines the ethanol content for which a table is applicable. If you change this value, you need to rework the all tables using the scale 1.</description>
  </table>
  <table type="2D" name="ethanol: scale 2" category="ethanol" storagetype="uint8" endian="big" sizex="2" userlevel="1" storageaddress="{CAL_ethanol_scale_2_low}">
   <scaling category="Percent" units="%" expression="x*100/255" to_byte="x*255/100" format="0.0" fineincrement="1" coarseincrement="5" />
   <table type="Static X Axis" name="" sizex="2">
    <data>Low</data>
    <data>High</data>
   </table>
   <description>This defines the ethanol content for which a table is applicable. If you change this value, you need to rework the all tables using the scale 2.</description>
  </table>
  <table category="obd" name="obd: P0176 config" sizey="1" storageaddress="{CAL_obd_P0176}" type="Switch" userlevel="1">
   <state data="00" name="Disabled"/>
   <state data="41" name="Type A (1-trip MIL)"/>
   <state data="51" name="Type A (1-trip MIL) + Freeze frame"/>
   <state data="42" name="Type B (2-trip MIL)"/>
   <state data="52" name="Type B (2-trip MIL) + Priority freeze frame (overwrite normal)"/>
   <state data="43" name="Type B (2-trip MIL)"/>
   <state data="53" name="Type B (2-trip MIL) + Freeze frame"/>
   <state data="44" name="Type A (1-trip blinking MIL)"/>
   <state data="54" name="Type A (1-trip blinking MIL) + Priority freeze frame (overwrite normal)"/>
   <description>P0176: Fuel Composition Sensor Circuit (no signal)</description>
  </table>
  <table category="obd" name="obd: P0177 config" sizey="1" storageaddress="{CAL_obd_P0177}" type="Switch" userlevel="1">
   <state data="00" name="Disabled"/>
   <state data="41" name="Type A (1-trip MIL)"/>
   <state data="51" name="Type A (1-trip MIL) + Freeze frame"/>
   <state data="42" name="Type B (2-trip MIL)"/>
   <state data="52" name="Type B (2-trip MIL) + Priority freeze frame (overwrite normal)"/>
   <state data="43" name="Type B (2-trip MIL)"/>
   <state data="53" name="Type B (2-trip MIL) + Freeze frame"/>
   <state data="44" name="Type A (1-trip blinking MIL)"/>
   <state data="54" name="Type A (1-trip blinking MIL) + Priority freeze frame (overwrite normal)"/>
   <description>P0177: Fuel Composition Sensor Range/Performance (frequency >= 170 Hz)</description>
  </table>

