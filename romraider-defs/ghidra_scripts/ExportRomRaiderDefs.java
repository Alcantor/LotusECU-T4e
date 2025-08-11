//@category Symbol
//@menupath Tools.Export.RomRaider
//@description Export user-defined CAL_/LEA_ symbols to an XML file that matches the RomRaider (*.xml) definition format.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.io.File;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

public class ExportRomRaiderDefs extends GhidraScript {
	/******************************/
	/* Custom X-Axis              */
	/******************************/

	private static final String [] getCustomAxis(String n) {
		if (n.equals("LEA_knock_retard2"))
			return new String [] {"Cyl #1","Cyl #2","Cyl #3","Cyl #4","Cyl #5","Cyl #6"};
		if (n.equals("LEA_perf_time_at_TPS"))
			return new String [] {"0 - 1.5 %","1.5 - 15 %","15 - 25 %","25 - 35 %","35 - 50 %","50 - 65 %","65 - 80 %","80 - 100 %"};
		if (n.equals("LEA_perf_time_at_RPM"))
			return new String [] {"500 - 1500 RPM","1500 - 2500 RPM","2500 - 3500 RPM","3500 - 4500 RPM","4500 - 5500 RPM","5500 - 6500 RPM","6500 - 7000 RPM","7000 RPM +"};
		if (n.equals("LEA_perf_time_at_KMH"))
			return new String [] {"0 - 30 KMH","30 - 60 KMH","60 - 90 KMH","90 - 120 KMH","120 - 150 KMH","150 - 180 KMH","180 - 210 KMH","210 KMH +"};
		if (n.equals("LEA_perf_time_at_coolant_temp"))
			return new String [] {"105 - 110 Deg C","110 - 115 Deg C","115 - 119 Deg C","119 Deg C +"};
		if (n.equals("LEA_perf_max_engine_speed"))
			return new String [] {"#5","#4","#3","#2","#1"};
		if (n.equals("LEA_perf_max_vehicle_speed"))
			return new String [] {"#5","#4","#3","#2","#1"};
		if (n.equals("LEA_perf_fastest_standing_start"))
			return new String [] {"0 - 100 KMH","0 - 160 KMH"};
		if (n.equals("LEA_perf_last_standing_start"))
			return new String [] {"0 - 100 KMH","0 - 160 KMH"};
		if (n.equals("CAL_injtip_in_adj_gears"))
			return new String [] {"Neutral","1st gear","2nd gear","3rd gear","4th gear","5th gear"};
		if (n.equals("CAL_ign_advance_adj_cyl"))
			return new String [] {"Cyl #1","Cyl #2","Cyl #3","Cyl #4","Cyl #5","Cyl #6"};
		if (n.equals("CAL_injtip_in_adj_gears_6"))
			return new String [] {"6th gear"};
		if (n.equals("CAL_misc_gears"))
			return new String [] {"Min 1st gear","Max 1st gear","Min 2nd gear","Max 2nd gear","Min 3rd gear","Max 3rd gear","Min 4th gear","Max 4th gear","Min 5th gear","Max 5th gear"};
		if (n.equals("CAL_misc_gears_6"))
			return new String [] {"Min 6th gear","Max 6th gear"};
		if (n.equals("CAL_misc_gears_?b"))
			return new String [] {"Min 1st gear","Max 1st gear","Min 2nd gear","Max 2nd gear","Min 3rd gear","Max 3rd gear","Min 4th gear","Max 4th gear","Min 5th gear","Max 5th gear","Min 6th gear","Max 6th gear"};
		if (n.equals("CAL_tpssmooth_decrement_adj1_a?"))
			return new String [] {"N","1st","2nd","3rd","4th","5th","6th"};
		if (n.equals("CAL_tpssmooth_decrement_adj1_b?"))
			return new String [] {"N","1st","2nd","3rd","4th","5th","6th"};
		if (n.equals("CAL_tpssmooth_increment_adj1_b?"))
			return new String [] {"1st","2nd","3rd","4th","5th","6th"};
		if (n.equals("CAL_misc_pps_1_range"))
			return new String [] {"low","high"};
		if (n.equals("CAL_misc_pps_2_range"))
			return new String [] {"low","high"};
		if (n.equals("CAL_misc_tps_1_range"))
			return new String [] {"low","high"};
		if (n.equals("CAL_misc_tps_2_range"))
			return new String [] {"low","high"};
		if (n.equals("CAL_cluster_fuel_level_warning_threshold"))
			return new String [] {"low","high"};

		if (n.equals("CAL_traction_slip_threshold_per_gear_ips")
			|| n.equals("CAL_traction_slip_threshold_per_gear_manual"))
			return new String [] {"1st","2nd","3rd","4th","5th"};
		if (n.equals("CAL_traction_gear_speed_ratios_ips")
			|| n.equals("CAL_traction_gear_speed_ratios_long")
			|| n.equals("CAL_traction_gear_speed_ratios_cr"))
			return new String [] {"1st","2nd","3rd","4th","5th", "6th"};

		if (
			n.equals("CAL_ac_compressor_deactivate_car_speed") ||
			n.equals("CAL_ac_compressor_engine_speed2") ||
			n.equals("CAL_ac_compressor_engine_speed3"))
			return new String [] {"high","low"};

        if (n.equals("CAL_ecu_system_voltage_threshold") ||
			n.equals("CAL_sensor_knock_voltage_threshold") ||
			n.equals("CAL_sensor_iat_voltage_threshold") ||
			n.equals("CAL_sensor_coolant_voltage_threshold") ||
			n.equals("CAL_sensor_intake_air_temp_voltage_threshold") ||
			n.equals("CAL_sensor_fuel_level_sensor_voltage_threshold") ||
			n.equals("CAL_sensor_adc37_threshold") ||
			n.equals("CAL_trans_pump_car_speed_threshold") || 
			n.equals("CAL_trans_temp_voltage_threshold") ||
			n.equals("CAL_ac_compressor_deactivate_car_speed") ||
			n.equals("CAL_cluster_coolant_warning") ||
			n.equals("CAL_ac_compressor_engine_speed2") ||
			n.equals("CAL_cruise_speed_limit") ||
			n.equals("CAL_ecu_engine_running_threshold_unknown"))
			return new String[] {"high", "low"};

		return null;
	};

	/******************************/
	/* Datatype formatting        */
	/******************************/

	private static final Map<String, List<DF>> formatMap = new HashMap<>();

	private static final DF[] formats = new DF[] {
		new DF("bool","uint8","#","x","x","0","1","10","Number"),
		new DF("uint8_t","uint8","#","x","x","0","1","10","Number"),
		new DF("uint16_t","uint16","#","x","x","0","1","100","Number"),
		new DF("uint32_t","uint32","#","x","x","0","1","100","Number"),
		new DF("int8_t","int8","#","x","x","0","1","10","Number"),
		new DF("int16_t","int16","#","x","x","0","1","10","Number"),
		new DF("u8_count","uint8","#","x","x","0","1","10","Number"),
		new DF("u8_gear","uint8","gear","x","x","0","1","10","Gear"),
		new DF("u8_x256","uint8","#","x*256","x/256","0","256","2560","Number"),
		new DF("u8_factor_1","uint8","%","x","x","0","1","5","Percent"),
		new DF("u8_factor_1/32","uint8","%","x*100/32","x*32/100","0","1","5","Percent"),
		new DF("u8_factor_1/64","uint8","%","x*100/64","x*64/100","0","1","5","Percent"),
		new DF("u8_factor_10/1632","uint8","%","x*1000/1632","x*1632/1000","0","1","5","Percent"),
		new DF("u8_factor_10/204","uint8","%","x*1000/204","x*204/1000","0","1","5","Percent"),
		new DF("u8_factor_1/100","uint8","%","x","x","0","1","5","Percent"),
		new DF("u8_factor_1/128","uint8","%","x*100/128","x*128/100","0","1","5","Percent"),
		new DF("u8_factor_1/128-1","uint8","%","(x*100/128)-100","(x+100)*128/100","0","1","5","Percent"),
		new DF("u8_factor_1/156-14/156","uint8","%","(x-14)*100/156","(x*156/100)+14","0","1","5","Percent"),
		new DF("u8_factor_1/200","uint8","%","x*100/200","x*200/100","0.0","1","5","Percent"),
		new DF("u8_factor_1/255","uint8","%","x*100/255","x*255/100","0.0","1","5","Percent"),
		new DF("u8_factor_1/256","uint8","%","x*100/256","x*256/100","0.0","1","5","Percent"),
		new DF("u8_factor_1/256-1/2","uint8","%","(x-128)*100/256","(x*256/100)+128","0.0","1","5","Percent"),
		new DF("u8_factor_1/1000","uint8","%","x*100/1000","x*1000/100","0.00","0.1","1","Percent"),
		new DF("u8_factor_1/1023","uint8","%","x*100/1023","x*1023/100","0.00","0.1","1","Percent"),
		new DF("u8_factor_1/2000","uint8","%","x*100/2000","x*2000/100","0.00","0.1","1","Percent"),
		new DF("u8_factor_1/2560","uint8","%","x*100/2560","x*2560/100","0.00","0.1","1","Percent"),
		new DF("u16_factor_1/32","uint16","%","x*100/32","x*32/100","0","1","5","Percent"),
		new DF("u16_factor_1/100","uint16","%","x","x","0","1","5","Percent"),
		new DF("u16_factor_1/255","uint16","%","x*100/255","x*255/100","0.0","1","5","Percent"),
		new DF("i16_factor_1/1000","int16","%","x*100/1000","x*1000/100","0.00","0.1","1","Percent"),
		new DF("u16_factor_1/1023","uint16","%","x*100/1023","x*1023/100","0.00","0.1","1","Percent"),
		new DF("u16_factor_1/2000","uint16","%","x*100/2000","x*2000/100","0.00","0.1","1","Percent"),
		new DF("i16_factor_1/2000","int16","%","x*100/2000","x*2000/100","0.00","0.1","1","Percent"),
		new DF("u16_factor_1/2000-2048/125","uint16","%","(x-32768)*100/2000","(x*2000/100)+32768","0.00","0.1","1","Percent"),
		new DF("u16_factor_1/2048","uint16","%","x*100/2048","x*2048/100","0.00","0.1","1","Percent"),
		new DF("u16_factor_1/10000","uint16","%","x/100","x*100","0.00","0.1","1","Percent"),
		new DF("u16_factor_1/65536","uint16","%","x*100/65536","x*65536/100","0.00","0.1","1","Percent"),
		new DF("u8_fuel_gal_x10","uint8","gal","x/10","x*10","0.00","0.1","1","gallons"),
		new DF("u16_distance_mm_div2","uint16","mm","x*2","x/2","0","2","10","mm"),
		new DF("u8_factor_1/2560","uint8","%","x*100/2560","x*2560/100","0.00","0.1","1","Percent"),
		new DF("u8_voltage_5/255v","uint8","v","x*5/255","x*255/5","0.0","0.1","0.5","Volt"),
		new DF("u8_voltage_5/1023v","uint8","v","x*5/1023","x*1023/5","0.00","0.05","0.2","Volt"),
		new DF("u16_voltage_5/1023v","uint16","v","x*5/1023","x*1023/5","0.00","0.05","0.2","Volt"),
		new DF("u16_voltage_18/1023v","uint16","v","x*18/1023","x*1023/18","0.00","0.05","0.2","Volt"),
		new DF("u16_current_mA","uint16","A","x/1000","x*1000","0.00","0.01","0.2","Ampere"),
		new DF("u8_voltage_72/1023v","uint8","v","x*72/1023","x/72*1023","0.0","0.2","1.0","Volt"),
		new DF("i8_angle_1/4deg","int8","°","x/4","x*4","0.00","0.25","1.0","Degrees"),
		new DF("u8_angle_1/4deg","uint8","°","x/4","x*4","0.00","0.25","1.0","Degrees"),
		new DF("u8_angle_1/4-10deg","uint8","°","(x/4)-10","(x+10)*4","0.00","0.25","1.0","Degree"),
		new DF("u8_angle_1/4-20deg","uint8","°","(x/4)-20","(x+20)*4","0.00","0.25","1.0","Degree"),
		new DF("u16_angle_1/4-20deg","uint16","°","(x/4)-20","(x+20)*4","0.00","0.25","1.0","Degree"),
		new DF("u8_angle_1/4-30deg","uint8","°","(x/4)-30","(x+30)*4","0.00","0.25","1.0","Degree"),
		new DF("u8_angle_1/4-32deg","uint8","°","(x/4)-32","(x+32)*4","0.00","0.25","1.0","Degree"),
		new DF("u8_angle_1/4-64deg","uint8","°","(x/4)-63.75","(x+63.75)*4","0.00","0.25","1.0","Degree"),
		new DF("u8_angle_720/256deg","uint8","°","x*720/256","x*256/720","0","2","8","Degree"),
		new DF("u16_angle_1/10deg","uint16","°","x/10","x*10","0.0","0.1","1.0","Degree"),
		new DF("i16_angle_1/4deg","int16","°","x/4","x*4","0.00","0.25","1.0","Degree"),
		new DF("u8_rspeed_4rpm","uint8","rpm","x*4","x/4","0","4","16","RPM"),
		new DF("u8_rspeed_8rpm","uint8","rpm","x*8","x/8","0","8","32","RPM"),
		new DF("u8_rspeed_10rpm","uint8","rpm","x*10","x/10","0","10","100","RPM"),
		new DF("u8_rspeed_50rpm","uint8","rpm","x*50","x/50","0","50","100","RPM"),
		new DF("u8_rspeed_4-512rpm","uint8","rpm","(x*4)-512","(x+512)/4","0","4","16","RPM"),
		new DF("u16_rspeed_rpm","uint16","rpm","x","x","0","10","100","RPM"),
		new DF("u16_rspeed_1/4rpm","uint16","rpm","x/4","x*4","0","10","100","RPM"),
		new DF("u16_rspeed_4rpm","uint16","rpm","x*4","x/4","0","10","100","RPM"),
		new DF("u8_rspeed_4+500rpm","uint8","rpm","(x*4)+500","(x-500)/4","0","4","16","RPM"),
		new DF("u8_rspeed_125/4+500rpm","uint8","rpm","(x*125/4)+500","(x-500)*4/125","0","32","100","RPM"),
		new DF("u8_rspeed_125/4rpm","uint8","rpm","x*125/4","x*4/125","0","32","100","RPM"),
		new DF("u16_rspeed_125/4+500rpm","uint16","rpm","(x*125/4)+500","(x-500)*4/125","0","32","100","RPM"),
		new DF("u8_rspeed_10+6000rpm","uint8","rpm","(x*10)+6000","(x-6000)/10","0","10","100","RPM"),
		new DF("u16_length_mm","uint16","cm","x/10","x*10","0.0","0.1","2","Centimeter"),
		new DF("u8_speed_kph","uint8","km/h","x","x","0","1","10","km/h"),
		new DF("u8_speed_1/10kph","uint8","km/h","x/10","x*10","0.0","0.1","1","km/h"),
		new DF("u8_speed_1/100kph","uint8","km/h","x/100","x*100","0.00","0.01","0.1","km/h"),
		new DF("u16_speed_1/100kph","uint16","km/h","x/100","x*100","0.00","0.01","1","km/h"),
		new DF("u8_temp_5/8-40c","uint8","°C","(x*5/8)-40","(x+40)*8/5","0.0","0.625","2","Degree Celsius"),
		new DF("u16_temp_5/8-40c","uint16","°C","(x*5/8)-40","(x+40)*8/5","0.0","0.625","2","Degree Celsius"),
		new DF("u8_temp_1-40c","uint8","°C","x-40","x+40","0","1","2","Degree Celsius"),
		new DF("u16_time_25ns","uint16","ns","x*25","x/25","0","25","100","Nanosecond"),
		new DF("u8_time_us","uint8","us","x","x","0","1","10","Microsecond"),
		new DF("u16_time_4us","uint16","rpm","15000000/x","15000000/x","0","1","10","RPM"),
		new DF("u8_time_8us","uint8","us","x*8","x/8","0","8","100","Microsecond"),
		new DF("u8_time_10us","uint8","us","x*10","x/10","0","10","100","Microsecond"),
		new DF("u8_time_-10us","uint8","us","x*-10","x/-10","0","10","100","Microsecond"),
		new DF("u8_time_20us","uint8","us","x*20","x/20","0","20","200","Microsecond"),
		new DF("u8_time_64us","uint8","us","x*64","x/64","0","64","200","Microsecond"),
		new DF("u8_time_256us","uint8","ms","x*256/1000","x*1000/256","0.0","0.2","1","Millisecond"),
		new DF("u8_time_512us","uint8","ms","x*512/1000","x*1000/512","0.0","0.4","2","Millisecond"),
		new DF("u8_time_5ms","uint8","ms","x*5","x/5","0","5","10","Millisecond"),
		new DF("i16_time_us","int16","us","x","x","0","1","10","Microsecond"),
		new DF("u16_time_5ms","uint16","s","x*5/1000","x*1000/5","0.00","0.1","1","Second"),
		new DF("u32_time_5ms","uint32","s","x*5/1000","x*1000/5","0.00","0.1","1","Second"),
		new DF("u8_time_10ms","uint8","ms","x*10","x/10","0","10","20","Millisecond"),
		new DF("u8_time_25ms","uint8","ms","x*25","x/25","0","25","100","Millisecond"),
		new DF("u8_time_50ms","uint8","s","x/20","x*20","0.0","0.05","1","Second"),
		new DF("u8_time_100ms","uint8","s","x/10","x*10","0.0","0.1","1","Second"),
		new DF("u16_time_10ms","uint16","ms","x*10","x/10","0","10","20","Millisecond"),
		new DF("u16_time_100ms","uint16","s","x/10","x*10","0.0","0.1","1","Second"),
		new DF("u32_time_100ms","uint32","s","x/10","x*10","0.0","0.1","1","Second"),
		new DF("u8_time_250ms","uint8","s","x/4","x*4","0.00","0.1","1","Second"),
		new DF("u8_time_800ms","uint8","s","x*0.8","x/0.8","0.0","1","5","Second"),
		new DF("u8_time_1600ms","uint8","s","x*1.6","x/1.6","0.0","1","5","Second"),
		new DF("u8_time_s","uint8","s","x","x","0","1","5","Second"),
		new DF("u16_time_s","uint16","s","x","x","0","1","5","Second"),
		new DF("u8_time_5s","uint8","s","x*5","x/5","0","5","25","Second"),
		new DF("u8_time_hours","uint8","hours","x","x","0","1","5","Hours"),
		new DF("u8_load_4mg/stroke","uint8","mg/stroke","x*4","x/4","0","4","20","Milligram/Stroke"),
		new DF("u8_load_1173mg/255stroke","uint8","mg/stroke","x*1173/255","x*255/1173","0.0","4","20","Milligram/Stroke"),
		new DF("u16_load_4mg/stroke","uint16","mg/stroke","x*4","x/4","0","4","20","Milligram/Stroke"),
		new DF("u16_load_mg/stroke","uint16","mg/stroke","x","x","0","1","20","Milligram/Stroke"),
		new DF("u8_flow_2g/s","uint8","g/s","x*2","x/2","0","2","10","Gram/Second"),
		new DF("u8_flow_100mg/s","uint8","g/s","x/10","x*10","0.0","0.1","10","Gram/Second"),
		new DF("u8_flow_-100mg/s","uint8","g/s","x/-10","x*-10","0.0","0.1","10","Gram/Second"),
		new DF("u16_flow_100/256mg/s","uint16","mg/s","x*100/256","x*256/100","0.0","0.1","10","Milligram/Second"),
		new DF("u8_flow_100/1024mg/s","uint8","mg/s","x*100/1024","x*1024/100","0.0","0.1","10","Milligram/Second"),
		new DF("i16_flow_100/1024mg/s","int16","mg/s","x*100/1024","x*1024/100","0.0","0.1","10","Milligram/Second"),
		new DF("u8_flow_100-12800mg/s","uint8","g/s","(x-128)/10","(x*10)+128","0.0","0.1","10","Gram/Second"),
		new DF("u16_flow_mg/s","uint16","mg/s","x","x","0","1","5","Milligram/Second"),
		new DF("u16_flow_10mg/s","uint16","g/s","x/100","x*100","0.0","0.01","1","Gram/Second"),
		new DF("u16_flow_100mg/s","uint16","g/s","x/10","x*10","0.0","0.01","1","Gram/Second"),
		new DF("u8_mass_g","uint8","g","x","x","0","1","5","Gram"),
		new DF("u16_mass_g","uint16","g","x","x","0","1","5","Gram"),
		new DF("u16_mass_mg","uint16","mg","x","x","0","1","5","Milligram"),
		new DF("u16_mass_40g","uint16","g","x*40","x/40","0","40","200","Gram"),
		new DF("u8_mass_4g","uint8","g","x*4","x/4","0","4","20","Gram"),
		new DF("u8_mass_8g","uint8","g","x*8","x/8","0","8","40","Gram"),
		new DF("u8_mass_65536mg","uint8","g","x*65.536","x/65.536","0","65","100","Gram"),
		new DF("u16_volume_cc","uint16","cc","x","x","0","10","50","Cubic centimeter"),
		new DF("u16_volume_1+153cc","uint16","cc","x+153","x-153","0","10","50","Cubic centimeter"),
		new DF("u8_volume_4cc","uint8","cc","x*4","x/4","0","4","40","Cubic centimeter"),
		new DF("u8_dt_factor_1/100/5ms","uint8","%/5ms","x","x","0","1","5","Percent/5ms"),
		new DF("u8_dt_factor_1/1023/5ms","uint8","%/5ms","x*100/1023","x*1023/100","0.00","0.1","1","Percent/5ms"),
		new DF("u16_ratio_rpm/kph","uint16","rpm/km/h","x","x","0.0","1","5","Gear Ratio"),
		new DF("u16_ratio_1/10mbar/5v","uint16","mbar/5volt","x/10","x*10","0.0","0.1","5","Millibar/5v"),
		new DF("u16_ratio_mbar/5v","uint16","mbar/5volt","x","x","0","10","50","Millibar/5v"),
		new DF("i16_pressure_1/10mbar","int16","mbar","x/10","x*10","0.0","0.1","5","Millibar"),
		new DF("i16_pressure_mbar","int16","mbar","x","x","0","10","50","Millibar"),
		new DF("u16_pressure_mbar","uint16","mbar","x","x","0","10","50","Millibar"),
		new DF("u8_pressure_1/10mbar","uint8","mbar","x/10","x*10","0.0","0.1","5","Millibar"),
		new DF("u8_pressure_4mbar","uint8","mbar","x*4","x/4","0","4","40","Millibar"),
		new DF("u8_pressure_8mbar","uint8","mbar","x*8","x/8","0","8","80","Millibar"),
		new DF("u8_pressure_50mbar","uint8","mbar","x*50","x/50","0","50","200","Millibar"),
		new DF("u8_lambda_1/100","uint8","λ","x/100","x*100","0.00","0.5","0.1","Lambda"),
		new DF("u8_afr_1/20+5","uint8","A/F","(x/20)+5","(x-5)*20","0.0","0.5","0.1","AFR"),
		new DF("u8_afr_1/20+5","uint8","λ","((x/20)+5)/14.6","((x14.6)-5)*20","0.00","0.5","0.1","Lambda"),
		new DF("u8_afr_1/100","uint8","A/F","x/100","x*100","0.0","0.5","0.1","AFR"),
		new DF("u16_afr_1/100","uint16","A/F","x/100","x*100","0.0","0.5","0.1","AFR"),
		new DF("u16_torque_nm","uint16","Newton meter","x","x","0","1","8","nm"),
		new DF("u8_torque_nm","uint8","Newton meter","x","x","0","1","5","nm"),
		new DF("u8_torque_2nm","uint8","Newton meter","x*2","x/2","0","2","8","nm"),
		new DF("u8_torque_4nm","uint8","Newton meter","x*4","x/4","0","4","16","nm"),
		new DF("u16_power_1/100kw","uint16","kW","x/100","x*100","0.0","10","50","kW"),
	};

	static {
		for (DF df : formats)
			formatMap.computeIfAbsent(df.name, k -> new ArrayList<>()).add(df);
	}

	private static List<DF> getDataformat(String datatype) {
		return formatMap.get(datatype);
	}

	/******************************/
	/* Multiple choices switch    */
	/******************************/

	private static final String[][] OBD2LEVEL = {
		{"Level 0 DTC: off", "00"},
		{"Level 0 DTC: off +self-heal", "40"},
		{"Level 1 DTC: Permanent", "41"},
		{"Level 1 DTC: Permanent, freeze frame (no overwrite)", "51"},
		{"Level 2 DTC: Pending and Permanent", "42"},
		{"Level 2 DTC: Pending and Permanent, freeze frame (overwrite level 1,3)", "52"},
		{"Level 3 DTC: Pending and Permanent", "43"},
		{"Level 3 DTC: Pending and Permanent, freeze frame (no overwrite)", "53"},
		{"Level 4 DTC: Permanent", "44"},
		{"Level 4 DTC: Permanent, freeze frame (overwrite level 1,3)", "54"}
	};

	private static final String[][] OBD2LEVEL_T6 = {
		{"OFF", "00"},
		{"ON 0x01", "01"},
		{"ON 0x11", "11"},
		{"ON 0x12", "12"},
		{"ON 0x13", "13"},
		{"ON 0x21", "21"},
		{"ON 0x53", "53"},
		{"ON 0x91", "91"},
		{"ON 0x92", "92"}
	};

	private static final String[][] OBD2MONITORS = {
		{"Components, Fuel System, Misfire, O2 Sensor Heater, O2 Sensor, Evaporative System, Catalyst", "07 65"},
		{"Components, Fuel System, Misfire, O2 Sensor Heater, O2 Sensor, Catalyst", "07 61"},
		{"Components, Fuel System, Misfire, O2 Sensor, Catalyst", "07 21"},
		{"Components, Fuel System, Misfire", "07 00"}
	};

	private static final String[][] UNLOCK_MAGIC = {
		{"Locked", "00 00 00 00"},
		{"Locked (Spaces)", "20 20 20 20"},
		{"Unlocked", "57 54 46 3F"}
	};

	private static final String[][] USE_TMAP = {
		{"Use temperature of MAF sensor", "00"},
		{"Use temperature of MAP sensor (after intercooler)", "01"}
	};

	private static final String[][] USE_TPMS = {
		{"No TPMS", "00"},
		{"Use TPMS module", "01"}
	};

	private static final String[][] TC_MODE = {
		{"No traction control", "00"},
		{"Normal traction control", "01"},
		{"Variable traction control","02"}
	};

	private static final String[][] LOAD_MODE = {
		{"Compute load from MAF", "00"},
		{"Compute load from MAP", "01"}
	};

	/* This mode is for boolean types, often feature flags */
	private static final String[][] ENABLE_MODE = {
		{"Disabled", "00"},
		{"Enabled", "01"}
	};


	/******************************/
	/* Program code               */
	/******************************/

	private static class DF {
		String name;
		String storageType;
		String units;
		String expression;
		String toBytes;
		String format;
		String fineIncrement;
		String coarseIncrement;
		String description;

		DF(String name, String storageType, String units, String expression, String toBytes,
				String format, String fineIncrement, String coarseIncrement, String description) {
			this.name = name;
			this.storageType = storageType;
			this.units = units;
			this.expression = expression;
			this.toBytes = toBytes;
			this.format = format;
			this.fineIncrement = fineIncrement;
			this.coarseIncrement = coarseIncrement;
			this.description = description;
		}

		void addXmlScaling(Document doc, Element parent) {
			Element e = doc.createElement("scaling");
			e.setAttribute("category", description);
			e.setAttribute("units", units);
			e.setAttribute("expression", expression);
			e.setAttribute("to_byte", toBytes);
			e.setAttribute("format", format);
			e.setAttribute("fineincrement", fineIncrement);
			e.setAttribute("coarseincrement", coarseIncrement);
			parent.appendChild(e);
		}
	}

	private static void createTextChild(Document doc, Element parent, String name, String text) {
		Element e = doc.createElement(name);
		e.appendChild(doc.createTextNode(text));
		parent.appendChild(e);
	}

	private static class SymRecBase {
		String name;
		long   offset;
		String xmlid;
		String market;
		String make;
		String model;
		String submodel;
		String transmission;
		String filesize;
		String memmodel;
		String flashmethod;
		String internalidaddress;
		String internalidstring;

		SymRecBase(String n, long o, String c) throws Exception {
			name = n;
			offset = o;
			String[] d = c.split("#");
			if (d.length < 11)
				throw new Exception("XXX_base has not enough info!");
			xmlid = d[0];
			market = d[1];
			make = d[2];
			model = d[3];
			submodel = d[4];
			transmission = d[5];
			filesize = d[6];
			memmodel = d[7];
			flashmethod = d[8];
			internalidaddress = d[9];
			internalidstring = d[10];
		}

		void getXmlSignature(Document doc, Element parent) {
			Element e = doc.createElement("romid");
			createTextChild(doc, e, "xmlid", xmlid);
			createTextChild(doc, e, "market", market);
			createTextChild(doc, e, "make", make);
			createTextChild(doc, e, "model", model);
			createTextChild(doc, e, "submodel", submodel);
			createTextChild(doc, e, "transmission", transmission);
			createTextChild(doc, e, "filesize", filesize);
			createTextChild(doc, e, "memmodel", memmodel);
			createTextChild(doc, e, "flashmethod", flashmethod);
			createTextChild(doc, e, "internalidaddress", internalidaddress);
			createTextChild(doc, e, "internalidstring", internalidstring);
			createTextChild(doc, e, "noRamOffset", "1");
			parent.appendChild(e);
		}
	}

	private static class SymRec {
		private static final Pattern varFormat = Pattern.compile("([^\\[]+)\\[(\\d+)]");
		String name;
		String category;
		String item;
		long offset;
		String datatype;
		int size;
		List<DF> dataformats;
		String comment;

		SymRec(String n, String ct, String it, long o, String dt, String c) {
			name = n;
			category = ct;
			item = it.replace('_', ' ');
			offset = o;
			Matcher m = varFormat.matcher(dt);
			if (m.matches()) {
				datatype = m.group(1);
				size = Integer.parseInt(m.group(2));
			} else {
				datatype = dt;
				size = 1;
			}
			dataformats = getDataformat(datatype);
			comment = c;
		}

		String prettyName() {
			return category+": "+item;
		}
	}

	private static class Syms {
		private final String prefix;
		private final Pattern symFormat;
		SymRecBase base;
		List<SymRec> syms = new ArrayList<>();
		HashMap<String,SymRec> Xsyms = new HashMap<>();
		HashMap<String,SymRec> Ysyms = new HashMap<>();

		Syms(String prefix) {
			this.prefix = prefix;
			symFormat = Pattern.compile("^"+prefix+"([a-zA-Z0-9]+)_(?:(.+)_([XY])_)?(.+)$");
		}

		void handle(String n, long o, String dt, String c) throws Exception {
			if (n.equals(prefix+"base")) {
				base = new SymRecBase(n, o, c);
				return;
			}
			Matcher m = symFormat.matcher(n);
			if (m.matches()) {
				SymRec s = new SymRec(n, m.group(1), m.group(4), o, dt, c);
				if (m.group(3) != null) {
					String key = prefix+m.group(1)+"_"+m.group(2);
					HashMap<String,SymRec> h = Xsyms;
					if (m.group(3).equals("Y")) h = Ysyms;
					if (h.put(key, s) != null)
						throw new Exception("Axis collision: "+n);
				} else syms.add(s);
			}
		}

		void finish() throws Exception {
			if (base == null)
				throw new Exception(prefix+"base missing");
			syms.sort(Comparator.comparing(r -> r.name));
			//syms.sort(Comparator.comparingLong(r -> r.offset));
			syms.forEach(i -> i.offset -= base.offset);
			Xsyms.values().forEach(i -> i.offset -= base.offset);
			Ysyms.values().forEach(i -> i.offset -= base.offset);
		}
	}

	private Syms[] getSymbols() throws Exception {
		SymbolTable st   = currentProgram.getSymbolTable();
		Listing     lst  = currentProgram.getListing();

		SymbolIterator it = st.getAllSymbols(true);
		Syms [] all = new Syms[] { new Syms("CAL_"), new Syms("LEA_") };

		while (it.hasNext() && !monitor.isCancelled()) {
			Symbol s = it.next();
			if (s.getSource() != SourceType.USER_DEFINED || !s.isPrimary()) continue;

			/* Symbol name */
			String name = s.getName();

			/* Address */
			Address addr = s.getAddress();

			/* EOL comment */
			String cmt = lst.getComment(CodeUnit.EOL_COMMENT, addr);
			if (cmt == null) cmt = "";

			/* Data-type string (or "undefined" if no Data exists) */
			Data data = lst.getDefinedDataAt(addr);
			String dt = (data != null) ? data.getDataType().getName() : "undefined";

			for(Syms p: all) p.handle(name, addr.getOffset(), dt, cmt);
		}

		for(Syms p: all) p.finish();
		return all;
	}

	private static void addXmlSwitch(Document doc, Element parent, SymRec s, String[][] valuey) {
		Element e = doc.createElement("table");
		e.setAttribute("type", "Switch");
		e.setAttribute("name", s.prettyName());
		e.setAttribute("category", s.category);
		e.setAttribute("sizey", String.valueOf(s.size));
		e.setAttribute("userlevel", "1");
		e.setAttribute("storageaddress", String.format("0x%04X", s.offset));
		for (String[] v : valuey) {
			Element ey = doc.createElement("state");
			ey.setAttribute("name", v[0]);
			ey.setAttribute("data", v[1]);
			e.appendChild(ey);
		}
		createTextChild(doc, e, "description", s.comment);
		parent.appendChild(e);
	}

	private static void addXml2DFixed(Document doc, Element parent, SymRec s, String namex, List<DF> dataformatx) throws Exception {
		int sizex = s.size / 2;

		Element e = doc.createElement("table");
		e.setAttribute("type", "2D");
		e.setAttribute("name", s.prettyName());
		e.setAttribute("category", s.category);
		e.setAttribute("storagetype", s.dataformats.get(0).storageType);
		e.setAttribute("endian", "big");
		e.setAttribute("sizex", String.valueOf(sizex));
		e.setAttribute("userlevel", "1");
		e.setAttribute("storageaddress", String.format("0x%04X", s.offset+sizex));
		for (DF df : s.dataformats) df.addXmlScaling(doc, e);

		Element ex = doc.createElement("table");
		ex.setAttribute("type", "X Axis");
		ex.setAttribute("name", namex);
		ex.setAttribute("storagetype", "uint8");
		ex.setAttribute("endian", "big");
		ex.setAttribute("sizex", String.valueOf(sizex));
		ex.setAttribute("storageaddress", String.format("0x%04X", s.offset));
		dataformatx.get(0).addXmlScaling(doc, ex);
		e.appendChild(ex);

		createTextChild(doc, e, "description", s.comment);
		parent.appendChild(e);
	}

	private static void addXml2DStatic(Document doc, Element parent, SymRec s) throws Exception {
		addXml2DStatic(doc, parent, s, new String[] {s.item}, "", null);
	}

	private static void addXml2DStatic(Document doc, Element parent, SymRec s, String [] valuex, String namex, List<DF> dataformatx) throws Exception {
		if (s.size > valuex.length)
			throw new Exception("Invalid axis size: "+s.name + " (" + s.size + ">" + valuex.length + ")");

		Element e = doc.createElement("table");
		e.setAttribute("type", "2D");
		e.setAttribute("name", s.prettyName());
		e.setAttribute("category", s.category);
		e.setAttribute("storagetype", s.dataformats.get(0).storageType);
		e.setAttribute("endian", "big");
		e.setAttribute("sizex", String.valueOf(s.size));
		e.setAttribute("userlevel", "1");
		e.setAttribute("storageaddress", String.format("0x%04X", s.offset));
		for (DF df : s.dataformats) df.addXmlScaling(doc, e);

		Element ex = doc.createElement("table");
		ex.setAttribute("type", "Static X Axis");
		ex.setAttribute("name", namex);
		ex.setAttribute("sizex", String.valueOf(s.size));
		for(int i=0; i<s.size; ++i)
			createTextChild(doc, ex, "data", valuex[i]);
		if (dataformatx != null)
			dataformatx.get(0).addXmlScaling(doc, ex);
		e.appendChild(ex);

		createTextChild(doc, e, "description", s.comment);
		parent.appendChild(e);
	}

	private static void addXml2D(Document doc, Element parent, SymRec s, SymRec sx) throws Exception {
		if (s.size != sx.size)
			throw new Exception("Invalid axis size: "+s.name);

		Element e = doc.createElement("table");
		e.setAttribute("type", "2D");
		e.setAttribute("name", s.prettyName());
		e.setAttribute("category", s.category);
		e.setAttribute("storagetype", s.dataformats.get(0).storageType);
		e.setAttribute("endian", "big");
		e.setAttribute("sizex", String.valueOf(sx.size));
		e.setAttribute("userlevel", "1");
		e.setAttribute("storageaddress", String.format("0x%04X", s.offset));
		for (DF df : s.dataformats) df.addXmlScaling(doc, e);

		Element ex = doc.createElement("table");
		ex.setAttribute("type", "X Axis");
		ex.setAttribute("name", sx.item);
		ex.setAttribute("storagetype", sx.dataformats.get(0).storageType);
		ex.setAttribute("endian", "big");
		ex.setAttribute("sizex", String.valueOf(sx.size));
		ex.setAttribute("storageaddress", String.format("0x%04X", sx.offset));
		sx.dataformats.get(0).addXmlScaling(doc, ex);
		e.appendChild(ex);

		createTextChild(doc, e, "description", s.comment);
		parent.appendChild(e);
	}

	private static void addXml3D(Document doc, Element parent, SymRec s, SymRec sx, SymRec sy) throws Exception {
		if (s.size != sx.size*sy.size)
			throw new Exception("Invalid axis size: "+s.name);

		Element e = doc.createElement("table");
		e.setAttribute("type", "3D");
		e.setAttribute("name", s.prettyName());
		e.setAttribute("category", s.category);
		e.setAttribute("storagetype", s.dataformats.get(0).storageType);
		e.setAttribute("endian", "big");
		e.setAttribute("sizex", String.valueOf(sx.size));
		e.setAttribute("sizey", String.valueOf(sy.size));
		e.setAttribute("userlevel", "1");
		e.setAttribute("storageaddress", String.format("0x%04X", s.offset));
		for (DF df : s.dataformats) df.addXmlScaling(doc, e);

		Element ex = doc.createElement("table");
		ex.setAttribute("type", "X Axis");
		ex.setAttribute("name", sx.item);
		ex.setAttribute("storagetype", sx.dataformats.get(0).storageType);
		ex.setAttribute("endian", "big");
		ex.setAttribute("sizex", String.valueOf(sx.size));
		ex.setAttribute("storageaddress", String.format("0x%04X", sx.offset));
		sx.dataformats.get(0).addXmlScaling(doc, ex);
		e.appendChild(ex);

		Element ey = doc.createElement("table");
		ey.setAttribute("type", "Y Axis");
		ey.setAttribute("name", sy.item);
		ey.setAttribute("storagetype", sy.dataformats.get(0).storageType);
		ey.setAttribute("endian", "big");
		ey.setAttribute("sizey", String.valueOf(sy.size));
		ey.setAttribute("storageaddress", String.format("0x%04X", sy.offset));
		sy.dataformats.get(0).addXmlScaling(doc, ey);
		e.appendChild(ey);

		createTextChild(doc, e, "description", s.comment);
		parent.appendChild(e);
	}

	private void doDefs(Document doc, Element parent, Syms s2) throws Exception {
		for (SymRec s : s2.syms) {
			if (s.datatype.equals("bool"))
				addXmlSwitch(doc, parent, s, ENABLE_MODE);
			else if (s.datatype.equals("u8_obd2level"))
				addXmlSwitch(doc, parent, s, OBD2LEVEL);
			else if (s.datatype.equals("u8_obd2level_t6"))
				addXmlSwitch(doc, parent, s, OBD2LEVEL_T6);
			else if ("CAL_obd2_monitors".equals(s.name))
				addXmlSwitch(doc, parent, s, OBD2MONITORS);
			else if ("CAL_ecu_unlock_magic".equals(s.name))
				addXmlSwitch(doc, parent, s, UNLOCK_MAGIC);
			else if ("CAL_misc_use_tmap".equals(s.name))
				addXmlSwitch(doc, parent, s, USE_TMAP);
			else if ("CAL_misc_use_tpms".equals(s.name))
				addXmlSwitch(doc, parent, s, USE_TPMS);
			else if ("CAL_tc_mode".equals(s.name))
				addXmlSwitch(doc, parent, s, TC_MODE);
			else if ("CAL_load_use_speed_density".equals(s.name))
				addXmlSwitch(doc, parent, s, LOAD_MODE);
			else if (s.dataformats == null)
				println("WARNING - Ignoring unknown format: "+s.name+" ("+s.datatype+")");
			else if (s.name.startsWith("CAL_misc_shift_lights_before_rev_limit"))
				addXml2DFixed(doc, parent, s, "Gear Number", getDataformat("uint8_t"));
			else {
				SymRec sx = s2.Xsyms.get(s.name);
				SymRec sy = s2.Ysyms.get(s.name);
				if (sx != null) {
					if(sx.dataformats != null) {
						if (sy != null) {
							if(sy.dataformats != null) addXml3D(doc, parent, s, sx, sy);
							else println("WARNING - Ignoring unknown Y format: "+s.name+" ("+sy.datatype+")");
						} else addXml2D(doc, parent, s, sx);
					} else println("WARNING - Ignoring unknown X format: "+s.name+" ("+sx.datatype+")");
				} else {
					int shift;
					String [] valuex = getCustomAxis(s.name);
					String namex = "";
					List<DF> dataformatx = null;
					if (valuex != null)
						addXml2DStatic(doc, parent, s, valuex, namex, dataformatx);
					else if (s.size > 1) {
						String datatype;
						if (s.name.equals("CAL_closedloop_min_runtime")) {
							shift = 4;
							namex = "stop coolant";
							datatype = "u8_temp_5/8-40c";
						} else if (s.name.equals("CAL_injtip_catalyst_adj")) {
							shift = 1;
							namex = "dfso_count";
							datatype = "uint8_t";
						} else if (s.name.equals("CAL_sensor_fuel_scaling")) {
							shift = 1;
							namex = "signal";
							datatype = "u8_voltage_5/1023v";
						} else if (s.name.equals("CAL_obd2_P0128_wait_air_mass")) {
							shift = 4;
							namex = "stop coolant";
							datatype = "u8_temp_5/8-40c";
						} else {
							println("WARNING - Using a fixed voltage scale for: "+s.name);
							shift = 3;
							namex = "signal";
							datatype = "u8_voltage_5/1023v";
						}
						valuex = new String[s.size];
						for (int i = 0; i < s.size; i++) valuex[i] = String.valueOf(i << (8 - shift));
						dataformatx = getDataformat(datatype);
						addXml2DStatic(doc, parent, s, valuex, namex, dataformatx);
					} else addXml2DStatic(doc, parent, s);
				}
			}
		}
	}

	private static void removeWhitespaceNodes(Node node) {
		NodeList children = node.getChildNodes();
		for (int i = children.getLength() - 1; i >= 0; i--) {
			Node child = children.item(i);
			if (child.getNodeType() == Node.TEXT_NODE && child.getTextContent().trim().isEmpty())
				node.removeChild(child);
			else if (child.getNodeType() == Node.ELEMENT_NODE)
				removeWhitespaceNodes(child);
		}
	}

	@Override
	public void run() throws Exception {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		DocumentBuilder builder = factory.newDocumentBuilder();
		Document doc;
		Element root;

		// assert that all dataformats storagetype values are the same
		for (final String k : formatMap.keySet()) {
			List<DF> dfList = formatMap.get(k);
			String storagetype = dfList.get(0).storageType;
			for (final DF df : dfList) {
				if (!df.storageType.equals(storagetype)) {
					throw new Exception("Data format "+k+" has mixed storage types: "+storagetype+" vs "+df.storageType);
				}
			}
		}

		Syms [] all = getSymbols();

		File inxml = new File(all[0].base.xmlid+"_defs.inc");
		if (inxml.isFile()) {
			println("Use template " + inxml.getAbsolutePath());
			doc = builder.parse(inxml);
			doc.getDocumentElement().normalize();
			removeWhitespaceNodes(doc.getDocumentElement());
			root = (Element)doc.getElementsByTagName("roms").item(0);
		} else {
			doc = builder.newDocument();
			root = doc.createElement("roms");
			doc.appendChild(root);
		}

		Element calRom = doc.createElement("rom");
		all[0].base.getXmlSignature(doc, calRom);
		doDefs(doc, calRom, all[0]);
		root.appendChild(calRom);

		Element leaRom = doc.createElement("rom");
		all[1].base.getXmlSignature(doc, leaRom);
		doDefs(doc, leaRom, all[1]);
		root.appendChild(leaRom);

		Transformer transformer = TransformerFactory.newInstance().newTransformer();
		transformer.setOutputProperty(OutputKeys.INDENT, "yes");
		transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "1");

		File outxml = new File(all[0].base.xmlid+"_defs.xml");

		DOMSource source = new DOMSource(doc);
		StreamResult result = new StreamResult(outxml);
		transformer.transform(source, result);

		println("RomRaider definition exported to " + outxml.getAbsolutePath());
	}
}
