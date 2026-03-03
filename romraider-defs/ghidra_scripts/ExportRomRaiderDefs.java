//Export user-defined CAL_/LEA_ symbols to an XML file that matches the
//RomRaider (*.xml) definition format.
//
//Symbol naming determines table dimensionality:
//
//  CAL_category_name          - 1D scalar or array (X-axis from pre-comment)
//  CAL_category_name_X_xaxis  - Separate symbol providing the X-axis data for a 2D table
//  CAL_category_name_Y_yaxis  - Separate symbol providing the Y-axis data for a 3D table
//
//  When _X_ and _Y_ symbols exist, they are matched to the base symbol by
//  category and name, and their data/datatype define the axis scaling.
//
//Each symbol's comments control the exported definition:
//
//  EOL comment  - Used as the table description in RomRaider.
//
//  Pre-comment  - Controls X-axis and display format. Three variants:
//
//    X-VALUE: label1,label2,...
//      Static X-axis with explicit labels (one per element).
//      Example: "X-VALUE: Cyl #1,Cyl #2,Cyl #3,Cyl #4,Cyl #5,Cyl #6"
//
//    X-SHIFT: shift,datatype,name
//      Computed X-axis: element indices are shifted left by (8-shift) bits.
//      The datatype overrides the default X-axis scaling, name is the axis label.
//      Example: "X-SHIFT: 4,u8_temp_5/8-40c,stop coolant"
//
//    SWITCH:
//    hex=label
//    hex=label
//      Renders the value as named states instead of a numeric value.
//      Each line maps a hex byte pattern to a human-readable label.
//      Example: "SWITCH:\n\n00=No traction control\n01=Normal traction control"
//
//Pair merging:
//
//  Symbol pairs with complementary suffixes (_disable/_enable, _limit_l/_limit_h,
//  _low/_high, _min/_max) that are contiguous in memory and share the same datatype
//  are automatically merged into a single 2-element table with a static X-axis.
//  The merged symbol takes the base name with the pair category appended
//  (e.g. hysteresis, limit, range, threshold), and the X-axis labels reflect
//  the memory order of the two values.
//  Example: CAL_ac_coolant_disable + CAL_ac_coolant_enable
//        -> CAL_ac_coolant_hysteresis  X-axis: [disable, enable]
//
//@category Symbol
//@menupath Tools.Export.RomRaider
//@description Export CAL_/LEA_ symbols to RomRaider XML definition format.

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
	/* Datatype formatting        */
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

	private static final Map<String, List<DF>> formatMap = new HashMap<>();

	private static final DF[] formats = new DF[] {
		new DF("uint8_t","uint8","#","x","x","0","1","10","Number"),
		new DF("uint16_t","uint16","#","x","x","0","1","100","Number"),
		new DF("u8_x256","uint8","#","x*256","x/256","0","256","2560","Number"),
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
		new DF("u8_factor_1/1023","uint8","%","x*100/1023","x*1023/100","0.00","0.1","1","Percent"),
		new DF("u8_factor_1/2000","uint8","%","x*100/2000","x*2000/100","0.00","0.1","1","Percent"),
		new DF("u16_factor_1/10","uint16","%","x*10","x/10","0","1","10","Percent"),
		new DF("u16_factor_1/100","uint16","%","x","x","0","1","5","Percent"),
		new DF("i16_factor_1/256","int16","%","x*100/256","x*256/100","0.0","1","5","Percent"),
		new DF("i16_factor_1/1000","int16","%","x*100/1000","x*1000/100","0.00","0.1","1","Percent"),
		new DF("u16_factor_1/1023","uint16","%","x*100/1023","x*1023/100","0.00","0.1","1","Percent"),
		new DF("u16_factor_1/1024-1024","uint16","%","(x-1024)*100/1024","(x*1024/100)+1024","0.00","0.1","1","Percent"),
		new DF("u16_factor_1/2000","uint16","%","x*100/2000","x*2000/100","0.00","0.1","1","Percent"),
		new DF("i16_factor_1/2000","int16","%","x*100/2000","x*2000/100","0.00","0.1","1","Percent"),
		new DF("u16_factor_1/2000-2048/125","uint16","%","(x-32768)*100/2000","(x*2000/100)+32768","0.00","0.1","1","Percent"),
		new DF("u16_factor_1/2048","uint16","%","x*100/2048","x*2048/100","0.00","0.1","1","Percent"),
		new DF("u16_factor_1/10000","uint16","%","x/100","x*100","0.00","0.01","0.1","Percent"),
		new DF("u16_factor_1/65536","uint16","%","x*100/65536","x*65536/100","0.00","0.1","1","Percent"),
		new DF("u8_factor_1/2560","uint8","%","x*100/2560","x*2560/100","0.00","0.1","1","Percent"),
		new DF("u8_voltage_5/255v","uint8","v","x*5/255","x*255/5","0.0","0.1","0.5","Volt"),
		new DF("u8_voltage_5/1023v","uint8","v","x*5/1023","x*1023/5","0.00","0.05","0.2","Volt"),
		new DF("u16_voltage_5/1023v","uint16","v","x*5/1023","x*1023/5","0.00","0.05","0.2","Volt"),
		new DF("u16_voltage_18/1023v","uint16","v","x*18/1023","x*1023/18","0.00","0.05","0.2","Volt"),
		new DF("u16_current_mA","uint16","A","x/1000","x*1000","0.00","0.01","0.2","Ampere"),
		new DF("u8_voltage_72/1023v","uint8","v","x*72/1023","x/72*1023","0.0","0.2","1.0","Volt"),
		new DF("u8_angle_1/4deg","uint8","°","x/4","x*4","0.00","0.25","1.0","Degrees"),
		new DF("u8_angle_1/4-10deg","uint8","°","(x/4)-10","(x+10)*4","0.00","0.25","1.0","Degree"),
		new DF("u8_angle_1/4-20deg","uint8","°","(x/4)-20","(x+20)*4","0.00","0.25","1.0","Degree"),
		new DF("u16_angle_1/4-20deg","uint16","°","(x/4)-20","(x+20)*4","0.00","0.25","1.0","Degree"),
		new DF("u8_angle_1/4-30deg","uint8","°","(x/4)-30","(x+30)*4","0.00","0.25","1.0","Degree"),
		new DF("u8_angle_1/4-32deg","uint8","°","(x/4)-32","(x+32)*4","0.00","0.25","1.0","Degree"),
		new DF("u8_angle_10/128deg","uint8","°","x*10/128","x*128/10","0.0","0.1","1","Degree"),
		new DF("u8_angle_10/128+2deg","uint8","°","(x*10/128)+2","(x-2)*128/10","0.0","0.1","1","Degree"),
		new DF("u8_angle_720/256deg","uint8","°","x*720/256","x*256/720","0","2","8","Degree"),
		new DF("u8_rspeed_4rpm","uint8","rpm","x*4","x/4","0","4","16","RPM"),
		new DF("u8_rspeed_8rpm","uint8","rpm","x*8","x/8","0","8","32","RPM"),
		new DF("u8_rspeed_4-512rpm","uint8","rpm","(x*4)-512","(x+512)/4","0","4","16","RPM"),
		new DF("u16_rspeed_rpm","uint16","rpm","x","x","0","10","100","RPM"),
		new DF("u16_rspeed_1/4rpm","uint16","rpm","x/4","x*4","0","10","100","RPM"),
		new DF("u8_rspeed_4+500rpm","uint8","rpm","(x*4)+500","(x-500)/4","0","4","16","RPM"),
		new DF("u8_rspeed_125/4+500rpm","uint8","rpm","(x*125/4)+500","(x-500)*4/125","0","32","100","RPM"),
		new DF("u8_rspeed_125/4rpm","uint8","rpm","x*125/4","x*4/125","0","32","100","RPM"),
		new DF("u16_rspeed_125/4+500rpm","uint16","rpm","(x*125/4)+500","(x-500)*4/125","0","32","100","RPM"),
		new DF("u8_rspeed_10+6000rpm","uint8","rpm","(x*10)+6000","(x-6000)/10","0","10","100","RPM"),
		new DF("u16_length_mm","uint16","cm","x/10","x*10","0.0","0.1","2","Centimeter"),
		new DF("u8_speed_kph","uint8","km/h","x","x","0","1","10","km/h"),
		new DF("u16_speed_1/100kph","uint16","km/h","x/100","x*100","0.00","0.01","1","km/h"),
		new DF("u8_temp_5/8-40c","uint8","°C","(x*5/8)-40","(x+40)*8/5","0.0","0.625","2","Degree Celsius"),
		new DF("u16_temp_5/8-40c","uint16","°C","(x*5/8)-40","(x+40)*8/5","0.0","0.625","2","Degree Celsius"),
		new DF("u8_temp_1-40c","uint8","°C","x-40","x+40","0","1","2","Degree Celsius"),
		new DF("u16_time_25ns","uint16","kHz","40000/x","40000/x","0.00","1","5","kHz"),
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
		new DF("u16_time_1-32768us","uint16","us","x-32768","x+32768","0","1","10","Microsecond"),
		new DF("u16_time_5ms","uint16","s","x*5/1000","x*1000/5","0.00","0.1","1","Second"),
		new DF("u32_time_5ms","uint32","s","x*5/1000","x*1000/5","0.00","0.1","1","Second"),
		new DF("u8_time_10ms","uint8","ms","x*10","x/10","0","10","20","Millisecond"),
		new DF("u8_time_25ms","uint8","ms","x*25","x/25","0","25","100","Millisecond"),
		new DF("u8_time_50ms","uint8","s","x/20","x*20","0.0","0.05","1","Second"),
		new DF("u8_time_100ms","uint8","s","x/10","x*10","0.0","0.1","1","Second"),
		new DF("u16_time_100ms","uint16","s","x/10","x*10","0.0","0.1","1","Second"),
		new DF("u32_time_100ms","uint32","s","x/10","x*10","0.0","0.1","1","Second"),
		new DF("u8_time_800ms","uint8","s","x*0.8","x/0.8","0.0","1","5","Second"),
		new DF("u8_time_1600ms","uint8","s","x*1.6","x/1.6","0.0","1","5","Second"),
		new DF("u8_time_s","uint8","s","x","x","0","1","5","Second"),
		new DF("u16_time_s","uint16","s","x","x","0","1","5","Second"),
		new DF("u8_time_5s","uint8","s","x*5","x/5","0","5","25","Second"),
		new DF("u8_load_4mg/stroke","uint8","mg/stroke","x*4","x/4","0","4","20","Milligram/Stroke"),
		new DF("u8_load_1173mg/255stroke","uint8","mg/stroke","x*1173/255","x*255/1173","0.0","4","20","Milligram/Stroke"),
		new DF("u16_load_4mg/stroke","uint16","mg/stroke","x*4","x/4","0","4","20","Milligram/Stroke"),
		new DF("u16_load_mg/stroke","uint16","mg/stroke","x","x","0","1","20","Milligram/Stroke"),
		new DF("u8_flow_100mg/s","uint8","g/s","x/10","x*10","0.0","0.1","10","Gram/Second"),
		new DF("u8_flow_-100mg/s","uint8","g/s","x/-10","x*-10","0.0","0.1","10","Gram/Second"),
		new DF("u16_flow_100/256mg/s","uint16","mg/s","x*100/256","x*256/100","0.0","0.1","10","Milligram/Second"),
		new DF("u8_flow_100/1024mg/s","uint8","mg/s","x*100/1024","x*1024/100","0.0","0.1","10","Milligram/Second"),
		new DF("i16_flow_100/1024mg/s","int16","mg/s","x*100/1024","x*1024/100","0.0","0.1","10","Milligram/Second"),
		new DF("u8_flow_100-12800mg/s","uint8","g/s","(x-128)/10","(x*10)+128","0.0","0.1","10","Gram/Second"),
		new DF("u16_flow_mg/s","uint16","mg/s","x","x","0","1","5","Milligram/Second"),
		new DF("u16_flow_10mg/s","uint16","g/s","x/100","x*100","0.0","0.01","1","Gram/Second"),
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
		new DF("u16_ratio_rpm/kph","uint16","rpm/km/h","x","x","0","1","5","Gear Ratio"),
		new DF("u16_ratio_1/10mbar/5v","uint16","mbar/5volt","x/10","x*10","0.0","0.1","5","Millibar/5v"),
		new DF("u16_ratio_mbar/5v","uint16","mbar/5volt","x","x","0","10","50","Millibar/5v"),
		new DF("i16_pressure_1/10mbar","int16","mbar","x/10","x*10","0.0","0.1","5","Millibar"),
		new DF("i16_pressure_mbar","int16","mbar","x","x","0","10","50","Millibar"),
		new DF("u16_pressure_mbar","uint16","mbar","x","x","0","10","50","Millibar"),
		new DF("u8_pressure_1/64mbar","uint8","mbar","x/64","x*64","0.00","0.01","0.1","Millibar"),
		new DF("u8_pressure_1/10mbar","uint8","mbar","x/10","x*10","0.0","0.1","5","Millibar"),
		new DF("u8_pressure_4mbar","uint8","mbar","x*4","x/4","0","4","40","Millibar"),
		new DF("u8_pressure_8mbar","uint8","mbar","x*8","x/8","0","8","80","Millibar"),
		new DF("u8_pressure_40mbar","uint8","mbar","x*40","x/40","0","40","200","Millibar"),
		new DF("u8_pressure_50mbar","uint8","mbar","x*50","x/50","0","50","200","Millibar"),
		new DF("u8_lambda_1/100","uint8","λ","x/100","x*100","0.00","0.5","0.1","Lambda"),
		new DF("u8_afr_1/20+5","uint8","A/F","(x/20)+5","(x-5)*20","0.0","0.5","0.1","AFR"),
		new DF("u8_afr_1/20+5","uint8","λ","((x/20)+5)/14.6","((x14.6)-5)*20","0.00","0.5","0.1","Lambda"),
		new DF("u8_afr_1/100","uint8","A/F","x/100","x*100","0.0","0.5","0.1","AFR"),
		new DF("u16_afr_1/100","uint16","A/F","x/100","x*100","0.0","0.5","0.1","AFR"),
		new DF("u16_torque_nm","uint16","Newton meter","x","x","0","1","8","nm"),
		new DF("u8_torque_2nm","uint8","Newton meter","x*2","x/2","0","2","8","nm")
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

	private static final String[][] OBD_CONFIG = {
		{"00", "Level 0 DTC: off"},
		{"40", "Level 0 DTC: off +self-heal"},
		{"41", "Level 1 DTC: Permanent"},
		{"51", "Level 1 DTC: Permanent, freeze frame (no overwrite)"},
		{"42", "Level 2 DTC: Pending and Permanent"},
		{"52", "Level 2 DTC: Pending and Permanent, freeze frame (overwrite level 1,3)"},
		{"43", "Level 3 DTC: Pending and Permanent"},
		{"53", "Level 3 DTC: Pending and Permanent, freeze frame (no overwrite)"},
		{"44", "Level 4 DTC: Permanent"},
		{"54", "Level 4 DTC: Permanent, freeze frame (overwrite level 1,3)"}
	};

	private static final String[][] OBD_CONFIG_T6 = {
		{"00", "OFF"},
		{"01", "ON 0x01"},
		{"11", "ON 0x11"},
		{"12", "ON 0x12"},
		{"13", "ON 0x13"},
		{"21", "ON 0x21"},
		{"53", "ON 0x53"},
		{"91", "ON 0x91"},
		{"92", "ON 0x92"}
	};

	private static final String[][] BOOLEAN = {
		{"00", "False"},
		{"01", "True"}
	};

	/******************************/
	/* CAL_/LEA_ symbols parsing  */
	/******************************/

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
		String description;

		/* X-Axis */
		String [] Xvalues;
		List<DF> Xdataformat;
		String Xname;

		/* Switch */
		String[][] switchData;

		SymRec(String n, String ct, String it, long o, String dt, String desc, String Xinfo) {
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
			description = desc;
			Xvalues = null;
			Xdataformat = null;
			Xname = "";
			switchData = null;
			if (Xinfo != null) parsePreComment(Xinfo);
		}

		private void parsePreComment(String info) {
			if (info.startsWith("SWITCH:")) {
				String[] parts = info.substring(7).trim().split("\n");
				switchData = new String[parts.length][];
				for (int i = 0; i < parts.length; i++) switchData[i] = parts[i].split("=");
			} else if (info.startsWith("X-VALUE:")) {
				Xvalues = info.substring(8).trim().split(",");
			} else if (info.startsWith("X-SHIFT:")) {
				String[] parts = info.substring(8).trim().split(",");
				int shift = Integer.parseInt(parts[0].trim());
				String xdatatype = parts[1].trim();
				Xname = parts[2].trim();
				Xvalues = new String[size];
				for (int i = 0; i < size; i++) Xvalues[i] = String.valueOf(i << (8 - shift));
				Xdataformat = getDataformat(xdatatype);
			}
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

		void handle(String n, long o, String dt, String desc, String Xinfo) throws Exception {
			if (n.equals(prefix+"base")) {
				base = new SymRecBase(n, o, desc);
				return;
			}
			Matcher m = symFormat.matcher(n);
			if (m.matches()) {
				SymRec s = new SymRec(n, m.group(1), m.group(4), o, dt, desc, Xinfo);
				if (m.group(3) != null) {
					String key = prefix+m.group(1)+"_"+m.group(2);
					HashMap<String,SymRec> h = Xsyms;
					if (m.group(3).equals("Y")) h = Ysyms;
					if (h.put(key, s) != null)
						throw new Exception("Axis collision: "+n);
				} else syms.add(s);
			}
		}

		private static final String[][] SUFFIX_PAIRS = {
			{"_disable", "_enable", "hysteresis", "disable", "enable"},
			{"_limit_l", "_limit_h", "limit", "low", "high"},
			{"_low", "_high", "range", "low", "high"},
			{"_min", "_max", "threshold", "min", "max"},

			/* Reversed order */
			{"_enable", "_disable", "hysteresis", "enable", "disable"},
			{"_limit_h", "_limit_l", "limit", "high", "low"},
			{"_high", "_low", "range", "high", "low"},
			{"_max", "_min", "threshold", "max", "min"}
		};

		void mergePairs() {
			syms.sort(Comparator.comparingLong(r -> r.offset));
			for (int i=0; i < syms.size()-1; ++i) {
				SymRec s1 = syms.get(i);
				SymRec s2 = syms.get(i+1);
				if(s1.size != 1 || s2.size != 1) continue;
				if(s1.dataformats != s2.dataformats) continue;
				/* Lazy check, it is not always +4. */
				if(s2.offset > s1.offset + 4) continue;
				for (String[] pair : SUFFIX_PAIRS) {
					if(!s1.name.endsWith(pair[0]) || !s2.name.endsWith(pair[1])) continue;
					s1.name = s1.name.substring(0, s1.name.length() - pair[0].length() + 1) + pair[2];
					s1.item = s1.item.substring(0, s1.item.length() - pair[0].length() + 1) + pair[2];
					s1.size = 2;
					s1.Xname = pair[2];
					s1.Xvalues = new String[] {pair[3], pair[4]};
					if (!s2.description.isEmpty()) {
						if (!s1.description.isEmpty() && !s1.description.equals(s2.description))
							s1.description += "\n" + s2.description;
						else s1.description = s2.description;
					}
					syms.remove(i+1);
					break;
				}
			}
		}

		void finish() throws Exception {
			if (base == null)
				throw new Exception(prefix+"base missing");
			mergePairs();
			syms.sort(Comparator.comparing(r -> r.name));
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

			/* EOL comment - Used for description */
			String ceol = lst.getComment(CodeUnit.EOL_COMMENT, addr);
			if (ceol == null) ceol = "";

			/* PRE comment - Used for information about the X-Axis */
			String cpre = lst.getComment(CodeUnit.PRE_COMMENT, addr);

			/* Data-type string (or "undefined" if no Data exists) */
			Data data = lst.getDefinedDataAt(addr);
			String dt = (data != null) ? data.getDataType().getName() : "undefined";

			for(Syms p: all) p.handle(name, addr.getOffset(), dt, ceol, cpre);
		}

		for(Syms p: all) p.finish();
		return all;
	}

	/******************************/
	/* RomRaider XML functions    */
	/******************************/

	private static void addXmlSignature(Document doc, Element parent, SymRecBase b) {
		Element e = doc.createElement("romid");
		createTextChild(doc, e, "xmlid", b.xmlid);
		createTextChild(doc, e, "market", b.market);
		createTextChild(doc, e, "make", b.make);
		createTextChild(doc, e, "model", b.model);
		createTextChild(doc, e, "submodel", b.submodel);
		createTextChild(doc, e, "transmission", b.transmission);
		createTextChild(doc, e, "filesize", b.filesize);
		createTextChild(doc, e, "memmodel", b.memmodel);
		createTextChild(doc, e, "flashmethod", b.flashmethod);
		createTextChild(doc, e, "internalidaddress", b.internalidaddress);
		createTextChild(doc, e, "internalidstring", b.internalidstring);
		createTextChild(doc, e, "noRamOffset", "1");
		parent.appendChild(e);
	}

	private static Element createTableElement(Document doc, SymRec s, String type) {
		Element e = doc.createElement("table");
		e.setAttribute("type", type);
		e.setAttribute("name", s.prettyName());
		e.setAttribute("category", s.category);
		e.setAttribute("storagetype", s.dataformats.get(0).storageType);
		e.setAttribute("endian", "big");
		e.setAttribute("userlevel", "1");
		e.setAttribute("storageaddress", String.format("0x%04X", s.offset));
		for (DF df : s.dataformats) df.addXmlScaling(doc, e);
		return e;
	}

	private static Element createAxisElement(Document doc, SymRec axis, String type, String sizeAttr) {
		Element e = doc.createElement("table");
		e.setAttribute("type", type);
		e.setAttribute("name", axis.item);
		e.setAttribute("storagetype", axis.dataformats.get(0).storageType);
		e.setAttribute("endian", "big");
		e.setAttribute(sizeAttr, String.valueOf(axis.size));
		e.setAttribute("storageaddress", String.format("0x%04X", axis.offset));
		axis.dataformats.get(0).addXmlScaling(doc, e);
		return e;
	}

	private static void addXmlSwitch(Document doc, Element parent, SymRec s, String[][] states) throws Exception {
		Element e = doc.createElement("table");
		e.setAttribute("type", "Switch");
		e.setAttribute("name", s.prettyName());
		e.setAttribute("category", s.category);
		e.setAttribute("sizey", String.valueOf(s.size));
		e.setAttribute("userlevel", "1");
		e.setAttribute("storageaddress", String.format("0x%04X", s.offset));
		for (String[] v : states) {
			Element ey = doc.createElement("state");
			if(v.length < 2)
				throw new Exception("Invalid options: "+s.name);
			ey.setAttribute("name", v[1]);
			ey.setAttribute("data", v[0]);
			e.appendChild(ey);
		}
		createTextChild(doc, e, "description", s.description);
		parent.appendChild(e);
	}

	private static void addXml2DStatic(Document doc, Element parent, SymRec s) throws Exception {
		addXml2DStatic(doc, parent, s, new String[] {s.item}, "", null);
	}

	private static void addXml2DStatic(Document doc, Element parent, SymRec s, String[] axisLabels, String axisName, List<DF> axisFormat) throws Exception {
		if (s.size > axisLabels.length)
			throw new Exception("Invalid axis size: "+s.name + " (" + s.size + ">" + axisLabels.length + ")");

		Element e = createTableElement(doc, s, "2D");
		e.setAttribute("sizex", String.valueOf(s.size));

		Element ex = doc.createElement("table");
		ex.setAttribute("type", "Static X Axis");
		ex.setAttribute("name", axisName);
		ex.setAttribute("sizex", String.valueOf(s.size));
		for(int i=0; i<s.size; ++i)
			createTextChild(doc, ex, "data", axisLabels[i]);
		if (axisFormat != null)
			axisFormat.get(0).addXmlScaling(doc, ex);
		e.appendChild(ex);

		createTextChild(doc, e, "description", s.description);
		parent.appendChild(e);
	}

	private static void addXml2D(Document doc, Element parent, SymRec s, SymRec sx) throws Exception {
		if (s.size != sx.size)
			throw new Exception("Invalid axis size: "+s.name);

		Element e = createTableElement(doc, s, "2D");
		e.setAttribute("sizex", String.valueOf(sx.size));
		e.appendChild(createAxisElement(doc, sx, "X Axis", "sizex"));

		createTextChild(doc, e, "description", s.description);
		parent.appendChild(e);
	}

	private static void addXml3D(Document doc, Element parent, SymRec s, SymRec sx, SymRec sy) throws Exception {
		if (s.size != sx.size*sy.size)
			throw new Exception("Invalid axis size: "+s.name);

		Element e = createTableElement(doc, s, "3D");
		e.setAttribute("sizex", String.valueOf(sx.size));
		e.setAttribute("sizey", String.valueOf(sy.size));
		e.appendChild(createAxisElement(doc, sx, "X Axis", "sizex"));
		e.appendChild(createAxisElement(doc, sy, "Y Axis", "sizey"));

		createTextChild(doc, e, "description", s.description);
		parent.appendChild(e);
	}

	private void doDefs(Document doc, Element parent, Syms syms) throws Exception {
		for (SymRec s : syms.syms) {
			if (s.switchData != null) {
				addXmlSwitch(doc, parent, s, s.switchData);
				continue;
			}
			if (s.datatype.equals("u8_obd_config")) {
				addXmlSwitch(doc, parent, s, OBD_CONFIG);
				continue;
			}
			if (s.datatype.equals("u8_obd_config_t6")) {
				addXmlSwitch(doc, parent, s, OBD_CONFIG_T6);
				continue;
			}
			if (s.datatype.equals("bool")) {
				addXmlSwitch(doc, parent, s, BOOLEAN);
				continue;
			}
			if (s.dataformats == null) {
				println("WARNING - Ignoring unknown format: "+s.name+" ("+s.datatype+")");
				continue;
			}
			SymRec sx = syms.Xsyms.get(s.name);
			SymRec sy = syms.Ysyms.get(s.name);
			if (sx != null && sx.dataformats != null) {
				if (sy != null && sy.dataformats != null) addXml3D(doc, parent, s, sx, sy);
				else if (sy != null) println("WARNING - Ignoring unknown Y format: "+s.name+" ("+sy.datatype+")");
				else addXml2D(doc, parent, s, sx);
			} else if (sx != null) println("WARNING - Ignoring unknown X format: "+s.name+" ("+sx.datatype+")");
			else if (s.Xvalues != null) addXml2DStatic(doc, parent, s, s.Xvalues, s.Xname, s.Xdataformat);
			else if (s.size > 1) println("WARNING - No X-axis pre-comment for: "+s.name);
			else addXml2DStatic(doc, parent, s);
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
		addXmlSignature(doc, calRom, all[0].base);
		doDefs(doc, calRom, all[0]);
		root.appendChild(calRom);

		Element leaRom = doc.createElement("rom");
		addXmlSignature(doc, leaRom, all[1].base);
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
