typedef unsigned char   undefined;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long long    uint16;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned short    ushort;
typedef ulong size_t;

typedef short int16_t;

typedef char int8_t;

typedef int int32_t;

typedef uchar uint8_t;

typedef uint8_t u8_pressure_4mbar;

typedef uint8_t u8_flow_100/1024mg/s;

typedef uint8_t u8_angle_1/4deg;

typedef ushort uint16_t;

typedef uint16_t u16_flow_10mg/s;

typedef struct struct_varptr struct_varptr, *Pstruct_varptr;

struct struct_varptr {
    void *ptr;
    uint16_t size_le;
};

typedef uint8_t u8_factor_1/500;

typedef uint16_t u16_factor_1/100;

typedef uint8_t u8_factor_1/100;

typedef uint16_t u16_factor_1/10;

typedef uint16_t u16_voltage_5/1023v;

typedef uint16_t u16_time_us;

typedef int16_t i16_time_us;

typedef uint uint32_t;

typedef uint32_t u32_mass_mg;

typedef uint8_t u8_mass_8g;

typedef uint8_t u8_rspeed_4+500rpm;

typedef uint8_t u8_factor_1/1023;

typedef uint8_t u8_dt_factor_1/100/5ms;

typedef uint8_t u8_factor_1/64;

typedef uint8_t u8_rspeed_4-512rpm;

typedef uint16_t u16_time_5ms;

typedef int16_t i16_rspeed_rpm;

typedef uint8_t u8_load_4mg/stroke;

typedef struct struct_filter_2nd_order struct_filter_2nd_order, *Pstruct_filter_2nd_order;

struct struct_filter_2nd_order {
    int32_t state[3]; // Filter state/delay line
    int16_t coef[5]; // Filter coefficients (a1, a2, b0, b1, b2)
};

typedef uint8_t u8_angle_720/256deg;

typedef struct struct_iumpr_monitor struct_iumpr_monitor, *Pstruct_iumpr_monitor;

struct struct_iumpr_monitor {
    uint16_t pass_count; // Number of test passes
    uint8_t passed; // Test passed flag (1 = passed this cycle)
    uint8_t pad1;
    uint16_t fail_count; // Number of test failures
    uint8_t failed; // Test failed flag (1 = failed this cycle)
    uint8_t pad2;
    uint16_t ratio; // Fail/pass ratio (scaled by 0x2005)
    uint8_t sensor_error; // Sensor error detected
    uint8_t ready; // Monitor ready flag
    uint16_t test_id; // OBD test ID (e.g., 0x85)
    uint8_t state; // Monitor state (0-3)
    uint8_t pad3;
};

typedef uint16_t u16_factor_1/65536;

typedef uint8_t u8_afr_1/20+5;

typedef uint8_t u8_flow_100mg/s;

typedef uint8_t u8_angle_1/4-32deg;

typedef uint8_t u8_rspeed_125/4+500rpm;

typedef uint16_t u16_time_1-32768us;

typedef uint8_t u8_rspeed_8rpm;

typedef uint16_t u16_time_25ns;

typedef uint8_t u8_time_5ms;

typedef uint16_t u16_length_mm;

typedef uint8_t u8_rspeed_4rpm;

typedef uint8_t u8_factor_1/156-14/156;

typedef uint16_t u16_load_mg/stroke;

typedef uint16_t u16_temp_5/8-40c;

typedef struct struct_segment_bss struct_segment_bss, *Pstruct_segment_bss;

struct struct_segment_bss {
    pointer dest;
    uint size;
};

typedef uint8_t u8_temp_5/8-40c;

typedef uint8_t u8_time_10ms;

typedef uint8_t u8_factor_1/256;

typedef uint16_t u16_factor_1/1023;

typedef uint8_t u8_afr_1/100;

typedef uint8_t u8_time_8us;

typedef uint8_t u8_time_100ms;

typedef int16_t i16_factor_1/256;

typedef uint8_t u8_angle_10/128+2deg;

typedef struct struct_filter_4th_order struct_filter_4th_order, *Pstruct_filter_4th_order;

struct struct_filter_4th_order {
    int32_t state[5]; // Filter state/delay line
    int16_t coef[8]; // Filter coefficients (4 pairs)
};

typedef uint32_t u32_time_100ms;

typedef uint8_t u8_x256;

typedef uint8_t u8_time_500ms;

typedef uint8_t u8_time_64us;

typedef uint8_t u8_factor_1/200;

typedef uint16_t u16_current_mA;

typedef uint16_t u16_voltage_18/1023v;

typedef uint16_t u16_ratio_mbar/5v;

typedef uint8_t u8_pressure_1/10mbar;

typedef uint8_t u8_factor_1/128;

typedef uint8_t u8_mass_4g;

typedef uint8_t u8_time_s;

typedef uint8_t u8_mass_65536mg;

typedef uint16_t u16_mass_g;

typedef uint16_t u16_rspeed_rpm;

typedef uint8_t u8_flow_100-12800mg/s;

typedef int16_t i16_flow_100mg/s;

typedef uint8_t u8_pressure_1/64mbar;

typedef uint8_t u8_factor_1/255;

typedef uint8_t u8_time_5s;

typedef uint8_t u8_rspeed_10+6000rpm;

typedef uint8_t u8_time_us;

typedef int16_t i16_pressure_1/10mbar;

typedef uint8_t u8_voltage_72/1023v;

typedef uint16_t u16_rspeed_1/4rpm;

typedef struct struct_diag_channel struct_diag_channel, *Pstruct_diag_channel;

struct struct_diag_channel {
    uint8_t result; // Diagnostic result/fault code
    uint8_t state; // State machine (0=idle, 1=counting, 2=confirmed, 3=clearing)
    uint16_t confirm_threshold; // Counter threshold to confirm fault (default 180)
    uint16_t clear_threshold; // Counter threshold to clear fault (default 1000)
    uint16_t confirm_count; // Counter toward fault confirmation
    uint16_t clear_count; // Counter toward fault clearing
    uint16_t reserved; // Reserved/padding
};

typedef uint16_t u16_ratio_rpm/kph;

typedef uint8_t u8_pressure_40mbar;

typedef struct struct_cluster_data struct_cluster_data, *Pstruct_cluster_data;

typedef uint8_t u8_speed_kph;

struct struct_cluster_data {
    u8_speed_kph speed_display; // Speed for cluster display (augmented for legal compliance)
    u8_speed_kph speed_odo; // Actual speed for odometer counting
    u16_rspeed_rpm rpm; // Engine RPM
    u8_factor_1/255 fuel_level; // Fuel level
    u8_temp_5/8-40c temp_coolant; // Coolant temperature
    uint8_t lights_flags[2]; // Lights flags
};

typedef int16_t i16_flow_100/1024mg/s;

typedef uint8_t u8_factor_1/256-1/2;

typedef uint8_t u8_obd_config;

typedef uint8_t u8_time_1600ms;

typedef uint8_t u8_time_20s;

typedef uint8_t u8_time_25ms;

typedef uint16_t u16_factor_1/2000-2048/125;

typedef uint16_t u16_flow_mg/s;

typedef uint8_t u8_voltage_5/255v;

typedef uint16_t u16_factor_1/1024-1024;

typedef uint8_t u8_factor_1/128-1;

typedef uint8_t u8_voltage_5/1023v;

typedef uint8_t u8_factor_1/32;

typedef uint8_t u8_time_256us;

typedef uint16_t u16_speed_1/100kph;

typedef int32_t i32_flow_100/1024mg/s;

typedef uint8_t u8_angle_10/128deg;

typedef int16_t i16_angle_1/4deg;

typedef int16_t i16_factor_1/1023;

typedef uint8_t u8_rspeed_125/4rpm;

typedef uint16_t u16_factor_1/1024;

typedef int16_t i16_factor_1/2000;

typedef uint8_t u8_lambda_1/100;

typedef uint8_t u8_temp_1-40c;

typedef uint16_t u16_pressure_mbar;

typedef struct struct_segment_data struct_segment_data, *Pstruct_segment_data;

struct struct_segment_data {
    pointer src;
    pointer dest;
    uint size;
};

typedef uint8_t u8_angle_1/4-10deg;

typedef uint16_t u16_factor_1/2000;

typedef uint32_t u32_load_mg/stroke;

typedef uint8_t u8_time_800ms;

typedef uint8_t u8_mass_g;

typedef uint8_t u8_flow_-100mg/s;

typedef int16_t i16_pressure_mbar;

typedef uint16_t u16_time_100ms;

typedef uint8_t u8_factor_1/2000;

typedef int16_t i16_pressure_4mbar;

typedef uint16_t u16_angle_1/10deg;

typedef uint16_t u16_factor_1/2048;

typedef uint8_t u8_time_20us;

typedef struct struct_cluster_text struct_cluster_text, *Pstruct_cluster_text;

struct struct_cluster_text {
    bool show; // Show flag
    char text[7]; // Text to be displayed
};

typedef uint16_t u16_factor_1/10000;

typedef uint8_t u8_time_-10us;

typedef uint8_t u8_time_50ms;

typedef uint32_t u32_time_us;

typedef uint8_t u8_factor_1/1000;

typedef uint8_t u8_factor_10/1632;

typedef uint16_t u16_time_s;

typedef uint8_t u8_factor_1/2560;

typedef uint16_t u16_time_4us;

typedef uint16_t u16_ratio_1/10mbar/5v;

typedef int32_t i32_angle_1/4deg;

typedef uint32_t u32_time_5ms;

typedef uint8_t u8_time_10us;

typedef uint16_t u16_afr_1/100;



undefined DAT_00380000;
uint REG_UMCR;
ushort REG_DPTMCR;
uint REG_SIUMCR;
ushort REG_RAMBAR;
uint REG_SGPIODT1;
uint REG_SGPIODT2;
uint REG_SGPIOCR;
uint REG_EMCR;
uint REG_BR0;
uint REG_OR0;
ushort REG_PORTQS;
uint REG_BR1;
byte REG_PQSPAR;
uint REG_OR1;
uint REG_BR2;
uint REG_OR2;
uint REG_BR3;
uint REG_OR3;
uint REG_DMBR;
uint REG_DMOR;
ushort REG_MPIOSMDR;
ushort REG_MPIOSMDDR;
ushort REG_MIOS14TPCR;
uint REG_SCCR;
uint REG_PLPRCR;
int DAT_00021fe0;
int DAT_00021fe4;
int DAT_00021fe8;
ushort REG_MPWMSM3_SCR;
ushort REG_SWSR;
uint REG_UC3FMCR;
uint REG_UC3FMCRE;
uint REG_UC3FCTL;
undefined4 UNK_00000000;
undefined DAT_00004354;
undefined DAT_00004884;
undefined4 DAT_00021fe8;
undefined LAB_00004000;
undefined1 DAT_003f8000;
ushort REG_TBSCR;
ushort REG_MPWMSM17_SCR;
ushort REG_MPWMSM18_PERR;
ushort REG_MPWMSM18_PULR;
ushort REG_MDASM29_SCR;
ushort REG_MPWMSM18_SCR;
ushort REG_MDASM30_SCR;
ushort REG_MPWMSM19_SCR;
ushort REG_MDASM31_SCR;
ushort REG_MPWMSM0_SCR;
ushort REG_MDASM11_SCR;
ushort REG_MPWMSM1_SCR;
ushort REG_MDASM12_SCR;
ushort REG_MCPSMSCR;
ushort REG_MDASM13_SCR;
ushort REG_MPWMSM2_SCR;
ushort REG_MDASM14_SCR;
ushort REG_MDASM15_SCR;
ushort REG_MPWMSM16_SCR;
ushort REG_MDASM27_SCR;
ushort REG_MDASM28_SCR;
byte REG_PORTQB_A;
byte REG_DDRQA_A;
ushort REG_QACR0_A;
ushort REG_QACR1_A;
ushort REG_QACR2_A;
ushort REG_QASR0_A;
ushort REG_QADCA_CCW0;
ushort REG_QADCA_CCW1;
ushort REG_QADCA_CCW2;
ushort REG_QADCA_CCW3;
ushort REG_QADCA_CCW4;
ushort REG_QADCA_CCW5;
ushort REG_QADCA_CCW6;
ushort REG_QADCA_CCW7;
ushort REG_QADCA_CCW8;
ushort REG_QADCA_CCW9;
ushort REG_QADCA_CCW10;
ushort REG_QADCA_CCW11;
ushort REG_QADCA_CCW12;
ushort REG_QADCA_CCW13;
ushort REG_QADCA_CCW14;
ushort REG_QADCA_CCW15;
ushort REG_QADCA_CCW16;
ushort REG_QADCA_CCW17;
ushort REG_QADCA_CCW18;
ushort REG_QADCA_CCW19;
ushort REG_QADC64MCR_A;
ushort REG_QADC64INT_A;
byte REG_PORTQA_A;
ushort REG_QADC64MCR_B;
ushort REG_QADC64INT_B;
byte REG_PORTQA_B;
byte REG_PORTQB_B;
byte REG_DDRQA_B;
ushort REG_QACR0_B;
ushort REG_QACR1_B;
ushort REG_QACR2_B;
ushort REG_QASR0_B;
ushort REG_QADCB_CCW0;
ushort REG_QADCB_CCW1;
ushort REG_QADCB_CCW2;
ushort REG_QADCB_CCW3;
ushort REG_QADCB_CCW4;
ushort REG_QADCB_CCW5;
ushort REG_QADCB_CCW6;
ushort REG_QADCB_CCW7;
ushort REG_QADCB_CCW8;
ushort REG_QADCB_CCW9;
ushort REG_QADCB_CCW10;
ushort REG_QADCB_CCW11;
ushort REG_QADCB_CCW12;
ushort REG_QADCB_CCW13;
ushort REG_QADCB_CCW14;
ushort REG_QADCB_CCW15;
ushort REG_QADCB_CCW16;
ushort REG_QADCB_CCW17;
ushort REG_QADCB_CCW18;
uint DAT_003fe010;
undefined UNK_0001869f;
undefined4 DAT_003fe010;
ushort REG_SCC1R0;
ushort REG_SCC1R1;
ushort REG_SC1SR;
ushort REG_SC1DR;
undefined4 DAT_003fe01c;
int DAT_003fe01c;
undefined1 DAT_003fe018;
undefined1 DAT_003fe020;
byte UNK_003fe021;
ushort DAT_003fe388;
ushort DAT_003fe384;
undefined DAT_003fe170;
short DAT_003fe388;
ushort DAT_003fe386;
uint DAT_003fe168;
int DAT_003fe16c;
undefined4 DAT_003fe128;
ushort DAT_003fe382;
undefined4 DAT_003fe374;
undefined2 DAT_003fe384;
undefined2 DAT_003fe386;
undefined2 DAT_003fe388;
undefined4 DAT_003fe16c;
undefined *DAT_003fe168;
undefined4 DAT_003fe12c;
undefined4 DAT_003fe130;
undefined4 DAT_003fe134;
undefined4 DAT_003fe138;
undefined4 DAT_003fe13c;
undefined4 DAT_003fe140;
undefined4 DAT_003fe144;
undefined4 DAT_003fe148;
undefined4 DAT_003fe14c;
undefined *DAT_003fe150;
undefined *DAT_003fe154;
undefined4 DAT_003fe158;
undefined *DAT_003fe15c;
undefined *DAT_003fe160;
undefined *DAT_003fe164;
undefined DAT_00001740;
undefined DAT_00002e80;
undefined DAT_0000ba00;
undefined DAT_00017401;
undefined DAT_0002e801;
undefined DAT_0005d017;
uint16_t flash_data_write_i;
uint DAT_003fe374;
int DAT_003fe370;
uint DAT_003fe378;
uint16_t flash_data_read_i;
ushort DAT_003fe37c;
undefined4 DAT_003fe370;
undefined1 DAT_003fe390;
undefined4 DAT_003fe6a0;
uint DAT_003fe6a0;
byte DAT_003fe6a6;
byte DAT_003fe6a4;
int DAT_003fe698;
undefined *DAT_003fe69c;
char DAT_003fe6a5;
undefined1 DAT_003fe498;
undefined DAT_003fe49d;
byte UNK_003fe499;
byte UNK_003fe49a;
byte UNK_003fe49b;
byte UNK_003fe49c;
ushort REG_QADCB_RJURR11;
undefined4 DAT_003fe6a8;
int DAT_003fe6a8;
ushort REG_MDASM28_AR;
ushort REG_MDASM28_BR;
undefined *PTR_DAT_00021fec;
undefined *DAT_003fe6ac;
undefined DAT_0000fff6;
undefined DAT_0000c350;
int DAT_003fe6ac;
undefined DAT_0000dc00;
undefined DAT_0000ffdc;

// WARNING: This function may have set the stack pointer
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Stage2 entry point (stage1 branches to 0x4000): runs init_system_registers then main

void entry_point(void)

{
  uint uVar1;
  
  init_system_registers();
  main();
  REG_SIUMCR = 0x420800;
  REG_BR0 = 0x400003;
  REG_OR0 = 0xfff80022;
  REG_BR1 = 3;
  REG_OR1 = 0xfff80002;
  REG_BR2 = 0xc00003;
  REG_OR2 = 0xfffe0022;
  REG_BR3 = 0xa00803;
  REG_OR3 = 0xffe00072;
  REG_DMBR = 0;
  REG_DMOR = 0;
  REG_DPTMCR = 0;
  REG_RAMBAR = 0xffa0;
  REG_PORTQS = 0;
  Ram00305016 = 0;
  REG_MPIOSMDR = 0;
  REG_MPIOSMDDR = 0;
  REG_MIOS14TPCR = 0;
  _DAT_00380000 = 0;
  REG_SGPIODT1 = 0;
  REG_SGPIODT2 = 0;
  REG_SGPIOCR = 0;
  REG_EMCR = 0;
  REG_UMCR = 0;
  REG_SCCR = 0;
  REG_PLPRCR = 0x410000;
  uVar1 = REG_PLPRCR;
  REG_PLPRCR = uVar1 & 0xfffff | 0x900000;
  REG_SCCR = 0x4010000;
  do {
    uVar1 = REG_PLPRCR;
  } while ((uVar1 >> 0x10 & 1) == 0);
  uVar1 = REG_UMCR;
  REG_UMCR = uVar1 & 0xefffffff;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Initializes MPC563 system registers: SIUMCR, chip selects BR0-3/OR0-3, DMBR/DMOR, DPTMCR, clock
// (SCCR/PLPRCR) and MIOS/port presets

void init_system_registers(void)

{
  uint uVar1;
  
  REG_SIUMCR = 0x420800;
  REG_BR0 = 0x400003;
  REG_OR0 = 0xfff80022;
  REG_BR1 = 3;
  REG_OR1 = 0xfff80002;
  REG_BR2 = 0xc00003;
  REG_OR2 = 0xfffe0022;
  REG_BR3 = 0xa00803;
  REG_OR3 = 0xffe00072;
  REG_DMBR = 0;
  REG_DMOR = 0;
  REG_DPTMCR = 0;
  REG_RAMBAR = 0xffa0;
  REG_PORTQS = 0;
  Ram00305016 = 0;
  REG_MPIOSMDR = 0;
  REG_MPIOSMDDR = 0;
  REG_MIOS14TPCR = 0;
  _DAT_00380000 = 0;
  REG_SGPIODT1 = 0;
  REG_SGPIODT2 = 0;
  REG_SGPIOCR = 0;
  REG_EMCR = 0;
  REG_UMCR = 0;
  REG_SCCR = 0;
  REG_PLPRCR = 0x410000;
  uVar1 = REG_PLPRCR;
  REG_PLPRCR = uVar1 & 0xfffff | 0x900000;
  REG_SCCR = 0x4010000;
  do {
    uVar1 = REG_PLPRCR;
  } while ((uVar1 >> 0x10 & 1) == 0);
  uVar1 = REG_UMCR;
  REG_UMCR = uVar1 & 0xefffffff;
  return;
}



// Runs the CRP01 K-Line flasher session, then handles a pending HC08 update (H308CODE magic) and
// boots the application

void efip_flasher_run(void)

{
  efip_session_run();
  if (((DAT_00021fe0 == 0x48433038) && (DAT_00021fe4 == 0x434f4445)) &&
     (DAT_00021fe8 == -0x55555556)) {
    hc08_erase_sequence();
  }
  prog_entry_point();
  return;
}



// Waits for the L-Line to read low (MPWMSM3 SCR bit 15), servicing the watchdog up to 5000
// iterations; returns 0 when low (CRP01 tool requests the flasher), 1 on timeout (normal boot)

undefined4 boot_l_line_low_wait(void)

{
  ushort uVar1;
  uint uVar2;
  
  uVar2 = 0;
  while( true ) {
    if (4999 < uVar2) {
      return 1;
    }
    REG_SWSR = 0x556c;
    REG_SWSR = 0xaa39;
    uVar1 = REG_MPWMSM3_SCR;
    if (-1 < (short)uVar1) break;
    uVar2 = uVar2 + 1;
  }
  return 0;
}



// Stage2 boot: L-Line low -> run the CRP01 flasher from RAM; H308CODE magic -> HC08 programming +
// update marker; then boot the application (prog_entry_point)

void main(void)

{
  int iVar1;
  
  iVar1 = boot_l_line_low_wait();
  if (iVar1 == 0) {
    stage2_to_ram();
    efip_flasher_run_ram();
  }
  if (((DAT_00021fe0 == 0x48433038) && (DAT_00021fe4 == 0x434f4445)) &&
     (DAT_00021fe8 == -0x55555556)) {
    REG_SWSR = 0x556c;
    REG_SWSR = 0xaa39;
    timer_enable_timebase();
    REG_SWSR = 0x556c;
    REG_SWSR = 0xaa39;
    iVar1 = hc08_program_sequence();
    if (iVar1 != 0) {
      flash_write_update_marker();
    }
  }
  prog_entry_point();
  return;
}



// Programs N halfwords (16-bit) to flash via UC3F controller, verifies after write

undefined4 flash_program_halfwords(short *param_1,short *param_2,int param_3)

{
  bool bVar1;
  short sVar2;
  short sVar3;
  uint uVar4;
  short *psVar5;
  short *psVar6;
  int iVar7;
  
  uVar4 = REG_UC3FCTL;
  if (((uVar4 >> 0x1c & 1) == 1) && (uVar4 = REG_UC3FCTL, (uVar4 >> 0x1b & 1) == 1)) {
    uVar4 = REG_UC3FMCR;
    REG_UC3FMCR = uVar4 & 0xffffff00;
    uVar4 = REG_UC3FMCRE;
    REG_UC3FMCRE = uVar4 & 0xfcffffff;
    uVar4 = REG_UC3FMCRE;
    REG_UC3FMCRE = uVar4 & 0x3fffffff | 0xc0000000;
    uVar4 = REG_UC3FCTL;
    REG_UC3FCTL = uVar4 & 0xfffcffff | 0x30000;
    uVar4 = REG_UC3FCTL;
    REG_UC3FCTL = uVar4 & 0xffff00ff | 0xff00;
    uVar4 = REG_UC3FCTL;
    REG_UC3FCTL = uVar4 & 0xfffffffd;
    uVar4 = REG_UC3FCTL;
    REG_UC3FCTL = uVar4 & 0xfffffffb;
    uVar4 = REG_UC3FCTL;
    REG_UC3FCTL = uVar4 & 0xfffffffd | 2;
    psVar5 = param_2;
    psVar6 = param_1;
    iVar7 = param_3;
    while (bVar1 = iVar7 != 0, iVar7 = iVar7 + -1, bVar1) {
      sVar2 = *psVar5;
      psVar5 = psVar5 + 1;
      *psVar6 = sVar2;
      psVar6 = psVar6 + 1;
      uVar4 = REG_UC3FCTL;
      REG_UC3FCTL = uVar4 & 0xfffffffe | 1;
      do {
        uVar4 = REG_UC3FCTL;
      } while ((int)uVar4 < 0);
      do {
        uVar4 = REG_UC3FCTL;
      } while ((uVar4 >> 0x1e & 1) == 0);
      uVar4 = REG_UC3FCTL;
      REG_UC3FCTL = uVar4 & 0xfffffffe;
    }
    uVar4 = REG_UC3FCTL;
    REG_UC3FCTL = uVar4 & 0xfffffffd;
    uVar4 = REG_UC3FCTL;
    REG_UC3FCTL = uVar4 & 0xffff00ff;
    uVar4 = REG_UC3FCTL;
    REG_UC3FCTL = uVar4 & 0xfffcffff;
    do {
      bVar1 = param_3 == 0;
      param_3 = param_3 + -1;
      if (bVar1) {
        return 1;
      }
      sVar2 = *param_1;
      param_1 = param_1 + 1;
      sVar3 = *param_2;
      param_2 = param_2 + 1;
    } while (sVar2 == sVar3);
  }
  return 0;
}



// Erases flash block via UC3F controller using block select and address mask parameters

undefined4 flash_erase(uint param_1,uint param_2)

{
  uint uVar1;
  undefined4 uVar2;
  
  uVar1 = REG_UC3FCTL;
  if (((uVar1 >> 0x1c & 1) == 1) && (uVar1 = REG_UC3FCTL, (uVar1 >> 0x1b & 1) == 1)) {
    uVar1 = REG_UC3FMCR;
    REG_UC3FMCR = uVar1 & 0xffffff00;
    uVar1 = REG_UC3FMCRE;
    REG_UC3FMCRE = uVar1 & 0xfcffffff;
    uVar1 = REG_UC3FMCRE;
    REG_UC3FMCRE = uVar1 & 0x3fffffff | 0xc0000000;
    uVar1 = REG_UC3FCTL;
    REG_UC3FCTL = (param_2 & 3) << 0x10 | uVar1 & 0xfffcffff;
    uVar1 = REG_UC3FCTL;
    REG_UC3FCTL = (param_1 & 0xff) << 8 | uVar1 & 0xffff00ff;
    uVar1 = REG_UC3FCTL;
    REG_UC3FCTL = uVar1 & 0xfffffffd;
    uVar1 = REG_UC3FCTL;
    REG_UC3FCTL = uVar1 & 0xfffffffb | 4;
    uVar1 = REG_UC3FCTL;
    REG_UC3FCTL = uVar1 & 0xfffffffd | 2;
    uRam00000000 = 0;
    uVar1 = REG_UC3FCTL;
    REG_UC3FCTL = uVar1 & 0xfffffffe | 1;
    while (uVar1 = REG_UC3FCTL, (int)uVar1 < 0) {
      REG_SWSR = 0x556c;
      REG_SWSR = 0xaa39;
    }
    while (uVar1 = REG_UC3FCTL, (uVar1 >> 0x1e & 1) == 0) {
      REG_SWSR = 0x556c;
      REG_SWSR = 0xaa39;
    }
    uVar1 = REG_UC3FCTL;
    REG_UC3FCTL = uVar1 & 0xfffffffe;
    uVar1 = REG_UC3FCTL;
    REG_UC3FCTL = uVar1 & 0xfffffffd;
    uVar1 = REG_UC3FCTL;
    REG_UC3FCTL = uVar1 & 0xffff00ff;
    uVar1 = REG_UC3FCTL;
    REG_UC3FCTL = uVar1 & 0xfffcffff;
    uVar2 = 1;
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}



// Writes the 0x2222 update marker to flash 0x21FE8/0x21FEA to signal a successful update

void flash_write_update_marker(void)

{
  undefined2 local_8 [4];
  
  local_8[0] = 0x2222;
  REG_SWSR = 0x556c;
  REG_SWSR = 0xaa39;
  memcpy_aligned(0x3f8000,&DAT_00004354,&DAT_00004884);
  REG_SWSR = 0x556c;
  REG_SWSR = 0xaa39;
  flash_program_halfwords(&DAT_00021fe8,local_8,1);
  flash_program_halfwords(0x21fea,local_8,1);
  return;
}



// Copies the stage2 flasher image (flash 0x4000-0x9FFF, 0x6000 bytes) to RAM 0x3F8000 so the
// flasher can run from RAM during flash programming (relative branches keep the copy executable)

void stage2_to_ram(void)

{
  bool bVar1;
  undefined1 uVar2;
  int iVar3;
  undefined1 *puVar4;
  undefined1 *puVar5;
  
  puVar5 = &DAT_003f8000;
  puVar4 = &LAB_00004000;
  iVar3 = 0x6000;
  while (bVar1 = iVar3 != 0, iVar3 = iVar3 + -1, bVar1) {
    REG_SWSR = 0x556c;
    REG_SWSR = 0xaa39;
    uVar2 = *puVar4;
    puVar4 = puVar4 + 1;
    *puVar5 = uVar2;
    puVar5 = puVar5 + 1;
  }
  return;
}



// Programs a single 32-bit word to flash via the UC3F controller

void flash_program_word(undefined4 param_1,undefined4 param_2,uint param_3)

{
  flash_program_halfwords(param_1,param_2,param_3 >> 1);
  return;
}



// Enables timebase timer by setting TBSCR enable bit

void timer_enable_timebase(void)

{
  ushort uVar1;
  
  uVar1 = REG_TBSCR;
  REG_TBSCR = uVar1 | 1;
  return;
}



// Saves current timebase value to indexed timer slot

void timer_save(ushort param_1)

{
  undefined4 uVar1;
  
  uVar1 = timer_read_tbl();
  *(undefined4 *)((uint)param_1 * 4 + 0x3fe000) = uVar1;
  return;
}



// Returns elapsed time since timer_save for indexed timer slot

int timer_elapsed(ushort param_1)

{
  int iVar1;
  
  iVar1 = timer_read_tbl();
  return iVar1 - *(int *)((uint)param_1 * 4 + 0x3fe000);
}



// Reads PowerPC Time Base Lower register (TBL)

undefined4 timer_read_tbl(void)

{
  undefined4 uVar1;
  
  uVar1 = TBLr;
  return uVar1;
}



// Blocking delay in milliseconds (param x 1000 timer ticks) with watchdog retrigger

void delay_blocking_ms(int param_1)

{
  uint uVar1;
  
  timer_save(1);
  while (uVar1 = timer_elapsed(1), uVar1 <= (uint)(param_1 * 1000)) {
    REG_SWSR = 0x556c;
    REG_SWSR = 0xaa39;
  }
  return;
}



// Blocking delay using timer slot 1 with watchdog retrigger

void delay_blocking(uint param_1)

{
  uint uVar1;
  
  timer_save(1);
  while (uVar1 = timer_elapsed(1), uVar1 <= param_1) {
    REG_SWSR = 0x556c;
    REG_SWSR = 0xaa39;
  }
  return;
}



// Initializes MIOS: configures PWM channels 0-3/16-19, MDASM channels 11-15/27-31, MPIO
// data/direction registers

void init_mios(void)

{
  ushort uVar1;
  
  uVar1 = REG_MCPSMSCR;
  REG_MCPSMSCR = uVar1 & 0x7fff | 0x8000;
  uVar1 = REG_MCPSMSCR;
  REG_MCPSMSCR = uVar1 & 0xbfff;
  uVar1 = REG_MCPSMSCR;
  REG_MCPSMSCR = uVar1 & 0xfff0 | 2;
  uVar1 = REG_MPWMSM0_SCR;
  REG_MPWMSM0_SCR = uVar1 & 0xff00 | 0xec;
  uVar1 = REG_MPWMSM0_SCR;
  REG_MPWMSM0_SCR = uVar1 & 0xefff;
  uVar1 = REG_MPWMSM0_SCR;
  REG_MPWMSM0_SCR = uVar1 & 0xbfff | 0x4000;
  uVar1 = REG_MPWMSM0_SCR;
  REG_MPWMSM0_SCR = uVar1 & 0xf7ff;
  uVar1 = REG_MPWMSM0_SCR;
  REG_MPWMSM0_SCR = uVar1 & 0xfbff;
  uVar1 = REG_MPWMSM1_SCR;
  REG_MPWMSM1_SCR = uVar1 & 0xff00 | 0xec;
  uVar1 = REG_MPWMSM1_SCR;
  REG_MPWMSM1_SCR = uVar1 & 0xefff;
  uVar1 = REG_MPWMSM1_SCR;
  REG_MPWMSM1_SCR = uVar1 & 0xbfff | 0x4000;
  uVar1 = REG_MPWMSM1_SCR;
  REG_MPWMSM1_SCR = uVar1 & 0xf7ff;
  uVar1 = REG_MPWMSM1_SCR;
  REG_MPWMSM1_SCR = uVar1 & 0xfbff;
  uVar1 = REG_MPWMSM2_SCR;
  REG_MPWMSM2_SCR = uVar1 & 0xff00 | 0xec;
  uVar1 = REG_MPWMSM2_SCR;
  REG_MPWMSM2_SCR = uVar1 & 0xefff;
  uVar1 = REG_MPWMSM2_SCR;
  REG_MPWMSM2_SCR = uVar1 & 0xbfff;
  uVar1 = REG_MPWMSM2_SCR;
  REG_MPWMSM2_SCR = uVar1 & 0xf7ff;
  uVar1 = REG_MPWMSM2_SCR;
  REG_MPWMSM2_SCR = uVar1 & 0xfbff;
  uVar1 = REG_MPWMSM3_SCR;
  REG_MPWMSM3_SCR = uVar1 & 0xff00 | 0xec;
  uVar1 = REG_MPWMSM3_SCR;
  REG_MPWMSM3_SCR = uVar1 & 0xefff;
  uVar1 = REG_MPWMSM3_SCR;
  REG_MPWMSM3_SCR = uVar1 & 0xbfff;
  uVar1 = REG_MPWMSM3_SCR;
  REG_MPWMSM3_SCR = uVar1 & 0xf7ff;
  uVar1 = REG_MPWMSM3_SCR;
  REG_MPWMSM3_SCR = uVar1 & 0xfbff;
  uVar1 = REG_MPWMSM16_SCR;
  REG_MPWMSM16_SCR = uVar1 & 0xff00 | 0xec;
  uVar1 = REG_MPWMSM16_SCR;
  REG_MPWMSM16_SCR = uVar1 & 0xefff;
  uVar1 = REG_MPWMSM16_SCR;
  REG_MPWMSM16_SCR = uVar1 & 0xbfff | 0x4000;
  uVar1 = REG_MPWMSM16_SCR;
  REG_MPWMSM16_SCR = uVar1 & 0xf7ff;
  uVar1 = REG_MPWMSM16_SCR;
  REG_MPWMSM16_SCR = uVar1 & 0xfbff;
  uVar1 = REG_MPWMSM17_SCR;
  REG_MPWMSM17_SCR = uVar1 & 0xff00 | 0xec;
  uVar1 = REG_MPWMSM17_SCR;
  REG_MPWMSM17_SCR = uVar1 & 0xefff;
  uVar1 = REG_MPWMSM17_SCR;
  REG_MPWMSM17_SCR = uVar1 & 0xbfff | 0x4000;
  uVar1 = REG_MPWMSM17_SCR;
  REG_MPWMSM17_SCR = uVar1 & 0xf7ff;
  uVar1 = REG_MPWMSM17_SCR;
  REG_MPWMSM17_SCR = uVar1 & 0xfbff;
  uVar1 = REG_MPWMSM18_SCR;
  REG_MPWMSM18_SCR = uVar1 & 0xff00 | 0xec;
  uVar1 = REG_MPWMSM18_SCR;
  REG_MPWMSM18_SCR = uVar1 & 0xefff;
  uVar1 = REG_MPWMSM18_SCR;
  REG_MPWMSM18_SCR = uVar1 & 0xbfff | 0x4000;
  uVar1 = REG_MPWMSM18_SCR;
  REG_MPWMSM18_SCR = uVar1 & 0xf7ff;
  uVar1 = REG_MPWMSM18_SCR;
  REG_MPWMSM18_SCR = uVar1 & 0xfbff | 0x400;
  REG_MPWMSM18_PERR = 1000;
  REG_MPWMSM18_PULR = 500;
  uVar1 = REG_MPWMSM19_SCR;
  REG_MPWMSM19_SCR = uVar1 & 0xff00 | 0xec;
  uVar1 = REG_MPWMSM19_SCR;
  REG_MPWMSM19_SCR = uVar1 & 0xefff;
  uVar1 = REG_MPWMSM19_SCR;
  REG_MPWMSM19_SCR = uVar1 & 0xbfff | 0x4000;
  uVar1 = REG_MPWMSM19_SCR;
  REG_MPWMSM19_SCR = uVar1 & 0xf7ff;
  uVar1 = REG_MPWMSM19_SCR;
  REG_MPWMSM19_SCR = uVar1 & 0xfbff;
  uVar1 = REG_MDASM11_SCR;
  REG_MDASM11_SCR = uVar1 & 0xfff0;
  uVar1 = REG_MDASM12_SCR;
  REG_MDASM12_SCR = uVar1 & 0xfff0;
  uVar1 = REG_MDASM13_SCR;
  REG_MDASM13_SCR = uVar1 & 0xfff0;
  uVar1 = REG_MDASM14_SCR;
  REG_MDASM14_SCR = uVar1 & 0xfff0;
  uVar1 = REG_MDASM15_SCR;
  REG_MDASM15_SCR = uVar1 & 0xfff0;
  uVar1 = REG_MDASM27_SCR;
  REG_MDASM27_SCR = uVar1 & 0xfff0;
  uVar1 = REG_MDASM28_SCR;
  REG_MDASM28_SCR = uVar1 & 0xfff0;
  uVar1 = REG_MDASM29_SCR;
  REG_MDASM29_SCR = uVar1 & 0xfff0;
  uVar1 = REG_MDASM30_SCR;
  REG_MDASM30_SCR = uVar1 & 0xfff0;
  uVar1 = REG_MDASM31_SCR;
  REG_MDASM31_SCR = uVar1 & 0xfff0;
  uVar1 = REG_MIOS14TPCR;
  REG_MIOS14TPCR = uVar1 & 0xfffd;
  uVar1 = REG_MIOS14TPCR;
  REG_MIOS14TPCR = uVar1 & 0xfffe;
  REG_MPIOSMDR = 0;
  REG_MPIOSMDDR = 0x7e15;
  return;
}



// Initializes QADC A converter, port and command queue

void init_qadc_a(void)

{
  ushort uVar1;
  
  REG_QADC64MCR_A = 0x280;
  REG_QADC64MCR_A = 0x180;
  REG_QADC64INT_A = 0;
  Ram00304808 = 0;
  REG_PORTQA_A = 0;
  REG_PORTQB_A = 0;
  REG_QACR0_A = 0x13;
  REG_QACR1_A = 0x1100;
  REG_QACR2_A = 0x12;
  REG_QADCA_CCW0 = 0x2c;
  REG_QADCA_CCW1 = 0x2d;
  REG_QADCA_CCW2 = 0x2e;
  REG_QADCA_CCW3 = 0x2f;
  REG_QADCA_CCW4 = 0x30;
  REG_QADCA_CCW5 = 0x31;
  REG_QADCA_CCW6 = 0x32;
  REG_QADCA_CCW7 = 0x33;
  REG_QADCA_CCW8 = 0x34;
  REG_QADCA_CCW9 = 0x35;
  REG_QADCA_CCW10 = 0x36;
  REG_QADCA_CCW11 = 0x37;
  REG_QADCA_CCW12 = 0x38;
  REG_QADCA_CCW13 = 0x39;
  REG_QADCA_CCW14 = 0x3a;
  REG_QADCA_CCW15 = 0x3b;
  REG_QADCA_CCW16 = 0x3c;
  REG_QADCA_CCW17 = 0x3d;
  REG_QADCA_CCW18 = 0x3f;
  REG_QADCA_CCW19 = 0x3f;
  uVar1 = REG_QACR1_A;
  REG_QACR1_A = uVar1 & 0xdfff | 0x2000;
  do {
    uVar1 = REG_QASR0_A;
  } while (-1 < (short)uVar1);
  return;
}



// Initializes QADC B converter, port and command queue

void init_qadc_b(void)

{
  ushort uVar1;
  
  REG_QADC64MCR_B = 0x280;
  REG_QADC64MCR_B = 0x180;
  REG_QADC64INT_B = 0;
  Ram00304c08 = 0;
  REG_PORTQA_B = 0;
  REG_PORTQB_B = 0;
  REG_QACR0_B = 0x13;
  REG_QACR1_B = 0x1100;
  REG_QACR2_B = 0x12;
  REG_QADCB_CCW0 = 0x2c;
  REG_QADCB_CCW1 = 0x2d;
  REG_QADCB_CCW2 = 0x2e;
  REG_QADCB_CCW3 = 0x2f;
  REG_QADCB_CCW4 = 0x30;
  REG_QADCB_CCW5 = 0x31;
  REG_QADCB_CCW6 = 0x32;
  REG_QADCB_CCW7 = 0x33;
  REG_QADCB_CCW8 = 0x34;
  REG_QADCB_CCW9 = 0x35;
  REG_QADCB_CCW10 = 0x36;
  REG_QADCB_CCW11 = 0x3b;
  REG_QADCB_CCW12 = 0x3a;
  REG_QADCB_CCW13 = 0x39;
  REG_QADCB_CCW14 = 0x38;
  REG_QADCB_CCW15 = 0x37;
  REG_QADCB_CCW16 = 0x3c;
  REG_QADCB_CCW17 = 0x3d;
  REG_QADCB_CCW18 = 0x3f;
  uVar1 = REG_QACR1_B;
  REG_QACR1_B = uVar1 & 0xdfff | 0x2000;
  do {
    uVar1 = REG_QASR0_B;
  } while (-1 < (short)uVar1);
  return;
}



// Programs flash from the parsed sub-packet descriptors until the decrypted stream is exhausted

undefined4 efip_program_handler(void)

{
  int iVar1;
  undefined1 local_18 [20];
  
  do {
    iVar1 = next_bytes(local_18);
    if (iVar1 == 0) {
      return 1;
    }
    iVar1 = efip_parse_subpacket(local_18[0]);
  } while ((iVar1 == 0) ||
          (iVar1 = flash_program_word(*(undefined4 *)(iVar1 + 0x200),*(undefined4 *)(iVar1 + 0x204),
                                      *(undefined1 *)(iVar1 + 0x20d)), iVar1 != 0));
  return 0;
}



// WARNING: Inlined function: push_27to31
// WARNING: Inlined function: pop_27to31
// Processes the CRP upload: receives 0x70 frames

undefined4 efip_data_process(void)

{
  bool bVar1;
  bool bVar2;
  bool bVar3;
  byte *pbVar4;
  int iVar5;
  uint uVar6;
  char local_28 [20];
  
  bVar1 = false;
  bVar2 = false;
  bVar3 = false;
  do {
    pbVar4 = (byte *)efip_recv_frame();
    if (pbVar4 == (byte *)0x0) {
      return 0;
    }
  } while (pbVar4[1] != 0x70);
  uVar6 = *pbVar4 - 1 & 0xff;
  iVar5 = memcpy_checked(pbVar4 + 2,uVar6);
  if (iVar5 == 0) {
    DAT_003fe010 = DAT_003fe010 + uVar6;
    enc3by2_decrypt(pbVar4 + 2,uVar6);
    iVar5 = next_bytes(local_28);
    if (iVar5 == 0) {
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    if (local_28[0] != 'T') {
      efip_send_cmd_72_error();
      return 0;
    }
    iVar5 = next_bytes(local_28);
    if (iVar5 == 0) {
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    if (local_28[0] != '4') {
      efip_send_cmd_72_error();
      return 0;
    }
    iVar5 = next_bytes(local_28);
    if (iVar5 == 0) {
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    if (local_28[0] != 'E') {
      efip_send_cmd_72_error();
      return 0;
    }
    iVar5 = next_bytes(local_28);
    if (iVar5 == 0) {
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    if (local_28[0] != '_') {
      efip_send_cmd_72_error();
      return 0;
    }
    iVar5 = next_bytes(local_28);
    if (iVar5 == 0) {
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    bVar1 = local_28[0] == '1';
    iVar5 = next_bytes(local_28);
    if (iVar5 == 0) {
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    bVar2 = local_28[0] == '1';
    iVar5 = next_bytes(local_28);
    if (iVar5 == 0) {
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    bVar3 = local_28[0] == '1';
    iVar5 = next_bytes(local_28);
    if (iVar5 == 0) {
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    iVar5 = next_bytes(local_28);
    if (iVar5 == 0) {
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    iVar5 = next_bytes(local_28);
    if (iVar5 == 0) {
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    iVar5 = next_bytes(local_28);
    if (iVar5 == 0) {
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    iVar5 = efip_program_handler();
    if (iVar5 == 0) {
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
  }
  uVar6 = efip_total_size_get();
  if (uVar6 < DAT_003fe010) {
    efip_send_cmd_72_error();
  }
  else {
    if (bVar2) {
      flash_erase(0x3f,0);
    }
    if (bVar1) {
      flash_erase(0x80,0);
    }
    if (bVar3) {
      flash_erase(0x40,0);
    }
    efip_send_cmd_72_ok();
    do {
      while( true ) {
        pbVar4 = (byte *)efip_recv_frame();
        if (pbVar4 == (byte *)0x0) {
          return 0;
        }
        if (pbVar4[1] != 0x70) break;
        uVar6 = *pbVar4 - 1 & 0xff;
        iVar5 = memcpy_checked(pbVar4 + 2,uVar6);
        if (iVar5 == 0) {
          DAT_003fe010 = DAT_003fe010 + uVar6;
          enc3by2_decrypt(pbVar4 + 2,uVar6);
          iVar5 = efip_program_handler();
          if (iVar5 == 0) {
            do {
                    // WARNING: Do nothing block with infinite loop
            } while( true );
          }
        }
        uVar6 = efip_total_size_get();
        if (uVar6 < DAT_003fe010) {
          efip_send_cmd_72_error();
          return 0;
        }
        efip_send_cmd_72_ok();
      }
      if (pbVar4[1] == 0x73) {
        iVar5 = efip_write_complete();
        if (iVar5 == 0) {
          efip_send_cmd_72_error();
          return 0;
        }
        efip_send_cmd_72_ok();
        return 1;
      }
    } while (pbVar4[1] != 0x71);
  }
  return 0;
}



// Waits for the enter-stage-II command: packet [01 71 72] -> ack 0x8D, packet with 0x81 -> switch
// baud and ack; 100 ms timeout -> boot application

void efip_enter_stage2(void)

{
  bool bVar1;
  int iVar2;
  char cVar4;
  undefined *puVar3;
  byte local_18 [12];
  
  bVar1 = false;
  timer_save(0);
  while ((iVar2 = efip_rx_ready(), iVar2 == 0 || (cVar4 = efip_recv_byte(), cVar4 != '\x01'))) {
    puVar3 = (undefined *)timer_elapsed(0);
    if (&UNK_0001869f < puVar3) {
      prog_entry_point();
      return;
    }
  }
  timer_save(0);
  do {
    iVar2 = efip_rx_ready();
    if (iVar2 != 0) {
      cVar4 = efip_recv_byte();
      if (cVar4 == 'q') {
LAB_00005628:
        timer_save(0);
        do {
          iVar2 = efip_rx_ready();
          if (iVar2 != 0) {
            local_18[0] = efip_recv_byte();
            if (local_18[0] == 0x72) {
              if (!bVar1) {
                local_18[0] = 0x8d;
                efip_send_bytes(local_18,1);
                return;
              }
            }
            else if ((local_18[0] == 0x81) && (bVar1)) {
              efip_baud_29069();
              local_18[0] = ~local_18[0];
              efip_send_bytes(local_18,1);
              return;
            }
          }
          puVar3 = (undefined *)timer_elapsed(0);
          if (&UNK_0001869f < puVar3) {
            prog_entry_point();
            return;
          }
        } while( true );
      }
      if (cVar4 == -0x7f) {
        bVar1 = true;
        goto LAB_00005628;
      }
    }
    puVar3 = (undefined *)timer_elapsed(0);
    if (&UNK_0001869f < puVar3) {
      prog_entry_point();
      return;
    }
  } while( true );
}



// CRP01 session: init SCI/buffers/enc3by2 key

void efip_session_run(void)

{
  int iVar1;
  
  timer_enable_timebase();
  REG_SWSR = 0x556c;
  REG_SWSR = 0xaa39;
  init_sci1();
  REG_SWSR = 0x556c;
  REG_SWSR = 0xaa39;
  efip_recv_state_reset();
  efip_buffer_clear();
  enc3by2_key_init();
  efip_parse_subpacket_reset();
  DAT_003fe010 = 0;
  efip_enter_stage2();
  iVar1 = efip_data_process();
  if (iVar1 == 0) {
    do {
                    // WARNING: Do nothing block with infinite loop
    } while( true );
  }
  return;
}



// Initializes QSCI1 (K-Line UART): baud 0x2A, 8N1, sends three sync bytes and drains RX

void init_sci1(void)

{
  ushort uVar1;
  
  REG_SCC1R1 = 0;
  REG_SCC1R0 = 0x2a;
  uVar1 = REG_SCC1R1;
  REG_SCC1R1 = uVar1 & 0xfff7 | 8;
  uVar1 = REG_SCC1R1;
  REG_SCC1R1 = uVar1 & 0xfffb;
  REG_SC1DR = 0;
  do {
    uVar1 = REG_SC1SR;
  } while ((uVar1 >> 7 & 1) == 0);
  REG_SC1DR = 0;
  do {
    uVar1 = REG_SC1SR;
  } while ((uVar1 >> 7 & 1) == 0);
  REG_SC1DR = 0;
  do {
    uVar1 = REG_SC1SR;
  } while ((uVar1 >> 7 & 1) == 0);
  while (uVar1 = REG_SC1SR, (uVar1 >> 6 & 1) != 0) {
    uVar1 = REG_SC1DR;
  }
  uVar1 = REG_SCC1R1;
  REG_SCC1R1 = uVar1 & 0xfffb | 4;
  return;
}



// Sets SCI1 baud rate (SCC1R0 = 0x2B, the 29069 baud stage-II speed requested by cmd 0x81)

void efip_baud_29069(void)

{
  REG_SCC1R0 = 0x2b;
  return;
}



// Transmits a byte buffer over SCI1 (K-Line): enables TX, waits TDRE per byte, waits TC at the end

void efip_send_bytes(byte *param_1,int param_2)

{
  byte bVar1;
  ushort uVar2;
  int iVar3;
  
  uVar2 = REG_SCC1R1;
  REG_SCC1R1 = uVar2 & 0xfffb;
  uVar2 = REG_SC1SR;
  if ((uVar2 >> 6 & 1) != 0) {
    uVar2 = REG_SC1DR;
  }
  iVar3 = 0;
  do {
    do {
      uVar2 = REG_SC1SR;
    } while ((uVar2 >> 8 & 1) == 0);
    bVar1 = *param_1;
    param_1 = param_1 + 1;
    REG_SC1DR = (ushort)bVar1;
    iVar3 = iVar3 + 1;
  } while (iVar3 != param_2);
  do {
    uVar2 = REG_SC1SR;
  } while ((uVar2 >> 7 & 1) == 0);
  uVar2 = REG_SCC1R1;
  REG_SCC1R1 = uVar2 & 0xfffb | 4;
  return;
}



// Returns true when the SCI1 receive data register is full (SC1SR RDRF)

bool efip_rx_ready(void)

{
  ushort uVar1;
  
  REG_SWSR = 0x556c;
  REG_SWSR = 0xaa39;
  uVar1 = REG_SC1SR;
  return (uVar1 >> 6 & 1) != 0;
}



// Blocking receive of one byte from SCI1 (K-Line), waits for RDRF

ushort efip_recv_byte(void)

{
  ushort uVar1;
  int iVar2;
  
  do {
    iVar2 = efip_rx_ready();
  } while (iVar2 == 0);
  uVar1 = REG_SC1DR;
  return uVar1 & 0xff;
}



// Resets the K-Line frame receiver state machine (byte position state)

void efip_recv_state_reset(void)

{
  DAT_003fe01c = 0;
  return;
}



// Byte-level K-Line frame receiver state machine: length, cmd, data, sum; verifies checksum and
// replies with the inverted sum after 10 ms

undefined4 efip_recv_packet(byte param_1)

{
  uint uVar1;
  byte *pbVar2;
  
  if (0x100 < DAT_003fe01c) {
    DAT_003fe01c = 0;
  }
  uVar1 = timer_elapsed(2);
  if (10000 < uVar1) {
    DAT_003fe01c = 0;
  }
  timer_save(2);
  if (DAT_003fe01c == 0) {
    DAT_003fe01c = 1;
    DAT_003fe018 = param_1;
    DAT_003fe020 = param_1;
  }
  else if (DAT_003fe01c == 1) {
    DAT_003fe01c = 2;
    DAT_003fe018 = DAT_003fe018 + param_1;
    bRam003fe021 = param_1;
  }
  else if ((DAT_003fe01c < 2) || ((int)(uint)DAT_003fe020 < DAT_003fe01c)) {
    if ((int)(DAT_003fe020 + 1) < DAT_003fe01c) {
      DAT_003fe01c = 0;
    }
    else {
      (&DAT_003fe020)[DAT_003fe01c] = param_1;
      DAT_003fe01c = 0;
      if (param_1 == DAT_003fe018) {
        delay_blocking_ms(10);
        DAT_003fe018 = ~DAT_003fe018;
        efip_send_bytes(&DAT_003fe018,1);
        return 1;
      }
    }
  }
  else {
    pbVar2 = &DAT_003fe020 + DAT_003fe01c;
    DAT_003fe01c = DAT_003fe01c + 1;
    *pbVar2 = param_1;
    DAT_003fe018 = DAT_003fe018 + param_1;
  }
  return 0;
}



// WARNING: Inlined function: push_27to31
// WARNING: Inlined function: pop_27to31
// Sends a K-Line packet: length, data, checksum, after a 10 ms delay

byte efip_send_packet(byte *param_1,byte param_2)

{
  byte bVar1;
  byte *pbVar2;
  int iVar3;
  byte *pbVar4;
  
  *param_1 = param_2;
  pbVar4 = param_1 + param_2 + 1;
  *pbVar4 = 0;
  pbVar2 = param_1;
  for (iVar3 = 0; iVar3 <= (int)(uint)param_2; iVar3 = iVar3 + 1) {
    bVar1 = *pbVar2;
    pbVar2 = pbVar2 + 1;
    *pbVar4 = *pbVar4 + bVar1;
  }
  delay_blocking_ms(10);
  efip_send_bytes(param_1,param_2 + 2);
  return *pbVar4;
}



// Waits for a complete K-Line frame (5 s timeout), returns the frame buffer or NULL on timeout

undefined1 * efip_recv_frame(void)

{
  int iVar1;
  undefined1 uVar3;
  uint uVar2;
  
  timer_save(3);
  do {
    while (iVar1 = efip_rx_ready(), iVar1 == 0) {
      uVar2 = timer_elapsed(3);
      if (5000000 < uVar2) {
        return (undefined1 *)0x0;
      }
    }
    uVar3 = efip_recv_byte();
    iVar1 = efip_recv_packet(uVar3);
  } while (iVar1 == 0);
  return &DAT_003fe020;
}



// Sends a K-Line message and waits for the inverted-checksum acknowledgement (50 ms timeout)

undefined4 efip_send_msg(undefined4 param_1,undefined4 param_2)

{
  byte bVar3;
  int iVar1;
  byte bVar4;
  uint uVar2;
  
  bVar3 = efip_send_packet(param_1,param_2);
  timer_save(3);
  do {
    while (iVar1 = efip_rx_ready(), iVar1 == 0) {
      uVar2 = timer_elapsed(3);
      if (49999 < uVar2) {
        if (true) {
          return 0;
        }
        bVar3 = efip_send_packet(param_1,param_2);
        timer_save(3);
      }
    }
    bVar4 = efip_recv_byte();
  } while (bVar3 != (byte)~bVar4);
  return 1;
}



// Sends the 0x72 response frame with error code 0 (ok, next frame)

void efip_send_cmd_72_ok(void)

{
  undefined1 uStack_18;
  undefined1 local_17;
  undefined1 local_16;
  
  local_17 = 0x72;
  local_16 = 0;
  efip_send_msg(&uStack_18,2);
  return;
}



// Sends the 0x72 response frame with an error code

void efip_send_cmd_72_error(void)

{
  undefined1 uStack_18;
  undefined1 local_17;
  undefined1 local_16;
  
  local_17 = 0x72;
  local_16 = 0xff;
  efip_send_msg(&uStack_18,2);
  return;
}



// Pushes one decrypted byte into the ring buffer (write side of next_bytes)

void next_bytes_put(undefined1 param_1)

{
  if (DAT_003fe388 < 0x200) {
    (&DAT_003fe170)[DAT_003fe384] = param_1;
    DAT_003fe384 = DAT_003fe384 + 1 & 0x1ff;
    DAT_003fe388 = DAT_003fe388 + 1;
  }
  return;
}



// Pulls the next decrypted byte from the ring buffer (512 bytes at 0x3FE170)

bool next_bytes(undefined1 *param_1)

{
  bool bVar1;
  
  bVar1 = DAT_003fe388 != 0;
  if (bVar1) {
    *param_1 = (&DAT_003fe170)[DAT_003fe386];
    DAT_003fe386 = DAT_003fe386 + 1 & 0x1ff;
    DAT_003fe388 = DAT_003fe388 + -1;
  }
  return bVar1;
}



// Decrypt step: w_sum = (cipher * key_mult) % key_mod, greedy bit decomposition over the 16-entry
// table, fails when the remainder is non-zero

uint enc3by2_decrypt_bits(uint param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  byte abStack_19 [17];
  
  uVar2 = 0;
  uVar1 = (param_1 - (param_1 / DAT_003fe168) * DAT_003fe168) * DAT_003fe16c;
  uVar1 = uVar1 - (uVar1 / DAT_003fe168) * DAT_003fe168;
  for (iVar3 = 0xf; -1 < iVar3; iVar3 = iVar3 + -1) {
    if (uVar1 < (uint)(&DAT_003fe128)[iVar3]) {
      abStack_19[iVar3 + 1] = 0;
    }
    else {
      abStack_19[iVar3 + 1] = 1;
    }
    uVar1 = uVar1 - (uint)abStack_19[iVar3 + 1] * (&DAT_003fe128)[iVar3];
  }
  if (uVar1 == 0) {
    for (uVar1 = 0; (int)uVar1 < 0x10; uVar1 = uVar1 + 1) {
      uVar2 = uVar2 + ((uint)abStack_19[uVar1 + 1] << (uVar1 & 0x3f)) & 0xffff;
    }
  }
  return uVar2;
}



// Decrypt step: plain word = (bit_flag - K) & 0xFFFF

int enc3by2_decrypt_word(undefined4 param_1)

{
  int iVar1;
  
  iVar1 = enc3by2_decrypt_bits(param_1);
  return iVar1 - (uint)DAT_003fe382;
}



// Initializes the CRP01 3by2 key: K = ~(9744 + sum of the 4 size bytes), key
// table/modulus/multiplier into RAM (crp01.py: T4e key at 0x6118)

void enc3by2_key_init(void)

{
  DAT_003fe374 = 0;
  DAT_003fe384 = 0;
  DAT_003fe386 = 0;
  DAT_003fe388 = 0;
  flash_data_write_i = 0;
  DAT_003fe16c = 0xc6e;
  DAT_003fe168 = &DAT_0005d017;
  DAT_003fe128 = 7;
  DAT_003fe12c = 0xf;
  DAT_003fe130 = 0x17;
  DAT_003fe134 = 0x2f;
  DAT_003fe138 = 0x5d;
  DAT_003fe13c = 0xba;
  DAT_003fe140 = 0x174;
  DAT_003fe144 = 0x2e8;
  DAT_003fe148 = 0x5d0;
  DAT_003fe14c = 0xba0;
  DAT_003fe150 = &DAT_00001740;
  DAT_003fe154 = &DAT_00002e80;
  DAT_003fe158 = 0x5d00;
  DAT_003fe15c = &DAT_0000ba00;
  DAT_003fe160 = &DAT_00017401;
  DAT_003fe164 = &DAT_0002e801;
  return;
}



// Decrypts the CRP data with the 3by2 algorithm (3 cipher bytes -> 2 plain bytes per step) and
// stores plain bytes into the next_bytes ring buffer

void enc3by2_decrypt(int param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  
  for (iVar2 = 0; iVar2 < param_2; iVar2 = iVar2 + 1) {
    if (DAT_003fe374 == 0) {
      DAT_003fe370 = (uint)*(byte *)(param_1 + iVar2) << 0x18;
      DAT_003fe382 = *(byte *)(param_1 + iVar2) + 0x2610;
      DAT_003fe374 = 1;
    }
    else if (DAT_003fe374 == 1) {
      DAT_003fe370 = DAT_003fe370 + (uint)*(byte *)(param_1 + iVar2) * 0x10000;
      DAT_003fe382 = DAT_003fe382 + *(byte *)(param_1 + iVar2);
      DAT_003fe374 = 2;
    }
    else if (DAT_003fe374 == 2) {
      DAT_003fe370 = DAT_003fe370 + (uint)*(byte *)(param_1 + iVar2) * 0x100;
      DAT_003fe382 = DAT_003fe382 + *(byte *)(param_1 + iVar2);
      DAT_003fe374 = 3;
    }
    else if (DAT_003fe374 == 3) {
      DAT_003fe370 = DAT_003fe370 + (uint)*(byte *)(param_1 + iVar2);
      DAT_003fe382 = ~(DAT_003fe382 + *(byte *)(param_1 + iVar2));
      DAT_003fe374 = 4;
    }
    else if ((DAT_003fe374 < 4) || (0xf < DAT_003fe374)) {
      if ((DAT_003fe374 < 0x10) || (DAT_003fe370 - 4U <= DAT_003fe374)) {
        if (DAT_003fe370 - 4U <= DAT_003fe374) {
          DAT_003fe374 = DAT_003fe374 + 1;
        }
      }
      else {
        uVar1 = (DAT_003fe374 - 0x10) % 3;
        if (uVar1 == 1) {
          DAT_003fe378 = DAT_003fe378 + (uint)*(byte *)(param_1 + iVar2) * 0x100;
        }
        else if (uVar1 == 0) {
          if (true) {
            DAT_003fe378 = (uint)*(byte *)(param_1 + iVar2);
          }
        }
        else if (uVar1 < 3) {
          DAT_003fe378 = DAT_003fe378 + (uint)*(byte *)(param_1 + iVar2) * 0x10000;
          DAT_003fe37c = enc3by2_decrypt_word(DAT_003fe378);
          next_bytes_put(DAT_003fe37c & 0xff);
          next_bytes_put((int)(uint)DAT_003fe37c >> 8);
          if (DAT_003fe374 == DAT_003fe370 - 5U) {
            flash_data_read_i = (DAT_003fe37c & 0xff) + (short)(((int)(uint)DAT_003fe37c >> 8) << 8)
            ;
          }
          else {
            flash_data_write_i = flash_data_write_i + (DAT_003fe37c & 0xff) + (DAT_003fe37c >> 8);
          }
        }
        DAT_003fe374 = DAT_003fe374 + 1;
      }
    }
    else {
      DAT_003fe374 = DAT_003fe374 + 1;
    }
  }
  return;
}



// Returns the CRP total size (first 4 bytes of the CRP data, big endian)

undefined4 efip_total_size_get(void)

{
  return DAT_003fe370;
}



// Returns true when all buffered data has been written to flash/EEPROM

bool efip_write_complete(void)

{
  return flash_data_read_i == flash_data_write_i;
}



// Clears the CRP frame accumulation buffer (0x102 bytes at 0x3FE390)

void efip_buffer_clear(void)

{
  int iVar1;
  
  for (iVar1 = 0; iVar1 < 0x102; iVar1 = iVar1 + 1) {
    (&DAT_003fe390)[iVar1] = 0;
  }
  return;
}



// Copies a frame into the accumulation buffer unless identical to the previous frame
// (retransmission filter)

bool memcpy_checked(void *param_1,size_t param_2)

{
  int iVar1;
  
  iVar1 = cmp_buffer(&DAT_003fe390,param_1,param_2);
  if (iVar1 == 0) {
    memcpy(&DAT_003fe390,param_1,param_2);
  }
  return iVar1 != 0;
}



// Resets the sub-packet parser state

void efip_parse_subpacket_reset(void)

{
  DAT_003fe6a0 = 0;
  return;
}



// Parses one CRP01 sub-packet record (0x55 header, length, 3-byte BE destination address, data,
// checksum) into a program descriptor

undefined1 * efip_parse_subpacket(byte param_1)

{
  byte *pbVar1;
  
  if (0x1fe < (int)DAT_003fe6a0) {
    DAT_003fe6a0 = 0;
  }
  if (DAT_003fe6a0 == 0) {
    if (param_1 == 0x55) {
      DAT_003fe6a0 = 1;
      DAT_003fe498 = 0x55;
      DAT_003fe6a6 = 0x55;
    }
  }
  else if (DAT_003fe6a0 == 1) {
    DAT_003fe6a0 = 2;
    DAT_003fe6a6 = DAT_003fe6a6 + param_1;
    DAT_003fe6a4 = param_1;
    bRam003fe499 = param_1;
  }
  else if (DAT_003fe6a0 == 2) {
    DAT_003fe6a0 = 3;
    DAT_003fe698 = (uint)param_1 << 0x10;
    DAT_003fe6a6 = DAT_003fe6a6 + param_1;
    bRam003fe49a = param_1;
  }
  else if (DAT_003fe6a0 == 3) {
    DAT_003fe6a0 = 4;
    DAT_003fe698 = DAT_003fe698 + (uint)param_1 * 0x100;
    DAT_003fe6a6 = DAT_003fe6a6 + param_1;
    bRam003fe49b = param_1;
  }
  else if (DAT_003fe6a0 == 4) {
    DAT_003fe6a0 = 5;
    DAT_003fe698 = DAT_003fe698 + (uint)param_1;
    DAT_003fe6a6 = DAT_003fe6a6 + param_1;
    bRam003fe49c = param_1;
  }
  else if (((int)DAT_003fe6a0 < 5) || ((int)(uint)DAT_003fe6a4 <= (int)DAT_003fe6a0)) {
    if (DAT_003fe6a0 == DAT_003fe6a4) {
      if (DAT_003fe6a6 == param_1) {
        DAT_003fe69c = &DAT_003fe49d;
        DAT_003fe6a0 = 0;
        DAT_003fe6a5 = DAT_003fe6a4 - 5;
        return &DAT_003fe498;
      }
      DAT_003fe6a0 = 0;
      return (undefined1 *)0x0;
    }
    DAT_003fe6a0 = 0;
  }
  else {
    pbVar1 = &DAT_003fe498 + DAT_003fe6a0;
    DAT_003fe6a0 = DAT_003fe6a0 + 1;
    *pbVar1 = param_1;
    DAT_003fe6a6 = DAT_003fe6a6 + param_1;
  }
  return (undefined1 *)0x0;
}



// Copies n bytes from src to dst

void * memcpy(void *__dest,void *__src,size_t __n)

{
  undefined1 uVar1;
  uint uVar2;
  
  while (uVar2 = __n & 0xffff, __n = __n - 1, uVar2 != 0) {
                    // WARNING: Load size is inaccurate
    uVar1 = *__src;
    __src = (void *)((int)__src + 1);
    *(undefined1 *)__dest = uVar1;
    __dest = (void *)((int)__dest + 1);
  }
  return __dest;
}



// Compares two buffers, returns 0 when equal (used to drop retransmitted frames)

undefined4 cmp_buffer(char *param_1,char *param_2,ushort param_3)

{
  char cVar1;
  char cVar2;
  ushort uVar3;
  
  uVar3 = 0;
  while( true ) {
    if (param_3 <= uVar3) {
      return 1;
    }
    cVar1 = *param_1;
    param_1 = param_1 + 1;
    cVar2 = *param_2;
    param_2 = param_2 + 1;
    if (cVar1 != cVar2) break;
    uVar3 = uVar3 + 1;
  }
  return 0;
}



// QADC B channel 11 check used by watchdog_retrigger: clears MPWMSM16 SCR bit 11 when the reading
// is below 0x200

void watchdog_qadc_check(void)

{
  ushort uVar1;
  
  uVar1 = REG_QADCB_RJURR11;
  if (uVar1 < 0x200) {
    uVar1 = REG_MPWMSM16_SCR;
    REG_MPWMSM16_SCR = uVar1 & 0xf7ff;
  }
  return;
}



// Retriggers hardware watchdog (SWSR sequence 0x556C/0xAA39), then checks QADC B channel 11 and
// clears MPWMSM16 SCR bit 11 when below 0x200

void watchdog_retrigger(void)

{
  REG_SWSR = 0x556c;
  REG_SWSR = 0xaa39;
  watchdog_qadc_check();
  return;
}



// Saves current timebase counter value for delay measurement

void delay_start(void)

{
  DAT_003fe6a8 = timer_read_tbl();
  return;
}



// Waits until specified number of timebase ticks have elapsed since delay_start

void delay_wait(uint param_1)

{
  int iVar1;
  
  do {
    iVar1 = timer_read_tbl();
  } while ((uint)(iVar1 - DAT_003fe6a8) <= param_1);
  return;
}



// Short delay (300 ticks) between HC08 serial bit transitions

void hc08_bit_delay(void)

{
  delay_blocking(300);
  return;
}



// Configures MDASM28 for input capture mode (HC08 serial receive)

void hc08_mdasm_init_capture(void)

{
  ushort uVar1;
  
  REG_MDASM28_SCR = 0;
  REG_MDASM28_AR = 0;
  REG_MDASM28_BR = 0;
  uVar1 = REG_MDASM28_SCR;
  REG_MDASM28_SCR = uVar1 & 0xfff0 | 4;
  return;
}



// Configures MDASM28 for edge detect mode (HC08 serial idle)

void hc08_mdasm_init_edge(void)

{
  ushort uVar1;
  
  REG_MDASM28_SCR = 0;
  uVar1 = REG_MDASM28_SCR;
  REG_MDASM28_SCR = uVar1 & 0xfff0 | 3;
  return;
}



// Sets MDASM28 output high (HC08 serial line)

void hc08_mdasm_set_high(void)

{
  ushort uVar1;
  
  uVar1 = REG_MDASM28_SCR;
  REG_MDASM28_SCR = uVar1 & 0xfbff | 0x400;
  return;
}



// Sets MDASM28 output low (HC08 serial line)

void hc08_mdasm_set_low(void)

{
  ushort uVar1;
  
  uVar1 = REG_MDASM28_SCR;
  REG_MDASM28_SCR = uVar1 & 0xfdff | 0x200;
  return;
}



// Reads MDASM28 input state (HC08 serial line level)

ushort hc08_mdasm_read(void)

{
  ushort uVar1;
  
  uVar1 = REG_MDASM28_SCR;
  return uVar1 >> 0xf;
}



// Starts MPWMSM2 output for HC08 clock/power signal

void hc08_mpwm_start(void)

{
  ushort uVar1;
  
  uVar1 = REG_MPIOSMDR;
  REG_MPIOSMDR = uVar1 & 0xbfff | 0x4000;
  return;
}



// Sets system clock register (SCCR = 0x4024100)

void init_clock(void)

{
  REG_SCCR = 0x4024100;
  return;
}



// Initializes HC08 interface: configures MIOS, clock, MDASM28, GPIO pins, EEPROM WP, MPWMSM2

void hc08_init(void)

{
  byte bVar1;
  ushort uVar2;
  
  DAT_003fe6ac = PTR_DAT_00021fec;
  init_mios();
  init_qadc_a();
  init_qadc_b();
  init_clock();
  hc08_mdasm_init_edge();
  uVar2 = Ram00304808;
  Ram00304808 = uVar2 & 0xf7ff | 0x800;
  uVar2 = Ram00304808;
  Ram00304808 = uVar2 & 0xffef | 0x10;
  uVar2 = Ram00304808;
  Ram00304808 = uVar2 & 0xffdf | 0x20;
  bVar1 = REG_PORTQA_A;
  REG_PORTQA_A = bVar1 & 0xf7 | 8;
  bVar1 = REG_PORTQB_A;
  REG_PORTQB_A = bVar1 & 0xef;
  bVar1 = REG_PORTQB_A;
  REG_PORTQB_A = bVar1 & 0xdf;
  delay_blocking(10000);
  uVar2 = REG_MPIOSMDR;
  REG_MPIOSMDR = uVar2 & 0xbfff;
  uVar2 = REG_MPIOSMDDR;
  REG_MPIOSMDDR = uVar2 | 0x4000;
  uVar2 = REG_MPWMSM2_SCR;
  REG_MPWMSM2_SCR = uVar2 & 0xff00 | 0xec;
  uVar2 = REG_MPWMSM2_SCR;
  REG_MPWMSM2_SCR = uVar2 & 0xefff;
  uVar2 = REG_MPWMSM2_SCR;
  REG_MPWMSM2_SCR = uVar2 & 0xbfff | 0x4000;
  uVar2 = REG_MPWMSM2_SCR;
  REG_MPWMSM2_SCR = uVar2 & 0xf7ff | 0x800;
  uVar2 = REG_MPWMSM2_SCR;
  REG_MPWMSM2_SCR = uVar2 & 0xfbff;
  return;
}



// Sends one byte to HC08 via bit-banged serial on MDASM28 (start bit, 8 data bits, stop bit)

void hc08_send_byte(uint param_1)

{
  hc08_mdasm_init_capture();
  hc08_mdasm_set_high();
  delay_start();
  hc08_mdasm_set_low();
  delay_wait(0x19);
  if ((param_1 & 1) == 0) {
    hc08_mdasm_set_low();
  }
  else {
    hc08_mdasm_set_high();
  }
  delay_wait(0x32);
  if ((param_1 & 2) == 0) {
    hc08_mdasm_set_low();
  }
  else {
    hc08_mdasm_set_high();
  }
  delay_wait(0x4b);
  if ((param_1 & 4) == 0) {
    hc08_mdasm_set_low();
  }
  else {
    hc08_mdasm_set_high();
  }
  delay_wait(100);
  if ((param_1 & 8) == 0) {
    hc08_mdasm_set_low();
  }
  else {
    hc08_mdasm_set_high();
  }
  delay_wait(0x7d);
  if ((param_1 & 0x10) == 0) {
    hc08_mdasm_set_low();
  }
  else {
    hc08_mdasm_set_high();
  }
  delay_wait(0x96);
  if ((param_1 & 0x20) == 0) {
    hc08_mdasm_set_low();
  }
  else {
    hc08_mdasm_set_high();
  }
  delay_wait(0xaf);
  if ((param_1 & 0x40) == 0) {
    hc08_mdasm_set_low();
  }
  else {
    hc08_mdasm_set_high();
  }
  delay_wait(200);
  if ((param_1 & 0x80) == 0) {
    hc08_mdasm_set_low();
  }
  else {
    hc08_mdasm_set_high();
  }
  delay_wait(0xe1);
  hc08_mdasm_set_high();
  delay_wait(0xfa);
  hc08_mdasm_init_edge();
  return;
}



// Receives one byte from HC08 via bit-banged serial on MDASM28, samples 8 data bits plus stop bit

uint hc08_recv_byte(void)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = hc08_mdasm_read();
  if (iVar1 != 0) {
    timer_save(0);
    do {
      iVar1 = hc08_mdasm_read();
      if (iVar1 == 0) {
        delay_start();
        delay_wait(0x25);
        iVar1 = hc08_mdasm_read();
        uVar2 = (uint)(iVar1 != 0);
        delay_wait(0x3e);
        iVar1 = hc08_mdasm_read();
        if (iVar1 != 0) {
          uVar2 = uVar2 | 2;
        }
        delay_wait(0x57);
        iVar1 = hc08_mdasm_read();
        if (iVar1 != 0) {
          uVar2 = uVar2 | 4;
        }
        delay_wait(0x70);
        iVar1 = hc08_mdasm_read();
        if (iVar1 != 0) {
          uVar2 = uVar2 | 8;
        }
        delay_wait(0x89);
        iVar1 = hc08_mdasm_read();
        if (iVar1 != 0) {
          uVar2 = uVar2 | 0x10;
        }
        delay_wait(0xa2);
        iVar1 = hc08_mdasm_read();
        if (iVar1 != 0) {
          uVar2 = uVar2 | 0x20;
        }
        delay_wait(0xbb);
        iVar1 = hc08_mdasm_read();
        if (iVar1 != 0) {
          uVar2 = uVar2 | 0x40;
        }
        delay_wait(0xd4);
        iVar1 = hc08_mdasm_read();
        if (iVar1 != 0) {
          uVar2 = uVar2 | 0x80;
        }
        delay_wait(0xed);
        iVar1 = hc08_mdasm_read();
        if (iVar1 == 0) {
          uVar2 = uVar2 | 0x8000;
        }
        delay_wait(0xfa);
        return uVar2;
      }
      uVar2 = timer_elapsed(0);
    } while (uVar2 < 0xf4241);
  }
  return 0xffffffff;
}



// HC08 passphrase authentication: sends "EFI Srl " (0x45 0x46 0x49 0x20 0x53 0x72 0x6C 0x20) and
// verifies echo

undefined4 hc08_authenticate(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  undefined4 uVar10;
  
  delay_blocking(600000);
  hc08_mpwm_start();
  delay_blocking(600000);
  hc08_send_byte(0xff);
  iVar1 = hc08_recv_byte();
  hc08_send_byte(0xff);
  iVar2 = hc08_recv_byte();
  hc08_send_byte(0xff);
  iVar3 = hc08_recv_byte();
  hc08_send_byte(0xff);
  iVar4 = hc08_recv_byte();
  hc08_send_byte(0xff);
  iVar5 = hc08_recv_byte();
  hc08_send_byte(0xff);
  iVar6 = hc08_recv_byte();
  hc08_send_byte(0xff);
  iVar7 = hc08_recv_byte();
  hc08_send_byte(0xff);
  iVar8 = hc08_recv_byte();
  iVar9 = hc08_recv_byte();
  if ((((((iVar1 == 0xff) && (iVar2 == 0xff)) && (iVar3 == 0xff)) &&
       ((iVar4 == 0xff && (iVar5 == 0xff)))) &&
      ((iVar6 == 0xff && ((iVar7 == 0xff && (iVar8 == 0xff)))))) && (iVar9 == 0x8000)) {
    uVar10 = 1;
  }
  else {
    uVar10 = 0;
  }
  return uVar10;
}



// Reads one byte from HC08 at specified address (sends cmd 0x4A, address high/low, reads data)

undefined4 hc08_read_byte(uint param_1,undefined1 *param_2)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  
  hc08_bit_delay();
  hc08_send_byte(0x4a);
  iVar1 = hc08_recv_byte();
  if (iVar1 == 0x4a) {
    iVar4 = (int)(param_1 & 0xffff) >> 8;
    hc08_send_byte(iVar4);
    iVar1 = hc08_recv_byte();
    if (iVar4 == iVar1) {
      hc08_send_byte(param_1 & 0xff);
      uVar3 = hc08_recv_byte();
      if ((param_1 & 0xff) == uVar3) {
        iVar1 = hc08_recv_byte();
        if (iVar1 == -1) {
          uVar2 = 0;
        }
        else {
          *param_2 = (char)iVar1;
          uVar2 = 1;
        }
      }
      else {
        uVar2 = 0;
      }
    }
    else {
      uVar2 = 0;
    }
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}



// Writes one byte to HC08 at specified address (sends cmd 0x49, address, data, verifies echo)

undefined4 hc08_write_byte(uint param_1,byte param_2)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  
  hc08_bit_delay();
  hc08_send_byte(0x49);
  iVar1 = hc08_recv_byte();
  if (iVar1 == 0x49) {
    iVar4 = (int)(param_1 & 0xffff) >> 8;
    hc08_send_byte(iVar4);
    iVar1 = hc08_recv_byte();
    if (iVar4 == iVar1) {
      hc08_send_byte(param_1 & 0xff);
      uVar3 = hc08_recv_byte();
      if ((param_1 & 0xff) == uVar3) {
        hc08_send_byte((uint)param_2);
        uVar3 = hc08_recv_byte();
        if (param_2 == uVar3) {
          uVar2 = 1;
        }
        else {
          uVar2 = 0;
        }
      }
      else {
        uVar2 = 0;
      }
    }
    else {
      uVar2 = 0;
    }
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}



// Reads 16-bit word from HC08 (sends cmd 0x1A, reads two bytes)

undefined4 hc08_read_word(ushort *param_1)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  
  hc08_bit_delay();
  hc08_send_byte(0x1a);
  iVar1 = hc08_recv_byte();
  if (iVar1 == 0x1a) {
    iVar1 = hc08_recv_byte();
    if (iVar1 == -1) {
      uVar2 = 0;
    }
    else {
      iVar3 = hc08_recv_byte();
      if (iVar3 == -1) {
        uVar2 = 0;
      }
      else {
        *param_1 = (ushort)(iVar1 << 8) | (ushort)iVar3;
        uVar2 = 1;
      }
    }
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}



// Writes single data byte to HC08 (sends cmd 0x19, data, verifies echo)

undefined4 hc08_write_data(byte param_1)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  
  hc08_bit_delay();
  hc08_send_byte(0x19);
  iVar1 = hc08_recv_byte();
  if (iVar1 == 0x19) {
    hc08_send_byte((uint)param_1);
    uVar3 = hc08_recv_byte();
    if (param_1 == uVar3) {
      uVar2 = 1;
    }
    else {
      uVar2 = 0;
    }
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}



// Reads HC08 security register (sends cmd 0x0C, reads 16-bit value)

undefined4 hc08_read_security(ushort *param_1)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  
  hc08_bit_delay();
  hc08_send_byte(0xc);
  iVar1 = hc08_recv_byte();
  iVar2 = hc08_recv_byte();
  if (iVar2 == -1) {
    uVar3 = 0;
  }
  else {
    iVar4 = hc08_recv_byte();
    if (iVar4 == -1) {
      uVar3 = 0;
    }
    else if (iVar1 == 0xc) {
      *param_1 = (ushort)iVar4;
      *param_1 = *param_1 | (ushort)(iVar2 << 8);
      uVar3 = 1;
    }
    else {
      uVar3 = 0;
    }
  }
  return uVar3;
}



// Sends verify passphrase command (0x28) to HC08 and checks acknowledgment

bool hc08_verify_passphrase(void)

{
  int iVar1;
  
  hc08_bit_delay();
  hc08_send_byte(0x28);
  iVar1 = hc08_recv_byte();
  return iVar1 == 0x28;
}



// Checks the HC08 flash is blank by reading bytes 0xFFF6-0xFFFD and testing for 0xFF

undefined4 hc08_is_blank(void)

{
  int iVar1;
  undefined *puVar2;
  char local_18 [20];
  
  puVar2 = &DAT_0000fff6;
  while( true ) {
    if (0xfffd < ((uint)puVar2 & 0xffff)) {
      return 1;
    }
    iVar1 = hc08_read_byte(puVar2,local_18);
    if (iVar1 == 0) break;
    if (local_18[0] != -1) {
      return 0;
    }
    puVar2 = puVar2 + 1;
  }
  return 0;
}



// Verifies HC08 flash write by reading back first byte and comparing remaining words

undefined4 hc08_verify_write(undefined2 param_1,void *param_2,byte param_3)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  undefined1 local_50 [2];
  undefined1 auStack_4e [70];
  
  if ((param_3 < 0x41) && (1 < param_3)) {
    iVar2 = hc08_read_byte(param_1,auStack_4e);
    if (iVar2 == 0) {
      uVar1 = 0;
    }
    else {
      for (iVar2 = 1; iVar2 < (int)(uint)param_3; iVar2 = iVar2 + 2) {
        iVar3 = hc08_read_word(local_50);
        if (iVar3 == 0) {
          return 0;
        }
        auStack_4e[iVar2] = local_50[0];
        auStack_4e[iVar2 + 1] = local_50[1];
      }
      iVar2 = memcmp(auStack_4e,param_2,(uint)param_3);
      if (iVar2 == 0) {
        uVar1 = 1;
      }
      else {
        uVar1 = 0;
      }
    }
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}



// Programs HC08 flash: unlocks (0x45,0x01,0x10,0xCC,0xFF,0x28), sends address/size/data, triggers
// programming

undefined4 hc08_program_flash(undefined4 param_1,int param_2,uint param_3)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  short local_128;
  undefined1 local_125;
  undefined1 local_124;
  undefined1 local_123;
  undefined1 local_122;
  undefined1 local_121;
  undefined1 local_116;
  undefined1 local_115;
  undefined1 local_114;
  undefined1 local_113;
  
  if ((param_3 & 0xff) < 0x41) {
    iVar2 = hc08_write_byte(0x100,0x45);
    if (iVar2 == 0) {
      uVar1 = 0;
    }
    else {
      iVar2 = hc08_write_data(1);
      if (iVar2 == 0) {
        uVar1 = 0;
      }
      else {
        iVar2 = hc08_write_data(0x10);
        if (iVar2 == 0) {
          uVar1 = 0;
        }
        else {
          iVar2 = hc08_write_data(0xcc);
          if (iVar2 == 0) {
            uVar1 = 0;
          }
          else {
            iVar2 = hc08_write_data(0xff);
            if (iVar2 == 0) {
              uVar1 = 0;
            }
            else {
              iVar2 = hc08_write_data(0x28);
              if (iVar2 == 0) {
                uVar1 = 0;
              }
              else {
                local_116 = 0x20;
                local_115 = (undefined1)param_3;
                local_114 = (undefined1)((uint)param_1 >> 8);
                local_113 = (undefined1)param_1;
                iVar2 = hc08_write_byte(0x110,0x20);
                if (iVar2 == 0) {
                  uVar1 = 0;
                }
                else {
                  iVar2 = hc08_write_data(local_115);
                  if (iVar2 == 0) {
                    uVar1 = 0;
                  }
                  else {
                    iVar2 = hc08_write_data(local_114);
                    if (iVar2 == 0) {
                      uVar1 = 0;
                    }
                    else {
                      iVar2 = hc08_write_data(local_113);
                      if (iVar2 == 0) {
                        uVar1 = 0;
                      }
                      else {
                        for (iVar2 = 0; iVar2 < (int)(param_3 & 0xff); iVar2 = iVar2 + 1) {
                          iVar3 = hc08_write_data(*(undefined1 *)(param_2 + iVar2));
                          if (iVar3 == 0) {
                            return 0;
                          }
                        }
                        iVar2 = hc08_read_security(&local_128);
                        if (iVar2 == 0) {
                          uVar1 = 0;
                        }
                        else {
                          local_125 = 0x79;
                          local_124 = 0;
                          local_123 = 0;
                          local_122 = 1;
                          local_121 = 0;
                          iVar2 = hc08_write_byte(local_128 + 1,0x79);
                          if (iVar2 == 0) {
                            uVar1 = 0;
                          }
                          else {
                            iVar2 = hc08_write_data(local_124);
                            if (iVar2 == 0) {
                              uVar1 = 0;
                            }
                            else {
                              iVar2 = hc08_write_data(local_123);
                              if (iVar2 == 0) {
                                uVar1 = 0;
                              }
                              else {
                                iVar2 = hc08_write_data(local_122);
                                if (iVar2 == 0) {
                                  uVar1 = 0;
                                }
                                else {
                                  iVar2 = hc08_write_data(local_121);
                                  if (iVar2 == 0) {
                                    uVar1 = 0;
                                  }
                                  else {
                                    iVar2 = hc08_verify_passphrase();
                                    if (iVar2 == 0) {
                                      uVar1 = 0;
                                    }
                                    else {
                                      delay_blocking(20000);
                                      iVar2 = hc08_verify_write(param_1,param_2,param_3);
                                      if (iVar2 == 0) {
                                        uVar1 = 0;
                                      }
                                      else {
                                        uVar1 = 1;
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}



// Mass erases HC08 flash: unlocks, sends erase command with address 0xFFFF, triggers erase sequence

undefined4 hc08_mass_erase(void)

{
  int iVar1;
  undefined4 uVar2;
  short local_118;
  undefined1 local_115;
  undefined1 local_114;
  undefined1 local_113;
  undefined1 local_112;
  undefined1 local_111;
  undefined1 local_106;
  undefined1 local_105;
  undefined1 local_104;
  undefined1 local_103;
  
  iVar1 = hc08_write_byte(0x100,0x45);
  if (iVar1 == 0) {
    uVar2 = 0;
  }
  else {
    iVar1 = hc08_write_byte(0x101,1);
    if (iVar1 == 0) {
      uVar2 = 0;
    }
    else {
      iVar1 = hc08_write_byte(0x102,0x10);
      if (iVar1 == 0) {
        uVar2 = 0;
      }
      else {
        iVar1 = hc08_write_byte(0x103,0xcc);
        if (iVar1 == 0) {
          uVar2 = 0;
        }
        else {
          iVar1 = hc08_write_byte(0x104,0xff);
          if (iVar1 == 0) {
            uVar2 = 0;
          }
          else {
            iVar1 = hc08_write_byte(0x105,0x2c);
            if (iVar1 == 0) {
              uVar2 = 0;
            }
            else {
              local_106 = 0x20;
              local_105 = 0;
              local_104 = 0xff;
              local_103 = 0xff;
              iVar1 = hc08_write_byte(0x110,0x20);
              if (iVar1 == 0) {
                uVar2 = 0;
              }
              else {
                iVar1 = hc08_write_byte(0x111,local_105);
                if (iVar1 == 0) {
                  uVar2 = 0;
                }
                else {
                  iVar1 = hc08_write_byte(0x112,local_104);
                  if (iVar1 == 0) {
                    uVar2 = 0;
                  }
                  else {
                    iVar1 = hc08_write_byte(0x113,local_103);
                    if (iVar1 == 0) {
                      uVar2 = 0;
                    }
                    else {
                      iVar1 = hc08_read_security(&local_118);
                      if (iVar1 == 0) {
                        uVar2 = 0;
                      }
                      else {
                        local_115 = 0x79;
                        local_114 = 0;
                        local_113 = 0;
                        local_112 = 1;
                        local_111 = 0;
                        iVar1 = hc08_write_byte(local_118 + 1,0x79);
                        if (iVar1 == 0) {
                          uVar2 = 0;
                        }
                        else {
                          iVar1 = hc08_write_byte(local_118 + 2,local_114);
                          if (iVar1 == 0) {
                            uVar2 = 0;
                          }
                          else {
                            iVar1 = hc08_write_byte(local_118 + 3,local_113);
                            if (iVar1 == 0) {
                              uVar2 = 0;
                            }
                            else {
                              iVar1 = hc08_write_byte(local_118 + 4,local_112);
                              if (iVar1 == 0) {
                                uVar2 = 0;
                              }
                              else {
                                iVar1 = hc08_write_byte(local_118 + 5,local_111);
                                if (iVar1 == 0) {
                                  uVar2 = 0;
                                }
                                else {
                                  iVar1 = hc08_verify_passphrase();
                                  if (iVar1 == 0) {
                                    uVar2 = 0;
                                  }
                                  else {
                                    uVar2 = 1;
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return uVar2;
}



// HC08 passphrase authentication with up to 3 retries

int hc08_authenticate_retry(void)

{
  int unaff_r30;
  int iVar1;
  
  iVar1 = 0;
  while ((iVar1 < 3 && (unaff_r30 = hc08_authenticate(), unaff_r30 == 0))) {
    delay_blocking(&DAT_0000c350);
    iVar1 = iVar1 + 1;
  }
  return unaff_r30;
}



// HC08 flash programming with up to 3 retries

int hc08_program_flash_retry(undefined2 param_1,undefined4 param_2,undefined1 param_3)

{
  int unaff_r30;
  int iVar1;
  
  iVar1 = 0;
  while ((iVar1 < 3 && (unaff_r30 = hc08_program_flash(param_1,param_2,param_3), unaff_r30 == 0))) {
    delay_blocking(&DAT_0000c350);
    iVar1 = iVar1 + 1;
  }
  return unaff_r30;
}



// HC08 mass erase with up to 3 retries

int hc08_mass_erase_retry(void)

{
  int unaff_r30;
  int iVar1;
  
  iVar1 = 0;
  while ((iVar1 < 3 && (unaff_r30 = hc08_mass_erase(), unaff_r30 == 0))) {
    delay_blocking(&DAT_0000c350);
    iVar1 = iVar1 + 1;
  }
  return unaff_r30;
}



// HC08 erase sequence: watchdog, init, authenticate retry, mass erase retry (K-Line split of
// boot08's hc08_program_sequence first half)

void hc08_erase_sequence(void)

{
  int iVar1;
  
  watchdog_retrigger();
  hc08_init();
  watchdog_retrigger();
  iVar1 = hc08_authenticate_retry();
  if (iVar1 != 0) {
    hc08_mass_erase_retry();
  }
  return;
}



// Full HC08 programming sequence: init hardware, authenticate, verify/erase, program flash blocks,
// write markers

undefined4 hc08_program_sequence(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined *puVar3;
  
  watchdog_retrigger();
  hc08_init();
  watchdog_retrigger();
  iVar1 = hc08_authenticate_retry();
  if (iVar1 == 0) {
    uVar2 = 0;
  }
  else {
    iVar1 = hc08_is_blank();
    if (iVar1 == 0) {
      iVar1 = hc08_mass_erase_retry();
      if (iVar1 != 0) {
        do {
          watchdog_retrigger();
        } while( true );
      }
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    for (puVar3 = &DAT_0000dc00; (int)puVar3 < 0xfc00; puVar3 = puVar3 + 0x40) {
      watchdog_retrigger();
      iVar1 = hc08_program_flash_retry((uint)puVar3 & 0xffff,puVar3 + DAT_003fe6ac + -0xdc00,0x40);
      if (iVar1 == 0) {
        watchdog_retrigger();
        iVar1 = hc08_mass_erase_retry();
        if (iVar1 != 0) {
          do {
            watchdog_retrigger();
          } while( true );
        }
        do {
                    // WARNING: Do nothing block with infinite loop
        } while( true );
      }
    }
    watchdog_retrigger();
    iVar1 = hc08_program_flash_retry(&DAT_0000ffdc,DAT_003fe6ac + 0x23dc,0x24);
    if (iVar1 == 0) {
      watchdog_retrigger();
      iVar1 = hc08_mass_erase_retry();
      if (iVar1 != 0) {
        do {
          watchdog_retrigger();
        } while( true );
      }
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    watchdog_retrigger();
    uVar2 = 1;
  }
  return uVar2;
}



// Byte copy with the destination aligned up to 4 bytes (flash programming alignment)

void memcpy_aligned(int param_1,undefined1 *param_2,int param_3)

{
  bool bVar1;
  undefined1 uVar2;
  undefined1 *puVar3;
  
  puVar3 = (undefined1 *)(param_1 + 3U & 0xfffffffc);
  param_3 = param_3 - (int)param_2;
  while (bVar1 = param_3 != 0, param_3 = param_3 + -1, bVar1) {
    uVar2 = *param_2;
    param_2 = param_2 + 1;
    *puVar3 = uVar2;
    puVar3 = puVar3 + 1;
  }
  return;
}



// Compares two memory blocks, returns -1/0/1 at first mismatch

int memcmp(void *__s1,void *__s2,size_t __n)

{
  int iVar1;
  byte *pbVar2;
  byte *pbVar3;
  
  pbVar2 = (byte *)((int)__s1 + -1);
  pbVar3 = (byte *)((int)__s2 + -1);
  iVar1 = __n + 1;
  do {
    iVar1 = iVar1 + -1;
    if (iVar1 == 0) {
      return 0;
    }
    pbVar2 = pbVar2 + 1;
    pbVar3 = pbVar3 + 1;
  } while (*pbVar2 == *pbVar3);
  if (*pbVar3 <= *pbVar2) {
    return 1;
  }
  return -1;
}



// WARNING: This is an inlined function
// WARNING: Unknown calling convention -- yet parameter storage is locked
// Compiler helper: saves registers r27-r31 to the caller stack frame

void push_27to31(void)

{
  int in_r11;
  undefined4 unaff_r27;
  undefined4 unaff_r28;
  undefined4 unaff_r29;
  undefined4 unaff_r30;
  undefined4 unaff_r31;
  
  *(undefined4 *)(in_r11 + -0x14) = unaff_r27;
  *(undefined4 *)(in_r11 + -0x10) = unaff_r28;
  *(undefined4 *)(in_r11 + -0xc) = unaff_r29;
  *(undefined4 *)(in_r11 + -8) = unaff_r30;
  *(undefined4 *)(in_r11 + -4) = unaff_r31;
  return;
}



// WARNING: This is an inlined function
// Compiler helper: restores registers r27-r31 from the caller stack frame

void pop_27to31(void)

{
  return;
}



// Runs the CRP01 K-Line flasher session, then handles a pending HC08 update (H308CODE magic) and
// boots the application (RAM copy)

void efip_flasher_run_ram(void)

{
  efip_session_run_ram();
  if (((DAT_00021fe0 == 0x48433038) && (DAT_00021fe4 == 0x434f4445)) &&
     (DAT_00021fe8 == -0x55555556)) {
    hc08_erase_sequence();
  }
  prog_entry_point();
  return;
}



// Waits for the L-Line to read low (MPWMSM3 SCR bit 15), servicing the watchdog up to 5000
// iterations; returns 0 when low (CRP01 tool requests the flasher), 1 on timeout (normal boot) (RAM
// copy)

undefined4 boot_l_line_low_wait_ram(void)

{
  ushort uVar1;
  uint uVar2;
  
  uVar2 = 0;
  while( true ) {
    if (4999 < uVar2) {
      return 1;
    }
    REG_SWSR = 0x556c;
    REG_SWSR = 0xaa39;
    uVar1 = REG_MPWMSM3_SCR;
    if (-1 < (short)uVar1) break;
    uVar2 = uVar2 + 1;
  }
  return 0;
}



// Stage2 boot: L-Line low -> run the CRP01 flasher from RAM; H308CODE magic -> HC08 programming +
// update marker; then boot the application (prog_entry_point) (RAM copy)

void main_ram(void)

{
  int iVar1;
  
  iVar1 = boot_l_line_low_wait_ram();
  if (iVar1 == 0) {
    stage2_to_ram_ram();
    func_0x007ec1dc();
  }
  if (((DAT_00021fe0 == 0x48433038) && (DAT_00021fe4 == 0x434f4445)) &&
     (DAT_00021fe8 == -0x55555556)) {
    REG_SWSR = 0x556c;
    REG_SWSR = 0xaa39;
    timer_enable_timebase_ram();
    REG_SWSR = 0x556c;
    REG_SWSR = 0xaa39;
    iVar1 = hc08_program_sequence_ram();
    if (iVar1 != 0) {
      flash_write_update_marker_ram();
    }
  }
  prog_entry_point();
  return;
}



// Programs N halfwords (16-bit) to flash via UC3F controller, verifies after write (RAM copy)

undefined4 flash_program_halfwords_ram(short *param_1,short *param_2,int param_3)

{
  bool bVar1;
  short sVar2;
  short sVar3;
  uint uVar4;
  short *psVar5;
  short *psVar6;
  int iVar7;
  
  uVar4 = REG_UC3FCTL;
  if (((uVar4 >> 0x1c & 1) == 1) && (uVar4 = REG_UC3FCTL, (uVar4 >> 0x1b & 1) == 1)) {
    uVar4 = REG_UC3FMCR;
    REG_UC3FMCR = uVar4 & 0xffffff00;
    uVar4 = REG_UC3FMCRE;
    REG_UC3FMCRE = uVar4 & 0xfcffffff;
    uVar4 = REG_UC3FMCRE;
    REG_UC3FMCRE = uVar4 & 0x3fffffff | 0xc0000000;
    uVar4 = REG_UC3FCTL;
    REG_UC3FCTL = uVar4 & 0xfffcffff | 0x30000;
    uVar4 = REG_UC3FCTL;
    REG_UC3FCTL = uVar4 & 0xffff00ff | 0xff00;
    uVar4 = REG_UC3FCTL;
    REG_UC3FCTL = uVar4 & 0xfffffffd;
    uVar4 = REG_UC3FCTL;
    REG_UC3FCTL = uVar4 & 0xfffffffb;
    uVar4 = REG_UC3FCTL;
    REG_UC3FCTL = uVar4 & 0xfffffffd | 2;
    psVar5 = param_2;
    psVar6 = param_1;
    iVar7 = param_3;
    while (bVar1 = iVar7 != 0, iVar7 = iVar7 + -1, bVar1) {
      sVar2 = *psVar5;
      psVar5 = psVar5 + 1;
      *psVar6 = sVar2;
      psVar6 = psVar6 + 1;
      uVar4 = REG_UC3FCTL;
      REG_UC3FCTL = uVar4 & 0xfffffffe | 1;
      do {
        uVar4 = REG_UC3FCTL;
      } while ((int)uVar4 < 0);
      do {
        uVar4 = REG_UC3FCTL;
      } while ((uVar4 >> 0x1e & 1) == 0);
      uVar4 = REG_UC3FCTL;
      REG_UC3FCTL = uVar4 & 0xfffffffe;
    }
    uVar4 = REG_UC3FCTL;
    REG_UC3FCTL = uVar4 & 0xfffffffd;
    uVar4 = REG_UC3FCTL;
    REG_UC3FCTL = uVar4 & 0xffff00ff;
    uVar4 = REG_UC3FCTL;
    REG_UC3FCTL = uVar4 & 0xfffcffff;
    do {
      bVar1 = param_3 == 0;
      param_3 = param_3 + -1;
      if (bVar1) {
        return 1;
      }
      sVar2 = *param_1;
      param_1 = param_1 + 1;
      sVar3 = *param_2;
      param_2 = param_2 + 1;
    } while (sVar2 == sVar3);
  }
  return 0;
}



// Erases flash block via UC3F controller using block select and address mask parameters (RAM copy)

undefined4 flash_erase_ram(uint param_1,uint param_2)

{
  uint uVar1;
  undefined4 uVar2;
  
  uVar1 = REG_UC3FCTL;
  if (((uVar1 >> 0x1c & 1) == 1) && (uVar1 = REG_UC3FCTL, (uVar1 >> 0x1b & 1) == 1)) {
    uVar1 = REG_UC3FMCR;
    REG_UC3FMCR = uVar1 & 0xffffff00;
    uVar1 = REG_UC3FMCRE;
    REG_UC3FMCRE = uVar1 & 0xfcffffff;
    uVar1 = REG_UC3FMCRE;
    REG_UC3FMCRE = uVar1 & 0x3fffffff | 0xc0000000;
    uVar1 = REG_UC3FCTL;
    REG_UC3FCTL = (param_2 & 3) << 0x10 | uVar1 & 0xfffcffff;
    uVar1 = REG_UC3FCTL;
    REG_UC3FCTL = (param_1 & 0xff) << 8 | uVar1 & 0xffff00ff;
    uVar1 = REG_UC3FCTL;
    REG_UC3FCTL = uVar1 & 0xfffffffd;
    uVar1 = REG_UC3FCTL;
    REG_UC3FCTL = uVar1 & 0xfffffffb | 4;
    uVar1 = REG_UC3FCTL;
    REG_UC3FCTL = uVar1 & 0xfffffffd | 2;
    uRam00000000 = 0;
    uVar1 = REG_UC3FCTL;
    REG_UC3FCTL = uVar1 & 0xfffffffe | 1;
    while (uVar1 = REG_UC3FCTL, (int)uVar1 < 0) {
      REG_SWSR = 0x556c;
      REG_SWSR = 0xaa39;
    }
    while (uVar1 = REG_UC3FCTL, (uVar1 >> 0x1e & 1) == 0) {
      REG_SWSR = 0x556c;
      REG_SWSR = 0xaa39;
    }
    uVar1 = REG_UC3FCTL;
    REG_UC3FCTL = uVar1 & 0xfffffffe;
    uVar1 = REG_UC3FCTL;
    REG_UC3FCTL = uVar1 & 0xfffffffd;
    uVar1 = REG_UC3FCTL;
    REG_UC3FCTL = uVar1 & 0xffff00ff;
    uVar1 = REG_UC3FCTL;
    REG_UC3FCTL = uVar1 & 0xfffcffff;
    uVar2 = 1;
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}



// Writes the 0x2222 update marker to flash 0x21FE8/0x21FEA to signal a successful update (RAM copy)

void flash_write_update_marker_ram(void)

{
  undefined2 local_8 [4];
  
  local_8[0] = 0x2222;
  REG_SWSR = 0x556c;
  REG_SWSR = 0xaa39;
  memcpy_aligned_ram(0x3f8000,&DAT_00004354,&DAT_00004884);
  REG_SWSR = 0x556c;
  REG_SWSR = 0xaa39;
  flash_program_halfwords_ram(&DAT_00021fe8,local_8,1);
  flash_program_halfwords_ram(0x21fea,local_8,1);
  return;
}



// Copies the stage2 flasher image (flash 0x4000-0x9FFF, 0x6000 bytes) to RAM 0x3F8000 so the
// flasher can run from RAM during flash programming (relative branches keep the copy executable)
// (RAM copy)

void stage2_to_ram_ram(void)

{
  bool bVar1;
  undefined1 uVar2;
  int iVar3;
  undefined1 *puVar4;
  undefined1 *puVar5;
  
  puVar5 = &DAT_003f8000;
  puVar4 = &LAB_00004000;
  iVar3 = 0x6000;
  while (bVar1 = iVar3 != 0, iVar3 = iVar3 + -1, bVar1) {
    REG_SWSR = 0x556c;
    REG_SWSR = 0xaa39;
    uVar2 = *puVar4;
    puVar4 = puVar4 + 1;
    *puVar5 = uVar2;
    puVar5 = puVar5 + 1;
  }
  return;
}



// Programs a single 32-bit word to flash via the UC3F controller (RAM copy)

void flash_program_word_ram(undefined4 param_1,undefined4 param_2,uint param_3)

{
  flash_program_halfwords_ram(param_1,param_2,param_3 >> 1);
  return;
}



// Enables timebase timer by setting TBSCR enable bit (RAM copy)

void timer_enable_timebase_ram(void)

{
  ushort uVar1;
  
  uVar1 = REG_TBSCR;
  REG_TBSCR = uVar1 | 1;
  return;
}



// Saves current timebase value to indexed timer slot (RAM copy)

void timer_save_ram(ushort param_1)

{
  undefined4 uVar1;
  
  uVar1 = timer_read_tbl_ram();
  *(undefined4 *)((uint)param_1 * 4 + 0x3fe000) = uVar1;
  return;
}



// Returns elapsed time since timer_save for indexed timer slot (RAM copy)

int timer_elapsed_ram(ushort param_1)

{
  int iVar1;
  
  iVar1 = timer_read_tbl_ram();
  return iVar1 - *(int *)((uint)param_1 * 4 + 0x3fe000);
}



// Reads PowerPC Time Base Lower register (TBL) (RAM copy)

undefined4 timer_read_tbl_ram(void)

{
  undefined4 uVar1;
  
  uVar1 = TBLr;
  return uVar1;
}



// Blocking delay in milliseconds (param x 1000 timer ticks) with watchdog retrigger (RAM copy)

void delay_blocking_ms_ram(int param_1)

{
  uint uVar1;
  
  timer_save_ram(1);
  while (uVar1 = timer_elapsed_ram(1), uVar1 <= (uint)(param_1 * 1000)) {
    REG_SWSR = 0x556c;
    REG_SWSR = 0xaa39;
  }
  return;
}



// Blocking delay using timer slot 1 with watchdog retrigger (RAM copy)

void delay_blocking_ram(uint param_1)

{
  uint uVar1;
  
  timer_save_ram(1);
  while (uVar1 = timer_elapsed_ram(1), uVar1 <= param_1) {
    REG_SWSR = 0x556c;
    REG_SWSR = 0xaa39;
  }
  return;
}



// Initializes MIOS: configures PWM channels 0-3/16-19, MDASM channels 11-15/27-31, MPIO
// data/direction registers (RAM copy)

void init_mios_ram(void)

{
  ushort uVar1;
  
  uVar1 = REG_MCPSMSCR;
  REG_MCPSMSCR = uVar1 & 0x7fff | 0x8000;
  uVar1 = REG_MCPSMSCR;
  REG_MCPSMSCR = uVar1 & 0xbfff;
  uVar1 = REG_MCPSMSCR;
  REG_MCPSMSCR = uVar1 & 0xfff0 | 2;
  uVar1 = REG_MPWMSM0_SCR;
  REG_MPWMSM0_SCR = uVar1 & 0xff00 | 0xec;
  uVar1 = REG_MPWMSM0_SCR;
  REG_MPWMSM0_SCR = uVar1 & 0xefff;
  uVar1 = REG_MPWMSM0_SCR;
  REG_MPWMSM0_SCR = uVar1 & 0xbfff | 0x4000;
  uVar1 = REG_MPWMSM0_SCR;
  REG_MPWMSM0_SCR = uVar1 & 0xf7ff;
  uVar1 = REG_MPWMSM0_SCR;
  REG_MPWMSM0_SCR = uVar1 & 0xfbff;
  uVar1 = REG_MPWMSM1_SCR;
  REG_MPWMSM1_SCR = uVar1 & 0xff00 | 0xec;
  uVar1 = REG_MPWMSM1_SCR;
  REG_MPWMSM1_SCR = uVar1 & 0xefff;
  uVar1 = REG_MPWMSM1_SCR;
  REG_MPWMSM1_SCR = uVar1 & 0xbfff | 0x4000;
  uVar1 = REG_MPWMSM1_SCR;
  REG_MPWMSM1_SCR = uVar1 & 0xf7ff;
  uVar1 = REG_MPWMSM1_SCR;
  REG_MPWMSM1_SCR = uVar1 & 0xfbff;
  uVar1 = REG_MPWMSM2_SCR;
  REG_MPWMSM2_SCR = uVar1 & 0xff00 | 0xec;
  uVar1 = REG_MPWMSM2_SCR;
  REG_MPWMSM2_SCR = uVar1 & 0xefff;
  uVar1 = REG_MPWMSM2_SCR;
  REG_MPWMSM2_SCR = uVar1 & 0xbfff;
  uVar1 = REG_MPWMSM2_SCR;
  REG_MPWMSM2_SCR = uVar1 & 0xf7ff;
  uVar1 = REG_MPWMSM2_SCR;
  REG_MPWMSM2_SCR = uVar1 & 0xfbff;
  uVar1 = REG_MPWMSM3_SCR;
  REG_MPWMSM3_SCR = uVar1 & 0xff00 | 0xec;
  uVar1 = REG_MPWMSM3_SCR;
  REG_MPWMSM3_SCR = uVar1 & 0xefff;
  uVar1 = REG_MPWMSM3_SCR;
  REG_MPWMSM3_SCR = uVar1 & 0xbfff;
  uVar1 = REG_MPWMSM3_SCR;
  REG_MPWMSM3_SCR = uVar1 & 0xf7ff;
  uVar1 = REG_MPWMSM3_SCR;
  REG_MPWMSM3_SCR = uVar1 & 0xfbff;
  uVar1 = REG_MPWMSM16_SCR;
  REG_MPWMSM16_SCR = uVar1 & 0xff00 | 0xec;
  uVar1 = REG_MPWMSM16_SCR;
  REG_MPWMSM16_SCR = uVar1 & 0xefff;
  uVar1 = REG_MPWMSM16_SCR;
  REG_MPWMSM16_SCR = uVar1 & 0xbfff | 0x4000;
  uVar1 = REG_MPWMSM16_SCR;
  REG_MPWMSM16_SCR = uVar1 & 0xf7ff;
  uVar1 = REG_MPWMSM16_SCR;
  REG_MPWMSM16_SCR = uVar1 & 0xfbff;
  uVar1 = REG_MPWMSM17_SCR;
  REG_MPWMSM17_SCR = uVar1 & 0xff00 | 0xec;
  uVar1 = REG_MPWMSM17_SCR;
  REG_MPWMSM17_SCR = uVar1 & 0xefff;
  uVar1 = REG_MPWMSM17_SCR;
  REG_MPWMSM17_SCR = uVar1 & 0xbfff | 0x4000;
  uVar1 = REG_MPWMSM17_SCR;
  REG_MPWMSM17_SCR = uVar1 & 0xf7ff;
  uVar1 = REG_MPWMSM17_SCR;
  REG_MPWMSM17_SCR = uVar1 & 0xfbff;
  uVar1 = REG_MPWMSM18_SCR;
  REG_MPWMSM18_SCR = uVar1 & 0xff00 | 0xec;
  uVar1 = REG_MPWMSM18_SCR;
  REG_MPWMSM18_SCR = uVar1 & 0xefff;
  uVar1 = REG_MPWMSM18_SCR;
  REG_MPWMSM18_SCR = uVar1 & 0xbfff | 0x4000;
  uVar1 = REG_MPWMSM18_SCR;
  REG_MPWMSM18_SCR = uVar1 & 0xf7ff;
  uVar1 = REG_MPWMSM18_SCR;
  REG_MPWMSM18_SCR = uVar1 & 0xfbff | 0x400;
  REG_MPWMSM18_PERR = 1000;
  REG_MPWMSM18_PULR = 500;
  uVar1 = REG_MPWMSM19_SCR;
  REG_MPWMSM19_SCR = uVar1 & 0xff00 | 0xec;
  uVar1 = REG_MPWMSM19_SCR;
  REG_MPWMSM19_SCR = uVar1 & 0xefff;
  uVar1 = REG_MPWMSM19_SCR;
  REG_MPWMSM19_SCR = uVar1 & 0xbfff | 0x4000;
  uVar1 = REG_MPWMSM19_SCR;
  REG_MPWMSM19_SCR = uVar1 & 0xf7ff;
  uVar1 = REG_MPWMSM19_SCR;
  REG_MPWMSM19_SCR = uVar1 & 0xfbff;
  uVar1 = REG_MDASM11_SCR;
  REG_MDASM11_SCR = uVar1 & 0xfff0;
  uVar1 = REG_MDASM12_SCR;
  REG_MDASM12_SCR = uVar1 & 0xfff0;
  uVar1 = REG_MDASM13_SCR;
  REG_MDASM13_SCR = uVar1 & 0xfff0;
  uVar1 = REG_MDASM14_SCR;
  REG_MDASM14_SCR = uVar1 & 0xfff0;
  uVar1 = REG_MDASM15_SCR;
  REG_MDASM15_SCR = uVar1 & 0xfff0;
  uVar1 = REG_MDASM27_SCR;
  REG_MDASM27_SCR = uVar1 & 0xfff0;
  uVar1 = REG_MDASM28_SCR;
  REG_MDASM28_SCR = uVar1 & 0xfff0;
  uVar1 = REG_MDASM29_SCR;
  REG_MDASM29_SCR = uVar1 & 0xfff0;
  uVar1 = REG_MDASM30_SCR;
  REG_MDASM30_SCR = uVar1 & 0xfff0;
  uVar1 = REG_MDASM31_SCR;
  REG_MDASM31_SCR = uVar1 & 0xfff0;
  uVar1 = REG_MIOS14TPCR;
  REG_MIOS14TPCR = uVar1 & 0xfffd;
  uVar1 = REG_MIOS14TPCR;
  REG_MIOS14TPCR = uVar1 & 0xfffe;
  REG_MPIOSMDR = 0;
  REG_MPIOSMDDR = 0x7e15;
  return;
}



// Initializes QADC A converter, port and command queue (RAM copy)

void init_qadc_a_ram(void)

{
  ushort uVar1;
  
  REG_QADC64MCR_A = 0x280;
  REG_QADC64MCR_A = 0x180;
  REG_QADC64INT_A = 0;
  Ram00304808 = 0;
  REG_PORTQA_A = 0;
  REG_PORTQB_A = 0;
  REG_QACR0_A = 0x13;
  REG_QACR1_A = 0x1100;
  REG_QACR2_A = 0x12;
  REG_QADCA_CCW0 = 0x2c;
  REG_QADCA_CCW1 = 0x2d;
  REG_QADCA_CCW2 = 0x2e;
  REG_QADCA_CCW3 = 0x2f;
  REG_QADCA_CCW4 = 0x30;
  REG_QADCA_CCW5 = 0x31;
  REG_QADCA_CCW6 = 0x32;
  REG_QADCA_CCW7 = 0x33;
  REG_QADCA_CCW8 = 0x34;
  REG_QADCA_CCW9 = 0x35;
  REG_QADCA_CCW10 = 0x36;
  REG_QADCA_CCW11 = 0x37;
  REG_QADCA_CCW12 = 0x38;
  REG_QADCA_CCW13 = 0x39;
  REG_QADCA_CCW14 = 0x3a;
  REG_QADCA_CCW15 = 0x3b;
  REG_QADCA_CCW16 = 0x3c;
  REG_QADCA_CCW17 = 0x3d;
  REG_QADCA_CCW18 = 0x3f;
  REG_QADCA_CCW19 = 0x3f;
  uVar1 = REG_QACR1_A;
  REG_QACR1_A = uVar1 & 0xdfff | 0x2000;
  do {
    uVar1 = REG_QASR0_A;
  } while (-1 < (short)uVar1);
  return;
}



// Initializes QADC B converter, port and command queue (RAM copy)

void init_qadc_b_ram(void)

{
  ushort uVar1;
  
  REG_QADC64MCR_B = 0x280;
  REG_QADC64MCR_B = 0x180;
  REG_QADC64INT_B = 0;
  Ram00304c08 = 0;
  REG_PORTQA_B = 0;
  REG_PORTQB_B = 0;
  REG_QACR0_B = 0x13;
  REG_QACR1_B = 0x1100;
  REG_QACR2_B = 0x12;
  REG_QADCB_CCW0 = 0x2c;
  REG_QADCB_CCW1 = 0x2d;
  REG_QADCB_CCW2 = 0x2e;
  REG_QADCB_CCW3 = 0x2f;
  REG_QADCB_CCW4 = 0x30;
  REG_QADCB_CCW5 = 0x31;
  REG_QADCB_CCW6 = 0x32;
  REG_QADCB_CCW7 = 0x33;
  REG_QADCB_CCW8 = 0x34;
  REG_QADCB_CCW9 = 0x35;
  REG_QADCB_CCW10 = 0x36;
  REG_QADCB_CCW11 = 0x3b;
  REG_QADCB_CCW12 = 0x3a;
  REG_QADCB_CCW13 = 0x39;
  REG_QADCB_CCW14 = 0x38;
  REG_QADCB_CCW15 = 0x37;
  REG_QADCB_CCW16 = 0x3c;
  REG_QADCB_CCW17 = 0x3d;
  REG_QADCB_CCW18 = 0x3f;
  uVar1 = REG_QACR1_B;
  REG_QACR1_B = uVar1 & 0xdfff | 0x2000;
  do {
    uVar1 = REG_QASR0_B;
  } while (-1 < (short)uVar1);
  return;
}



// Programs flash from the parsed sub-packet descriptors until the decrypted stream is exhausted
// (RAM copy)

undefined4 efip_program_handler_ram(void)

{
  int iVar1;
  undefined1 local_18 [20];
  
  do {
    iVar1 = next_bytes_ram(local_18);
    if (iVar1 == 0) {
      return 1;
    }
    iVar1 = efip_parse_subpacket_ram(local_18[0]);
  } while ((iVar1 == 0) ||
          (iVar1 = flash_program_word_ram
                             (*(undefined4 *)(iVar1 + 0x200),*(undefined4 *)(iVar1 + 0x204),
                              *(undefined1 *)(iVar1 + 0x20d)), iVar1 != 0));
  return 0;
}



// WARNING: Inlined function: push_27to31_ram
// WARNING: Inlined function: pop_27to31_ram
// Processes the CRP upload: receives 0x70 frames

undefined4 efip_data_process_ram(void)

{
  bool bVar1;
  bool bVar2;
  bool bVar3;
  byte *pbVar4;
  int iVar5;
  uint uVar6;
  char acStack_28 [20];
  
  bVar1 = false;
  bVar2 = false;
  bVar3 = false;
  do {
    pbVar4 = (byte *)efip_recv_frame_ram();
    if (pbVar4 == (byte *)0x0) {
      return 0;
    }
  } while (pbVar4[1] != 0x70);
  uVar6 = *pbVar4 - 1 & 0xff;
  iVar5 = memcpy_checked_ram(pbVar4 + 2,uVar6);
  if (iVar5 == 0) {
    DAT_003fe010 = DAT_003fe010 + uVar6;
    enc3by2_decrypt_ram(pbVar4 + 2,uVar6);
    iVar5 = next_bytes_ram(acStack_28);
    if (iVar5 == 0) {
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    if (acStack_28[0] != 'T') {
      efip_send_cmd_72_error_ram();
      return 0;
    }
    iVar5 = next_bytes_ram(acStack_28);
    if (iVar5 == 0) {
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    if (acStack_28[0] != '4') {
      efip_send_cmd_72_error_ram();
      return 0;
    }
    iVar5 = next_bytes_ram(acStack_28);
    if (iVar5 == 0) {
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    if (acStack_28[0] != 'E') {
      efip_send_cmd_72_error_ram();
      return 0;
    }
    iVar5 = next_bytes_ram(acStack_28);
    if (iVar5 == 0) {
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    if (acStack_28[0] != '_') {
      efip_send_cmd_72_error_ram();
      return 0;
    }
    iVar5 = next_bytes_ram(acStack_28);
    if (iVar5 == 0) {
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    bVar1 = acStack_28[0] == '1';
    iVar5 = next_bytes_ram(acStack_28);
    if (iVar5 == 0) {
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    bVar2 = acStack_28[0] == '1';
    iVar5 = next_bytes_ram(acStack_28);
    if (iVar5 == 0) {
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    bVar3 = acStack_28[0] == '1';
    iVar5 = next_bytes_ram(acStack_28);
    if (iVar5 == 0) {
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    iVar5 = next_bytes_ram(acStack_28);
    if (iVar5 == 0) {
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    iVar5 = next_bytes_ram(acStack_28);
    if (iVar5 == 0) {
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    iVar5 = next_bytes_ram(acStack_28);
    if (iVar5 == 0) {
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    iVar5 = efip_program_handler_ram();
    if (iVar5 == 0) {
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
  }
  uVar6 = efip_total_size_get_ram();
  if (uVar6 < DAT_003fe010) {
    efip_send_cmd_72_error_ram();
  }
  else {
    if (bVar2) {
      flash_erase_ram(0x3f,0);
    }
    if (bVar1) {
      flash_erase_ram(0x80,0);
    }
    if (bVar3) {
      flash_erase_ram(0x40,0);
    }
    efip_send_cmd_72_ok_ram();
    do {
      while( true ) {
        pbVar4 = (byte *)efip_recv_frame_ram();
        if (pbVar4 == (byte *)0x0) {
          return 0;
        }
        if (pbVar4[1] != 0x70) break;
        uVar6 = *pbVar4 - 1 & 0xff;
        iVar5 = memcpy_checked_ram(pbVar4 + 2,uVar6);
        if (iVar5 == 0) {
          DAT_003fe010 = DAT_003fe010 + uVar6;
          enc3by2_decrypt_ram(pbVar4 + 2,uVar6);
          iVar5 = efip_program_handler_ram();
          if (iVar5 == 0) {
            do {
                    // WARNING: Do nothing block with infinite loop
            } while( true );
          }
        }
        uVar6 = efip_total_size_get_ram();
        if (uVar6 < DAT_003fe010) {
          efip_send_cmd_72_error_ram();
          return 0;
        }
        efip_send_cmd_72_ok_ram();
      }
      if (pbVar4[1] == 0x73) {
        iVar5 = efip_write_complete_ram();
        if (iVar5 == 0) {
          efip_send_cmd_72_error_ram();
          return 0;
        }
        efip_send_cmd_72_ok_ram();
        return 1;
      }
    } while (pbVar4[1] != 0x71);
  }
  return 0;
}



// Waits for the enter-stage-II command: packet [01 71 72] -> ack 0x8D, packet with 0x81 -> switch
// baud and ack; 100 ms timeout -> boot application (RAM copy)

void efip_enter_stage2_ram(void)

{
  bool bVar1;
  int iVar2;
  char cVar4;
  undefined *puVar3;
  byte local_18 [12];
  
  bVar1 = false;
  timer_save_ram(0);
  while ((iVar2 = efip_rx_ready_ram(), iVar2 == 0 || (cVar4 = efip_recv_byte_ram(), cVar4 != '\x01')
         )) {
    puVar3 = (undefined *)timer_elapsed_ram(0);
    if (&UNK_0001869f < puVar3) {
      prog_entry_point();
      return;
    }
  }
  timer_save_ram(0);
  do {
    iVar2 = efip_rx_ready_ram();
    if (iVar2 != 0) {
      cVar4 = efip_recv_byte_ram();
      if (cVar4 == 'q') {
LAB_003f9628:
        timer_save_ram(0);
        do {
          iVar2 = efip_rx_ready_ram();
          if (iVar2 != 0) {
            local_18[0] = efip_recv_byte_ram();
            if (local_18[0] == 0x72) {
              if (!bVar1) {
                local_18[0] = 0x8d;
                efip_send_bytes_ram(local_18,1);
                return;
              }
            }
            else if ((local_18[0] == 0x81) && (bVar1)) {
              efip_baud_29069_ram();
              local_18[0] = ~local_18[0];
              efip_send_bytes_ram(local_18,1);
              return;
            }
          }
          puVar3 = (undefined *)timer_elapsed_ram(0);
          if (&UNK_0001869f < puVar3) {
            prog_entry_point();
            return;
          }
        } while( true );
      }
      if (cVar4 == -0x7f) {
        bVar1 = true;
        goto LAB_003f9628;
      }
    }
    puVar3 = (undefined *)timer_elapsed_ram(0);
    if (&UNK_0001869f < puVar3) {
      prog_entry_point();
      return;
    }
  } while( true );
}



// CRP01 session: init SCI/buffers/enc3by2 key

void efip_session_run_ram(void)

{
  int iVar1;
  
  timer_enable_timebase_ram();
  REG_SWSR = 0x556c;
  REG_SWSR = 0xaa39;
  init_sci1_ram();
  REG_SWSR = 0x556c;
  REG_SWSR = 0xaa39;
  efip_recv_state_reset_ram();
  efip_buffer_clear_ram();
  enc3by2_key_init_ram();
  efip_parse_subpacket_reset_ram();
  DAT_003fe010 = 0;
  efip_enter_stage2_ram();
  iVar1 = efip_data_process_ram();
  if (iVar1 == 0) {
    do {
                    // WARNING: Do nothing block with infinite loop
    } while( true );
  }
  return;
}



// Initializes QSCI1 (K-Line UART): baud 0x2A, 8N1, sends three sync bytes and drains RX (RAM copy)

void init_sci1_ram(void)

{
  ushort uVar1;
  
  REG_SCC1R1 = 0;
  REG_SCC1R0 = 0x2a;
  uVar1 = REG_SCC1R1;
  REG_SCC1R1 = uVar1 & 0xfff7 | 8;
  uVar1 = REG_SCC1R1;
  REG_SCC1R1 = uVar1 & 0xfffb;
  REG_SC1DR = 0;
  do {
    uVar1 = REG_SC1SR;
  } while ((uVar1 >> 7 & 1) == 0);
  REG_SC1DR = 0;
  do {
    uVar1 = REG_SC1SR;
  } while ((uVar1 >> 7 & 1) == 0);
  REG_SC1DR = 0;
  do {
    uVar1 = REG_SC1SR;
  } while ((uVar1 >> 7 & 1) == 0);
  while (uVar1 = REG_SC1SR, (uVar1 >> 6 & 1) != 0) {
    uVar1 = REG_SC1DR;
  }
  uVar1 = REG_SCC1R1;
  REG_SCC1R1 = uVar1 & 0xfffb | 4;
  return;
}



// Sets SCI1 baud rate (SCC1R0 = 0x2B, the 29069 baud stage-II speed requested by cmd 0x81) (RAM
// copy)

void efip_baud_29069_ram(void)

{
  REG_SCC1R0 = 0x2b;
  return;
}



// Transmits a byte buffer over SCI1 (K-Line): enables TX, waits TDRE per byte, waits TC at the end
// (RAM copy)

void efip_send_bytes_ram(byte *param_1,int param_2)

{
  byte bVar1;
  ushort uVar2;
  int iVar3;
  
  uVar2 = REG_SCC1R1;
  REG_SCC1R1 = uVar2 & 0xfffb;
  uVar2 = REG_SC1SR;
  if ((uVar2 >> 6 & 1) != 0) {
    uVar2 = REG_SC1DR;
  }
  iVar3 = 0;
  do {
    do {
      uVar2 = REG_SC1SR;
    } while ((uVar2 >> 8 & 1) == 0);
    bVar1 = *param_1;
    param_1 = param_1 + 1;
    REG_SC1DR = (ushort)bVar1;
    iVar3 = iVar3 + 1;
  } while (iVar3 != param_2);
  do {
    uVar2 = REG_SC1SR;
  } while ((uVar2 >> 7 & 1) == 0);
  uVar2 = REG_SCC1R1;
  REG_SCC1R1 = uVar2 & 0xfffb | 4;
  return;
}



// Returns true when the SCI1 receive data register is full (SC1SR RDRF) (RAM copy)

bool efip_rx_ready_ram(void)

{
  ushort uVar1;
  
  REG_SWSR = 0x556c;
  REG_SWSR = 0xaa39;
  uVar1 = REG_SC1SR;
  return (uVar1 >> 6 & 1) != 0;
}



// Blocking receive of one byte from SCI1 (K-Line), waits for RDRF (RAM copy)

ushort efip_recv_byte_ram(void)

{
  ushort uVar1;
  int iVar2;
  
  do {
    iVar2 = efip_rx_ready_ram();
  } while (iVar2 == 0);
  uVar1 = REG_SC1DR;
  return uVar1 & 0xff;
}



// Resets the K-Line frame receiver state machine (byte position state) (RAM copy)

void efip_recv_state_reset_ram(void)

{
  DAT_003fe01c = 0;
  return;
}



// Byte-level K-Line frame receiver state machine: length, cmd, data, sum; verifies checksum and
// replies with the inverted sum after 10 ms (RAM copy)

undefined4 efip_recv_packet_ram(byte param_1)

{
  uint uVar1;
  byte *pbVar2;
  
  if (0x100 < DAT_003fe01c) {
    DAT_003fe01c = 0;
  }
  uVar1 = timer_elapsed_ram(2);
  if (10000 < uVar1) {
    DAT_003fe01c = 0;
  }
  timer_save_ram(2);
  if (DAT_003fe01c == 0) {
    DAT_003fe01c = 1;
    DAT_003fe018 = param_1;
    DAT_003fe020 = param_1;
  }
  else if (DAT_003fe01c == 1) {
    DAT_003fe01c = 2;
    DAT_003fe018 = DAT_003fe018 + param_1;
    bRam003fe021 = param_1;
  }
  else if ((DAT_003fe01c < 2) || ((int)(uint)DAT_003fe020 < DAT_003fe01c)) {
    if ((int)(DAT_003fe020 + 1) < DAT_003fe01c) {
      DAT_003fe01c = 0;
    }
    else {
      (&DAT_003fe020)[DAT_003fe01c] = param_1;
      DAT_003fe01c = 0;
      if (param_1 == DAT_003fe018) {
        delay_blocking_ms_ram(10);
        DAT_003fe018 = ~DAT_003fe018;
        efip_send_bytes_ram(&DAT_003fe018,1);
        return 1;
      }
    }
  }
  else {
    pbVar2 = &DAT_003fe020 + DAT_003fe01c;
    DAT_003fe01c = DAT_003fe01c + 1;
    *pbVar2 = param_1;
    DAT_003fe018 = DAT_003fe018 + param_1;
  }
  return 0;
}



// WARNING: Inlined function: push_27to31_ram
// WARNING: Inlined function: pop_27to31_ram
// Sends a K-Line packet: length, data, checksum, after a 10 ms delay (RAM copy)

byte efip_send_packet_ram(byte *param_1,byte param_2)

{
  byte bVar1;
  byte *pbVar2;
  int iVar3;
  byte *pbVar4;
  
  *param_1 = param_2;
  pbVar4 = param_1 + param_2 + 1;
  *pbVar4 = 0;
  pbVar2 = param_1;
  for (iVar3 = 0; iVar3 <= (int)(uint)param_2; iVar3 = iVar3 + 1) {
    bVar1 = *pbVar2;
    pbVar2 = pbVar2 + 1;
    *pbVar4 = *pbVar4 + bVar1;
  }
  delay_blocking_ms_ram(10);
  efip_send_bytes_ram(param_1,param_2 + 2);
  return *pbVar4;
}



// Waits for a complete K-Line frame (5 s timeout), returns the frame buffer or NULL on timeout (RAM
// copy)

undefined1 * efip_recv_frame_ram(void)

{
  int iVar1;
  undefined1 uVar3;
  uint uVar2;
  
  timer_save_ram(3);
  do {
    while (iVar1 = efip_rx_ready_ram(), iVar1 == 0) {
      uVar2 = timer_elapsed_ram(3);
      if (5000000 < uVar2) {
        return (undefined1 *)0x0;
      }
    }
    uVar3 = efip_recv_byte_ram();
    iVar1 = efip_recv_packet_ram(uVar3);
  } while (iVar1 == 0);
  return &DAT_003fe020;
}



// Sends a K-Line message and waits for the inverted-checksum acknowledgement (50 ms timeout) (RAM
// copy)

undefined4 efip_send_msg_ram(undefined4 param_1,undefined4 param_2)

{
  byte bVar3;
  int iVar1;
  byte bVar4;
  uint uVar2;
  
  bVar3 = efip_send_packet_ram(param_1,param_2);
  timer_save_ram(3);
  do {
    while (iVar1 = efip_rx_ready_ram(), iVar1 == 0) {
      uVar2 = timer_elapsed_ram(3);
      if (49999 < uVar2) {
        if (true) {
          return 0;
        }
        bVar3 = efip_send_packet_ram(param_1,param_2);
        timer_save_ram(3);
      }
    }
    bVar4 = efip_recv_byte_ram();
  } while (bVar3 != (byte)~bVar4);
  return 1;
}



// Sends the 0x72 response frame with error code 0 (ok, next frame) (RAM copy)

void efip_send_cmd_72_ok_ram(void)

{
  undefined1 uStack_18;
  undefined1 local_17;
  undefined1 local_16;
  
  local_17 = 0x72;
  local_16 = 0;
  efip_send_msg_ram(&uStack_18,2);
  return;
}



// Sends the 0x72 response frame with an error code (RAM copy)

void efip_send_cmd_72_error_ram(void)

{
  undefined1 uStack_18;
  undefined1 local_17;
  undefined1 local_16;
  
  local_17 = 0x72;
  local_16 = 0xff;
  efip_send_msg_ram(&uStack_18,2);
  return;
}



// Pushes one decrypted byte into the ring buffer (write side of next_bytes) (RAM copy)

void next_bytes_put_ram(undefined1 param_1)

{
  if (DAT_003fe388 < 0x200) {
    (&DAT_003fe170)[DAT_003fe384] = param_1;
    DAT_003fe384 = DAT_003fe384 + 1 & 0x1ff;
    DAT_003fe388 = DAT_003fe388 + 1;
  }
  return;
}



// Pulls the next decrypted byte from the ring buffer (512 bytes at 0x3FE170) (RAM copy)

bool next_bytes_ram(undefined1 *param_1)

{
  bool bVar1;
  
  bVar1 = DAT_003fe388 != 0;
  if (bVar1) {
    *param_1 = (&DAT_003fe170)[DAT_003fe386];
    DAT_003fe386 = DAT_003fe386 + 1 & 0x1ff;
    DAT_003fe388 = DAT_003fe388 + -1;
  }
  return bVar1;
}



// Decrypt step: w_sum = (cipher * key_mult) % key_mod, greedy bit decomposition over the 16-entry
// table, fails when the remainder is non-zero (RAM copy)

uint enc3by2_decrypt_bits_ram(uint param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  byte abStack_19 [17];
  
  uVar2 = 0;
  uVar1 = (param_1 - (param_1 / DAT_003fe168) * DAT_003fe168) * DAT_003fe16c;
  uVar1 = uVar1 - (uVar1 / DAT_003fe168) * DAT_003fe168;
  for (iVar3 = 0xf; -1 < iVar3; iVar3 = iVar3 + -1) {
    if (uVar1 < (uint)(&DAT_003fe128)[iVar3]) {
      abStack_19[iVar3 + 1] = 0;
    }
    else {
      abStack_19[iVar3 + 1] = 1;
    }
    uVar1 = uVar1 - (uint)abStack_19[iVar3 + 1] * (&DAT_003fe128)[iVar3];
  }
  if (uVar1 == 0) {
    for (uVar1 = 0; (int)uVar1 < 0x10; uVar1 = uVar1 + 1) {
      uVar2 = uVar2 + ((uint)abStack_19[uVar1 + 1] << (uVar1 & 0x3f)) & 0xffff;
    }
  }
  return uVar2;
}



// Decrypt step: plain word = (bit_flag - K) & 0xFFFF (RAM copy)

int enc3by2_decrypt_word_ram(undefined4 param_1)

{
  int iVar1;
  
  iVar1 = enc3by2_decrypt_bits_ram(param_1);
  return iVar1 - (uint)DAT_003fe382;
}



// Initializes the CRP01 3by2 key: K = ~(9744 + sum of the 4 size bytes), key
// table/modulus/multiplier into RAM (crp01.py: T4e key at 0x6118) (RAM copy)

void enc3by2_key_init_ram(void)

{
  DAT_003fe374 = 0;
  DAT_003fe384 = 0;
  DAT_003fe386 = 0;
  DAT_003fe388 = 0;
  flash_data_write_i = 0;
  DAT_003fe16c = 0xc6e;
  DAT_003fe168 = &DAT_0005d017;
  DAT_003fe128 = 7;
  DAT_003fe12c = 0xf;
  DAT_003fe130 = 0x17;
  DAT_003fe134 = 0x2f;
  DAT_003fe138 = 0x5d;
  DAT_003fe13c = 0xba;
  DAT_003fe140 = 0x174;
  DAT_003fe144 = 0x2e8;
  DAT_003fe148 = 0x5d0;
  DAT_003fe14c = 0xba0;
  DAT_003fe150 = &DAT_00001740;
  DAT_003fe154 = &DAT_00002e80;
  DAT_003fe158 = 0x5d00;
  DAT_003fe15c = &DAT_0000ba00;
  DAT_003fe160 = &DAT_00017401;
  DAT_003fe164 = &DAT_0002e801;
  return;
}



// Decrypts the CRP data with the 3by2 algorithm (3 cipher bytes -> 2 plain bytes per step) and
// stores plain bytes into the next_bytes ring buffer (RAM copy)

void enc3by2_decrypt_ram(int param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  
  for (iVar2 = 0; iVar2 < param_2; iVar2 = iVar2 + 1) {
    if (DAT_003fe374 == 0) {
      DAT_003fe370 = (uint)*(byte *)(param_1 + iVar2) << 0x18;
      DAT_003fe382 = *(byte *)(param_1 + iVar2) + 0x2610;
      DAT_003fe374 = 1;
    }
    else if (DAT_003fe374 == 1) {
      DAT_003fe370 = DAT_003fe370 + (uint)*(byte *)(param_1 + iVar2) * 0x10000;
      DAT_003fe382 = DAT_003fe382 + *(byte *)(param_1 + iVar2);
      DAT_003fe374 = 2;
    }
    else if (DAT_003fe374 == 2) {
      DAT_003fe370 = DAT_003fe370 + (uint)*(byte *)(param_1 + iVar2) * 0x100;
      DAT_003fe382 = DAT_003fe382 + *(byte *)(param_1 + iVar2);
      DAT_003fe374 = 3;
    }
    else if (DAT_003fe374 == 3) {
      DAT_003fe370 = DAT_003fe370 + (uint)*(byte *)(param_1 + iVar2);
      DAT_003fe382 = ~(DAT_003fe382 + *(byte *)(param_1 + iVar2));
      DAT_003fe374 = 4;
    }
    else if ((DAT_003fe374 < 4) || (0xf < DAT_003fe374)) {
      if ((DAT_003fe374 < 0x10) || (DAT_003fe370 - 4U <= DAT_003fe374)) {
        if (DAT_003fe370 - 4U <= DAT_003fe374) {
          DAT_003fe374 = DAT_003fe374 + 1;
        }
      }
      else {
        uVar1 = (DAT_003fe374 - 0x10) % 3;
        if (uVar1 == 1) {
          DAT_003fe378 = DAT_003fe378 + (uint)*(byte *)(param_1 + iVar2) * 0x100;
        }
        else if (uVar1 == 0) {
          if (true) {
            DAT_003fe378 = (uint)*(byte *)(param_1 + iVar2);
          }
        }
        else if (uVar1 < 3) {
          DAT_003fe378 = DAT_003fe378 + (uint)*(byte *)(param_1 + iVar2) * 0x10000;
          DAT_003fe37c = enc3by2_decrypt_word_ram(DAT_003fe378);
          next_bytes_put_ram(DAT_003fe37c & 0xff);
          next_bytes_put_ram((int)(uint)DAT_003fe37c >> 8);
          if (DAT_003fe374 == DAT_003fe370 - 5U) {
            flash_data_read_i = (DAT_003fe37c & 0xff) + (short)(((int)(uint)DAT_003fe37c >> 8) << 8)
            ;
          }
          else {
            flash_data_write_i = flash_data_write_i + (DAT_003fe37c & 0xff) + (DAT_003fe37c >> 8);
          }
        }
        DAT_003fe374 = DAT_003fe374 + 1;
      }
    }
    else {
      DAT_003fe374 = DAT_003fe374 + 1;
    }
  }
  return;
}



// Returns the CRP total size (first 4 bytes of the CRP data, big endian) (RAM copy)

undefined4 efip_total_size_get_ram(void)

{
  return DAT_003fe370;
}



// Returns true when all buffered data has been written to flash/EEPROM (RAM copy)

bool efip_write_complete_ram(void)

{
  return flash_data_read_i == flash_data_write_i;
}



// Clears the CRP frame accumulation buffer (0x102 bytes at 0x3FE390) (RAM copy)

void efip_buffer_clear_ram(void)

{
  int iVar1;
  
  for (iVar1 = 0; iVar1 < 0x102; iVar1 = iVar1 + 1) {
    (&DAT_003fe390)[iVar1] = 0;
  }
  return;
}



// Copies a frame into the accumulation buffer unless identical to the previous frame
// (retransmission filter) (RAM copy)

bool memcpy_checked_ram(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  
  iVar1 = cmp_buffer_ram(&DAT_003fe390,param_1,param_2);
  if (iVar1 == 0) {
    memcpy_ram(&DAT_003fe390,param_1,param_2);
  }
  return iVar1 != 0;
}



// Resets the sub-packet parser state (RAM copy)

void efip_parse_subpacket_reset_ram(void)

{
  DAT_003fe6a0 = 0;
  return;
}



// Parses one CRP01 sub-packet record (0x55 header

undefined1 * efip_parse_subpacket_ram(byte param_1)

{
  byte *pbVar1;
  
  if (0x1fe < (int)DAT_003fe6a0) {
    DAT_003fe6a0 = 0;
  }
  if (DAT_003fe6a0 == 0) {
    if (param_1 == 0x55) {
      DAT_003fe6a0 = 1;
      DAT_003fe498 = 0x55;
      DAT_003fe6a6 = 0x55;
    }
  }
  else if (DAT_003fe6a0 == 1) {
    DAT_003fe6a0 = 2;
    DAT_003fe6a6 = DAT_003fe6a6 + param_1;
    DAT_003fe6a4 = param_1;
    bRam003fe499 = param_1;
  }
  else if (DAT_003fe6a0 == 2) {
    DAT_003fe6a0 = 3;
    DAT_003fe698 = (uint)param_1 << 0x10;
    DAT_003fe6a6 = DAT_003fe6a6 + param_1;
    bRam003fe49a = param_1;
  }
  else if (DAT_003fe6a0 == 3) {
    DAT_003fe6a0 = 4;
    DAT_003fe698 = DAT_003fe698 + (uint)param_1 * 0x100;
    DAT_003fe6a6 = DAT_003fe6a6 + param_1;
    bRam003fe49b = param_1;
  }
  else if (DAT_003fe6a0 == 4) {
    DAT_003fe6a0 = 5;
    DAT_003fe698 = DAT_003fe698 + (uint)param_1;
    DAT_003fe6a6 = DAT_003fe6a6 + param_1;
    bRam003fe49c = param_1;
  }
  else if (((int)DAT_003fe6a0 < 5) || ((int)(uint)DAT_003fe6a4 <= (int)DAT_003fe6a0)) {
    if (DAT_003fe6a0 == DAT_003fe6a4) {
      if (DAT_003fe6a6 == param_1) {
        DAT_003fe69c = &DAT_003fe49d;
        DAT_003fe6a0 = 0;
        DAT_003fe6a5 = DAT_003fe6a4 - 5;
        return &DAT_003fe498;
      }
      DAT_003fe6a0 = 0;
      return (undefined1 *)0x0;
    }
    DAT_003fe6a0 = 0;
  }
  else {
    pbVar1 = &DAT_003fe498 + DAT_003fe6a0;
    DAT_003fe6a0 = DAT_003fe6a0 + 1;
    *pbVar1 = param_1;
    DAT_003fe6a6 = DAT_003fe6a6 + param_1;
  }
  return (undefined1 *)0x0;
}



// Copies n bytes from src to dst (RAM copy)

void memcpy_ram(undefined1 *param_1,undefined1 *param_2,short param_3)

{
  undefined1 uVar1;
  bool bVar2;
  
  while (bVar2 = param_3 != 0, param_3 = param_3 + -1, bVar2) {
    uVar1 = *param_2;
    param_2 = param_2 + 1;
    *param_1 = uVar1;
    param_1 = param_1 + 1;
  }
  return;
}



// Compares two buffers, returns 0 when equal (used to drop retransmitted frames) (RAM copy)

undefined4 cmp_buffer_ram(char *param_1,char *param_2,ushort param_3)

{
  char cVar1;
  char cVar2;
  ushort uVar3;
  
  uVar3 = 0;
  while( true ) {
    if (param_3 <= uVar3) {
      return 1;
    }
    cVar1 = *param_1;
    param_1 = param_1 + 1;
    cVar2 = *param_2;
    param_2 = param_2 + 1;
    if (cVar1 != cVar2) break;
    uVar3 = uVar3 + 1;
  }
  return 0;
}



// QADC B channel 11 check used by watchdog_retrigger: clears MPWMSM16 SCR bit 11 when the reading
// is below 0x200 (RAM copy)

void watchdog_qadc_check_ram(void)

{
  ushort uVar1;
  
  uVar1 = REG_QADCB_RJURR11;
  if (uVar1 < 0x200) {
    uVar1 = REG_MPWMSM16_SCR;
    REG_MPWMSM16_SCR = uVar1 & 0xf7ff;
  }
  return;
}



// Retriggers hardware watchdog (SWSR sequence 0x556C/0xAA39), then checks QADC B channel 11 and
// clears MPWMSM16 SCR bit 11 when below 0x200 (RAM copy)

void watchdog_retrigger_ram(void)

{
  REG_SWSR = 0x556c;
  REG_SWSR = 0xaa39;
  watchdog_qadc_check_ram();
  return;
}



// Saves current timebase counter value for delay measurement (RAM copy)

void delay_start_ram(void)

{
  DAT_003fe6a8 = timer_read_tbl_ram();
  return;
}



// Waits until specified number of timebase ticks have elapsed since delay_start (RAM copy)

void delay_wait_ram(uint param_1)

{
  int iVar1;
  
  do {
    iVar1 = timer_read_tbl_ram();
  } while ((uint)(iVar1 - DAT_003fe6a8) <= param_1);
  return;
}



// Short delay (300 ticks) between HC08 serial bit transitions (RAM copy)

void hc08_bit_delay_ram(void)

{
  delay_blocking_ram(300);
  return;
}



// Configures MDASM28 for input capture mode (HC08 serial receive) (RAM copy)

void hc08_mdasm_init_capture_ram(void)

{
  ushort uVar1;
  
  REG_MDASM28_SCR = 0;
  REG_MDASM28_AR = 0;
  REG_MDASM28_BR = 0;
  uVar1 = REG_MDASM28_SCR;
  REG_MDASM28_SCR = uVar1 & 0xfff0 | 4;
  return;
}



// Configures MDASM28 for edge detect mode (HC08 serial idle) (RAM copy)

void hc08_mdasm_init_edge_ram(void)

{
  ushort uVar1;
  
  REG_MDASM28_SCR = 0;
  uVar1 = REG_MDASM28_SCR;
  REG_MDASM28_SCR = uVar1 & 0xfff0 | 3;
  return;
}



// Sets MDASM28 output high (HC08 serial line) (RAM copy)

void hc08_mdasm_set_high_ram(void)

{
  ushort uVar1;
  
  uVar1 = REG_MDASM28_SCR;
  REG_MDASM28_SCR = uVar1 & 0xfbff | 0x400;
  return;
}



// Sets MDASM28 output low (HC08 serial line) (RAM copy)

void hc08_mdasm_set_low_ram(void)

{
  ushort uVar1;
  
  uVar1 = REG_MDASM28_SCR;
  REG_MDASM28_SCR = uVar1 & 0xfdff | 0x200;
  return;
}



// Reads MDASM28 input state (HC08 serial line level) (RAM copy)

ushort hc08_mdasm_read_ram(void)

{
  ushort uVar1;
  
  uVar1 = REG_MDASM28_SCR;
  return uVar1 >> 0xf;
}



// Starts MPWMSM2 output for HC08 clock/power signal (RAM copy)

void hc08_mpwm_start_ram(void)

{
  ushort uVar1;
  
  uVar1 = REG_MPIOSMDR;
  REG_MPIOSMDR = uVar1 & 0xbfff | 0x4000;
  return;
}



// Sets system clock register (SCCR = 0x4024100) (RAM copy)

void init_clock_ram(void)

{
  REG_SCCR = 0x4024100;
  return;
}



// Initializes HC08 interface: configures MIOS, clock, MDASM28, GPIO pins, EEPROM WP, MPWMSM2 (RAM
// copy)

void hc08_init_ram(void)

{
  byte bVar1;
  ushort uVar2;
  
  DAT_003fe6ac = PTR_DAT_00021fec;
  init_mios_ram();
  init_qadc_a_ram();
  init_qadc_b_ram();
  init_clock_ram();
  hc08_mdasm_init_edge_ram();
  uVar2 = Ram00304808;
  Ram00304808 = uVar2 & 0xf7ff | 0x800;
  uVar2 = Ram00304808;
  Ram00304808 = uVar2 & 0xffef | 0x10;
  uVar2 = Ram00304808;
  Ram00304808 = uVar2 & 0xffdf | 0x20;
  bVar1 = REG_PORTQA_A;
  REG_PORTQA_A = bVar1 & 0xf7 | 8;
  bVar1 = REG_PORTQB_A;
  REG_PORTQB_A = bVar1 & 0xef;
  bVar1 = REG_PORTQB_A;
  REG_PORTQB_A = bVar1 & 0xdf;
  delay_blocking_ram(10000);
  uVar2 = REG_MPIOSMDR;
  REG_MPIOSMDR = uVar2 & 0xbfff;
  uVar2 = REG_MPIOSMDDR;
  REG_MPIOSMDDR = uVar2 | 0x4000;
  uVar2 = REG_MPWMSM2_SCR;
  REG_MPWMSM2_SCR = uVar2 & 0xff00 | 0xec;
  uVar2 = REG_MPWMSM2_SCR;
  REG_MPWMSM2_SCR = uVar2 & 0xefff;
  uVar2 = REG_MPWMSM2_SCR;
  REG_MPWMSM2_SCR = uVar2 & 0xbfff | 0x4000;
  uVar2 = REG_MPWMSM2_SCR;
  REG_MPWMSM2_SCR = uVar2 & 0xf7ff | 0x800;
  uVar2 = REG_MPWMSM2_SCR;
  REG_MPWMSM2_SCR = uVar2 & 0xfbff;
  return;
}



// Sends one byte to HC08 via bit-banged serial on MDASM28 (start bit, 8 data bits, stop bit) (RAM
// copy)

void hc08_send_byte_ram(uint param_1)

{
  hc08_mdasm_init_capture_ram();
  hc08_mdasm_set_high_ram();
  delay_start_ram();
  hc08_mdasm_set_low_ram();
  delay_wait_ram(0x19);
  if ((param_1 & 1) == 0) {
    hc08_mdasm_set_low_ram();
  }
  else {
    hc08_mdasm_set_high_ram();
  }
  delay_wait_ram(0x32);
  if ((param_1 & 2) == 0) {
    hc08_mdasm_set_low_ram();
  }
  else {
    hc08_mdasm_set_high_ram();
  }
  delay_wait_ram(0x4b);
  if ((param_1 & 4) == 0) {
    hc08_mdasm_set_low_ram();
  }
  else {
    hc08_mdasm_set_high_ram();
  }
  delay_wait_ram(100);
  if ((param_1 & 8) == 0) {
    hc08_mdasm_set_low_ram();
  }
  else {
    hc08_mdasm_set_high_ram();
  }
  delay_wait_ram(0x7d);
  if ((param_1 & 0x10) == 0) {
    hc08_mdasm_set_low_ram();
  }
  else {
    hc08_mdasm_set_high_ram();
  }
  delay_wait_ram(0x96);
  if ((param_1 & 0x20) == 0) {
    hc08_mdasm_set_low_ram();
  }
  else {
    hc08_mdasm_set_high_ram();
  }
  delay_wait_ram(0xaf);
  if ((param_1 & 0x40) == 0) {
    hc08_mdasm_set_low_ram();
  }
  else {
    hc08_mdasm_set_high_ram();
  }
  delay_wait_ram(200);
  if ((param_1 & 0x80) == 0) {
    hc08_mdasm_set_low_ram();
  }
  else {
    hc08_mdasm_set_high_ram();
  }
  delay_wait_ram(0xe1);
  hc08_mdasm_set_high_ram();
  delay_wait_ram(0xfa);
  hc08_mdasm_init_edge_ram();
  return;
}



// Receives one byte from HC08 via bit-banged serial on MDASM28, samples 8 data bits plus stop bit
// (RAM copy)

uint hc08_recv_byte_ram(void)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = hc08_mdasm_read_ram();
  if (iVar1 != 0) {
    timer_save_ram(0);
    do {
      iVar1 = hc08_mdasm_read_ram();
      if (iVar1 == 0) {
        delay_start_ram();
        delay_wait_ram(0x25);
        iVar1 = hc08_mdasm_read_ram();
        uVar2 = (uint)(iVar1 != 0);
        delay_wait_ram(0x3e);
        iVar1 = hc08_mdasm_read_ram();
        if (iVar1 != 0) {
          uVar2 = uVar2 | 2;
        }
        delay_wait_ram(0x57);
        iVar1 = hc08_mdasm_read_ram();
        if (iVar1 != 0) {
          uVar2 = uVar2 | 4;
        }
        delay_wait_ram(0x70);
        iVar1 = hc08_mdasm_read_ram();
        if (iVar1 != 0) {
          uVar2 = uVar2 | 8;
        }
        delay_wait_ram(0x89);
        iVar1 = hc08_mdasm_read_ram();
        if (iVar1 != 0) {
          uVar2 = uVar2 | 0x10;
        }
        delay_wait_ram(0xa2);
        iVar1 = hc08_mdasm_read_ram();
        if (iVar1 != 0) {
          uVar2 = uVar2 | 0x20;
        }
        delay_wait_ram(0xbb);
        iVar1 = hc08_mdasm_read_ram();
        if (iVar1 != 0) {
          uVar2 = uVar2 | 0x40;
        }
        delay_wait_ram(0xd4);
        iVar1 = hc08_mdasm_read_ram();
        if (iVar1 != 0) {
          uVar2 = uVar2 | 0x80;
        }
        delay_wait_ram(0xed);
        iVar1 = hc08_mdasm_read_ram();
        if (iVar1 == 0) {
          uVar2 = uVar2 | 0x8000;
        }
        delay_wait_ram(0xfa);
        return uVar2;
      }
      uVar2 = timer_elapsed_ram(0);
    } while (uVar2 < 0xf4241);
  }
  return 0xffffffff;
}



// HC08 passphrase authentication: sends "EFI Srl " (0x45 0x46 0x49 0x20 0x53 0x72 0x6C 0x20) and
// verifies echo (RAM copy)

undefined4 hc08_authenticate_ram(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  undefined4 uVar10;
  
  delay_blocking_ram(600000);
  hc08_mpwm_start_ram();
  delay_blocking_ram(600000);
  hc08_send_byte_ram(0xff);
  iVar1 = hc08_recv_byte_ram();
  hc08_send_byte_ram(0xff);
  iVar2 = hc08_recv_byte_ram();
  hc08_send_byte_ram(0xff);
  iVar3 = hc08_recv_byte_ram();
  hc08_send_byte_ram(0xff);
  iVar4 = hc08_recv_byte_ram();
  hc08_send_byte_ram(0xff);
  iVar5 = hc08_recv_byte_ram();
  hc08_send_byte_ram(0xff);
  iVar6 = hc08_recv_byte_ram();
  hc08_send_byte_ram(0xff);
  iVar7 = hc08_recv_byte_ram();
  hc08_send_byte_ram(0xff);
  iVar8 = hc08_recv_byte_ram();
  iVar9 = hc08_recv_byte_ram();
  if ((((((iVar1 == 0xff) && (iVar2 == 0xff)) && (iVar3 == 0xff)) &&
       ((iVar4 == 0xff && (iVar5 == 0xff)))) &&
      ((iVar6 == 0xff && ((iVar7 == 0xff && (iVar8 == 0xff)))))) && (iVar9 == 0x8000)) {
    uVar10 = 1;
  }
  else {
    uVar10 = 0;
  }
  return uVar10;
}



// Reads one byte from HC08 at specified address (sends cmd 0x4A, address high/low, reads data) (RAM
// copy)

undefined4 hc08_read_byte_ram(uint param_1,undefined1 *param_2)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  
  hc08_bit_delay_ram();
  hc08_send_byte_ram(0x4a);
  iVar1 = hc08_recv_byte_ram();
  if (iVar1 == 0x4a) {
    iVar4 = (int)(param_1 & 0xffff) >> 8;
    hc08_send_byte_ram(iVar4);
    iVar1 = hc08_recv_byte_ram();
    if (iVar4 == iVar1) {
      hc08_send_byte_ram(param_1 & 0xff);
      uVar3 = hc08_recv_byte_ram();
      if ((param_1 & 0xff) == uVar3) {
        iVar1 = hc08_recv_byte_ram();
        if (iVar1 == -1) {
          uVar2 = 0;
        }
        else {
          *param_2 = (char)iVar1;
          uVar2 = 1;
        }
      }
      else {
        uVar2 = 0;
      }
    }
    else {
      uVar2 = 0;
    }
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}



// Writes one byte to HC08 at specified address (sends cmd 0x49, address, data, verifies echo) (RAM
// copy)

undefined4 hc08_write_byte_ram(uint param_1,byte param_2)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  
  hc08_bit_delay_ram();
  hc08_send_byte_ram(0x49);
  iVar1 = hc08_recv_byte_ram();
  if (iVar1 == 0x49) {
    iVar4 = (int)(param_1 & 0xffff) >> 8;
    hc08_send_byte_ram(iVar4);
    iVar1 = hc08_recv_byte_ram();
    if (iVar4 == iVar1) {
      hc08_send_byte_ram(param_1 & 0xff);
      uVar3 = hc08_recv_byte_ram();
      if ((param_1 & 0xff) == uVar3) {
        hc08_send_byte_ram((uint)param_2);
        uVar3 = hc08_recv_byte_ram();
        if (param_2 == uVar3) {
          uVar2 = 1;
        }
        else {
          uVar2 = 0;
        }
      }
      else {
        uVar2 = 0;
      }
    }
    else {
      uVar2 = 0;
    }
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}



// Reads 16-bit word from HC08 (sends cmd 0x1A, reads two bytes) (RAM copy)

undefined4 hc08_read_word_ram(ushort *param_1)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  
  hc08_bit_delay_ram();
  hc08_send_byte_ram(0x1a);
  iVar1 = hc08_recv_byte_ram();
  if (iVar1 == 0x1a) {
    iVar1 = hc08_recv_byte_ram();
    if (iVar1 == -1) {
      uVar2 = 0;
    }
    else {
      iVar3 = hc08_recv_byte_ram();
      if (iVar3 == -1) {
        uVar2 = 0;
      }
      else {
        *param_1 = (ushort)(iVar1 << 8) | (ushort)iVar3;
        uVar2 = 1;
      }
    }
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}



// Writes single data byte to HC08 (sends cmd 0x19, data, verifies echo) (RAM copy)

undefined4 hc08_write_data_ram(byte param_1)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  
  hc08_bit_delay_ram();
  hc08_send_byte_ram(0x19);
  iVar1 = hc08_recv_byte_ram();
  if (iVar1 == 0x19) {
    hc08_send_byte_ram((uint)param_1);
    uVar3 = hc08_recv_byte_ram();
    if (param_1 == uVar3) {
      uVar2 = 1;
    }
    else {
      uVar2 = 0;
    }
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}



// Reads HC08 security register (sends cmd 0x0C, reads 16-bit value) (RAM copy)

undefined4 hc08_read_security_ram(ushort *param_1)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  
  hc08_bit_delay_ram();
  hc08_send_byte_ram(0xc);
  iVar1 = hc08_recv_byte_ram();
  iVar2 = hc08_recv_byte_ram();
  if (iVar2 == -1) {
    uVar3 = 0;
  }
  else {
    iVar4 = hc08_recv_byte_ram();
    if (iVar4 == -1) {
      uVar3 = 0;
    }
    else if (iVar1 == 0xc) {
      *param_1 = (ushort)iVar4;
      *param_1 = *param_1 | (ushort)(iVar2 << 8);
      uVar3 = 1;
    }
    else {
      uVar3 = 0;
    }
  }
  return uVar3;
}



// Sends verify passphrase command (0x28) to HC08 and checks acknowledgment (RAM copy)

bool hc08_verify_passphrase_ram(void)

{
  int iVar1;
  
  hc08_bit_delay_ram();
  hc08_send_byte_ram(0x28);
  iVar1 = hc08_recv_byte_ram();
  return iVar1 == 0x28;
}



// Checks the HC08 flash is blank by reading bytes 0xFFF6-0xFFFD and testing for 0xFF (RAM copy)

undefined4 hc08_is_blank_ram(void)

{
  int iVar1;
  undefined *puVar2;
  char local_18 [20];
  
  puVar2 = &DAT_0000fff6;
  while( true ) {
    if (0xfffd < ((uint)puVar2 & 0xffff)) {
      return 1;
    }
    iVar1 = hc08_read_byte_ram(puVar2,local_18);
    if (iVar1 == 0) break;
    if (local_18[0] != -1) {
      return 0;
    }
    puVar2 = puVar2 + 1;
  }
  return 0;
}



// Verifies HC08 flash write by reading back first byte and comparing remaining words (RAM copy)

undefined4 hc08_verify_write_ram(undefined2 param_1,char *param_2,byte param_3)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  undefined1 local_50 [2];
  char acStack_4e [70];
  
  if ((param_3 < 0x41) && (1 < param_3)) {
    iVar2 = hc08_read_byte_ram(param_1,acStack_4e);
    if (iVar2 == 0) {
      uVar1 = 0;
    }
    else {
      for (iVar2 = 1; iVar2 < (int)(uint)param_3; iVar2 = iVar2 + 2) {
        iVar3 = hc08_read_word_ram(local_50);
        if (iVar3 == 0) {
          return 0;
        }
        acStack_4e[iVar2] = local_50[0];
        acStack_4e[iVar2 + 1] = local_50[1];
      }
      iVar2 = memcmp_ram(acStack_4e,param_2,(uint)param_3);
      if (iVar2 == 0) {
        uVar1 = 1;
      }
      else {
        uVar1 = 0;
      }
    }
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}



// Programs HC08 flash: unlocks (0x45,0x01,0x10,0xCC,0xFF,0x28), sends address/size/data, triggers
// programming (RAM copy)

undefined4 hc08_program_flash_ram(undefined4 param_1,int param_2,uint param_3)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  short local_128;
  undefined1 local_125;
  undefined1 local_124;
  undefined1 local_123;
  undefined1 local_122;
  undefined1 local_121;
  undefined1 local_116;
  undefined1 local_115;
  undefined1 local_114;
  undefined1 local_113;
  
  if ((param_3 & 0xff) < 0x41) {
    iVar2 = hc08_write_byte_ram(0x100,0x45);
    if (iVar2 == 0) {
      uVar1 = 0;
    }
    else {
      iVar2 = hc08_write_data_ram(1);
      if (iVar2 == 0) {
        uVar1 = 0;
      }
      else {
        iVar2 = hc08_write_data_ram(0x10);
        if (iVar2 == 0) {
          uVar1 = 0;
        }
        else {
          iVar2 = hc08_write_data_ram(0xcc);
          if (iVar2 == 0) {
            uVar1 = 0;
          }
          else {
            iVar2 = hc08_write_data_ram(0xff);
            if (iVar2 == 0) {
              uVar1 = 0;
            }
            else {
              iVar2 = hc08_write_data_ram(0x28);
              if (iVar2 == 0) {
                uVar1 = 0;
              }
              else {
                local_116 = 0x20;
                local_115 = (undefined1)param_3;
                local_114 = (undefined1)((uint)param_1 >> 8);
                local_113 = (undefined1)param_1;
                iVar2 = hc08_write_byte_ram(0x110,0x20);
                if (iVar2 == 0) {
                  uVar1 = 0;
                }
                else {
                  iVar2 = hc08_write_data_ram(local_115);
                  if (iVar2 == 0) {
                    uVar1 = 0;
                  }
                  else {
                    iVar2 = hc08_write_data_ram(local_114);
                    if (iVar2 == 0) {
                      uVar1 = 0;
                    }
                    else {
                      iVar2 = hc08_write_data_ram(local_113);
                      if (iVar2 == 0) {
                        uVar1 = 0;
                      }
                      else {
                        for (iVar2 = 0; iVar2 < (int)(param_3 & 0xff); iVar2 = iVar2 + 1) {
                          iVar3 = hc08_write_data_ram(*(undefined1 *)(param_2 + iVar2));
                          if (iVar3 == 0) {
                            return 0;
                          }
                        }
                        iVar2 = hc08_read_security_ram(&local_128);
                        if (iVar2 == 0) {
                          uVar1 = 0;
                        }
                        else {
                          local_125 = 0x79;
                          local_124 = 0;
                          local_123 = 0;
                          local_122 = 1;
                          local_121 = 0;
                          iVar2 = hc08_write_byte_ram(local_128 + 1,0x79);
                          if (iVar2 == 0) {
                            uVar1 = 0;
                          }
                          else {
                            iVar2 = hc08_write_data_ram(local_124);
                            if (iVar2 == 0) {
                              uVar1 = 0;
                            }
                            else {
                              iVar2 = hc08_write_data_ram(local_123);
                              if (iVar2 == 0) {
                                uVar1 = 0;
                              }
                              else {
                                iVar2 = hc08_write_data_ram(local_122);
                                if (iVar2 == 0) {
                                  uVar1 = 0;
                                }
                                else {
                                  iVar2 = hc08_write_data_ram(local_121);
                                  if (iVar2 == 0) {
                                    uVar1 = 0;
                                  }
                                  else {
                                    iVar2 = hc08_verify_passphrase_ram();
                                    if (iVar2 == 0) {
                                      uVar1 = 0;
                                    }
                                    else {
                                      delay_blocking_ram(20000);
                                      iVar2 = hc08_verify_write_ram(param_1,param_2,param_3);
                                      if (iVar2 == 0) {
                                        uVar1 = 0;
                                      }
                                      else {
                                        uVar1 = 1;
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}



// Mass erases HC08 flash: unlocks, sends erase command with address 0xFFFF, triggers erase sequence
// (RAM copy)

undefined4 hc08_mass_erase_ram(void)

{
  int iVar1;
  undefined4 uVar2;
  short local_118;
  undefined1 local_115;
  undefined1 local_114;
  undefined1 local_113;
  undefined1 local_112;
  undefined1 local_111;
  undefined1 local_106;
  undefined1 local_105;
  undefined1 local_104;
  undefined1 local_103;
  
  iVar1 = hc08_write_byte_ram(0x100,0x45);
  if (iVar1 == 0) {
    uVar2 = 0;
  }
  else {
    iVar1 = hc08_write_byte_ram(0x101,1);
    if (iVar1 == 0) {
      uVar2 = 0;
    }
    else {
      iVar1 = hc08_write_byte_ram(0x102,0x10);
      if (iVar1 == 0) {
        uVar2 = 0;
      }
      else {
        iVar1 = hc08_write_byte_ram(0x103,0xcc);
        if (iVar1 == 0) {
          uVar2 = 0;
        }
        else {
          iVar1 = hc08_write_byte_ram(0x104,0xff);
          if (iVar1 == 0) {
            uVar2 = 0;
          }
          else {
            iVar1 = hc08_write_byte_ram(0x105,0x2c);
            if (iVar1 == 0) {
              uVar2 = 0;
            }
            else {
              local_106 = 0x20;
              local_105 = 0;
              local_104 = 0xff;
              local_103 = 0xff;
              iVar1 = hc08_write_byte_ram(0x110,0x20);
              if (iVar1 == 0) {
                uVar2 = 0;
              }
              else {
                iVar1 = hc08_write_byte_ram(0x111,local_105);
                if (iVar1 == 0) {
                  uVar2 = 0;
                }
                else {
                  iVar1 = hc08_write_byte_ram(0x112,local_104);
                  if (iVar1 == 0) {
                    uVar2 = 0;
                  }
                  else {
                    iVar1 = hc08_write_byte_ram(0x113,local_103);
                    if (iVar1 == 0) {
                      uVar2 = 0;
                    }
                    else {
                      iVar1 = hc08_read_security_ram(&local_118);
                      if (iVar1 == 0) {
                        uVar2 = 0;
                      }
                      else {
                        local_115 = 0x79;
                        local_114 = 0;
                        local_113 = 0;
                        local_112 = 1;
                        local_111 = 0;
                        iVar1 = hc08_write_byte_ram(local_118 + 1,0x79);
                        if (iVar1 == 0) {
                          uVar2 = 0;
                        }
                        else {
                          iVar1 = hc08_write_byte_ram(local_118 + 2,local_114);
                          if (iVar1 == 0) {
                            uVar2 = 0;
                          }
                          else {
                            iVar1 = hc08_write_byte_ram(local_118 + 3,local_113);
                            if (iVar1 == 0) {
                              uVar2 = 0;
                            }
                            else {
                              iVar1 = hc08_write_byte_ram(local_118 + 4,local_112);
                              if (iVar1 == 0) {
                                uVar2 = 0;
                              }
                              else {
                                iVar1 = hc08_write_byte_ram(local_118 + 5,local_111);
                                if (iVar1 == 0) {
                                  uVar2 = 0;
                                }
                                else {
                                  iVar1 = hc08_verify_passphrase_ram();
                                  if (iVar1 == 0) {
                                    uVar2 = 0;
                                  }
                                  else {
                                    uVar2 = 1;
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return uVar2;
}



// HC08 passphrase authentication with up to 3 retries (RAM copy)

int hc08_authenticate_retry_ram(void)

{
  int unaff_r30;
  int iVar1;
  
  iVar1 = 0;
  while ((iVar1 < 3 && (unaff_r30 = hc08_authenticate_ram(), unaff_r30 == 0))) {
    delay_blocking_ram(&DAT_0000c350);
    iVar1 = iVar1 + 1;
  }
  return unaff_r30;
}



// HC08 flash programming with up to 3 retries (RAM copy)

int hc08_program_flash_retry_ram(undefined2 param_1,undefined4 param_2,undefined1 param_3)

{
  int unaff_r30;
  int iVar1;
  
  iVar1 = 0;
  while ((iVar1 < 3 && (unaff_r30 = hc08_program_flash_ram(param_1,param_2,param_3), unaff_r30 == 0)
         )) {
    delay_blocking_ram(&DAT_0000c350);
    iVar1 = iVar1 + 1;
  }
  return unaff_r30;
}



// HC08 mass erase with up to 3 retries (RAM copy)

int hc08_mass_erase_retry_ram(void)

{
  int unaff_r30;
  int iVar1;
  
  iVar1 = 0;
  while ((iVar1 < 3 && (unaff_r30 = hc08_mass_erase_ram(), unaff_r30 == 0))) {
    delay_blocking_ram(&DAT_0000c350);
    iVar1 = iVar1 + 1;
  }
  return unaff_r30;
}



// HC08 erase sequence: watchdog, init, authenticate retry, mass erase retry (K-Line split of
// boot08's hc08_program_sequence first half) (RAM copy)

void hc08_erase_sequence_ram(void)

{
  int iVar1;
  
  watchdog_retrigger_ram();
  hc08_init_ram();
  watchdog_retrigger_ram();
  iVar1 = hc08_authenticate_retry_ram();
  if (iVar1 != 0) {
    hc08_mass_erase_retry_ram();
  }
  return;
}



// Full HC08 programming sequence: init hardware, authenticate, verify/erase, program flash blocks,
// write markers (RAM copy)

undefined4 hc08_program_sequence_ram(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined *puVar3;
  
  watchdog_retrigger_ram();
  hc08_init_ram();
  watchdog_retrigger_ram();
  iVar1 = hc08_authenticate_retry_ram();
  if (iVar1 == 0) {
    uVar2 = 0;
  }
  else {
    iVar1 = hc08_is_blank_ram();
    if (iVar1 == 0) {
      iVar1 = hc08_mass_erase_retry_ram();
      if (iVar1 != 0) {
        do {
          watchdog_retrigger_ram();
        } while( true );
      }
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    for (puVar3 = &DAT_0000dc00; (int)puVar3 < 0xfc00; puVar3 = puVar3 + 0x40) {
      watchdog_retrigger_ram();
      iVar1 = hc08_program_flash_retry_ram
                        ((uint)puVar3 & 0xffff,puVar3 + DAT_003fe6ac + -0xdc00,0x40);
      if (iVar1 == 0) {
        watchdog_retrigger_ram();
        iVar1 = hc08_mass_erase_retry_ram();
        if (iVar1 != 0) {
          do {
            watchdog_retrigger_ram();
          } while( true );
        }
        do {
                    // WARNING: Do nothing block with infinite loop
        } while( true );
      }
    }
    watchdog_retrigger_ram();
    iVar1 = hc08_program_flash_retry_ram(&DAT_0000ffdc,DAT_003fe6ac + 0x23dc,0x24);
    if (iVar1 == 0) {
      watchdog_retrigger_ram();
      iVar1 = hc08_mass_erase_retry_ram();
      if (iVar1 != 0) {
        do {
          watchdog_retrigger_ram();
        } while( true );
      }
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    watchdog_retrigger_ram();
    uVar2 = 1;
  }
  return uVar2;
}



// Byte copy with the destination aligned up to 4 bytes (flash programming alignment) (RAM copy)

void memcpy_aligned_ram(int param_1,undefined1 *param_2,int param_3)

{
  bool bVar1;
  undefined1 uVar2;
  undefined1 *puVar3;
  
  puVar3 = (undefined1 *)(param_1 + 3U & 0xfffffffc);
  param_3 = param_3 - (int)param_2;
  while (bVar1 = param_3 != 0, param_3 = param_3 + -1, bVar1) {
    uVar2 = *param_2;
    param_2 = param_2 + 1;
    *puVar3 = uVar2;
    puVar3 = puVar3 + 1;
  }
  return;
}



// Compares two memory blocks, returns -1/0/1 at first mismatch (RAM copy)

int memcmp_ram(char *__s1,char *__s2,size_t __n)

{
  int iVar1;
  byte *pbVar2;
  byte *pbVar3;
  
  pbVar2 = (byte *)(__s1 + -1);
  pbVar3 = (byte *)(__s2 + -1);
  iVar1 = __n + 1;
  do {
    iVar1 = iVar1 + -1;
    if (iVar1 == 0) {
      return 0;
    }
    pbVar2 = pbVar2 + 1;
    pbVar3 = pbVar3 + 1;
  } while (*pbVar2 == *pbVar3);
  if (*pbVar3 <= *pbVar2) {
    return 1;
  }
  return -1;
}



// WARNING: This is an inlined function
// WARNING: Unknown calling convention -- yet parameter storage is locked
// Compiler helper: saves registers r27-r31 to the caller stack frame (RAM copy)

void push_27to31_ram(void)

{
  int in_r11;
  undefined4 unaff_r27;
  undefined4 unaff_r28;
  undefined4 unaff_r29;
  undefined4 unaff_r30;
  undefined4 unaff_r31;
  
  *(undefined4 *)(in_r11 + -0x14) = unaff_r27;
  *(undefined4 *)(in_r11 + -0x10) = unaff_r28;
  *(undefined4 *)(in_r11 + -0xc) = unaff_r29;
  *(undefined4 *)(in_r11 + -8) = unaff_r30;
  *(undefined4 *)(in_r11 + -4) = unaff_r31;
  return;
}



// WARNING: This is an inlined function
// Compiler helper: restores registers r27-r31 from the caller stack frame (RAM copy)

void pop_27to31_ram(void)

{
  return;
}


