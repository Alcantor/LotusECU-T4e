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



struct_segment_data[7] segment_data;
struct_segment_bss[3] segment_bss;
uint REG_SIUMCR;
uint REG_SYPCR;
uint REG_SGPIODT1;
uint REG_SCCRK;
uint REG_SGPIODT2;
uint REG_SCCR;
uint REG_PLPRCRK;
uint REG_SGPIOCR;
uint REG_PLPRCR;
uint REG_UMCR;
uint REG_PDMCR;
undefined4 DAT_003f92c0;
ushort REG_TBSCR;
undefined1 DAT_003f92d5;
undefined1 DAT_003f92d7;
undefined1 DAT_003f92d8;
undefined1 DAT_003f8bb9;
undefined1 DAT_003f8bb8;
uint REG_SIMASK;
ushort DAT_003fd5a0;
byte DAT_003fda9e;
byte DAT_003fda9f;
byte DAT_003f92c4;
undefined1 DAT_003f92d0;
char DAT_003f80d8;
u16_time_5ms fuelpump_timer;
u16_time_5ms CAL_ecu_fuelpump_prime;
uint REG_SIMASK2;
u8_angle_1/4-32deg dev_ign_adv_adj;
uint REG_SIMASK3;
ushort REG_MPIOSMDR;
undefined1 L9822E_outputs;
u8_factor_1/256-1/2 dev_inj_efficiency_adj;
u8_angle_720/256deg dev_inj_angle;
ushort REG_RSR;
u8_angle_1/4deg dev_vvt_angle;
int8_t dev_afr_adj;
ushort REG_MPWMSM16_SCR;
ushort REG_DPTMCR;
ushort REG_RAMBAR;
undefined REG_DPTRAM;
char[2048] tpu_microcode;
ushort DAT_003fe18e;
ushort REG_TPU3A_CH12_PARAM4;
ushort REG_TPUMCR_A;
ushort REG_TPU3A_CH13_PARAM0;
ushort REG_TPU3A_CH13_PARAM1;
ushort REG_TICR_A;
ushort REG_TPU3A_CH13_PARAM4;
ushort REG_CIER_A;
ushort REG_CFSR0_A;
ushort REG_CFSR1_A;
ushort REG_CFSR2_A;
ushort REG_TPU3A_CH14_PARAM0;
ushort REG_CFSR3_A;
ushort REG_HSQR0_A;
ushort REG_HSQR1_A;
ushort REG_HSRR0_A;
ushort REG_TPU3A_CH14_PARAM4;
ushort REG_HSRR1_A;
ushort REG_TPU3A_CH14_PARAM5;
ushort REG_CPR0_A;
ushort REG_CPR1_A;
ushort REG_CISR_A;
ushort REG_TPU3A_CH15_PARAM0;
ushort REG_TPU3A_CH15_PARAM1;
ushort REG_TPUMCR2_A;
ushort REG_TPU3A_CH15_PARAM4;
ushort REG_TPUMCR3_A;
ushort REG_TPU3A_CH0_PARAM0;
ushort REG_TPU3A_CH0_PARAM1;
ushort REG_TPU3A_CH0_PARAM3;
ushort REG_TPU3A_CH1_PARAM0;
ushort REG_TPU3A_CH1_PARAM1;
ushort REG_TPU3A_CH1_PARAM2;
ushort REG_TPU3A_CH2_PARAM0;
ushort REG_TPU3A_CH2_PARAM4;
ushort REG_TPU3A_CH2_PARAM5;
ushort REG_TPU3A_CH3_PARAM0;
ushort REG_TPU3A_CH3_PARAM4;
ushort REG_TPU3A_CH3_PARAM5;
ushort REG_TPU3A_CH4_PARAM0;
ushort REG_TPU3A_CH4_PARAM4;
ushort REG_TPU3A_CH4_PARAM5;
ushort REG_TPU3A_CH5_PARAM0;
ushort REG_TPU3A_CH5_PARAM4;
ushort REG_TPU3A_CH5_PARAM5;
ushort REG_TPU3A_CH6_PARAM0;
ushort REG_TPU3A_CH6_PARAM4;
ushort REG_TPU3A_CH6_PARAM5;
ushort REG_TPU3A_CH7_PARAM0;
ushort REG_TPU3A_CH7_PARAM4;
ushort REG_TPU3A_CH7_PARAM5;
ushort REG_TPU3A_CH8_PARAM0;
ushort REG_TPU3A_CH8_PARAM1;
ushort REG_TPU3A_CH8_PARAM4;
ushort REG_TPU3A_CH9_PARAM0;
ushort REG_TPU3A_CH9_PARAM1;
ushort REG_TPU3A_CH9_PARAM4;
ushort REG_TPU3A_CH10_PARAM0;
ushort REG_TPU3A_CH10_PARAM1;
ushort REG_TPU3A_CH10_PARAM2;
ushort REG_TPU3A_CH11_PARAM0;
ushort REG_TPU3A_CH11_PARAM1;
ushort REG_TPU3A_CH11_PARAM4;
ushort REG_TPU3A_CH12_PARAM0;
ushort REG_TPU3A_CH12_PARAM1;
short DAT_003f92fa;
ushort REG_HSRR1_B;
ushort REG_TPU3B_CH1_PARAM1;
short DAT_003f92fc;
ushort REG_TPU3B_CH2_PARAM1;
short DAT_003f92fe;
ushort REG_TPU3B_CH3_PARAM1;
short DAT_003f9300;
ushort REG_TPU3B_CH4_PARAM1;
ushort REG_CISR_B;
ushort DAT_003fe184;
ushort REG_TPU3B_CH1_PARAM3;
undefined1 DAT_003f8bcc;
u16_angle_1/10deg DAT_003f8bc4;
ushort REG_CIER_B;
short DAT_003f8bd0;
ushort REG_CFSR1_B;
short DAT_003fe178;
ushort REG_TPU3B_CH10_PARAM0;
ushort DAT_003f92dc;
pointer PTR_DAT_00075ec8;
ushort REG_HSQR0_B;
ushort REG_HSRR0_B;
ushort REG_TPU3B_CH10_PARAM4;
ushort REG_TPU3B_CH10_PARAM5;
ushort REG_CPR0_B;
bool[4] inj_active_cyl;
u16_angle_1/10deg inj_angle_2;
undefined1 DAT_003f8bcd;
u16_angle_1/10deg DAT_003f8bc6;
ushort DAT_003f92f4;
ushort REG_TPU3B_CH2_PARAM3;
ushort REG_TPU3B_CH11_PARAM0;
ushort REG_TPU3B_CH11_PARAM4;
ushort REG_TPU3B_CH11_PARAM5;
undefined1 DAT_003f8bce;
u16_angle_1/10deg DAT_003f8bc8;
ushort REG_CFSR0_B;
ushort DAT_003f92f6;
ushort REG_TPU3B_CH3_PARAM3;
ushort REG_TPU3B_CH12_PARAM0;
ushort REG_TPU3B_CH12_PARAM4;
ushort REG_TPU3B_CH12_PARAM5;
undefined1 DAT_003f8bcf;
ushort REG_TPU3B_CH13_PARAM4;
u16_angle_1/10deg DAT_003f8bca;
ushort REG_TPU3B_CH13_PARAM5;
ushort DAT_003f92f8;
ushort REG_TPU3B_CH4_PARAM3;
ushort REG_TPU3B_CH13_PARAM0;
ushort DAT_003f8bc4;
byte DAT_003f8bcc;
ushort DAT_003f8bd0;
byte DAT_003f8bd2;
uint16_t misfire_flags;
bool engine_is_running;
undefined1 tc_fuelcut;
uint8_t obd_P0351_debounce_count;
u16_time_us inj_time_final_2;
uint16_t revlimit_flags;
ushort DAT_003f8bc6;
byte DAT_003f8bcd;
u16_time_us DAT_003f9302;
uint8_t obd_P0352_debounce_count;
ushort DAT_003f8bc8;
byte DAT_003f8bce;
uint8_t obd_P0353_debounce_count;
ushort DAT_003f8bca;
byte DAT_003f8bcf;
uint8_t obd_P0354_debounce_count;
uint8_t ign_feedback_coil_id;
uint8_t ign_feedback_pending_flags;
char DAT_003f8bc0;
char DAT_003f8bc1;
char DAT_003f8bc2;
char DAT_003f8bc3;
char DAT_003fe18a;
short DAT_003f92dc;
short DAT_003f92f4;
short DAT_003f92f6;
short DAT_003f92f8;
uint REG_SISR2;
ushort REG_MPWMSM19_SCR;
u16_time_25ns CAL_evap_period;
ushort REG_MPWMSM0_SCR;
ushort REG_MPWMSM1_PERR;
ushort REG_MPWMSM1_PULR;
ushort REG_MPWMSM1_SCR;
ushort REG_MPWMSM2_SCR;
ushort REG_MPWMSM3_SCR;
ushort REG_MDASM27_SCR;
ushort REG_MDASM28_SCR;
ushort REG_MDASM29_SCR;
ushort REG_MDASM30_SCR;
ushort REG_MDASM31_SCR;
ushort REG_MPIOSMDDR;
ushort REG_MIOS14TPCR;
ushort REG_MDASM11_SCR;
ushort REG_MDASM12_SCR;
ushort REG_MCPSMSCR;
ushort REG_MDASM13_SCR;
ushort REG_MDASM14_SCR;
ushort REG_MDASM15_SCR;
ushort REG_MPWMSM17_SCR;
ushort REG_MPWMSM18_PERR;
ushort REG_MPWMSM18_PULR;
ushort REG_MPWMSM18_SCR;
u16_time_25ns CAL_tps_period;
ushort REG_QDSCI_IL;
ushort REG_QSPI_IL;
ushort REG_SCC1R0;
ushort REG_SCC1R1;
ushort REG_PORTQS;
byte REG_PQSPAR;
byte REG_DDRQST;
ushort REG_SPCR0;
ushort REG_SPCR1;
ushort REG_SPCR2;
byte REG_SPCR3;
ushort REG_QSMCMMCR;
byte DAT_003f9304;
undefined1 DAT_003f8000;
undefined1 DAT_003f8001;
undefined1 DAT_003f8002;
ushort REG_RECRAM0;
undefined1 DAT_003f8bdd;
ushort REG_RECRAM1;
undefined1 DAT_003f930b;
ushort REG_RECRAM2;
undefined1 DAT_003f92c4;
ushort REG_RECRAM3;
ushort REG_TRANRAM0;
ushort REG_TRANRAM1;
ushort REG_TRANRAM2;
ushort REG_TRANRAM3;
byte REG_SPSR;
byte REG_COMDRAM0;
byte REG_COMDRAM1;
byte REG_COMDRAM2;
byte REG_COMDRAM3;
byte DAT_003f8004;
undefined1 DAT_003fd00c;
int DAT_003f8bd8;
ushort DAT_003fd00a;
byte DAT_003f8bdc;
byte DAT_003f930c;
ushort DAT_003f930e;
undefined2 DAT_003f931c;
undefined2 DAT_003f931e;
undefined2 DAT_003f9320;
char[4] CAL_ecu_unlock_magic;
undefined DAT_0000fffe;
undefined DAT_003f9344;
uint16_t ecu_CRC_computed;
bool dev_unlocked;
ushort REG_TPU3B_CH9_PARAM2;
ushort REG_TPU3B_CH9_PARAM3;
ushort REG_TPUMCR_B;
ushort REG_TICR_B;
ushort REG_CFSR2_B;
ushort REG_TPU3B_CH14_PARAM0;
ushort REG_CFSR3_B;
ushort REG_TPU3B_CH14_PARAM2;
ushort REG_HSQR1_B;
ushort REG_CPR1_B;
ushort REG_TPU3B_CH15_PARAM0;
ushort REG_TPU3B_CH15_PARAM2;
ushort REG_TPUMCR2_B;
ushort REG_TPUMCR3_B;
ushort REG_TPU3B_CH0_PARAM0;
ushort REG_TPU3B_CH0_PARAM1;
ushort REG_TPU3B_CH0_PARAM3;
ushort REG_TPU3B_CH1_PARAM0;
ushort REG_TPU3B_CH1_PARAM2;
ushort REG_TPU3B_CH2_PARAM0;
ushort REG_TPU3B_CH2_PARAM2;
ushort REG_TPU3B_CH3_PARAM0;
ushort REG_TPU3B_CH3_PARAM2;
ushort REG_TPU3B_CH4_PARAM0;
ushort REG_TPU3B_CH4_PARAM2;
ushort REG_TPU3B_CH5_PARAM0;
ushort REG_TPU3B_CH5_PARAM1;
ushort REG_TPU3B_CH5_PARAM2;
ushort REG_TPU3B_CH6_PARAM0;
ushort REG_TPU3B_CH6_PARAM1;
u16_time_25ns CAL_vvt_period;
ushort REG_TPU3B_CH6_PARAM2;
u16_time_25ns CAL_vvl_period;
ushort REG_TPU3B_CH7_PARAM0;
ushort REG_TPU3B_CH7_PARAM2;
ushort REG_TPU3B_CH7_PARAM3;
ushort REG_TPU3B_CH8_PARAM0;
ushort REG_TPU3B_CH8_PARAM2;
ushort REG_TPU3B_CH8_PARAM3;
ushort REG_TPU3B_CH9_PARAM0;
u16_factor_1/1023[16] tps_target_history_1;
short DAT_003fd00a;
short DAT_003fde3a;
char DAT_003f800e;
short DAT_003f800c;
uint DAT_003f8bf8;
char DAT_003f800f;
uint16_t obd_task_scheduler;
short DAT_003fd3c8;
ushort DAT_003fcff0;
uint8_t DAT_003f8bf5;
short DAT_003fcff2;
short DAT_003f8bea;
char DAT_003fd326;
short DAT_003f8be8;
int DAT_003f8bec;
short DAT_003fcff8;
short DAT_003fcffa;
short DAT_003fcffc;
byte DAT_003f8bf4;
short DAT_003f8bf0;
byte DAT_003f94a1;
byte DAT_003f94a0;
int DAT_003fd668;
byte DAT_003fd66c;
short DAT_003fd228;
ushort DAT_003f9488;
u16_time_5ms DAT_003f8bf2;
u16_time_5ms DAT_003fd00e;
ushort DAT_003fd30a;
uint8_t[16] CAL_misfire_dfso_count_max;
uint8_t[16] misfire_dfso_count;
undefined1 obd_mode_0x2F_state;
undefined1 obd_mode_0x2F_value;
u16_factor_1/1023 pps_tps_target;
u8_time_5ms hc08_parse_timer;
uint REG_SISR3;
ushort REG_PISCR;
u16_time_5ms hc08_send_timer;
undefined2 dt_tps_injtip;
u16_time_100ms ecu_runtime;
u16_time_5ms fan_low_stop_timer;
u16_time_5ms fan_high_stop_timer;
i16_factor_1/1023 dt_tps_target_2;
u8_time_10ms ac_on_timer;
u8_time_10ms fan_low_on_timer;
u32_mass_mg maf_accumulated_1;
u8_time_10ms fan_high_on_timer;
undefined2 maf_accumulated_2;
uint8_t o2_heater_warmup_state;
u16_time_5ms pre_o2_heater_timer;
u16_time_5ms post_o2_heater_timer;
u32_time_5ms engine_runtime;
u8_temp_5/8-40c coolant_smooth;
u16_factor_1/1023[16] tps_target_history_2;
u8_factor_1/255 tps;
uint16_t shutdown_flags;
u8_time_5ms CAL_sensor_dt_tps_target_1_age;
uint8_t CAL_dfso_delay_recovery_multiplier;
uint16_t LEA_ecu_engine_speed_byte_coefficient;
u8_factor_1/256 CAL_load_reactivity;
bool pre_o2_heater_is_off;
bool post_o2_heater_is_off;
u8_factor_1/100 CAL_load_alphaN_adj_corr_limit_h;
u8_factor_1/100 CAL_load_alphaN_adj_corr_limit_l;
u8_temp_5/8-40c CAL_load_alphaN_adj_corr_coolant_min;
u8_time_5ms CAL_sensor_o2_heater_warmup_period;
u16_time_5ms CAL_sensor_o2_heater_warmup_time;
i16_factor_1/1023 dt_tps_target_1;
uint32_t load_1_smooth_x;
undefined4 dt_engine_speed;
u8_rspeed_125/4+500rpm engine_speed_3;
u16_rspeed_1/4rpm engine_speed_1;
u16_rspeed_rpm CAL_load_alphaN_adj_corr_dt_engine_speed_max;
u32_time_5ms shutdown_delay_2;
u16_time_5ms CAL_load_alphaN_adj_corr_time_between_step;
u8_time_5ms hc08_recv_timer;
undefined1 obd_mode_0x13_state;
u16_factor_1/100 CAL_load_alphaN_adj_corr_max;
u16_factor_1/100 CAL_load_alphaN_adj_corr_min;
u16_time_5ms CAL_load_alphaN_adj_corr_time_min;
uint16_t dfso_flags;
u8_dt_factor_1/100/5ms injtip_in_adj2;
u8_dt_factor_1/100/5ms injtip_out_adj2;
undefined1 dfso_delay;
u8_time_5ms CAL_sensor_dt_tps_target_2_age;
u16_factor_1/1023 CAL_injtip_in_dt_tps_target_2_limit;
u16_factor_1/1023 CAL_injtip_in_dt_tps_target_2_min;
u16_factor_1/1023 CAL_injtip_out_dt_tps_target_2_limit;
u16_flow_10mg/s maf_flow_1;
u16_factor_1/1023 CAL_injtip_out_dt_tps_target_2_min;
u32_load_mg/stroke load_1_smooth;
u32_load_mg/stroke load_1;
u8_factor_1/255 load_use_alphaN_tps_min;
u8_factor_1/100 load_alphaN_maf_error;
u16_factor_1/1023 CAL_load_alphaN_adj_corr_dt_tps_target_1_max;
uint16_t closedloop_flags;
u16_voltage_5/1023v[32] maf_adc_history;
ushort REG_QADCA_RJURR11;
ushort REG_QADCA_RJURR10;
uint8_t CAL_sensor_maf_avg_size;
int16_t maf_adc_history_i;
u16_voltage_5/1023v[32] map_adc_history;
uint8_t CAL_sensor_map_avg_size;
int16_t map_adc_history_i;
uint REG_PITC;
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
byte REG_PORTQB_A;
byte REG_DDRQA_A;
ushort REG_QACR0_A;
ushort REG_QACR1_A;
ushort REG_QACR2_A;
ushort REG_QADCA_RJURR0;
struct_filter_4th_order filter_tps;
u16_factor_1/1023 tps_1_smooth;
char DAT_003f8c40;
ushort REG_SWSR;
uint32_t pps_1_smooth_x;
u8_factor_1/256 CAL_sensor_pps_reactivity;
uint32_t pps_2_smooth_x;
u8_factor_1/256 CAL_sensor_fuel_reactivity;
uint32_t fuel_level_smooth_x;
uint32_t evap_pressure_smooth_x;
u8_factor_1/256 CAL_sensor_evap_reactivity;
ushort DAT_003fd0b4;
ushort DAT_003fd0c0;
ushort DAT_003fd0de;
ushort REG_QADCA_RJURR1;
ushort DAT_003fd0e6;
ushort REG_QADCA_RJURR2;
ushort DAT_003fd0ea;
u16_voltage_5/1023v sensor_adc_coolant;
ushort DAT_003fd0ec;
u16_voltage_5/1023v sensor_adc_tc_button;
u16_voltage_5/1023v sensor_adc_engine_air;
ushort DAT_003fd0ee;
ushort REG_QADCA_RJURR5;
ushort DAT_003fd0f0;
ushort REG_QADCA_RJURR6;
ushort REG_QADCA_RJURR7;
ushort REG_QADCA_RJURR8;
ushort REG_QADCA_RJURR9;
u16_voltage_5/1023v sensor_adc_baro;
ushort REG_QADCA_RJURR12;
ushort REG_QADCB_RJURR0;
ushort REG_QADCA_RJURR13;
ushort REG_QADCB_RJURR1;
ushort REG_QADCA_RJURR14;
ushort REG_QADCB_RJURR2;
u16_voltage_5/1023v sensor_adc_pre_o2;
ushort REG_QADCA_RJURR15;
ushort REG_QADCB_RJURR3;
u16_voltage_5/1023v sensor_adc_post_o2;
ushort REG_QADCA_RJURR16;
ushort REG_QADCB_RJURR4;
ushort REG_QADCA_RJURR17;
ushort REG_QADCB_RJURR5;
u16_voltage_18/1023v sensor_adc_ecu_voltage;
ushort REG_QADCB_RJURR6;
u16_voltage_5/1023v sensor_adc_evap;
ushort REG_QADCB_RJURR7;
u16_voltage_5/1023v sensor_adc_fuel_level;
ushort REG_QADCB_RJURR8;
ushort REG_QADCB_RJURR9;
ushort REG_QADCB_RJURR10;
u16_voltage_5/1023v sensor_adc_intake_air;
ushort REG_QADCB_RJURR11;
ushort REG_QADCB_RJURR12;
ushort REG_QADCB_RJURR13;
ushort REG_QADCB_RJURR14;
ushort REG_QADCB_RJURR16;
undefined2 sensor_adc_oil_vvtl;
ushort REG_QADCB_RJURR17;
u16_voltage_5/1023v sensor_adc_map;
u16_voltage_5/1023v sensor_adc_free_2;
u16_voltage_5/1023v sensor_adc_free_1;
u16_voltage_5/1023v sensor_adc_oil_pressure;
u16_voltage_5/1023v sensor_adc_free_3;
u16_voltage_18/1023v sensor_adc_ign;
u16_voltage_5/1023v sensor_adc_free_4;
u16_voltage_5/1023v sensor_adc_ac_fan_request;
u16_voltage_5/1023v sensor_adc_tc_knob;
u16_voltage_5/1023v sensor_adc_tps_2;
undefined2 sensor_adc_knock;
bool CAL_misc_use_tmap;
u16_voltage_5/1023v sensor_adc_pre_o2_heater_sense;
u16_voltage_5/1023v sensor_adc_post_o2_heater_sense;
ushort REG_QADCA_RJURR3;
ushort REG_QADCA_RJURR4;
u8_factor_1/64 CAL_sensor_pps_1_gain;
u16_voltage_5/1023v LEA_sensor_pps_1_offset;
u8_factor_1/64 CAL_sensor_pps_2_gain;
u16_voltage_5/1023v LEA_sensor_pps_2_offset;
u16_voltage_5/1023v CAL_sensor_pps_offset_diff_max;
u16_voltage_5/1023v CAL_sensor_pps_1_offset_limit_l;
u8_factor_1/256 CAL_sensor_pps_offset_reactivity;
u16_voltage_5/1023v CAL_sensor_pps_1_offset;
u16_voltage_5/1023v CAL_sensor_pps_2_offset;
u16_voltage_5/1023v CAL_sensor_pps_2_offset_limit_l;
byte DAT_003f93a1;
byte DAT_003f93a2;
short DAT_003fd0d6;
u16_pressure_mbar CAL_sensor_baro_fallback;
u8_temp_5/8-40c engine_air_smooth;
u16_temp_5/8-40c engine_air;
u16_temp_5/8-40c coolant;
i16_pressure_mbar atmo_pressure;
u8_factor_1/156-14/156 fuel_level;
i16_pressure_1/10mbar evap_pressure;
u8_temp_5/8-40c[33] CAL_sensor_engine_air_scaling;
u8_temp_5/8-40c[33] CAL_sensor_coolant_scaling;
u16_ratio_mbar/5v CAL_sensor_baro_gain;
i16_pressure_mbar CAL_sensor_baro_offset;
u16_ratio_1/10mbar/5v CAL_sensor_evap_gain;
i16_pressure_1/10mbar CAL_sensor_evap_offset;
u16_ratio_mbar/5v CAL_sensor_map_gain;
u8_temp_5/8-40c intake_air_smooth;
i16_pressure_mbar CAL_sensor_map_offset;
u8_lambda_1/100 pre_o2;
u8_lambda_1/100 post_o2;
u8_factor_1/255 CAL_tps_fallback;
u8_temp_5/8-40c CAL_sensor_engine_air_fallback;
u8_temp_5/8-40c CAL_sensor_coolant_fallback;
i16_pressure_mbar map;
u8_factor_1/2560 CAL_sensor_engine_air_reactivity;
u8_factor_1/2560 CAL_sensor_coolant_reactivity;
u8_factor_1/2560 CAL_sensor_intake_air_reactivity;
uint16_t sensor_fault_flags;
u8_temp_5/8-40c[33] CAL_sensor_intake_air_scaling;
u8_voltage_5/1023v[16] CAL_sensor_o2_scaling_X_signal;
u8_lambda_1/100[16] CAL_sensor_o2_scaling;
u16_factor_1/1023 tps_max;
uint32_t engine_air_smooth_x;
uint32_t coolant_smooth_x;
uint32_t intake_air_smooth_x;
u16_temp_5/8-40c intake_air;
bool tps_both_fault;
u8_factor_1/156-14/156[9] CAL_sensor_fuel_scaling;
uint16_t CAL_ecu_engine_speed_byte_coefficient;
uint16_t CAL_ecu_engine_speed_byte_offset;
u16_time_4us engine_speed_period;
u16_current_mA pre_o2_heater_current;
u16_current_mA post_o2_heater_current;
u16_current_mA CAL_sensor_o2_heater_max;
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
short DAT_003fd1fa;
byte DAT_003f93fb;
byte DAT_003f94be;
int DAT_003f8c68;
int DAT_003f8c6c;
int DAT_003f8c70;
int DAT_003f8c74;
int DAT_003f8c78;
byte DAT_003f9366;
int DAT_003f8c7c;
uint DAT_003f8c80;
ushort DAT_003f8c60;
uint DAT_003f8c84;
u8_temp_5/8-40c[16] CAL_ign_adv_idle_base_X_coolant;
ushort DAT_003f8c62;
u8_angle_1/4deg[16] CAL_ign_adv_idle_base;
uint DAT_003f8c88;
u8_rspeed_4-512rpm[16] CAL_ign_adv_idle_adj1_X_idle_error;
ushort DAT_003f8c64;
u8_load_4mg/stroke CAL_vvl_high_load_enable;
u8_angle_1/4-32deg[16] CAL_ign_adv_idle_adj1;
uint DAT_003f8c8c;
u8_temp_5/8-40c[16] CAL_ign_adv_idle_adj2_X_engine_air;
ushort DAT_003f8c66;
u8_angle_1/4-32deg[16] CAL_ign_adv_idle_adj2;
short DAT_003f8c9c;
uint32_t DAT_003f8ca0;
int DAT_003f8020;
int DAT_003f8024;
int DAT_003f8028;
int DAT_003f802c;
u8_rspeed_125/4+500rpm[8] CAL_ign_adv_high_cam_base_X_engine_speed;
u8_load_4mg/stroke[8] CAL_ign_adv_high_cam_base_Y_engine_load;
u8_angle_1/4-10deg[64] CAL_ign_adv_high_cam_base;
u8_rspeed_125/4+500rpm[8] CAL_ign_adv_high_cam_knock_safe_X_engine_speed;
u8_load_4mg/stroke[8] CAL_ign_adv_high_cam_knock_safe_Y_engine_load;
u8_angle_1/4-10deg[64] CAL_ign_adv_high_cam_knock_safe;
u8_mass_8g[8] CAL_ign_adv_adj2_X_maf_accumulated;
u8_factor_1/255[8] CAL_ign_adv_adj2_Y_tps;
u8_factor_1/255[64] CAL_ign_adv_adj2;
u8_rspeed_125/4+500rpm[8] CAL_ign_dwell_base_X_engine_speed;
u8_voltage_72/1023v[8] CAL_ign_dwell_base_Y_car_voltage;
u8_time_64us[64] CAL_ign_dwell_base;
u8_rspeed_125/4+500rpm[32] CAL_ign_adv_low_cam_knock_safe_X_engine_speed;
u8_load_4mg/stroke[32] CAL_ign_adv_low_cam_knock_safe_Y_engine_load;
u16_factor_1/1023 pps;
u8_angle_1/4-10deg[1024] CAL_ign_adv_low_cam_knock_safe;
u8_rspeed_125/4+500rpm[32] CAL_ign_adv_low_cam_base_X_engine_speed;
u8_load_4mg/stroke[32] CAL_ign_adv_low_cam_base_Y_engine_load;
u8_angle_1/4-10deg[1024] CAL_ign_adv_low_cam_base;
u8_rspeed_125/4+500rpm[16] CAL_ign_adv_adj3_X_engine_speed;
u8_angle_1/4-32deg[16] CAL_ign_adv_adj3;
u8_temp_5/8-40c[8] CAL_ign_adv_adj3_adj_X_coolant;
u8_factor_1/128[8] CAL_ign_adv_adj3_adj;
uint8_t[16] CAL_ign_adv_idle_adj3_X_engine_speed_dt;
u8_angle_1/4-32deg[16] CAL_ign_adv_idle_adj3;
u8_factor_1/100[8] CAL_ign_adv_adj4_X_dt_tps_injtip;
u8_angle_1/4deg[8] CAL_ign_adv_adj4;
undefined2 ign_adv_adj2;
u8_angle_1/4deg ign_adv_cranking;
u8_factor_1/128 ign_adv_adj3_adj;
i16_angle_1/4deg ign_adv_adj3_base;
undefined1 ign_adv_adj4;
uint16_t ign_flags;
u8_speed_kph car_speed_smooth;
i16_angle_1/4deg ign_adv_idle_adj2;
i16_angle_1/4deg ign_adv_idle_adj3;
undefined2 ign_adv_idle_adj1_alternative;
undefined2 ign_adv_base2;
undefined2 ign_adv_idle_adj1;
undefined2 ign_adv_idle_base;
i16_angle_1/4deg[4] ign_adv_cyl;
u8_factor_1/255 ign_adv_adj_by_tc;
u8_temp_5/8-40c CAL_ign_stop_coolant_to_use_adj2_min;
u8_temp_5/8-40c CAL_ign_stop_coolant_to_use_adj2_max;
u8_angle_1/4deg CAL_ign_adv_dfso;
u8_angle_1/4-32deg[4] CAL_ign_adv_adj_cyl;
undefined2 ign_adv_base;
u8_angle_1/4deg ign_adv_smooth_step;
undefined2 ign_adv_knock;
i16_angle_1/4deg ign_adv_final;
u16_time_us ign_dwell_time;
u8_time_5ms ign_adv_idle_adj1_timer;
uint16_t idle_flags;
i16_rspeed_rpm engine_speed_idle_error;
u8_angle_1/4deg CAL_ign_adv_idle_adj_ac_on;
u8_angle_1/4-32deg CAL_ign_adv_limit_l;
int32_t engine_speed_dt;
u8_temp_5/8-40c coolant_stop;
u16_rspeed_rpm engine_speed_2;
i16_angle_1/4deg ign_adv_smooth;
i16_angle_1/4deg ign_adv_adj1;
i16_angle_1/4deg ign_adv_adj3;
u8_speed_kph CAL_idle_flow_adj5_max;
uint32_t ac_fan_flags;
bool vvl_is_high_cam;
u8_angle_1/4deg[4] knock_retard1;
u8_angle_1/4deg[4] knock_retard2;
u8_load_4mg/stroke load_2;
u16_rspeed_rpm CAL_vvl_rpm_enable;
u8_time_5ms CAL_ign_adv_idle_adj1_time;
u8_temp_5/8-40c[8] CAL_ign_adv_cranking_X_coolant_stop;
u8_angle_1/4deg[8] CAL_ign_adv_cranking;
u8_rspeed_4-512rpm[16] CAL_ign_adv_idle_adj1_alternative_X_idle_error;
u8_angle_1/4-32deg[16] CAL_ign_adv_idle_adj1_alternative;
u8_rspeed_125/4+500rpm[8] CAL_ign_adv_smooth_step_X_engine_speed;
u16_time_5ms ign_cranking_timer;
uint32_t[72] crank_tooth_pattern;
u8_factor_1/255[16] CAL_ign_adv_smooth_step_Y_pps;
u8_angle_1/4deg[128] CAL_ign_adv_smooth_step;
u8_temp_5/8-40c[16] CAL_ign_adv_adj1_X_engine_air;
u8_angle_1/4-32deg[16] CAL_ign_adv_adj1;
undefined1 ign_adv_smooth_timer;
u8_time_10ms CAL_ign_cranking_runtime_max;
uint8_t CAL_obd_P0351_debounce_threshold;
uint8_t CAL_obd_P0352_debounce_threshold;
struct_diag_channel[31] diag_channel;
uint8_t CAL_obd_P0353_debounce_threshold;
uint8_t CAL_obd_P0354_debounce_threshold;
uint16_t ign_feedback_missed_flags;
byte DAT_003fd180;
undefined2 DAT_003fd17c;
i16_angle_1/4deg knock_retard2_sum;
ushort DAT_003fd190;
int DAT_003fd18c;
int DAT_003fd184;
undefined1 DAT_003fd196;
int DAT_003f8cac;
byte DAT_003f8047;
int DAT_003fd170;
undefined2 DAT_003f8044;
u16_flow_mg/s CAL_inj_flow_rate;
u8_voltage_72/1023v[16] CAL_inj_time_base_X_car_voltage;
u8_time_20us[16] CAL_inj_time_base;
u8_temp_5/8-40c[16] CAL_inj_time_adj1_X_coolant_stop;
u8_mass_g[24] CAL_inj_time_adj1_Y_maf_accumulated;
u8_factor_1/32[384] CAL_inj_time_adj1;
u8_temp_5/8-40c[16] CAL_inj_time_adj2_X_engine_air;
u8_factor_1/128[16] CAL_inj_time_adj2;
i16_time_us LEA_ltft_zone1_adj;
u8_afr_1/100 CAL_inj_afr_adj_per_adv_adj;
u8_rspeed_125/4+500rpm[32] CAL_inj_efficiency_X_engine_speed;
u8_load_4mg/stroke[32] CAL_inj_efficiency_Y_engine_load;
u8_factor_1/200[1024] CAL_inj_efficiency;
u16_time_us inj_time_base;
u32_time_us inj_time_afr;
u32_time_us inj_time_final_1;
u8_load_4mg/stroke[16] CAL_inj_time_adj3_X_engine_load;
u32_time_us inj_time_cranking;
u8_temp_5/8-40c[16] CAL_inj_time_adj3_Y_coolant;
u8_factor_1/64[256] CAL_inj_time_adj3;
u16_afr_1/100 afr_target;
undefined2 inj_fuel_load_needed;
u32_time_us inj_time_cranking_adj;
u8_angle_720/256deg inj_angle_1;
u8_afr_1/100 afr_adj;
undefined1 inj_efficiency;
undefined1 inj_duty_cycle;
u16_rspeed_rpm revlimit;
u16_rspeed_rpm revlimit_misfire_eval;
u8_temp_5/8-40c[16] CAL_inj_time_adj_cranking_X_coolant_stop;
u8_time_256us[16] CAL_inj_time_adj_cranking;
u8_rspeed_125/4+500rpm[8] CAL_inj_angle_X_engine_speed;
u8_load_4mg/stroke[8] CAL_inj_angle_Y_engine_load;
u8_angle_720/256deg[64] CAL_inj_angle;
u8_temp_5/8-40c[8] CAL_revlimit_speed_base_X_coolant;
u8_time_100ms[8] CAL_revlimit_speed_base_Y_timer;
u8_rspeed_10+6000rpm[64] CAL_revlimit_speed_base;
u16_rspeed_rpm CAL_revlimit_offset_misfire_eval;
u16_afr_1/100 CAL_stft_afr;
u32_time_us injtip_reactive;
u32_time_us injtip_in;
u32_time_us injtip_out;
u8_factor_1/64 inj_time_adj3;
u8_factor_1/64 inj_time_adj1;
u16_rspeed_rpm CAL_revlimit_speed_adj_limp_reduced;
u8_factor_1/64 inj_time_adj2;
u16_rspeed_rpm LEA_tc_launchcontrol_revlimit;
uint8_t tc_flags;
undefined1 tc_min_speed;
u8_rspeed_125/4+500rpm[16] CAL_inj_afr_base_X_engine_speed;
u8_speed_kph wheel_speed_f_max_2;
u8_load_4mg/stroke[16] CAL_inj_afr_base_Y_engine_load;
u8_afr_1/20+5[256] CAL_inj_afr_base;
u16_rspeed_rpm CAL_revlimit_offset_reset_timer;
undefined2 evap_fuel_load;
i16_factor_1/2000 inj_time_adj_by_stft;
i16_factor_1/2000 inj_time_adj_by_ltft;
u8_time_100ms revlimit_timer_2;
u16_rspeed_rpm revlimit_base;
u8_time_5ms revlimit_timer_1;
u8_temp_5/8-40c[16] CAL_idle_speed_base_X_coolant;
short DAT_003fd1ec;
u8_rspeed_4+500rpm[16] CAL_idle_speed_base;
ushort DAT_003fd1fa;
u8_temp_5/8-40c[16] CAL_idle_flow_adj4_adj_X_coolant;
ushort DAT_003fd1e2;
u8_mass_4g[8] CAL_idle_flow_adj4_adj_Y_maf_accumulated;
ushort DAT_003fd1e4;
u8_factor_1/64[128] CAL_idle_flow_adj4_adj;
u8_flow_100mg/s DAT_003f8cbc;
u8_voltage_72/1023v[8] CAL_idle_flow_adj3_X_car_voltage;
byte DAT_003fd1df;
u8_flow_100-12800mg/s[8] CAL_idle_flow_adj3;
byte DAT_003fd1dd;
u8_rspeed_4+500rpm[8] CAL_idle_flow_adj4_X_idle_speed_target;
byte DAT_003fd1de;
u8_flow_100mg/s[8] CAL_idle_flow_adj4;
u8_rspeed_4-512rpm[16] CAL_idle_flow_adj5_X_engine_speed_idle_error;
byte DAT_003f93fc;
u8_flow_100-12800mg/s[16] CAL_idle_flow_adj5;
byte DAT_003f93fd;
u8_rspeed_4-512rpm[16] CAL_idle_flow_adj8_corr_step_X_engine_speed_idle_error;
byte DAT_003fd1e0;
u8_flow_100/1024mg/s[16] CAL_idle_flow_adj8_corr_step;
ushort DAT_003fd1e8;
short DAT_002f822e;
short DAT_002f8232;
short DAT_002f8230;
short DAT_002f8234;
short DAT_003f8048;
u8_flow_100mg/s[8] CAL_idle_tps_X_target_flow;
u8_pressure_4mbar[8] CAL_idle_tps_Y_vacuum;
u8_factor_1/1023[64] CAL_idle_tps;
u8_pressure_4mbar[4] CAL_idle_tps_engine_stop_X_atmo_pressure;
u8_temp_5/8-40c[16] CAL_idle_tps_engine_stop_Y_coolant;
u8_factor_1/1023[64] CAL_idle_tps_engine_stop;
u8_time_10ms[8] CAL_idle_flow_adj_ac_X_on_time;
u8_flow_100mg/s[8] CAL_idle_flow_adj_ac;
u8_time_10ms[8] CAL_idle_flow_adj_fan_low_X_on_time;
u8_flow_100mg/s[8] CAL_idle_flow_adj_fan_low;
u8_time_10ms[8] CAL_idle_flow_adj_fan_high_X_on_time;
u8_flow_100mg/s[8] CAL_idle_flow_adj_fan_high;
u8_speed_kph[8] CAL_idle_speed_adj_X_car_speed;
u8_rspeed_4rpm[8] CAL_idle_speed_adj;
u8_speed_kph[8] CAL_idle_flow_adj6_X_car_speed;
u8_flow_100mg/s[8] CAL_idle_flow_adj6;
u8_rspeed_125/4+500rpm[16] CAL_idle_flow_adj7_X_engine_speed;
u8_flow_100mg/s[16] CAL_idle_flow_adj7;
uint8_t idle_flow_adj4_adj;
uint8_t idle_flow_adj4;
i16_flow_100mg/s idle_flow_adj5_or_zero;
i32_flow_100/1024mg/s idle_flow_adj8;
i16_pressure_4mbar vacuum_2;
i16_flow_100/1024mg/s LEA_idle_flow_adj1;
u8_flow_100mg/s CAL_idle_flow_adj1_corr_max;
i16_flow_100/1024mg/s LEA_idle_flow_adj1_ac_on;
u8_flow_-100mg/s CAL_idle_flow_adj1_corr_min;
u8_flow_100mg/s CAL_idle_flow_adj1_corr_limit_h;
u8_flow_-100mg/s CAL_idle_flow_adj1_corr_limit_l;
u8_flow_100mg/s idle_flow_target;
uint8_t idle_status;
u16_factor_1/1023 idle_tps_target;
undefined idle_flow_adj5;
undefined1 idle_flow_adj8_corr_step;
undefined idle_flow_adj2;
u8_flow_100mg/s CAL_idle_flow_base;
undefined1 idle_flow_adj7;
u8_time_5ms CAL_idle_flow_adj8_corr_time_between_step;
u8_flow_100mg/s CAL_idle_flow_adj8_corr_limit_h;
u8_flow_-100mg/s CAL_idle_flow_adj8_corr_limit_l;
i16_rspeed_rpm idle_speed_target;
u8_factor_1/1023 CAL_idle_flow_pps_max;
undefined2 idle_flow_adj3;
undefined2 idle_flow_adj6;
u8_rspeed_8rpm CAL_idle_flow_adj7_disable;
u8_rspeed_8rpm CAL_idle_flow_adj7_enable;
undefined1 idle_flow_adj_ac;
undefined1 idle_flow_adj_fan_low;
undefined1 idle_flow_adj_fan_high;
u16_factor_1/1023 CAL_idle_tps_limit_h;
u16_mass_g CAL_idle_flow_adj1_corr_maf_accumulated_min;
i16_pressure_mbar vacuum_1;
u16_rspeed_rpm CAL_idle_speed_adj_ac_on;
uint16_t evap_flags;
u16_flow_mg/s evap_flow;
u8_pressure_4mbar[8] CAL_idle_flow_adj2_X_atmo_pressure;
u8_flow_100mg/s[8] CAL_idle_flow_adj2;
undefined2 idle_speed_adj;
byte DAT_003f8cbc;
u8_time_5ms DAT_003f8cb8;
short DAT_003fd1e8;
u8_time_5ms DAT_003f8cb9;
char DAT_003fd1e0;
u8_time_5ms CAL_idle_flow_time_between_decrement;
u8_time_5ms CAL_idle_speed_time_between_decrement;
char DAT_003fe182;
undefined2 DAT_003fe184;
char DAT_003fd200;
undefined1 DAT_003f8b28;
undefined1 DAT_003fe189;
uint8_t DAT_003fd65c;
u16_time_4us CAL_misc_engine_running_enable;
undefined2 DAT_003fd228;
u16_time_4us CAL_misc_engine_running_disable;
u8_temp_5/8-40c engine_air_stop;
char DAT_003fd22f;
short DAT_003f8086;
u16_voltage_5/1023v sensor_adc_maf1;
ushort REG_TPU3A_CH15_PARAM6;
u16_time_us wheel_period_fl;
u16_voltage_5/1023v sensor_adc_maf2;
ushort REG_TPU3A_CH0_PARAM2;
u16_time_us wheel_period_fr;
u8_mass_65536mg[17] CAL_obd_P0128_wait_air_mass;
u16_time_us wheel_period_rl;
u16_time_us wheel_period_rr;
char DAT_003f9374;
undefined2 DAT_003fe178;
undefined2 DAT_003f8056;
uint16_t[15] engine_speed_period_history;
ushort DAT_003f8086;
uint8_t CAL_sensor_engine_speed_period_avg_size;
undefined2 DAT_003fbff0;
undefined2 dfso_count;
undefined2 DAT_003fda9c;
ushort DAT_003f8cc0;
byte DAT_003f8cc2;
uint8_t CAL_misc_engine_running_crank_tooth_min;
u16_time_4us engine_speed_period_avg;
uint8_t CAL_sensor_dt_engine_speed_age;
uint8_t CAL_ign_adv_idle_adj3_engine_speed_dt_age;
u8_factor_1/256 CAL_injtip_catalyst_adj_fadeout;
undefined1 injtip_in_speed;
short DAT_003fd268;
undefined1 injtip_in_coolant;
u32_time_us DAT_003fd260;
undefined1 injtip_out_speed;
u32_time_us DAT_003fd264;
undefined1 injtip_out_coolant;
undefined1 injtip_in_gear;
u8_rspeed_125/4+500rpm[16] CAL_injtip_in_adj1_X_engine_speed;
u8_factor_1/128[16] CAL_injtip_in_adj1;
u8_rspeed_125/4+500rpm[16] CAL_injtip_in_adj2_X_engine_speed;
u8_dt_factor_1/100/5ms[16] CAL_injtip_in_adj2;
u8_temp_5/8-40c[16] CAL_injtip_in_adj3_X_coolant;
u8_factor_1/64[16] CAL_injtip_in_adj3;
u8_rspeed_125/4+500rpm[16] CAL_injtip_out_adj1_X_engine_speed;
u8_factor_1/128[16] CAL_injtip_out_adj1;
u8_rspeed_125/4+500rpm[16] CAL_injtip_out_adj2_X_engine_speed;
u8_dt_factor_1/100/5ms[16] CAL_injtip_out_adj2;
u8_temp_5/8-40c[16] CAL_injtip_out_adj3_X_coolant;
u8_factor_1/64[16] CAL_injtip_out_adj3;
u8_factor_1/128[6] CAL_injtip_in_adj_gears;
u8_speed_kph CAL_dfso_car_speed_enable;
u8_speed_kph CAL_dfso_car_speed_disable;
u8_factor_1/255[4] CAL_dfso_delay_X_pps;
u8_time_5ms[4] CAL_dfso_delay;
u8_factor_1/128 CAL_injtip_in_adj_gears_6;
u8_time_us CAL_injtip_time_base;
uint8_t car_gear_current;
u8_factor_1/1023 CAL_dfso_pps_disable;
u8_factor_1/1023 CAL_dfso_pps_enable;
u16_rspeed_rpm CAL_dfso_engine_speed_enable;
u16_rspeed_rpm CAL_dfso_engine_speed_disable;
u8_temp_5/8-40c CAL_dfso_coolant_enable;
u8_temp_5/8-40c CAL_dfso_coolant_disable;
u8_time_50ms CAL_dfso_runtime_min;
uint8_t[17] CAL_injtip_catalyst_adj;
u8_temp_5/8-40c[8] CAL_vvt_runtime_min_X_coolant_stop;
i16_angle_1/4deg vvt_target;
u8_time_100ms[8] CAL_vvt_runtime_min;
u16_factor_1/1024 vvt_duty_cycle;
int16_t vvt_ctrl_p;
int32_t vvt_ctrl_i;
int32_t vvt_output;
i32_angle_1/4deg vvt_rest_pos_sum;
int32_t vvt_rest_pos_count;
i16_angle_1/4deg vvt_pos;
bool vvt_cam_updated;
bool vvt_rest_pos_measured;
i16_angle_1/4deg vvt_diff;
bool vvt_rest_pos_fault;
i16_angle_1/4deg vvt_target_smooth;
uint16_t vvt_runtime_min;
i16_angle_1/4deg vvt_rest_pos_min;
i16_angle_1/4deg vvt_rest_pos_max;
u8_rspeed_125/4+500rpm[16] CAL_vvt_adv_low_cam_base_X_engine_speed;
i32_angle_1/4deg vvt_rest_pos_avg;
u8_load_4mg/stroke[16] CAL_vvt_adv_low_cam_base_Y_engine_load;
u8_angle_1/4deg[256] CAL_vvt_adv_low_cam_base;
u8_temp_5/8-40c[16] CAL_vvt_adv_adj_X_coolant;
u8_angle_1/4deg[16] CAL_vvt_adv_adj;
u8_angle_1/4deg CAL_vvt_rest_pos_threshold;
u8_rspeed_125/4+500rpm[16] CAL_vvt_adv_high_cam_base_X_engine_speed;
i16_factor_1/256 CAL_vvt_ctrl_p_gain;
u8_load_4mg/stroke[16] CAL_vvt_adv_high_cam_base_Y_engine_load;
u8_angle_1/4deg[256] CAL_vvt_adv_high_cam_base;
u16_factor_1/2048 vvl_duty_cycle;
u16_rspeed_rpm CAL_vvl_rpm_disable;
u8_temp_5/8-40c CAL_vvl_coolant_enable;
u8_temp_5/8-40c CAL_vvl_coolant_disable;
u16_factor_1/2048 CAL_vvl_duty_cycle_engaged;
u16_rspeed_rpm CAL_vvl_rpm_high_load_enable;
u16_factor_1/2048 CAL_vvl_duty_cycle_disengaged;
u16_rspeed_rpm CAL_vvl_rpm_high_load_disable;
u8_load_4mg/stroke CAL_vvl_high_load_disable;
undefined DAT_00019000;
i16_factor_1/256 CAL_vvt_ctrl_i_gain;
u8_time_5ms vvt_timer;
bool vvt_target_reached;
uint8_t LEA_obd_P2649_flags;
uint8_t LEA_obd_P0077_flags;
u16_time_5ms CAL_ecu_startrelay_runtime_max;
char[17] LEA_ecu_VIN;
u16_time_s shutdown_delay_1;
uint8_t eeprom_saved;
u8_voltage_72/1023v CAL_ecu_ign_min;
u8_temp_5/8-40c[8] CAL_ecu_shutdown_delay_X_engine_air;
u8_temp_5/8-40c[8] CAL_ecu_shutdown_delay_Y_coolant;
u8_time_5s[64] CAL_ecu_shutdown_delay;
ushort DAT_003fcffa;
ushort DAT_003fcff8;
u8_rspeed_125/4+500rpm CAL_ac_engine_speed_disable;
u8_rspeed_125/4+500rpm CAL_ac_engine_speed_enable;
u8_time_100ms CAL_ac_pps_disable_time_min;
u8_time_5ms CAL_ac_user_enable_time_min;
u8_speed_kph CAL_ac_car_speed_disable;
u8_speed_kph CAL_ac_car_speed_enable;
u16_time_5ms CAL_ac_runtime_min;
u8_temp_5/8-40c CAL_ac_coolant_disable;
u8_temp_5/8-40c CAL_ac_coolant_enable;
u8_factor_1/255 CAL_ac_pps_disable;
u8_factor_1/255 CAL_ac_tps_enable;
u8_time_5ms CAL_ac_user_disable_time_min;
uint16_t uint16_t_003fd2a6;
u16_ratio_rpm/kph[2] CAL_misc_gears_6;
uint ratio;
u16_ratio_rpm/kph[10] CAL_misc_gears;
u8_temp_5/8-40c CAL_misc_recirculation_pump_stop_enable;
u8_temp_5/8-40c CAL_misc_recirculation_pump_stop_disable;
u8_temp_5/8-40c CAL_fan_high_disable;
u8_temp_5/8-40c CAL_fan_high_ac_disable;
u8_speed_kph CAL_fan_car_speed_disable;
u16_time_5ms CAL_fan_high_stop_time_min;
u8_time_20s CAL_fan_high_stop_user_delay;
u16_time_100ms fan_high_stop_user_timer;
u16_time_5ms CAL_fan_low_stop_time_min;
u8_temp_5/8-40c CAL_fan_low_enable;
u8_temp_5/8-40c CAL_fan_low_disable;
u8_temp_5/8-40c CAL_fan_low_stop_enable;
u8_temp_5/8-40c CAL_fan_low_stop_disable;
u8_temp_5/8-40c CAL_fan_high_enable;
u8_temp_5/8-40c CAL_fan_high_ac_enable;
bool DAT_003fd2ad;
bool DAT_003fd2ae;
bool DAT_003fd2af;
bool DAT_003fd2b0;
undefined1 DAT_003fd2b1;
bool DAT_003fd2b2;
bool DAT_003fd2b3;
bool DAT_003fd2b4;
bool DAT_003fd2bd;
bool DAT_003fd2bc;
ushort DAT_003f8cf0;
u16_rspeed_rpm obd_mode_0x2F_RPM;
u8_factor_1/255 DAT_003fd2ac;
byte DAT_003fc005;
short DAT_003f8802;
uint8_t[8] CAL_misc_shift_lights_before_revlimit_X_car_gear_current;
uint16_t obd_mil_flags;
struct_cluster_data cluster_data;
bool LEA_tc_button_fitted;
u16_rspeed_rpm CAL_misc_shift_lights_margin;
u16_rspeed_rpm CAL_misc_airbox_flap_disable;
u16_rspeed_rpm CAL_misc_airbox_flap_enable;
uint16_t[256] CRC16_lookup;
ushort DAT_003fd2fe;
short DAT_003fd320;
undefined2 DAT_003fd356;
undefined2 DAT_003fd322;
u8_time_5ms DAT_003fd326;
u8_rspeed_125/4+500rpm[16] LEA_load_alphaN_adj_X_engine_speed;
byte DAT_003f8cfa;
u8_factor_1/255[16] LEA_load_alphaN_adj_Y_tps;
ushort DAT_003fd30e;
u8_factor_1/100[256] LEA_load_alphaN_adj;
ushort DAT_003fd310;
undefined1 DAT_003fd32c;
byte DAT_003fd32d;
undefined DAT_003fa318;
undefined DAT_003fa328;
undefined DAT_003fa338;
undefined DAT_003fa348;
u16_flow_10mg/s maf_flow_2;
u8_rspeed_125/4+500rpm[16] CAL_load_alphaN_base_X_engine_speed;
u8_factor_1/255[16] CAL_load_alphaN_base_Y_tps;
u8_load_4mg/stroke[256] CAL_load_alphaN_base;
u8_time_5ms CAL_load_use_alphaN_timer;
u8_rspeed_125/4+500rpm[16] CAL_load_possible_max_X_engine_speed;
u8_load_4mg/stroke[16] CAL_load_possible_max;
u8_rspeed_125/4+500rpm[16] CAL_load_use_alphaN_tps_min_X_engine_speed;
u8_factor_1/255[16] CAL_load_use_alphaN_tps_min;
u16_voltage_5/1023v[32] CAL_sensor_maf_scaling_X_signal;
u16_flow_10mg/s[32] CAL_sensor_maf_scaling;
u16_load_mg/stroke CAL_load_possible_max_mode22;
u16_load_mg/stroke CAL_load_possible_max_absolute;
undefined2 load_diff;
u32_load_mg/stroke load_maf;
u16_flow_10mg/s maf_flow_diff;
u32_load_mg/stroke load_alphaN;
u16_factor_1/100 load_alphaN_adj;
u16_rspeed_rpm CAL_load_use_alphaN_engine_speed_max;
u8_factor_1/255 load_3;
u16_factor_1/1023 CAL_load_use_alphaN_dt_tps_target_1_negative_min;
u8_factor_1/255 load_4;
u8_factor_1/100 load_5;
uint8_t load_use_alphaN;
u16_factor_1/1023 CAL_load_use_alphaN_dt_tps_target_1_positive_min;
u8_factor_1/255[16] CAL_load_alphaN_engine_stop_X_tps;
u8_load_4mg/stroke[16] CAL_load_alphaN_engine_stop;
ushort DAT_003fd580;
short DAT_003f8d1e;
u8_time_100ms DAT_003f8d22;
u8_time_100ms DAT_003f80bc;
short DAT_003f8d26;
u8_time_100ms DAT_003f8d29;
ushort DAT_003f9522;
u8_time_100ms DAT_003f80bd;
short DAT_003f94ca;
ushort DAT_003f94c6;
u8_time_100ms DAT_003f8d24;
ushort DAT_003f94ee;
ushort DAT_003f94c8;
undefined4 evap_concentration_1;
undefined2 evap_pressure_drop_1;
uint8_t CAL_evap_purge_mode;
u8_time_100ms CAL_evap_initial_delay;
undefined2 evap_pressure_drop_inc;
u8_pressure_1/64mbar CAL_evap_pressure_drop_inc_limit_l;
u8_time_100ms CAL_evap_dfso_recovery_delay;
u8_time_1600ms CAL_evap_restart_delay;
u8_time_800ms CAL_evap_engine_start_delay;
u8_time_100ms CAL_evap_duty_cycle_initial_time;
u8_time_100ms CAL_evap_closedloop_delay;
uint8_t evap_leak_state;
u8_time_100ms CAL_evap_learn_delay;
undefined2 evap_purge_command;
undefined1 evap_pressure_drop_2;
uint8_t LEA_obd_P0441_flags;
u16_factor_1/100 evap_concentration_2;
undefined1 evap_state;
uint8_t LEA_obd_P0444_flags;
uint16_t fuel_system_status;
uint8_t LEA_obd_P0445_flags;
u16_time_100ms fuel_learn_timer;
u8_time_100ms DAT_003f8d28;
char DAT_003f80bc;
short DAT_003fc056;
ushort DAT_003fd17c;
char DAT_003f8d29;
u8_pressure_4mbar CAL_evap_pressure_drop_idle_limit_h;
u16_flow_mg/s evap_fuel_flow_correction;
undefined2 evap_fuel_flow;
u8_pressure_4mbar evap_pressure_drop_max;
u8_pressure_4mbar evap_pressure_drop_max_vacuum;
u8_pressure_4mbar evap_pressure_drop_max_load;
u8_time_8us CAL_evap_inj_time_enable;
undefined4 evap_concentration_adj;
u8_time_8us CAL_evap_inj_time_disable;
undefined2 evap_fuel_load_prev;
u8_pressure_1/64mbar CAL_evap_pressure_drop_dec_initial;
undefined2 evap_stft_neg;
u8_flow_100mg/s CAL_evap_idle_flow_enable;
u8_flow_100mg/s CAL_evap_idle_flow_disable;
uint8_t CAL_evap_flow_divisor;
u8_pressure_4mbar evap_pressure_drop_max_leak_test;
undefined2 evap_pressure_drop_dec;
u8_time_100ms CAL_evap_stft_stability_delay;
u8_factor_1/255 CAL_evap_duty_cycle_initial;
u8_factor_1/255 CAL_evap_duty_cycle_limit_h;
u8_factor_1/255 CAL_evap_duty_cycle_limit_l;
u8_pressure_4mbar[16] CAL_evap_purge_X_pressure_drop;
u8_pressure_4mbar[16] CAL_evap_purge_Y_vacuum;
u8_factor_1/255[256] CAL_evap_purge;
u8_pressure_4mbar[8] CAL_evap_pressure_drop_max_X_vacuum;
u8_pressure_4mbar[8] CAL_evap_pressure_drop_max;
i16_pressure_mbar vacuum_smooth;
undefined1 evap_flow_2;
undefined2 evap_pwm_pulse;
undefined2 evap_duty_adj;
i16_factor_1/2000 inj_time_stft_smooth;
char DAT_003f80bd;
char DAT_003f8d22;
char DAT_003f8d28;
char DAT_003f8d24;
short DAT_003f8d00;
short DAT_003f94ec;
byte DAT_003f8d23;
int DAT_003fd368;
int DAT_003f8d10;
u16_factor_1/2000 CAL_stft_limit;
uint32_t vacuum_smooth_x;
u8_factor_1/256 CAL_evap_vacuum_reactivity;
undefined2 DAT_002f8024;
uint8_t LEA_obd_P0447_engine_start_count;
undefined2 DAT_002f8026;
uint8_t LEA_obd_P0447_warm_up_cycle_count;
undefined1 DAT_002f82ff;
undefined2 DAT_002f830e;
uint8_t LEA_obd_P0448_flags;
undefined2 DAT_002f8310;
uint8_t LEA_obd_P0448_engine_start_count;
undefined1 DAT_002f8312;
uint8_t LEA_obd_P0448_warm_up_cycle_count;
undefined2 DAT_002f8314;
undefined1 DAT_002f8316;
undefined1 DAT_002f8317;
undefined1 DAT_002f8318;
undefined2 DAT_002f831a;
undefined2 DAT_002f831c;
uint8_t LEA_obd_P0201_flags;
undefined1 DAT_002f831e;
uint8_t LEA_obd_P0201_engine_start_count;
undefined1 DAT_002f831f;
uint8_t LEA_obd_P0201_warm_up_cycle_count;
undefined2 DAT_002f8320;
undefined1 DAT_002f82c3;
undefined1 DAT_002f8322;
undefined4 DAT_002f833c;
undefined2 DAT_002f8342;
undefined4 DAT_002f8344;
uint8_t LEA_obd_P0202_flags;
undefined2 DAT_002f834e;
uint8_t LEA_obd_P0202_engine_start_count;
undefined2 DAT_002f8350;
uint8_t LEA_obd_P0202_warm_up_cycle_count;
undefined2 DAT_002f8352;
undefined2 DAT_002f822e;
undefined2 DAT_002f8230;
undefined2 DAT_002f8232;
undefined2 DAT_002f8234;
uint8_t DAT_002f82c2;
uint8_t LEA_obd_P0203_flags;
undefined2 DAT_002f8354;
uint8_t LEA_obd_P0203_engine_start_count;
uint8_t LEA_obd_P0203_warm_up_cycle_count;
undefined2 DAT_002f8206;
undefined2 DAT_002f821a;
undefined2 DAT_002f8236;
undefined2 DAT_002f824a;
undefined2 DAT_002f825e;
undefined2 DAT_002f8272;
uint8_t LEA_obd_P0204_flags;
undefined2 DAT_002f829a;
uint8_t LEA_obd_P0204_engine_start_count;
undefined2 DAT_002f82ae;
uint8_t LEA_obd_P0204_warm_up_cycle_count;
undefined1 DAT_002f82cf;
undefined1 DAT_002f82df;
undefined1 DAT_002f82ef;
undefined1 DAT_003fce7a;
uint8_t LEA_obd_P0205_flags;
uint8_t LEA_obd_P0205_engine_start_count;
uint8_t LEA_obd_P0205_warm_up_cycle_count;
uint8_t LEA_obd_P0351_flags;
uint8_t LEA_obd_P0351_engine_start_count;
uint8_t LEA_obd_P0351_warm_up_cycle_count;
uint8_t LEA_obd_P0352_flags;
uint8_t LEA_obd_P0352_engine_start_count;
uint8_t LEA_obd_P0352_warm_up_cycle_count;
uint8_t LEA_obd_P0353_flags;
uint8_t LEA_obd_P0353_engine_start_count;
uint8_t LEA_obd_P0353_warm_up_cycle_count;
uint8_t LEA_obd_P0354_flags;
uint8_t LEA_obd_P0354_engine_start_count;
uint8_t LEA_obd_P0354_warm_up_cycle_count;
uint8_t LEA_obd_P0627_flags;
uint8_t LEA_obd_P0627_engine_start_count;
uint8_t LEA_obd_P0627_warm_up_cycle_count;
uint8_t LEA_obd_P0480_flags;
uint8_t LEA_obd_P0480_engine_start_count;
uint8_t LEA_obd_P0480_warm_up_cycle_count;
uint8_t LEA_obd_P0481_flags;
uint8_t LEA_obd_P0481_engine_start_count;
uint8_t LEA_obd_P0481_warm_up_cycle_count;
uint8_t LEA_obd_P0135_flags;
uint8_t LEA_obd_P0135_engine_start_count;
uint8_t LEA_obd_P0135_warm_up_cycle_count;
uint8_t LEA_obd_P0141_flags;
uint8_t LEA_obd_P0141_engine_start_count;
uint8_t LEA_obd_P0141_warm_up_cycle_count;
uint8_t LEA_obd_P2602_flags;
uint8_t LEA_obd_P2602_engine_start_count;
uint8_t LEA_obd_P2602_warm_up_cycle_count;
uint8_t LEA_obd_P2603_flags;
uint8_t LEA_obd_P2603_engine_start_count;
uint8_t LEA_obd_P2603_warm_up_cycle_count;
uint8_t LEA_obd_P2648_flags;
uint8_t LEA_obd_P2648_engine_start_count;
uint8_t LEA_obd_P2648_warm_up_cycle_count;
uint8_t LEA_obd_P2649_engine_start_count;
uint8_t LEA_obd_P2649_warm_up_cycle_count;
uint8_t LEA_obd_P0455_flags;
uint8_t LEA_obd_P0455_engine_start_count;
uint8_t LEA_obd_P0455_warm_up_cycle_count;
uint8_t LEA_obd_P0441_engine_start_count;
uint8_t LEA_obd_P0441_warm_up_cycle_count;
uint8_t LEA_obd_P0446_flags;
uint8_t LEA_obd_P0446_engine_start_count;
uint8_t LEA_obd_P0446_warm_up_cycle_count;
uint8_t LEA_obd_P0500_flags;
uint8_t LEA_obd_P0500_engine_start_count;
uint8_t LEA_obd_P0500_warm_up_cycle_count;
uint8_t LEA_obd_P0335_flags;
uint8_t LEA_obd_P0335_engine_start_count;
uint8_t LEA_obd_P0335_warm_up_cycle_count;
uint8_t LEA_obd_P0340_flags;
uint8_t LEA_obd_P0340_engine_start_count;
uint8_t LEA_obd_P0340_warm_up_cycle_count;
uint8_t LEA_obd_P0171_flags;
uint8_t LEA_obd_P0171_engine_start_count;
uint8_t LEA_obd_P0171_warm_up_cycle_count;
uint8_t LEA_obd_P0172_flags;
uint8_t LEA_obd_P0172_engine_start_count;
uint8_t LEA_obd_P0172_warm_up_cycle_count;
uint8_t LEA_obd_P0506_flags;
uint8_t LEA_obd_P0506_engine_start_count;
uint8_t LEA_obd_P0506_warm_up_cycle_count;
uint8_t LEA_obd_P0507_flags;
uint8_t LEA_obd_P0507_engine_start_count;
uint8_t LEA_obd_P0507_warm_up_cycle_count;
uint8_t LEA_obd_P0442_flags;
uint8_t LEA_obd_P0442_engine_start_count;
uint8_t LEA_obd_P0442_warm_up_cycle_count;
uint8_t LEA_obd_P0456_flags;
uint8_t LEA_obd_P0456_engine_start_count;
uint8_t LEA_obd_P0456_warm_up_cycle_count;
uint8_t LEA_obd_P0601_flags;
uint8_t LEA_obd_P0601_engine_start_count;
uint8_t LEA_obd_P0601_warm_up_cycle_count;
uint8_t LEA_obd_P0606_flags;
uint8_t LEA_obd_P0606_engine_start_count;
uint8_t LEA_obd_P0606_warm_up_cycle_count;
uint8_t LEA_obd_P1302_flags;
uint8_t LEA_obd_P1302_engine_start_count;
uint8_t LEA_obd_P1302_warm_up_cycle_count;
uint8_t LEA_obd_P1301_flags;
uint8_t LEA_obd_P1301_engine_start_count;
uint8_t LEA_obd_P1301_warm_up_cycle_count;
uint8_t LEA_obd_P0301_flags;
uint8_t LEA_obd_P0301_engine_start_count;
uint8_t LEA_obd_P0301_warm_up_cycle_count;
uint8_t LEA_obd_P0302_flags;
uint8_t LEA_obd_P0302_engine_start_count;
uint8_t LEA_obd_P0302_warm_up_cycle_count;
uint8_t LEA_obd_P0303_flags;
uint8_t LEA_obd_P0303_engine_start_count;
uint8_t LEA_obd_P0303_warm_up_cycle_count;
uint8_t LEA_obd_P0304_flags;
uint8_t LEA_obd_P0304_engine_start_count;
uint8_t LEA_obd_P0304_warm_up_cycle_count;
uint8_t LEA_obd_P0300_flags;
uint8_t LEA_obd_P0300_engine_start_count;
uint8_t LEA_obd_P0300_warm_up_cycle_count;
uint8_t LEA_obd_P0134_flags;
uint8_t LEA_obd_P0134_engine_start_count;
uint8_t LEA_obd_P0134_warm_up_cycle_count;
uint8_t LEA_obd_P0140_flags;
uint8_t LEA_obd_P0140_engine_start_count;
uint8_t LEA_obd_P0140_warm_up_cycle_count;
uint8_t LEA_obd_P0133_flags;
uint8_t LEA_obd_P0133_engine_start_count;
uint8_t LEA_obd_P0133_warm_up_cycle_count;
uint8_t LEA_obd_P0139_flags;
uint8_t LEA_obd_P0139_engine_start_count;
uint8_t LEA_obd_P0139_warm_up_cycle_count;
uint8_t LEA_obd_P0101_flags;
uint8_t LEA_obd_P0101_engine_start_count;
uint8_t LEA_obd_P0101_warm_up_cycle_count;
uint8_t LEA_obd_P0102_flags;
uint8_t LEA_obd_P0102_engine_start_count;
uint8_t LEA_obd_P0102_warm_up_cycle_count;
uint8_t LEA_obd_P0103_flags;
uint8_t LEA_obd_P0103_engine_start_count;
uint8_t LEA_obd_P0103_warm_up_cycle_count;
uint8_t LEA_obd_P0106_flags;
uint8_t LEA_obd_P0106_engine_start_count;
uint8_t LEA_obd_P0106_warm_up_cycle_count;
uint8_t LEA_obd_P0107_flags;
uint8_t LEA_obd_P0107_engine_start_count;
uint8_t LEA_obd_P0107_warm_up_cycle_count;
uint8_t LEA_obd_P0108_flags;
uint8_t LEA_obd_P0108_engine_start_count;
uint8_t LEA_obd_P0108_warm_up_cycle_count;
uint8_t LEA_obd_P0131_flags;
uint8_t LEA_obd_P0131_engine_start_count;
uint8_t LEA_obd_P0131_warm_up_cycle_count;
uint8_t LEA_obd_P0132_flags;
uint8_t LEA_obd_P0132_engine_start_count;
uint8_t LEA_obd_P0132_warm_up_cycle_count;
uint8_t LEA_obd_P0137_flags;
uint8_t LEA_obd_P0137_engine_start_count;
uint8_t LEA_obd_P0137_warm_up_cycle_count;
uint8_t LEA_obd_P0138_flags;
uint8_t LEA_obd_P0138_engine_start_count;
uint8_t LEA_obd_P0138_warm_up_cycle_count;
uint8_t LEA_obd_P0111_flags;
uint8_t LEA_obd_P0111_engine_start_count;
uint8_t LEA_obd_P0111_warm_up_cycle_count;
uint8_t LEA_obd_P0112_flags;
uint8_t LEA_obd_P0112_engine_start_count;
uint8_t LEA_obd_P0112_warm_up_cycle_count;
uint8_t LEA_obd_P0113_flags;
uint8_t LEA_obd_P0113_engine_start_count;
uint8_t LEA_obd_P0113_warm_up_cycle_count;
uint8_t LEA_obd_P0116_flags;
uint8_t LEA_obd_P0116_engine_start_count;
uint8_t LEA_obd_P0116_warm_up_cycle_count;
uint8_t LEA_obd_P0117_flags;
uint8_t LEA_obd_P0117_engine_start_count;
uint8_t LEA_obd_P0117_warm_up_cycle_count;
uint8_t LEA_obd_P0118_flags;
uint8_t LEA_obd_P0118_engine_start_count;
uint8_t LEA_obd_P0118_warm_up_cycle_count;
uint8_t LEA_obd_P0237_flags;
uint8_t LEA_obd_P0237_engine_start_count;
uint8_t LEA_obd_P0237_warm_up_cycle_count;
uint8_t LEA_obd_P0238_flags;
uint8_t LEA_obd_P0238_engine_start_count;
uint8_t LEA_obd_P0238_warm_up_cycle_count;
uint8_t LEA_obd_P0452_flags;
uint8_t LEA_obd_P0452_engine_start_count;
uint8_t LEA_obd_P0452_warm_up_cycle_count;
uint8_t LEA_obd_P0453_flags;
uint8_t LEA_obd_P0453_engine_start_count;
uint8_t LEA_obd_P0453_warm_up_cycle_count;
uint8_t LEA_obd_P0327_flags;
uint8_t LEA_obd_P0327_engine_start_count;
uint8_t LEA_obd_P0327_warm_up_cycle_count;
uint8_t LEA_obd_P0328_flags;
uint8_t LEA_obd_P0328_engine_start_count;
uint8_t LEA_obd_P0328_warm_up_cycle_count;
uint8_t LEA_obd_P0462_flags;
uint8_t LEA_obd_P0462_engine_start_count;
uint8_t LEA_obd_P0462_warm_up_cycle_count;
uint8_t LEA_obd_P0463_flags;
uint8_t LEA_obd_P0463_engine_start_count;
uint8_t LEA_obd_P0463_warm_up_cycle_count;
uint8_t LEA_obd_P0562_flags;
uint8_t LEA_obd_P0562_engine_start_count;
uint8_t LEA_obd_P0562_warm_up_cycle_count;
uint8_t LEA_obd_P0563_flags;
uint8_t LEA_obd_P0563_engine_start_count;
uint8_t LEA_obd_P0563_warm_up_cycle_count;
uint8_t LEA_obd_P0128_flags;
uint8_t LEA_obd_P0128_engine_start_count;
uint8_t LEA_obd_P0128_warm_up_cycle_count;
uint8_t LEA_obd_P0461_flags;
uint8_t LEA_obd_P0461_engine_start_count;
uint8_t LEA_obd_P0461_warm_up_cycle_count;
uint8_t LEA_obd_P0451_flags;
uint8_t LEA_obd_P0451_engine_start_count;
uint8_t LEA_obd_P0451_warm_up_cycle_count;
uint8_t LEA_obd_P2138_flags;
uint8_t LEA_obd_P2138_engine_start_count;
uint8_t LEA_obd_P2138_warm_up_cycle_count;
uint8_t LEA_obd_P2122_flags;
uint8_t LEA_obd_P2122_engine_start_count;
uint8_t LEA_obd_P2122_warm_up_cycle_count;
uint8_t LEA_obd_P2123_flags;
uint8_t LEA_obd_P2123_engine_start_count;
uint8_t LEA_obd_P2123_warm_up_cycle_count;
uint8_t LEA_obd_P2127_flags;
uint8_t LEA_obd_P2127_engine_start_count;
uint8_t LEA_obd_P2127_warm_up_cycle_count;
uint8_t LEA_obd_P2128_flags;
uint8_t LEA_obd_P2128_engine_start_count;
uint8_t LEA_obd_P2128_warm_up_cycle_count;
uint8_t LEA_obd_P2135_flags;
uint8_t LEA_obd_P2135_engine_start_count;
uint8_t LEA_obd_P2135_warm_up_cycle_count;
uint8_t LEA_obd_P0122_flags;
uint8_t LEA_obd_P0122_engine_start_count;
uint8_t LEA_obd_P0122_warm_up_cycle_count;
uint8_t LEA_obd_P0123_flags;
uint8_t LEA_obd_P0123_engine_start_count;
uint8_t LEA_obd_P0123_warm_up_cycle_count;
uint8_t LEA_obd_P0222_flags;
uint8_t LEA_obd_P0223_flags;
uint8_t LEA_obd_P0638_flags;
uint8_t LEA_obd_P0638_engine_start_count;
uint8_t LEA_obd_P0638_warm_up_cycle_count;
uint8_t LEA_obd_P2173_flags;
uint8_t LEA_obd_P2173_engine_start_count;
uint8_t LEA_obd_P2173_warm_up_cycle_count;
uint8_t LEA_obd_P2104_flags;
uint8_t LEA_obd_P2104_engine_start_count;
uint8_t LEA_obd_P2104_warm_up_cycle_count;
uint8_t LEA_obd_P2105_flags;
uint8_t LEA_obd_P2105_engine_start_count;
uint8_t LEA_obd_P2105_warm_up_cycle_count;
uint8_t LEA_obd_P2107_flags;
uint8_t LEA_obd_P2107_engine_start_count;
uint8_t LEA_obd_P2107_warm_up_cycle_count;
uint8_t LEA_obd_P2106_flags;
uint8_t LEA_obd_P2106_engine_start_count;
uint8_t LEA_obd_P2106_warm_up_cycle_count;
uint8_t LEA_obd_P2100_flags;
uint8_t LEA_obd_P2100_engine_start_count;
uint8_t LEA_obd_P2100_warm_up_cycle_count;
uint8_t LEA_obd_P2102_flags;
uint8_t LEA_obd_P2102_engine_start_count;
uint8_t LEA_obd_P2102_warm_up_cycle_count;
uint8_t LEA_obd_P2103_flags;
uint8_t LEA_obd_P2103_engine_start_count;
uint8_t[2] CAL_obd_monitors;
uint8_t LEA_obd_P2103_warm_up_cycle_count;
uint8_t LEA_obd_P2108_flags;
uint8_t LEA_obd_P2108_engine_start_count;
uint8_t LEA_obd_P2108_warm_up_cycle_count;
uint8_t LEA_obd_P0630_flags;
uint8_t LEA_obd_P0630_engine_start_count;
uint8_t LEA_obd_P0630_warm_up_cycle_count;
char[32] LEA_base;
uint16_t LEA_ecu_engine_speed_byte_offset;
u8_factor_1/256-1/2 LEA_ltft_zone2_adj;
u8_factor_1/256-1/2 LEA_ltft_zone3_adj;
u16_factor_1/65536[4] LEA_knock_retard2;
i16_time_us[4][16] LEA_misfire_stroke_time;
uint16_t LEA_obd_iumpr_ignition_count;
uint16_t LEA_obd_iumpr_obdcond_count;
uint16_t[10] LEA_misfire_max_result_history;
u16_voltage_5/1023v LEA_sensor_tps_1_offset;
u16_voltage_5/1023v LEA_sensor_tps_2_offset;
u16_rspeed_1/4rpm LEA_obd_freeze_engine_speed;
uint8_t LEA_obd_freeze_fuel_system_status;
u8_factor_1/255 LEA_obd_freeze_load;
u8_speed_kph LEA_obd_freeze_car_speed;
u8_factor_1/255 LEA_obd_freeze_tps;
u16_flow_10mg/s LEA_obd_freeze_maf_flow;
u8_temp_1-40c LEA_obd_freeze_coolant;
u8_factor_1/128-1 LEA_obd_freeze_stft;
u8_factor_1/128-1 LEA_obd_freeze_ltft;
uint8_t LEA_obd_monitors_completeness;
uint16_t LEA_obd_freeze2_dtc;
u16_rspeed_1/4rpm LEA_obd_freeze2_engine_speed;
u16_flow_10mg/s LEA_obd_freeze2_maf_flow;
i16_factor_1/2000 LEA_obd_freeze2_stft;
i16_factor_1/2000 LEA_obd_freeze2_ltft;
u8_temp_5/8-40c LEA_obd_freeze2_coolant;
u8_temp_5/8-40c LEA_obd_freeze2_coolant_stop;
u8_temp_5/8-40c LEA_obd_freeze2_engine_air;
u8_factor_1/255 LEA_obd_freeze2_tps;
u32_time_5ms LEA_obd_freeze2_engine_runtime;
u16_voltage_5/1023v LEA_obd_freeze2_sensor_adc_pre_o2;
u16_voltage_5/1023v LEA_obd_freeze2_sensor_adc_post_o2;
u8_speed_kph LEA_obd_freeze2_car_speed;
u16_time_5ms LEA_o2_rich2lean_avg_time;
u16_time_5ms LEA_o2_lean2rich_avg_time;
u16_factor_1/100 LEA_o2_switch_time_ratio;
u8_factor_1/500[64] CAL_obd_P1302_threshold;
uint16_t LEA_obd_freeze_dtc;
uint16_t[6] LEA_obd_iumpr_pass_count;
uint16_t[6] LEA_obd_iumpr_fail_count;
u16_voltage_5/1023v CAL_sensor_tps_1_offset;
u16_voltage_5/1023v CAL_sensor_tps_2_offset;
u32_time_100ms[8] LEA_perf_time_at_TPS;
u32_time_100ms[8] LEA_perf_time_at_RPM;
u8_time_100ms[2] LEA_perf_fastest_standing_start;
u8_time_100ms[2] LEA_perf_last_standing_start;
u16_rspeed_rpm[5] LEA_perf_max_engine_speed;
uint8_t CAL_obd_P0139_debounce_threshold;
char[17] CAL_ecu_generic_VIN;
u32_time_100ms[8] LEA_perf_time_at_KMH;
u32_time_100ms[4] LEA_perf_time_at_coolant_temp;
u32_time_100ms LEA_perf_engine_run_timer;
uint16_t LEA_perf_number_of_standing_starts;
u8_temp_5/8-40c LEA_perf_max_engine_speed_5_coolant_temp;
u32_time_100ms LEA_perf_max_engine_speed_5_run_timer;
u8_temp_5/8-40c LEA_perf_max_engine_speed_4_coolant_temp;
u32_time_100ms LEA_perf_max_engine_speed_4_run_timer;
u8_temp_5/8-40c LEA_perf_max_engine_speed_3_coolant_temp;
u32_time_100ms LEA_perf_max_engine_speed_3_run_timer;
u8_temp_5/8-40c LEA_perf_max_engine_speed_2_coolant_temp;
u32_time_100ms LEA_perf_max_engine_speed_2_run_timer;
u8_temp_5/8-40c LEA_perf_max_engine_speed_1_coolant_temp;
u32_time_100ms LEA_perf_max_engine_speed_1_run_timer;
u8_speed_kph[5] LEA_perf_max_vehicle_speed;
uint8_t LEA_obd_P0420_flags;
uint8_t LEA_obd_P0420_engine_start_count;
uint8_t LEA_obd_P0420_warm_up_cycle_count;
uint8_t LEA_obd_P0011_flags;
uint8_t LEA_obd_P0011_engine_start_count;
uint8_t LEA_obd_P0011_warm_up_cycle_count;
uint8_t LEA_obd_P0012_flags;
uint8_t LEA_obd_P0012_engine_start_count;
uint8_t LEA_obd_P0012_warm_up_cycle_count;
uint8_t LEA_obd_P0016_flags;
uint8_t LEA_obd_P0016_engine_start_count;
uint8_t LEA_obd_P0016_warm_up_cycle_count;
uint8_t LEA_obd_P2647_flags;
uint8_t LEA_obd_P2647_engine_start_count;
uint8_t LEA_obd_P2647_warm_up_cycle_count;
uint8_t LEA_obd_P2646_flags;
uint8_t LEA_obd_P2646_engine_start_count;
uint8_t LEA_obd_P2646_warm_up_cycle_count;
uint8_t LEA_obd_P0076_flags;
uint8_t LEA_obd_P0076_engine_start_count;
uint8_t LEA_obd_P0076_warm_up_cycle_count;
uint8_t LEA_obd_P0077_engine_start_count;
uint8_t LEA_obd_P0077_warm_up_cycle_count;
uint8_t LEA_obd_P0646_flags;
uint8_t LEA_obd_P0646_engine_start_count;
uint8_t LEA_obd_P0646_warm_up_cycle_count;
uint8_t LEA_obd_P0647_flags;
uint8_t LEA_obd_P0647_engine_start_count;
uint8_t LEA_obd_P0647_warm_up_cycle_count;
uint8_t LEA_obd_P0444_engine_start_count;
uint8_t LEA_obd_P0444_warm_up_cycle_count;
uint8_t LEA_obd_P0445_engine_start_count;
uint8_t LEA_obd_P0445_warm_up_cycle_count;
i16_time_us[4][16] misfire_stroke_time_baseline;
uint8_t LEA_obd_P0447_flags;
uint DAT_002f8550;
undefined1 DAT_003fd3ce;
undefined2 dev_reset_lea_magic;
ushort DAT_003fd3a4;
undefined2 stft_enleanment_initial;
u8_time_5ms DAT_003f80c0;
i16_factor_1/2000 DAT_003f8d42;
u8_temp_5/8-40c CAL_stft_engine_air_min;
u8_time_5ms CAL_stft_idle_time_between_step;
undefined2 DAT_003fd3a6;
char DAT_003f8d3e;
u16_factor_1/2000 CAL_stft_idle_enrichment_step;
u16_factor_1/2000 CAL_stft_idle_enleanment_step;
undefined1 DAT_003fd3a8;
u16_factor_1/2000 CAL_stft_idle_enrichment_initial;
ushort DAT_003fd60a;
u16_factor_1/2000 CAL_stft_idle_enleanment_initial;
u16_voltage_5/1023v CAL_stft_stoich_max;
u16_voltage_5/1023v CAL_stft_stoich_min;
uint8_t obd_P0201_debounce_count;
uint8_t obd_P0202_debounce_count;
uint8_t obd_P0203_debounce_count;
uint8_t obd_P0204_debounce_count;
u8_time_s[17] CAL_stft_runtime_min;
uint8_t obd_P0135_debounce_count;
u16_time_5ms stft_time_use_adj_timer;
undefined2 stft_lean_threshold;
u8_rspeed_125/4+500rpm[8] CAL_stft_enrichment_step_X_engine_speed;
undefined2 stft_rich_threshold;
u8_load_4mg/stroke[8] CAL_stft_enrichment_step_Y_engine_load;
u8_factor_1/2000[64] CAL_stft_enrichment_step;
u16_time_5ms stft_time_use_adj;
u8_rspeed_125/4+500rpm[8] CAL_stft_enleanment_step_X_engine_speed;
u8_load_4mg/stroke[8] CAL_stft_enleanment_step_Y_engine_load;
u8_factor_1/2000[64] CAL_stft_enleanment_step;
u8_rspeed_125/4+500rpm[8] CAL_stft_enrichment_initial_X_engine_speed;
u8_load_4mg/stroke[8] CAL_stft_enrichment_initial_Y_engine_load;
u8_factor_1/2000[64] CAL_stft_enrichment_initial;
u8_rspeed_125/4+500rpm[8] CAL_stft_enleanment_initial_X_engine_speed;
u8_load_4mg/stroke[8] CAL_stft_enleanment_initial_Y_engine_load;
u8_factor_1/2000[64] CAL_stft_enleanment_initial;
uint8_t obd_P0134_debounce_count;
uint8_t obd_P0131_debounce_count;
uint8_t obd_P0132_debounce_count;
u8_rspeed_125/4+500rpm[8] CAL_stft_time_use_adj_X_engine_speed;
u8_time_25ms[8] CAL_stft_time_use_adj;
u16_time_5ms CAL_stft_o2_test_runtime_min;
u16_voltage_5/1023v CAL_stft_o2_test_min;
u16_voltage_5/1023v CAL_stft_o2_test_max;
u8_time_5ms CAL_stft_time_between_step;
undefined2 stft_enrichment_step;
undefined2 stft_enleanment_step;
undefined2 stft_enrichment_initial;
byte DAT_003f80c0;
ushort DAT_003f8d30;
short DAT_003fd3a6;
u8_rspeed_125/4+500rpm CAL_stft_lean_rpm_min;
u8_factor_1/64 CAL_stft_enrichment_step_adj;
u8_factor_1/64 CAL_stft_enleanment_step_adj;
char DAT_003f9395;
undefined1 DAT_003f8d3d;
u8_factor_1/256-1/2 CAL_ltft_zone2_limit_h;
u8_time_5s DAT_003f8d3c;
u8_factor_1/256-1/2 CAL_ltft_zone2_limit_l;
u8_factor_1/256-1/2 CAL_ltft_zone3_limit_h;
short DAT_003fd398;
u8_factor_1/256-1/2 CAL_ltft_zone3_limit_l;
short DAT_003fd39a;
u8_factor_1/256 CAL_stft_smooth_reactivity;
u8_temp_5/8-40c CAL_ltft_engine_air_min;
u8_factor_1/156-14/156 CAL_ltft_fuel_min;
uint32_t inj_time_stft_smooth_x;
i16_pressure_mbar CAL_ltft_atmo_min;
u8_time_us CAL_ltft_zone1_step;
u16_flow_10mg/s CAL_ltft_zone1_flow_max;
u16_rspeed_rpm CAL_ltft_zone1_engine_speed_max;
u16_flow_10mg/s CAL_ltft_zone2_flow_max;
u16_flow_10mg/s CAL_ltft_zone2_flow_min;
u16_load_mg/stroke CAL_ltft_zone2_load_max;
u16_load_mg/stroke CAL_ltft_zone2_load_min;
u16_flow_10mg/s CAL_ltft_zone3_flow_min;
u16_load_mg/stroke CAL_ltft_zone3_load_min;
u8_temp_5/8-40c CAL_ltft_coolant_min;
u8_time_5s CAL_ltft_time_between_step;
u16_factor_1/2000-2048/125 CAL_ltft_stft_smooth_max;
u16_factor_1/2000-2048/125 CAL_ltft_stft_smooth_min;
u8_factor_1/156-14/156 fuel_level_smooth;
u8_time_10us CAL_ltft_zone1_limit_h;
u8_time_-10us CAL_ltft_zone1_limit_l;
u8_angle_10/128+2deg knock_window_start;
u8_angle_10/128deg knock_window_width;
u8_rspeed_125/4+500rpm[16] CAL_knock_window_start_X_engine_speed;
u8_load_4mg/stroke[16] CAL_knock_window_start_Y_engine_load;
uint32_t[4] knock_window_params;
u8_angle_10/128+2deg[256] CAL_knock_window_start;
u8_rspeed_125/4+500rpm[16] CAL_knock_window_width_X_engine_speed;
u8_load_4mg/stroke[16] CAL_knock_window_width_Y_engine_load;
u8_angle_10/128deg[256] CAL_knock_window_width;
u8_time_5ms DAT_003f8d50;
uint8_t knock_flags;
undefined2 knock_ign_diff;
undefined2 knock_cyl_worst;
u8_angle_1/4deg CAL_knock_retard1_limit;
u8_rspeed_125/4+500rpm CAL_knock_retard1_engine_speed_max;
u8_rspeed_125/4+500rpm CAL_knock_retard1_engine_speed_min;
u8_temp_5/8-40c CAL_knock_retard1_coolant_min;
u8_rspeed_125/4rpm CAL_knock_speed_margin;
u8_load_4mg/stroke CAL_knock_load_margin;
u8_time_5ms CAL_knock_retard1_dt_tps_target_2_time;
u8_angle_1/4deg CAL_knock_retard1_vvt_diff_max;
u16_factor_1/1023 CAL_knock_retard1_dt_tps_target_2_max;
u8_rspeed_125/4+500rpm[16] CAL_knock_sensitivity_cylinder1_X_engine_speed;
u8_load_4mg/stroke[16] CAL_knock_sensitivity_cylinder1_Y_engine_load;
uint8_t[256] CAL_knock_sensitivity_cylinder1;
u8_rspeed_125/4+500rpm[16] CAL_knock_sensitivity_cylinder2_X_engine_speed;
u8_load_4mg/stroke[16] CAL_knock_sensitivity_cylinder2_Y_engine_load;
uint8_t[256] CAL_knock_sensitivity_cylinder2;
u8_rspeed_125/4+500rpm[16] CAL_knock_sensitivity_cylinder3_X_engine_speed;
uint8_t[4] knock_sensitivity_threshold;
u8_load_4mg/stroke[16] CAL_knock_sensitivity_cylinder3_Y_engine_load;
uint8_t[256] CAL_knock_sensitivity_cylinder3;
uint8_t knock_peak_threshold;
uint8_t[4] knock_peak_over_threshold;
u8_rspeed_125/4+500rpm[16] CAL_knock_sensitivity_cylinder4_X_engine_speed;
u8_load_4mg/stroke[16] CAL_knock_sensitivity_cylinder4_Y_engine_load;
uint8_t[256] CAL_knock_sensitivity_cylinder4;
u8_rspeed_125/4+500rpm[8] CAL_knock_peak_threshold_X_engine_speed;
u8_load_4mg/stroke[8] CAL_knock_peak_threshold_Y_engine_load;
uint8_t[64] CAL_knock_peak_threshold;
uint8_t[8] CAL_knock_retard1_inc_X_peak_over_threshold;
u8_angle_1/4deg[8] CAL_knock_retard1_inc;
u8_rspeed_125/4+500rpm[8] CAL_knock_retard_load_min_X_engine_speed;
u8_load_4mg/stroke[8] CAL_knock_retard_load_min;
u8_rspeed_125/4+500rpm[8] CAL_knock_retard2_corr_load_min_X_engine_speed;
u8_load_4mg/stroke[8] CAL_knock_retard2_corr_load_min;
uint8_t[4] knock_first_read;
ushort DAT_003f8d4a;
short DAT_003f8d4c;
undefined2 DAT_003f811c;
undefined1 DAT_003f8124;
u8_x256 CAL_knock_signal_smooth_limit_l;
uint16_t[4] knock_signal_smooth_low;
uint16_t[4] knock_peak;
uint16_t[4] knock_signal;
uint32_t[4] knock_signal_smooth;
undefined1 knock_detected;
uint8_t CAL_knock_signal_fadeout_step;
u8_time_5ms[4] knock_retard1_timer;
u8_factor_1/256 CAL_knock_signal_reactivity;
uint8_t CAL_knock_retard2_corr_inc_coef;
uint8_t CAL_knock_retard2_corr_dec_step;
byte DAT_003f810a;
byte DAT_003f810b;
undefined DAT_000786c4;
undefined DAT_003f80e5;
undefined DAT_003f80e9;
undefined DAT_003f812c;
byte DAT_003f8135;
char DAT_003f8d50;
char DAT_003f93a6;
short DAT_003f8d5e;
char DAT_003fd3d4;
byte DAT_003fbf24;
byte DAT_003fbf25;
undefined1 DAT_003f8d58;
short DAT_002f830e;
byte DAT_003f8d60;
byte DAT_003f8d61;
uint16_t DAT_003fd3d0;
u8_factor_1/128-1 obd_stft;
u8_factor_1/128-1 obd_ltft;
byte DAT_003f8d62;
uint16_t DAT_003fd3d2;
uint DAT_003fd3d8;
u16_speed_1/100kph wheel_speed_r_max;
u8_temp_1-40c obd_temp;
bool engine_has_started;
uint16_t[128] obd_trouble_list;
uint16_t[128] obd_pending_list;
ushort DAT_002f8310;
ushort DAT_003fbf2a;
char DAT_003f8d58;
char DAT_002f8316;
undefined1 DAT_003fd3b4;
short DAT_003fbf2c;
u8_obd_config DAT_003f8d68;
uint DAT_003f8d64;
char DAT_003f8d5a;
ushort DAT_002f830e;
u8_factor_1/255 DAT_002f8312;
u16_flow_10mg/s DAT_002f8314;
u16_rspeed_1/4rpm DAT_002f8310;
u16_voltage_5/1023v sensor_adc_tps_1;
undefined1 DAT_003f8d59;
byte DAT_002f82c3;
byte DAT_002f8317;
byte DAT_003fbf27;
byte DAT_003f8d5a;
byte DAT_003fbf26;
char DAT_002f8322;
undefined1 DAT_003f8d5d;
char DAT_003f8d59;
char DAT_003fd3b4;
undefined4 DAT_003fd3d8;
char DAT_003f8d5d;
uint8_t CAL_obd_warm_up_cycles_clear_freeze_frame;
char DAT_003fd3ce;
byte DAT_003f8d71;
ushort DAT_003fd3ec;
byte DAT_003fbf54;
byte DAT_003fbf55;
ushort DAT_003fbf52;
byte DAT_003fbf5f;
byte DAT_003fbf5e;
uint16_t cat_diag_pre_o2_max_sw;
ushort DAT_003fbf56;
uint16_t cat_diag_pre_o2_sw;
ushort DAT_003fbf58;
short DAT_003f8d78;
short DAT_003f8d7a;
ushort DAT_003fd3ea;
short DAT_003fbf78;
short DAT_003fbf76;
int DAT_003fd3f0;
short DAT_003fbf7c;
short DAT_003fbf7a;
byte DAT_002f82ff;
ushort DAT_003f8d72;
ushort DAT_003f8d74;
ushort DAT_002f8352;
ushort DAT_003fbf7e;
undefined1 DAT_002f82d7;
undefined1 DAT_002f82e7;
undefined DAT_003fce6a;
undefined DAT_003fce72;
uint8_t obd_P0420_debounce_count;
u8_obd_config CAL_obd_P0420;
uint8_t CAL_obd_P0420_debounce_threshold;
byte DAT_003fbf5a;
char DAT_003f8d76;
char DAT_003fbf5b;
byte DAT_003f93fe;
short DAT_003f9400;
u8_time_100ms CAL_obd_P0016_debounce_threshold;
char DAT_003fe0cc;
byte DAT_003fbfa8;
ushort DAT_003fbfaa;
short DAT_003fbf80;
byte DAT_003f8d82;
byte DAT_003fbfa9;
byte DAT_003f8d83;
u8_time_100ms obd_P0016_debounce_count;
uint8_t obd_P0011_debounce_count;
uint8_t obd_P0012_debounce_count;
uint8_t obd_P0076_debounce_count;
u8_obd_config CAL_obd_P0011;
uint8_t obd_P0077_debounce_count;
uint8_t obd_P0116_debounce_count;
uint8_t obd_P0117_debounce_count;
u8_obd_config CAL_obd_P0012;
uint8_t obd_P0118_debounce_count;
u8_obd_config CAL_obd_P0016;
u8_time_100ms obd_P0340_debounce_count;
uint8_t CAL_obd_P0011_debounce_threshold;
uint8_t CAL_obd_P0012_debounce_threshold;
char DAT_003fbf3e;
char DAT_003f8d80;
u8_obd_config CAL_obd_P2646;
char DAT_003f8d81;
u8_time_100ms CAL_obd_P2646_debounce_threshold;
u8_time_100ms CAL_obd_P2647_debounce_threshold;
u8_time_100ms obd_P2646_debounce_count;
u8_time_100ms obd_P2647_debounce_count;
u8_obd_config CAL_obd_P2647;
ushort DAT_003fd530;
ushort DAT_003fd520;
u8_obd_config CAL_obd_P0448;
ushort DAT_003fd532;
ushort DAT_003fd52c;
ushort DAT_003fd534;
undefined UNK_00002ee0;
u8_obd_config CAL_obd_P0201;
uint8_t obd_P0205_debounce_count;
u8_obd_config CAL_obd_P0202;
u8_obd_config CAL_obd_P0203;
u8_obd_config CAL_obd_P0204;
uint8_t obd_P0647_debounce_count;
uint8_t obd_P0646_debounce_count;
u8_obd_config CAL_obd_P0205;
uint8_t obd_P0444_debounce_count;
uint8_t obd_P0445_debounce_count;
uint8_t obd_P0447_debounce_count;
uint8_t obd_P0448_debounce_count;
u8_obd_config CAL_obd_P0351;
u8_obd_config CAL_obd_P0352;
u8_obd_config CAL_obd_P0353;
u8_obd_config CAL_obd_P0354;
u8_obd_config CAL_obd_P0627;
u8_obd_config CAL_obd_P0480;
u8_obd_config CAL_obd_P0481;
u8_obd_config CAL_obd_P0135;
u8_obd_config CAL_obd_P0141;
u8_obd_config CAL_obd_P2602;
u8_obd_config CAL_obd_P2603;
u8_obd_config CAL_obd_P2648;
u8_obd_config CAL_obd_P2649;
uint8_t hc08_obd_flags;
uint8_t obd_P0627_debounce_count;
uint8_t obd_P0480_debounce_count;
uint8_t obd_P0481_debounce_count;
uint8_t obd_P2602_debounce_count;
uint8_t obd_P2603_debounce_count;
uint8_t obd_P2648_debounce_count;
uint8_t obd_P2649_debounce_count;
uint8_t obd_P0141_debounce_count;
uint16_t obd_P0076_fault_sample_count;
uint16_t obd_P0077_fault_sample_count;
uint16_t obd_P0647_fault_sample_count;
uint16_t obd_P0646_fault_sample_count;
uint16_t obd_P0444_fault_sample_count;
uint16_t obd_P0445_fault_sample_count;
uint16_t obd_P0201_fault_sample_count;
uint16_t obd_P0202_fault_sample_count;
uint16_t obd_P0203_fault_sample_count;
uint16_t obd_P0204_fault_sample_count;
u16_current_mA CAL_obd_P0135_P0141_threshold;
uint16_t obd_P0205_fault_sample_count;
uint16_t obd_P0351_fault_sample_count;
uint16_t obd_P0352_fault_sample_count;
uint16_t obd_P0353_fault_sample_count;
uint16_t obd_P0354_fault_sample_count;
uint16_t obd_P0627_fault_sample_count;
uint16_t obd_P0480_fault_sample_count;
uint16_t obd_P0481_fault_sample_count;
uint16_t obd_P0135_fault_sample_count;
uint16_t obd_P0141_fault_sample_count;
uint16_t obd_P0447_fault_sample_count;
uint16_t obd_P0448_fault_sample_count;
uint16_t obd_P2602_fault_sample_count;
uint16_t obd_P2603_fault_sample_count;
uint16_t obd_P2648_fault_sample_count;
uint16_t obd_P2649_fault_sample_count;
uint8_t CAL_obd_P0076_debounce_threshold;
u16_time_100ms obd_fault_sample_threshold;
uint8_t CAL_obd_P0077_debounce_threshold;
uint8_t CAL_obd_P0646_debounce_threshold;
uint8_t CAL_obd_P0647_debounce_threshold;
uint8_t CAL_obd_P0444_debounce_threshold;
uint8_t CAL_obd_P0445_debounce_threshold;
uint8_t CAL_obd_P0447_debounce_threshold;
uint8_t CAL_obd_P0448_debounce_threshold;
uint8_t CAL_obd_P0201_debounce_threshold;
uint8_t CAL_obd_P0202_debounce_threshold;
u8_obd_config CAL_obd_P0076;
uint8_t CAL_obd_P0203_debounce_threshold;
uint8_t CAL_obd_P0204_debounce_threshold;
uint8_t CAL_obd_P0205_debounce_threshold;
u8_obd_config CAL_obd_P0077;
uint8_t CAL_obd_P0627_debounce_threshold;
uint8_t CAL_obd_P0480_debounce_threshold;
uint8_t CAL_obd_P0481_debounce_threshold;
u8_obd_config CAL_obd_P0646;
uint8_t CAL_obd_P2602_debounce_threshold;
uint8_t CAL_obd_P2603_debounce_threshold;
u8_obd_config CAL_obd_P0647;
u8_obd_config CAL_obd_P0444;
uint8_t CAL_obd_P0135_debounce_threshold;
uint8_t CAL_obd_P2648_debounce_threshold;
uint8_t CAL_obd_P2649_debounce_threshold;
u8_obd_config CAL_obd_P0445;
uint8_t CAL_obd_P0141_debounce_threshold;
u8_obd_config CAL_obd_P0447;
uint8_t obd_resp_len;
char DAT_003fd780;
uint8_t obd_resp_i;
char DAT_003fd884;
uint16_t obd_kline_session_timer;
uint8_t[128] obd_req;
ushort REG_SC1SR;
ushort REG_SC1DR;
uint8_t[11] obd_resp;
byte DAT_003f930b;
byte DAT_003f8002;
byte DAT_003f8001;
byte DAT_003f8000;
char DAT_003f81c0;
ushort DAT_003fd542;
char DAT_003fd538;
byte DAT_003fd540;
ushort DAT_003fe0bc;
ushort DAT_002f8354;
byte DAT_003fd544;
ushort DAT_003f947a;
byte DAT_003fd547;
byte DAT_003fd545;
byte DAT_003fd546;
short DAT_003fc060;
char DAT_003fc05c;
char DAT_003f8e6c;
char DAT_003f8e6e;
char DAT_003f8e6d;
short DAT_003fc058;
short DAT_003fc05a;
char DAT_003fc05d;
char DAT_003f8e6a;
byte DAT_003f8e6b;
undefined1 DAT_003fc05f;
undefined1 DAT_003fc05e;
char DAT_003f8e6f;
i16_pressure_mbar CAL_evap_leak_vacuum_min;
uint8_t obd_P0455_debounce_count;
i16_pressure_1/10mbar evap_leak_pressure_min;
u8_obd_config CAL_obd_P0455;
u8_time_100ms CAL_obd_P0441_debounce_threshold;
u8_time_100ms CAL_obd_P0446_debounce_threshold;
u8_obd_config CAL_obd_P0441;
u8_time_100ms obd_P0441_debounce_count;
u8_time_100ms obd_P0446_debounce_count;
u8_obd_config CAL_obd_P0446;
i16_pressure_1/10mbar evap_pressure_smooth;
byte DAT_003f8e72;
byte DAT_003fbf9f;
u8_obd_config CAL_obd_P0340;
byte DAT_003fbffa;
short DAT_003fc02a;
short DAT_003fbf98;
short DAT_003f8e70;
byte DAT_003fbf9c;
byte DAT_003fe189;
byte DAT_003fbf9d;
byte DAT_003fe188;
u8_time_100ms obd_P0335_debounce_count;
u8_time_100ms obd_P0500_debounce_count;
u8_time_100ms CAL_obd_P0335_debounce_threshold;
u8_time_100ms CAL_obd_P0340_debounce_threshold;
u8_time_100ms CAL_obd_P0500_debounce_threshold;
u8_obd_config CAL_obd_P0500;
u8_obd_config CAL_obd_P0335;
undefined2 DAT_003fbf98;
undefined2 DAT_003f8e70;
short DAT_003fbf82;
byte DAT_003fbf89;
short DAT_003fd556;
ushort DAT_003fd39a;
ushort DAT_003fc022;
byte DAT_003fbfb6;
u8_obd_config CAL_obd_P0171;
ushort DAT_003fd398;
ushort DAT_003fc020;
short DAT_003fbf84;
byte DAT_003fbfb7;
u8_obd_config CAL_obd_P0172;
uint8_t obd_P0171_debounce_count;
uint8_t obd_P0172_debounce_count;
uint8_t CAL_obd_P0171_debounce_threshold;
uint8_t CAL_obd_P0172_debounce_threshold;
ushort DAT_003fbfa2;
ushort DAT_003fbfa0;
byte DAT_003fbfa5;
byte DAT_003fbfc8;
byte DAT_003fbfa4;
byte DAT_003fbfc7;
u8_obd_config CAL_obd_P0506;
u8_obd_config CAL_obd_P0507;
u8_time_100ms CAL_obd_P0506_P0507_fault_sample_threshold;
uint8_t obd_P0506_debounce_count;
uint8_t obd_P0507_debounce_count;
uint8_t CAL_obd_P0506_debounce_threshold;
uint8_t CAL_obd_P0507_debounce_threshold;
uint8_t obd_P0506_fault_sample_count;
uint8_t obd_P0507_fault_sample_count;
uint DAT_003fd59c;
u16_time_100ms DAT_003f8e82;
u8_time_100ms DAT_003fd594;
u8_time_100ms DAT_003fd595;
ushort DAT_003f8e86;
byte DAT_003f8e88;
short DAT_003f81c8;
byte DAT_003f8e84;
char DAT_003fbfbe;
u8_factor_1/156-14/156[16] CAL_evap_leak_P0456_threshold_X_fuel_level;
u8_pressure_1/10mbar[16] CAL_evap_leak_P0456_threshold;
u8_factor_1/156-14/156[16] CAL_evap_leak_P0442_threshold_X_fuel_level;
u8_pressure_1/10mbar[16] CAL_evap_leak_P0442_threshold;
u8_pressure_1/10mbar[8] CAL_evap_leak_pressure_margin_X_pressure_ripple;
u8_factor_1/156-14/156[16] CAL_evap_leak_pressure_margin_Y_fuel_level;
u8_pressure_1/10mbar[128] CAL_evap_leak_pressure_margin;
undefined1 obd_mode_0x08_state;
u8_obd_config CAL_obd_P0442;
u8_obd_config CAL_obd_P0456;
u8_temp_5/8-40c CAL_evap_leak_coolant_min;
u8_temp_5/8-40c CAL_evap_leak_engine_air_max;
u8_temp_5/8-40c CAL_evap_leak_engine_air_stop_max;
u8_time_100ms CAL_evap_leak_purge_time;
i16_pressure_mbar CAL_evap_leak_gross_pressure;
u8_factor_1/156-14/156 CAL_evap_leak_fuel_level_min;
u8_factor_1/156-14/156 CAL_evap_leak_fuel_level_max;
u8_time_100ms CAL_evap_leak_initial_delay;
u8_time_100ms CAL_evap_leak_settle_time;
u8_time_100ms CAL_evap_leak_baseline_time;
u8_time_100ms CAL_evap_leak_P0442_time;
u16_time_100ms CAL_evap_leak_P0456_time;
uint16_t CAL_evap_leak_purge_min;
uint16_t CAL_evap_leak_purge_retry_min;
i16_pressure_mbar CAL_evap_leak_atmo_pressure_min;
uint8_t CAL_evap_leak_force;
uint8_t obd_P0456_debounce_count;
u16_time_100ms CAL_evap_leak_cooldown;
uint8_t obd_P0442_debounce_count;
i16_pressure_1/10mbar evap_leak_pressure_rise;
i16_pressure_1/10mbar evap_leak_result;
u8_pressure_1/10mbar evap_leak_P0456_threshold;
u8_pressure_1/10mbar evap_leak_P0442_threshold;
i16_pressure_1/10mbar evap_leak_pressure_ripple;
i16_pressure_1/10mbar evap_leak_pressure_max;
i16_pressure_1/10mbar evap_reference;
u8_time_100ms evap_leak_baseline_timer;
u8_time_100ms evap_leak_P0442_timer;
u16_time_100ms evap_leak_P0456_timer;
i16_pressure_1/10mbar evap_leak_vacuum_target;
uint8_t CAL_obd_P0442_debounce_threshold;
uint8_t CAL_obd_P0456_debounce_threshold;
uint8_t CAL_obd_P0455_debounce_threshold;
u8_obd_config CAL_obd_P0606;
u8_obd_config CAL_obd_P0601;
u8_obd_config CAL_obd_P0630;
byte DAT_003f8e9e;
int32_t misfire_dt_unused;
uint8_t[1089] CAL_misfire_unused;
u8_temp_5/8-40c CAL_misfire_eval_coolant_low;
u8_time_us[9] CAL_misfire_cat_threshold_base;
u8_temp_5/8-40c CAL_misfire_eval_coolant_high;
u8_load_4mg/stroke[9] CAL_misfire_load_min;
u8_rspeed_125/4+500rpm CAL_misfire_eval_engine_speed_low;
u16_rspeed_rpm[16] CAL_misfire_threshold_X_engine_speed;
u8_rspeed_125/4+500rpm CAL_misfire_eval_engine_speed_high;
u16_load_mg/stroke[16] CAL_misfire_threshold_Y_engine_load;
u8_factor_1/156-14/156 CAL_misfire_eval_fuel_level_min;
u16_time_1-32768us[256] CAL_misfire_threshold;
u16_time_5ms CAL_misfire_eval_speed_transient_delay;
u8_rspeed_125/4+500rpm[8] CAL_obd_P1302_threshold_X_engine_speed;
u16_time_5ms CAL_misfire_eval_inhibit_delay;
u8_load_4mg/stroke[8] CAL_obd_P1302_threshold_Y_engine_load;
u16_time_5ms CAL_misfire_cylinder_cut_delay;
u16_rspeed_rpm CAL_misfire_eval_dt_engine_speed_max;
int16_t CAL_misfire_eval_dt_unused_max;
bool CAL_misfire_use_cylinder_cut;
uint16_t[4] misfire_cat_count_prev;
u8_time_us[9] CAL_misfire_cat_threshold_adj;
uint16_t[4] misfire_count_prev;
u8_factor_1/1000 CAL_obd_P1301_threshold;
uint8_t misfire_unused;
u16_time_us misfire_threshold;
uint16_t misfire_cat_max_result;
u8_obd_config CAL_obd_P1302;
u8_obd_config CAL_obd_P1301;
u8_obd_config CAL_obd_P0301;
uint8_t obd_P1301_debounce_count;
uint8_t obd_P1302_debounce_count;
u8_obd_config CAL_obd_P0302;
uint8_t obd_P1302_threshold;
u8_obd_config CAL_obd_P0303;
u8_time_us misfire_cat_threshold_adj;
uint16_t misfire_cylinder_cut_timer;
uint16_t misfire_eval_inhibit_timer;
u8_load_4mg/stroke misfire_load_min;
u8_obd_config CAL_obd_P0304;
uint16_t misfire_eval_speed_transient_timer;
uint8_t obd_P1301_flags_prev;
uint8_t obd_P1302_flags_prev;
u8_obd_config CAL_obd_P0300;
uint8_t obd_P1301_threshold;
u8_time_us misfire_cat_threshold;
uint16_t misfire_max_result;
uint16_t misfire_total_count;
uint16_t misfire_cat_total_count;
uint16_t misfire_dead_cylinder_penalty;
uint8_t CAL_obd_P1301_debounce_threshold;
uint8_t CAL_obd_P1302_debounce_threshold;
uint16_t[4] misfire_cat_timer;
undefined1 DAT_003fc490;
undefined1 DAT_003f8e90;
undefined1 DAT_003fc488;
undefined1 DAT_003f8e91;
undefined1 DAT_003fc489;
undefined1 DAT_003f8e92;
undefined1 DAT_003fc48a;
undefined1 DAT_003f8e93;
undefined1 DAT_003fc48b;
undefined1 DAT_003f8e94;
byte DAT_003f81d0;
uint DAT_003f81d4;
short DAT_003f8ea0;
ushort DAT_003f8eb2;
ushort DAT_003f8eb4;
ushort DAT_003fc024;
ushort DAT_003fc030;
ushort DAT_003fc02e;
ushort DAT_003fc02c;
u8_obd_config CAL_obd_P0134;
ushort DAT_003fc026;
u8_obd_config CAL_obd_P0140;
uint16_t o2_flags;
u8_time_100ms obd_P0140_debounce_count;
uint8_t CAL_obd_P0134_debounce_threshold;
u8_time_100ms CAL_obd_P0140_debounce_threshold;
short DAT_003fd61e;
byte DAT_003fbf86;
byte DAT_003fbf87;
ushort DAT_003fbfd2;
ushort DAT_003fbfd4;
byte DAT_003fbfd6;
byte DAT_003fbfd7;
ushort DAT_003fc028;
u16_time_5ms CAL_obd_P0133_threshold1_rich2lean;
byte DAT_003fbfc9;
char DAT_003f8eb6;
u16_time_5ms CAL_obd_P0133_threshold1_lean2rich;
int DAT_003f8eb8;
byte DAT_003f949a;
char DAT_003fbf8e;
ushort DAT_003f8ebc;
u16_time_5ms DAT_003fbfea;
byte DAT_002f82c2;
undefined2 DAT_003fc054;
undefined2 DAT_003fd61c;
undefined2 DAT_003fc036;
undefined2 DAT_003fd61a;
ushort DAT_003fc032;
ushort DAT_003fc034;
uint8_t obd_P0133_debounce_count;
uint8_t obd_P0139_debounce_count;
u32_time_5ms o2_lean2rich_total_time;
u32_time_5ms o2_rich2lean_total_time;
undefined1 o2_rich2lean_switch_count;
uint8_t o2_lean2rich_switch_count;
u16_time_5ms cat_diag_pre_o2_timer;
u8_obd_config CAL_obd_P0133;
u8_obd_config CAL_obd_P0139;
u8_time_5ms CAL_obd_P0133_threshold2_lean2rich;
u8_time_5ms CAL_obd_P0133_threshold3_rich2lean;
u8_factor_1/100 CAL_obd_P0133_threshold2_ratio;
u8_factor_1/100 CAL_obd_P0133_threshold3_ratio;
uint8_t CAL_obd_P0133_debounce_threshold;
ushort DAT_002f834e;
ushort DAT_002f8350;
byte DAT_003fbf88;
short DAT_003fbfea;
short DAT_003f8ebc;
byte DAT_003fdce8;
char DAT_003f949b;
undefined4 DAT_003f81d8;
int DAT_003f81fc;
short DAT_003fd61c;
short DAT_003fc054;
short DAT_003fd61a;
short DAT_003fc036;
ushort DAT_003fd60c;
ushort DAT_003fbfc2;
ushort DAT_003fd610;
byte DAT_003fd614;
byte DAT_003fbfbf;
char DAT_003fd621;
ushort DAT_003fd60e;
ushort DAT_003fbfc4;
ushort DAT_003fd612;
byte DAT_003fd615;
undefined1 post_o2_state;
char DAT_003fdb6c;
char DAT_003fdb7c;
char DAT_003fdb7d;
char DAT_003fdb7e;
byte DAT_003fbfcf;
byte DAT_003fbf3f;
ushort DAT_003fbf42;
byte DAT_003fbf40;
ushort DAT_003fbf44;
byte DAT_003fc039;
byte DAT_003fc03a;
byte DAT_003fc03b;
char DAT_003fdb81;
ushort DAT_003fc03c;
short DAT_003fd658;
short DAT_003f8f1e;
short DAT_003fc01c;
short DAT_003fc01e;
ushort DAT_003fc040;
byte DAT_003fc042;
byte DAT_003fc043;
byte DAT_003fc03e;
byte DAT_003fc03f;
ushort DAT_003fc086;
ushort DAT_003fc084;
uint8_t obd_P0101_debounce_count;
uint8_t obd_P0102_debounce_count;
uint8_t obd_P0103_debounce_count;
uint8_t obd_P0106_debounce_count;
uint8_t obd_P0107_debounce_count;
uint8_t obd_P0108_debounce_count;
uint8_t obd_P0111_debounce_count;
uint8_t obd_P0112_debounce_count;
uint8_t obd_P0113_debounce_count;
uint8_t obd_P0137_debounce_count;
uint8_t obd_P0327_debounce_count;
uint8_t obd_P0328_debounce_count;
uint8_t obd_P0138_debounce_count;
uint8_t obd_P0237_debounce_count;
uint8_t obd_P0238_debounce_count;
undefined1 flags_to_hc08;
u8_obd_config CAL_obd_P0101;
u8_obd_config CAL_obd_P0102;
u8_obd_config CAL_obd_P0103;
u8_obd_config CAL_obd_P0106;
u8_obd_config CAL_obd_P0107;
u8_obd_config CAL_obd_P0108;
u8_obd_config CAL_obd_P0131;
u8_obd_config CAL_obd_P0132;
u8_obd_config CAL_obd_P0137;
u8_obd_config CAL_obd_P0138;
u8_obd_config CAL_obd_P0111;
u8_obd_config CAL_obd_P0112;
u8_obd_config CAL_obd_P0113;
u8_obd_config CAL_obd_P0116;
u8_obd_config CAL_obd_P0117;
u8_obd_config CAL_obd_P0118;
u8_obd_config CAL_obd_P0237;
u8_obd_config CAL_obd_P0238;
u8_obd_config CAL_obd_P0452;
u8_obd_config CAL_obd_P0453;
u8_obd_config CAL_obd_P0327;
u8_obd_config CAL_obd_P0328;
u8_obd_config CAL_obd_P0462;
u8_obd_config CAL_obd_P0463;
u8_obd_config CAL_obd_P0562;
u8_obd_config CAL_obd_P0563;
u8_time_100ms CAL_obd_fault_sample_threshold;
u16_voltage_5/1023v CAL_obd_P0103_threshold;
u16_voltage_5/1023v CAL_obd_P0102_threshold;
u16_voltage_5/1023v CAL_obd_P0131_threshold;
u16_voltage_5/1023v CAL_obd_P0132_threshold;
u16_voltage_5/1023v CAL_obd_P0137_threshold;
u16_voltage_5/1023v CAL_obd_P0138_threshold;
u16_voltage_5/1023v CAL_obd_P0113_threshold;
u16_voltage_5/1023v CAL_obd_P0112_threshold;
u16_voltage_5/1023v CAL_obd_P0108_threshold;
u16_voltage_5/1023v CAL_obd_P0107_threshold;
u16_voltage_5/1023v CAL_obd_P0118_threshold;
u16_voltage_5/1023v CAL_obd_P0117_threshold;
u16_voltage_18/1023v CAL_obd_P0563_threshold;
u16_voltage_18/1023v CAL_obd_P0562_threshold;
u8_time_100ms CAL_obd_P0562_fault_sample_threshold;
u8_time_100ms CAL_obd_P0563_fault_sample_threshold;
u8_temp_5/8-40c CAL_obd_P0116_threshold;
u16_voltage_5/1023v CAL_obd_P0453_threshold;
u16_voltage_5/1023v CAL_obd_P0452_threshold;
u16_time_s CAL_obd_P0116_engine_runtime_min;
u16_voltage_5/1023v CAL_obd_P0463_threshold;
u16_voltage_5/1023v CAL_obd_P0462_threshold;
uint16_t obd_P0101_fault_sample_count;
uint16_t obd_P0102_fault_sample_count;
uint16_t obd_P0103_fault_sample_count;
uint16_t obd_P0106_fault_sample_count;
uint16_t obd_P0107_fault_sample_count;
uint16_t obd_P0108_fault_sample_count;
uint16_t obd_P0131_fault_sample_count;
uint16_t obd_P0132_fault_sample_count;
u16_voltage_5/1023v CAL_obd_P0238_threshold;
u16_voltage_5/1023v CAL_obd_P0237_threshold;
uint8_t CAL_obd_P0106_debounce_threshold;
uint8_t CAL_obd_P0107_debounce_threshold;
uint8_t CAL_obd_P0108_debounce_threshold;
uint8_t CAL_obd_P0111_debounce_threshold;
uint8_t CAL_obd_P0112_debounce_threshold;
uint8_t CAL_obd_P0113_debounce_threshold;
uint8_t CAL_obd_P0116_debounce_threshold;
uint8_t CAL_obd_P0117_debounce_threshold;
uint8_t CAL_obd_P0118_debounce_threshold;
uint8_t CAL_obd_P0131_debounce_threshold;
uint8_t CAL_obd_P0132_debounce_threshold;
uint8_t CAL_obd_P0137_debounce_threshold;
uint8_t CAL_obd_P0138_debounce_threshold;
uint8_t CAL_obd_P0102_debounce_threshold;
uint8_t CAL_obd_P0103_debounce_threshold;
uint8_t CAL_obd_P0101_debounce_threshold;
uint8_t CAL_obd_P0452_debounce_threshold;
uint8_t CAL_obd_P0453_debounce_threshold;
uint16_t obd_P0111_fault_sample_count;
uint16_t obd_P0112_fault_sample_count;
uint8_t CAL_obd_P0327_debounce_threshold;
uint16_t obd_P0113_fault_sample_count;
uint8_t CAL_obd_P0328_debounce_threshold;
uint16_t obd_P0116_fault_sample_count;
uint8_t CAL_obd_P0563_debounce_threshold;
uint16_t obd_P0117_fault_sample_count;
uint8_t CAL_obd_P0562_debounce_threshold;
uint16_t obd_P0118_fault_sample_count;
uint16_t obd_P0137_fault_sample_count;
uint16_t obd_P0327_fault_sample_count;
uint16_t obd_P0328_fault_sample_count;
uint16_t obd_P0138_fault_sample_count;
uint16_t obd_P0237_fault_sample_count;
uint16_t obd_P0238_fault_sample_count;
uint8_t obd_P0452_debounce_count;
uint16_t obd_P0452_fault_sample_count;
uint8_t obd_P0453_debounce_count;
uint16_t obd_P0453_fault_sample_count;
uint8_t obd_P0462_debounce_count;
uint8_t CAL_obd_P0237_debounce_threshold;
uint16_t obd_P0462_fault_sample_count;
uint8_t CAL_obd_P0238_debounce_threshold;
uint8_t obd_P0463_debounce_count;
uint16_t obd_P0463_fault_sample_count;
uint8_t obd_P0563_debounce_count;
uint16_t obd_P0563_fault_sample_count;
uint8_t obd_P0562_debounce_count;
uint16_t obd_P0562_fault_sample_count;
uint8_t CAL_obd_P0462_debounce_threshold;
uint8_t CAL_obd_P0463_debounce_threshold;
uint8_t DAT_003fd66c;
byte DAT_003fc083;
uint DAT_003fd668;
byte DAT_003fd65c;
u8_time_100ms obd_P0128_debounce_count;
u8_temp_5/8-40c CAL_obd_P0128_threshold;
u8_load_4mg/stroke[8] CAL_obd_P0128_air_mass_factor_X_engine_load;
u8_obd_config CAL_obd_P0128;
u8_factor_1/255[8] CAL_obd_P0128_air_mass_factor;
u8_time_100ms CAL_obd_P0128_debounce_threshold;
byte DAT_003f8f3c;
short DAT_003f8f3e;
byte DAT_003fd676;
char DAT_003fd677;
byte DAT_003f8f2a;
byte DAT_003f8f2e;
byte DAT_003fc09c;
byte DAT_003fc0a1;
byte DAT_003fd678;
short DAT_003fc0a2;
byte DAT_003fd679;
short DAT_003f8f2c;
byte DAT_003fc09e;
char DAT_003fc09d;
char DAT_003f8201;
byte DAT_003fc0a4;
short DAT_003fc0a6;
short DAT_003f8f30;
byte DAT_003fc0aa;
byte DAT_003fc0ab;
short DAT_003f8f32;
byte DAT_003fc0a5;
short DAT_003fc0a8;
byte DAT_003f8f34;
byte DAT_003f8f36;
byte DAT_003f8f35;
short DAT_003f8f3a;
short DAT_003f8f38;
char DAT_003f8200;
byte DAT_003fc0ac;
byte DAT_003fc0ad;
short DAT_003fc0ae;
byte DAT_003fc09f;
byte DAT_003fc0a0;
u8_obd_config CAL_obd_P0461;
u8_obd_config CAL_obd_P0451;
u8_time_100ms obd_P0461_debounce_count;
u8_time_100ms obd_P0451_debounce_count;
u8_time_100ms CAL_obd_P0451_debounce_threshold;
u8_time_100ms CAL_obd_P0461_debounce_threshold;
uint8_t DAT_003f8208;
uint8_t DAT_003f8f40;
uint8_t DAT_003f8f41;
uint8_t DAT_003f8f42;
undefined2 DAT_003fc02e;
undefined2 DAT_003fc02c;
uint8_t DAT_003fbfbd;
uint8_t DAT_003f8f4a;
uint8_t obd_mode_0x01_pids_supported_51_58;
uint8_t obd_mode_0x01_pids_supported_59_60;
uint8_t DAT_003fbfbe;
uint8_t DAT_003fd2ac;
uint8_t obd_mode_0x01_pids_supported_01_08;
uint8_t obd_mode_0x01_pids_supported_09_10;
u16_voltage_5/1023v tps_1_range_corrected_low;
uint8_t obd_mode_0x01_pids_supported_11_18;
uint8_t obd_mode_0x01_pids_supported_19_20;
uint8_t obd_mode_0x01_pids_supported_21_28;
uint8_t obd_mode_0x01_pids_supported_29_30;
uint8_t obd_mode_0x01_pids_supported_31_38;
uint8_t obd_mode_0x01_pids_supported_39_40;
uint8_t obd_mode_0x01_pids_supported_41_48;
uint8_t obd_mode_0x01_pids_supported_49_50;
u16_voltage_5/1023v sensor_adc_pps_1;
u16_voltage_5/1023v sensor_adc_pps_2;
uint8_t obd_mil_dtc_count;
uint8_t obd_mode_0x02_pids_supported_19_20;
uint8_t obd_mode_0x02_pids_supported_01_08;
uint8_t obd_mode_0x02_pids_supported_09_10;
uint8_t obd_mode_0x02_pids_supported_11_18;
byte DAT_003fd780;
uint8_t obd_trouble_list_count;
undefined2 DAT_003fd60a;
undefined1 DAT_003fd621;
undefined2 DAT_003fd60e;
undefined1 DAT_003fd615;
undefined2 DAT_003fd612;
undefined2 DAT_003fd60c;
undefined1 DAT_003fd614;
undefined2 DAT_003fd610;
uint8_t obd_pending_list_count;
uint8_t LEA_obd_P0222_engine_start_count;
uint8_t LEA_obd_P0222_warm_up_cycle_count;
uint8_t LEA_obd_P0223_engine_start_count;
uint8_t LEA_obd_P0223_warm_up_cycle_count;
undefined1 DAT_003fd884;
uint8_t DAT_003fc97a;
uint8_t DAT_003fc97b;
char DAT_003fc97c;
char DAT_003fc97d;
uint8_t obd_mode_0x09_pids_supported_09_10;
uint8_t obd_mode_0x09_pids_supported_11_18;
uint8_t obd_mode_0x09_pids_supported_19_20;
uint8_t obd_mode_0x09_pids_supported_01_08;
byte DAT_003fd884;
undefined2 DAT_003fddd6;
undefined2 DAT_003fddd4;
undefined2 DAT_003fddce;
undefined2 DAT_003fddcc;
undefined2 DAT_003fddde;
undefined2 DAT_003fdddc;
undefined2 DAT_003fdde6;
undefined2 DAT_003fdde4;
undefined1 DAT_003fc97a;
undefined1 DAT_003fc97b;
undefined1 DAT_003fc97c;
undefined1 DAT_003fc97d;
uint16_t DAT_002f8352;
undefined2 DAT_003fbf7e;
undefined2 DAT_003fbf82;
uint8_t obd_mode_0x06_pids_supported_01_08;
uint8_t obd_mode_0x06_pids_supported_09_10;
uint8_t obd_mode_0x06_pids_supported_11_18;
uint8_t obd_mode_0x06_pids_supported_19_20;
byte DAT_003f8f60;
u16_time_5ms DAT_003fbff8;
uint8_t obd_mode_0x08_pids_supported_09_10;
uint8_t obd_mode_0x08_pids_supported_11_18;
uint8_t obd_mode_0x08_pids_supported_19_20;
u16_time_5ms obd_mode_0x08_timer;
uint8_t obd_mode_0x08_pids_supported_01_08;
undefined DAT_0000ffe4;
undefined DAT_0000ffe8;
undefined DAT_0000ffec;
undefined DAT_003fc97e;
undefined DAT_003fc982;
undefined DAT_003fc986;
undefined DAT_003fc98a;
uint8_t obd_mode_0x22_pids_supported_0201_0208;
undefined DAT_003fc98e;
uint8_t obd_mode_0x22_pids_supported_0209_0210;
undefined DAT_003fc992;
uint8_t obd_mode_0x22_pids_supported_0211_0218;
undefined DAT_003fc996;
uint8_t obd_mode_0x22_pids_supported_0219_0220;
uint8_t obd_mode_0x22_pids_supported_0221_0228;
uint8_t obd_mode_0x22_pids_supported_0229_0230;
uint8_t obd_mode_0x22_pids_supported_0231_0238;
uint8_t obd_mode_0x22_pids_supported_0239_0240;
uint8_t obd_mode_0x22_pids_supported_0241_0248;
uint8_t obd_mode_0x22_pids_supported_0249_0250;
uint8_t obd_mode_0x22_pids_supported_0251_0258;
uint8_t obd_mode_0x22_pids_supported_0259_0260;
uint8_t obd_mode_0x22_pids_supported_0261_0268;
uint8_t obd_mode_0x22_pids_supported_0269_0270;
uint8_t obd_mode_0x22_pids_supported_0271_0278;
uint8_t obd_mode_0x22_pids_supported_0279_0280;
uint8_t DAT_003f85b8;
uint8_t DAT_003f85b9;
short DAT_003fda9c;
u16_time_5ms DAT_003fbff6;
uint8_t DAT_003f85ba;
uint8_t DAT_003f85bb;
uint8_t obd_mode_0x2F_pids_supported_09_10;
uint8_t obd_mode_0x2F_pids_supported_79_80;
u16_time_5ms DAT_003fbfec;
u16_time_5ms DAT_003fbfee;
u16_time_5ms DAT_003fc006;
u16_time_5ms DAT_003fc008;
u16_time_5ms DAT_003fc000;
uint8_t DAT_003f85bc;
uint8_t DAT_003f85bd;
uint8_t DAT_003f85be;
u16_time_5ms DAT_003fc010;
undefined1 DAT_003fda9e;
undefined1 DAT_003fda9f;
u16_time_5ms DAT_003fbf6a;
u16_time_5ms DAT_003fc012;
u16_time_5ms DAT_003fc014;
u16_time_5ms DAT_003fc016;
u16_time_5ms DAT_003fc018;
u16_time_5ms DAT_003fc01a;
u16_time_5ms DAT_003fc00e;
ushort REG_TPU3A_CH1_PARAM3;
ushort REG_TPU3A_CH2_PARAM1;
ushort REG_TPU3A_CH2_PARAM2;
ushort REG_TPU3A_CH2_PARAM3;
undefined obd_mode_0x2F_pids_supported_11_18;
uint8_t obd_mode_0x2F_pids_supported_29_30;
uint8_t obd_mode_0x2F_pids_supported_31_38;
uint8_t obd_mode_0x2F_pids_supported_51_58;
uint8_t obd_mode_0x2F_pids_supported_61_68;
ushort REG_TPU3A_CH3_PARAM1;
uint8_t obd_mode_0x2F_pids_supported_69_70;
ushort REG_TPU3A_CH3_PARAM2;
uint8_t obd_mode_0x2F_pids_supported_71_78;
ushort REG_TPU3A_CH3_PARAM3;
ushort REG_TPU3A_CH4_PARAM1;
ushort REG_TPU3A_CH4_PARAM2;
ushort REG_TPU3A_CH4_PARAM3;
u16_time_5ms obd_mode_0x2F_timer;
short DAT_003fbff0;
u8_time_5ms DAT_003fbff2;
ushort DAT_003fbff4;
u8_time_5ms DAT_003fc00d;
u8_time_5ms obd_mode_0x2F_pulse_interval;
u16_factor_1/1023[16] CAL_tps_target;
u16_factor_1/1023 dev_pps_1;
u16_factor_1/1023 dev_pps_2;
u16_factor_1/1023 dev_pps_1_smooth;
u16_factor_1/1023 dev_pps_2_smooth;
undefined2 pps_min;
u16_factor_1/1023[16] CAL_tps_target_X_pps;
u16_time_5ms pps_offset_timer;
u8_time_5ms CAL_sensor_pps_offset_time_between_step;
byte DAT_003fe048;
byte DAT_003f8f88;
undefined2 DAT_003f8f8a;
byte DAT_003fc469;
byte DAT_003f8f8c;
undefined2 DAT_003f8f8e;
byte DAT_003fc45f;
byte DAT_003f8f90;
undefined2 DAT_003f8f92;
byte DAT_003fc460;
u8_obd_config CAL_obd_P2138;
byte DAT_003f8f94;
undefined2 DAT_003f8f96;
byte DAT_003fc461;
byte DAT_003f8f98;
u8_obd_config CAL_obd_P2122;
undefined2 DAT_003f8f9a;
byte DAT_003fc462;
u8_obd_config CAL_obd_P2123;
u8_obd_config CAL_obd_P2127;
u8_obd_config CAL_obd_P2128;
undefined1 DAT_003fc469;
undefined1 DAT_003f8f88;
undefined1 DAT_003fc45f;
undefined1 DAT_003f8f8c;
undefined1 DAT_003fc460;
undefined1 DAT_003f8f90;
undefined1 DAT_003fc461;
undefined1 DAT_003f8f94;
undefined1 DAT_003fc462;
undefined1 DAT_003f8f98;
undefined1 DAT_003fdb50;
undefined1 DAT_003fdb51;
undefined1 DAT_003fdb52;
uint8_t tps_state_machine;
pointer[5] tps_state_table;
uint8_t tps_state_motor_off_timer;
u16_factor_1/1023 dev_tps_rest_position;
u16_factor_1/10000 CAL_tps_ctrl_i_gain;
char DAT_003fdb52;
uint16_t CAL_tps_ctrl_i_limit;
u16_factor_1/10000 DAT_003fdb36;
uint DAT_003fdb38;
short DAT_003fdb58;
int DAT_003fdb5c;
ushort DAT_003fdb20;
undefined1 DAT_003fdb24;
short DAT_003fdb26;
u16_factor_1/1023 tps_diff;
int32_t tps_ctrl_i;
int32_t tps_ctrl_p;
int32_t tps_ctrl_i_sum;
u16_factor_1/1023[16] CAL_tps_motor_duty_cycle_X_tps;
uint8_t tps_state_test_passed;
u16_voltage_5/1023v tps_state_test_sample_tps_2;
u16_voltage_5/1023v tps_state_test_sample_tps_1;
i16_factor_1/1023 tps_dt;
uint8_t tps_state_test_failed;
int16_t tps_ctrl_d;
int16_t tps_output;
u16_factor_1/1024-1024[16] CAL_tps_motor_duty_cycle;
u16_factor_1/1023[4] tps_1_smooth_history;
u16_voltage_5/1023v tps_state_test_target;
uint8_t tps_state_test_sample_timer;
struct_filter_4th_order filter_tps_diff;
uint16_t tps_state_test_timer;
u16_factor_1/10 CAL_tps_ctrl_d_gain;
u16_factor_1/100 CAL_tps_ctrl_p_gain;
ushort DAT_003f9422;
ushort DAT_003f940e;
ushort DAT_003f9424;
ushort DAT_003f9426;
ushort DAT_003f9412;
ushort DAT_003f9428;
u16_voltage_5/1023v tps_2_range_corrected_low;
u16_voltage_5/1023v tps_1_range_corrected_high;
u16_voltage_5/1023v tps_2_range_corrected_high;
undefined2 tps_1_gain_corrected;
undefined2 tps_2_gain_computed;
int DAT_003fdb64;
undefined1 DAT_003fdb62;
ushort DAT_003fe056;
ushort DAT_003fbfe4;
u16_factor_1/1023 DAT_003fdb60;
char DAT_003fe05b;
char DAT_003fe06a;
ushort DAT_003f9526;
char DAT_003fe06e;
char DAT_003fdb8a;
u8_factor_1/255[8] CAL_tps_smooth_inc_X_tps_target;
u8_factor_1/1023[8] CAL_tps_smooth_inc;
uint16_t CAL_tps_smooth_time_between_step;
u16_factor_1/1023 tps_target_smooth;
u8_factor_1/255[8] CAL_tps_smooth_dec_X_tps_target;
u8_factor_1/1023[8] CAL_tps_smooth_dec;
u16_factor_1/1023 tps_state_sweep_limit_l;
uint8_t tps_state_sweep_enable;
uint8_t tps_state_sweep_direction;
u16_factor_1/1023 tps_target;
u8_factor_1/1023 tps_target_smooth_dec;
u8_factor_1/1023 tps_target_smooth_inc;
uint16_t tps_smooth_timer;
u16_factor_1/1023 CAL_tps_limit_h;
u16_factor_1/1023 CAL_tps_limit_l;
uint8_t tps_state_sweep_time_between_step;
uint8_t tps_state_sweep_timer;
uint8_t tps_state_sweep_step;
u16_factor_1/1023 tps_state_sweep_limit_h;
byte DAT_003fdff4;
uint8_t CAL_obd_P2173_debounce_threshold;
byte DAT_003fdb81;
u8_time_100ms obd_P2103_debounce_count;
undefined2 DAT_003f8fb8;
uint8_t CAL_obd_P2104_debounce_threshold;
u8_time_100ms obd_P2108_debounce_count;
byte DAT_003fc466;
uint8_t CAL_obd_P2105_debounce_threshold;
uint8_t CAL_obd_P2106_debounce_threshold;
byte DAT_003fdb6c;
undefined2 DAT_003f8fb0;
uint8_t CAL_obd_P2107_debounce_threshold;
byte DAT_003fc432;
u8_time_100ms CAL_obd_P2100_debounce_threshold;
u8_time_100ms CAL_obd_P2102_debounce_threshold;
byte DAT_003fdb7c;
undefined2 DAT_003f8fb2;
u8_time_100ms CAL_obd_P2103_debounce_threshold;
byte DAT_003fc433;
u8_time_100ms CAL_obd_P2108_debounce_threshold;
byte DAT_003fdb7d;
undefined2 DAT_003f8fb4;
byte DAT_003fc464;
byte DAT_003fdb7e;
undefined2 DAT_003f8fb6;
byte DAT_003fc465;
ushort DAT_003fbfe8;
undefined1 DAT_003fdb8a;
uint8_t obd_P0638_debounce_count;
uint8_t obd_P2173_debounce_count;
uint8_t obd_P2104_debounce_count;
uint8_t obd_P2105_debounce_count;
u8_obd_config CAL_obd_P2135;
uint8_t obd_P2106_debounce_count;
uint8_t obd_P2107_debounce_count;
uint8_t obd_P2100_debounce_count;
uint8_t obd_P2102_debounce_count;
u8_obd_config CAL_obd_P0122;
u8_obd_config CAL_obd_P0123;
u8_obd_config CAL_obd_P0222;
u8_obd_config CAL_obd_P0223;
u8_obd_config CAL_obd_P0638;
u8_obd_config CAL_obd_P2173;
u8_obd_config CAL_obd_P2104;
u8_obd_config CAL_obd_P2105;
u8_obd_config CAL_obd_P2107;
u8_obd_config CAL_obd_P2106;
u8_obd_config CAL_obd_P2100;
u8_obd_config CAL_obd_P2102;
u8_obd_config CAL_obd_P2103;
u8_obd_config CAL_obd_P2108;
u16_factor_1/1023 CAL_obd_P0638_threshold;
uint16_t obd_P0638_fault_sample_count;
uint16_t obd_P2173_fault_sample_count;
uint16_t obd_P2104_fault_sample_count;
uint16_t obd_P2105_fault_sample_count;
uint16_t obd_P2106_fault_sample_count;
uint16_t obd_P2107_fault_sample_count;
uint8_t CAL_obd_P0638_debounce_threshold;
undefined1 DAT_003fc432;
undefined1 DAT_003fdb6c;
undefined1 DAT_003fc433;
undefined1 DAT_003fdb7c;
undefined1 DAT_003fc464;
undefined1 DAT_003fdb7d;
undefined1 DAT_003fc465;
undefined1 DAT_003fdb7e;
undefined1 DAT_003fc466;
undefined1 DAT_003fdb81;
struct_filter_4th_order filter_unused_1;
struct_filter_4th_order filter_unused_2;
struct_filter_2nd_order filter_unused_3;
struct_filter_2nd_order filter_unused_4;
byte DAT_003fc08f;
byte DAT_003fc090;
byte DAT_003fc093;
undefined2 DAT_003fc09a;
undefined2 DAT_003f8fc8;
undefined2 DAT_003fc094;
undefined2 DAT_003f8fca;
undefined2 DAT_003fc096;
undefined2 DAT_003f8fcc;
struct_iumpr_monitor[6] iumpr_monitor;
undefined2 DAT_003fc098;
undefined2 DAT_003f8fce;
byte DAT_003f87d8;
byte DAT_003f87d9;
byte DAT_003f87da;
undefined2 DAT_003f87dc;
ushort DAT_003fc08a;
ushort DAT_003fc08c;
uint8_t *[6] iumpr_list;
byte DAT_003fc08e;
short DAT_003f8fca;
short DAT_003f8fce;
byte DAT_003fc091;
short DAT_003f8fc8;
byte DAT_003fc092;
short DAT_003fc09a;
short DAT_003f8fcc;
byte DAT_003fc088;
byte DAT_003fc089;
undefined DAT_003fddca;
undefined DAT_003fddd0;
u8_factor_1/256 CAL_tc_car_speed_reactivity;
u16_length_mm CAL_tc_front_tyre_circumference;
uint8_t CAL_tc_mode;
u8_factor_1/100 CAL_tc_slip_target_adj;
u8_speed_kph CAL_tc_front_speed_max;
u8_speed_kph CAL_tc_front_speed_min;
u16_rspeed_rpm CAL_tc_engine_speed_min;
u8_speed_kph[4] CAL_tc_slip_target_base_X_speed_front;
u8_factor_1/255[4] CAL_tc_slip_target_base_Y_pps;
u8_factor_1/100 CAL_tc_slip_min;
u8_factor_1/100[16] CAL_tc_slip_target_base;
u8_factor_10/1632 CAL_tc_slip_to_retard_ratio;
u8_factor_1/100[16] CAL_tc_fuelcut_X_slip;
u8_factor_1/255 CAL_tc_ign_adv_adj_limit;
uint8_t[16] CAL_tc_fuelcut;
u8_factor_1/256 CAL_tc_slip_reactivity;
u16_speed_1/100kph wheel_speed_f_max_1;
u16_speed_1/100kph wheel_speed_front_diff;
u16_speed_1/100kph wheel_speed_rear_diff;
uint32_t car_speed_smooth_x;
uint32_t tc_slip_diff_smooth_x;
u8_factor_1/255 tc_retard_adj1;
u16_speed_1/100kph wheel_speed_rl;
u8_factor_1/255 tc_retard_adj2;
u16_speed_1/100kph wheel_speed_rr;
u16_speed_1/100kph wheel_speed_fl;
u16_speed_1/100kph wheel_speed_fr;
u16_speed_1/100kph wheel_speed_diff;
u8_factor_1/100 tc_slip;
u8_factor_1/100 tc_slip_diff_smooth;
u8_factor_1/100 tc_slip_target;
undefined1 tc_state;
u16_length_mm CAL_tc_rear_tyre_circumference;
uint8_t CAL_tc_abs_ring_teeth_count;
short DAT_003f8804;
byte DAT_003f8fe4;
u16_time_5ms tc_slip_target_adj_timer;
u16_time_5ms tc_step_timer;
u16_speed_1/100kph CAL_tc_slip_adj_left_right_enable;
u16_time_5ms CAL_tc_slip_target_adj_time;
u16_time_5ms CAL_tc_time_between_step;
undefined1 DAT_003f8fe8;
undefined2 hc08_crc16;
char DAT_003f9009;
ushort REG_SC2SR;
undefined1 DAT_003f900b;
ushort REG_SC2DR;
undefined1 DAT_003f900a;
undefined1 DAT_003f9009;
uint8_t hc08_parse_len;
undefined1 DAT_003f9006;
ushort REG_SCC2R0;
ushort REG_SCC2R1;
byte DAT_003f900a;
char[32] sci2_rx_buffer;
byte DAT_003f9009;
byte DAT_003f900b;
byte DAT_003f9007;
undefined1 DAT_003f9008;
char[32] sci2_tx_buffer;
byte DAT_003f9008;
char[20] hc08_parse_buf;
uint8_t DAT_003f9006;
uint8_t hc08_parse_sum;
byte DAT_003f9006;
u8_factor_1/255 hc08_pps;
u8_factor_1/255 hc08_tps;
u8_factor_1/255 hc08_tps_target;
u8_voltage_5/255v hc08_PTB1_maf;
u8_voltage_5/255v hc08_PTB2_tps_1;
u8_voltage_5/255v hc08_PTB3_tps_2;
u8_voltage_5/255v hc08_PTB4_pps_1;
u8_voltage_5/255v hc08_PTB5_pps_2;
u8_voltage_5/255v hc08_PTB6;
u8_voltage_5/255v hc08_PTB7;
undefined1 DAT_003fdfd3;
undefined1 DAT_003fdfd4;
uint8_t DAT_003fe059;
uint8_t DAT_003fe05a;
u16_factor_1/1023[3] pps_1_history;
u16_factor_1/1023 DAT_003fe04e;
u16_factor_1/1023[3] pps_2_history;
u16_factor_1/1023 DAT_003fe050;
undefined1 DAT_003fe05b;
undefined2 pps_diff;
undefined1 DAT_003fe06e;
u16_factor_1/1023 CAL_sensor_pps_match_max;
u16_factor_1/1023 pps_1;
u16_factor_1/1023 pps_2;
undefined1 pps_correlation_state;
u16_voltage_5/1023v pps_1_range_high;
u16_voltage_5/1023v pps_1_range_low;
u16_voltage_5/1023v pps_2_range_high;
u16_voltage_5/1023v pps_2_range_low;
undefined1 DAT_003fdff4;
u16_voltage_5/1023v tps_2_range_high;
undefined1 DAT_003fe048;
u16_voltage_5/1023v tps_2_range_low;
undefined2 DAT_003fe054;
undefined2 DAT_003fe052;
u16_factor_1/1023[3] tps_1_history;
undefined2 DAT_003fe050;
u16_factor_1/1023[3] tps_2_history;
undefined2 DAT_003fe04e;
undefined2 DAT_003fe056;
undefined1 DAT_003fe05a;
undefined1 DAT_003fe059;
undefined2 DAT_003fe068;
undefined2 DAT_003fe066;
undefined2 DAT_003fe064;
undefined2 DAT_003fe062;
undefined1 DAT_003fe06a;
undefined1 DAT_003fe06d;
undefined1 DAT_003fe06c;
undefined1 DAT_003fe06f;
undefined1 DAT_003fe071;
u16_voltage_5/1023v CAL_misc_pps_1_range_low;
u16_voltage_5/1023v CAL_misc_pps_1_range_high;
u16_voltage_5/1023v CAL_misc_pps_2_range_low;
u16_voltage_5/1023v CAL_misc_pps_2_range_high;
u16_factor_1/1023 tps_1;
u16_factor_1/1023 tps_2;
undefined1 tps_correlation_state;
u16_voltage_5/1023v CAL_misc_tps_1_range_low;
u16_voltage_5/1023v CAL_misc_tps_1_range_high;
u16_voltage_5/1023v CAL_misc_tps_2_range_low;
u16_voltage_5/1023v CAL_misc_tps_2_range_high;
u16_voltage_5/1023v tps_1_range_high;
u16_voltage_5/1023v tps_1_range_low;
uint8_t DAT_003fe06c;
uint8_t DAT_003fe06d;
u16_factor_1/1023 DAT_003fe062;
u16_factor_1/1023 DAT_003fe064;
undefined2 DAT_003fbfe4;
u16_factor_1/1023 CAL_sensor_tps_match_max;
struct_varptr[470] struct_varptr_ARRAY_0007601c;
undefined1 DAT_003f8b08;
undefined1 DAT_003f8b09;
uint16_t[8] uint16_t_ARRAY_003f95fc;
struct_varptr[231] log_varptr_list;
char[512] log_data;
ushort REG_RX14MSKLO_B;
ushort REG_RX15MSKHI_B;
ushort REG_CANB_MB11_CS;
ushort REG_RX15MSKLO_B;
ushort REG_CANB_MB11_ID_HI;
ushort REG_ESTAT_B;
ushort REG_CANB_MB11_ID_LO;
ushort REG_IMASK_B;
ushort REG_CANB_MB0_CS;
ushort REG_CANB_MB0_ID_HI;
ushort REG_CANB_MB0_ID_LO;
ushort REG_CANB_MB12_CS;
ushort REG_CANB_MB12_ID_HI;
ushort REG_CANB_MB12_ID_LO;
ushort REG_CANB_MB1_CS;
ushort REG_CANB_MB1_ID_HI;
ushort REG_CANB_MB1_ID_LO;
ushort REG_CANB_MB13_CS;
ushort REG_CANB_MB13_ID_HI;
ushort REG_CANB_MB13_ID_LO;
ushort REG_CANB_MB2_CS;
ushort REG_CANB_MB2_ID_HI;
ushort REG_CANB_MB2_ID_LO;
ushort REG_CANB_MB14_CS;
ushort REG_CANB_MB14_ID_HI;
ushort REG_CANB_MB14_ID_LO;
ushort REG_CANB_MB3_CS;
ushort REG_CANB_MB3_ID_HI;
ushort REG_CANB_MB3_ID_LO;
ushort REG_CANB_MB15_CS;
ushort REG_CANB_MB15_ID_HI;
ushort REG_CANB_MB15_ID_LO;
ushort REG_CANB_MB4_CS;
ushort REG_CANB_MB4_ID_HI;
ushort REG_CANB_MB4_ID_LO;
ushort REG_CANB_MB5_CS;
ushort REG_CANB_MB5_ID_HI;
ushort REG_CANB_MB5_ID_LO;
ushort REG_CANB_MB6_CS;
ushort REG_CANB_MB6_ID_HI;
ushort REG_CANB_MB6_ID_LO;
ushort REG_CANB_MB7_CS;
ushort REG_CANB_MB7_ID_HI;
ushort REG_CANB_MB7_ID_LO;
ushort REG_CANB_MB8_CS;
ushort REG_CANB_MB8_ID_HI;
ushort REG_CANB_MB8_ID_LO;
ushort REG_CANB_MB9_CS;
ushort REG_CANB_MB9_ID_HI;
ushort REG_CANB_MB9_ID_LO;
ushort REG_CANMCR_B;
ushort REG_CANB_MB10_CS;
ushort REG_CANICR_B;
ushort REG_CANB_MB10_ID_HI;
byte REG_CANCTRL0_B;
ushort REG_CANB_MB10_ID_LO;
byte REG_CANCTRL1_B;
byte REG_PRESDIV_B;
byte REG_CTRL2_B;
ushort REG_RXGMSKHI_B;
ushort REG_RXGMSKLO_B;
ushort REG_RX14MSKHI_B;
ushort DAT_003f9066;
byte *DAT_003f9078;
byte *DAT_003f9058;
ushort REG_IFLAG_B;
byte REG_CANB_MB0_DATA0;
byte REG_CANB_MB3_DATA4;
byte DAT_003f9070;
byte *DAT_003f906c;
byte REG_CANB_MB3_DATA0;
byte REG_CANB_MB3_DATA1;
byte REG_CANB_MB3_DATA2;
byte REG_CANB_MB3_DATA3;
ushort DAT_003f9068;
undefined4 can_b_rx_data_ptr;
byte REG_CANB_MB13_DATA0;
ushort REG_TIMER_B;
byte REG_CANB_MB14_DATA0;
struct_varptr *DAT_003f9074;
struct_varptr *DAT_003f9060;
ushort DAT_003f9064;
byte *DAT_003f905c;
byte REG_CANB_MB1_DATA0;
byte REG_CANB_MB1_DATA1;
byte REG_CANB_MB1_DATA2;
byte REG_CANB_MB1_DATA3;
byte REG_CANB_MB1_DATA4;
byte REG_CANB_MB1_DATA5;
byte REG_CANB_MB1_DATA6;
byte REG_CANB_MB15_DATA0;
byte REG_CANB_MB15_DATA1;
byte REG_CANB_MB15_DATA2;
byte REG_CANB_MB15_DATA3;
byte REG_CANB_MB15_DATA4;
byte REG_CANB_MB15_DATA5;
byte REG_CANB_MB15_DATA6;
byte REG_CANB_MB15_DATA7;
ushort REG_CANA_MB6_CS;
ushort REG_CANA_MB6_ID_HI;
ushort REG_CANA_MB6_ID_LO;
ushort REG_CANA_MB7_CS;
ushort REG_CANA_MB7_ID_HI;
ushort REG_CANA_MB7_ID_LO;
ushort REG_CANA_MB8_CS;
ushort REG_CANA_MB8_ID_HI;
ushort REG_CANA_MB8_ID_LO;
ushort REG_CANA_MB9_CS;
ushort REG_CANA_MB9_ID_HI;
ushort REG_CANA_MB9_ID_LO;
ushort REG_CANMCR_A;
ushort REG_CANA_MB10_CS;
ushort REG_CANICR_A;
ushort REG_CANA_MB10_ID_HI;
byte REG_CANCTRL0_A;
ushort REG_CANA_MB10_ID_LO;
byte REG_CANCTRL1_A;
byte REG_PRESDIV_A;
byte REG_CTRL2_A;
ushort REG_RXGMSKHI_A;
ushort REG_RXGMSKLO_A;
ushort REG_RX14MSKHI_A;
ushort REG_RX14MSKLO_A;
ushort REG_RX15MSKHI_A;
ushort REG_CANA_MB11_CS;
ushort REG_RX15MSKLO_A;
ushort REG_CANA_MB11_ID_HI;
ushort REG_ESTAT_A;
ushort REG_CANA_MB11_ID_LO;
ushort REG_IMASK_A;
ushort REG_CANA_MB0_CS;
ushort REG_CANA_MB0_ID_HI;
ushort REG_CANA_MB0_ID_LO;
ushort REG_CANA_MB12_CS;
ushort REG_CANA_MB12_ID_HI;
ushort REG_CANA_MB12_ID_LO;
ushort REG_CANA_MB1_CS;
ushort REG_CANA_MB1_ID_HI;
ushort REG_CANA_MB1_ID_LO;
ushort REG_CANA_MB13_CS;
ushort REG_CANA_MB13_ID_HI;
ushort REG_CANA_MB13_ID_LO;
ushort REG_CANA_MB2_CS;
ushort REG_CANA_MB2_ID_HI;
ushort REG_CANA_MB2_ID_LO;
ushort REG_CANA_MB14_CS;
ushort REG_CANA_MB14_ID_HI;
ushort REG_CANA_MB14_ID_LO;
ushort REG_CANA_MB3_CS;
ushort REG_CANA_MB3_ID_HI;
ushort REG_CANA_MB3_ID_LO;
ushort REG_CANA_MB15_CS;
ushort REG_CANA_MB15_ID_HI;
ushort REG_CANA_MB15_ID_LO;
ushort REG_CANA_MB4_CS;
ushort REG_CANA_MB4_ID_HI;
ushort REG_CANA_MB4_ID_LO;
ushort REG_CANA_MB5_CS;
ushort REG_CANA_MB5_ID_HI;
ushort REG_CANA_MB5_ID_LO;
ushort DAT_003f908e;
byte *DAT_003f9098;
ushort REG_IFLAG_A;
byte *DAT_003f9080;
byte REG_CANA_MB0_DATA0;
byte DAT_003fe0ac;
byte *DAT_003fe0b0;
uint16_t[45] log_canid;
byte REG_CANA_MB2_DATA0;
undefined2 DAT_003fe0bc;
undefined2 DAT_003fe0c4;
undefined2 DAT_003fe0c6;
undefined2 DAT_003fe0c8;
byte REG_CANA_MB6_DATA0;
byte REG_CANA_MB6_DATA1;
byte REG_CANA_MB6_DATA2;
byte REG_CANA_MB6_DATA3;
byte REG_CANA_MB6_DATA4;
byte REG_CANA_MB6_DATA5;
byte REG_CANA_MB6_DATA6;
byte REG_CANA_MB6_DATA7;
ushort DAT_003f9090;
byte *DAT_003f909c;
char DAT_003fe0b4;
undefined1 DAT_003fe09c;
byte *DAT_003fe0b8;
undefined1 DAT_003f8a88;
byte REG_CANA_MB3_DATA0;
byte REG_CANA_MB3_DATA1;
byte REG_CANA_MB3_DATA2;
byte REG_CANA_MB13_DATA0;
byte REG_CANA_MB13_DATA1;
ushort REG_TIMER_A;
byte REG_CANA_MB14_DATA0;
undefined1 DAT_003fe0b4;
byte REG_CANA_MB14_DATA1;
byte DAT_003fe0ad;
undefined1 DAT_003fe0ac;
char *DAT_003fe0b0;
struct_varptr *PTR_DAT_003f9094;
struct_varptr *PTR_DAT_003f9088;
ushort DAT_003f908c;
byte *DAT_003f9084;
byte REG_CANA_MB1_DATA0;
byte REG_CANA_MB1_DATA1;
byte REG_CANA_MB1_DATA2;
byte REG_CANA_MB1_DATA3;
byte REG_CANA_MB1_DATA4;
byte REG_CANA_MB1_DATA5;
byte REG_CANA_MB1_DATA6;
byte REG_CANA_MB15_DATA0;
byte REG_CANA_MB15_DATA1;
byte REG_CANA_MB15_DATA2;
byte REG_CANA_MB15_DATA3;
byte REG_CANA_MB15_DATA4;
byte REG_CANA_MB15_DATA5;
byte REG_CANA_MB15_DATA6;
byte REG_CANA_MB15_DATA7;
byte REG_CANA_MB4_DATA0;
byte REG_CANA_MB4_DATA2;
byte REG_CANA_MB4_DATA4;
byte REG_CANA_MB4_DATA5;
byte REG_CANA_MB4_DATA6;
byte REG_CANA_MB4_DATA7;
byte DAT_003fe0cc;
char DAT_003fe189;
char DAT_003fe188;
int DAT_003fe190;
byte DAT_003fbf9e;
char DAT_003f90b8;
undefined4 DAT_003f8020;
undefined4 DAT_003f802c;
uint8_t[4] ign_coil_isr_phase;
ushort REG_TPU3A_CH1_PARAM4;
u8_time_5ms CAL_knock_retard1_time_between_step;
u8_angle_1/4deg CAL_knock_retard1_dec;
undefined4 DAT_003f8024;
undefined4 DAT_003f8028;
byte DAT_003f90a4;
byte DAT_003f90ba;
ushort REG_TPU3A_CH8_PARAM5;
ushort DAT_003f90b6;
ushort DAT_003f90b4;
undefined *DAT_003f90ac;
char DAT_003f8b28;
char DAT_003f90b9;
byte DAT_003fe18a;
short DAT_003fe184;
uint16_t CAL_ecu_CRC_stored;
byte DAT_003fe18c;
ushort DAT_003f8b2a;
ushort DAT_003f8b2c;
char DAT_003f937d;
char DAT_003f937e;
char DAT_003f937f;
char DAT_003f92d0;
uint8_t DAT_003f80d8;
undefined UNK_0000f424;
ushort REG_TPU3A_CH9_PARAM5;
uint8_t knock_cyl_i;
ushort DAT_003f90b0;
ushort REG_TPU3A_CH0_PARAM5;
ushort DAT_003f90b2;
ushort REG_TPU3A_CH10_PARAM4;
ushort REG_TPU3A_CH11_PARAM5;
ushort REG_TPU3A_CH12_PARAM5;
ushort REG_TPU3A_CH13_PARAM5;
byte DAT_003f90a5;
pointer PTR_DAT_0007b070;
uint16_t misfire_window_count;
uint16_t misfire_cat_window_count;
uint8_t misfire_i;
ushort REG_TPU3A_CH15_PARAM5;
uint16_t[4] misfire_count;
i16_time_us[4] misfire_stroke_diff_1;
i16_time_us[4] misfire_stroke_diff_2;
u16_time_us misfire_stroke_time_tpu;
u16_time_us[4] misfire_stroke_time;
u16_time_us[4] misfire_stroke_time_prev;
i16_time_us[4] misfire_stroke_time_smooth;
u16_time_us[4] misfire_stroke_time_dt;
i16_time_us[4] misfire_stroke_cyl_diff;
uint16_t[4] misfire_cat_count;
uint16_t misfire_cat_timer_max;
uint8_t[4] misfire_event_flags;
byte DAT_003fe18d;
pointer PTR_cleanup_callbacks_0007b0b0;
undefined DAT_003f90c0;
undefined DAT_003f91c0;

// Enables external hardware interrupts via MSR register

void enable_external_interrupts(void)

{
  uint in_MSR;
  
  init_system_registers(in_MSR | 0x2000);
  return;
}



// Empty stub function (no operation)

void nop_stub(void)

{
  return;
}



void entry_point(undefined4 param_1,undefined4 param_2,uint param_3)

{
  char *destination;
  char *source;
  
  init_stack();
  enable_external_interrupts();
  init_segment();
  nop_stub2();
  main();
  exit(0x75d30);
  if ((param_3 != 0) && (destination != source)) {
    memcpy(destination,source,param_3);
    nop_stub(destination,param_3);
  }
  return;
}



// Copies memory block with null/same-pointer check before copy

void memcpy_checked(char *destination,char *source,uint size)

{
  if ((size != 0) && (destination != source)) {
    memcpy(destination,source,size);
    nop_stub(destination,size);
  }
  return;
}



// Zeroes memory block using memset

void memzero(char *destination,uint size)

{
  if (size != 0) {
    memset_thunk(destination,0,size);
  }
  return;
}



// Initializes stack pointer (stub)

void init_stack(void)

{
  return;
}



// Copies initialized data from ROM to RAM and zeroes BSS segment

void init_segment(void)

{
  struct_segment_bss *psVar1;
  struct_segment_data *psVar2;
  
  for (psVar2 = segment_data; psVar2->size != 0; psVar2 = psVar2 + 1) {
    memcpy_checked(psVar2->dest,psVar2->src,psVar2->size);
  }
  for (psVar1 = segment_bss; psVar1->size != 0; psVar1 = psVar1 + 1) {
    memzero(psVar1->dest,psVar1->size);
  }
  return;
}



// Initializes MPC561 system registers (PLL, SYPCR, SCCR, PDMCR, SGPIOCR, UMCR)

void init_system_registers(void)

{
  REG_PLPRCRK = 0x55ccaa33;
  REG_PLPRCR = 0x900000;
  REG_SIUMCR = 0;
  REG_SYPCR = 0x7a1ff87;
  REG_SCCRK = 0x55ccaa33;
  REG_SCCR = 0x4024100;
  REG_PDMCR = 0x42100000;
  REG_SGPIOCR = 0xfcff;
  REG_SGPIODT1 = 0;
  REG_SGPIODT2 = 0;
  REG_UMCR = 0;
  return;
}



// Copies memory block with overlap handling (forward or backward copy)

void memcpy(char *destination,char *source,uint size)

{
  char *pcVar1;
  int iVar2;
  char *pcVar3;
  
  if (destination <= source) {
    pcVar1 = source + -1;
    pcVar3 = destination + -1;
    iVar2 = size + 1;
    while( true ) {
      iVar2 = iVar2 + -1;
      if (iVar2 == 0) break;
      pcVar1 = pcVar1 + 1;
      pcVar3 = pcVar3 + 1;
      *pcVar3 = *pcVar1;
    }
    return;
  }
  pcVar1 = source + size;
  pcVar3 = destination + size;
  iVar2 = size + 1;
  while( true ) {
    iVar2 = iVar2 + -1;
    if (iVar2 == 0) break;
    pcVar1 = pcVar1 + -1;
    pcVar3 = pcVar3 + -1;
    *pcVar3 = *pcVar1;
  }
  return;
}



// Fills memory block with constant value, optimized for 32-byte blocks

void memset(char *destination,int value,uint size)

{
  uint uVar1;
  uint *puVar2;
  char *pcVar3;
  uint uVar4;
  
  uVar4 = value & 0xff;
  pcVar3 = destination + -1;
  if (0x1f < size) {
    uVar1 = ~(uint)pcVar3 & 3;
    if (uVar1 != 0) {
      size = size - uVar1;
      do {
        uVar1 = uVar1 - 1;
        pcVar3 = pcVar3 + 1;
        *pcVar3 = (char)value;
      } while (uVar1 != 0);
    }
    if (uVar4 != 0) {
      uVar4 = uVar4 | uVar4 << 8 | uVar4 << 0x18 | uVar4 << 0x10;
    }
    puVar2 = (uint *)(pcVar3 + -3);
    for (uVar1 = size >> 5; uVar1 != 0; uVar1 = uVar1 - 1) {
      puVar2[1] = uVar4;
      puVar2[2] = uVar4;
      puVar2[3] = uVar4;
      puVar2[4] = uVar4;
      puVar2[5] = uVar4;
      puVar2[6] = uVar4;
      puVar2[7] = uVar4;
      puVar2 = puVar2 + 8;
      *puVar2 = uVar4;
    }
    for (uVar1 = size >> 2 & 7; uVar1 != 0; uVar1 = uVar1 - 1) {
      puVar2 = puVar2 + 1;
      *puVar2 = uVar4;
    }
    pcVar3 = (char *)((int)puVar2 + 3);
    size = size & 3;
  }
  if (size != 0) {
    do {
      size = size - 1;
      pcVar3 = pcVar3 + 1;
      *pcVar3 = (char)uVar4;
    } while (size != 0);
    return;
  }
  return;
}



// Wrapper that calls memset (compiler-generated thunk)

void memset_thunk(char *destination,int value,uint size)

{
  memset(destination,value,size);
  return;
}



// Sets exception/interrupt vector handler address

void set_exception_vector(undefined4 param_1)

{
  DAT_003f92c0 = param_1;
  return;
}



// ISR: System timebase tick (5ms scheduler)

undefined8 isr_timebase(undefined4 param_1,undefined4 param_2)

{
  ushort uVar1;
  undefined4 in_MSR;
  undefined4 in_SRR1;
  
  uVar1 = REG_TBSCR;
  REG_TBSCR = uVar1 & 0xfffe;
  returnFromInterrupt(in_MSR,in_SRR1);
  return CONCAT44(param_1,param_2);
}



// Main loop: initializes ECU subsystems and runs continuous engine management tasks including
// ignition, injection, sensors, diagnostics, and communication

void main(void)

{
  uint uVar1;
  ushort uVar2;
  
  copyCAL2RAM();
  pps_check_init();
  dev_inj_efficiency_adj = 128;
  dev_ign_adv_adj = 128;
  dev_inj_angle = 0;
  dev_vvt_angle = 0;
  DAT_003f92d5 = 0x80;
  dev_afr_adj = 0;
  DAT_003f92d7 = 0;
  DAT_003f92d8 = 0;
  DAT_003f8bb9 = 0;
  DAT_003f8bb8 = 0;
  fuelpump_timer = CAL_ecu_fuelpump_prime;
  uVar2 = REG_MPWMSM16_SCR;
  REG_MPWMSM16_SCR = uVar2 & 0xf7ff | 0x800;
  eeprom_load();
  uVar2 = REG_RSR;
  if ((uVar2 >> 0xc & 1) == 1) {
    uVar2 = REG_RSR;
    REG_RSR = uVar2 & 0xefff | 0x1000;
    DAT_003fd5a0 = DAT_003fd5a0 | 2;
  }
  init_siu();
  REG_SIMASK = 0;
  REG_SIMASK2 = 0;
  REG_SIMASK3 = 0;
  uVar1 = REG_SIMASK3;
  REG_SIMASK3 = uVar1 & 0xffefffff | 0x100000;
  uVar1 = REG_SIMASK3;
  REG_SIMASK3 = uVar1 & 0xfdffffff | 0x2000000;
  uVar1 = REG_SIMASK3;
  REG_SIMASK3 = uVar1 & 0x7fffffff | 0x80000000;
  uVar1 = REG_SIMASK3;
  REG_SIMASK3 = uVar1 & 0xbfffffff | 0x40000000;
  uVar1 = REG_SIMASK2;
  REG_SIMASK2 = uVar1 & 0xff7fffff | 0x800000;
  uVar1 = REG_SIMASK2;
  REG_SIMASK2 = uVar1 & 0xffbfffff | 0x400000;
  uVar1 = REG_SIMASK3;
  REG_SIMASK3 = uVar1 & 0xffbfffff | 0x400000;
  uVar2 = REG_MPIOSMDR;
  REG_MPIOSMDR = uVar2 & 0xdfff | 0x2000;
  uVar2 = REG_MPIOSMDR;
  REG_MPIOSMDR = uVar2 & 0xffef | 0x10;
  do {
    watchdog_retrigger();
    obd_kline_dispatch();
    DAT_003f92c4 = DAT_003fda9e | L9822E_outputs & ~DAT_003fda9f;
    DAT_003f92d0 = 1;
    L9822E_outputs = DAT_003f92c4;
    spi_pcs1();
    spi_pcs0();
    spi_pcs3();
    DAT_003f92d0 = 0;
    if (DAT_003f80d8 != -1) {
      spi_pcs2(DAT_003f80d8);
      DAT_003f80d8 = -1;
    }
    adc_sample();
    L9822E_fault_check();
    TLE6220_fault_check();
    obd_task();
    adc_avg();
    engine_load();
    adc_convert();
    shutdown();
    fan_control();
    ac_compressor();
    idle();
    evap_state_machine();
    evap();
    injtip();
    gear_determination();
    log_copy();
    closedloop();
    injection();
    ignition();
    dev_reset_lea();
    hc08_com();
    dev_varptr_io_update();
    vvt();
    vvl();
    airbox_flap();
    knock_window();
    knock();
    recirculation_pump();
    traction_control();
  } while( true );
}



// Empty stub function (no operation)

void nop_stub2(void)

{
  return;
}



// 2D table lookup with linear interpolation for uint8 values

uint8_t lookup_2D_uint8_interpolated(uint8_t size_x,uint8_t input_x,uint8_t *lut,uint8_t *x_axis)

{
  short sVar1;
  uint8_t uVar2;
  short sVar3;
  
  sVar1 = size_x - 1;
  sVar3 = 0;
  if (*x_axis < input_x) {
    if (input_x < x_axis[sVar1]) {
      for (; (x_axis[sVar3] < input_x && (sVar3 < sVar1)); sVar3 = sVar3 + 1) {
      }
      if (input_x == x_axis[sVar3]) {
        uVar2 = lut[sVar3];
      }
      else if (x_axis[sVar3] == x_axis[sVar3 + -1]) {
        uVar2 = lut[sVar3];
      }
      else {
        uVar2 = lut[sVar3 + -1] +
                (char)((int)((int)(short)((ushort)lut[sVar3] - (ushort)lut[sVar3 + -1]) *
                            ((uint)input_x - (uint)x_axis[sVar3 + -1])) /
                      (int)((uint)x_axis[sVar3] - (uint)x_axis[sVar3 + -1]));
      }
    }
    else {
      uVar2 = lut[sVar1];
    }
  }
  else {
    uVar2 = *lut;
  }
  return uVar2;
}



// 2D table lookup with linear interpolation for uint16 values

uint16_t lookup_2D_uint16_interpolated
                   (uint8_t size_x,uint16_t input_x,uint16_t *lut,uint16_t *x_axis)

{
  short last;
  uint16_t result;
  short i;
  
  last = size_x - 1;
  i = 0;
  if (*x_axis < input_x) {
    if (input_x < x_axis[last]) {
      for (; (x_axis[i] < input_x && (i < last)); i = i + 1) {
      }
      if (input_x == x_axis[i]) {
        result = lut[i];
      }
      else if (x_axis[i] == x_axis[i + -1]) {
        result = lut[i];
      }
      else {
        result = lut[i + -1] +
                 (short)((int)((int)(short)(lut[i] - lut[i + -1]) *
                              ((uint)input_x - (uint)x_axis[i + -1])) /
                        (int)((uint)x_axis[i] - (uint)x_axis[i + -1]));
      }
    }
    else {
      result = lut[last];
    }
  }
  else {
    result = *lut;
  }
  return result;
}



// 2D table lookup with fixed-point axis calculation

uint8_t lookup_2D_uint8_interpolated_noaxis(uint8_t shift,uint16_t input,uint8_t *lut)

{
  int iVar1;
  uint uVar2;
  uint8_t uVar3;
  
  uVar2 = (uint)input << (shift & 0x3f) & 0xffff;
  iVar1 = (int)uVar2 >> 8;
  if (lut[iVar1] == lut[iVar1 + 1]) {
    uVar3 = lut[iVar1];
  }
  else {
    uVar2 = (int)(short)((ushort)lut[iVar1 + 1] - (ushort)lut[iVar1]) *
            (uVar2 - (int)(short)(iVar1 << 8));
    uVar3 = lut[iVar1] + (char)(uVar2 >> 8) + ((int)uVar2 < 0 && (uVar2 & 0xff) != 0);
  }
  return uVar3;
}



// WARNING: Inlined function: push_23to31
// WARNING: Inlined function: pop_23to31
// 3D table lookup with bilinear interpolation for uint8 values

uint8_t lookup_3D_uint8_interpolated
                  (uint8_t size_x,uint8_t size_y,uint16_t input_x,uint16_t input_y,uint8_t *lut,
                  uint8_t *x_axis,uint8_t *y_axis)

{
  ushort uVar1;
  ushort uVar2;
  ushort uVar3;
  ushort uVar4;
  ushort uVar5;
  short sVar6;
  uint8_t uVar7;
  ushort uVar8;
  ushort uVar9;
  ushort uVar10;
  byte local_38;
  byte local_37;
  
  uVar3 = input_x & 0xff;
  uVar4 = input_y & 0xff;
  uVar1 = (ushort)size_x;
  uVar8 = uVar1 - 1;
  uVar2 = (ushort)size_y;
  uVar5 = uVar2 - 1;
  uVar10 = 0;
  uVar9 = 0;
  if ((uVar3 < *x_axis) && (uVar4 < *y_axis)) {
    uVar7 = *lut;
  }
  else if ((x_axis[(short)uVar8] < uVar3) && (y_axis[(short)uVar5] < uVar4)) {
    uVar7 = lut[(int)(short)uVar1 * (int)(short)uVar2 + -1];
  }
  else {
    for (; (y_axis[(short)uVar9] < uVar4 && ((short)uVar9 < (short)uVar5)); uVar9 = uVar9 + 1) {
    }
    if ((y_axis[(short)uVar9] < uVar4) && (uVar9 == uVar5)) {
      uVar9 = uVar9 + 1;
    }
    for (; (x_axis[(short)uVar10] < uVar3 && ((short)uVar10 < (short)uVar8)); uVar10 = uVar10 + 1) {
    }
    if ((x_axis[(short)uVar10] < uVar3) && (uVar10 == uVar8)) {
      uVar10 = uVar10 + 1;
    }
    if (((uVar3 == x_axis[(short)uVar10]) && (uVar4 == y_axis[(short)uVar9])) && (uVar9 == size_y))
    {
      uVar7 = lut[(int)(short)uVar10 + ((short)uVar9 + -1) * (int)(short)uVar1];
    }
    else if ((uVar3 == x_axis[(short)uVar10]) && (uVar4 == y_axis[(short)uVar9])) {
      uVar7 = lut[(int)(short)uVar10 + (int)(short)uVar9 * (int)(short)uVar1];
    }
    else {
      uVar5 = (ushort)size_x;
      if (((uVar4 == y_axis[(short)uVar9]) || (uVar9 == uVar2)) || (uVar9 == 0)) {
        if (uVar9 == uVar2) {
          uVar9 = uVar9 - 1;
        }
        if (uVar10 == uVar1) {
          if (x_axis[(short)uVar10 + -1] == x_axis[(short)uVar10 + -2]) {
            uVar7 = lut[((short)uVar9 + 1) * (int)(short)uVar1 + -2];
          }
          else {
            uVar7 = lut[((short)uVar9 + 1) * (int)(short)uVar1 + -1];
          }
        }
        else if (uVar10 == 0) {
          uVar7 = lut[(int)(short)uVar9 * (int)(short)uVar1];
        }
        else {
          sVar6 = uVar10 + uVar9 * uVar5;
          if (x_axis[(short)uVar10 + -1] == x_axis[(short)uVar10]) {
            uVar7 = lut[sVar6 + -1];
          }
          else {
            uVar7 = lut[sVar6 + -1] +
                    (char)((int)(((int)(short)uVar3 - (uint)x_axis[(short)uVar10 + -1]) *
                                ((uint)lut[sVar6] - (uint)lut[sVar6 + -1])) /
                          (int)((uint)x_axis[(short)uVar10] - (uint)x_axis[(short)uVar10 + -1]));
          }
        }
      }
      else if (((uVar3 == x_axis[(short)uVar10]) || (uVar10 == uVar1)) || (uVar10 == 0)) {
        if (uVar10 == uVar1) {
          uVar10 = uVar10 - 1;
        }
        sVar6 = uVar10 + uVar9 * uVar5;
        if (uVar9 == uVar2) {
          if (y_axis[(short)uVar9 + -2] == y_axis[(short)uVar9 + -1]) {
            uVar7 = lut[(int)sVar6 + (short)uVar1 * -2];
          }
          else {
            uVar7 = lut[(int)sVar6 - (int)(short)uVar1];
          }
        }
        else if (uVar9 == 0) {
          uVar7 = lut[(short)uVar10];
        }
        else if (y_axis[(short)uVar9 + -1] == y_axis[(short)uVar9]) {
          uVar7 = lut[(int)sVar6 - (int)(short)uVar1];
        }
        else {
          uVar7 = lut[(int)sVar6 - (int)(short)uVar1] +
                  (char)((int)(((int)(short)uVar4 - (uint)y_axis[(short)uVar9 + -1]) *
                              ((uint)lut[sVar6] - (uint)lut[(int)sVar6 - (int)(short)uVar1])) /
                        (int)((uint)y_axis[(short)uVar9] - (uint)y_axis[(short)uVar9 + -1]));
        }
      }
      else {
        sVar6 = uVar10 + (uVar9 - 1) * uVar5;
        if (x_axis[(short)uVar10 + -1] == x_axis[(short)uVar10]) {
          local_37 = lut[sVar6];
          local_38 = lut[(int)sVar6 + (int)(short)uVar1];
        }
        else {
          local_37 = lut[sVar6 + -1] +
                     (char)((int)(((int)(short)uVar3 - (uint)x_axis[(short)uVar10 + -1]) *
                                 ((uint)lut[sVar6] - (uint)lut[sVar6 + -1])) /
                           (int)((uint)x_axis[(short)uVar10] - (uint)x_axis[(short)uVar10 + -1]));
          local_38 = lut[(int)sVar6 + (int)(short)uVar8] +
                     (char)((int)(((int)(short)uVar3 - (uint)x_axis[(short)uVar10 + -1]) *
                                 ((uint)lut[(int)sVar6 + (int)(short)uVar1] -
                                 (uint)lut[(int)sVar6 + (int)(short)uVar8])) /
                           (int)((uint)x_axis[(short)uVar10] - (uint)x_axis[(short)uVar10 + -1]));
        }
        uVar7 = local_37 +
                (char)((int)(((int)(short)uVar4 - (uint)y_axis[(short)uVar9 + -1]) *
                            ((uint)local_38 - (uint)local_37)) /
                      (int)((uint)y_axis[(short)uVar9] - (uint)y_axis[(short)uVar9 + -1]));
      }
    }
  }
  return uVar7;
}



// WARNING: Inlined function: push_24to31
// WARNING: Inlined function: pop_24to31
// 3D table lookup with bilinear interpolation for uint16 values

uint16_t lookup_3D_uint16_interpolated
                   (uint8_t size_x,uint8_t size_y,uint16_t input_x,uint16_t input_y,uint16_t *lut,
                   uint16_t *x_axis,uint16_t *y_axis)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  uint uVar8;
  uint uVar9;
  ushort local_28;
  ushort local_26;
  
  uVar1 = (uint)size_x;
  uVar2 = (uint)size_y;
  uVar3 = (uint)input_x;
  uVar4 = (uint)input_y;
  uVar6 = uVar1 - 1;
  uVar5 = uVar2 - 1;
  uVar9 = 0;
  uVar8 = 0;
  if ((uVar3 < *x_axis) && (uVar4 < *y_axis)) {
    local_26 = *lut;
  }
  else if ((x_axis[uVar6] < uVar3) && (y_axis[uVar5] < uVar4)) {
    local_26 = lut[uVar1 * uVar2 + -1];
  }
  else {
    for (; (y_axis[uVar8] < uVar4 && ((int)uVar8 < (int)uVar5)); uVar8 = uVar8 + 1) {
    }
    if ((y_axis[uVar8] < uVar4) && (uVar8 == uVar5)) {
      uVar8 = uVar8 + 1;
    }
    for (; (x_axis[uVar9] < uVar3 && ((int)uVar9 < (int)uVar6)); uVar9 = uVar9 + 1) {
    }
    if ((x_axis[uVar9] < uVar3) && (uVar9 == uVar6)) {
      uVar9 = uVar9 + 1;
    }
    if (((uVar3 == x_axis[uVar9]) && (uVar4 == y_axis[uVar8])) && (uVar8 == size_y)) {
      local_26 = lut[uVar9 + (uVar8 - 1) * uVar1];
    }
    else if ((uVar3 == x_axis[uVar9]) && (uVar4 == y_axis[uVar8])) {
      local_26 = lut[uVar9 + uVar8 * uVar1];
    }
    else if (((uVar4 == y_axis[uVar8]) || (uVar8 == uVar2)) || (uVar8 == 0)) {
      if (uVar8 == uVar2) {
        uVar8 = uVar8 - 1;
      }
      if (uVar9 == uVar1) {
        if (x_axis[uVar9 - 1] == x_axis[uVar9 - 2]) {
          local_26 = lut[(uVar8 + 1) * uVar1 + -2];
        }
        else {
          local_26 = lut[(uVar8 + 1) * uVar1 + -1];
        }
      }
      else if (uVar9 == 0) {
        local_26 = lut[uVar8 * uVar1];
      }
      else {
        iVar7 = uVar9 + uVar8 * uVar1;
        if (x_axis[uVar9 - 1] == x_axis[uVar9]) {
          local_26 = lut[iVar7 + -1];
        }
        else {
          local_26 = lut[iVar7 + -1] +
                     (short)((int)((uVar3 - x_axis[uVar9 - 1]) *
                                  ((uint)lut[iVar7] - (uint)lut[iVar7 + -1])) /
                            (int)((uint)x_axis[uVar9] - (uint)x_axis[uVar9 - 1]));
        }
      }
    }
    else if (((uVar3 == x_axis[uVar9]) || (uVar9 == uVar1)) || (uVar9 == 0)) {
      if (uVar9 == uVar1) {
        uVar9 = uVar9 - 1;
      }
      iVar7 = uVar9 + uVar8 * uVar1;
      if (uVar8 == uVar2) {
        if (y_axis[uVar8 - 2] == y_axis[uVar8 - 1]) {
          local_26 = lut[iVar7 + uVar1 * -2];
        }
        else {
          local_26 = lut[iVar7 - uVar1];
        }
      }
      else if (uVar8 == 0) {
        local_26 = lut[uVar9];
      }
      else if (y_axis[uVar8 - 1] == y_axis[uVar8]) {
        local_26 = lut[iVar7 - uVar1];
      }
      else {
        local_26 = lut[iVar7 - uVar1] +
                   (short)((int)((uVar4 - y_axis[uVar8 - 1]) *
                                ((uint)lut[iVar7] - (uint)lut[iVar7 - uVar1])) /
                          (int)((uint)y_axis[uVar8] - (uint)y_axis[uVar8 - 1]));
      }
    }
    else {
      iVar7 = uVar9 + (uVar8 - 1) * uVar1;
      if (x_axis[uVar9 - 1] == x_axis[uVar9]) {
        local_26 = lut[iVar7];
        local_28 = lut[iVar7 + uVar1];
      }
      else {
        local_26 = lut[iVar7 + -1] +
                   (short)((int)((uVar3 - x_axis[uVar9 - 1]) *
                                ((uint)lut[iVar7] - (uint)lut[iVar7 + -1])) /
                          (int)((uint)x_axis[uVar9] - (uint)x_axis[uVar9 - 1]));
        local_28 = lut[iVar7 + uVar6] +
                   (short)((int)((uVar3 - x_axis[uVar9 - 1]) *
                                ((uint)lut[iVar7 + uVar1] - (uint)lut[iVar7 + uVar6])) /
                          (int)((uint)x_axis[uVar9] - (uint)x_axis[uVar9 - 1]));
      }
      local_26 = local_26 +
                 (short)((int)((uVar4 - y_axis[uVar8 - 1]) * ((uint)local_28 - (uint)local_26)) /
                        (int)((uint)y_axis[uVar8] - (uint)y_axis[uVar8 - 1]));
    }
  }
  return local_26;
}



// WARNING: Inlined function: push_25to31
// WARNING: Inlined function: pop_25to31
// 3D table lookup with fixed-point axis calculation

uint8_t lookup_3D_uint8_interpolated_noaxis
                  (uint8_t size_x,uint8_t shift_x,uint8_t shift_y,uint16_t input_x,uint16_t input_y,
                  uint8_t *lut)

{
  uint uVar1;
  short sVar3;
  uint uVar2;
  short sVar4;
  short sVar5;
  short sVar6;
  
  uVar1 = (input_x & 0xff) << (shift_x & 0x3f);
  sVar3 = (short)uVar1;
  uVar2 = (input_y & 0xff) << (shift_y & 0x3f);
  sVar4 = (short)(char)(uVar1 >> 8) + (ushort)(sVar3 < 0 && (uVar1 & 0xff) != 0);
  sVar5 = (short)(char)(uVar2 >> 8) + (ushort)((short)uVar2 < 0 && (uVar2 & 0xff) != 0);
  sVar6 = sVar4 + sVar5 * (ushort)size_x;
  uVar1 = (uint)lut[sVar6] +
          (int)(((int)sVar3 + sVar4 * -0x100) * ((uint)lut[sVar6 + 1] - (uint)lut[sVar6])) /
          ((sVar4 + 1) * 0x100 + sVar4 * -0x100);
  return (char)uVar1 +
         (char)((int)(((int)(short)uVar2 + sVar5 * -0x100) *
                     (((uint)lut[(uint)size_x + (int)sVar6] +
                       (int)(((int)sVar3 + sVar4 * -0x109) *
                            ((uint)lut[(int)sVar6 + size_x + 1] -
                            (uint)lut[(uint)size_x + (int)sVar6])) /
                       ((sVar4 + 1) * 0x100 + sVar4 * -0x109) & 0xff) - (uVar1 & 0xff))) /
               ((sVar5 + 1) * 0x100 + sVar5 * -0x100));
}



// Loads TPU microcode from ROM to DPTRAM

void tpu_load_microcode(void)

{
  ushort uVar1;
  
  uVar1 = REG_DPTMCR;
  REG_DPTMCR = uVar1 & 0xfeff;
  REG_RAMBAR = 0xffa0;
  memcpy(&REG_DPTRAM,tpu_microcode,0x800);
  return;
}



// Initializes both TPU modules (A and B)

void init_tpu(void)

{
  tpu_load_microcode();
  init_tpu_a();
  init_tpu_b();
  return;
}



// Initializes TPU-A: crank/cam sensing, ignition coils, wheel speed inputs

void init_tpu_a(void)

{
  ushort uVar1;
  
  REG_TPUMCR_A = 0x480;
  REG_TPUMCR2_A = 0;
  REG_TPUMCR3_A = 0x53;
  REG_CPR1_A = 0;
  REG_CPR0_A = 0;
  REG_CFSR3_A = 0;
  REG_CFSR2_A = 0;
  REG_CFSR1_A = 0;
  REG_CFSR0_A = 0;
  uVar1 = REG_CFSR3_A;
  REG_CFSR3_A = uVar1 & 0xfff0 | 0xb;
  REG_TPU3A_CH0_PARAM0 = 4;
  REG_TPU3A_CH0_PARAM1 = 0x121;
  REG_TPU3A_CH0_PARAM3 = 0xff44;
  uVar1 = REG_HSQR1_A;
  REG_HSQR1_A = uVar1 & 0xfffc | 3;
  uVar1 = REG_HSRR1_A;
  REG_HSRR1_A = uVar1 & 0xfffc | 1;
  uVar1 = REG_CPR1_A;
  REG_CPR1_A = uVar1 & 0xfffc | 3;
  do {
    uVar1 = REG_HSRR1_A;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR3_A;
  REG_CFSR3_A = uVar1 & 0xff0f | 0xe0;
  uVar1 = REG_HSQR1_A;
  REG_HSQR1_A = uVar1 & 0xfff3;
  REG_TPU3A_CH1_PARAM0 = 0x89;
  REG_TPU3A_CH1_PARAM1 = DAT_003fe18e;
  REG_TPU3A_CH1_PARAM2 = 0xec;
  uVar1 = REG_CPR1_A;
  REG_CPR1_A = uVar1 & 0xfff3 | 0xc;
  uVar1 = REG_HSRR1_A;
  REG_HSRR1_A = uVar1 & 0xfff3 | 4;
  do {
    uVar1 = REG_HSRR1_A;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR3_A;
  REG_CFSR3_A = uVar1 & 0xf0ff | 0xc00;
  REG_TPU3A_CH2_PARAM0 = 0xb02;
  REG_TPU3A_CH2_PARAM4 = 0xff;
  REG_TPU3A_CH2_PARAM5 = 0x51e;
  uVar1 = REG_HSQR1_A;
  REG_HSQR1_A = uVar1 & 0xffcf | 0x10;
  uVar1 = REG_HSRR1_A;
  REG_HSRR1_A = uVar1 & 0xffcf | 0x20;
  uVar1 = REG_CPR1_A;
  REG_CPR1_A = uVar1 & 0xffcf | 0x30;
  do {
    uVar1 = REG_HSRR1_A;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR3_A;
  REG_CFSR3_A = uVar1 & 0xfff | 0xc000;
  uVar1 = REG_HSQR1_A;
  REG_HSQR1_A = uVar1 & 0xff3f | 0x40;
  REG_TPU3A_CH3_PARAM0 = 0xb02;
  REG_TPU3A_CH3_PARAM4 = 0xff;
  REG_TPU3A_CH3_PARAM5 = 0x51e;
  uVar1 = REG_HSRR1_A;
  REG_HSRR1_A = uVar1 & 0xff3f | 0x80;
  uVar1 = REG_CPR1_A;
  REG_CPR1_A = uVar1 & 0xff3f | 0xc0;
  do {
    uVar1 = REG_HSRR1_A;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR2_A;
  REG_CFSR2_A = uVar1 & 0xfff0 | 0xc;
  uVar1 = REG_HSQR1_A;
  REG_HSQR1_A = uVar1 & 0xfcff | 0x100;
  REG_TPU3A_CH4_PARAM0 = 0xb02;
  REG_TPU3A_CH4_PARAM4 = 0xff;
  REG_TPU3A_CH4_PARAM5 = 0x51e;
  uVar1 = REG_HSRR1_A;
  REG_HSRR1_A = uVar1 & 0xfcff | 0x200;
  uVar1 = REG_CPR1_A;
  REG_CPR1_A = uVar1 & 0xfcff | 0x300;
  do {
    uVar1 = REG_HSRR1_A;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR2_A;
  REG_CFSR2_A = uVar1 & 0xff0f | 0xc0;
  uVar1 = REG_HSQR1_A;
  REG_HSQR1_A = uVar1 & 0xf3ff | 0x400;
  REG_TPU3A_CH5_PARAM0 = 0xb02;
  REG_TPU3A_CH5_PARAM4 = 0xff;
  REG_TPU3A_CH5_PARAM5 = 0x51e;
  uVar1 = REG_HSRR1_A;
  REG_HSRR1_A = uVar1 & 0xf3ff | 0x800;
  uVar1 = REG_CPR1_A;
  REG_CPR1_A = uVar1 & 0xf3ff | 0xc00;
  do {
    uVar1 = REG_HSRR1_A;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR2_A;
  REG_CFSR2_A = uVar1 & 0xf0ff | 0xc00;
  uVar1 = REG_HSQR1_A;
  REG_HSQR1_A = uVar1 & 0xcfff | 0x1000;
  REG_TPU3A_CH6_PARAM0 = 0xb02;
  REG_TPU3A_CH6_PARAM4 = 0xff;
  REG_TPU3A_CH6_PARAM5 = 0x51e;
  uVar1 = REG_HSRR1_A;
  REG_HSRR1_A = uVar1 & 0xcfff | 0x2000;
  uVar1 = REG_CPR1_A;
  REG_CPR1_A = uVar1 & 0xcfff | 0x3000;
  do {
    uVar1 = REG_HSRR1_A;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR2_A;
  REG_CFSR2_A = uVar1 & 0xfff | 0xc000;
  uVar1 = REG_HSQR1_A;
  REG_HSQR1_A = uVar1 & 0x3fff | 0x8000;
  REG_TPU3A_CH7_PARAM0 = 0xb02;
  REG_TPU3A_CH7_PARAM4 = 0xff37;
  REG_TPU3A_CH7_PARAM5 = 0x1038;
  uVar1 = REG_HSRR1_A;
  REG_HSRR1_A = uVar1 & 0x3fff | 0x8000;
  uVar1 = REG_CPR1_A;
  REG_CPR1_A = uVar1 & 0x3fff | 0x4000;
  do {
    uVar1 = REG_HSRR1_A;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR1_A;
  REG_CFSR1_A = uVar1 & 0xfff0 | 0xf;
  uVar1 = REG_HSQR0_A;
  REG_HSQR0_A = uVar1 & 0xfffc;
  REG_TPU3A_CH8_PARAM0 = 0xb;
  REG_TPU3A_CH8_PARAM1 = 0x100;
  REG_TPU3A_CH8_PARAM4 = 0xff00;
  uVar1 = REG_CPR0_A;
  REG_CPR0_A = uVar1 & 0xfffc | 1;
  uVar1 = REG_HSRR0_A;
  REG_HSRR0_A = uVar1 & 0xfffc | 2;
  do {
    uVar1 = REG_HSRR0_A;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR1_A;
  REG_CFSR1_A = uVar1 & 0xff0f | 0xf0;
  uVar1 = REG_HSQR0_A;
  REG_HSQR0_A = uVar1 & 0xfff3;
  REG_TPU3A_CH9_PARAM0 = 0xb;
  REG_TPU3A_CH9_PARAM1 = 0x100;
  REG_TPU3A_CH9_PARAM4 = 0xff00;
  uVar1 = REG_HSRR0_A;
  REG_HSRR0_A = uVar1 & 0xfff3 | 8;
  uVar1 = REG_CPR0_A;
  REG_CPR0_A = uVar1 & 0xfff3 | 4;
  do {
    uVar1 = REG_HSRR0_A;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR1_A;
  REG_CFSR1_A = uVar1 & 0xf0ff | 0xa00;
  uVar1 = REG_HSQR0_A;
  REG_HSQR0_A = uVar1 & 0xffcf | 0x10;
  REG_TPU3A_CH10_PARAM0 = 7;
  REG_TPU3A_CH10_PARAM1 = 0xe;
  REG_TPU3A_CH10_PARAM2 = 1;
  uVar1 = REG_HSRR0_A;
  REG_HSRR0_A = uVar1 & 0xffcf | 0x10;
  uVar1 = REG_CPR0_A;
  REG_CPR0_A = uVar1 & 0xffcf | 0x10;
  do {
    uVar1 = REG_HSRR0_A;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR1_A;
  REG_CFSR1_A = uVar1 & 0xfff | 0xf000;
  uVar1 = REG_HSQR0_A;
  REG_HSQR0_A = uVar1 & 0xff3f;
  REG_TPU3A_CH11_PARAM0 = 0xb;
  REG_TPU3A_CH11_PARAM1 = 0x100;
  REG_TPU3A_CH11_PARAM4 = 0xff00;
  uVar1 = REG_CPR0_A;
  REG_CPR0_A = uVar1 & 0xff3f | 0x40;
  uVar1 = REG_HSRR0_A;
  REG_HSRR0_A = uVar1 & 0xff3f | 0x80;
  do {
    uVar1 = REG_HSRR0_A;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR0_A;
  REG_CFSR0_A = uVar1 & 0xfff0 | 0xf;
  uVar1 = REG_HSQR0_A;
  REG_HSQR0_A = uVar1 & 0xfcff;
  REG_TPU3A_CH12_PARAM0 = 0xb;
  REG_TPU3A_CH12_PARAM1 = 0x100;
  REG_TPU3A_CH12_PARAM4 = 0xff00;
  uVar1 = REG_CPR0_A;
  REG_CPR0_A = uVar1 & 0xfcff | 0x100;
  uVar1 = REG_HSRR0_A;
  REG_HSRR0_A = uVar1 & 0xfcff | 0x200;
  do {
    uVar1 = REG_HSRR0_A;
  } while (uVar1 != 0);
  do {
    uVar1 = REG_HSRR0_A;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR0_A;
  REG_CFSR0_A = uVar1 & 0xff0f | 0xf0;
  uVar1 = REG_HSQR0_A;
  REG_HSQR0_A = uVar1 & 0xf3ff;
  REG_TPU3A_CH13_PARAM0 = 0xb;
  REG_TPU3A_CH13_PARAM1 = 0x100;
  REG_TPU3A_CH13_PARAM4 = 0xff00;
  uVar1 = REG_CPR0_A;
  REG_CPR0_A = uVar1 & 0xf3ff | 0x400;
  uVar1 = REG_HSRR0_A;
  REG_HSRR0_A = uVar1 & 0xf3ff | 0x800;
  do {
    uVar1 = REG_HSRR0_A;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR0_A;
  REG_CFSR0_A = uVar1 & 0xf0ff | 0xc00;
  uVar1 = REG_HSQR0_A;
  REG_HSQR0_A = uVar1 & 0xcfff;
  REG_TPU3A_CH14_PARAM0 = 0xb02;
  REG_TPU3A_CH14_PARAM4 = 0;
  REG_TPU3A_CH14_PARAM5 = 0xc001;
  uVar1 = REG_HSRR0_A;
  REG_HSRR0_A = uVar1 & 0xcfff | 0x2000;
  uVar1 = REG_CPR0_A;
  REG_CPR0_A = uVar1 & 0xcfff | 0x1000;
  do {
    uVar1 = REG_HSRR0_A;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR0_A;
  REG_CFSR0_A = uVar1 & 0xfff | 0xf000;
  uVar1 = REG_HSQR0_A;
  REG_HSQR0_A = uVar1 & 0x3fff;
  REG_TPU3A_CH15_PARAM0 = 0xb;
  REG_TPU3A_CH15_PARAM1 = 0x100;
  REG_TPU3A_CH15_PARAM4 = 0xff00;
  uVar1 = REG_HSRR0_A;
  REG_HSRR0_A = uVar1 & 0x3fff | 0x8000;
  uVar1 = REG_CPR0_A;
  REG_CPR0_A = uVar1 & 0x3fff | 0x4000;
  do {
    uVar1 = REG_HSRR0_A;
  } while (uVar1 != 0);
  uVar1 = REG_TICR_A;
  REG_TICR_A = uVar1 & 0xf8ff | 0x500;
  uVar1 = REG_TICR_A;
  REG_TICR_A = uVar1 & 0xff3f;
  uVar1 = REG_CISR_A;
  if (uVar1 != 0) {
    REG_CISR_A = 0;
  }
  REG_CIER_A = 0xff9f;
  return;
}



// Sets cylinder 1 injector pulse width

void set_injector1_time(ushort param_1)

{
  ushort uVar1;
  
  if (param_1 < 0x8000) {
    DAT_003f92fa = 0;
  }
  else {
    DAT_003f92fa = param_1 + 0x8001;
    param_1 = 0x7fff;
  }
  REG_TPU3B_CH1_PARAM1 = param_1;
  uVar1 = REG_HSRR1_B;
  REG_HSRR1_B = uVar1 & 0xfff3 | 4;
  do {
    uVar1 = REG_HSRR1_B;
  } while (uVar1 != 0);
  return;
}



// Sets cylinder 2 injector pulse width

void set_injector2_time(ushort param_1)

{
  ushort uVar1;
  
  if (param_1 < 0x8000) {
    DAT_003f92fc = 0;
  }
  else {
    DAT_003f92fc = param_1 + 0x8001;
    param_1 = 0x7fff;
  }
  REG_TPU3B_CH2_PARAM1 = param_1;
  uVar1 = REG_HSRR1_B;
  REG_HSRR1_B = uVar1 & 0xffcf | 0x10;
  do {
    uVar1 = REG_HSRR1_B;
  } while (uVar1 != 0);
  return;
}



// Sets cylinder 3 injector pulse width

void set_injector3_time(ushort param_1)

{
  ushort uVar1;
  
  if (param_1 < 0x8000) {
    DAT_003f92fe = 0;
  }
  else {
    DAT_003f92fe = param_1 + 0x8001;
    param_1 = 0x7fff;
  }
  REG_TPU3B_CH3_PARAM1 = param_1;
  uVar1 = REG_HSRR1_B;
  REG_HSRR1_B = uVar1 & 0xff3f | 0x40;
  do {
    uVar1 = REG_HSRR1_B;
  } while (uVar1 != 0);
  return;
}



// Sets cylinder 4 injector pulse width

void set_injector4_time(ushort param_1)

{
  ushort uVar1;
  
  if (param_1 < 0x8000) {
    DAT_003f9300 = 0;
  }
  else {
    DAT_003f9300 = param_1 + 0x8001;
    param_1 = 0x7fff;
  }
  REG_TPU3B_CH4_PARAM1 = param_1;
  uVar1 = REG_HSRR1_B;
  REG_HSRR1_B = uVar1 & 0xfcff | 0x100;
  do {
    uVar1 = REG_HSRR1_B;
  } while (uVar1 != 0);
  return;
}



// ISR: TPU-B channel 0 interrupt flag clear

void isr_tpu_b_ch0_clear(void)

{
  ushort uVar1;
  
  uVar1 = REG_CISR_B;
  REG_CISR_B = uVar1 & 0xfffe;
  return;
}



// ISR: Cylinder 1 injector pulse timing

void isr_injection_cyl1(void)

{
  ushort uVar1;
  
  uVar1 = REG_CISR_B;
  REG_CISR_B = uVar1 & 0xfffd;
  if ((DAT_003fe184 & 0x10) == 0) {
    uVar1 = REG_CIER_B;
    REG_CIER_B = uVar1 & 0xfbff;
    uVar1 = REG_CIER_B;
    REG_CIER_B = uVar1 | 2;
    inj_active_cyl[3] = true;
    DAT_003f8bc4 = inj_angle_2;
    if (DAT_003fe178 != 0) {
      DAT_003fe178 = DAT_003fe178 + -1;
    }
    if (DAT_003f92dc != 0) {
      REG_TPU3B_CH1_PARAM3 = DAT_003f92dc;
      uVar1 = REG_HSRR1_B;
      REG_HSRR1_B = uVar1 & 0xfff3 | 4;
      do {
        uVar1 = REG_HSRR1_B;
      } while (uVar1 != 0);
      DAT_003f92dc = 0;
    }
  }
  else {
    if (inj_active_cyl[3]) {
      inj_active_cyl[3] = false;
      DAT_003f8bcc = 0;
      uVar1 = REG_CISR_B;
      REG_CISR_B = uVar1 & 0xfbff;
      uVar1 = REG_CFSR1_B;
      REG_CFSR1_B = uVar1 & 0xf0ff;
      uVar1 = REG_CFSR1_B;
      REG_CFSR1_B = uVar1 & 0xf0ff | 0xc00;
      uVar1 = REG_HSQR0_B;
      REG_HSQR0_B = uVar1 & 0xffcf | 0x10;
      REG_TPU3B_CH10_PARAM0 = 0xb02;
      DAT_003f8bc4 = inj_angle_2;
      DAT_003f8bd0 = inj_angle_2 + 57;
      if (0x47 < DAT_003f8bd0) {
        DAT_003f8bd0 = inj_angle_2 - 15;
      }
      REG_TPU3B_CH10_PARAM4 = (ushort)(&PTR_DAT_00075ec8)[DAT_003f8bd0];
      REG_TPU3B_CH10_PARAM5 = 3000;
      uVar1 = REG_CPR0_B;
      REG_CPR0_B = uVar1 & 0xffcf | 0x30;
      uVar1 = REG_HSRR0_B;
      REG_HSRR0_B = uVar1 & 0xffcf | 0x20;
      do {
        uVar1 = REG_HSRR0_B;
      } while (uVar1 != 0);
      uVar1 = REG_CIER_B;
      REG_CIER_B = uVar1 | 0x400;
    }
    if (DAT_003f92fa != 0) {
      set_injector1_time(DAT_003f92fa);
    }
  }
  return;
}



// ISR: Cylinder 2 injector pulse timing

void isr_injection_cyl2(void)

{
  ushort uVar1;
  
  uVar1 = REG_CISR_B;
  REG_CISR_B = uVar1 & 0xfffb;
  if ((DAT_003fe184 & 0x20) == 0) {
    uVar1 = REG_CIER_B;
    REG_CIER_B = uVar1 & 0xf7ff;
    uVar1 = REG_CIER_B;
    REG_CIER_B = uVar1 | 4;
    inj_active_cyl[2] = true;
    DAT_003f8bc6 = inj_angle_2;
    if (DAT_003fe178 != 0) {
      DAT_003fe178 = DAT_003fe178 + -1;
    }
    if (DAT_003f92f4 != 0) {
      REG_TPU3B_CH2_PARAM3 = DAT_003f92f4;
      uVar1 = REG_HSRR1_B;
      REG_HSRR1_B = uVar1 & 0xffcf | 0x10;
      do {
        uVar1 = REG_HSRR1_B;
      } while (uVar1 != 0);
      DAT_003f92f4 = 0;
    }
  }
  else {
    if (inj_active_cyl[2]) {
      inj_active_cyl[2] = false;
      DAT_003f8bcd = 0;
      uVar1 = REG_CISR_B;
      REG_CISR_B = uVar1 & 0xf7ff;
      uVar1 = REG_CFSR1_B;
      REG_CFSR1_B = uVar1 & 0xfff;
      uVar1 = REG_CFSR1_B;
      REG_CFSR1_B = uVar1 & 0xfff | 0xc000;
      uVar1 = REG_HSQR0_B;
      REG_HSQR0_B = uVar1 & 0xff3f | 0x40;
      REG_TPU3B_CH11_PARAM0 = 0xb02;
      DAT_003f8bc6 = inj_angle_2;
      DAT_003f8bd0 = inj_angle_2 + 39;
      if (0x47 < DAT_003f8bd0) {
        DAT_003f8bd0 = inj_angle_2 - 33;
      }
      REG_TPU3B_CH11_PARAM4 = (ushort)(&PTR_DAT_00075ec8)[DAT_003f8bd0];
      REG_TPU3B_CH11_PARAM5 = 3000;
      uVar1 = REG_CPR0_B;
      REG_CPR0_B = uVar1 & 0xff3f | 0xc0;
      uVar1 = REG_HSRR0_B;
      REG_HSRR0_B = uVar1 & 0xff3f | 0x80;
      do {
        uVar1 = REG_HSRR1_B;
      } while (uVar1 != 0);
      uVar1 = REG_CIER_B;
      REG_CIER_B = uVar1 | 0x800;
    }
    if (DAT_003f92fc != 0) {
      set_injector2_time(DAT_003f92fc);
    }
  }
  return;
}



// ISR: Cylinder 3 injector pulse timing

void isr_injection_cyl3(void)

{
  ushort uVar1;
  
  uVar1 = REG_CISR_B;
  REG_CISR_B = uVar1 & 0xfff7;
  if ((DAT_003fe184 & 0x40) == 0) {
    uVar1 = REG_CIER_B;
    REG_CIER_B = uVar1 & 0xefff;
    uVar1 = REG_CIER_B;
    REG_CIER_B = uVar1 | 8;
    inj_active_cyl[1] = true;
    DAT_003f8bc8 = inj_angle_2;
    if (DAT_003fe178 != 0) {
      DAT_003fe178 = DAT_003fe178 + -1;
    }
    if (DAT_003f92f6 != 0) {
      REG_TPU3B_CH3_PARAM3 = DAT_003f92f6;
      uVar1 = REG_HSRR1_B;
      REG_HSRR1_B = uVar1 & 0xff3f | 0x40;
      do {
        uVar1 = REG_HSRR1_B;
      } while (uVar1 != 0);
      DAT_003f92f6 = 0;
    }
  }
  else {
    if (inj_active_cyl[1]) {
      inj_active_cyl[1] = false;
      DAT_003f8bce = 0;
      uVar1 = REG_CISR_B;
      REG_CISR_B = uVar1 & 0xefff;
      uVar1 = REG_CFSR0_B;
      REG_CFSR0_B = uVar1 & 0xfff0;
      uVar1 = REG_CFSR0_B;
      REG_CFSR0_B = uVar1 & 0xfff0 | 0xc;
      uVar1 = REG_HSQR0_B;
      REG_HSQR0_B = uVar1 & 0xfcff | 0x100;
      REG_TPU3B_CH12_PARAM0 = 0xb02;
      DAT_003f8bc8 = inj_angle_2;
      DAT_003f8bd0 = inj_angle_2 + 3;
      if (0x47 < DAT_003f8bd0) {
        DAT_003f8bd0 = inj_angle_2 - 69;
      }
      REG_TPU3B_CH12_PARAM4 = (ushort)(&PTR_DAT_00075ec8)[DAT_003f8bd0];
      REG_TPU3B_CH12_PARAM5 = 3000;
      uVar1 = REG_CPR0_B;
      REG_CPR0_B = uVar1 & 0xfcff | 0x300;
      uVar1 = REG_HSRR0_B;
      REG_HSRR0_B = uVar1 & 0xfcff | 0x200;
      do {
        uVar1 = REG_HSRR0_B;
      } while (uVar1 != 0);
      uVar1 = REG_CIER_B;
      REG_CIER_B = uVar1 | 0x1000;
    }
    if (DAT_003f92fe != 0) {
      set_injector3_time(DAT_003f92fe);
    }
  }
  return;
}



// ISR: Cylinder 4 injector pulse timing

void isr_injection_cyl4(void)

{
  ushort uVar1;
  
  uVar1 = REG_CISR_B;
  REG_CISR_B = uVar1 & 0xffef;
  if ((DAT_003fe184 & 0x80) == 0) {
    uVar1 = REG_CIER_B;
    REG_CIER_B = uVar1 & 0xdfff;
    uVar1 = REG_CIER_B;
    REG_CIER_B = uVar1 | 8;
    inj_active_cyl[0] = true;
    DAT_003f8bca = inj_angle_2;
    if (DAT_003fe178 != 0) {
      DAT_003fe178 = DAT_003fe178 + -1;
    }
    if (DAT_003f92f8 != 0) {
      REG_TPU3B_CH4_PARAM3 = DAT_003f92f8;
      uVar1 = REG_HSRR1_B;
      REG_HSRR1_B = uVar1 & 0xfcff | 0x100;
      do {
        uVar1 = REG_HSRR1_B;
      } while (uVar1 != 0);
      DAT_003f92f8 = 0;
    }
  }
  else {
    if (inj_active_cyl[0]) {
      inj_active_cyl[0] = false;
      DAT_003f8bcf = 0;
      uVar1 = REG_CISR_B;
      REG_CISR_B = uVar1 & 0xdfff;
      uVar1 = REG_CFSR0_B;
      REG_CFSR0_B = uVar1 & 0xff0f;
      uVar1 = REG_CFSR0_B;
      REG_CFSR0_B = uVar1 & 0xff0f | 0xc0;
      uVar1 = REG_HSQR0_B;
      REG_HSQR0_B = uVar1 & 0xf3ff | 0x400;
      REG_TPU3B_CH13_PARAM0 = 0xb02;
      DAT_003f8bca = inj_angle_2;
      DAT_003f8bd0 = inj_angle_2 + 21;
      if (0x47 < DAT_003f8bd0) {
        DAT_003f8bd0 = inj_angle_2 - 51;
      }
      REG_TPU3B_CH13_PARAM4 = (ushort)(&PTR_DAT_00075ec8)[DAT_003f8bd0];
      REG_TPU3B_CH13_PARAM5 = 3000;
      uVar1 = REG_CPR0_B;
      REG_CPR0_B = uVar1 & 0xf3ff | 0xc00;
      uVar1 = REG_HSRR0_B;
      REG_HSRR0_B = uVar1 & 0xf3ff | 0x800;
      do {
        uVar1 = REG_HSRR0_B;
      } while (uVar1 != 0);
      uVar1 = REG_CIER_B;
      REG_CIER_B = uVar1 | 0x2000;
    }
    if (DAT_003f9300 != 0) {
      set_injector4_time(DAT_003f9300);
    }
  }
  return;
}



// ISR: TPU-B channel 5 interrupt flag clear

void isr_tpu_b_ch5_clear(void)

{
  ushort uVar1;
  
  uVar1 = REG_CISR_B;
  REG_CISR_B = uVar1 & 0xffdf;
  return;
}



// ISR: TPU-B channel 6 interrupt flag clear

void isr_tpu_b_ch6_clear(void)

{
  ushort uVar1;
  
  uVar1 = REG_CISR_B;
  REG_CISR_B = uVar1 & 0xffbf;
  return;
}



// ISR: Variable Valve Timing solenoid PWM output

void isr_vvt_pwm(void)

{
  ushort uVar1;
  
  uVar1 = REG_CISR_B;
  REG_CISR_B = uVar1 & 0xff7f;
  return;
}



// ISR: TPU-B channel 8 interrupt flag clear

void isr_tpu_b_ch8_clear(void)

{
  ushort uVar1;
  
  uVar1 = REG_CISR_B;
  REG_CISR_B = uVar1 & 0xfeff;
  return;
}



// ISR: Variable Valve Lift solenoid PWM output

void isr_vvl_pwm(void)

{
  ushort uVar1;
  
  uVar1 = REG_CISR_B;
  REG_CISR_B = uVar1 & 0xfdff;
  return;
}



// ISR: Cylinder 1 injector output completion

void isr_injection_output_cyl1(void)

{
  uint uVar1;
  ushort uVar2;
  uint uVar3;
  
  uVar2 = REG_CISR_B;
  REG_CISR_B = uVar2 & 0xfbff;
  uVar1 = (int)((int)(short)DAT_003f8bc4 & 0xff00U) >> 8;
  uVar2 = DAT_003f8bc4 & 0xff;
  DAT_003f8bcc = DAT_003f8bcc + 1;
  if (DAT_003f8bcc < 2) {
    DAT_003f8bd2 = DAT_003f8bd2 + 1;
    if (engine_is_running) {
      if (((((revlimit_flags & 0x10) == 0) && ((misfire_flags & 0x40) == 0)) &&
          (obd_P0351_debounce_count != 0)) && ((DAT_003f8bd2 < tc_fuelcut || (tc_fuelcut == 0xff))))
      {
        set_injector1_time(inj_time_final_2);
      }
      else {
        if (tc_fuelcut <= DAT_003f8bd2) {
          DAT_003f8bd2 = 0;
        }
        set_injector1_time(200);
      }
      if ((short)(DAT_003f8bc4 & 0xff) < (short)inj_angle_2) {
        uVar3 = uVar1 + 0x80;
        if ((uVar1 + 0x80 & 0xff) < 0x80) {
          uVar2 = uVar2 + 1;
          uVar3 = uVar1 + 0x100;
        }
      }
      else if ((short)inj_angle_2 < (short)(DAT_003f8bc4 & 0xff)) {
        uVar3 = uVar1 - 0x80;
        if ((uVar1 - 0x80 & 0xff) < 0x80) {
          uVar2 = uVar2 - 1;
          uVar3 = uVar1;
        }
      }
      else {
        uVar3 = 0x80;
      }
      DAT_003f8bc4 = (ushort)((uVar3 & 0xff) << 8) | uVar2 & 0xff;
    }
  }
  else {
    DAT_003f8bcc = 0;
    DAT_003f8bd0 = (DAT_003f8bc4 & 0xff) + 0x39;
    if (0x47 < DAT_003f8bd0) {
      DAT_003f8bd0 = (DAT_003f8bc4 & 0xff) - 0xf;
    }
    Ram003045a8 = ((int)(short)DAT_003f8bc4 & 0xff00U) * 0x10000 +
                  ((uint)(&PTR_DAT_00075ec8)[(short)DAT_003f8bd0] & 0xff) * 0x10000 + 3000;
    uVar2 = REG_HSRR0_B;
    REG_HSRR0_B = uVar2 & 0xffcf | 0x20;
    do {
      uVar2 = REG_HSRR0_B;
    } while (uVar2 != 0);
  }
  return;
}



// ISR: Cylinder 2 injector output completion

void isr_injection_output_cyl2(void)

{
  uint uVar1;
  ushort uVar2;
  uint uVar3;
  
  uVar2 = REG_CISR_B;
  REG_CISR_B = uVar2 & 0xf7ff;
  uVar1 = (int)((int)(short)DAT_003f8bc6 & 0xff00U) >> 8;
  uVar2 = DAT_003f8bc6 & 0xff;
  DAT_003f8bcd = DAT_003f8bcd + 1;
  if (DAT_003f8bcd < 2) {
    DAT_003f8bd2 = DAT_003f8bd2 + 1;
    if (engine_is_running) {
      if (((((revlimit_flags & 0x10) == 0) && ((misfire_flags & 0x80) == 0)) &&
          (obd_P0352_debounce_count != 0)) && ((DAT_003f8bd2 < tc_fuelcut || (tc_fuelcut == 0xff))))
      {
        set_injector2_time(inj_time_final_2);
        DAT_003f9302 = inj_time_final_2;
      }
      else {
        if (tc_fuelcut <= DAT_003f8bd2) {
          DAT_003f8bd2 = 0;
        }
        set_injector2_time(200);
        DAT_003f9302 = 200;
      }
      if ((short)(DAT_003f8bc6 & 0xff) < (short)inj_angle_2) {
        uVar3 = uVar1 + 0x80;
        if ((uVar1 + 0x80 & 0xff) < 0x80) {
          uVar2 = uVar2 + 1;
          uVar3 = uVar1 + 0x100;
        }
      }
      else if ((short)inj_angle_2 < (short)(DAT_003f8bc6 & 0xff)) {
        uVar3 = uVar1 - 0x80;
        if ((uVar1 - 0x80 & 0xff) < 0x80) {
          uVar2 = uVar2 - 1;
          uVar3 = uVar1;
        }
      }
      else {
        uVar3 = 0x80;
      }
      DAT_003f8bc6 = (ushort)((uVar3 & 0xff) << 8) | uVar2 & 0xff;
    }
  }
  else {
    DAT_003f8bcd = 0;
    DAT_003f8bd0 = (DAT_003f8bc6 & 0xff) + 0x27;
    if (0x47 < DAT_003f8bd0) {
      DAT_003f8bd0 = (DAT_003f8bc6 & 0xff) - 0x21;
    }
    Ram003045b8 = ((int)(short)DAT_003f8bc6 & 0xff00U) * 0x10000 +
                  ((uint)(&PTR_DAT_00075ec8)[(short)DAT_003f8bd0] & 0xff) * 0x10000 + 3000;
    uVar2 = REG_HSRR0_B;
    REG_HSRR0_B = uVar2 & 0xff3f | 0x80;
    do {
      uVar2 = REG_HSRR0_B;
    } while (uVar2 != 0);
  }
  return;
}



// ISR: Cylinder 3 injector output completion

void isr_injection_output_cyl3(void)

{
  uint uVar1;
  ushort uVar2;
  uint uVar3;
  
  uVar2 = REG_CISR_B;
  REG_CISR_B = uVar2 & 0xefff;
  uVar1 = (int)((int)(short)DAT_003f8bc8 & 0xff00U) >> 8;
  uVar2 = DAT_003f8bc8 & 0xff;
  DAT_003f8bce = DAT_003f8bce + 1;
  if (DAT_003f8bce < 2) {
    DAT_003f8bd2 = DAT_003f8bd2 + 1;
    if (engine_is_running) {
      if (((((revlimit_flags & 0x10) == 0) && ((misfire_flags & 0x100) == 0)) &&
          (obd_P0353_debounce_count != 0)) && ((DAT_003f8bd2 < tc_fuelcut || (tc_fuelcut == 0xff))))
      {
        set_injector3_time(inj_time_final_2);
      }
      else {
        if (tc_fuelcut <= DAT_003f8bd2) {
          DAT_003f8bd2 = 0;
        }
        set_injector3_time(200);
      }
      if ((short)(DAT_003f8bc8 & 0xff) < (short)inj_angle_2) {
        uVar3 = uVar1 + 0x80;
        if ((uVar1 + 0x80 & 0xff) < 0x80) {
          uVar2 = uVar2 + 1;
          uVar3 = uVar1 + 0x100;
        }
      }
      else if ((short)inj_angle_2 < (short)(DAT_003f8bc8 & 0xff)) {
        uVar3 = uVar1 - 0x80;
        if ((uVar1 - 0x80 & 0xff) < 0x80) {
          uVar2 = uVar2 - 1;
          uVar3 = uVar1;
        }
      }
      else {
        uVar3 = 0x80;
      }
      DAT_003f8bc8 = (ushort)((uVar3 & 0xff) << 8) | uVar2 & 0xff;
    }
  }
  else {
    DAT_003f8bce = 0;
    DAT_003f8bd0 = (DAT_003f8bc8 & 0xff) + 3;
    if (0x47 < DAT_003f8bd0) {
      DAT_003f8bd0 = (DAT_003f8bc8 & 0xff) - 0x45;
    }
    Ram003045c8 = ((int)(short)DAT_003f8bc8 & 0xff00U) * 0x10000 +
                  ((uint)(&PTR_DAT_00075ec8)[(short)DAT_003f8bd0] & 0xff) * 0x10000 + 3000;
    uVar2 = REG_HSRR0_B;
    REG_HSRR0_B = uVar2 & 0xfcff | 0x200;
    do {
      uVar2 = REG_HSRR0_B;
    } while (uVar2 != 0);
  }
  return;
}



// ISR: Cylinder 4 injector output completion

void isr_injection_output_cyl4(void)

{
  uint uVar1;
  ushort uVar2;
  uint uVar3;
  
  uVar2 = REG_CISR_B;
  REG_CISR_B = uVar2 & 0xdfff;
  uVar1 = (int)((int)(short)DAT_003f8bca & 0xff00U) >> 8;
  uVar2 = DAT_003f8bca & 0xff;
  DAT_003f8bcf = DAT_003f8bcf + 1;
  if (DAT_003f8bcf < 2) {
    DAT_003f8bd2 = DAT_003f8bd2 + 1;
    if (engine_is_running) {
      if (((((revlimit_flags & 0x10) == 0) && ((misfire_flags & 0x200) == 0)) &&
          (obd_P0354_debounce_count != 0)) && ((DAT_003f8bd2 < tc_fuelcut || (tc_fuelcut == 0xff))))
      {
        set_injector4_time(inj_time_final_2);
      }
      else {
        if (tc_fuelcut <= DAT_003f8bd2) {
          DAT_003f8bd2 = 0;
        }
        set_injector4_time(200);
      }
      if ((short)(DAT_003f8bca & 0xff) < (short)inj_angle_2) {
        uVar3 = uVar1 + 0x80;
        if ((uVar1 + 0x80 & 0xff) < 0x80) {
          uVar2 = uVar2 + 1;
          uVar3 = uVar1 + 0x100;
        }
      }
      else if ((short)inj_angle_2 < (short)(DAT_003f8bca & 0xff)) {
        uVar3 = uVar1 - 0x80;
        if ((uVar1 - 0x80 & 0xff) < 0x80) {
          uVar2 = uVar2 - 1;
          uVar3 = uVar1;
        }
      }
      else {
        uVar3 = 0x80;
      }
      DAT_003f8bca = (ushort)((uVar3 & 0xff) << 8) | uVar2 & 0xff;
    }
  }
  else {
    DAT_003f8bcf = 0;
    DAT_003f8bd0 = (DAT_003f8bca & 0xff) + 0x15;
    if (0x47 < DAT_003f8bd0) {
      DAT_003f8bd0 = (DAT_003f8bca & 0xff) - 0x33;
    }
    Ram003045d8 = ((int)(short)DAT_003f8bca & 0xff00U) * 0x10000 +
                  ((uint)(&PTR_DAT_00075ec8)[(short)DAT_003f8bd0] & 0xff) * 0x10000 + 3000;
    uVar2 = REG_HSRR0_B;
    REG_HSRR0_B = uVar2 & 0xf3ff | 0x800;
    do {
      uVar2 = REG_HSRR0_B;
    } while (uVar2 != 0);
  }
  return;
}



// ISR: TPU-B channel 14 interrupt flag clear

void isr_tpu_b_ch14_clear(void)

{
  ushort uVar1;
  
  uVar1 = REG_CISR_B;
  REG_CISR_B = uVar1 & 0xbfff;
  return;
}



// ISR: Ignition feedback signal for coil diagnostics

void isr_ign_feedback(void)

{
  ushort uVar1;
  
  uVar1 = REG_CISR_B;
  REG_CISR_B = uVar1 & 0x7fff;
  if (ign_feedback_coil_id == 1) {
    ign_feedback_pending_flags = ign_feedback_pending_flags & 0xfe;
  }
  else if (ign_feedback_coil_id == 2) {
    ign_feedback_pending_flags = ign_feedback_pending_flags & 0xfd;
  }
  else if (ign_feedback_coil_id == 3) {
    ign_feedback_pending_flags = ign_feedback_pending_flags & 0xfb;
  }
  else if (ign_feedback_coil_id == 4) {
    ign_feedback_pending_flags = ign_feedback_pending_flags & 0xf7;
  }
  return;
}



// Schedules injection events based on engine position and load

void schedule_injection(void)

{
  ushort uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  DAT_003f8bd0 = inj_angle_2 + 57;
  if (0x47 < DAT_003f8bd0) {
    DAT_003f8bd0 = inj_angle_2 - 15;
  }
  iVar3 = (int)DAT_003f8bd0;
  DAT_003f8bc0 = (char)(&PTR_DAT_00075ec8)[iVar3];
  DAT_003f8bd0 = inj_angle_2 + 39;
  if (0x47 < DAT_003f8bd0) {
    DAT_003f8bd0 = inj_angle_2 - 33;
  }
  iVar4 = (int)DAT_003f8bd0;
  DAT_003f8bc1 = (char)(&PTR_DAT_00075ec8)[iVar4];
  DAT_003f8bd0 = inj_angle_2 + 3;
  if (0x47 < DAT_003f8bd0) {
    DAT_003f8bd0 = inj_angle_2 - 69;
  }
  iVar2 = (int)DAT_003f8bd0;
  DAT_003f8bc2 = (char)(&PTR_DAT_00075ec8)[iVar2];
  DAT_003f8bd0 = inj_angle_2 + 21;
  if (0x47 < DAT_003f8bd0) {
    DAT_003f8bd0 = inj_angle_2 - 51;
  }
  DAT_003f8bc3 = (char)(&PTR_DAT_00075ec8)[DAT_003f8bd0];
  if (((DAT_003fe18a == (char)(&PTR_DAT_00075ec8)[iVar3]) && ((DAT_003fe184 & 0x10) == 0)) &&
     (DAT_003fe178 == 0)) {
    if (0x7fff < inj_time_final_2) {
      DAT_003f92dc = inj_time_final_2 + 32769;
      inj_time_final_2 = 32767;
    }
    REG_TPU3B_CH1_PARAM1 = inj_time_final_2;
    uVar1 = REG_HSRR1_B;
    REG_HSRR1_B = uVar1 & 0xfff3 | 4;
    do {
      uVar1 = REG_HSRR1_B;
    } while (uVar1 != 0);
    if (engine_is_running) {
      DAT_003fe184 = DAT_003fe184 | 0x10;
    }
  }
  else if (((DAT_003fe18a == (char)(&PTR_DAT_00075ec8)[iVar4]) && ((DAT_003fe184 & 0x20) == 0)) &&
          (DAT_003fe178 == 0)) {
    if (0x7fff < inj_time_final_2) {
      DAT_003f92f4 = inj_time_final_2 + 32769;
      inj_time_final_2 = 32767;
    }
    REG_TPU3B_CH2_PARAM1 = inj_time_final_2;
    uVar1 = REG_HSRR1_B;
    REG_HSRR1_B = uVar1 & 0xffcf | 0x10;
    do {
      uVar1 = REG_HSRR1_B;
    } while (uVar1 != 0);
    if (engine_is_running) {
      DAT_003fe184 = DAT_003fe184 | 0x20;
    }
  }
  else if (((DAT_003fe18a == (char)(&PTR_DAT_00075ec8)[iVar2]) && ((DAT_003fe184 & 0x40) == 0)) &&
          (DAT_003fe178 == 0)) {
    if (0x7fff < inj_time_final_2) {
      DAT_003f92f6 = inj_time_final_2 + 32769;
      inj_time_final_2 = 32767;
    }
    REG_TPU3B_CH3_PARAM1 = inj_time_final_2;
    uVar1 = REG_HSRR1_B;
    REG_HSRR1_B = uVar1 & 0xff3f | 0x40;
    do {
      uVar1 = REG_HSRR1_B;
    } while (uVar1 != 0);
    if (engine_is_running) {
      DAT_003fe184 = DAT_003fe184 | 0x40;
    }
  }
  else if (((DAT_003fe18a == (char)(&PTR_DAT_00075ec8)[DAT_003f8bd0]) &&
           ((DAT_003fe184 & 0x80) == 0)) && (DAT_003fe178 == 0)) {
    if (0x7fff < inj_time_final_2) {
      DAT_003f92f8 = inj_time_final_2 + 32769;
      inj_time_final_2 = 32767;
    }
    REG_TPU3B_CH4_PARAM1 = inj_time_final_2;
    uVar1 = REG_HSRR1_B;
    REG_HSRR1_B = uVar1 & 0xfcff | 0x100;
    do {
      uVar1 = REG_HSRR1_B;
    } while (uVar1 != 0);
    if (engine_is_running) {
      DAT_003fe184 = DAT_003fe184 | 0x80;
    }
  }
  return;
}



// ISR: TPU-B interrupt dispatcher - routes to channel-specific handlers

undefined8 isr_tpu_b(undefined4 param_1,undefined4 param_2)

{
  ushort uVar1;
  uint uVar2;
  ushort uVar3;
  undefined4 in_MSR;
  undefined4 in_SRR1;
  
  uVar1 = REG_CISR_B;
  uVar3 = REG_CIER_B;
  uVar1 = uVar1 & uVar3;
  while( true ) {
    if (uVar1 == 0) break;
    if ((uVar1 & 1) == 0) {
      if ((uVar1 & 2) == 0) {
        if ((uVar1 & 4) == 0) {
          if ((uVar1 & 8) == 0) {
            if ((uVar1 & 0x10) == 0) {
              if ((uVar1 & 0x20) == 0) {
                if ((uVar1 & 0x40) == 0) {
                  if ((uVar1 & 0x80) == 0) {
                    if ((uVar1 & 0x100) == 0) {
                      if ((uVar1 & 0x200) == 0) {
                        if ((uVar1 & 0x400) == 0) {
                          if ((uVar1 & 0x800) == 0) {
                            if ((uVar1 & 0x1000) == 0) {
                              if ((uVar1 & 0x2000) == 0) {
                                if ((uVar1 & 0x4000) == 0) {
                                  if ((uVar1 & 0x8000) != 0) {
                                    isr_ign_feedback();
                                  }
                                }
                                else {
                                  isr_tpu_b_ch14_clear();
                                }
                              }
                              else {
                                isr_injection_output_cyl4();
                              }
                            }
                            else {
                              isr_injection_output_cyl3();
                            }
                          }
                          else {
                            isr_injection_output_cyl2();
                          }
                        }
                        else {
                          isr_injection_output_cyl1();
                        }
                      }
                      else {
                        isr_vvl_pwm();
                      }
                    }
                    else {
                      isr_tpu_b_ch8_clear();
                    }
                  }
                  else {
                    isr_vvt_pwm();
                  }
                }
                else {
                  isr_tpu_b_ch6_clear();
                }
              }
              else {
                isr_tpu_b_ch5_clear();
              }
            }
            else {
              isr_injection_cyl4();
            }
          }
          else {
            isr_injection_cyl3();
          }
        }
        else {
          isr_injection_cyl2();
        }
      }
      else {
        isr_injection_cyl1();
      }
    }
    else {
      isr_tpu_b_ch0_clear();
    }
    uVar1 = REG_CISR_B;
    uVar3 = REG_CIER_B;
    uVar1 = uVar1 & uVar3;
  }
  uVar2 = REG_SISR2;
  REG_SISR2 = uVar2 & 0xff7fffff | 0x800000;
  returnFromInterrupt(in_MSR,in_SRR1);
  return CONCAT44(param_1,param_2);
}



// Initializes MIOS (Modular I/O System) for PWM and I/O

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
  REG_MPWMSM1_SCR = uVar1 & 0xff00 | 0xc0;
  uVar1 = REG_MPWMSM1_SCR;
  REG_MPWMSM1_SCR = uVar1 & 0xefff;
  uVar1 = REG_MPWMSM1_SCR;
  REG_MPWMSM1_SCR = uVar1 & 0xbfff | 0x4000;
  uVar1 = REG_MPWMSM1_SCR;
  REG_MPWMSM1_SCR = uVar1 & 0xf7ff;
  uVar1 = REG_MPWMSM1_SCR;
  REG_MPWMSM1_SCR = uVar1 & 0xfbff | 0x400;
  REG_MPWMSM1_PERR = CAL_evap_period;
  REG_MPWMSM1_PULR = 0;
  uVar1 = REG_MPWMSM2_SCR;
  REG_MPWMSM2_SCR = uVar1 & 0xff00 | 0xec;
  uVar1 = REG_MPWMSM2_SCR;
  REG_MPWMSM2_SCR = uVar1 & 0xefff;
  uVar1 = REG_MPWMSM2_SCR;
  REG_MPWMSM2_SCR = uVar1 & 0xbfff | 0x4000;
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
  REG_MPWMSM18_PERR = CAL_tps_period;
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
  REG_MPIOSMDDR = 0x7e3f;
  uVar1 = REG_MPIOSMDR;
  REG_MPIOSMDR = uVar1 & 0xbfff;
  uVar1 = REG_MPIOSMDDR;
  REG_MPIOSMDDR = uVar1 | 0x4000;
  uVar1 = REG_MPIOSMDDR;
  REG_MPIOSMDDR = uVar1 & 0xff7f;
  return;
}



// Initializes QSM (Queued Serial Module) for SPI communication

void init_qsm(void)

{
  ushort uVar1;
  
  REG_QSMCMMCR = 0x80;
  REG_QSPI_IL = 0;
  REG_PQSPAR = 0x7b;
  REG_DDRQST = 0x7e;
  uVar1 = REG_PORTQS;
  REG_PORTQS = uVar1 & 0xffbf | 0x40;
  uVar1 = REG_PORTQS;
  REG_PORTQS = uVar1 & 0xffdf | 0x20;
  uVar1 = REG_PORTQS;
  REG_PORTQS = uVar1 & 0xffef | 0x10;
  uVar1 = REG_PORTQS;
  REG_PORTQS = uVar1 & 0xfff7;
  uVar1 = REG_PORTQS;
  REG_PORTQS = uVar1 & 0xfffd | 2;
  uVar1 = REG_PORTQS;
  REG_PORTQS = uVar1 & 0xfffb | 4;
  REG_SPCR0 = 0xa11a;
  REG_SPCR1 = 0x7f03;
  REG_SPCR2 = 0x100;
  REG_SPCR3 = 0;
  uVar1 = REG_QDSCI_IL;
  REG_QDSCI_IL = uVar1 & 0xe0ff | 0x1800;
  REG_SCC1R0 = 0x78;
  REG_SCC1R1 = 0xc;
  return;
}



// SPI PCS1: Daisy chain TLE6220 → TLE6220 → TLE6220 → L9822E

void spi_pcs1(void)

{
  ushort uVar1;
  byte bVar2;
  
  REG_SPCR0 = 0xa10a;
  REG_SPCR1 = 0x1a03;
  REG_SPCR2 = 0x100;
  REG_SPCR3 = 0;
  REG_TRANRAM0 = ~(ushort)L9822E_outputs & 0xff;
  REG_TRANRAM1 = 0;
  REG_TRANRAM2 = 0;
  REG_TRANRAM3 = 0;
  REG_COMDRAM0 = 0xbc;
  REG_COMDRAM1 = 0xbc;
  REG_COMDRAM2 = 0xbc;
  REG_COMDRAM3 = 0x3c;
  uVar1 = REG_SPCR2;
  REG_SPCR2 = uVar1 & 0xffe0;
  uVar1 = REG_SPCR2;
  REG_SPCR2 = uVar1 & 0xe0ff | 0x300;
  uVar1 = REG_SPCR1;
  REG_SPCR1 = uVar1 & 0x7fff | 0x8000;
  do {
    bVar2 = REG_SPSR;
  } while (-1 < (char)bVar2);
  bVar2 = REG_SPSR;
  REG_SPSR = bVar2 & 0x7f;
  uVar1 = REG_RECRAM0;
  DAT_003f9304 = ~(byte)uVar1;
  uVar1 = REG_RECRAM1;
  DAT_003f8000 = (char)uVar1;
  uVar1 = REG_RECRAM2;
  DAT_003f8001 = (char)uVar1;
  uVar1 = REG_RECRAM3;
  DAT_003f8002 = (char)uVar1;
  DAT_003f930b = DAT_003f8bdd;
  DAT_003f8bdd = DAT_003f92c4;
  return;
}



// Sends command to knock sensor interface via SPI

void send_spi_pcs2(ushort param_1)

{
  ushort uVar1;
  byte bVar2;
  
  REG_SPCR0 = 0xa014;
  REG_SPCR1 = 0x7f01;
  REG_SPCR2 = 0x100;
  REG_SPCR3 = 0;
  REG_TRANRAM0 = param_1 & 0xff;
  REG_COMDRAM0 = 0x3a;
  uVar1 = REG_SPCR2;
  REG_SPCR2 = uVar1 & 0xffe0;
  uVar1 = REG_SPCR2;
  REG_SPCR2 = uVar1 & 0xe0ff;
  uVar1 = REG_SPCR1;
  REG_SPCR1 = uVar1 & 0x7fff | 0x8000;
  do {
    bVar2 = REG_SPSR;
  } while (-1 < (char)bVar2);
  bVar2 = REG_SPSR;
  REG_SPSR = bVar2 & 0x7f;
  return;
}



// SPI PCS3: TLE6209 throttle motor H-bridge

void spi_pcs3(void)

{
  ushort uVar1;
  byte bVar2;
  
  REG_SPCR0 = 0xa10a;
  REG_SPCR1 = 0x1a03;
  REG_SPCR2 = 0x100;
  REG_SPCR3 = 0;
  REG_TRANRAM0 = (ushort)DAT_003f8004;
  REG_COMDRAM0 = 0x36;
  uVar1 = REG_SPCR2;
  REG_SPCR2 = uVar1 & 0xffe0;
  uVar1 = REG_SPCR2;
  REG_SPCR2 = uVar1 & 0xe0ff;
  uVar1 = REG_SPCR1;
  REG_SPCR1 = uVar1 & 0x7fff | 0x8000;
  do {
    bVar2 = REG_SPSR;
  } while (-1 < (char)bVar2);
  bVar2 = REG_SPSR;
  REG_SPSR = bVar2 & 0x7f;
  uVar1 = REG_RECRAM0;
  uVar1 = REG_RECRAM0;
  if ((uVar1 == 0xff) || (uVar1 = REG_RECRAM0, uVar1 == 2)) {
    if (DAT_003fd00a < 9) {
      if (DAT_003fd00a == 0) {
        DAT_003f8004 = 0x80;
        DAT_003f8bd8 = 0;
      }
      else {
        DAT_003f8004 = 0x80;
      }
    }
    else {
      DAT_003f8004 = 0x81;
    }
  }
  else if (DAT_003f8bd8 == 0) {
    DAT_003f8bd8 = 1;
    DAT_003fd00a = 0x14;
    DAT_003f8004 = 0x81;
  }
  else {
    if (DAT_003fd00a < 9) {
      DAT_003f8004 = 0x80;
    }
    else {
      DAT_003f8004 = 0x81;
    }
    if (DAT_003fd00a == 0) {
      uVar1 = REG_RECRAM0;
      DAT_003f8bdc = (byte)uVar1;
      DAT_003f8bd8 = 0;
    }
  }
  if (DAT_003f8bdc != 0) {
    DAT_003f930c = DAT_003f930c | DAT_003f8bdc;
    DAT_003f8bdc = 0;
  }
  uVar1 = REG_RECRAM0;
  DAT_003fd00c = (char)uVar1;
  return;
}



// SPI PCS0: SC33394FDH power supply status (read but unused)

void spi_pcs0(void)

{
  ushort uVar1;
  byte bVar2;
  
  REG_SPCR0 = 0x800a;
  REG_SPCR1 = 0x1a03;
  REG_SPCR2 = 0x100;
  REG_SPCR3 = 0;
  REG_TRANRAM0 = 0xfe00;
  REG_COMDRAM0 = 0x7f;
  uVar1 = REG_SPCR2;
  REG_SPCR2 = uVar1 & 0xffe0;
  uVar1 = REG_SPCR2;
  REG_SPCR2 = uVar1 & 0xe0ff;
  uVar1 = REG_SPCR1;
  REG_SPCR1 = uVar1 & 0x7fff | 0x8000;
  do {
    bVar2 = REG_SPSR;
  } while (-1 < (char)bVar2);
  bVar2 = REG_SPSR;
  REG_SPSR = bVar2 & 0x7f;
  DAT_003f930e = REG_RECRAM0;
  return;
}



// WARNING: Inlined function: push_27to31
// WARNING: Inlined function: pop_27to31
// Executes EEPROM read/write command via SPI

void eeprom_command(char *in,char *out,uint size)

{
  ushort uVar1;
  byte bVar2;
  uint uVar3;
  uint uVar4;
  
  uVar4 = size - 1 & 0xff;
  eeprom_cs_assert();
  REG_SPCR0 = 0xa005;
  REG_SPCR1 = 0x1a03;
  REG_SPCR2 = 0;
  REG_SPCR3 = 0;
  for (uVar3 = 0; (uVar3 & 0xff) < uVar4; uVar3 = uVar3 + 1) {
    (&REG_TRANRAM0)[uVar3 & 0xff] = (ushort)(byte)in[uVar3 & 0xff];
    (&REG_COMDRAM0)[uVar3 & 0xff] = 0xbe;
  }
  (&REG_TRANRAM0)[uVar4] = (ushort)(byte)in[uVar4];
  (&REG_COMDRAM0)[uVar4] = 0x3e;
  uVar1 = REG_SPCR2;
  REG_SPCR2 = uVar1 & 0xffe0;
  uVar1 = REG_SPCR2;
  REG_SPCR2 = (ushort)(uVar4 << 8) & 0x1f00 | uVar1 & 0xe0ff;
  uVar1 = REG_SPCR1;
  REG_SPCR1 = uVar1 & 0x7fff | 0x8000;
  do {
    bVar2 = REG_SPSR;
  } while (-1 < (char)bVar2);
  bVar2 = REG_SPSR;
  REG_SPSR = bVar2 & 0x7f;
  for (uVar4 = 0; (uVar4 & 0xff) < (size & 0xff); uVar4 = uVar4 + 1) {
    out[uVar4 & 0xff] = (char)(&REG_RECRAM0)[uVar4 & 0xff];
  }
  eeprom_cs_deassert();
  return;
}



// Copies calibration data from ROM to RAM for runtime access

void copyCAL2RAM(void)

{
  undefined2 *puVar1;
  undefined2 uVar2;
  ushort uVar3;
  undefined2 *puVar4;
  undefined2 *puVar5;
  int iVar6;
  
  watchdog_retrigger();
  puVar5 = (undefined2 *)0x3f9322;
  puVar4 = (undefined2 *)&DAT_0000fffe;
  iVar6 = 0xf25;
  do {
    puVar1 = puVar4 + 1;
    puVar4 = puVar4 + 2;
    uVar2 = *puVar4;
    puVar5[1] = *puVar1;
    puVar5 = puVar5 + 2;
    *puVar5 = uVar2;
    iVar6 = iVar6 + -1;
  } while (iVar6 != 0);
  ecu_CRC_computed = CRC16(&DAT_003f9344,0x3c72);
  if ((((CAL_ecu_unlock_magic[0] == 'W') && (CAL_ecu_unlock_magic[1] == 'T')) &&
      (CAL_ecu_unlock_magic[2] == 'F')) && (CAL_ecu_unlock_magic[3] == '?')) {
    dev_unlocked = true;
  }
  else {
    dev_unlocked = false;
  }
  init_qadc_a();
  init_qadc_b();
  init_can_a();
  init_can_b();
  init_tpu();
  init_mios();
  init_pit();
  init_qsm();
  DAT_003f931c = stub_return_0x102();
  DAT_003f931e = stub_return_zero_1();
  DAT_003f9320 = stub_return_zero_2();
  uVar3 = REG_MPWMSM16_SCR;
  REG_MPWMSM16_SCR = uVar3 & 0xf7ff | 0x800;
  hc08_init();
  init_tps_state();
  return;
}



// Initializes TPU-B: injection timing signals, VVT/VVL PWM outputs

void init_tpu_b(void)

{
  ushort uVar1;
  
  REG_TPUMCR_B = 0x480;
  REG_TPUMCR2_B = 0;
  REG_TPUMCR3_B = 0x53;
  REG_CPR1_B = 0;
  REG_CPR0_B = 0;
  REG_CFSR3_B = 0;
  REG_CFSR2_B = 0;
  REG_CFSR1_B = 0;
  REG_CFSR0_B = 0;
  uVar1 = REG_CFSR3_B;
  REG_CFSR3_B = uVar1 & 0xfff0 | 0xb;
  REG_TPU3B_CH0_PARAM0 = 4;
  REG_TPU3B_CH0_PARAM1 = 0x121;
  REG_TPU3B_CH0_PARAM3 = 0xff44;
  uVar1 = REG_HSQR1_B;
  REG_HSQR1_B = uVar1 & 0xfffc | 3;
  uVar1 = REG_CPR1_B;
  REG_CPR1_B = uVar1 & 0xfffc | 3;
  uVar1 = REG_HSRR1_B;
  REG_HSRR1_B = uVar1 & 0xfffc | 1;
  do {
    uVar1 = REG_HSRR1_B;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR3_B;
  REG_CFSR3_B = uVar1 & 0xff0f | 0xe0;
  uVar1 = REG_HSQR1_B;
  REG_HSQR1_B = uVar1 & 0xfff3;
  REG_TPU3B_CH1_PARAM0 = 0x89;
  REG_TPU3B_CH1_PARAM1 = 10;
  REG_TPU3B_CH1_PARAM2 = 0xec;
  uVar1 = REG_CPR1_B;
  REG_CPR1_B = uVar1 & 0xfff3 | 0xc;
  uVar1 = REG_HSRR1_B;
  REG_HSRR1_B = uVar1 & 0xfff3 | 4;
  do {
    uVar1 = REG_HSRR1_B;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR3_B;
  REG_CFSR3_B = uVar1 & 0xf0ff | 0xe00;
  uVar1 = REG_HSQR1_B;
  REG_HSQR1_B = uVar1 & 0xffcf;
  REG_TPU3B_CH2_PARAM0 = 0x89;
  REG_TPU3B_CH2_PARAM1 = 10;
  REG_TPU3B_CH2_PARAM2 = 0xec;
  uVar1 = REG_CPR1_B;
  REG_CPR1_B = uVar1 & 0xffcf | 0x30;
  uVar1 = REG_HSRR1_B;
  REG_HSRR1_B = uVar1 & 0xffcf | 0x10;
  do {
    uVar1 = REG_HSRR1_B;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR3_B;
  REG_CFSR3_B = uVar1 & 0xfff | 0xe000;
  uVar1 = REG_HSQR1_B;
  REG_HSQR1_B = uVar1 & 0xff3f;
  REG_TPU3B_CH3_PARAM0 = 0x89;
  REG_TPU3B_CH3_PARAM1 = 10;
  REG_TPU3B_CH3_PARAM2 = 0xec;
  uVar1 = REG_CPR1_B;
  REG_CPR1_B = uVar1 & 0xff3f | 0xc0;
  uVar1 = REG_HSRR1_B;
  REG_HSRR1_B = uVar1 & 0xff3f | 0x40;
  do {
    uVar1 = REG_HSRR1_B;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR2_B;
  REG_CFSR2_B = uVar1 & 0xfff0 | 0xe;
  uVar1 = REG_HSQR1_B;
  REG_HSQR1_B = uVar1 & 0xfcff;
  REG_TPU3B_CH4_PARAM0 = 0x89;
  REG_TPU3B_CH4_PARAM1 = 10;
  REG_TPU3B_CH4_PARAM2 = 0xec;
  uVar1 = REG_CPR1_B;
  REG_CPR1_B = uVar1 & 0xfcff | 0x300;
  uVar1 = REG_HSRR1_B;
  REG_HSRR1_B = uVar1 & 0xfcff | 0x100;
  do {
    uVar1 = REG_HSRR1_B;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR2_B;
  REG_CFSR2_B = uVar1 & 0xff0f | 0xe0;
  uVar1 = REG_HSQR1_B;
  REG_HSQR1_B = uVar1 & 0xf3ff;
  REG_TPU3B_CH5_PARAM0 = 0x89;
  REG_TPU3B_CH5_PARAM1 = 10;
  REG_TPU3B_CH5_PARAM2 = 0xec;
  uVar1 = REG_CPR1_B;
  REG_CPR1_B = uVar1 & 0xf3ff | 0xc00;
  uVar1 = REG_HSRR1_B;
  REG_HSRR1_B = uVar1 & 0xf3ff | 0x400;
  do {
    uVar1 = REG_HSRR1_B;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR2_B;
  REG_CFSR2_B = uVar1 & 0xf0ff | 0xe00;
  uVar1 = REG_HSQR1_B;
  REG_HSQR1_B = uVar1 & 0xcfff;
  REG_TPU3B_CH6_PARAM0 = 0x89;
  REG_TPU3B_CH6_PARAM1 = 10;
  REG_TPU3B_CH6_PARAM2 = 0xec;
  uVar1 = REG_CPR1_B;
  REG_CPR1_B = uVar1 & 0xcfff | 0x3000;
  uVar1 = REG_HSRR1_B;
  REG_HSRR1_B = uVar1 & 0xcfff | 0x1000;
  do {
    uVar1 = REG_HSRR1_B;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR2_B;
  REG_CFSR2_B = uVar1 & 0xfff | 0x9000;
  uVar1 = REG_HSQR1_B;
  REG_HSQR1_B = uVar1 & 0x3fff;
  REG_TPU3B_CH7_PARAM0 = 0x92;
  REG_TPU3B_CH7_PARAM2 = (ushort)((int)(uint)CAL_vvt_period >> 1);
  REG_TPU3B_CH7_PARAM3 = CAL_vvt_period;
  uVar1 = REG_CPR1_B;
  REG_CPR1_B = uVar1 & 0x3fff | 0x4000;
  uVar1 = REG_HSRR1_B;
  REG_HSRR1_B = uVar1 & 0x3fff | 0x8000;
  do {
    uVar1 = REG_HSRR1_B;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR1_B;
  REG_CFSR1_B = uVar1 & 0xfff0 | 9;
  uVar1 = REG_HSQR0_B;
  REG_HSQR0_B = uVar1 & 0xfffc;
  REG_TPU3B_CH8_PARAM0 = 0x92;
  REG_TPU3B_CH8_PARAM2 = 0;
  REG_TPU3B_CH8_PARAM3 = 1000;
  uVar1 = REG_CPR0_B;
  REG_CPR0_B = uVar1 & 0xfffc | 1;
  uVar1 = REG_HSRR0_B;
  REG_HSRR0_B = uVar1 & 0xfffc | 2;
  do {
    uVar1 = REG_HSRR0_B;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR1_B;
  REG_CFSR1_B = uVar1 & 0xff0f | 0x90;
  uVar1 = REG_HSQR0_B;
  REG_HSQR0_B = uVar1 & 0xfff3;
  REG_TPU3B_CH9_PARAM0 = 0x92;
  REG_TPU3B_CH9_PARAM2 = (ushort)((int)(uint)CAL_vvl_period >> 1);
  REG_TPU3B_CH9_PARAM3 = CAL_vvl_period;
  uVar1 = REG_CPR0_B;
  REG_CPR0_B = uVar1 & 0xfff3 | 4;
  uVar1 = REG_HSRR0_B;
  REG_HSRR0_B = uVar1 & 0xfff3 | 8;
  do {
    uVar1 = REG_HSRR0_B;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR1_B;
  REG_CFSR1_B = uVar1 & 0xf0ff;
  uVar1 = REG_CFSR1_B;
  REG_CFSR1_B = uVar1 & 0xf0ff | 0xc00;
  uVar1 = REG_HSQR0_B;
  REG_HSQR0_B = uVar1 & 0xffcf | 0x10;
  REG_TPU3B_CH10_PARAM0 = 0xb02;
  REG_TPU3B_CH10_PARAM4 = 0x800d;
  REG_TPU3B_CH10_PARAM5 = 3000;
  uVar1 = REG_CPR0_B;
  REG_CPR0_B = uVar1 & 0xffcf | 0x30;
  uVar1 = REG_HSRR0_B;
  REG_HSRR0_B = uVar1 & 0xffcf | 0x20;
  do {
    uVar1 = REG_HSRR0_B;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR1_B;
  REG_CFSR1_B = uVar1 & 0xfff;
  uVar1 = REG_CFSR1_B;
  REG_CFSR1_B = uVar1 & 0xfff | 0xc000;
  uVar1 = REG_HSQR0_B;
  REG_HSQR0_B = uVar1 & 0xff3f | 0x40;
  REG_TPU3B_CH11_PARAM0 = 0xb02;
  REG_TPU3B_CH11_PARAM4 = 0x8041;
  REG_TPU3B_CH11_PARAM5 = 3000;
  uVar1 = REG_CPR0_B;
  REG_CPR0_B = uVar1 & 0xff3f | 0xc0;
  uVar1 = REG_HSRR0_B;
  REG_HSRR0_B = uVar1 & 0xff3f | 0x80;
  do {
    uVar1 = REG_HSRR0_B;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR0_B;
  REG_CFSR0_B = uVar1 & 0xfff0;
  uVar1 = REG_CFSR0_B;
  REG_CFSR0_B = uVar1 & 0xfff0 | 0xc;
  uVar1 = REG_HSQR0_B;
  REG_HSQR0_B = uVar1 & 0xfcff | 0x100;
  REG_TPU3B_CH12_PARAM0 = 0xb02;
  REG_TPU3B_CH12_PARAM4 = 0x801f;
  REG_TPU3B_CH12_PARAM5 = 3000;
  uVar1 = REG_CPR0_B;
  REG_CPR0_B = uVar1 & 0xfcff | 0x300;
  uVar1 = REG_HSRR0_B;
  REG_HSRR0_B = uVar1 & 0xfcff | 0x200;
  do {
    uVar1 = REG_HSRR0_B;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR0_B;
  REG_CFSR0_B = uVar1 & 0xff0f;
  uVar1 = REG_CFSR0_B;
  REG_CFSR0_B = uVar1 & 0xff0f | 0xc0;
  uVar1 = REG_HSQR0_B;
  REG_HSQR0_B = uVar1 & 0xf3ff | 0x400;
  REG_TPU3B_CH13_PARAM0 = 0xb02;
  REG_TPU3B_CH13_PARAM4 = 0x802f;
  REG_TPU3B_CH13_PARAM5 = 3000;
  uVar1 = REG_CPR0_B;
  REG_CPR0_B = uVar1 & 0xf3ff | 0xc00;
  uVar1 = REG_HSRR0_B;
  REG_HSRR0_B = uVar1 & 0xf3ff | 0x800;
  do {
    uVar1 = REG_HSRR0_B;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR0_B;
  REG_CFSR0_B = uVar1 & 0xf0ff | 0x800;
  uVar1 = REG_HSQR0_B;
  REG_HSQR0_B = uVar1 & 0xcfff;
  REG_TPU3B_CH14_PARAM0 = 0xc;
  REG_TPU3B_CH14_PARAM2 = 0x19;
  uVar1 = REG_CPR0_B;
  REG_CPR0_B = uVar1 & 0xcfff | 0x1000;
  uVar1 = REG_HSRR0_B;
  REG_HSRR0_B = uVar1 & 0xcfff | 0x1000;
  do {
    uVar1 = REG_HSRR0_B;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR0_B;
  REG_CFSR0_B = uVar1 & 0xfff | 0x8000;
  uVar1 = REG_HSQR0_B;
  REG_HSQR0_B = uVar1 & 0x3fff;
  REG_TPU3B_CH15_PARAM0 = 7;
  REG_TPU3B_CH15_PARAM2 = 0xff00;
  uVar1 = REG_HSRR0_B;
  REG_HSRR0_B = uVar1 & 0x3fff | 0xc000;
  uVar1 = REG_CPR0_B;
  REG_CPR0_B = uVar1 & 0x3fff | 0x4000;
  do {
    uVar1 = REG_HSRR0_B;
  } while (uVar1 != 0);
  uVar1 = REG_TICR_B;
  REG_TICR_B = uVar1 & 0xf8ff | 0x400;
  uVar1 = REG_TICR_B;
  REG_TICR_B = uVar1 & 0xff3f;
  uVar1 = REG_CISR_B;
  if (uVar1 != 0) {
    REG_CISR_B = 0;
  }
  REG_CIER_B = 0xc01e;
  return;
}



// ISR: PIT 500us tick - O2 heater monitoring and fast tasks

undefined8 isr_pit_500us(undefined4 param_1,undefined4 param_2)

{
  uint uVar1;
  short sVar2;
  int iVar3;
  ushort uVar4;
  undefined4 in_MSR;
  undefined4 in_SRR1;
  
  iVar3 = (int)(uint)engine_speed_3 >> 4;
  uVar4 = REG_PISCR;
  if ((uVar4 >> 7 & 1) == 1) {
    uVar4 = REG_PISCR;
    REG_PISCR = uVar4 & 0xff7f | 0x80;
  }
  if (engine_runtime != 0) {
    o2_heater_500us();
  }
  obd_mode_0x13_state = obd_mode_0x13_state + -1;
  if (obd_mode_0x13_state == '\0') {
    obd_mode_0x13_state = '\n';
    if (DAT_003fd00a != 0) {
      DAT_003fd00a = DAT_003fd00a + -1;
    }
    pps_5ms();
    if (engine_is_running == false) {
      engine_runtime = 0;
    }
    else if (engine_runtime != 4294967295) {
      engine_runtime = engine_runtime + 1;
    }
    if (hc08_parse_timer != 0) {
      hc08_parse_timer = hc08_parse_timer + 255;
    }
    if (hc08_recv_timer != 0) {
      hc08_recv_timer = hc08_recv_timer + 255;
    }
    if (DAT_003fde3a != 0) {
      DAT_003fde3a = DAT_003fde3a + -1;
    }
    if (fuelpump_timer != 0) {
      fuelpump_timer = fuelpump_timer - 1;
    }
    if (pre_o2_heater_timer != 0) {
      pre_o2_heater_timer = pre_o2_heater_timer - 1;
    }
    if (post_o2_heater_timer != 0) {
      post_o2_heater_timer = post_o2_heater_timer - 1;
    }
    if (hc08_send_timer != 0) {
      hc08_send_timer = hc08_send_timer - 1;
    }
    DAT_003f800e = DAT_003f800e + -1;
    if (DAT_003f800e == '\0') {
      DAT_003f800e = '\x02';
      if (ac_on_timer != 255) {
        ac_on_timer = ac_on_timer + 1;
      }
      if (fan_low_on_timer != 255) {
        fan_low_on_timer = fan_low_on_timer + 1;
      }
      if (fan_high_on_timer != 255) {
        fan_high_on_timer = fan_high_on_timer + 1;
      }
    }
    DAT_003f800c = DAT_003f800c + -1;
    if (DAT_003f800c < 1) {
      DAT_003f800c = 0x14;
      obd_task_scheduler = 65535;
      if (DAT_003f8bf8 < 0x257fda8) {
        DAT_003f8bf8 = DAT_003f8bf8 + 1;
      }
      if (ecu_runtime != 65535) {
        ecu_runtime = ecu_runtime + 1;
      }
      DAT_003f800f = DAT_003f800f + -1;
      if (DAT_003f800f == '\0') {
        DAT_003f800f = '\x02';
        misfire_monitor_200ms();
      }
      cluster_task_100ms();
      evap_100ms();
      if ((dfso_flags & 1) != 0) {
        if ((misfire_flags & 0x10) == 0) {
          if (misfire_dfso_count[iVar3] < CAL_misfire_dfso_count_max[iVar3]) {
            misfire_dfso_count[iVar3] = misfire_dfso_count[iVar3] + 1;
          }
        }
      }
      ltft_100ms();
      obd_check_evap_flow_100ms();
    }
    if (DAT_003fd3c8 != 0) {
      DAT_003fd3c8 = DAT_003fd3c8 + -1;
    }
    if ((dfso_flags & 2) == 0) {
      if ((short)DAT_003fcff0 < (short)(ushort)dfso_delay) {
        DAT_003f8bf5 = DAT_003f8bf5 + 255;
        if (DAT_003f8bf5 == 0) {
          DAT_003f8bf5 = CAL_dfso_delay_recovery_multiplier;
          DAT_003fcff0 = DAT_003fcff0 + 1;
        }
      }
      else {
        DAT_003fcff0 = (ushort)dfso_delay;
      }
    }
    else if (DAT_003fcff0 != 0) {
      DAT_003fcff0 = DAT_003fcff0 - 1;
    }
    if ((dfso_flags & 1) == 0) {
      DAT_003fcff2 = 0;
    }
    else if (DAT_003fcff2 < 0x13ec) {
      DAT_003fcff2 = DAT_003fcff2 + 1;
    }
    if (DAT_003f8bea != 0) {
      DAT_003f8bea = DAT_003f8bea + -1;
    }
    if (DAT_003fd326 != '\0') {
      DAT_003fd326 = DAT_003fd326 + -1;
    }
    if (DAT_003f8be8 != 0) {
      DAT_003f8be8 = DAT_003f8be8 + -1;
    }
    if (shutdown_delay_2 != 0) {
      shutdown_delay_2 = shutdown_delay_2 - 1;
    }
    if (((shutdown_flags & 1) == 0) || (engine_speed_1 != 0)) {
      DAT_003f8bec = 0;
    }
    else {
      DAT_003f8bec = DAT_003f8bec + 1;
    }
    if (fan_low_stop_timer != 65535) {
      fan_low_stop_timer = fan_low_stop_timer + 1;
    }
    if (fan_high_stop_timer != 65535) {
      fan_high_stop_timer = fan_high_stop_timer + 1;
    }
    if (DAT_003fcff8 != 0) {
      DAT_003fcff8 = DAT_003fcff8 + -1;
    }
    if (DAT_003fcffa != 0) {
      DAT_003fcffa = DAT_003fcffa + -1;
    }
    if (DAT_003fcffc != 0) {
      DAT_003fcffc = DAT_003fcffc + -1;
    }
    ignition_5ms();
    idle_5ms();
    stft_5ms();
    if (obd_mode_0x2F_state == '\x15') {
      if (obd_mode_0x2F_value == '\0') {
        uVar4 = REG_MPIOSMDR;
        REG_MPIOSMDR = uVar4 & 0xfffb;
        uVar4 = REG_MPIOSMDR;
        REG_MPIOSMDR = uVar4 & 0xfffe;
      }
      else {
        uVar4 = REG_MPIOSMDR;
        REG_MPIOSMDR = uVar4 & 0xfffb | 4;
        uVar4 = REG_MPIOSMDR;
        REG_MPIOSMDR = uVar4 & 0xfffe | 1;
      }
    }
    else if (engine_runtime == 0) {
      uVar4 = REG_MPIOSMDR;
      REG_MPIOSMDR = uVar4 & 0xfffb;
      uVar4 = REG_MPIOSMDR;
      REG_MPIOSMDR = uVar4 & 0xfffe;
      o2_heater_warmup_state = 0;
    }
    else if (engine_runtime < CAL_sensor_o2_heater_warmup_time) {
      o2_heater_warmup_state = 1;
      DAT_003f8bf4 = DAT_003f8bf4 + 1;
      if (((uint)CAL_sensor_o2_heater_warmup_period << 2) / 5 < (uint)DAT_003f8bf4) {
        if (DAT_003f8bf4 < CAL_sensor_o2_heater_warmup_period) {
          uVar4 = REG_MPIOSMDR;
          REG_MPIOSMDR = uVar4 & 0xfffb;
          uVar4 = REG_MPIOSMDR;
          REG_MPIOSMDR = uVar4 & 0xfffe;
        }
        else {
          DAT_003f8bf4 = 0;
        }
      }
      else {
        if (post_o2_heater_is_off == false) {
          uVar4 = REG_MPIOSMDR;
          REG_MPIOSMDR = uVar4 & 0xfffb | 4;
        }
        else {
          uVar4 = REG_MPIOSMDR;
          REG_MPIOSMDR = uVar4 & 0xfffb;
        }
        if (pre_o2_heater_is_off == false) {
          uVar4 = REG_MPIOSMDR;
          REG_MPIOSMDR = uVar4 & 0xfffe | 1;
        }
        else {
          uVar4 = REG_MPIOSMDR;
          REG_MPIOSMDR = uVar4 & 0xfffe;
        }
      }
    }
    else {
      o2_heater_warmup_state = 2;
    }
    revlimit_5ms();
    uVar1 = (0x100 - (uint)CAL_load_reactivity) * load_1_smooth_x;
    load_1_smooth_x =
         ((int)uVar1 >> 8) + (uint)((int)uVar1 < 0 && (uVar1 & 0xff) != 0) +
         CAL_load_reactivity * load_1;
    load_1_smooth =
         ((int)load_1_smooth_x >> 8) +
         (uint)((int)load_1_smooth_x < 0 && (load_1_smooth_x & 0xff) != 0);
    for (sVar2 = 0xf; 0 < sVar2; sVar2 = sVar2 + -1) {
      tps_target_history_2[sVar2] = tps_target_history_2[sVar2 + -1];
    }
    tps_target_history_2[0] = pps_tps_target;
    uVar4 = (ushort)CAL_sensor_dt_tps_target_2_age;
    if (0xf < CAL_sensor_dt_tps_target_2_age) {
      uVar4 = 0xf;
    }
    dt_tps_target_2 = pps_tps_target - tps_target_history_2[(short)uVar4];
    for (sVar2 = 0xf; 0 < sVar2; sVar2 = sVar2 + -1) {
      tps_target_history_1[sVar2] = tps_target_history_1[sVar2 + -1];
    }
    tps_target_history_1[0] = pps_tps_target;
    uVar4 = (ushort)CAL_sensor_dt_tps_target_1_age;
    if (0xf < CAL_sensor_dt_tps_target_1_age) {
      uVar4 = 0xf;
    }
    dt_tps_target_1 = pps_tps_target - tps_target_history_1[(short)uVar4];
    if ((short)dt_tps_injtip < 0) {
      DAT_003f8bf0 = DAT_003f8bf0 + 1;
      if ((short)(ushort)DAT_003f94a1 <= DAT_003f8bf0) {
        DAT_003f8bf0 = 0;
        dt_tps_injtip = dt_tps_injtip + injtip_out_adj2;
        if (0 < (short)dt_tps_injtip) {
          dt_tps_injtip = 0;
        }
      }
    }
    else if ((0 < (short)dt_tps_injtip) &&
            (DAT_003f8bf0 = DAT_003f8bf0 + 1, (short)(ushort)DAT_003f94a0 <= DAT_003f8bf0)) {
      DAT_003f8bf0 = 0;
      dt_tps_injtip = dt_tps_injtip - injtip_in_adj2;
      if ((short)dt_tps_injtip < 0) {
        dt_tps_injtip = 0;
      }
    }
    if (dt_tps_target_2 < 0) {
      if ((int)dt_tps_target_2 < -(int)(short)CAL_injtip_out_dt_tps_target_2_min) {
        if ((int)dt_tps_target_2 < -(int)(short)CAL_injtip_out_dt_tps_target_2_limit) {
          dt_tps_injtip = -CAL_injtip_out_dt_tps_target_2_limit;
          DAT_003f8bf0 = 0;
        }
        else if (dt_tps_target_2 < (short)dt_tps_injtip) {
          dt_tps_injtip = dt_tps_target_2;
          DAT_003f8bf0 = 0;
        }
      }
    }
    else if ((short)CAL_injtip_in_dt_tps_target_2_min < dt_tps_target_2) {
      if ((short)CAL_injtip_in_dt_tps_target_2_limit < dt_tps_target_2) {
        dt_tps_injtip = CAL_injtip_in_dt_tps_target_2_limit;
        DAT_003f8bf0 = 0;
      }
      else if ((short)dt_tps_injtip < dt_tps_target_2) {
        dt_tps_injtip = dt_tps_target_2;
        DAT_003f8bf0 = 0;
      }
    }
    pps_offset_5ms();
    obd_check_catalyst_5ms();
    obd_check_o2_slow_response_5ms();
    obd_check_misfire_5ms();
    obd_kline_sci_handler();
    obd_mode_0x2F_test_5ms();
    obd_mode_0x08_evap_control_5ms();
    vvt_5ms();
    knock_5ms();
    traction_control_5ms();
    if (engine_is_running == false) {
      DAT_003fd668 = 0;
      maf_accumulated_2 = 0;
      maf_accumulated_1 = 0;
    }
    else if (maf_accumulated_1 != 4294967295) {
      maf_accumulated_1 = maf_accumulated_1 + maf_flow_1 / 0x14;
      DAT_003fd668 = DAT_003fd668 + ((uint)maf_flow_1 * (uint)DAT_003fd66c) / 0x13ec;
    }
    if (maf_accumulated_1 < 0x3e8000) {
      maf_accumulated_2 = (undefined2)(maf_accumulated_1 / 1000);
    }
    if ((((CAL_load_alphaN_adj_corr_coolant_min < coolant_smooth) &&
         ((int)(uint)DAT_003f9488 < (int)DAT_003fd228)) &&
        (dt_tps_target_1 < (short)CAL_load_alphaN_adj_corr_dt_tps_target_1_max)) &&
       (((-(int)(short)CAL_load_alphaN_adj_corr_dt_tps_target_1_max < (int)dt_tps_target_1 &&
         (-(int)(short)CAL_load_alphaN_adj_corr_dt_engine_speed_max < dt_engine_speed)) &&
        ((dt_engine_speed < (short)CAL_load_alphaN_adj_corr_dt_engine_speed_max &&
         ((tps <= load_use_alphaN_tps_min && ((dfso_flags & 1) == 0)))))))) {
      closedloop_flags = closedloop_flags | 0x200;
      if (((DAT_003f8bf2 == 0) && (DAT_003fd00e == 0)) &&
         (DAT_003fd00e = CAL_load_alphaN_adj_corr_time_between_step, (DAT_003fd30a & 0x8000) != 0))
      {
        sVar2 = (DAT_003fd30a & 0x7fff) + 0x28;
        if ((short)CAL_load_alphaN_adj_corr_min < (short)(ushort)load_alphaN_maf_error) {
          if (((short)CAL_load_alphaN_adj_corr_max <= (short)(ushort)load_alphaN_maf_error) &&
             (CAL_load_alphaN_adj_corr_limit_l <
              *(byte *)((int)&LEA_ecu_engine_speed_byte_coefficient + (int)sVar2))) {
            *(char *)((int)&LEA_ecu_engine_speed_byte_coefficient + (int)sVar2) =
                 *(char *)((int)&LEA_ecu_engine_speed_byte_coefficient + (int)sVar2) + -1;
          }
        }
        else if (*(byte *)((int)&LEA_ecu_engine_speed_byte_coefficient + (int)sVar2) <
                 CAL_load_alphaN_adj_corr_limit_h) {
          *(char *)((int)&LEA_ecu_engine_speed_byte_coefficient + (int)sVar2) =
               *(char *)((int)&LEA_ecu_engine_speed_byte_coefficient + (int)sVar2) + '\x01';
        }
      }
    }
    else {
      closedloop_flags = closedloop_flags & 0xfdff;
      DAT_003fd00e = CAL_load_alphaN_adj_corr_time_between_step;
      DAT_003f8bf2 = CAL_load_alphaN_adj_corr_time_min;
    }
    if (DAT_003fd00e != 0) {
      DAT_003fd00e = DAT_003fd00e - 1;
    }
    if (DAT_003f8bf2 != 0) {
      DAT_003f8bf2 = DAT_003f8bf2 - 1;
    }
  }
  uVar1 = REG_SISR3;
  REG_SISR3 = uVar1 & 0xffefffff | 0x100000;
  returnFromInterrupt(in_MSR,in_SRR1);
  return CONCAT44(param_1,param_2);
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// Resets MAF averaging buffer

void reset_maf_avg(u16_voltage_5_1023v v)

{
  short sVar1;
  
  for (sVar1 = 0x1f; 0 < sVar1; sVar1 = sVar1 + -1) {
    maf_adc_history[sVar1] = v;
  }
  maf_adc_history[0] = v;
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// Reads MAF sensor raw ADC value from QADC-A channel 11 (RJURR11)

u16_voltage_5_1023v read_adc_maf(void)

{
  ushort uVar1;
  
  uVar1 = REG_QADCA_RJURR11;
  return uVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// Reads MAP sensor raw ADC value from QADC-A channel 10 (RJURR10)

u16_voltage_5_1023v read_adc_map(void)

{
  ushort uVar1;
  
  uVar1 = REG_QADCA_RJURR10;
  return uVar1;
}



// Computes first MAF moving average

int make_maf_avg1(void)

{
  int sum;
  ushort j;
  ushort avg_size;
  ushort i;
  
  sum = 0;
  j = maf_adc_history_i;
  if (CAL_sensor_maf_avg_size < 0x20) {
    if (CAL_sensor_maf_avg_size == 0) {
      i = 1;
      avg_size = 1;
    }
    else {
      i = (ushort)CAL_sensor_maf_avg_size;
      avg_size = i;
    }
  }
  else {
    i = 0x1f;
    avg_size = 0x1f;
  }
  for (; 0 < (short)i; i = i - 1) {
    sum = sum + (short)maf_adc_history[(short)j];
    j = j - 1 & 0x1f;
  }
  return sum / (int)(short)avg_size;
}



// Computes second MAF moving average

int make_maf_avg2(void)

{
  ushort uVar1;
  int sum;
  ushort avg_size;
  ushort i;
  
  sum = 0;
  if (CAL_sensor_maf_avg_size < 0x20) {
    if (CAL_sensor_maf_avg_size == 0) {
      avg_size = 1;
    }
    else {
      avg_size = (ushort)CAL_sensor_maf_avg_size;
    }
  }
  else {
    avg_size = 0x1f;
  }
  uVar1 = maf_adc_history_i - avg_size;
  for (i = avg_size; 0 < (short)i; i = i - 1) {
    sum = sum + (short)maf_adc_history[(short)(uVar1 & 0x1f)];
    uVar1 = (uVar1 & 0x1f) - 1;
  }
  return sum / (int)(short)avg_size;
}



// Computes MAP sensor moving average

int make_map_avg(void)

{
  int iVar1;
  ushort uVar2;
  ushort uVar3;
  ushort uVar4;
  
  iVar1 = 0;
  uVar2 = map_adc_history_i;
  if (CAL_sensor_map_avg_size < 0x20) {
    if (CAL_sensor_map_avg_size == 0) {
      uVar4 = 1;
      uVar3 = 1;
    }
    else {
      uVar4 = (ushort)CAL_sensor_map_avg_size;
      uVar3 = uVar4;
    }
  }
  else {
    uVar4 = 0x1f;
    uVar3 = 0x1f;
  }
  for (; 0 < (short)uVar4; uVar4 = uVar4 - 1) {
    iVar1 = iVar1 + (short)map_adc_history[(short)uVar2];
    uVar2 = uVar2 - 1 & 0x1f;
  }
  return iVar1 / (int)(short)uVar3;
}



// Initializes PIT (Periodic Interrupt Timer) for 5ms scheduler

void init_pit(void)

{
  ushort uVar1;
  uint uVar2;
  
  uVar2 = REG_PITC;
  REG_PITC = uVar2 & 0xffff | 0x1f40000;
  uVar1 = REG_PISCR;
  REG_PISCR = uVar1 & 0xff | 0x100;
  uVar1 = REG_PISCR;
  REG_PISCR = uVar1 & 0xfffe | 1;
  uVar1 = REG_PISCR;
  REG_PISCR = uVar1 & 0xfffb | 4;
  uVar1 = REG_PISCR;
  REG_PISCR = uVar1 & 0xff7f | 0x80;
  return;
}



// Initializes QADC-A module for analog sensor inputs

void init_qadc_a(void)

{
  ushort uVar1;
  
  REG_QADC64MCR_A = 0x280;
  REG_QADC64MCR_A = 0x180;
  REG_QADC64INT_A = 0xd800;
  Ram00304808 = 0;
  REG_PORTQA_A = 0;
  REG_PORTQB_A = 0;
  REG_QACR0_A = 0x11;
  REG_QACR1_A = 0x9800;
  REG_QACR2_A = 0x1182;
  REG_QADCA_CCW2 = 0x2c;
  REG_QADCA_CCW3 = 0x2d;
  REG_QADCA_CCW4 = 0x2e;
  REG_QADCA_CCW5 = 0x2f;
  REG_QADCA_CCW0 = 0x30;
  REG_QADCA_CCW1 = 0x31;
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
  uVar1 = REG_QACR2_A;
  REG_QACR2_A = uVar1 & 0xdfff | 0x2000;
  do {
    uVar1 = REG_QASR0_A;
  } while ((uVar1 >> 0xd & 1) == 0);
  return;
}



// ISR: QADC conversion complete - ADC interrupt handler (Called every 204.8 us)
// 
// QACR0_A = 0x0011: PSH=1, PSL=1
// QACR1_A = 0x9800: MQ1 = Periodic timer 2048 QCLK cycles
// Interval = 2048 / (40 MHz / (1+1 + 1+1)) = 204.8 us

undefined8 isr_qadc(undefined4 param_1,undefined4 param_2)

{
  uint uVar1;
  ushort uVar2;
  undefined4 in_MSR;
  undefined4 in_SRR1;
  
  uVar2 = REG_QASR0_A;
  if ((short)uVar2 < 0) {
    uVar2 = REG_QASR0_A;
    REG_QASR0_A = uVar2 & 0x7fff;
    uVar2 = REG_QADCA_RJURR0;
    tps_1_smooth = adc_filter_update(&filter_tps,uVar2);
    tps_state_machine_dispatch();
  }
  uVar1 = REG_SISR3;
  REG_SISR3 = uVar1 & 0xffbfffff | 0x400000;
  returnFromInterrupt(in_MSR,in_SRR1);
  return CONCAT44(param_1,param_2);
}



// 2D table lookup without interpolation (nearest cell)

uint8_t lookup_2D_uint8_fixed(uint8_t size_x,uint8_t value_x,uint8_t *lut)

{
  short sVar1;
  
  for (sVar1 = 0; (lut[sVar1] < value_x && ((int)sVar1 < (int)(size_x - 1))); sVar1 = sVar1 + 1) {
  }
  DAT_003f8c40 = (char)sVar1 + -1;
  return lut[(uint)size_x + (int)sVar1];
}



// 3D table lookup without interpolation (nearest cell)

uint8_t lookup_3D_uint8_fixed
                  (uint8_t size_x,uint8_t size_y,uint8_t input_x,uint8_t input_y,uint8_t *x_axis,
                  uint8_t *y_axis,uint8_t *lut)

{
  short sVar1;
  short sVar2;
  
  sVar1 = 0;
  for (sVar2 = 0; (x_axis[sVar2] < input_x && ((int)sVar2 < (int)(size_x - 1))); sVar2 = sVar2 + 1)
  {
  }
  for (; (y_axis[sVar1] < input_y && ((int)sVar1 < (int)(size_y - 1))); sVar1 = sVar1 + 1) {
  }
  return lut[(int)sVar2 + (uint)size_x * (int)sVar1];
}



// Retriggers hardware watchdog timer

void watchdog_retrigger(void)

{
  REG_SWSR = 0x556c;
  REG_SWSR = 0xaa39;
  return;
}



// Computes PPS1 averaged value

int smooth_pps_1(int param_1)

{
  uint uVar1;
  
  uVar1 = pps_1_smooth_x * (0x100 - (uint)CAL_sensor_pps_reactivity);
  pps_1_smooth_x =
       ((int)uVar1 >> 8) + (uint)((int)uVar1 < 0 && (uVar1 & 0xff) != 0) +
       param_1 * (uint)CAL_sensor_pps_reactivity;
  return ((int)pps_1_smooth_x >> 8) +
         (uint)((int)pps_1_smooth_x < 0 && (pps_1_smooth_x & 0xff) != 0);
}



// Computes PPS2 averaged value

int smooth_pps_2(int param_1)

{
  uint uVar1;
  
  uVar1 = pps_2_smooth_x * (0x100 - (uint)CAL_sensor_pps_reactivity);
  pps_2_smooth_x =
       ((int)uVar1 >> 8) + (uint)((int)uVar1 < 0 && (uVar1 & 0xff) != 0) +
       param_1 * (uint)CAL_sensor_pps_reactivity;
  return ((int)pps_2_smooth_x >> 8) +
         (uint)((int)pps_2_smooth_x < 0 && (pps_2_smooth_x & 0xff) != 0);
}



// Computes fuel level averaged value

int smooth_fuel_level(int param_1)

{
  uint uVar1;
  
  uVar1 = fuel_level_smooth_x * (0x100 - (uint)CAL_sensor_fuel_reactivity);
  fuel_level_smooth_x =
       ((int)uVar1 >> 8) + (uint)((int)uVar1 < 0 && (uVar1 & 0xff) != 0) +
       param_1 * (uint)CAL_sensor_fuel_reactivity;
  return ((int)fuel_level_smooth_x >> 8) +
         (uint)((int)fuel_level_smooth_x < 0 && (fuel_level_smooth_x & 0xff) != 0);
}



// Computes EVAP pressure averaged value

int smooth_evap_pressure(int param_1)

{
  uint uVar1;
  
  uVar1 = evap_pressure_smooth_x * (0x100 - (uint)CAL_sensor_evap_reactivity);
  evap_pressure_smooth_x =
       ((int)uVar1 >> 8) + (uint)((int)uVar1 < 0 && (uVar1 & 0xff) != 0) +
       param_1 * (uint)CAL_sensor_evap_reactivity;
  return ((int)evap_pressure_smooth_x >> 8) +
         (uint)((int)evap_pressure_smooth_x < 0 && (evap_pressure_smooth_x & 0xff) != 0);
}



// Samples all ADC channels for sensor readings

void adc_sample(void)

{
  ushort uVar1;
  
  sensor_adc_baro = REG_QADCA_RJURR2;
  sensor_adc_oil_pressure = REG_QADCA_RJURR5;
  sensor_adc_tps_2 = REG_QADCA_RJURR1;
  sensor_adc_evap = REG_QADCA_RJURR6;
  sensor_adc_free_1 = REG_QADCA_RJURR7;
  if (CAL_misc_use_tmap) {
    sensor_adc_engine_air = REG_QADCA_RJURR13;
    sensor_adc_intake_air = REG_QADCA_RJURR8;
  }
  else {
    sensor_adc_engine_air = REG_QADCA_RJURR8;
  }
  sensor_adc_oil_vvtl = REG_QADCA_RJURR9;
  sensor_adc_map = REG_QADCA_RJURR10;
  DAT_003fd0b4 = sensor_adc_map;
  sensor_adc_free_2 = REG_QADCA_RJURR14;
  sensor_adc_fuel_level = REG_QADCA_RJURR15;
  sensor_adc_free_3 = REG_QADCB_RJURR0;
  sensor_adc_coolant = REG_QADCB_RJURR1;
  sensor_adc_tc_button = REG_QADCB_RJURR2;
  sensor_adc_pre_o2 = REG_QADCB_RJURR3;
  sensor_adc_post_o2 = REG_QADCB_RJURR5;
  sensor_adc_pre_o2_heater_sense = REG_QADCB_RJURR4;
  sensor_adc_post_o2_heater_sense = REG_QADCB_RJURR6;
  DAT_003fd0c0 = REG_QADCB_RJURR7;
  sensor_adc_knock = REG_QADCB_RJURR8;
  DAT_003fd0de = REG_QADCB_RJURR9;
  uVar1 = REG_QADCB_RJURR10;
  sensor_adc_ecu_voltage =
       (u16_voltage_18_1023v)((int)((uint)uVar1 + (uint)sensor_adc_ecu_voltage * 7) >> 3);
  sensor_adc_ign = REG_QADCB_RJURR11;
  sensor_adc_free_4 = REG_QADCB_RJURR12;
  sensor_adc_ac_fan_request = REG_QADCB_RJURR13;
  DAT_003fd0e6 = REG_QADCB_RJURR14;
  sensor_adc_tc_knob = REG_QADCA_RJURR12;
  DAT_003fd0ea = REG_QADCA_RJURR16;
  DAT_003fd0ec = REG_QADCA_RJURR17;
  DAT_003fd0ee = REG_QADCB_RJURR16;
  DAT_003fd0f0 = REG_QADCB_RJURR17;
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// Reads PPS1 (pedal position sensor 1) raw ADC value from QADC-A channel 3 (RJURR3)

u16_voltage_5_1023v read_adc_pps_1(void)

{
  ushort uVar1;
  
  uVar1 = REG_QADCA_RJURR3;
  return uVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// Reads PPS2 (pedal position sensor 2) raw ADC value from QADC-A channel 4 (RJURR4)

u16_voltage_5_1023v read_adc_pps_2(void)

{
  ushort uVar1;
  
  uVar1 = REG_QADCA_RJURR4;
  return uVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// Reads TPS1 (throttle position sensor 1) raw ADC value from QADC-A channel 0 (RJURR0)

u16_voltage_5_1023v read_adc_tps_1(void)

{
  ushort uVar1;
  
  uVar1 = REG_QADCA_RJURR0;
  return uVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// Reads TPS2 (throttle position sensor 2) raw ADC value from QADC-A channel 1 (RJURR1)

u16_voltage_5_1023v read_adc_tps_2(void)

{
  ushort uVar1;
  
  uVar1 = REG_QADCA_RJURR1;
  return uVar1;
}



// Converts PPS1 raw ADC to pedal position

int convert_pps_1(short param_1)

{
  uint uVar1;
  int iVar2;
  
  uVar1 = (uint)CAL_sensor_pps_1_gain * ((int)param_1 - (int)(short)LEA_sensor_pps_1_offset);
  iVar2 = ((int)uVar1 >> 6) + (uint)((int)uVar1 < 0 && (uVar1 & 0x3f) != 0);
  if (iVar2 < 0) {
    iVar2 = 0;
  }
  else if (0x3ff < iVar2) {
    iVar2 = 0x3ff;
  }
  return iVar2;
}



// Converts PPS2 raw ADC to pedal position

int convert_pps_2(short param_1)

{
  uint uVar1;
  int iVar2;
  
  uVar1 = (uint)CAL_sensor_pps_2_gain * ((int)param_1 - (int)(short)LEA_sensor_pps_2_offset);
  iVar2 = ((int)uVar1 >> 6) + (uint)((int)uVar1 < 0 && (uVar1 & 0x3f) != 0);
  if (iVar2 < 0) {
    iVar2 = 0;
  }
  else if (0x3ff < iVar2) {
    iVar2 = 0x3ff;
  }
  return iVar2;
}



// Learns PPS1 minimum offset (gravitates toward lowest reading)

void learn_pps_1_offset(short param_1)

{
  uint uVar1;
  
  if ((0 < (int)(short)LEA_sensor_pps_1_offset - (int)param_1) &&
     (uVar1 = abs((int)param_1 - (int)(short)CAL_sensor_pps_1_offset),
     (int)uVar1 < (int)(CAL_sensor_pps_offset_diff_max + 5))) {
    uVar1 = (uint)CAL_sensor_pps_offset_reactivity *
            ((int)(short)LEA_sensor_pps_1_offset - (int)param_1);
    LEA_sensor_pps_1_offset =
         LEA_sensor_pps_1_offset -
         ((short)(uVar1 >> 8) + (ushort)((int)uVar1 < 0 && (uVar1 & 0xff) != 0));
    if ((int)(short)LEA_sensor_pps_1_offset < (int)(uint)CAL_sensor_pps_1_offset_limit_l) {
      LEA_sensor_pps_1_offset = CAL_sensor_pps_1_offset_limit_l;
    }
  }
  uVar1 = abs((int)(short)LEA_sensor_pps_1_offset - (int)(short)CAL_sensor_pps_1_offset);
  if ((int)(CAL_sensor_pps_offset_diff_max + 5) < (int)uVar1) {
    LEA_sensor_pps_1_offset = CAL_sensor_pps_1_offset;
  }
  return;
}



// Learns PPS2 minimum offset (gravitates toward lowest reading)

void learn_pps_2_offset(short param_1)

{
  uint uVar1;
  
  if ((0 < (int)(short)LEA_sensor_pps_2_offset - (int)param_1) &&
     (uVar1 = abs((int)param_1 - (int)(short)CAL_sensor_pps_2_offset),
     (int)uVar1 < (int)(CAL_sensor_pps_offset_diff_max + 5))) {
    uVar1 = (uint)CAL_sensor_pps_offset_reactivity *
            ((int)(short)LEA_sensor_pps_2_offset - (int)param_1);
    LEA_sensor_pps_2_offset =
         LEA_sensor_pps_2_offset -
         ((short)(uVar1 >> 8) + (ushort)((int)uVar1 < 0 && (uVar1 & 0xff) != 0));
    if ((int)(short)LEA_sensor_pps_2_offset < (int)(uint)CAL_sensor_pps_2_offset_limit_l) {
      LEA_sensor_pps_2_offset = CAL_sensor_pps_2_offset_limit_l;
    }
  }
  uVar1 = abs((int)(short)LEA_sensor_pps_2_offset - (int)(short)CAL_sensor_pps_2_offset);
  if ((int)(CAL_sensor_pps_offset_diff_max + 5) < (int)uVar1) {
    LEA_sensor_pps_2_offset = CAL_sensor_pps_2_offset;
  }
  return;
}



// WARNING: Inlined function: push_20to31
// WARNING: Inlined function: pop_20to31
// Returns nearest cell address in 3D table for given inputs

ushort lookup_3D_uint8_get_address
                 (uint8_t size_x,uint8_t size_y,uint16_t input_x,uint16_t input_y,uint8_t *x_axis,
                 uint8_t *y_axis)

{
  short sVar1;
  short sVar2;
  uint uVar3;
  ushort uVar4;
  ushort uVar5;
  
  uVar4 = 0;
  uVar5 = 0;
  while ((((int)(short)uVar4 < (int)(size_x - 1) &&
          ((ushort)x_axis[(short)uVar4] < (input_x & 0xff))) &&
         (x_axis[(short)uVar4 + 1] < engine_speed_3))) {
    uVar4 = uVar4 + 1;
  }
  if (uVar4 == 0) {
    if ((int)(short)((ushort)x_axis[1] - (ushort)*x_axis) / 2 <
        (int)(short)((input_x & 0xff) - (ushort)*x_axis)) {
      uVar4 = 1;
    }
    uVar3 = abs((int)(short)(input_x & 0xff) - (int)(short)(ushort)x_axis[(short)uVar4]);
    sVar1 = (short)uVar3;
  }
  else if (uVar4 == size_x) {
    sVar1 = (input_x & 0xff) - (ushort)x_axis[(short)uVar4];
  }
  else {
    if ((int)(short)((ushort)x_axis[(short)uVar4 + 1] - (ushort)x_axis[(short)uVar4]) / 2 <
        (int)(short)((input_x & 0xff) - (ushort)x_axis[(short)uVar4])) {
      uVar4 = uVar4 + 1;
    }
    uVar3 = abs((int)(short)(input_x & 0xff) - (int)(short)(ushort)x_axis[(short)uVar4]);
    sVar1 = (short)uVar3;
  }
  while ((((int)(short)uVar5 < (int)(size_y - 1) &&
          ((ushort)y_axis[(short)uVar5] < (input_y & 0xff))) &&
         ((ushort)y_axis[(short)uVar5 + 1] < (input_y & 0xff)))) {
    uVar5 = uVar5 + 1;
  }
  if (uVar5 == 0) {
    if ((int)(short)((ushort)y_axis[1] - (ushort)*y_axis) / 2 <
        (int)(short)((input_y & 0xff) - (ushort)*y_axis)) {
      uVar5 = 1;
    }
    uVar3 = abs((int)(short)(input_y & 0xff) - (int)(short)(ushort)y_axis[(short)uVar5]);
    sVar2 = (short)uVar3;
  }
  else if (uVar5 == size_x) {
    sVar2 = (input_y & 0xff) - (ushort)y_axis[(short)uVar5];
  }
  else {
    if ((int)(short)((ushort)y_axis[(short)uVar5 + 1] - (ushort)y_axis[(short)uVar5]) / 2 <
        (int)(short)((input_y & 0xff) - (ushort)y_axis[(short)uVar5])) {
      uVar5 = uVar5 + 1;
    }
    uVar3 = abs((int)(short)(input_y & 0xff) - (int)(short)(ushort)y_axis[(short)uVar5]);
    sVar2 = (short)uVar3;
  }
  uVar4 = uVar4 + uVar5 * 0x10;
  if ((sVar1 <= (short)(ushort)DAT_003f93a1) && (sVar2 <= (short)(ushort)DAT_003f93a2)) {
    uVar4 = uVar4 | 0x8000;
  }
  return uVar4;
}



// Converts raw ADC values to engineering units (temp, pressure, etc)

void adc_convert(void)

{
  int iVar1;
  uint uVar2;
  byte bVar4;
  short sVar3;
  
  bVar4 = lookup_2D_uint8_interpolated_noaxis(3,sensor_adc_coolant,CAL_sensor_coolant_scaling);
  coolant = (u16_temp_5_8_40c)bVar4;
  bVar4 = lookup_2D_uint8_interpolated_noaxis(3,sensor_adc_engine_air,CAL_sensor_engine_air_scaling)
  ;
  engine_air = (u16_temp_5_8_40c)bVar4;
  bVar4 = lookup_2D_uint8_interpolated_noaxis(3,sensor_adc_intake_air,CAL_sensor_intake_air_scaling)
  ;
  intake_air = (u16_temp_5_8_40c)bVar4;
  if (((shutdown_flags & 0x10) == 0) && ((shutdown_flags & 1) != 0)) {
    coolant_smooth_x = (uint)coolant * 0xa00;
    engine_air_smooth_x = (uint)engine_air * 0xa00;
    intake_air_smooth_x = (uint)intake_air * 0xa00;
    shutdown_flags = shutdown_flags | 0x10;
  }
  if ((sensor_fault_flags & 2) == 0) {
    iVar1 = (0xa00 - (uint)CAL_sensor_coolant_reactivity) * coolant_smooth_x;
    iVar1 = iVar1 / 0xa00 + (iVar1 >> 0x1f);
    coolant_smooth_x =
         (iVar1 - (iVar1 >> 0x1f)) + (uint)CAL_sensor_coolant_reactivity * (uint)coolant;
    iVar1 = (int)coolant_smooth_x / 0xa00 + ((int)coolant_smooth_x >> 0x1f);
    coolant_smooth = (char)iVar1 - (char)(iVar1 >> 0x1f);
  }
  else {
    coolant_smooth = CAL_sensor_coolant_fallback;
  }
  if ((sensor_fault_flags & 1) == 0) {
    iVar1 = (0xa00 - (uint)CAL_sensor_engine_air_reactivity) * engine_air_smooth_x;
    iVar1 = iVar1 / 0xa00 + (iVar1 >> 0x1f);
    engine_air_smooth_x =
         (iVar1 - (iVar1 >> 0x1f)) + (uint)CAL_sensor_engine_air_reactivity * (uint)engine_air;
    iVar1 = (int)engine_air_smooth_x / 0xa00 + ((int)engine_air_smooth_x >> 0x1f);
    engine_air_smooth = (char)iVar1 - (char)(iVar1 >> 0x1f);
  }
  else {
    engine_air_smooth = CAL_sensor_engine_air_fallback;
  }
  iVar1 = (0xa00 - (uint)CAL_sensor_intake_air_reactivity) * intake_air_smooth_x;
  iVar1 = iVar1 / 0xa00 + (iVar1 >> 0x1f);
  intake_air_smooth_x =
       (iVar1 - (iVar1 >> 0x1f)) + (uint)CAL_sensor_intake_air_reactivity * (uint)intake_air;
  iVar1 = (int)intake_air_smooth_x / 0xa00 + ((int)intake_air_smooth_x >> 0x1f);
  intake_air_smooth = (char)iVar1 - (char)(iVar1 >> 0x1f);
  pre_o2 = lookup_2D_uint8_interpolated
                     (16,(uint8_t)sensor_adc_pre_o2,CAL_sensor_o2_scaling,
                      CAL_sensor_o2_scaling_X_signal);
  post_o2 = lookup_2D_uint8_interpolated
                      (16,(uint8_t)sensor_adc_post_o2,CAL_sensor_o2_scaling,
                       CAL_sensor_o2_scaling_X_signal);
  fuel_level = lookup_2D_uint8_interpolated_noaxis(1,sensor_adc_fuel_level,CAL_sensor_fuel_scaling);
  uVar2 = (uint)sensor_adc_evap * (uint)CAL_sensor_evap_gain;
  evap_pressure =
       (((short)((int)uVar2 >> 10) + (ushort)((int)uVar2 < 0 && (uVar2 & 0x3ff) != 0)) -
       CAL_sensor_evap_offset) - DAT_003fd0d6;
  if ((sensor_fault_flags & 8) == 0) {
    uVar2 = (uint)sensor_adc_baro * (uint)CAL_sensor_baro_gain;
    atmo_pressure =
         CAL_sensor_baro_offset +
         (short)((int)uVar2 >> 10) + (ushort)((int)uVar2 < 0 && (uVar2 & 0x3ff) != 0);
  }
  else {
    atmo_pressure = CAL_sensor_baro_fallback;
  }
  if (tps_both_fault == false) {
    sVar3 = (short)tps_max >> 2;
    if (sVar3 < 0) {
      tps = 0;
    }
    else if (sVar3 < 0x100) {
      tps = (u8_factor_1_255)sVar3;
    }
    else {
      tps = 255;
    }
  }
  else {
    tps = CAL_tps_fallback;
  }
  uVar2 = (uint)sensor_adc_map * (uint)CAL_sensor_map_gain;
  map = CAL_sensor_map_offset +
        (short)((int)uVar2 >> 10) + (ushort)((int)uVar2 < 0 && (uVar2 & 0x3ff) != 0);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked
// Computes 8-bit engine speed value

uint8_t compute_engine_speed_byte(void)

{
  int iVar1;
  
  iVar1 = ((uint)CAL_ecu_engine_speed_byte_coefficient << 3) / (uint)engine_speed_period -
          (uint)CAL_ecu_engine_speed_byte_offset;
  if (iVar1 < 0x100) {
    if (iVar1 < 0) {
      iVar1 = 0;
    }
  }
  else {
    iVar1 = 0xff;
  }
  return (uint8_t)iVar1;
}



// Returns constant 0x102 (unused)

undefined2 stub_return_0x102(void)

{
  return 0x102;
}



// Returns 0 (unused)

undefined2 stub_return_zero_1(void)

{
  return 0;
}



// Returns 0 (unused)

undefined2 stub_return_zero_2(void)

{
  return 0;
}



// O2 heater current monitoring and protection (500us task)

void o2_heater_500us(void)

{
  uint uVar1;
  ushort uVar2;
  
  uVar2 = REG_QADCB_RJURR4;
  uVar1 = ((uint)uVar2 * 0x2693) / 0x3ff;
  pre_o2_heater_current = (u16_current_mA)uVar1;
  uVar2 = REG_QADCB_RJURR6;
  post_o2_heater_current = (u16_current_mA)(((uint)uVar2 * 0x2693) / 0x3ff);
  if (((uint)CAL_sensor_o2_heater_max < (uVar1 & 0xffff)) && (!pre_o2_heater_is_off)) {
    uVar2 = REG_MPIOSMDR;
    REG_MPIOSMDR = uVar2 & 0xfffe;
    pre_o2_heater_is_off = true;
    pre_o2_heater_timer = 100;
    diag_set(0x19,0x18);
  }
  if ((CAL_sensor_o2_heater_max < post_o2_heater_current) && (post_o2_heater_is_off == false)) {
    uVar2 = REG_MPIOSMDR;
    REG_MPIOSMDR = uVar2 & 0xfffb;
    post_o2_heater_is_off = true;
    post_o2_heater_timer = 100;
    diag_set(0x1a,0x19);
  }
  if (o2_heater_warmup_state == 2) {
    if (((pre_o2_heater_current < CAL_sensor_o2_heater_max) && (pre_o2_heater_timer == 0)) &&
       (pre_o2_heater_is_off == false)) {
      uVar2 = REG_MPIOSMDR;
      REG_MPIOSMDR = uVar2 & 0xfffe | 1;
      diag_set(0x19,0);
    }
    if (((post_o2_heater_current < CAL_sensor_o2_heater_max) && (post_o2_heater_timer == 0)) &&
       (post_o2_heater_is_off == false)) {
      uVar2 = REG_MPIOSMDR;
      REG_MPIOSMDR = uVar2 & 0xfffb | 4;
      diag_set(0x1a,0);
    }
    if ((pre_o2_heater_is_off != false) && (pre_o2_heater_timer == 0)) {
      pre_o2_heater_is_off = false;
      uVar2 = REG_MPIOSMDR;
      REG_MPIOSMDR = uVar2 & 0xfffe | 1;
    }
    if ((post_o2_heater_is_off != false) && (post_o2_heater_timer == 0)) {
      post_o2_heater_is_off = false;
      uVar2 = REG_MPIOSMDR;
      REG_MPIOSMDR = uVar2 & 0xfffb | 4;
    }
  }
  return;
}



// Sorts a 10-element uint16_t array ascending (selection sort); used by the OBD statistics history
// buffers. BUG: the swap temporary is 8-bit (mask at 0x00033c4c) so the smaller element of each
// exchange is written back truncated to its low byte. Arrays staying below 256 are unaffected; the
// P0420 catalyst history (threshold alone is 600) is visibly corrupted in real decram dumps.

void sort10(uint16_t *array)

{
  ushort uVar1;
  byte bVar2;
  byte bVar3;
  
  for (bVar3 = 0; bVar2 = bVar3, bVar3 < 9; bVar3 = bVar3 + 1) {
    for (; bVar2 < 10; bVar2 = bVar2 + 1) {
      if (array[bVar2] < array[bVar3]) {
        uVar1 = array[bVar2];
        array[bVar2] = array[bVar3];
        array[bVar3] = uVar1 & 0xff;
      }
    }
  }
  return;
}



// Initializes QADC-B module for additional analog inputs

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



// WARNING: Inlined function: push_26to31
// WARNING: Inlined function: pop_26to31
// Main ignition advance calculation - base timing, corrections, knock retard

void ignition(void)

{
  byte bVar2;
  int iVar1;
  uint uVar3;
  short sVar4;
  uint uVar5;
  uint uVar6;
  
  bVar2 = lookup_3D_uint8_interpolated
                    (8,8,(ushort)engine_speed_3,
                     (ushort)((int)(uint)sensor_adc_ecu_voltage >> 2) & 0xff,CAL_ign_dwell_base,
                     CAL_ign_dwell_base_X_engine_speed,CAL_ign_dwell_base_Y_car_voltage);
  ign_dwell_time = (ushort)bVar2 << 6;
  if (((vvl_is_high_cam == false) || (CAL_vvl_rpm_enable <= engine_speed_2)) ||
     (load_2 <= CAL_vvl_high_load_enable)) {
    bVar2 = lookup_3D_uint8_interpolated
                      (32,32,(ushort)engine_speed_3,(ushort)load_2,CAL_ign_adv_low_cam_base,
                       CAL_ign_adv_low_cam_base_X_engine_speed,
                       CAL_ign_adv_low_cam_base_Y_engine_load);
    ign_adv_base = bVar2 - 0x28;
    bVar2 = lookup_3D_uint8_interpolated
                      (32,32,(ushort)engine_speed_3,(ushort)load_2,CAL_ign_adv_low_cam_knock_safe,
                       CAL_ign_adv_low_cam_knock_safe_X_engine_speed,
                       CAL_ign_adv_low_cam_knock_safe_Y_engine_load);
  }
  else {
    bVar2 = lookup_3D_uint8_interpolated
                      (8,8,(ushort)engine_speed_3,(ushort)load_2,CAL_ign_adv_high_cam_base,
                       CAL_ign_adv_high_cam_base_X_engine_speed,
                       CAL_ign_adv_high_cam_base_Y_engine_load);
    ign_adv_base = bVar2 - 0x28;
    bVar2 = lookup_3D_uint8_interpolated
                      (8,8,(ushort)engine_speed_3,(ushort)load_2,CAL_ign_adv_high_cam_knock_safe,
                       CAL_ign_adv_high_cam_knock_safe_X_engine_speed,
                       CAL_ign_adv_high_cam_knock_safe_Y_engine_load);
  }
  ign_adv_knock = bVar2 - 0x28;
  if (maf_accumulated_2 < 0x7f8) {
    bVar2 = lookup_3D_uint8_interpolated
                      (8,8,(ushort)((int)(uint)maf_accumulated_2 >> 3) & 0xff,(ushort)tps,
                       CAL_ign_adv_adj2,CAL_ign_adv_adj2_X_maf_accumulated,CAL_ign_adv_adj2_Y_tps);
    ign_adv_adj2 = (ushort)bVar2;
  }
  else {
    ign_adv_adj2 = 0xff;
  }
  ign_adv_smooth_step =
       lookup_3D_uint8_interpolated
                 (8,16,(ushort)engine_speed_3,(short)pps >> 2 & 0xff,CAL_ign_adv_smooth_step,
                  CAL_ign_adv_smooth_step_X_engine_speed,CAL_ign_adv_smooth_step_Y_pps);
  ign_adv_cranking =
       lookup_2D_uint8_interpolated
                 (8,coolant_stop,CAL_ign_adv_cranking,CAL_ign_adv_cranking_X_coolant_stop);
  bVar2 = lookup_2D_uint8_interpolated
                    (16,engine_air_smooth,CAL_ign_adv_adj1,CAL_ign_adv_adj1_X_engine_air);
  ign_adv_adj1 = (i16_angle_1_4deg)(char)(bVar2 ^ 0x80);
  bVar2 = lookup_2D_uint8_interpolated
                    (16,coolant_smooth,CAL_ign_adv_idle_base,CAL_ign_adv_idle_base_X_coolant);
  ign_adv_idle_base = (ushort)bVar2;
  bVar2 = lookup_2D_uint8_interpolated
                    (16,engine_air_smooth,CAL_ign_adv_idle_adj2,CAL_ign_adv_idle_adj2_X_engine_air);
  ign_adv_idle_adj2 = (i16_angle_1_4deg)(char)(bVar2 ^ 0x80);
  bVar2 = lookup_2D_uint8_interpolated
                    (16,engine_speed_3,CAL_ign_adv_adj3,CAL_ign_adv_adj3_X_engine_speed);
  ign_adv_adj3_base = (i16_angle_1_4deg)(char)(bVar2 ^ 0x80);
  ign_adv_adj3_adj =
       lookup_2D_uint8_interpolated
                 (8,coolant_smooth,CAL_ign_adv_adj3_adj,CAL_ign_adv_adj3_adj_X_coolant);
  uVar5 = (int)ign_adv_adj3_base * (uint)ign_adv_adj3_adj;
  ign_adv_adj3 = (short)((int)uVar5 >> 7) + (ushort)((int)uVar5 < 0 && (uVar5 & 0x7f) != 0);
  if (dt_tps_injtip < 0x100) {
    if (dt_tps_injtip < 0) {
      ign_adv_adj4 = lookup_2D_uint8_interpolated
                               (8,0,CAL_ign_adv_adj4,CAL_ign_adv_adj4_X_dt_tps_injtip);
    }
    else {
      ign_adv_adj4 = lookup_2D_uint8_interpolated
                               (8,(uint8_t)dt_tps_injtip,CAL_ign_adv_adj4,
                                CAL_ign_adv_adj4_X_dt_tps_injtip);
    }
  }
  else {
    ign_adv_adj4 = lookup_2D_uint8_interpolated
                             (8,255,CAL_ign_adv_adj4,CAL_ign_adv_adj4_X_dt_tps_injtip);
  }
  if ((CAL_ign_stop_coolant_to_use_adj2_min < coolant_stop) &&
     (coolant_stop < CAL_ign_stop_coolant_to_use_adj2_max)) {
    ign_flags = ign_flags | 0x16;
  }
  else {
    ign_flags = ign_flags & 0xffe9;
  }
  ign_adv_base2 = ign_adv_base;
  if (engine_speed_idle_error < -0x200) {
    bVar2 = lookup_2D_uint8_interpolated
                      (16,0,CAL_ign_adv_idle_adj1,CAL_ign_adv_idle_adj1_X_idle_error);
    ign_adv_idle_adj1 = (short)(char)(bVar2 ^ 0x80);
    bVar2 = lookup_2D_uint8_interpolated
                      (16,0,CAL_ign_adv_idle_adj1_alternative,
                       CAL_ign_adv_idle_adj1_alternative_X_idle_error);
    ign_adv_idle_adj1_alternative = (short)(char)(bVar2 ^ 0x80);
  }
  else if (engine_speed_idle_error < 0x200) {
    uVar5 = (int)engine_speed_idle_error + 0x200;
    bVar2 = lookup_2D_uint8_interpolated
                      (16,(char)((int)uVar5 >> 2) + ((int)uVar5 < 0 && (uVar5 & 3) != 0),
                       CAL_ign_adv_idle_adj1,CAL_ign_adv_idle_adj1_X_idle_error);
    ign_adv_idle_adj1 = (short)(char)(bVar2 ^ 0x80);
    uVar5 = (int)engine_speed_idle_error + 0x200;
    bVar2 = lookup_2D_uint8_interpolated
                      (16,(char)((int)uVar5 >> 2) + ((int)uVar5 < 0 && (uVar5 & 3) != 0),
                       CAL_ign_adv_idle_adj1_alternative,
                       CAL_ign_adv_idle_adj1_alternative_X_idle_error);
    ign_adv_idle_adj1_alternative = (short)(char)(bVar2 ^ 0x80);
  }
  else {
    bVar2 = lookup_2D_uint8_interpolated
                      (16,255,CAL_ign_adv_idle_adj1,CAL_ign_adv_idle_adj1_X_idle_error);
    ign_adv_idle_adj1 = (short)(char)(bVar2 ^ 0x80);
    bVar2 = lookup_2D_uint8_interpolated
                      (16,255,CAL_ign_adv_idle_adj1_alternative,
                       CAL_ign_adv_idle_adj1_alternative_X_idle_error);
    ign_adv_idle_adj1_alternative = (short)(char)(bVar2 ^ 0x80);
  }
  if (CAL_idle_flow_adj5_max < car_speed_smooth) {
    ign_adv_idle_adj1 = ign_adv_idle_adj1_alternative;
  }
  if (DAT_003fd1fa == 0) {
    ign_adv_idle_adj3 = 0;
    if ((ign_adv_idle_adj1_timer != 0) && (ign_adv_idle_adj1 < 0)) {
      uVar5 = abs((int)ign_adv_idle_adj1);
      iVar1 = (int)(short)uVar5 *
              (((uint)ign_adv_idle_adj1_timer * 100) / (uint)CAL_ign_adv_idle_adj1_time);
      iVar1 = iVar1 / 100 + (iVar1 >> 0x1f);
      ign_adv_idle_adj1 = ign_adv_idle_adj1 + ((short)iVar1 - (short)(iVar1 >> 0x1f));
    }
  }
  else {
    ign_adv_idle_adj1_timer = CAL_ign_adv_idle_adj1_time;
    sVar4 = (short)(((int)DAT_003fd1fa * (int)(short)(ushort)DAT_003f93fb) /
                   ((short)(ushort)DAT_003f94be * 10));
    if (-1 < ign_adv_idle_adj1) {
      sVar4 = ign_adv_idle_adj1 + sVar4;
    }
    ign_adv_idle_adj1 = sVar4;
    if (engine_speed_dt < -0xff) {
      bVar2 = lookup_2D_uint8_interpolated
                        (16,0,CAL_ign_adv_idle_adj3,CAL_ign_adv_idle_adj3_X_engine_speed_dt);
      ign_adv_idle_adj3 = (i16_angle_1_4deg)(char)(bVar2 ^ 0x80);
    }
    else if (engine_speed_dt < 0x100) {
      bVar2 = lookup_2D_uint8_interpolated
                        (16,(uint8_t)((engine_speed_dt + 0xff) / 2),CAL_ign_adv_idle_adj3,
                         CAL_ign_adv_idle_adj3_X_engine_speed_dt);
      ign_adv_idle_adj3 = (i16_angle_1_4deg)(char)(bVar2 ^ 0x80);
    }
    else {
      bVar2 = lookup_2D_uint8_interpolated
                        (16,255,CAL_ign_adv_idle_adj3,CAL_ign_adv_idle_adj3_X_engine_speed_dt);
      ign_adv_idle_adj3 = (i16_angle_1_4deg)(char)(bVar2 ^ 0x80);
    }
  }
  if (ign_cranking_timer == 0) {
    if ((idle_flags & 2) == 0) {
      if ((idle_flags & 8) == 0) {
        if ((ign_flags & 0x16) == 0) {
          iVar1 = (int)((int)ign_adv_base2 * (uint)ign_adv_adj_by_tc) / 0xff +
                  ((int)((int)ign_adv_base2 * (uint)ign_adv_adj_by_tc) >> 0x1f);
          ign_adv_final =
               (short)(char)(dev_ign_adv_adj ^ 0x80) / 2 +
               ((ign_adv_adj1 + ((short)iVar1 - (short)(iVar1 >> 0x1f)) + ign_adv_adj3) -
               (ushort)ign_adv_adj4);
        }
        else {
          iVar1 = ((int)ign_adv_base2 * (int)(short)ign_adv_adj2) / 0xff +
                  ((int)ign_adv_base2 * (int)(short)ign_adv_adj2 >> 0x1f);
          iVar1 = (uint)ign_adv_adj_by_tc * (iVar1 - (iVar1 >> 0x1f));
          iVar1 = iVar1 / 0xff + (iVar1 >> 0x1f);
          ign_adv_final =
               (short)(char)(dev_ign_adv_adj ^ 0x80) / 2 +
               ((ign_adv_adj1 + ((short)iVar1 - (short)(iVar1 >> 0x1f)) + ign_adv_adj3) -
               (ushort)ign_adv_adj4);
        }
      }
      else if ((ac_fan_flags & 0x400) == 0) {
        ign_adv_final =
             ign_adv_idle_base +
             ign_adv_idle_adj1 + ign_adv_idle_adj3 + ign_adv_idle_adj2 +
             (short)(char)(dev_ign_adv_adj ^ 0x80) / 2;
      }
      else {
        ign_adv_final =
             ign_adv_idle_base +
             ign_adv_idle_adj1 + ign_adv_idle_adj3 + ign_adv_idle_adj2 +
             (ushort)CAL_ign_adv_idle_adj_ac_on + (short)(char)(dev_ign_adv_adj ^ 0x80) / 2;
      }
    }
    else {
      ign_adv_final = (i16_angle_1_4deg)CAL_ign_adv_dfso;
    }
  }
  else {
    ign_adv_final = (i16_angle_1_4deg)ign_adv_cranking;
  }
  if ((int)ign_adv_final < (int)(char)(CAL_ign_adv_limit_l ^ 0x80)) {
    ign_adv_final = (i16_angle_1_4deg)(char)(CAL_ign_adv_limit_l ^ 0x80);
  }
  ign_adv_cyl[0] =
       ((ign_adv_smooth + (char)(CAL_ign_adv_adj_cyl[0] ^ 0x80)) - (ushort)knock_retard1[0]) -
       (ushort)knock_retard2[0];
  if ((int)ign_adv_cyl[0] < (int)(char)(CAL_ign_adv_limit_l ^ 0x80)) {
    ign_adv_cyl[0] = (i16_angle_1_4deg)(char)(CAL_ign_adv_limit_l ^ 0x80);
  }
  ign_adv_cyl[1] =
       ((ign_adv_smooth + (char)(CAL_ign_adv_adj_cyl[1] ^ 0x80)) - (ushort)knock_retard1[3]) -
       (ushort)knock_retard2[3];
  if ((int)ign_adv_cyl[1] < (int)(char)(CAL_ign_adv_limit_l ^ 0x80)) {
    ign_adv_cyl[1] = (i16_angle_1_4deg)(char)(CAL_ign_adv_limit_l ^ 0x80);
  }
  ign_adv_cyl[2] =
       ((ign_adv_smooth + (char)(CAL_ign_adv_adj_cyl[2] ^ 0x80)) - (ushort)knock_retard1[1]) -
       (ushort)knock_retard2[1];
  if ((int)ign_adv_cyl[2] < (int)(char)(CAL_ign_adv_limit_l ^ 0x80)) {
    ign_adv_cyl[2] = (i16_angle_1_4deg)(char)(CAL_ign_adv_limit_l ^ 0x80);
  }
  ign_adv_cyl[3] =
       ((ign_adv_smooth + (char)(CAL_ign_adv_adj_cyl[3] ^ 0x80)) - (ushort)knock_retard1[2]) -
       (ushort)knock_retard2[2];
  if ((int)ign_adv_cyl[3] < (int)(char)(CAL_ign_adv_limit_l ^ 0x80)) {
    ign_adv_cyl[3] = (i16_angle_1_4deg)(char)(CAL_ign_adv_limit_l ^ 0x80);
  }
  DAT_003f8c68 = (int)((uint)ign_dwell_time * 0xb400) / (int)(uint)engine_speed_period;
  DAT_003f8c6c = ign_adv_cyl[0] * 0x80;
  DAT_003f8c70 = ign_adv_cyl[1] * 0x80;
  DAT_003f8c74 = ign_adv_cyl[2] * 0x80;
  DAT_003f8c78 = ign_adv_cyl[3] * 0x80;
  DAT_003f8c7c = (uint)DAT_003f9366 * 0x80;
  iVar1 = (DAT_003f8c7c + 0x21c00) - (DAT_003f8c68 + ign_adv_cyl[0] * 0x80);
  iVar1 = iVar1 / 0x28 + (iVar1 >> 0x1f);
  DAT_003f8c80 = iVar1 - (iVar1 >> 0x1f);
  if ((int)DAT_003f8c80 < 0) {
    iVar1 = (int)(engine_speed_period * DAT_003f8c80) / 0x480 +
            ((int)(engine_speed_period * DAT_003f8c80) >> 0x1f);
    DAT_003f8c60 = ign_dwell_time + ((short)iVar1 - (short)(iVar1 >> 0x1f));
    DAT_003f8c80 = 0;
  }
  else if ((int)DAT_003f8c80 < 0xe00) {
    DAT_003f8c60 = ign_dwell_time;
  }
  else {
    DAT_003f8c80 = 0xdff;
    DAT_003f8c60 = ign_dwell_time;
  }
  iVar1 = (DAT_003f8c7c + 0x21c00) - (DAT_003f8c68 + ign_adv_cyl[1] * 0x80);
  iVar1 = iVar1 / 0x28 + (iVar1 >> 0x1f);
  DAT_003f8c84 = iVar1 - (iVar1 >> 0x1f);
  if ((int)DAT_003f8c84 < 0) {
    iVar1 = (int)(engine_speed_period * DAT_003f8c84) / 0x480 +
            ((int)(engine_speed_period * DAT_003f8c84) >> 0x1f);
    DAT_003f8c62 = ign_dwell_time + ((short)iVar1 - (short)(iVar1 >> 0x1f));
    DAT_003f8c84 = 0;
  }
  else if ((int)DAT_003f8c84 < 0xe00) {
    DAT_003f8c62 = ign_dwell_time;
  }
  else {
    DAT_003f8c84 = 0xdff;
    DAT_003f8c62 = ign_dwell_time;
  }
  iVar1 = (DAT_003f8c7c + 0x21c00) - (DAT_003f8c68 + ign_adv_cyl[2] * 0x80);
  iVar1 = iVar1 / 0x28 + (iVar1 >> 0x1f);
  DAT_003f8c88 = iVar1 - (iVar1 >> 0x1f);
  if ((int)DAT_003f8c88 < 0) {
    iVar1 = (int)(engine_speed_period * DAT_003f8c88) / 0x480 +
            ((int)(engine_speed_period * DAT_003f8c88) >> 0x1f);
    DAT_003f8c64 = ign_dwell_time + ((short)iVar1 - (short)(iVar1 >> 0x1f));
    DAT_003f8c88 = 0;
  }
  else if ((int)DAT_003f8c88 < 0xe00) {
    DAT_003f8c64 = ign_dwell_time;
  }
  else {
    DAT_003f8c88 = 0xdff;
    DAT_003f8c64 = ign_dwell_time;
  }
  iVar1 = (DAT_003f8c7c + 0x21c00) - (DAT_003f8c68 + ign_adv_cyl[3] * 0x80);
  iVar1 = iVar1 / 0x28 + (iVar1 >> 0x1f);
  DAT_003f8c8c = iVar1 - (iVar1 >> 0x1f);
  if ((int)DAT_003f8c8c < 0) {
    iVar1 = (int)(engine_speed_period * DAT_003f8c8c) / 0x480 +
            ((int)(engine_speed_period * DAT_003f8c8c) >> 0x1f);
    DAT_003f8c66 = ign_dwell_time + ((short)iVar1 - (short)(iVar1 >> 0x1f));
    DAT_003f8c8c = 0;
  }
  else if ((int)DAT_003f8c8c < 0xe00) {
    DAT_003f8c66 = ign_dwell_time;
  }
  else {
    DAT_003f8c8c = 0xdff;
    DAT_003f8c66 = ign_dwell_time;
  }
  sVar4 = (short)((int)DAT_003f8c80 >> 7) +
          (ushort)((int)DAT_003f8c80 < 0 && (DAT_003f8c80 & 0x7f) != 0);
  DAT_003f8c9c = sVar4 + 0x1e;
  if (DAT_003f8c9c < 0) {
    DAT_003f8c9c = sVar4 + 0x66;
  }
  else if (0x48 < DAT_003f8c9c) {
    DAT_003f8c9c = sVar4 + -0x2a;
  }
  if ((DAT_003f8c9c == 0x23) || (DAT_003f8c9c == 0x47)) {
    uVar5 = engine_speed_period / 9;
  }
  else {
    uVar5 = 0;
  }
  iVar1 = (int)DAT_003f8c80 >> 0x1f;
  if ((DAT_003f8c9c == 0x24) || (DAT_003f8c9c == 0)) {
    uVar6 = (iVar1 * 0x80 | DAT_003f8c80 * 0x2000000 + iVar1 >> 0x19) - iVar1;
    uVar3 = uVar6 * 2;
    uVar3 = ((int)uVar3 / 3 + ((int)(uVar3 | uVar6 >> 0x1f) >> 0x1f)) - ((int)uVar3 >> 0x1f);
  }
  else {
    uVar3 = (iVar1 * 0x80 | DAT_003f8c80 * 0x2000000 + iVar1 >> 0x19) - iVar1;
  }
  if ((shutdown_flags & 1) == 0) {
    DAT_003f8020 = ((uVar3 & 0xffff) * 0x100 + crank_tooth_pattern[DAT_003f8c9c]) * 0x10000;
  }
  else {
    DAT_003f8020 = (uint)DAT_003f8c60 +
                   ((uVar3 & 0xffff) * 0x100 + crank_tooth_pattern[DAT_003f8c9c]) * 0x10000 + uVar5;
  }
  sVar4 = (short)((int)DAT_003f8c84 >> 7) +
          (ushort)((int)DAT_003f8c84 < 0 && (DAT_003f8c84 & 0x7f) != 0);
  DAT_003f8c9c = sVar4 + 0xc;
  if (DAT_003f8c9c < 0) {
    DAT_003f8c9c = sVar4 + 0x54;
  }
  else if (0x48 < DAT_003f8c9c) {
    DAT_003f8c9c = sVar4 + -0x3c;
  }
  if ((DAT_003f8c9c == 0x23) || (DAT_003f8c9c == 0x47)) {
    uVar5 = engine_speed_period / 9;
  }
  else {
    uVar5 = 0;
  }
  iVar1 = (int)DAT_003f8c84 >> 0x1f;
  if ((DAT_003f8c9c == 0x24) || (DAT_003f8c9c == 0)) {
    uVar6 = (iVar1 * 0x80 | DAT_003f8c84 * 0x2000000 + iVar1 >> 0x19) - iVar1;
    uVar3 = uVar6 * 2;
    uVar3 = ((int)uVar3 / 3 + ((int)(uVar3 | uVar6 >> 0x1f) >> 0x1f)) - ((int)uVar3 >> 0x1f);
  }
  else {
    uVar3 = (iVar1 * 0x80 | DAT_003f8c84 * 0x2000000 + iVar1 >> 0x19) - iVar1;
  }
  if ((shutdown_flags & 1) == 0) {
    DAT_003f8024 = ((uVar3 & 0xffff) * 0x100 + crank_tooth_pattern[DAT_003f8c9c]) * 0x10000;
  }
  else {
    DAT_003f8024 = (uint)DAT_003f8c62 +
                   ((uVar3 & 0xffff) * 0x100 + crank_tooth_pattern[DAT_003f8c9c]) * 0x10000 + uVar5;
  }
  sVar4 = (short)((int)DAT_003f8c88 >> 7) +
          (ushort)((int)DAT_003f8c88 < 0 && (DAT_003f8c88 & 0x7f) != 0);
  DAT_003f8c9c = sVar4 + -0x18;
  if (DAT_003f8c9c < 0) {
    DAT_003f8c9c = sVar4 + 0x30;
  }
  else if (0x48 < DAT_003f8c9c) {
    DAT_003f8c9c = sVar4 + -0x60;
  }
  if ((DAT_003f8c9c == 0x23) || (DAT_003f8c9c == 0x47)) {
    uVar5 = engine_speed_period / 9;
  }
  else {
    uVar5 = 0;
  }
  iVar1 = (int)DAT_003f8c88 >> 0x1f;
  if ((DAT_003f8c9c == 0x24) || (DAT_003f8c9c == 0)) {
    uVar6 = (iVar1 * 0x80 | DAT_003f8c88 * 0x2000000 + iVar1 >> 0x19) - iVar1;
    uVar3 = uVar6 * 2;
    uVar3 = ((int)uVar3 / 3 + ((int)(uVar3 | uVar6 >> 0x1f) >> 0x1f)) - ((int)uVar3 >> 0x1f);
  }
  else {
    uVar3 = (iVar1 * 0x80 | DAT_003f8c88 * 0x2000000 + iVar1 >> 0x19) - iVar1;
  }
  if ((shutdown_flags & 1) == 0) {
    DAT_003f8028 = ((uVar3 & 0xffff) * 0x100 + crank_tooth_pattern[DAT_003f8c9c]) * 0x10000;
  }
  else {
    DAT_003f8028 = (uint)DAT_003f8c64 +
                   ((uVar3 & 0xffff) * 0x100 + crank_tooth_pattern[DAT_003f8c9c]) * 0x10000 + uVar5;
  }
  sVar4 = (short)((int)DAT_003f8c8c >> 7) +
          (ushort)((int)DAT_003f8c8c < 0 && (DAT_003f8c8c & 0x7f) != 0);
  DAT_003f8c9c = sVar4 + -6;
  if (DAT_003f8c9c < 0) {
    DAT_003f8c9c = sVar4 + 0x42;
  }
  else if (0x48 < DAT_003f8c9c) {
    DAT_003f8c9c = sVar4 + -0x4e;
  }
  DAT_003f8ca0 = crank_tooth_pattern[DAT_003f8c9c];
  if ((DAT_003f8c9c == 0x23) || (DAT_003f8c9c == 0x47)) {
    uVar5 = engine_speed_period / 9;
  }
  else {
    uVar5 = 0;
  }
  iVar1 = (int)DAT_003f8c8c >> 0x1f;
  if ((DAT_003f8c9c == 0x24) || (DAT_003f8c9c == 0)) {
    uVar6 = (iVar1 * 0x80 | DAT_003f8c8c * 0x2000000 + iVar1 >> 0x19) - iVar1;
    uVar3 = uVar6 * 2;
    uVar3 = ((int)uVar3 / 3 + ((int)(uVar3 | uVar6 >> 0x1f) >> 0x1f)) - ((int)uVar3 >> 0x1f);
  }
  else {
    uVar3 = (iVar1 * 0x80 | DAT_003f8c8c * 0x2000000 + iVar1 >> 0x19) - iVar1;
  }
  if ((shutdown_flags & 1) == 0) {
    DAT_003f802c = ((uVar3 & 0xffff) * 0x100 + DAT_003f8ca0) * 0x10000;
  }
  else {
    DAT_003f802c = (uint)DAT_003f8c66 + ((uVar3 & 0xffff) * 0x100 + DAT_003f8ca0) * 0x10000 + uVar5;
  }
  return;
}



// Ignition advance smoothing task (5ms)

void ignition_5ms(void)

{
  if (ign_adv_idle_adj1_timer != 0) {
    ign_adv_idle_adj1_timer = ign_adv_idle_adj1_timer + 255;
  }
  if (((((idle_flags & 8) == 0) && ((dfso_flags & 2) == 0)) ||
      (car_speed_smooth < CAL_idle_flow_adj5_max)) ||
     ((engine_speed_idle_error < 1 ||
      ((int)((int)ign_adv_smooth - (uint)ign_adv_smooth_step) <= (int)ign_adv_final)))) {
    if ((idle_flags & 8) == 0) {
      if ((int)((int)ign_adv_smooth + (uint)ign_adv_smooth_step) < (int)ign_adv_final) {
        ign_adv_smooth_timer = ign_adv_smooth_timer + 1;
        if (9 < ign_adv_smooth_timer) {
          ign_adv_smooth_timer = 0;
          ign_adv_smooth = ign_adv_smooth + (ushort)ign_adv_smooth_step;
        }
      }
      else {
        ign_adv_smooth = ign_adv_final;
      }
    }
    else {
      ign_adv_smooth = ign_adv_final;
    }
  }
  else {
    ign_adv_smooth_timer = ign_adv_smooth_timer + 1;
    if (9 < ign_adv_smooth_timer) {
      ign_adv_smooth_timer = 0;
      ign_adv_smooth = ign_adv_smooth - (ushort)ign_adv_smooth_step;
    }
  }
  if (engine_is_running) {
    if (ign_cranking_timer != 0) {
      ign_cranking_timer = ign_cranking_timer - 1;
    }
  }
  else {
    ign_cranking_timer = (u16_time_5ms)((int)(short)(ushort)CAL_ign_cranking_runtime_max << 1);
  }
  return;
}



// Evaluates misfire counters per cylinder and calls diag_set (200ms)

void misfire_monitor_200ms(void)

{
  if (engine_is_running) {
    if ((ign_feedback_missed_flags & 1) == 0) {
      diag_set(0x1b,0);
    }
    else {
      diag_set(0x1b,0x1a);
      ign_feedback_missed_flags = ign_feedback_missed_flags & 0xfffe;
    }
    if ((ign_feedback_missed_flags & 2) == 0) {
      diag_set(0x1c,0);
    }
    else {
      diag_set(0x1c,0x1b);
      ign_feedback_missed_flags = ign_feedback_missed_flags & 0xfffd;
    }
    if ((ign_feedback_missed_flags & 4) == 0) {
      diag_set(0x1d,0);
    }
    else {
      diag_set(0x1d,0x1c);
      ign_feedback_missed_flags = ign_feedback_missed_flags & 0xfffb;
    }
    if ((ign_feedback_missed_flags & 8) == 0) {
      diag_set(0x1e,0);
    }
    else {
      diag_set(0x1e,0x1d);
      ign_feedback_missed_flags = ign_feedback_missed_flags & 0xfff7;
    }
  }
  else {
    ign_feedback_missed_flags = 0;
    ign_feedback_pending_flags = 0;
    diag_channel[0x1b].result = 0;
    diag_channel[0x1b].state = 0;
    diag_channel[0x1b].confirm_threshold = (uint16_t)CAL_obd_P0351_debounce_threshold;
    diag_channel[0x1b].clear_threshold = 5;
    diag_channel[0x1b].confirm_count = 0;
    diag_channel[0x1b].clear_count = 0;
    diag_channel[0x1c].result = 0;
    diag_channel[0x1c].state = 0;
    diag_channel[0x1c].confirm_threshold = (uint16_t)CAL_obd_P0352_debounce_threshold;
    diag_channel[0x1c].clear_threshold = 5;
    diag_channel[0x1c].confirm_count = 0;
    diag_channel[0x1c].clear_count = 0;
    diag_channel[0x1d].result = 0;
    diag_channel[0x1d].state = 0;
    diag_channel[0x1d].confirm_threshold = (uint16_t)CAL_obd_P0353_debounce_threshold;
    diag_channel[0x1d].clear_threshold = 5;
    diag_channel[0x1d].confirm_count = 0;
    diag_channel[0x1d].clear_count = 0;
    diag_channel[0x1e].result = 0;
    diag_channel[0x1e].state = 0;
    diag_channel[0x1e].confirm_threshold = (uint16_t)CAL_obd_P0354_debounce_threshold;
    diag_channel[0x1e].clear_threshold = 5;
    diag_channel[0x1e].confirm_count = 0;
    diag_channel[0x1e].clear_count = 0;
  }
  return;
}



// Main fuel injection calculation - base pulse width, corrections, enrichment

void injection(void)

{
  short sVar3;
  uint uVar1;
  int iVar2;
  byte bVar5;
  int iVar4;
  
  bVar5 = lookup_2D_uint8_interpolated
                    (16,(uint8_t)((int)(uint)sensor_adc_ecu_voltage >> 2),CAL_inj_time_base,
                     CAL_inj_time_base_X_car_voltage);
  inj_time_base = (ushort)bVar5 * 0x14;
  if ((sensor_fault_flags & 0x31cf) == 0) {
    revlimit_base = 6000;
  }
  else {
    revlimit_base = 6000 - CAL_revlimit_speed_adj_limp_reduced;
  }
  bVar5 = lookup_3D_uint8_interpolated
                    (8,8,(ushort)coolant_smooth,(ushort)revlimit_timer_2,CAL_revlimit_speed_base,
                     CAL_revlimit_speed_base_X_coolant,CAL_revlimit_speed_base_Y_timer);
  revlimit = revlimit_base + (ushort)bVar5 * 10;
  if (((wheel_speed_f_max_2 < tc_min_speed) && ((tc_flags & 0x80) != 0)) &&
     (LEA_tc_launchcontrol_revlimit < revlimit)) {
    revlimit = LEA_tc_launchcontrol_revlimit;
  }
  revlimit_misfire_eval = revlimit - CAL_revlimit_offset_misfire_eval;
  if (dev_inj_angle < 3) {
    inj_angle_1 = lookup_3D_uint8_interpolated
                            (8,8,(ushort)engine_speed_3,(ushort)load_2,CAL_inj_angle,
                             CAL_inj_angle_X_engine_speed,CAL_inj_angle_Y_engine_load);
  }
  else {
    inj_angle_1 = dev_inj_angle;
  }
  bVar5 = lookup_2D_uint8_interpolated
                    (16,coolant_stop,CAL_inj_time_adj_cranking,
                     CAL_inj_time_adj_cranking_X_coolant_stop);
  inj_time_cranking_adj = (uint)bVar5 * 0x100;
  inj_time_cranking = inj_time_cranking_adj + inj_time_base;
  if (0xffff < inj_time_cranking) {
    inj_time_cranking = 65535;
  }
  bVar5 = lookup_3D_uint8_interpolated
                    (16,16,(ushort)engine_speed_3,(ushort)load_2,CAL_inj_afr_base,
                     CAL_inj_afr_base_X_engine_speed,CAL_inj_afr_base_Y_engine_load);
  afr_target = (ushort)bVar5 * 5 + (short)((int)dev_afr_adj << 1) + 500;
  if (afr_target < CAL_stft_afr) {
    DAT_003fd180 = DAT_003fd180 | 1;
    if ((((int)(uint)(ushort)knock_retard2_sum >> 2) - (int)ign_adv_adj1) - (int)ign_adv_adj3 < 1) {
      afr_adj = 0;
    }
    else if ((int)((uint)CAL_inj_afr_adj_per_adv_adj *
                  ((((int)(uint)(ushort)knock_retard2_sum >> 2) - (int)ign_adv_adj1) -
                  (int)ign_adv_adj3)) >> 2 < 0x100) {
      afr_adj = (u8_afr_1_100)
                ((int)((uint)CAL_inj_afr_adj_per_adv_adj *
                      ((((int)(uint)(ushort)knock_retard2_sum >> 2) - (int)ign_adv_adj1) -
                      (int)ign_adv_adj3)) >> 2);
    }
    else {
      afr_adj = 255;
    }
  }
  else {
    DAT_003fd180 = DAT_003fd180 & 0xfe;
    afr_adj = 0;
  }
  bVar5 = lookup_3D_uint8_interpolated
                    (32,32,(ushort)engine_speed_3,(ushort)load_2,CAL_inj_efficiency,
                     CAL_inj_efficiency_X_engine_speed,CAL_inj_efficiency_Y_engine_load);
  sVar3 = (dev_inj_efficiency_adj - 0x80) + (ushort)bVar5;
  if (sVar3 < 0x100) {
    if (sVar3 < 0) {
      inj_efficiency = 0;
    }
    else {
      inj_efficiency = (byte)sVar3;
    }
  }
  else {
    inj_efficiency = 0xff;
  }
  uVar1 = ((uint)inj_efficiency * (uint)CAL_inj_flow_rate) / 200;
  DAT_003fd17c = (undefined2)uVar1;
  inj_fuel_load_needed =
       (ushort)((int)(load_1_smooth * 10000) / (int)((uint)afr_target - (uint)afr_adj));
  if (evap_fuel_load < inj_fuel_load_needed) {
    DAT_003fd190 = inj_fuel_load_needed - evap_fuel_load;
  }
  else {
    DAT_003fd190 = 0;
  }
  inj_time_afr = ((uint)DAT_003fd190 * 10000) / (uVar1 & 0xffff);
  inj_time_adj3 =
       lookup_3D_uint8_interpolated
                 (16,16,(ushort)load_2,(ushort)coolant_smooth,CAL_inj_time_adj3,
                  CAL_inj_time_adj3_X_engine_load,CAL_inj_time_adj3_Y_coolant);
  inj_time_adj2 =
       lookup_2D_uint8_interpolated
                 (16,engine_air_smooth,CAL_inj_time_adj2,CAL_inj_time_adj2_X_engine_air);
  if (maf_accumulated_2 < 0x100) {
    inj_time_adj1 =
         lookup_3D_uint8_interpolated
                   (16,24,(ushort)coolant_stop,maf_accumulated_2 & 0xff,CAL_inj_time_adj1,
                    CAL_inj_time_adj1_X_coolant_stop,CAL_inj_time_adj1_Y_maf_accumulated);
  }
  else {
    inj_time_adj1 =
         lookup_3D_uint8_interpolated
                   (16,24,(ushort)coolant_stop,255,CAL_inj_time_adj1,
                    CAL_inj_time_adj1_X_coolant_stop,CAL_inj_time_adj1_Y_maf_accumulated);
  }
  uVar1 = inj_time_afr * inj_time_adj1;
  uVar1 = (uint)inj_time_adj3 * (((int)uVar1 >> 5) + (uint)((int)uVar1 < 0 && (uVar1 & 0x1f) != 0));
  uVar1 = (uint)inj_time_adj2 * (((int)uVar1 >> 6) + (uint)((int)uVar1 < 0 && (uVar1 & 0x3f) != 0));
  DAT_003fd18c = injtip_in +
                 ((int)uVar1 >> 7) + (uint)((int)uVar1 < 0 && (uVar1 & 0x7f) != 0) + injtip_reactive
                 + injtip_out;
  iVar2 = (DAT_003fd18c * inj_time_adj_by_stft) / 2000 +
          (DAT_003fd18c * inj_time_adj_by_stft >> 0x1f);
  iVar4 = (DAT_003fd18c * inj_time_adj_by_ltft) / 1000 +
          (DAT_003fd18c * inj_time_adj_by_ltft >> 0x1f);
  DAT_003fd184 = DAT_003fd18c + (iVar2 - (iVar2 >> 0x1f)) + (iVar4 - (iVar4 >> 0x1f));
  if (DAT_003fd184 < 0) {
    inj_time_final_1 = (u32_time_us)inj_time_base;
  }
  else {
    inj_time_final_1 = DAT_003fd184 + (uint)inj_time_base + (int)LEA_ltft_zone1_adj;
  }
  if ((int)inj_time_final_1 < 0xa0) {
    inj_time_final_2 = 160;
    DAT_003fd196 = 0;
    inj_duty_cycle = 0;
  }
  else {
    if (0xffff < (int)inj_time_final_1) {
      inj_time_final_1 = 65535;
    }
    DAT_003f8cac = (uint)engine_speed_period * 8 + -500;
    if (DAT_003f8cac < (int)inj_time_final_1) {
      DAT_003fd170 = (uint)DAT_003f8047 + (inj_time_final_1 - DAT_003f8cac) * 4;
      if (DAT_003f8cac < DAT_003fd170) {
        DAT_003fd196 = 100;
        DAT_003fd170 = DAT_003f8cac;
      }
      else {
        DAT_003fd196 = (undefined1)((DAT_003fd170 * 100) / DAT_003f8cac);
      }
      inj_duty_cycle = 100;
    }
    else {
      DAT_003fd170 = 0xa0;
      inj_duty_cycle = (undefined1)((int)(inj_time_final_1 * 100) / DAT_003f8cac);
      DAT_003fd196 = 0;
    }
    inj_time_final_2 = (u16_time_us)inj_time_final_1;
    DAT_003f8044 = (undefined2)DAT_003fd170;
  }
  if ((uint)((int)(uint)engine_speed_1 >> 2) < (uint)revlimit) {
    if ((uint)((int)(uint)engine_speed_1 >> 2) <= (uint)revlimit_misfire_eval) {
      revlimit_flags = revlimit_flags & 0xfffe;
    }
  }
  else {
    revlimit_flags = revlimit_flags | 9;
  }
  if ((int)(uint)engine_speed_1 >> 2 <=
      (int)((uint)revlimit - (uint)CAL_revlimit_offset_reset_timer)) {
    revlimit_flags = revlimit_flags & 0xfff7;
    revlimit_timer_2 = 0;
  }
  if ((((shutdown_flags & 1) == 0) || ((dfso_flags & 1) != 0)) || ((revlimit_flags & 1) != 0)) {
    revlimit_flags = revlimit_flags | 0x10;
  }
  else {
    revlimit_flags = revlimit_flags & 0xffef;
  }
  inj_angle_2 = (u16_angle_1_10deg)(((uint)inj_angle_1 * 0x2d0) / 0xa00);
  return;
}



// Rev limiter state machine (5ms)

void revlimit_5ms(void)

{
  if (((revlimit_flags & 8) == 0) || (0xfe < revlimit_timer_2)) {
    revlimit_timer_1 = 0;
  }
  else {
    revlimit_timer_1 = revlimit_timer_1 + 1;
    if (revlimit_timer_1 == 20) {
      revlimit_timer_1 = 0;
      revlimit_timer_2 = revlimit_timer_2 + 1;
    }
  }
  return;
}



// WARNING: Inlined function: push_20to31
// WARNING: Inlined function: pop_20to31
// Main idle speed control - target calculation and throttle position

void idle(void)

{
  short sVar1;
  short sVar2;
  ushort uVar3;
  byte bVar5;
  ushort uVar4;
  short sVar7;
  uint uVar6;
  uint uVar8;
  int iVar9;
  
  bVar5 = lookup_2D_uint8_interpolated
                    (8,car_speed_smooth,CAL_idle_speed_adj,CAL_idle_speed_adj_X_car_speed);
  idle_speed_adj = (ushort)bVar5 << 2;
  if (DAT_003fd1ec < idle_speed_adj) {
    DAT_003fd1ec = idle_speed_adj;
  }
  bVar5 = lookup_2D_uint8_interpolated
                    (16,coolant_smooth,CAL_idle_speed_base,CAL_idle_speed_base_X_coolant);
  sVar7 = (ushort)bVar5 * 4 + 500;
  sVar1 = LEA_idle_flow_adj1;
  sVar2 = DAT_003fd1ec;
  if ((ac_fan_flags & 0x400) != 0) {
    sVar1 = LEA_idle_flow_adj1_ac_on;
    sVar2 = DAT_003fd1ec + CAL_idle_speed_adj_ac_on;
  }
  idle_speed_target = sVar7 + sVar2 + DAT_003fd1fa;
  uVar8 = (uint)sVar1;
  if (0x5f0 < idle_speed_target) {
    idle_speed_target = 1520;
  }
  engine_speed_idle_error = (short)((int)(uint)engine_speed_1 >> 2) - idle_speed_target;
  DAT_003fd1e2 = idle_speed_target + (ushort)CAL_idle_flow_adj7_enable * 8;
  DAT_003fd1e4 = idle_speed_target + (ushort)CAL_idle_flow_adj7_disable * 8;
  uVar6 = (int)idle_speed_target - 500;
  idle_flow_adj4 =
       lookup_2D_uint8_interpolated
                 (8,(char)((int)uVar6 >> 2) + ((int)uVar6 < 0 && (uVar6 & 3) != 0),
                  CAL_idle_flow_adj4,CAL_idle_flow_adj4_X_idle_speed_target);
  if (maf_accumulated_2 < 0x400) {
    idle_flow_adj4_adj =
         lookup_3D_uint8_interpolated
                   (16,8,(ushort)coolant_smooth,(ushort)((int)(uint)maf_accumulated_2 >> 2) & 0xff,
                    CAL_idle_flow_adj4_adj,CAL_idle_flow_adj4_adj_X_coolant,
                    CAL_idle_flow_adj4_adj_Y_maf_accumulated);
  }
  else {
    idle_flow_adj4_adj =
         lookup_3D_uint8_interpolated
                   (16,8,(ushort)coolant_smooth,255,CAL_idle_flow_adj4_adj,
                    CAL_idle_flow_adj4_adj_X_coolant,CAL_idle_flow_adj4_adj_Y_maf_accumulated);
  }
  if ((short)pps < (short)(ushort)CAL_idle_flow_pps_max) {
    if (vacuum_1 < 0x400) {
      if (vacuum_1 < 0) {
        vacuum_2 = 0;
      }
      else {
        vacuum_2 = vacuum_1 >> 2;
      }
    }
    else {
      vacuum_2 = 255;
    }
  }
  if ((uint)DAT_003fd1e2 < (uint)((int)(uint)engine_speed_1 >> 2)) {
    DAT_003f8cbc = idle_flow_target + idle_flow_adj7;
  }
  else if ((uint)((int)(uint)engine_speed_1 >> 2) < (uint)DAT_003fd1e4) {
    DAT_003f8cbc = idle_flow_target;
  }
  else {
    DAT_003f8cbc = idle_flow_target +
                   (char)(((uint)idle_flow_adj7 *
                          (((int)(uint)engine_speed_1 >> 2) - (uint)DAT_003fd1e4)) /
                         ((uint)DAT_003fd1e2 - (uint)DAT_003fd1e4));
  }
  DAT_003fd1dd = lookup_3D_uint8_interpolated
                           (8,8,(ushort)DAT_003fd1df,vacuum_2 & 0xff,CAL_idle_tps,
                            CAL_idle_tps_X_target_flow,CAL_idle_tps_Y_vacuum);
  if (atmo_pressure < 0x400) {
    uVar4 = atmo_pressure >> 2 & 0xff;
  }
  else {
    uVar4 = 255;
  }
  idle_flow_adj2 =
       lookup_2D_uint8_interpolated
                 (8,(uint8_t)uVar4,CAL_idle_flow_adj2,CAL_idle_flow_adj2_X_atmo_pressure);
  bVar5 = lookup_2D_uint8_interpolated
                    (8,car_speed_smooth,CAL_idle_flow_adj6,CAL_idle_flow_adj6_X_car_speed);
  idle_flow_adj6 = (ushort)bVar5;
  bVar5 = lookup_2D_uint8_interpolated
                    (8,(uint8_t)((int)(uint)sensor_adc_ecu_voltage >> 2),CAL_idle_flow_adj3,
                     CAL_idle_flow_adj3_X_car_voltage);
  idle_flow_adj3 = (short)(char)(bVar5 ^ 0x80);
  DAT_003fd1de = lookup_3D_uint8_interpolated
                           (4,16,uVar4,(ushort)coolant_smooth,CAL_idle_tps_engine_stop,
                            CAL_idle_tps_engine_stop_X_atmo_pressure,
                            CAL_idle_tps_engine_stop_Y_coolant);
  idle_flow_adj7 =
       lookup_2D_uint8_interpolated
                 (16,engine_speed_3,CAL_idle_flow_adj7,CAL_idle_flow_adj7_X_engine_speed);
  if (engine_speed_idle_error < -0x200) {
    bVar5 = lookup_2D_uint8_interpolated
                      (16,0,CAL_idle_flow_adj5,CAL_idle_flow_adj5_X_engine_speed_idle_error);
    idle_flow_adj5 = bVar5 ^ 0x80;
  }
  else if (engine_speed_idle_error < 0x200) {
    uVar6 = (int)engine_speed_idle_error + 0x200;
    bVar5 = lookup_2D_uint8_interpolated
                      (16,(char)((int)uVar6 >> 2) + ((int)uVar6 < 0 && (uVar6 & 3) != 0),
                       CAL_idle_flow_adj5,CAL_idle_flow_adj5_X_engine_speed_idle_error);
    idle_flow_adj5 = bVar5 ^ 0x80;
  }
  else {
    bVar5 = lookup_2D_uint8_interpolated
                      (16,255,CAL_idle_flow_adj5,CAL_idle_flow_adj5_X_engine_speed_idle_error);
    idle_flow_adj5 = bVar5 ^ 0x80;
  }
  if (engine_speed_idle_error < -0x200) {
    idle_flow_adj8_corr_step =
         lookup_2D_uint8_interpolated
                   (16,0,CAL_idle_flow_adj8_corr_step,
                    CAL_idle_flow_adj8_corr_step_X_engine_speed_idle_error);
  }
  else if (engine_speed_idle_error < 0x200) {
    uVar6 = (int)engine_speed_idle_error + 0x200;
    idle_flow_adj8_corr_step =
         lookup_2D_uint8_interpolated
                   (16,(char)((int)uVar6 >> 2) + ((int)uVar6 < 0 && (uVar6 & 3) != 0),
                    CAL_idle_flow_adj8_corr_step,
                    CAL_idle_flow_adj8_corr_step_X_engine_speed_idle_error);
  }
  else {
    idle_flow_adj8_corr_step =
         lookup_2D_uint8_interpolated
                   (16,255,CAL_idle_flow_adj8_corr_step,
                    CAL_idle_flow_adj8_corr_step_X_engine_speed_idle_error);
  }
  uVar4 = (ushort)DAT_003f94be * 10;
  sVar7 = sVar7 + DAT_003fd1ec + (ushort)DAT_003f93fc;
  if (((((int)idle_speed_target + (int)(short)(ushort)DAT_003f93fc < (int)(uint)engine_speed_2) &&
       (dt_engine_speed < (int)-(uint)DAT_003f93fd)) ||
      (uVar3 = DAT_003fd1fa, (idle_flags & 8) == 0)) &&
     ((DAT_003fd1e0 = CAL_idle_flow_base, uVar3 = uVar4,
      (int)(uint)engine_speed_2 <= (int)(short)uVar4 + (int)sVar7 && (engine_is_running != false))))
  {
    if ((int)sVar7 < (int)(uint)engine_speed_2) {
      uVar3 = engine_speed_2 - sVar7;
    }
    else {
      uVar3 = DAT_003fd1fa;
      if ((idle_flags & 8) == 0) {
        uVar3 = (ushort)DAT_003f93fc;
      }
    }
  }
  DAT_003fd1fa = uVar3;
  if ((ac_fan_flags & 0x400) == 0) {
    idle_flow_adj_ac = 0;
  }
  else {
    idle_flow_adj_ac =
         lookup_2D_uint8_interpolated
                   (8,ac_on_timer,CAL_idle_flow_adj_ac,CAL_idle_flow_adj_ac_X_on_time);
  }
  if ((ac_fan_flags & 0x800) == 0) {
    idle_flow_adj_fan_low = 0;
  }
  else {
    idle_flow_adj_fan_low =
         lookup_2D_uint8_interpolated
                   (8,fan_low_on_timer,CAL_idle_flow_adj_fan_low,CAL_idle_flow_adj_fan_low_X_on_time
                   );
  }
  if ((ac_fan_flags & 0x1000) == 0) {
    idle_flow_adj_fan_high = 0;
  }
  else {
    idle_flow_adj_fan_high =
         lookup_2D_uint8_interpolated
                   (8,fan_high_on_timer,CAL_idle_flow_adj_fan_high,
                    CAL_idle_flow_adj_fan_high_X_on_time);
  }
  if ((((short)pps < (short)(ushort)CAL_idle_flow_pps_max) &&
      ((uint)((int)(uint)engine_speed_1 >> 2) < (uint)DAT_003fd1e4)) && (engine_is_running != false)
     ) {
    uVar4 = idle_flags & 0xfffd | 8;
    if ((car_speed_smooth < CAL_idle_flow_adj5_max) || (engine_speed_idle_error < 0)) {
      idle_flow_adj5_or_zero = (i16_flow_100mg_s)(char)idle_flow_adj5;
    }
    else {
      idle_flow_adj5_or_zero = 0;
    }
    if (DAT_003fd1e8 == 0) {
      DAT_003fd1e8 = (ushort)CAL_idle_flow_adj8_corr_time_between_step;
      if ((((DAT_003fd1ec == 0) && (DAT_003fd1fa == 0)) || (engine_speed_idle_error < 0)) &&
         ((0 < idle_flow_adj8 || (-200 < engine_speed_idle_error)))) {
        if (engine_speed_idle_error < 0) {
          idle_flow_adj8 = idle_flow_adj8 + (uint)idle_flow_adj8_corr_step;
        }
        else if (0 < engine_speed_idle_error) {
          idle_flow_adj8 = idle_flow_adj8 - (uint)idle_flow_adj8_corr_step;
        }
        if ((int)((idle_flow_adj8 >> 10) +
                 (uint)(idle_flow_adj8 < 0 && (idle_flow_adj8 & 0x3ffU) != 0)) <
            (int)(uint)CAL_idle_flow_adj8_corr_limit_h) {
          if ((int)((idle_flow_adj8 >> 10) +
                   (uint)(idle_flow_adj8 < 0 && (idle_flow_adj8 & 0x3ffU) != 0)) <=
              (int)-(uint)CAL_idle_flow_adj8_corr_limit_l) {
            idle_flow_adj8 = (uint)CAL_idle_flow_adj8_corr_limit_l * -0x400;
          }
        }
        else {
          idle_flow_adj8 = (uint)CAL_idle_flow_adj8_corr_limit_h << 10;
        }
        if ((maf_accumulated_2 < CAL_idle_flow_adj1_corr_maf_accumulated_min) ||
           ((evap_flags & 2) != 0)) {
          uVar4 = idle_flags & 0xfff9 | 8;
        }
        else {
          uVar4 = idle_flags & 0xfffd | 0xc;
          if ((int)(uint)CAL_idle_flow_adj1_corr_max <
              (int)((idle_flow_adj8 >> 10) +
                   (uint)(idle_flow_adj8 < 0 && (idle_flow_adj8 & 0x3ffU) != 0))) {
            if ((ac_fan_flags & 0x400) == 0) {
              uVar6 = (uint)LEA_idle_flow_adj1;
              if (((int)(((int)uVar6 >> 10) + (uint)((int)uVar6 < 0 && (uVar6 & 0x3ff) != 0)) <
                   (int)(short)(ushort)CAL_idle_flow_adj1_corr_limit_h) &&
                 (LEA_idle_flow_adj1 = LEA_idle_flow_adj1 + 1, DAT_002f8232 < LEA_idle_flow_adj1)) {
                DAT_002f8232 = LEA_idle_flow_adj1;
              }
            }
            else {
              uVar6 = (uint)LEA_idle_flow_adj1_ac_on;
              if (((int)(((int)uVar6 >> 10) + (uint)((int)uVar6 < 0 && (uVar6 & 0x3ff) != 0)) <
                   (int)(short)(ushort)CAL_idle_flow_adj1_corr_limit_h) &&
                 (LEA_idle_flow_adj1_ac_on = LEA_idle_flow_adj1_ac_on + 1,
                 DAT_002f822e < LEA_idle_flow_adj1_ac_on)) {
                DAT_002f822e = LEA_idle_flow_adj1_ac_on;
              }
            }
          }
          if ((int)((idle_flow_adj8 >> 10) +
                   (uint)(idle_flow_adj8 < 0 && (idle_flow_adj8 & 0x3ffU) != 0)) <
              (int)-(uint)CAL_idle_flow_adj1_corr_min) {
            if ((ac_fan_flags & 0x400) == 0) {
              uVar6 = (uint)LEA_idle_flow_adj1;
              if ((-(int)(short)(ushort)CAL_idle_flow_adj1_corr_limit_l <
                   (int)(((int)uVar6 >> 10) + (uint)((int)uVar6 < 0 && (uVar6 & 0x3ff) != 0))) &&
                 (LEA_idle_flow_adj1 = LEA_idle_flow_adj1 + -1, LEA_idle_flow_adj1 < DAT_002f8234))
              {
                DAT_002f8234 = LEA_idle_flow_adj1;
              }
            }
            else {
              uVar6 = (uint)LEA_idle_flow_adj1_ac_on;
              if ((-(int)(short)(ushort)CAL_idle_flow_adj1_corr_limit_l <
                   (int)(((int)uVar6 >> 10) + (uint)((int)uVar6 < 0 && (uVar6 & 0x3ff) != 0))) &&
                 (LEA_idle_flow_adj1_ac_on = LEA_idle_flow_adj1_ac_on + -1,
                 LEA_idle_flow_adj1_ac_on < DAT_002f8230)) {
                DAT_002f8230 = LEA_idle_flow_adj1_ac_on;
              }
            }
          }
        }
      }
      else {
        idle_flow_adj8 = 0;
      }
    }
  }
  else if ((((uint)((int)(uint)engine_speed_1 >> 2) < (uint)DAT_003fd1e4) &&
           (engine_is_running != false)) && (engine_speed_idle_error < 0)) {
    idle_flow_adj5_or_zero = (i16_flow_100mg_s)(char)idle_flow_adj5;
    idle_flow_adj8 = 0;
    DAT_003fd1e8 = (ushort)CAL_idle_flow_adj8_corr_time_between_step;
    uVar4 = idle_flags & 0xfff7;
  }
  else {
    idle_flow_adj5_or_zero = 0;
    idle_flow_adj8 = 0;
    DAT_003fd1e8 = (ushort)CAL_idle_flow_adj8_corr_time_between_step;
    if (((short)pps < (short)(ushort)CAL_idle_flow_pps_max) &&
       ((uint)DAT_003fd1e4 < (uint)((int)(uint)engine_speed_1 >> 2))) {
      uVar4 = idle_flags & 0xfff7 | 2;
    }
    else {
      uVar4 = idle_flags & 0xfff5;
    }
  }
  idle_flags = uVar4;
  iVar9 = idle_flow_adj8 >> 10;
  if ((idle_flags & 8) == 0) {
    idle_status = 0;
  }
  else if (((idle_flags & 8) == 0) ||
          (maf_accumulated_2 < CAL_idle_flow_adj1_corr_maf_accumulated_min)) {
    idle_status = 1;
  }
  else if (((int)(uint)CAL_idle_flow_adj1_corr_max <
            (int)(iVar9 + (uint)(idle_flow_adj8 < 0 && (idle_flow_adj8 & 0x3ffU) != 0))) ||
          ((int)(iVar9 + (uint)(idle_flow_adj8 < 0 && (idle_flow_adj8 & 0x3ffU) != 0)) <
           (int)-(uint)CAL_idle_flow_adj1_corr_min)) {
    idle_status = 2;
  }
  else if (DAT_003f8048 == 0) {
    idle_status = 4;
  }
  else {
    idle_status = 3;
  }
  iVar9 = (uint)DAT_003fd1e0 +
          ((((int)uVar8 >> 10) + (uint)((int)uVar8 < 0 && (uVar8 & 0x3ff) != 0) +
           (((int)idle_flow_adj3 +
            ((int)((uint)idle_flow_adj4 * (uint)idle_flow_adj4_adj) >> 6) +
            (int)idle_flow_adj5_or_zero + (int)(short)idle_flow_adj6 +
            iVar9 + (uint)(idle_flow_adj8 < 0 && (idle_flow_adj8 & 0x3ffU) != 0) +
            (int)(short)(ushort)idle_flow_adj_ac + (int)(short)(ushort)idle_flow_adj_fan_low +
            (int)(short)(ushort)idle_flow_adj_fan_high) - (int)(char)idle_flow_adj2)) -
          evap_flow / 100);
  if (iVar9 < 0x100) {
    if (iVar9 < 0) {
      idle_flow_target = 0;
    }
    else {
      idle_flow_target = (u8_flow_100mg_s)iVar9;
    }
  }
  else {
    idle_flow_target = 255;
  }
  if (engine_is_running == false) {
    idle_tps_target = (u16_factor_1_1023)DAT_003fd1de;
  }
  else if (DAT_003fd1dd < CAL_idle_tps_limit_h) {
    idle_tps_target = (u16_factor_1_1023)DAT_003fd1dd;
  }
  else {
    idle_tps_target = CAL_idle_tps_limit_h;
  }
  return;
}



// Idle control task (5ms)

void idle_5ms(void)

{
  if (DAT_003fd1df < DAT_003f8cbc) {
    DAT_003fd1df = DAT_003f8cbc;
  }
  else if (DAT_003f8cb8 == 0) {
    DAT_003f8cb8 = CAL_idle_flow_time_between_decrement;
    if ((DAT_003f8cbc < DAT_003fd1df) && (DAT_003fd1df != 0)) {
      DAT_003fd1df = DAT_003fd1df - 1;
    }
  }
  else {
    DAT_003f8cb8 = DAT_003f8cb8 + 255;
  }
  if (DAT_003fd1e8 != 0) {
    DAT_003fd1e8 = DAT_003fd1e8 + -1;
  }
  if (idle_status == 3) {
    DAT_003f8048 = DAT_003f8048 + -1;
  }
  else if (idle_status == 4) {
    DAT_003f8048 = 0;
  }
  else {
    DAT_003f8048 = 6000;
  }
  if (DAT_003f8cb9 == '\0') {
    DAT_003f8cb9 = CAL_idle_speed_time_between_decrement;
    if ((idle_speed_adj < DAT_003fd1ec) && (10 < DAT_003fd1ec)) {
      DAT_003fd1ec = DAT_003fd1ec + -10;
    }
    else {
      DAT_003fd1ec = idle_speed_adj;
    }
    if (DAT_003fd1fa < 0xb) {
      DAT_003fd1fa = 0;
    }
    else {
      DAT_003fd1fa = DAT_003fd1fa + -10;
    }
    if (DAT_003fd1e0 != '\0') {
      DAT_003fd1e0 = DAT_003fd1e0 + -1;
    }
  }
  else {
    DAT_003f8cb9 = DAT_003f8cb9 + 255;
  }
  return;
}



// Computes averaged sensor values with filtering

void adc_avg(void)

{
  ushort uVar1;
  
  uVar1 = REG_TPU3A_CH0_PARAM2;
  if (2 < (uVar1 & 0xff)) {
    DAT_003fe182 = '\0';
    DAT_003fe184 = 0;
    DAT_003fd200 = '\0';
    DAT_003f8b28 = 1;
    DAT_003fe189 = 0;
  }
  uVar1 = REG_TPU3A_CH8_PARAM4;
  if ((uVar1 & 0xff) != 0) {
    wheel_period_rr = 65535;
  }
  uVar1 = REG_TPU3A_CH11_PARAM4;
  if ((uVar1 & 0xff) != 0) {
    wheel_period_fl = 65535;
  }
  uVar1 = REG_TPU3A_CH12_PARAM4;
  if ((uVar1 & 0xff) != 0) {
    wheel_period_fr = 65535;
  }
  uVar1 = REG_TPU3A_CH13_PARAM4;
  if ((uVar1 & 0xff) != 0) {
    wheel_period_rl = 65535;
  }
  uVar1 = REG_TPU3A_CH15_PARAM6;
  if (((uVar1 & 0xff00) == 0) || (DAT_003fe182 != '\0')) {
    if ((DAT_003fd22f == '\x01') &&
       ((uVar1 = REG_TPU3A_CH15_PARAM6, 0xd < uVar1 && (DAT_003fd200 != '\0')))) {
      DAT_003fd22f = '\0';
    }
    sensor_adc_maf2 = make_maf_avg2();
    sensor_adc_maf1 = make_maf_avg1();
    sensor_adc_map = make_map_avg();
  }
  else {
    engine_speed_period = 65535;
    engine_speed_1 = 0;
    engine_is_running = false;
    init_on_crank_tooth(0xffff);
    coolant_stop = lookup_2D_uint8_interpolated_noaxis
                             (3,sensor_adc_coolant,CAL_sensor_coolant_scaling);
    engine_air_stop =
         lookup_2D_uint8_interpolated_noaxis(3,sensor_adc_engine_air,CAL_sensor_engine_air_scaling);
    DAT_003fd65c = lookup_2D_uint8_interpolated_noaxis
                             (4,(ushort)coolant_stop,CAL_obd_P0128_wait_air_mass);
    DAT_003fd228 = 0;
    sensor_adc_maf1 = read_adc_maf();
    sensor_adc_maf2 = sensor_adc_maf1;
    sensor_adc_map = read_adc_map();
    reset_maf_avg(sensor_adc_maf1);
    if (DAT_003fd22f == '\0') {
      DAT_003fd22f = '\x01';
      revlimit_flags = 4;
    }
  }
  engine_speed_3 = compute_engine_speed_byte();
  if (engine_speed_period == 65535) {
    engine_speed_1 = 0;
  }
  else {
    engine_speed_1 = (u16_rspeed_1_4rpm)(60000000 / engine_speed_period);
  }
  engine_speed_2 = (u16_rspeed_rpm)((int)(uint)engine_speed_1 >> 2);
  if (((engine_speed_period < CAL_misc_engine_running_enable) && (DAT_003f8086 == 0)) &&
     (uVar1 = REG_TPU3A_CH15_PARAM6, (uVar1 & 0xff00) == 0)) {
    engine_is_running = true;
  }
  else if (CAL_misc_engine_running_disable < engine_speed_period) {
    engine_is_running = false;
  }
  return;
}



// Initializes cranking fuel enrichment parameters

void init_cranking_injection(void)

{
  ushort uVar1;
  uint uVar2;
  ushort uVar3;
  
  if (DAT_003f9374 == '\0') {
    uVar2 = 100;
  }
  else {
    uVar2 = inj_time_cranking & 0xffff;
  }
  uVar3 = (ushort)uVar2;
  if (uVar2 < 0x8000) {
    DAT_003f92f8 = 0;
    DAT_003fe178 = 4;
  }
  else {
    DAT_003f92f8 = uVar3 + 0x8001;
    uVar3 = 0x7fff;
    DAT_003fe178 = 8;
  }
  uVar1 = REG_CFSR2_B;
  REG_CFSR2_B = uVar1 & 0xfff0;
  uVar1 = REG_CFSR3_B;
  REG_CFSR3_B = uVar1 & 0xf0ff;
  uVar1 = REG_CFSR3_B;
  REG_CFSR3_B = uVar1 & 0xf0ff;
  uVar1 = REG_CFSR3_B;
  REG_CFSR3_B = uVar1 & 0xff0f;
  uVar1 = REG_CPR1_B;
  REG_CPR1_B = uVar1 & 0xfcff;
  uVar1 = REG_CPR1_B;
  REG_CPR1_B = uVar1 & 0xff3f;
  uVar1 = REG_CPR1_B;
  REG_CPR1_B = uVar1 & 0xffcf;
  uVar1 = REG_CPR1_B;
  REG_CPR1_B = uVar1 & 0xfff3;
  uVar1 = REG_CFSR3_B;
  REG_CFSR3_B = uVar1 & 0xff0f | 0xe0;
  uVar1 = REG_HSQR1_B;
  REG_HSQR1_B = uVar1 & 0xfff3;
  REG_TPU3B_CH1_PARAM0 = 0x89;
  REG_TPU3B_CH1_PARAM1 = uVar3;
  REG_TPU3B_CH1_PARAM2 = 0xec;
  uVar1 = REG_CPR1_B;
  REG_CPR1_B = uVar1 & 0xfff3 | 0xc;
  uVar1 = REG_HSRR1_B;
  REG_HSRR1_B = uVar1 & 0xfff3 | 4;
  do {
    uVar1 = REG_HSRR1_B;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR3_B;
  REG_CFSR3_B = uVar1 & 0xf0ff | 0xe00;
  uVar1 = REG_HSQR1_B;
  REG_HSQR1_B = uVar1 & 0xffcf;
  REG_TPU3B_CH2_PARAM0 = 0x89;
  REG_TPU3B_CH2_PARAM1 = uVar3;
  REG_TPU3B_CH2_PARAM2 = 0xec;
  uVar1 = REG_CPR1_B;
  REG_CPR1_B = uVar1 & 0xffcf | 0x30;
  uVar1 = REG_HSRR1_B;
  REG_HSRR1_B = uVar1 & 0xffcf | 0x10;
  do {
    uVar1 = REG_HSRR1_B;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR3_B;
  REG_CFSR3_B = uVar1 & 0xfff | 0xe000;
  uVar1 = REG_HSQR1_B;
  REG_HSQR1_B = uVar1 & 0xff3f;
  REG_TPU3B_CH3_PARAM0 = 0x89;
  REG_TPU3B_CH3_PARAM1 = uVar3;
  REG_TPU3B_CH3_PARAM2 = 0xec;
  uVar1 = REG_CPR1_B;
  REG_CPR1_B = uVar1 & 0xff3f | 0xc0;
  uVar1 = REG_HSRR1_B;
  REG_HSRR1_B = uVar1 & 0xff3f | 0x40;
  do {
    uVar1 = REG_HSRR1_B;
  } while (uVar1 != 0);
  uVar1 = REG_CFSR2_B;
  REG_CFSR2_B = uVar1 & 0xfff0 | 0xe;
  uVar1 = REG_HSQR1_B;
  REG_HSQR1_B = uVar1 & 0xfcff;
  REG_TPU3B_CH4_PARAM0 = 0x89;
  REG_TPU3B_CH4_PARAM1 = uVar3;
  REG_TPU3B_CH4_PARAM2 = 0xec;
  uVar3 = REG_CPR1_B;
  REG_CPR1_B = uVar3 & 0xfcff | 0x300;
  uVar3 = REG_HSRR1_B;
  REG_HSRR1_B = uVar3 & 0xfcff | 0x100;
  do {
    uVar3 = REG_HSRR1_B;
  } while (uVar3 != 0);
  DAT_003f92dc = DAT_003f92f8;
  DAT_003f92f4 = DAT_003f92f8;
  DAT_003f92f6 = DAT_003f92f8;
  return;
}



// Initializes engine speed buffers used by on_crank_tooth

void init_on_crank_tooth(uint16_t param_1)

{
  short sVar1;
  
  for (sVar1 = 7; 0 < sVar1; sVar1 = sVar1 + -1) {
    (&DAT_003f8056)[sVar1] = param_1;
  }
  DAT_003f8056 = param_1;
  for (sVar1 = 0xf; 0 < sVar1; sVar1 = sVar1 + -1) {
    engine_speed_period_history[sVar1] = param_1;
  }
  engine_speed_period_history[0] = param_1;
  return;
}



// Processes crank tooth timing, updates engine speed calculations

void on_crank_tooth(void)

{
  ushort uVar2;
  int iVar1;
  uint uVar3;
  
  if (engine_speed_period < CAL_misc_engine_running_disable) {
    if (DAT_003f8086 != 0) {
      DAT_003f8086 = DAT_003f8086 - 1;
    }
  }
  else {
    DAT_003f8086 = (ushort)CAL_misc_engine_running_crank_tooth_min;
  }
  DAT_003fda9c = DAT_003fbff0;
  if (injtip_reactive != 0) {
    uVar3 = injtip_reactive * CAL_injtip_catalyst_adj_fadeout;
    injtip_reactive = ((int)uVar3 >> 8) + (uint)((int)uVar3 < 0 && (uVar3 & 0xff) != 0);
  }
  if (((dfso_flags & 1) != 0) && (dfso_count < 0x7ff)) {
    dfso_count = dfso_count + 1;
  }
  uVar2 = REG_TPU3A_CH15_PARAM6;
  if ((uVar2 & 0xff00) == 0) {
    for (DAT_003f8cc0 = 7; 0 < (short)DAT_003f8cc0; DAT_003f8cc0 = DAT_003f8cc0 + -1) {
      (&DAT_003f8056)[(short)DAT_003f8cc0] = (&DAT_003f8056)[(short)DAT_003f8cc0 + -1];
    }
    DAT_003f8056 = engine_speed_period;
    if (DAT_003f8cc2 < 3) {
      DAT_003f8cc2 = DAT_003f8cc2 + 1;
    }
    else {
      DAT_003f8cc2 = 0;
      for (DAT_003f8cc0 = 0xf; 0 < (short)DAT_003f8cc0; DAT_003f8cc0 = DAT_003f8cc0 + -1) {
        engine_speed_period_history[(short)DAT_003f8cc0] =
             engine_speed_period_history[(short)DAT_003f8cc0 + -1];
      }
      engine_speed_period_history[0] = engine_speed_period;
      uVar2 = (ushort)CAL_ign_adv_idle_adj3_engine_speed_dt_age;
      iVar1 = ((int)((uint)engine_speed_period_history[(short)uVar2 + 2] +
                    (uint)engine_speed_period_history[(short)uVar2 + 3] +
                    (uint)engine_speed_period_history[(short)uVar2 + 4] +
                    (uint)engine_speed_period_history[(short)uVar2 + 5]) >> 2) -
              ((int)((uint)engine_speed_period +
                    (uint)engine_speed_period_history[1] + (uint)engine_speed_period_history[2] +
                    (uint)engine_speed_period_history[3]) >> 2);
      iVar1 = iVar1 / 0xf + (iVar1 >> 0x1f);
      engine_speed_dt = iVar1 - (iVar1 >> 0x1f);
    }
    iVar1 = 0;
    if (CAL_sensor_engine_speed_period_avg_size < 8) {
      if (CAL_sensor_engine_speed_period_avg_size == 0) {
        engine_speed_period_avg = engine_speed_period;
      }
      else {
        for (DAT_003f8cc0 = (ushort)CAL_sensor_engine_speed_period_avg_size; 0 < (short)DAT_003f8cc0
            ; DAT_003f8cc0 = DAT_003f8cc0 - 1) {
          iVar1 = iVar1 + (uint)(&DAT_003f8056)[(short)DAT_003f8cc0];
        }
        engine_speed_period_avg =
             (u16_time_4us)(iVar1 / (int)(uint)CAL_sensor_engine_speed_period_avg_size);
      }
    }
    else {
      CAL_sensor_engine_speed_period_avg_size = 7;
    }
    DAT_003f8cc0 = (ushort)CAL_sensor_dt_engine_speed_age;
    if (7 < DAT_003f8cc0) {
      DAT_003f8cc0 = 7;
    }
    iVar1 = (60000000 / DAT_003f8056 - 60000000 / (&DAT_003f8056)[(short)DAT_003f8cc0]) *
            (uint)DAT_003f8056 * (int)(short)DAT_003f8cc0;
    iVar1 = iVar1 / 2500000 + (iVar1 >> 0x1f);
    dt_engine_speed = iVar1 - (iVar1 >> 0x1f);
  }
  return;
}



// Transient fuel compensation (tip-in/tip-out enrichment)

void injtip(void)

{
  ushort uVar1;
  uint uVar2;
  byte bVar3;
  
  switch(car_gear_current) {
  case '\0':
    injtip_in_gear = CAL_injtip_in_adj_gears[0];
    break;
  case '\x01':
    injtip_in_gear = CAL_injtip_in_adj_gears[1];
    break;
  case '\x02':
    injtip_in_gear = CAL_injtip_in_adj_gears[2];
    break;
  case '\x03':
    injtip_in_gear = CAL_injtip_in_adj_gears[3];
    break;
  case '\x04':
    injtip_in_gear = CAL_injtip_in_adj_gears[4];
    break;
  case '\x05':
    injtip_in_gear = CAL_injtip_in_adj_gears[5];
    break;
  case '\x06':
    injtip_in_gear = CAL_injtip_in_adj_gears_6;
    break;
  default:
    injtip_in_gear = CAL_injtip_in_adj_gears[0];
  }
  injtip_in_adj2 =
       lookup_2D_uint8_interpolated
                 (16,engine_speed_3,CAL_injtip_in_adj2,CAL_injtip_in_adj2_X_engine_speed);
  injtip_in_speed =
       lookup_2D_uint8_interpolated
                 (16,engine_speed_3,CAL_injtip_in_adj1,CAL_injtip_in_adj1_X_engine_speed);
  injtip_in_coolant =
       lookup_2D_uint8_interpolated
                 (16,coolant_smooth,CAL_injtip_in_adj3,CAL_injtip_in_adj3_X_coolant);
  injtip_out_adj2 =
       lookup_2D_uint8_interpolated
                 (16,engine_speed_3,CAL_injtip_out_adj2,CAL_injtip_out_adj2_X_engine_speed);
  injtip_out_speed =
       lookup_2D_uint8_interpolated
                 (16,engine_speed_3,CAL_injtip_out_adj1,CAL_injtip_out_adj1_X_engine_speed);
  injtip_out_coolant =
       lookup_2D_uint8_interpolated
                 (16,coolant_smooth,CAL_injtip_out_adj3,CAL_injtip_out_adj3_X_coolant);
  DAT_003fd268 = dt_tps_injtip;
  if (dt_tps_injtip < 0) {
    uVar2 = -(int)dt_tps_injtip * (uint)injtip_out_speed;
    uVar2 = (uint)injtip_out_coolant *
            (((int)uVar2 >> 7) + (uint)((int)uVar2 < 0 && (uVar2 & 0x7f) != 0));
    DAT_003fd264 = (uint)CAL_injtip_time_base *
                   (((int)uVar2 >> 6) + (uint)((int)uVar2 < 0 && (uVar2 & 0x3f) != 0));
    DAT_003fd260 = 0;
  }
  else {
    uVar2 = (int)dt_tps_injtip * (uint)injtip_in_speed;
    uVar2 = (uint)injtip_in_coolant *
            (((int)uVar2 >> 7) + (uint)((int)uVar2 < 0 && (uVar2 & 0x7f) != 0));
    uVar2 = (uint)injtip_in_gear *
            (((int)uVar2 >> 6) + (uint)((int)uVar2 < 0 && (uVar2 & 0x3f) != 0));
    DAT_003fd260 = (uint)CAL_injtip_time_base *
                   (((int)uVar2 >> 7) + (uint)((int)uVar2 < 0 && (uVar2 & 0x7f) != 0));
    DAT_003fd264 = 0;
  }
  if (engine_is_running == false) {
    injtip_out = 0;
    injtip_in = 0;
  }
  else {
    injtip_in = DAT_003fd260;
    injtip_out = DAT_003fd264;
  }
  dfso_delay = lookup_2D_uint8_interpolated
                         (4,(uint8_t)((short)pps >> 2),CAL_dfso_delay,CAL_dfso_delay_X_pps);
  if (((((uint)CAL_dfso_engine_speed_enable < (uint)((int)(uint)engine_speed_1 >> 2)) &&
       ((uint)CAL_dfso_runtime_min * 10 < engine_runtime)) &&
      (CAL_dfso_coolant_enable < coolant_smooth)) &&
     (((CAL_dfso_car_speed_enable < car_speed_smooth || (car_speed_smooth == 0)) &&
      ((short)pps < (short)(ushort)CAL_dfso_pps_enable)))) {
    if (((DAT_003fcff0 == 0) && (injtip_out == 0)) ||
       (uVar1 = dfso_flags | 2, car_gear_current == 0)) {
      uVar1 = dfso_flags | 3;
    }
  }
  else if (((((uint)((int)(uint)engine_speed_1 >> 2) <= (uint)CAL_dfso_engine_speed_disable) ||
            ((car_speed_smooth <= CAL_dfso_car_speed_disable && (car_speed_smooth != 0)))) ||
           (coolant_smooth < CAL_dfso_coolant_disable)) ||
          (uVar1 = dfso_flags, (short)(ushort)CAL_dfso_pps_disable <= (short)pps)) {
    if ((dfso_flags & 1) != 0) {
      bVar3 = lookup_2D_uint8_interpolated_noaxis(1,dfso_count,CAL_injtip_catalyst_adj);
      injtip_reactive = (uint)CAL_injtip_time_base * (uint)bVar3;
      DAT_003fcff0 = (ushort)dfso_delay;
    }
    dfso_count = 0;
    uVar1 = dfso_flags & 0xfffc;
  }
  dfso_flags = uVar1;
  return;
}



// Variable Valve Timing control logic

void vvt(void)

{
  uint uVar1;
  byte bVar2;
  byte bVar3;
  ushort uVar4;
  
  if (dev_vvt_angle < 4) {
    if (vvl_is_high_cam) {
      bVar3 = lookup_3D_uint8_interpolated
                        (16,16,(ushort)engine_speed_3,(ushort)load_2,CAL_vvt_adv_high_cam_base,
                         CAL_vvt_adv_high_cam_base_X_engine_speed,
                         CAL_vvt_adv_high_cam_base_Y_engine_load);
    }
    else {
      bVar3 = lookup_3D_uint8_interpolated
                        (16,16,(ushort)engine_speed_3,(ushort)load_2,CAL_vvt_adv_low_cam_base,
                         CAL_vvt_adv_low_cam_base_X_engine_speed,
                         CAL_vvt_adv_low_cam_base_Y_engine_load);
    }
    bVar2 = lookup_2D_uint8_interpolated
                      (16,coolant_smooth,CAL_vvt_adv_adj,CAL_vvt_adv_adj_X_coolant);
    uVar4 = (ushort)bVar3 - (ushort)bVar2;
    if ((short)uVar4 < 0x14) {
      uVar4 = 0x14;
    }
  }
  else {
    uVar4 = (ushort)dev_vvt_angle;
  }
  bVar3 = lookup_2D_uint8_interpolated
                    (8,coolant_stop,CAL_vvt_runtime_min,CAL_vvt_runtime_min_X_coolant_stop);
  vvt_runtime_min = (ushort)bVar3 * 0x14;
  if ((((vvt_runtime_min < engine_runtime) && ((sensor_fault_flags & 0x20) == 0)) &&
      (vvt_rest_pos_measured == true)) && (vvt_rest_pos_fault == false)) {
    vvt_target = uVar4;
    if (vvl_is_high_cam == true) {
      if (0xac < (short)uVar4) {
        vvt_target = 172;
      }
    }
    else if (vvl_is_high_cam == false) {
      if (0xa0 < (short)uVar4) {
        vvt_target = 160;
      }
    }
    else if (0xa0 < (short)uVar4) {
      vvt_target = 160;
    }
    vvt_diff = vvt_target_smooth - vvt_pos;
    uVar1 = (int)vvt_diff * (int)CAL_vvt_ctrl_p_gain;
    vvt_ctrl_p = (short)(uVar1 >> 8) + (ushort)((int)uVar1 < 0 && (uVar1 & 0xff) != 0);
    vvt_output = (int)vvt_ctrl_p + (vvt_ctrl_i >> 8);
    if (vvt_output < 0x191) {
      if (vvt_output < -400) {
        vvt_output = -400;
      }
    }
    else {
      vvt_output = 400;
    }
    vvt_duty_cycle = (short)(vvt_output >> 1) + 400;
  }
  else if (vvt_rest_pos_measured == false) {
    if (engine_runtime < vvt_runtime_min) {
      if (vvt_cam_updated == true) {
        vvt_cam_updated = false;
        if (vvt_rest_pos_count == 0) {
          vvt_rest_pos_max = vvt_pos;
          vvt_rest_pos_min = vvt_pos;
        }
        else if (vvt_rest_pos_max < vvt_pos) {
          vvt_rest_pos_max = vvt_pos;
        }
        else if (vvt_pos < vvt_rest_pos_min) {
          vvt_rest_pos_min = vvt_pos;
        }
        vvt_rest_pos_sum = vvt_rest_pos_sum + vvt_pos;
        vvt_rest_pos_count = vvt_rest_pos_count + 1;
      }
    }
    else {
      if (vvt_rest_pos_count == 0) {
        vvt_rest_pos_avg = 0;
      }
      else {
        vvt_rest_pos_avg = vvt_rest_pos_sum / vvt_rest_pos_count;
      }
      uVar1 = abs(vvt_rest_pos_avg);
      vvt_rest_pos_fault = (int)(uint)CAL_vvt_rest_pos_threshold < (int)uVar1;
      vvt_rest_pos_measured = true;
    }
    vvt_duty_cycle = 0;
    vvt_ctrl_p = 0;
    vvt_ctrl_i = 0;
    vvt_output = 0;
  }
  else {
    vvt_duty_cycle = 0;
    vvt_ctrl_p = 0;
    vvt_ctrl_i = 0;
    vvt_output = 0;
    if ((sensor_fault_flags & 0x20) != 0) {
      vvt_pos = 0;
    }
    vvt_target_smooth = vvt_pos;
  }
  if (obd_mode_0x2F_state == '\t') {
    uVar1 = (uint)CAL_vvt_period * (uint)obd_mode_0x2F_value >> 8;
  }
  else {
    uVar1 = (uint)CAL_vvt_period * (uint)vvt_duty_cycle >> 10;
  }
  set_vvt_pwm(uVar1 & 0xffff);
  return;
}



// Variable Valve Lift control logic

void vvl(void)

{
  uint uVar1;
  
  if ((CAL_vvl_coolant_enable < coolant_smooth) &&
     (((CAL_vvl_rpm_high_load_enable < engine_speed_2 && (CAL_vvl_high_load_enable < load_2)) ||
      (CAL_vvl_rpm_enable < engine_speed_2)))) {
    vvl_duty_cycle = CAL_vvl_duty_cycle_engaged;
    vvl_is_high_cam = true;
  }
  else if ((coolant_smooth < CAL_vvl_coolant_disable) ||
          (((engine_speed_2 < CAL_vvl_rpm_disable && (load_2 < CAL_vvl_high_load_disable)) ||
           (engine_speed_2 < CAL_vvl_rpm_high_load_disable)))) {
    vvl_duty_cycle = CAL_vvl_duty_cycle_disengaged;
    vvl_is_high_cam = false;
  }
  if (obd_mode_0x2F_state == '\n') {
    uVar1 = (uint)CAL_vvl_period * (uint)obd_mode_0x2F_value >> 8;
  }
  else {
    uVar1 = (uint)CAL_vvl_period * (uint)vvl_duty_cycle >> 0xb;
  }
  set_vvl_pwm(uVar1 & 0xffff);
  return;
}



// VVT control task (5ms)

void vvt_5ms(void)

{
  if ((((engine_runtime <= vvt_runtime_min) || ((sensor_fault_flags & 0x20) != 0)) ||
      (!vvt_rest_pos_measured)) || (vvt_rest_pos_fault)) {
    vvt_target_reached = false;
  }
  else {
    vvt_timer = vvt_timer + 1;
    if (vvt_target_reached) {
      vvt_target_smooth = vvt_target;
    }
    if (vvt_timer == 10) {
      vvt_timer = 0;
      if ((vvt_target_smooth != vvt_target) && (!vvt_target_reached)) {
        if (vvt_target_smooth < vvt_target) {
          vvt_target_smooth = vvt_target_smooth + 1;
        }
        else if (vvt_target < vvt_target_smooth) {
          vvt_target_smooth = vvt_target_smooth + -1;
        }
        if (vvt_target_smooth == vvt_target) {
          vvt_target_reached = true;
        }
      }
      vvt_ctrl_i = vvt_ctrl_i + (int)vvt_diff * (int)CAL_vvt_ctrl_i_gain;
      if (vvt_ctrl_i < 0x19001) {
        if (vvt_ctrl_i < -0x19000) {
          vvt_ctrl_i = -102400;
        }
      }
      else {
        vvt_ctrl_i = (int32_t)&DAT_00019000;
      }
    }
  }
  return;
}



// Sets VVL solenoid PWM duty cycle

void set_vvl_pwm(ushort param_1)

{
  if ((LEA_obd_P2649_flags & 4) == 0) {
    REG_TPU3B_CH9_PARAM2 = param_1;
  }
  else {
    REG_TPU3B_CH9_PARAM2 = 0;
  }
  return;
}



// Sets VVT solenoid PWM duty cycle

void set_vvt_pwm(ushort param_1)

{
  if ((LEA_obd_P0077_flags & 4) == 0) {
    REG_TPU3B_CH7_PARAM2 = param_1;
  }
  else {
    REG_TPU3B_CH7_PARAM2 = 0;
  }
  return;
}



// ECU shutdown sequence

void shutdown(void)

{
  ushort uVar1;
  byte bVar2;
  
  if ((uint)sensor_adc_ign < (uint)CAL_ecu_ign_min << 2) {
    shutdown_flags = shutdown_flags | 8;
  }
  else if ((shutdown_flags & 8) != 0) {
    fuelpump_timer = CAL_ecu_fuelpump_prime;
    shutdown_flags = shutdown_flags & 0xfff7;
  }
  if ((fuelpump_timer == 0) || ((shutdown_flags & 1) == 0)) {
    L9822E_outputs = L9822E_outputs & 0xfe;
  }
  else {
    L9822E_outputs = L9822E_outputs | 1;
  }
  if ((uint)sensor_adc_ign < (uint)CAL_ecu_ign_min << 2) {
    shutdown_flags = shutdown_flags & 0xffee;
    if ((engine_speed_1 == 0) && (shutdown_delay_2 == 0)) {
      if (eeprom_saved == 0) {
        eeprom_wp_pin_enable();
        eeprom_save();
        eeprom_saved = 1;
      }
      uVar1 = REG_MPWMSM16_SCR;
      REG_MPWMSM16_SCR = uVar1 & 0xf7ff;
      eeprom_wp_pin_disable();
    }
  }
  else {
    shutdown_flags = shutdown_flags | 1;
    uVar1 = REG_MPWMSM16_SCR;
    REG_MPWMSM16_SCR = uVar1 & 0xf7ff | 0x800;
    if (CAL_misc_use_tmap) {
      bVar2 = lookup_3D_uint8_fixed
                        (8,8,intake_air_smooth,coolant_smooth,CAL_ecu_shutdown_delay_X_engine_air,
                         CAL_ecu_shutdown_delay_Y_coolant,CAL_ecu_shutdown_delay);
    }
    else {
      bVar2 = lookup_3D_uint8_fixed
                        (8,8,engine_air_smooth,coolant_smooth,CAL_ecu_shutdown_delay_X_engine_air,
                         CAL_ecu_shutdown_delay_Y_coolant,CAL_ecu_shutdown_delay);
    }
    shutdown_delay_1 = (ushort)bVar2 * 5;
    shutdown_delay_2 = (uint)shutdown_delay_1 * 200;
  }
  if (((shutdown_flags & 1) == 0) || (CAL_ecu_startrelay_runtime_max <= engine_runtime)) {
    L9822E_outputs = L9822E_outputs & 0x7f;
  }
  else if ((LEA_ecu_VIN[0xb] == 'B') || (LEA_ecu_VIN[0xb] == 'M')) {
    uVar1 = REG_MPIOSMDR;
    if ((uVar1 >> 7 & 1) == 0) {
      L9822E_outputs = L9822E_outputs | 0x80;
    }
    else {
      L9822E_outputs = L9822E_outputs & 0x7f;
    }
  }
  else {
    L9822E_outputs = L9822E_outputs | 0x80;
  }
  return;
}



// AC compressor clutch control logic

void ac_compressor(void)

{
  ushort uVar1;
  
  if ((short)(ushort)CAL_ac_pps_disable < (short)pps >> 2) {
    ac_fan_flags = ac_fan_flags | 0x80;
  }
  else if (tps < CAL_ac_tps_enable) {
    ac_fan_flags = ac_fan_flags & 0xffffff7f;
  }
  if (CAL_ac_coolant_disable < coolant_smooth) {
    ac_fan_flags = ac_fan_flags | 0x100;
  }
  else if (coolant_smooth < CAL_ac_coolant_enable) {
    ac_fan_flags = ac_fan_flags & 0xfffffeff;
  }
  if (CAL_ac_engine_speed_disable < engine_speed_3) {
    ac_fan_flags = ac_fan_flags | 0x200;
  }
  else if (engine_speed_3 < CAL_ac_engine_speed_enable) {
    ac_fan_flags = ac_fan_flags & 0xfffffdff;
  }
  if (CAL_ac_car_speed_disable < car_speed_smooth) {
    ac_fan_flags = ac_fan_flags | 0x4000;
  }
  else if (engine_speed_3 < CAL_ac_car_speed_enable) {
    ac_fan_flags = ac_fan_flags & 0xffffbfff;
  }
  if ((ac_fan_flags & 0x80) == 0) {
    DAT_003fcffc = (ushort)CAL_ac_pps_disable_time_min * 0x14;
  }
  if (((CAL_ac_runtime_min < engine_runtime) && ((ac_fan_flags & 0x4300) == 0)) &&
     (((ac_fan_flags & 0x80) == 0 || (((ac_fan_flags & 0x80) != 0 && (DAT_003fcffc == 0)))))) {
    uVar1 = REG_MPIOSMDR;
    if ((short)uVar1 < 0) {
      ac_on_timer = 0;
      ac_fan_flags = ac_fan_flags & 0xfffffbff;
      DAT_003fcff8 = (ushort)CAL_ac_user_disable_time_min;
      if (DAT_003fcffa == 0) {
        L9822E_outputs = L9822E_outputs & 0xef;
      }
    }
    else {
      ac_fan_flags = ac_fan_flags | 0x400;
      DAT_003fcffa = (ushort)CAL_ac_user_enable_time_min;
      if (DAT_003fcff8 == 0) {
        L9822E_outputs = L9822E_outputs | 0x10;
      }
    }
  }
  else {
    L9822E_outputs = L9822E_outputs & 0xef;
    DAT_003fcff8 = (ushort)CAL_ac_user_disable_time_min;
    DAT_003fcffa = (ushort)CAL_ac_user_enable_time_min;
    ac_fan_flags = ac_fan_flags & 0xfffffbff;
    ac_on_timer = 0;
  }
  return;
}



// Calculates current gear from speed and RPM

void gear_determination(void)

{
  if (car_speed_smooth == 0) {
    car_gear_current = 0;
  }
  else {
    ratio = (uint)((int)(uint)engine_speed_1 >> 2) / (uint)car_speed_smooth;
    if ((ratio < CAL_misc_gears[0]) || (CAL_misc_gears[1] < ratio)) {
      if ((ratio < CAL_misc_gears[2]) || (CAL_misc_gears[3] < ratio)) {
        if ((ratio < CAL_misc_gears[4]) || (CAL_misc_gears[5] < ratio)) {
          if ((ratio < CAL_misc_gears[6]) || (CAL_misc_gears[7] < ratio)) {
            if ((ratio < CAL_misc_gears[8]) || (CAL_misc_gears[9] < ratio)) {
              if ((ratio < CAL_misc_gears_6[0]) || (CAL_misc_gears_6[1] < ratio)) {
                if (car_gear_current != 0) {
                  uint16_t_003fd2a6 = uint16_t_003fd2a6 | 1;
                }
                car_gear_current = 0;
              }
              else {
                if (car_gear_current != 6) {
                  uint16_t_003fd2a6 = uint16_t_003fd2a6 | 1;
                }
                car_gear_current = 6;
              }
            }
            else {
              if (car_gear_current != 5) {
                uint16_t_003fd2a6 = uint16_t_003fd2a6 | 1;
              }
              car_gear_current = 5;
            }
          }
          else {
            if (car_gear_current != 4) {
              uint16_t_003fd2a6 = uint16_t_003fd2a6 | 1;
            }
            car_gear_current = 4;
          }
        }
        else {
          if (car_gear_current != 3) {
            uint16_t_003fd2a6 = uint16_t_003fd2a6 | 1;
          }
          car_gear_current = 3;
        }
      }
      else {
        if (car_gear_current != 2) {
          uint16_t_003fd2a6 = uint16_t_003fd2a6 | 1;
        }
        car_gear_current = 2;
      }
    }
    else {
      if (car_gear_current != 1) {
        uint16_t_003fd2a6 = uint16_t_003fd2a6 | 1;
      }
      car_gear_current = 1;
    }
  }
  return;
}



// Coolant recirculation pump control

void recirculation_pump(void)

{
  if (obd_mode_0x2F_state == '\x14') {
    if (obd_mode_0x2F_value == '\0') {
      L9822E_outputs = L9822E_outputs & 0xfd;
    }
    else {
      L9822E_outputs = L9822E_outputs | 2;
    }
  }
  else if (engine_speed_1 == 0) {
    if (coolant_smooth < CAL_misc_recirculation_pump_stop_enable) {
      if (coolant_smooth <= CAL_misc_recirculation_pump_stop_disable) {
        ac_fan_flags = ac_fan_flags & 0xffff7fff;
        L9822E_outputs = L9822E_outputs & 0xfd;
      }
    }
    else {
      ac_fan_flags = ac_fan_flags | 0x8000;
      L9822E_outputs = L9822E_outputs | 2;
    }
  }
  else {
    ac_fan_flags = ac_fan_flags & 0xffff7fff;
    L9822E_outputs = L9822E_outputs & 0xfd;
  }
  return;
}



// Radiator fan control based on coolant temperature

void fan_control(void)

{
  uint uVar1;
  
  if (engine_speed_1 == 0) {
    if (coolant_smooth < CAL_fan_low_stop_enable) {
      uVar1 = ac_fan_flags & 0xffffffdf;
      if (coolant_smooth <= CAL_fan_low_stop_disable) {
        uVar1 = ac_fan_flags & 0xfffeffdf;
      }
    }
    else {
      uVar1 = ac_fan_flags & 0xffffffdf | 0x10000;
    }
  }
  else if (coolant_smooth < CAL_fan_low_enable) {
    uVar1 = ac_fan_flags & 0xfffeffff;
    if (coolant_smooth <= CAL_fan_low_disable) {
      uVar1 = ac_fan_flags & 0xfffeffdf;
    }
  }
  else {
    uVar1 = ac_fan_flags & 0xfffeffff | 0x20;
  }
  ac_fan_flags = uVar1;
  if (((car_speed_smooth < CAL_fan_car_speed_disable) &&
      ((((ac_fan_flags & 0x20) != 0 || ((sensor_fault_flags & 3) != 0)) ||
       ((L9822E_outputs & 0x10) != 0)))) ||
     ((((ac_fan_flags & 0x10000) != 0 && ((ac_fan_flags & 0x8000) != 0)) ||
      ((ac_fan_flags & 0x1000) != 0)))) {
    ac_fan_flags = ac_fan_flags | 0x800;
    if (CAL_fan_low_stop_time_min <= fan_low_stop_timer) {
      L9822E_outputs = L9822E_outputs | 8;
    }
  }
  else {
    ac_fan_flags = ac_fan_flags & 0xfffff7ff;
    fan_low_stop_timer = 0;
    L9822E_outputs = L9822E_outputs & 0xf7;
    fan_low_on_timer = 0;
  }
  if (coolant_smooth < CAL_fan_high_enable) {
    if (coolant_smooth <= CAL_fan_high_disable) {
      ac_fan_flags = ac_fan_flags & 0xfffffff7;
    }
  }
  else {
    ac_fan_flags = ac_fan_flags | 8;
  }
  if (coolant_smooth < CAL_fan_high_ac_enable) {
    if (coolant_smooth <= CAL_fan_high_ac_disable) {
      ac_fan_flags = ac_fan_flags & 0xffffffef;
    }
  }
  else {
    ac_fan_flags = ac_fan_flags | 0x10;
  }
  if (((car_speed_smooth < CAL_fan_car_speed_disable) && (engine_speed_1 != 0)) &&
     (((fan_high_stop_user_timer != 0 || ((ac_fan_flags & 8) != 0)) ||
      ((((L9822E_outputs & 0x10) != 0 && ((ac_fan_flags & 0x10) != 0)) ||
       ((sensor_fault_flags & 3) != 0)))))) {
    ac_fan_flags = ac_fan_flags | 0x1000;
    if (CAL_fan_high_stop_time_min <= fan_high_stop_timer) {
      L9822E_outputs = L9822E_outputs | 4;
    }
  }
  else {
    ac_fan_flags = ac_fan_flags & 0xffffefff;
    fan_high_stop_timer = 0;
    L9822E_outputs = L9822E_outputs & 0xfb;
    fan_high_on_timer = 0;
  }
  if (sensor_adc_ac_fan_request < 0x200) {
    fan_high_stop_user_timer = (ushort)CAL_fan_high_stop_user_delay * 200;
  }
  return;
}



// Updates variable pointer I/O for external tool communication

void dev_varptr_io_update(void)

{
  ushort uVar1;
  
  DAT_003fd2ad = (L9822E_outputs & 8) != 0;
  DAT_003fd2ae = (L9822E_outputs & 4) != 0;
  DAT_003fd2af = (L9822E_outputs & 0x10) != 0;
  DAT_003fd2b0 = (L9822E_outputs & 2) != 0;
  uVar1 = REG_MPWMSM16_SCR;
  REG_MPWMSM16_SCR = uVar1 & 0x7fff | 0x8000;
  DAT_003fd2b1 = 1;
  uVar1 = REG_MPIOSMDR;
  DAT_003fd2b2 = -1 < (short)uVar1;
  DAT_003fd2b3 = (uint)CAL_ecu_ign_min << 2 <= (uint)sensor_adc_ign;
  DAT_003fd2b4 = sensor_adc_ac_fan_request < 0x200;
  uVar1 = REG_MPIOSMDR;
  DAT_003fd2bd = (uVar1 >> 2 & 1) == 1;
  uVar1 = REG_MPIOSMDR;
  DAT_003fd2bc = (uVar1 & 1) == 1;
  return;
}



// Sends engine data to instrument cluster via CAN

void send_cluster_data(void)

{
  byte bVar1;
  
  bVar1 = lookup_2D_uint8_fixed
                    (8,car_gear_current,CAL_misc_shift_lights_before_revlimit_X_car_gear_current);
  DAT_003f8cf0 = revlimit + (ushort)bVar1 * -10;
  if (DAT_003f8cf0 < engine_speed_2) {
    ac_fan_flags = ac_fan_flags | 0x40000;
  }
  else if ((int)(uint)engine_speed_2 <
           (int)((uint)DAT_003f8cf0 - (uint)CAL_misc_shift_lights_margin)) {
    ac_fan_flags = ac_fan_flags & 0xfffbffff;
  }
  if (fuel_level < 0xe) {
    DAT_003fd2ac = 0;
  }
  else if (fuel_level < 0xab) {
    DAT_003fd2ac = (u8_factor_1_255)(((fuel_level - 0xe & 0xffff) * 0xff) / 0x9c);
  }
  else {
    DAT_003fd2ac = 255;
  }
  if ((((tc_flags & 0x20) == 0) && (engine_speed_1 != 0)) || (LEA_tc_button_fitted != true)) {
    cluster_data.lights_flags[0] = 0;
  }
  else {
    cluster_data.lights_flags[0] = 8;
  }
  if (obd_mode_0x2F_state == '\x17') {
    if (obd_mode_0x2F_value != '\0') {
      cluster_data.lights_flags[0] = cluster_data.lights_flags[0] | 4;
    }
  }
  else if (sensor_adc_oil_pressure < 0x200) {
    cluster_data.lights_flags[0] = cluster_data.lights_flags[0] | 4;
  }
  if ((ac_fan_flags & 0x40000) != 0) {
    cluster_data.lights_flags[0] = cluster_data.lights_flags[0] | 1;
  }
  if (obd_mode_0x2F_state == '\x11') {
    if (obd_mode_0x2F_value != '\0') {
      cluster_data.lights_flags[0] = cluster_data.lights_flags[0] | 2;
    }
  }
  else if ((obd_mil_flags & 8) != 0) {
    cluster_data.lights_flags[0] = cluster_data.lights_flags[0] | 2;
  }
  bVar1 = car_speed_smooth;
  if (obd_mode_0x2F_state == '\v') {
    bVar1 = DAT_003fc005;
  }
  cluster_data._0_2_ = (ushort)bVar1 << 8;
  if (obd_mode_0x2F_state == '\f') {
    cluster_data.rpm = obd_mode_0x2F_RPM;
  }
  else if (DAT_003f8802 == 0) {
    cluster_data.rpm = LEA_tc_launchcontrol_revlimit;
  }
  else {
    cluster_data.rpm = engine_speed_2;
  }
  cluster_data.fuel_level = DAT_003fd2ac;
  cluster_data.temp_coolant = coolant_smooth;
  cluster_data.lights_flags[1] = 0;
  can_a_send_cluster(&cluster_data);
  return;
}



// Airbox flap control for cold air intake

void airbox_flap(void)

{
  if (obd_mode_0x2F_state == '\x16') {
    if (obd_mode_0x2F_value == '\0') {
      L9822E_outputs = L9822E_outputs & 0xbf;
    }
    else {
      L9822E_outputs = L9822E_outputs | 0x40;
    }
  }
  else if (engine_speed_2 < CAL_misc_airbox_flap_disable) {
    L9822E_outputs = L9822E_outputs | 0x40;
  }
  else if (CAL_misc_airbox_flap_enable <= engine_speed_2) {
    L9822E_outputs = L9822E_outputs & 0xbf;
  }
  return;
}



// Builds and sends cluster data over CAN-B - 100ms rate assumed from ISR call site

void cluster_task_100ms(void)

{
  if (fan_high_stop_user_timer != 0) {
    fan_high_stop_user_timer = fan_high_stop_user_timer - 1;
  }
  send_cluster_data();
  return;
}



// Computes CRC16 using lookup table for calibration and learned data integrity

uint16_t CRC16(char *data,ushort size)

{
  uint uVar1;
  
  uVar1 = 0;
  for (; size != 0; size = size - 1) {
    watchdog_retrigger();
    uVar1 = (int)uVar1 >> 8 ^ (uint)CRC16_lookup[(uVar1 ^ (byte)*data) & 0xff];
    data = (char *)((byte *)data + 1);
  }
  return (uint16_t)uVar1;
}



// Calculates engine load from MAF and Alpha-N table

void engine_load(void)

{
  u32_load_mg_stroke uVar1;
  uint uVar2;
  byte bVar3;
  byte bVar4;
  int iVar5;
  uint uVar6;
  
  maf_flow_2 = lookup_2D_uint16_interpolated
                         (32,sensor_adc_maf2,CAL_sensor_maf_scaling,CAL_sensor_maf_scaling_X_signal)
  ;
  maf_flow_1 = lookup_2D_uint16_interpolated
                         (32,sensor_adc_maf1,CAL_sensor_maf_scaling,CAL_sensor_maf_scaling_X_signal)
  ;
  maf_flow_diff = maf_flow_1 - maf_flow_2;
  if ((int)(uint)DAT_003fd2fe < (int)atmo_pressure) {
    vacuum_1 = atmo_pressure - DAT_003fd2fe;
    if (0x3ff < vacuum_1) {
      vacuum_1 = 1023;
    }
  }
  else {
    vacuum_1 = 0;
  }
  bVar3 = lookup_3D_uint8_interpolated
                    (16,16,(ushort)engine_speed_3,(ushort)tps,LEA_load_alphaN_adj,
                     LEA_load_alphaN_adj_X_engine_speed,LEA_load_alphaN_adj_Y_tps);
  load_alphaN_adj = (u16_factor_1_100)bVar3;
  DAT_003fd30a = lookup_3D_uint8_get_address
                           (16,16,(ushort)engine_speed_3,(ushort)tps,
                            LEA_load_alphaN_adj_X_engine_speed,LEA_load_alphaN_adj_Y_tps);
  load_use_alphaN_tps_min =
       lookup_2D_uint8_interpolated
                 (16,engine_speed_3,CAL_load_use_alphaN_tps_min,
                  CAL_load_use_alphaN_tps_min_X_engine_speed);
  bVar3 = lookup_2D_uint8_interpolated
                    (16,tps,CAL_load_alphaN_engine_stop,CAL_load_alphaN_engine_stop_X_tps);
  bVar4 = lookup_3D_uint8_interpolated
                    (16,16,(ushort)engine_speed_3,(ushort)tps,CAL_load_alphaN_base,
                     CAL_load_alphaN_base_X_engine_speed,CAL_load_alphaN_base_Y_tps);
  DAT_003fd320 = (ushort)bVar4 << 2;
  if (engine_is_running == false) {
    iVar5 = (uint)bVar3 * 4 * (int)atmo_pressure;
    iVar5 = iVar5 / 0x3f5 + (iVar5 >> 0x1f);
    load_alphaN = ((iVar5 - (iVar5 >> 0x1f)) * 0x12a) /
                  (((int)((uint)engine_air_smooth * 5) >> 3) + 0xe9);
  }
  else {
    iVar5 = (uint)bVar4 * 4 * (int)(short)load_alphaN_adj;
    iVar5 = iVar5 / 100 + (iVar5 >> 0x1f);
    iVar5 = (int)atmo_pressure * (iVar5 - (iVar5 >> 0x1f));
    iVar5 = iVar5 / 0x3f5 + (iVar5 >> 0x1f);
    load_alphaN = ((iVar5 - (iVar5 >> 0x1f)) * 0x12a) /
                  (((int)((uint)engine_air_smooth * 5) >> 3) + 0xe9);
  }
  iVar5 = (uint)engine_speed_period_avg * ((int)((uint)maf_flow_1 + (uint)maf_flow_2) >> 1);
  iVar5 = iVar5 / 10 + (iVar5 >> 0x1f);
  uVar6 = iVar5 - (iVar5 >> 0x1f);
  uVar2 = uVar6 * 2;
  iVar5 = (int)uVar2 / 10000 + ((int)(uVar2 | uVar6 >> 0x1f) >> 0x1f);
  load_maf = iVar5 - (iVar5 >> 0x1f);
  uVar2 = (((uint)evap_flow * (uint)engine_speed_period_avg) / 100 << 1) / 10000;
  DAT_003fd356 = (undefined2)uVar2;
  load_diff = (short)load_maf - (short)load_alphaN;
  if (load_maf != 0) {
    load_alphaN_maf_error = (u8_factor_1_100)((int)(load_alphaN * 100) / (int)load_maf);
  }
  DAT_003fd322 = (undefined2)((((load_diff * 10000) / (int)(uint)engine_speed_period_avg) * 10) / 2)
  ;
  if ((((int)dt_tps_target_1 < -(int)(short)CAL_load_use_alphaN_dt_tps_target_1_negative_min) ||
      ((short)CAL_load_use_alphaN_dt_tps_target_1_positive_min < dt_tps_target_1)) ||
     ((load_use_alphaN_tps_min < tps && ((idle_flags & 8) == 0)))) {
    DAT_003fd326 = CAL_load_use_alphaN_timer;
  }
  if (((engine_is_running == false) || ((sensor_fault_flags & 0x10) != 0)) ||
     ((DAT_003fd326 != 0 &&
      ((int)(uint)engine_speed_2 < (int)(short)CAL_load_use_alphaN_engine_speed_max)))) {
    load_use_alphaN = 1;
    uVar1 = load_alphaN;
  }
  else {
    load_use_alphaN = 0;
    uVar1 = load_maf;
  }
  load_1 = uVar1 + uVar2;
  if ((int)load_1_smooth >> 2 < 0xff) {
    load_2 = (u8_load_4mg_stroke)((int)load_1_smooth >> 2);
  }
  else {
    load_2 = 255;
  }
  iVar5 = (int)(load_1_smooth * 100) / (int)(uint)CAL_load_possible_max_mode22;
  if ((short)iVar5 < 0x100) {
    load_5 = (u8_factor_1_100)iVar5;
  }
  else {
    load_5 = 255;
  }
  DAT_003f8cfa = lookup_2D_uint8_interpolated
                           (16,engine_speed_3,CAL_load_possible_max,
                            CAL_load_possible_max_X_engine_speed);
  if ((int)load_1_smooth >> 2 < (int)(uint)DAT_003f8cfa) {
    load_3 = (u8_factor_1_255)
             (((int)(load_1_smooth * 0x3f5) / (int)atmo_pressure << 6) / (int)(uint)DAT_003f8cfa);
  }
  else {
    load_3 = 255;
  }
  if ((int)load_1_smooth < (int)(uint)CAL_load_possible_max_absolute) {
    load_4 = (u8_factor_1_255)
             ((int)(load_1_smooth * 0xff) / (int)(uint)CAL_load_possible_max_absolute);
  }
  else {
    load_4 = 255;
  }
  bVar3 = lookup_2D_uint8_interpolated(16,engine_speed_3,&DAT_003fa328,&DAT_003fa318);
  DAT_003fd30e = (ushort)bVar3 << 1;
  bVar3 = lookup_2D_uint8_interpolated(16,engine_speed_3,&DAT_003fa348,&DAT_003fa338);
  DAT_003fd310 = bVar3 + 0x99;
  uVar2 = 0x6aa4 / (((int)((uint)engine_air_smooth * 5) >> 3) + 0xe9U);
  DAT_003fd32c = (char)uVar2;
  iVar5 = (atmo_pressure * 100) / 0x3f5 + (atmo_pressure * 100 >> 0x1f);
  DAT_003fd32d = (char)iVar5 - (char)(iVar5 >> 0x1f);
  DAT_003fd2fe = (short)(((uint)DAT_003fd30e * (uint)DAT_003fd32d) / 100) +
                 (short)((int)(load_1_smooth * 0x9392) /
                        (int)((uint)(ushort)(bVar3 + 0x99) * (uVar2 & 0xff)));
  return;
}



// EVAP purge state machine - manages canister purge sequence

void evap_state_machine(void)

{
  if (((((((evap_flags & 0x100) == 0) || ((DAT_003fd580 & 0x1000) != 0)) ||
        ((DAT_003fd580 & 0x8000) != 0)) &&
       ((((DAT_003fd580 & 4) == 0 || ((evap_flags & 1) == 0)) && ((DAT_003fd580 & 1) == 0)))) ||
      (CAL_evap_purge_mode == 1)) &&
     (((CAL_evap_purge_mode != 2 && (DAT_003f8d1e == 0)) &&
      ((((misfire_flags & 0x20) == 0 &&
        ((((fuel_system_status & 2) != 0 && ((DAT_003fd580 & 0x400) == 0)) &&
         ((LEA_obd_P0441_flags & 4) == 0)))) &&
       (((LEA_obd_P0444_flags & 4) == 0 && ((LEA_obd_P0445_flags & 4) == 0)))))))) {
    evap_flags = evap_flags | 2;
  }
  else if ((fuel_system_status & 2) == 0) {
    if (((fuel_system_status & 0x404) == 0) || (DAT_003f8d22 == 0)) {
      evap_flags = evap_flags & 0xfffd;
    }
  }
  else {
    evap_flags = evap_flags & 0xfffd;
  }
  if (DAT_003f80bc == 0) {
    evap_flags = evap_flags & 0xff7f;
  }
  else {
    evap_flags = evap_flags | 0x80;
  }
  if ((dfso_flags & 2) == 0) {
    evap_flags = evap_flags & 0xffdf;
  }
  else {
    evap_flags = evap_flags | 0x20;
  }
  if (((DAT_003f8d1e == 0) && ((DAT_003fd580 & 0x400) == 0)) &&
     (((evap_flags & 0x20) == 0 || ((evap_flags & 0x80) == 0)))) {
    evap_flags = evap_flags & 0xffbf;
  }
  else {
    evap_flags = evap_flags | 0x40;
  }
  if (!engine_is_running) {
    DAT_003f8d1e = (ushort)CAL_evap_engine_start_delay << 3;
    DAT_003f8d26 = (ushort)CAL_evap_restart_delay << 4;
  }
  if ((DAT_003fd180 & 1) == 0) {
    DAT_003f8d22 = CAL_evap_closedloop_delay;
  }
  if ((closedloop_flags & 0x10) == 0) {
    evap_flags = evap_flags & 0xfeff;
  }
  else if ((evap_flags & 0x800) == 0) {
    evap_flags = evap_flags | 0x100;
  }
  if (evap_state == 2) {
    if ((((evap_flags & 0x40) == 0) && ((evap_flags & 0x20) == 0)) && (evap_pressure_drop_2 != '\0')
       ) {
      if ((evap_flags & 2) == 0) {
        return;
      }
      evap_pressure_drop_inc = (ushort)CAL_evap_pressure_drop_inc_limit_l;
      evap_state = 1;
      return;
    }
    if ((evap_flags & 0x100) == 0) {
      evap_state = 0;
      inj_time_adj_by_stft = 0;
      return;
    }
    if (fuel_learn_timer != 0) {
      evap_state = 0;
      inj_time_adj_by_stft = 0;
      return;
    }
    if ((evap_flags & 0x800) == 0) {
      evap_state = 0;
      inj_time_adj_by_stft = 0;
      fuel_learn_timer = (u16_time_100ms)((int)(uint)DAT_003f9522 >> 3);
      return;
    }
    evap_state = 0;
    inj_time_adj_by_stft = 0;
    fuel_learn_timer = DAT_003f9522;
    return;
  }
  if (evap_state < 2) {
    if (evap_state == 0) {
      if (((evap_flags & 0x100) != 0) && (fuel_learn_timer == 0)) {
        if ((evap_flags & 0x800) == 0) {
          if ((evap_flags & 0x1000) == 0) {
            fuel_learn_timer = DAT_003f9522;
          }
          else {
            evap_flags = evap_flags & 0xfeff | 0x800;
          }
        }
        else {
          evap_flags = evap_flags & 0xfeff;
        }
      }
      if ((evap_flags & 2) == 0) {
        if ((DAT_003fd580 & 4) == 0) {
          DAT_003f80bc = CAL_evap_initial_delay;
          evap_concentration_1 = 0;
          evap_pressure_drop_1 = 0;
          DAT_003f8d29 = CAL_evap_duty_cycle_initial_time;
          evap_pressure_drop_2 = 0;
          return;
        }
        if ((evap_flags & 1) == 0) {
          DAT_003f80bc = CAL_evap_initial_delay;
          evap_concentration_1 = 0;
          evap_pressure_drop_1 = 0;
          DAT_003f8d29 = CAL_evap_duty_cycle_initial_time;
          evap_pressure_drop_2 = 0;
          return;
        }
        DAT_003f80bc = CAL_evap_initial_delay;
        evap_concentration_1 = 0;
        evap_pressure_drop_1 = 0;
        DAT_003f8d29 = CAL_evap_duty_cycle_initial_time;
        evap_flags = evap_flags & 0xfbff;
        evap_pressure_drop_2 = 0;
        evap_state = 4;
        DAT_003fd580 = DAT_003fd580 | 8;
        return;
      }
      if ((evap_flags & 0x20) != 0) {
        DAT_003f80bc = CAL_evap_initial_delay;
        evap_concentration_1 = 0;
        evap_pressure_drop_1 = 0;
        DAT_003f8d29 = CAL_evap_duty_cycle_initial_time;
        evap_pressure_drop_2 = 0;
        return;
      }
      if ((evap_flags & 0x40) != 0) {
        DAT_003f80bc = CAL_evap_initial_delay;
        evap_concentration_1 = 0;
        evap_pressure_drop_1 = 0;
        DAT_003f8d29 = CAL_evap_duty_cycle_initial_time;
        evap_pressure_drop_2 = 0;
        return;
      }
      DAT_003f80bc = CAL_evap_initial_delay;
      evap_concentration_1 = 0;
      evap_pressure_drop_1 = 0;
      DAT_003f8d29 = CAL_evap_duty_cycle_initial_time;
      evap_pressure_drop_2 = 0;
      evap_state = 1;
      return;
    }
    if (true) {
      if ((evap_flags & 0x40) != 0) {
        evap_state = 0;
        return;
      }
      if ((evap_flags & 0x20) != 0) {
        if (DAT_003f8d26 != 0) {
          evap_pressure_drop_1 = 0;
        }
        DAT_003f80bd = CAL_evap_dfso_recovery_delay;
        evap_pressure_drop_2 = 0;
        evap_state = 3;
        return;
      }
      if ((evap_flags & 2) == 0) {
        evap_state = evap_state + 1;
        return;
      }
      if (((DAT_003f94ca < evap_purge_command) && (evap_concentration_2 < DAT_003f94c6)) &&
         ((closedloop_flags & 0x10) != 0)) {
        if (DAT_003f8d24 == 0) {
          evap_flags = evap_flags | 0x900;
        }
      }
      else {
        DAT_003f8d24 = CAL_evap_learn_delay;
      }
      if (evap_concentration_2 <= DAT_003f94ee) {
        if (evap_purge_command <= DAT_003f94ca) {
          return;
        }
        evap_flags = evap_flags | 1;
        return;
      }
      if ((DAT_003fd580 & 4) == 0) {
        return;
      }
      evap_flags = evap_flags & 0xfffe | 0x200;
      return;
    }
  }
  else {
    if (evap_state == 4) {
      if ((((DAT_003fd580 & 4) == 0) || ((evap_flags & 2) != 0)) || ((evap_flags & 1) == 0)) {
        DAT_003fd580 = DAT_003fd580 & 0xfff7;
        evap_state = 0;
      }
      if (evap_leak_state < 3) {
        DAT_003f80bc = CAL_evap_initial_delay;
      }
      if (evap_concentration_2 <= DAT_003f94c8) {
        return;
      }
      evap_flags = evap_flags & 0xfffe | 0x600;
      return;
    }
    if (evap_state < 4) {
      if ((DAT_003f80bd != '\0') && ((evap_flags & 0x40) == 0)) {
        if ((evap_flags & 0x20) != 0) {
          return;
        }
        evap_state = 1;
        return;
      }
      evap_state = 0;
      return;
    }
  }
  evap_state = 0;
  return;
}



// WARNING: Inlined function: push_26to31
// WARNING: Inlined function: pop_26to31
// EVAP purge duty cycle calculation

void evap(void)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  ushort uVar4;
  
  if ((inj_time_stft_smooth < -199) || (199 < inj_time_stft_smooth)) {
    evap_flags = evap_flags & 0xffef;
  }
  else {
    evap_flags = evap_flags | 0x10;
  }
  if ((((inj_time_stft_smooth < -99) || (99 < inj_time_stft_smooth)) || ((evap_flags & 0x100) == 0))
     || (evap_pressure_drop_2 != 0)) {
    evap_flags = evap_flags & 0xefff;
    DAT_003f8d28 = CAL_evap_stft_stability_delay;
  }
  else if (DAT_003f8d28 == 0) {
    evap_flags = evap_flags | 0x1000;
  }
  if (DAT_003f80bc == '\0') {
    uVar2 = ((uint)maf_flow_1 * 0xe1) / ((uint)evap_concentration_2 * 2 + 0x2ee);
    evap_pressure_drop_inc = (ushort)uVar2;
    if ((uVar2 & 0xffff) < (uint)CAL_evap_pressure_drop_inc_limit_l) {
      evap_pressure_drop_inc = (ushort)CAL_evap_pressure_drop_inc_limit_l;
    }
    if (evap_state == '\x04') {
      evap_pressure_drop_dec = 500;
    }
    else {
      evap_pressure_drop_dec = 300;
    }
  }
  else {
    evap_pressure_drop_inc = (ushort)CAL_evap_pressure_drop_inc_limit_l;
    evap_pressure_drop_dec = (ushort)CAL_evap_pressure_drop_dec_initial;
  }
  if ((((idle_flow_target < CAL_evap_idle_flow_disable) ||
       ((int)inj_time_final_1 < (int)((uint)CAL_evap_inj_time_disable << 3))) ||
      ((evap_state == '\x02' && ((evap_flags & 0x10) != 0)))) ||
     ((evap_state == '\x04' && ((DAT_003fd580 & 0x20) == 0)))) {
    evap_flags = evap_flags & 0xfffb | 8;
  }
  else if ((((CAL_evap_idle_flow_enable < idle_flow_target) &&
            ((int)((uint)CAL_evap_inj_time_enable << 3) < (int)inj_time_final_1)) &&
           ((evap_flags & 0x10) != 0)) &&
          (((evap_state == '\x01' &&
            ((((DAT_003fd580 & 0x8000) == 0 && ((DAT_003fd580 & 0x1000) == 0)) ||
             ((short)evap_purge_command < DAT_003fc056)))) ||
           ((evap_state == '\x04' && ((DAT_003fd580 & 0x20) != 0)))))) {
    evap_flags = evap_flags & 0xfff7 | 4;
  }
  else {
    evap_flags = evap_flags & 0xfff3;
  }
  if (vacuum_1 == 0) {
    evap_pressure_drop_max_vacuum = 0;
  }
  else {
    evap_pressure_drop_max_vacuum =
         lookup_2D_uint8_interpolated
                   (8,(uint8_t)(vacuum_smooth >> 2),CAL_evap_pressure_drop_max,
                    CAL_evap_pressure_drop_max_X_vacuum);
  }
  if (evap_concentration_2 < 2) {
    evap_pressure_drop_max_load = 255;
  }
  else {
    if (evap_fuel_load_prev < inj_fuel_load_needed) {
      uVar2 = (uint)inj_fuel_load_needed - (uint)evap_fuel_load_prev & 0xffff;
    }
    else {
      uVar2 = 0;
    }
    evap_fuel_load_prev =
         (ushort)(((uint)DAT_003fd17c * ((uint)CAL_evap_inj_time_enable * 8 - (uint)inj_time_base))
                 / 10000);
    uVar2 = ((uVar2 * 0x46cfc) / (uint)((int)(uint)evap_concentration_2 >> 1)) /
            (uint)((int)(uint)engine_speed_period_avg >> 3) & 0xffff;
    if (uVar2 < 0x100) {
      evap_pressure_drop_max_load = (u8_pressure_4mbar)uVar2;
    }
    else {
      evap_pressure_drop_max_load = 255;
    }
  }
  if (evap_pressure_drop_max_load < evap_pressure_drop_max_vacuum) {
    evap_pressure_drop_max = evap_pressure_drop_max_load;
  }
  else {
    evap_pressure_drop_max = evap_pressure_drop_max_vacuum;
  }
  if ((CAL_evap_pressure_drop_idle_limit_h < evap_pressure_drop_max) && ((idle_flags & 8) != 0)) {
    evap_pressure_drop_max = CAL_evap_pressure_drop_idle_limit_h;
  }
  if ((evap_pressure_drop_max_leak_test < evap_pressure_drop_max) && (evap_state == '\x04')) {
    evap_pressure_drop_max = evap_pressure_drop_max_leak_test;
  }
  bVar1 = lookup_3D_uint8_interpolated
                    (16,16,(ushort)evap_pressure_drop_2,vacuum_smooth >> 2 & 0xff,CAL_evap_purge,
                     CAL_evap_purge_X_pressure_drop,CAL_evap_purge_Y_vacuum);
  evap_duty_adj = (ushort)bVar1;
  uVar2 = ((uint)evap_pressure_drop_2 * 0x9a9250) / 0x1cb168;
  evap_flow = (u16_flow_mg_s)uVar2;
  uVar4 = REG_MPWMSM0_SCR;
  if ((short)uVar4 < 0) {
    evap_flow_2 = 0;
  }
  else if (evap_flow < 0x29cd) {
    evap_flow_2 = (undefined1)(evap_flow / CAL_evap_flow_divisor);
  }
  else {
    evap_flow_2 = 0xf2;
  }
  if ((DAT_003fd180 & 1) == 0) {
    evap_stft_neg = -inj_time_stft_smooth;
  }
  else {
    evap_stft_neg = 0;
  }
  iVar3 = (int)((int)evap_stft_neg * (uint)inj_fuel_load_needed * 0x19) /
          (int)(uint)engine_speed_period_avg;
  if (iVar3 < 0x8000) {
    if (iVar3 < -0x8000) {
      evap_fuel_flow_correction = 32768;
    }
    else {
      evap_fuel_flow_correction = (u16_flow_mg_s)iVar3;
    }
  }
  else {
    evap_fuel_flow_correction = 32767;
  }
  if (evap_flow == 0) {
    evap_concentration_adj = 0;
  }
  else if (evap_flow < 0x1a) {
    evap_concentration_adj = (int)(short)evap_fuel_flow_correction << 2;
  }
  else {
    evap_concentration_adj = ((short)evap_fuel_flow_correction * 100) / (int)uVar2;
  }
  iVar3 = ((int)evap_concentration_1 >> 8) +
          (uint)((int)evap_concentration_1 < 0 && (evap_concentration_1 & 0xff) != 0);
  if (iVar3 < 0) {
    evap_concentration_2 = 0;
  }
  else if (iVar3 < 0x10000) {
    evap_concentration_2 = (u16_factor_1_100)iVar3;
  }
  else {
    evap_concentration_2 = 65535;
  }
  uVar2 = (uVar2 * evap_concentration_2) / 100;
  if (uVar2 < 0x10000) {
    evap_fuel_flow = (ushort)uVar2;
  }
  else {
    evap_fuel_flow = 0xffff;
  }
  evap_fuel_load = (undefined2)(((uint)evap_fuel_flow * (uint)engine_speed_period_avg) / 250000);
  if (obd_mode_0x2F_state == '\r') {
    evap_purge_command = (ushort)obd_mode_0x2F_value;
    uVar4 = (ushort)obd_mode_0x2F_value;
  }
  else if (evap_pressure_drop_1 == 0) {
    evap_purge_command = 0;
    uVar4 = 0;
  }
  else {
    evap_purge_command = CAL_evap_duty_cycle_limit_l + evap_duty_adj;
    if (CAL_evap_duty_cycle_limit_h < evap_purge_command) {
      evap_purge_command = (ushort)CAL_evap_duty_cycle_limit_h;
    }
    else if (evap_purge_command < CAL_evap_duty_cycle_limit_l) {
      evap_purge_command = (ushort)CAL_evap_duty_cycle_limit_l;
    }
    uVar4 = evap_purge_command;
    if (DAT_003f8d29 != '\0') {
      uVar4 = (ushort)CAL_evap_duty_cycle_initial;
    }
  }
  evap_pwm_pulse = (undefined2)((int)(short)uVar4 * (uint)CAL_evap_period >> 8);
  set_evap_pwm(evap_pwm_pulse);
  return;
}



// EVAP monitoring task (100ms)

void evap_100ms(void)

{
  uint uVar1;
  
  if ((DAT_003f80bc != '\0') && ((evap_flags & 0x10) != 0)) {
    DAT_003f80bc = DAT_003f80bc + -1;
  }
  if (DAT_003f80bd != '\0') {
    DAT_003f80bd = DAT_003f80bd + -1;
  }
  if ((DAT_003f8d1e != 0) && ((fuel_system_status & 2) != 0)) {
    DAT_003f8d1e = DAT_003f8d1e + -1;
  }
  if (DAT_003f8d22 != '\0') {
    DAT_003f8d22 = DAT_003f8d22 + -1;
  }
  if (DAT_003f8d28 != '\0') {
    DAT_003f8d28 = DAT_003f8d28 + -1;
  }
  if (DAT_003f8d26 != 0) {
    DAT_003f8d26 = DAT_003f8d26 + -1;
  }
  if (DAT_003f8d24 != '\0') {
    DAT_003f8d24 = DAT_003f8d24 + -1;
  }
  if (DAT_003f8d29 != '\0') {
    DAT_003f8d29 = DAT_003f8d29 + -1;
  }
  uVar1 = vacuum_smooth_x * (0x100 - (uint)CAL_evap_vacuum_reactivity);
  vacuum_smooth_x =
       ((int)uVar1 >> 8) + (uint)((int)uVar1 < 0 && (uVar1 & 0xff) != 0) +
       (int)vacuum_1 * (uint)CAL_evap_vacuum_reactivity;
  vacuum_smooth =
       (short)(vacuum_smooth_x >> 8) +
       (ushort)((int)vacuum_smooth_x < 0 && (vacuum_smooth_x & 0xff) != 0);
  if (evap_pressure_drop_2 != 0) {
    if (((0 < evap_concentration_adj) &&
        ((inj_time_stft_smooth < DAT_003f8d00 ||
         ((int)inj_time_stft_smooth <= -((short)CAL_stft_limit + -0x28))))) ||
       ((evap_concentration_adj < 0 &&
        ((DAT_003f8d00 < inj_time_stft_smooth ||
         ((short)CAL_stft_limit + -0x28 <= (int)inj_time_stft_smooth)))))) {
      evap_concentration_1 = evap_concentration_1 + evap_concentration_adj * DAT_003f94ec;
      if (evap_concentration_1 < 0xffff01) {
        if (evap_concentration_1 < 0) {
          evap_concentration_1 = 0;
        }
      }
      else {
        evap_concentration_1 = 0xffff00;
      }
    }
    DAT_003f8d00 = inj_time_stft_smooth;
  }
  if ((evap_flags & 0x20) == 0) {
    if ((uint)evap_pressure_drop_max << 8 < (uint)evap_pressure_drop_1) {
      if (DAT_003f8d23 < 3) {
        DAT_003f8d23 = DAT_003f8d23 + 1;
      }
      else {
        evap_pressure_drop_1 = (ushort)evap_pressure_drop_max << 8;
      }
    }
    else {
      DAT_003f8d23 = 0;
      if ((evap_flags & 4) == 0) {
        if ((evap_flags & 8) != 0) {
          if (evap_pressure_drop_dec < evap_pressure_drop_1) {
            evap_pressure_drop_1 = evap_pressure_drop_1 - evap_pressure_drop_dec;
          }
          else {
            evap_pressure_drop_1 = 0;
          }
        }
      }
      else if ((uint)evap_pressure_drop_inc + (uint)evap_pressure_drop_1 <
               (uint)evap_pressure_drop_max << 8) {
        evap_pressure_drop_1 = (ushort)((uint)evap_pressure_drop_inc + (uint)evap_pressure_drop_1);
      }
      else {
        evap_pressure_drop_1 = (ushort)evap_pressure_drop_max << 8;
      }
    }
    evap_pressure_drop_2 = (byte)(evap_pressure_drop_1 >> 8);
  }
  else {
    DAT_003f8d23 = 0;
  }
  DAT_003fd368 = DAT_003fd368 + (uint)evap_pressure_drop_2;
  DAT_003f8d10 = DAT_003f8d10 + (uint)evap_flow;
  return;
}



// Sets EVAP purge solenoid PWM duty cycle

void set_evap_pwm(ushort param_1)

{
  if ((LEA_obd_P0445_flags & 4) == 0) {
    REG_MPWMSM1_PULR = param_1;
  }
  else {
    REG_MPWMSM1_PULR = 0;
  }
  return;
}



// Initializes EEPROM with default calibration data

void eeprom_default_data(void)

{
  int iVar1;
  int iVar2;
  
  memcpy(LEA_base,"CroftT4E090 03/12/2010 Lotus EngV0099",0x20);
  LEA_sensor_pps_1_offset = CAL_sensor_pps_1_offset;
  LEA_sensor_pps_2_offset = CAL_sensor_pps_2_offset;
  LEA_idle_flow_adj1 = 0;
  LEA_idle_flow_adj1_ac_on = 0;
  for (iVar2 = 0; iVar2 < 8; iVar2 = iVar2 + 1) {
    (&DAT_002f82df)[iVar2] = (&DAT_003fce7a)[iVar2];
    (&DAT_002f82cf)[iVar2] = (&DAT_003fce7a)[iVar2];
  }
  for (iVar2 = 8; iVar2 < 0x10; iVar2 = iVar2 + 1) {
    (&DAT_002f82df)[iVar2] = 0;
    (&DAT_002f82cf)[iVar2] = 0;
  }
  LEA_ecu_engine_speed_byte_coefficient = CAL_ecu_engine_speed_byte_coefficient;
  LEA_ecu_engine_speed_byte_offset = CAL_ecu_engine_speed_byte_offset;
  DAT_002f8024 = 0;
  DAT_002f8026 = 0;
  for (iVar2 = 8; iVar2 < 0x28; iVar2 = iVar2 + 1) {
    *(u8_factor_1_500 *)((int)&LEA_ecu_engine_speed_byte_coefficient + iVar2) =
         CAL_obd_P1302_threshold[iVar2 + 0x38];
  }
  for (iVar2 = 0x28; iVar2 < 0x128; iVar2 = iVar2 + 1) {
    *(undefined1 *)((int)&LEA_ecu_engine_speed_byte_coefficient + iVar2) = 100;
  }
  LEA_ltft_zone1_adj = 0;
  LEA_ltft_zone3_adj = 128;
  LEA_ltft_zone2_adj = 128;
  DAT_002f82ff = 0;
  LEA_obd_freeze_dtc = 0;
  LEA_obd_freeze_engine_speed = 0;
  LEA_obd_freeze_fuel_system_status = 0;
  LEA_obd_freeze_load = 0;
  LEA_obd_freeze_car_speed = 0;
  LEA_obd_freeze_tps = 0;
  LEA_obd_freeze_maf_flow = 0;
  LEA_obd_freeze_coolant = 0;
  LEA_obd_freeze_stft = 0;
  LEA_obd_freeze_ltft = 0;
  DAT_002f830e = 0;
  DAT_002f8310 = 0;
  DAT_002f8312 = 0;
  DAT_002f8314 = 0;
  DAT_002f8316 = 0;
  DAT_002f8317 = 0;
  DAT_002f8318 = 0;
  DAT_002f831a = 0;
  DAT_002f831c = 0;
  DAT_002f831e = 0;
  DAT_002f831f = 0;
  DAT_002f8320 = 0;
  DAT_002f82c3 = 0;
  DAT_002f8322 = 0;
  LEA_obd_P0011_flags = 0;
  LEA_obd_P0011_engine_start_count = 3;
  LEA_obd_P0011_warm_up_cycle_count = 40;
  LEA_obd_P0012_flags = 0;
  LEA_obd_P0012_engine_start_count = 3;
  LEA_obd_P0012_warm_up_cycle_count = 40;
  LEA_obd_P0016_flags = 0;
  LEA_obd_P0016_engine_start_count = 3;
  LEA_obd_P0016_warm_up_cycle_count = 40;
  LEA_obd_P0076_flags = 0;
  LEA_obd_P0076_engine_start_count = 3;
  LEA_obd_P0076_warm_up_cycle_count = 40;
  LEA_obd_P0077_flags = 0;
  LEA_obd_P0077_engine_start_count = 3;
  LEA_obd_P0077_warm_up_cycle_count = 40;
  LEA_obd_P0101_flags = 0;
  LEA_obd_P0101_engine_start_count = 3;
  LEA_obd_P0101_warm_up_cycle_count = 40;
  LEA_obd_P0102_flags = 0;
  LEA_obd_P0102_engine_start_count = 3;
  LEA_obd_P0102_warm_up_cycle_count = 40;
  LEA_obd_P0103_flags = 0;
  LEA_obd_P0103_engine_start_count = 3;
  LEA_obd_P0103_warm_up_cycle_count = 40;
  LEA_obd_P0106_flags = 0;
  LEA_obd_P0106_engine_start_count = 3;
  LEA_obd_P0106_warm_up_cycle_count = 40;
  LEA_obd_P0107_flags = 0;
  LEA_obd_P0107_engine_start_count = 3;
  LEA_obd_P0107_warm_up_cycle_count = 40;
  LEA_obd_P0108_flags = 0;
  LEA_obd_P0108_engine_start_count = 3;
  LEA_obd_P0108_warm_up_cycle_count = 40;
  LEA_obd_P0111_flags = 0;
  LEA_obd_P0111_engine_start_count = 3;
  LEA_obd_P0111_warm_up_cycle_count = 40;
  LEA_obd_P0112_flags = 0;
  LEA_obd_P0112_engine_start_count = 3;
  LEA_obd_P0112_warm_up_cycle_count = 40;
  LEA_obd_P0113_flags = 0;
  LEA_obd_P0113_engine_start_count = 3;
  LEA_obd_P0113_warm_up_cycle_count = 40;
  LEA_obd_P0116_flags = 0;
  LEA_obd_P0116_engine_start_count = 3;
  LEA_obd_P0116_warm_up_cycle_count = 40;
  LEA_obd_P0117_flags = 0;
  LEA_obd_P0117_engine_start_count = 3;
  LEA_obd_P0117_warm_up_cycle_count = 40;
  LEA_obd_P0118_flags = 0;
  LEA_obd_P0118_engine_start_count = 3;
  LEA_obd_P0118_warm_up_cycle_count = 40;
  LEA_obd_P0122_flags = 0;
  LEA_obd_P0123_flags = 0;
  LEA_obd_P0128_flags = 0;
  LEA_obd_P0128_engine_start_count = 3;
  LEA_obd_P0128_warm_up_cycle_count = 40;
  LEA_obd_P0131_flags = 0;
  LEA_obd_P0131_engine_start_count = 3;
  LEA_obd_P0131_warm_up_cycle_count = 40;
  LEA_obd_P0132_flags = 0;
  LEA_obd_P0132_engine_start_count = 3;
  LEA_obd_P0132_warm_up_cycle_count = 40;
  LEA_obd_P0133_flags = 0;
  LEA_obd_P0133_engine_start_count = 3;
  LEA_obd_P0133_warm_up_cycle_count = 40;
  LEA_obd_P0134_flags = 0;
  LEA_obd_P0134_engine_start_count = 3;
  LEA_obd_P0134_warm_up_cycle_count = 40;
  LEA_obd_P0135_flags = 0;
  LEA_obd_P0135_engine_start_count = 3;
  LEA_obd_P0135_warm_up_cycle_count = 40;
  LEA_obd_P0137_flags = 0;
  LEA_obd_P0137_engine_start_count = 3;
  LEA_obd_P0137_warm_up_cycle_count = 40;
  LEA_obd_P0138_flags = 0;
  LEA_obd_P0138_engine_start_count = 3;
  LEA_obd_P0138_warm_up_cycle_count = 40;
  LEA_obd_P0139_flags = 0;
  LEA_obd_P0139_engine_start_count = 3;
  LEA_obd_P0139_warm_up_cycle_count = 40;
  LEA_obd_P0140_flags = 0;
  LEA_obd_P0140_engine_start_count = 3;
  LEA_obd_P0140_warm_up_cycle_count = 40;
  LEA_obd_P0141_flags = 0;
  LEA_obd_P0141_engine_start_count = 3;
  LEA_obd_P0141_warm_up_cycle_count = 40;
  LEA_obd_P0171_flags = 0;
  LEA_obd_P0171_engine_start_count = 3;
  LEA_obd_P0171_warm_up_cycle_count = 40;
  LEA_obd_P0172_flags = 0;
  LEA_obd_P0172_engine_start_count = 3;
  LEA_obd_P0172_warm_up_cycle_count = 40;
  LEA_obd_P0201_flags = 0;
  LEA_obd_P0201_engine_start_count = 3;
  LEA_obd_P0201_warm_up_cycle_count = 40;
  LEA_obd_P0202_flags = 0;
  LEA_obd_P0202_engine_start_count = 3;
  LEA_obd_P0202_warm_up_cycle_count = 40;
  LEA_obd_P0203_flags = 0;
  LEA_obd_P0203_engine_start_count = 3;
  LEA_obd_P0203_warm_up_cycle_count = 40;
  LEA_obd_P0204_flags = 0;
  LEA_obd_P0204_engine_start_count = 3;
  LEA_obd_P0204_warm_up_cycle_count = 40;
  LEA_obd_P0205_flags = 0;
  LEA_obd_P0205_engine_start_count = 3;
  LEA_obd_P0205_warm_up_cycle_count = 40;
  LEA_obd_P0222_flags = 0;
  LEA_obd_P0122_engine_start_count = 3;
  LEA_obd_P0122_warm_up_cycle_count = 40;
  LEA_obd_P0223_flags = 0;
  LEA_obd_P0123_engine_start_count = 3;
  LEA_obd_P0123_warm_up_cycle_count = 40;
  LEA_obd_P0237_flags = 0;
  LEA_obd_P0237_engine_start_count = 3;
  LEA_obd_P0237_warm_up_cycle_count = 40;
  LEA_obd_P0238_flags = 0;
  LEA_obd_P0238_engine_start_count = 3;
  LEA_obd_P0238_warm_up_cycle_count = 40;
  LEA_obd_P0300_flags = 0;
  LEA_obd_P0300_engine_start_count = 3;
  LEA_obd_P0300_warm_up_cycle_count = 40;
  LEA_obd_P0301_flags = 0;
  LEA_obd_P0301_engine_start_count = 3;
  LEA_obd_P0301_warm_up_cycle_count = 40;
  LEA_obd_P0302_flags = 0;
  LEA_obd_P0302_engine_start_count = 3;
  LEA_obd_P0302_warm_up_cycle_count = 40;
  LEA_obd_P0303_flags = 0;
  LEA_obd_P0303_engine_start_count = 3;
  LEA_obd_P0303_warm_up_cycle_count = 40;
  LEA_obd_P0304_flags = 0;
  LEA_obd_P0304_engine_start_count = 3;
  LEA_obd_P0304_warm_up_cycle_count = 40;
  LEA_obd_P0327_flags = 0;
  LEA_obd_P0327_engine_start_count = 3;
  LEA_obd_P0327_warm_up_cycle_count = 40;
  LEA_obd_P0328_flags = 0;
  LEA_obd_P0328_engine_start_count = 3;
  LEA_obd_P0328_warm_up_cycle_count = 40;
  LEA_obd_P1301_flags = 0;
  LEA_obd_P1301_engine_start_count = 3;
  LEA_obd_P1301_warm_up_cycle_count = 40;
  LEA_obd_P1302_flags = 0;
  LEA_obd_P1302_engine_start_count = 3;
  LEA_obd_P1302_warm_up_cycle_count = 40;
  LEA_obd_P0335_flags = 0;
  LEA_obd_P0335_engine_start_count = 3;
  LEA_obd_P0335_warm_up_cycle_count = 40;
  LEA_obd_P0340_flags = 0;
  LEA_obd_P0340_engine_start_count = 3;
  LEA_obd_P0340_warm_up_cycle_count = 40;
  LEA_obd_P0351_flags = 0;
  LEA_obd_P0351_engine_start_count = 3;
  LEA_obd_P0351_warm_up_cycle_count = 40;
  LEA_obd_P0352_flags = 0;
  LEA_obd_P0352_engine_start_count = 3;
  LEA_obd_P0352_warm_up_cycle_count = 40;
  LEA_obd_P0353_flags = 0;
  LEA_obd_P0353_engine_start_count = 3;
  LEA_obd_P0353_warm_up_cycle_count = 40;
  LEA_obd_P0354_flags = 0;
  LEA_obd_P0354_engine_start_count = 3;
  LEA_obd_P0354_warm_up_cycle_count = 40;
  LEA_obd_P0420_flags = 0;
  LEA_obd_P0420_engine_start_count = 3;
  LEA_obd_P0420_warm_up_cycle_count = 40;
  LEA_obd_P0441_flags = 0;
  LEA_obd_P0441_engine_start_count = 3;
  LEA_obd_P0441_warm_up_cycle_count = 40;
  LEA_obd_P0442_flags = 0;
  LEA_obd_P0442_engine_start_count = 3;
  LEA_obd_P0442_warm_up_cycle_count = 40;
  LEA_obd_P0444_flags = 0;
  LEA_obd_P0444_engine_start_count = 3;
  LEA_obd_P0444_warm_up_cycle_count = 40;
  LEA_obd_P0445_flags = 0;
  LEA_obd_P0445_engine_start_count = 3;
  LEA_obd_P0445_warm_up_cycle_count = 40;
  LEA_obd_P0446_flags = 0;
  LEA_obd_P0446_engine_start_count = 3;
  LEA_obd_P0446_warm_up_cycle_count = 40;
  LEA_obd_P0447_flags = 0;
  LEA_obd_P0447_engine_start_count = 3;
  LEA_obd_P0447_warm_up_cycle_count = 40;
  LEA_obd_P0448_flags = 0;
  LEA_obd_P0448_engine_start_count = 3;
  LEA_obd_P0448_warm_up_cycle_count = 40;
  LEA_obd_P0451_flags = 0;
  LEA_obd_P0451_engine_start_count = 3;
  LEA_obd_P0451_warm_up_cycle_count = 40;
  LEA_obd_P0452_flags = 0;
  LEA_obd_P0452_engine_start_count = 3;
  LEA_obd_P0452_warm_up_cycle_count = 40;
  LEA_obd_P0453_flags = 0;
  LEA_obd_P0453_engine_start_count = 3;
  LEA_obd_P0453_warm_up_cycle_count = 40;
  LEA_obd_P0455_flags = 0;
  LEA_obd_P0455_engine_start_count = 3;
  LEA_obd_P0455_warm_up_cycle_count = 40;
  LEA_obd_P0456_flags = 0;
  LEA_obd_P0456_engine_start_count = 3;
  LEA_obd_P0456_warm_up_cycle_count = 40;
  LEA_obd_P0461_flags = 0;
  LEA_obd_P0461_engine_start_count = 3;
  LEA_obd_P0461_warm_up_cycle_count = 40;
  LEA_obd_P0462_flags = 0;
  LEA_obd_P0462_engine_start_count = 3;
  LEA_obd_P0462_warm_up_cycle_count = 40;
  LEA_obd_P0463_flags = 0;
  LEA_obd_P0463_engine_start_count = 3;
  LEA_obd_P0463_warm_up_cycle_count = 40;
  LEA_obd_P0480_flags = 0;
  LEA_obd_P0480_engine_start_count = 3;
  LEA_obd_P0480_warm_up_cycle_count = 40;
  LEA_obd_P0481_flags = 0;
  LEA_obd_P0481_engine_start_count = 3;
  LEA_obd_P0481_warm_up_cycle_count = 40;
  LEA_obd_P0500_flags = 0;
  LEA_obd_P0500_engine_start_count = 3;
  LEA_obd_P0500_warm_up_cycle_count = 40;
  LEA_obd_P0506_flags = 0;
  LEA_obd_P0506_engine_start_count = 3;
  LEA_obd_P0506_warm_up_cycle_count = 40;
  LEA_obd_P0507_flags = 0;
  LEA_obd_P0507_engine_start_count = 3;
  LEA_obd_P0507_warm_up_cycle_count = 40;
  LEA_obd_P0563_flags = 0;
  LEA_obd_P0563_engine_start_count = 3;
  LEA_obd_P0563_warm_up_cycle_count = 40;
  LEA_obd_P0562_flags = 0;
  LEA_obd_P0562_engine_start_count = 3;
  LEA_obd_P0562_warm_up_cycle_count = 40;
  LEA_obd_P0601_flags = 0;
  LEA_obd_P0601_engine_start_count = 3;
  LEA_obd_P0601_warm_up_cycle_count = 40;
  LEA_obd_P0606_flags = 0;
  LEA_obd_P0606_engine_start_count = 3;
  LEA_obd_P0606_warm_up_cycle_count = 40;
  LEA_obd_P0627_flags = 0;
  LEA_obd_P0627_engine_start_count = 3;
  LEA_obd_P0627_warm_up_cycle_count = 40;
  LEA_obd_P0630_flags = 0;
  LEA_obd_P0630_engine_start_count = 3;
  LEA_obd_P0630_warm_up_cycle_count = 40;
  LEA_obd_P0638_flags = 0;
  LEA_obd_P0638_engine_start_count = 3;
  LEA_obd_P0638_warm_up_cycle_count = 40;
  LEA_obd_P0647_flags = 0;
  LEA_obd_P0647_engine_start_count = 3;
  LEA_obd_P0647_warm_up_cycle_count = 40;
  LEA_obd_P0646_flags = 0;
  LEA_obd_P0646_engine_start_count = 3;
  LEA_obd_P0646_warm_up_cycle_count = 40;
  LEA_obd_P2122_flags = 0;
  LEA_obd_P2122_engine_start_count = 3;
  LEA_obd_P2122_warm_up_cycle_count = 40;
  LEA_obd_P2123_flags = 0;
  LEA_obd_P2123_engine_start_count = 3;
  LEA_obd_P2123_warm_up_cycle_count = 40;
  LEA_obd_P2127_flags = 0;
  LEA_obd_P2127_engine_start_count = 3;
  LEA_obd_P2127_warm_up_cycle_count = 40;
  LEA_obd_P2128_flags = 0;
  LEA_obd_P2128_engine_start_count = 3;
  LEA_obd_P2128_warm_up_cycle_count = 40;
  LEA_obd_P2135_flags = 0;
  LEA_obd_P2135_engine_start_count = 3;
  LEA_obd_P2135_warm_up_cycle_count = 40;
  LEA_obd_P2138_flags = 0;
  LEA_obd_P2138_engine_start_count = 3;
  LEA_obd_P2138_warm_up_cycle_count = 40;
  LEA_obd_P2173_flags = 0;
  LEA_obd_P2173_engine_start_count = 3;
  LEA_obd_P2173_warm_up_cycle_count = 40;
  LEA_obd_P2602_flags = 0;
  LEA_obd_P2602_engine_start_count = 3;
  LEA_obd_P2602_warm_up_cycle_count = 40;
  LEA_obd_P2603_flags = 0;
  LEA_obd_P2603_engine_start_count = 3;
  LEA_obd_P2603_warm_up_cycle_count = 40;
  LEA_obd_P2646_flags = 0;
  LEA_obd_P2646_engine_start_count = 3;
  LEA_obd_P2646_warm_up_cycle_count = 40;
  LEA_obd_P2647_flags = 0;
  LEA_obd_P2647_engine_start_count = 3;
  LEA_obd_P2647_warm_up_cycle_count = 40;
  LEA_obd_P2648_flags = 0;
  LEA_obd_P2648_engine_start_count = 3;
  LEA_obd_P2648_warm_up_cycle_count = 40;
  LEA_obd_P2649_flags = 0;
  LEA_obd_P2649_engine_start_count = 3;
  LEA_obd_P2649_warm_up_cycle_count = 40;
  LEA_obd_P2104_flags = 0;
  LEA_obd_P2104_engine_start_count = 3;
  LEA_obd_P2104_warm_up_cycle_count = 40;
  LEA_obd_P2105_flags = 0;
  LEA_obd_P2105_engine_start_count = 3;
  LEA_obd_P2105_warm_up_cycle_count = 40;
  LEA_obd_P2106_flags = 0;
  LEA_obd_P2106_engine_start_count = 3;
  LEA_obd_P2106_warm_up_cycle_count = 40;
  LEA_obd_P2107_flags = 0;
  LEA_obd_P2107_engine_start_count = 3;
  LEA_obd_P2107_warm_up_cycle_count = 40;
  LEA_obd_P2100_flags = 0;
  LEA_obd_P2100_engine_start_count = 3;
  LEA_obd_P2100_warm_up_cycle_count = 40;
  LEA_obd_P2102_flags = 0;
  LEA_obd_P2102_engine_start_count = 3;
  LEA_obd_P2102_warm_up_cycle_count = 40;
  LEA_obd_P2103_flags = 0;
  LEA_obd_P2103_engine_start_count = 3;
  LEA_obd_P2103_warm_up_cycle_count = 40;
  LEA_obd_P2108_flags = 0;
  LEA_obd_P2108_engine_start_count = 3;
  LEA_obd_P2108_warm_up_cycle_count = 40;
  LEA_obd_monitors_completeness = CAL_obd_monitors[1];
  LEA_obd_freeze2_dtc = 0;
  LEA_obd_freeze2_engine_speed = 0;
  LEA_obd_freeze2_maf_flow = 0;
  LEA_obd_freeze2_stft = 0;
  LEA_obd_freeze2_ltft = 0;
  LEA_obd_freeze2_coolant = 0;
  LEA_obd_freeze2_coolant_stop = 0;
  LEA_obd_freeze2_engine_air = 0;
  LEA_obd_freeze2_tps = 0;
  LEA_obd_freeze2_engine_runtime = 0;
  LEA_obd_freeze2_sensor_adc_pre_o2 = 0;
  LEA_obd_freeze2_sensor_adc_post_o2 = 0;
  DAT_002f833c = 0;
  LEA_obd_freeze2_car_speed = 0;
  LEA_perf_time_at_TPS[0] = 0;
  LEA_perf_time_at_TPS[1] = 0;
  LEA_perf_time_at_TPS[2] = 0;
  LEA_perf_time_at_TPS[3] = 0;
  LEA_perf_time_at_TPS[4] = 0;
  LEA_perf_time_at_TPS[5] = 0;
  LEA_perf_time_at_TPS[6] = 0;
  LEA_perf_time_at_TPS[7] = 0;
  LEA_perf_time_at_RPM[0] = 0;
  LEA_perf_time_at_RPM[1] = 0;
  LEA_perf_time_at_RPM[2] = 0;
  LEA_perf_time_at_RPM[3] = 0;
  LEA_perf_time_at_RPM[4] = 0;
  LEA_perf_time_at_RPM[5] = 0;
  LEA_perf_time_at_RPM[6] = 0;
  LEA_perf_time_at_RPM[7] = 0;
  LEA_perf_time_at_KMH[0] = 0;
  LEA_perf_time_at_KMH[1] = 0;
  LEA_perf_time_at_KMH[2] = 0;
  LEA_perf_time_at_KMH[3] = 0;
  LEA_perf_time_at_KMH[4] = 0;
  LEA_perf_time_at_KMH[5] = 0;
  LEA_perf_time_at_KMH[6] = 0;
  LEA_perf_time_at_KMH[7] = 0;
  LEA_perf_time_at_coolant_temp[0] = 0;
  LEA_perf_time_at_coolant_temp[1] = 0;
  LEA_perf_time_at_coolant_temp[2] = 0;
  LEA_perf_time_at_coolant_temp[3] = 0;
  LEA_perf_max_engine_speed[0] = 0;
  LEA_perf_max_engine_speed[1] = 0;
  LEA_perf_max_engine_speed[2] = 0;
  LEA_perf_max_engine_speed[3] = 0;
  LEA_perf_max_engine_speed[4] = 0;
  LEA_perf_max_engine_speed_5_coolant_temp = 0;
  LEA_perf_max_engine_speed_5_run_timer = 0;
  LEA_perf_max_engine_speed_4_coolant_temp = 0;
  LEA_perf_max_engine_speed_4_run_timer = 0;
  LEA_perf_max_engine_speed_3_coolant_temp = 0;
  LEA_perf_max_engine_speed_3_run_timer = 0;
  LEA_perf_max_engine_speed_2_coolant_temp = 0;
  LEA_perf_max_engine_speed_2_run_timer = 0;
  LEA_perf_max_engine_speed_1_coolant_temp = 0;
  LEA_perf_max_engine_speed_1_run_timer = 0;
  LEA_perf_max_vehicle_speed[0] = 0;
  LEA_perf_max_vehicle_speed[1] = 0;
  LEA_perf_max_vehicle_speed[2] = 0;
  LEA_perf_max_vehicle_speed[3] = 0;
  LEA_perf_max_vehicle_speed[4] = 0;
  LEA_perf_fastest_standing_start[0] = 255;
  LEA_perf_fastest_standing_start[1] = 255;
  LEA_perf_last_standing_start[0] = 0;
  LEA_perf_last_standing_start[1] = 0;
  LEA_perf_engine_run_timer = 0;
  LEA_perf_number_of_standing_starts = 0;
  for (iVar2 = 0; iVar2 < 0x10; iVar2 = iVar2 + 1) {
    for (iVar1 = 0; iVar1 < 4; iVar1 = iVar1 + 1) {
      LEA_misfire_stroke_time[iVar1][iVar2] = misfire_stroke_time_baseline[iVar1][iVar2];
    }
  }
  for (iVar2 = 0; iVar2 < 0x10; iVar2 = iVar2 + 1) {
    misfire_dfso_count[iVar2] = 0;
    (&DAT_002f82ef)[iVar2] = 0;
  }
  DAT_002f8342 = 0x3f5;
  DAT_002f8344 = 0;
  for (iVar2 = 0; iVar2 < 4; iVar2 = iVar2 + 1) {
    LEA_knock_retard2[iVar2] = 0;
  }
  LEA_o2_rich2lean_avg_time = 0;
  LEA_o2_lean2rich_avg_time = 0;
  LEA_o2_switch_time_ratio = 0;
  DAT_002f834e = 0;
  DAT_002f8350 = 0x3ff;
  DAT_002f8352 = 0;
  for (iVar2 = 0; iVar2 < 0x11; iVar2 = iVar2 + 1) {
    LEA_ecu_VIN[iVar2] = CAL_ecu_generic_VIN[iVar2];
  }
  for (iVar2 = 0; iVar2 < 6; iVar2 = iVar2 + 1) {
    LEA_obd_iumpr_pass_count[iVar2] = 0;
    LEA_obd_iumpr_fail_count[iVar2] = 0;
  }
  LEA_obd_iumpr_ignition_count = 0;
  LEA_obd_iumpr_obdcond_count = 0;
  for (iVar2 = 0; iVar2 < 10; iVar2 = iVar2 + 1) {
    (&DAT_002f8206)[iVar2] = 0;
    (&DAT_002f821a)[iVar2] = 0;
    (&DAT_002f8236)[iVar2] = 0;
    (&DAT_002f824a)[iVar2] = 0;
    (&DAT_002f825e)[iVar2] = 0;
    (&DAT_002f8272)[iVar2] = 0;
    LEA_misfire_max_result_history[iVar2] = 0;
    (&DAT_002f829a)[iVar2] = 0;
    (&DAT_002f82ae)[iVar2] = 0;
  }
  LEA_tc_button_fitted = false;
  DAT_002f822e = 0;
  DAT_002f8230 = 0;
  DAT_002f8232 = 0;
  DAT_002f8234 = 0;
  DAT_002f82c2 = CAL_obd_P0139_debounce_threshold;
  DAT_002f8354 = 0;
  LEA_tc_launchcontrol_revlimit = 10000;
  LEA_sensor_tps_1_offset = CAL_sensor_tps_1_offset;
  LEA_sensor_tps_2_offset = CAL_sensor_tps_2_offset;
  return;
}



// Clears all current OBD DTC flags (bit 3)

void obd_clear_current_flags(void)

{
  LEA_obd_P0011_flags = LEA_obd_P0011_flags & 0xf7;
  LEA_obd_P0012_flags = LEA_obd_P0012_flags & 0xf7;
  LEA_obd_P0016_flags = LEA_obd_P0016_flags & 0xf7;
  LEA_obd_P0076_flags = LEA_obd_P0076_flags & 0xf7;
  LEA_obd_P0077_flags = LEA_obd_P0077_flags & 0xf7;
  LEA_obd_P0101_flags = LEA_obd_P0101_flags & 0xf7;
  LEA_obd_P0102_flags = LEA_obd_P0102_flags & 0xf7;
  LEA_obd_P0103_flags = LEA_obd_P0103_flags & 0xf7;
  LEA_obd_P0106_flags = LEA_obd_P0106_flags & 0xf7;
  LEA_obd_P0107_flags = LEA_obd_P0107_flags & 0xf7;
  LEA_obd_P0108_flags = LEA_obd_P0108_flags & 0xf7;
  LEA_obd_P0111_flags = LEA_obd_P0111_flags & 0xf7;
  LEA_obd_P0112_flags = LEA_obd_P0112_flags & 0xf7;
  LEA_obd_P0113_flags = LEA_obd_P0113_flags & 0xf7;
  LEA_obd_P0116_flags = LEA_obd_P0116_flags & 0xf7;
  LEA_obd_P0117_flags = LEA_obd_P0117_flags & 0xf7;
  LEA_obd_P0118_flags = LEA_obd_P0118_flags & 0xf7;
  LEA_obd_P0122_flags = LEA_obd_P0122_flags & 0xf7;
  LEA_obd_P0123_flags = LEA_obd_P0123_flags & 0xf7;
  LEA_obd_P0128_flags = LEA_obd_P0128_flags & 0xf7;
  LEA_obd_P0131_flags = LEA_obd_P0131_flags & 0xf7;
  LEA_obd_P0132_flags = LEA_obd_P0132_flags & 0xf7;
  LEA_obd_P0133_flags = LEA_obd_P0133_flags & 0xf7;
  LEA_obd_P0134_flags = LEA_obd_P0134_flags & 0xf7;
  LEA_obd_P0135_flags = LEA_obd_P0135_flags & 0xf7;
  LEA_obd_P0137_flags = LEA_obd_P0137_flags & 0xf7;
  LEA_obd_P0138_flags = LEA_obd_P0138_flags & 0xf7;
  LEA_obd_P0139_flags = LEA_obd_P0139_flags & 0xf7;
  LEA_obd_P0140_flags = LEA_obd_P0140_flags & 0xf7;
  LEA_obd_P0141_flags = LEA_obd_P0141_flags & 0xf7;
  LEA_obd_P0171_flags = LEA_obd_P0171_flags & 0xf7;
  LEA_obd_P0172_flags = LEA_obd_P0172_flags & 0xf7;
  LEA_obd_P0201_flags = LEA_obd_P0201_flags & 0xf7;
  LEA_obd_P0202_flags = LEA_obd_P0202_flags & 0xf7;
  LEA_obd_P0203_flags = LEA_obd_P0203_flags & 0xf7;
  LEA_obd_P0204_flags = LEA_obd_P0204_flags & 0xf7;
  LEA_obd_P0205_flags = LEA_obd_P0205_flags & 0xf7;
  LEA_obd_P0222_flags = LEA_obd_P0222_flags & 0xf7;
  LEA_obd_P0223_flags = LEA_obd_P0223_flags & 0xf7;
  LEA_obd_P0237_flags = LEA_obd_P0237_flags & 0xf7;
  LEA_obd_P0238_flags = LEA_obd_P0238_flags & 0xf7;
  LEA_obd_P0300_flags = LEA_obd_P0300_flags & 0xf7;
  LEA_obd_P0301_flags = LEA_obd_P0301_flags & 0xf7;
  LEA_obd_P0302_flags = LEA_obd_P0302_flags & 0xf7;
  LEA_obd_P0303_flags = LEA_obd_P0303_flags & 0xf7;
  LEA_obd_P0304_flags = LEA_obd_P0304_flags & 0xf7;
  LEA_obd_P0327_flags = LEA_obd_P0327_flags & 0xf7;
  LEA_obd_P0328_flags = LEA_obd_P0328_flags & 0xf7;
  LEA_obd_P0335_flags = LEA_obd_P0335_flags & 0xf7;
  LEA_obd_P0340_flags = LEA_obd_P0340_flags & 0xf7;
  LEA_obd_P1301_flags = LEA_obd_P1301_flags & 0xf7;
  LEA_obd_P1302_flags = LEA_obd_P1302_flags & 0xf7;
  LEA_obd_P0351_flags = LEA_obd_P0351_flags & 0xf7;
  LEA_obd_P0352_flags = LEA_obd_P0352_flags & 0xf7;
  LEA_obd_P0353_flags = LEA_obd_P0353_flags & 0xf7;
  LEA_obd_P0354_flags = LEA_obd_P0354_flags & 0xf7;
  LEA_obd_P0420_flags = LEA_obd_P0420_flags & 0xf7;
  LEA_obd_P0441_flags = LEA_obd_P0441_flags & 0xf7;
  LEA_obd_P0442_flags = LEA_obd_P0442_flags & 0xf7;
  LEA_obd_P0444_flags = LEA_obd_P0444_flags & 0xf7;
  LEA_obd_P0445_flags = LEA_obd_P0445_flags & 0xf7;
  LEA_obd_P0446_flags = LEA_obd_P0446_flags & 0xf7;
  LEA_obd_P0447_flags = LEA_obd_P0447_flags & 0xf7;
  LEA_obd_P0448_flags = LEA_obd_P0448_flags & 0xf7;
  LEA_obd_P0451_flags = LEA_obd_P0451_flags & 0xf7;
  LEA_obd_P0452_flags = LEA_obd_P0452_flags & 0xf7;
  LEA_obd_P0453_flags = LEA_obd_P0453_flags & 0xf7;
  LEA_obd_P0455_flags = LEA_obd_P0455_flags & 0xf7;
  LEA_obd_P0456_flags = LEA_obd_P0456_flags & 0xf7;
  LEA_obd_P0463_flags = LEA_obd_P0463_flags & 0xf7;
  LEA_obd_P0462_flags = LEA_obd_P0462_flags & 0xf7;
  LEA_obd_P0480_flags = LEA_obd_P0480_flags & 0xf7;
  LEA_obd_P0481_flags = LEA_obd_P0481_flags & 0xf7;
  LEA_obd_P0500_flags = LEA_obd_P0500_flags & 0xf7;
  LEA_obd_P0506_flags = LEA_obd_P0506_flags & 0xf7;
  LEA_obd_P0507_flags = LEA_obd_P0507_flags & 0xf7;
  LEA_obd_P0563_flags = LEA_obd_P0563_flags & 0xf7;
  LEA_obd_P0562_flags = LEA_obd_P0562_flags & 0xf7;
  LEA_obd_P0601_flags = LEA_obd_P0601_flags & 0xf7;
  LEA_obd_P0606_flags = LEA_obd_P0606_flags & 0xf7;
  LEA_obd_P0627_flags = LEA_obd_P0627_flags & 0xf7;
  LEA_obd_P0630_flags = LEA_obd_P0630_flags & 0xf7;
  LEA_obd_P0638_flags = LEA_obd_P0638_flags & 0xf7;
  LEA_obd_P0647_flags = LEA_obd_P0647_flags & 0xf7;
  LEA_obd_P0646_flags = LEA_obd_P0646_flags & 0xf7;
  LEA_obd_P2122_flags = LEA_obd_P2122_flags & 0xf7;
  LEA_obd_P2123_flags = LEA_obd_P2123_flags & 0xf7;
  LEA_obd_P2127_flags = LEA_obd_P2127_flags & 0xf7;
  LEA_obd_P2128_flags = LEA_obd_P2128_flags & 0xf7;
  LEA_obd_P2135_flags = LEA_obd_P2135_flags & 0xf7;
  LEA_obd_P2138_flags = LEA_obd_P2138_flags & 0xf7;
  LEA_obd_P2173_flags = LEA_obd_P2173_flags & 0xf7;
  LEA_obd_P2602_flags = LEA_obd_P2602_flags & 0xf7;
  LEA_obd_P2603_flags = LEA_obd_P2603_flags & 0xf7;
  LEA_obd_P2646_flags = LEA_obd_P2646_flags & 0xf7;
  LEA_obd_P2647_flags = LEA_obd_P2647_flags & 0xf7;
  LEA_obd_P2648_flags = LEA_obd_P2648_flags & 0xf7;
  LEA_obd_P2649_flags = LEA_obd_P2649_flags & 0xf7;
  LEA_obd_P2104_flags = LEA_obd_P2104_flags & 0xf7;
  LEA_obd_P2105_flags = LEA_obd_P2105_flags & 0xf7;
  LEA_obd_P2106_flags = LEA_obd_P2106_flags & 0xf7;
  LEA_obd_P2107_flags = LEA_obd_P2107_flags & 0xf7;
  LEA_obd_P2100_flags = LEA_obd_P2100_flags & 0xf7;
  LEA_obd_P2102_flags = LEA_obd_P2102_flags & 0xf7;
  LEA_obd_P2103_flags = LEA_obd_P2103_flags & 0xf7;
  LEA_obd_P2108_flags = LEA_obd_P2108_flags & 0xf7;
  return;
}



// Saves learned parameters to EEPROM with CRC

void eeprom_save(void)

{
  uint16_t uVar1;
  
  obd_pre_save();
  uVar1 = CRC16(LEA_base,0x550);
  DAT_002f8550 = (uint)uVar1;
  DAT_003fd3ce = 0;
  eeprom_write(LEA_base,0x554);
  return;
}



// Loads learned parameters from EEPROM with CRC validation

void eeprom_load(void)

{
  uint16_t uVar2;
  int iVar1;
  
  eeprom_read(LEA_base,0x554);
  uVar2 = CRC16(LEA_base,0x550);
  if (DAT_002f8550 != uVar2) {
    DAT_003fd5a0 = DAT_003fd5a0 | 1;
  }
  iVar1 = memcmp("CroftT4E090 03/12/2010 Lotus EngV0099",LEA_base,0x20);
  if ((iVar1 == 0) && ((DAT_003fd5a0 & 1) == 0)) {
    LEA_sensor_pps_1_offset = LEA_sensor_pps_1_offset + CAL_sensor_pps_offset_diff_max;
    LEA_sensor_pps_2_offset = LEA_sensor_pps_2_offset + CAL_sensor_pps_offset_diff_max;
    obd_clear_current_flags();
  }
  else {
    eeprom_default_data();
  }
  return;
}



// Resets learned parameter to default value via external command

void dev_reset_lea(void)

{
  int iVar1;
  int iVar2;
  
  if (dev_reset_lea_magic == 0x5352) {
    for (iVar2 = 0; iVar2 < 0x10; iVar2 = iVar2 + 1) {
      for (iVar1 = 0; iVar1 < 4; iVar1 = iVar1 + 1) {
        LEA_misfire_stroke_time[iVar1][iVar2] = misfire_stroke_time_baseline[iVar1][iVar2];
      }
    }
    for (iVar2 = 0; iVar2 < 0x10; iVar2 = iVar2 + 1) {
      misfire_dfso_count[iVar2] = 0;
      (&DAT_002f82ef)[iVar2] = 0;
    }
    for (iVar2 = 0; iVar2 < 4; iVar2 = iVar2 + 1) {
      LEA_knock_retard2[iVar2] = 0;
    }
    LEA_idle_flow_adj1 = 0;
    LEA_idle_flow_adj1_ac_on = 0;
    LEA_ecu_engine_speed_byte_coefficient = CAL_ecu_engine_speed_byte_coefficient;
    LEA_ecu_engine_speed_byte_offset = CAL_ecu_engine_speed_byte_offset;
    DAT_002f8024 = 0;
    DAT_002f8026 = 0;
    for (iVar2 = 8; iVar2 < 0x28; iVar2 = iVar2 + 1) {
      *(u8_factor_1_500 *)((int)&LEA_ecu_engine_speed_byte_coefficient + iVar2) =
           CAL_obd_P1302_threshold[iVar2 + 0x38];
    }
    for (iVar2 = 0x28; iVar2 < 0x128; iVar2 = iVar2 + 1) {
      *(undefined1 *)((int)&LEA_ecu_engine_speed_byte_coefficient + iVar2) = 100;
    }
    LEA_ltft_zone1_adj = 0;
    LEA_ltft_zone3_adj = 128;
    LEA_ltft_zone2_adj = 128;
    for (iVar2 = 0; iVar2 < 10; iVar2 = iVar2 + 1) {
      (&DAT_002f8206)[iVar2] = 0;
      (&DAT_002f821a)[iVar2] = 0;
      (&DAT_002f8236)[iVar2] = 0;
      (&DAT_002f824a)[iVar2] = 0;
      (&DAT_002f825e)[iVar2] = 0;
      (&DAT_002f8272)[iVar2] = 0;
      LEA_misfire_max_result_history[iVar2] = 0;
      (&DAT_002f829a)[iVar2] = 0;
      (&DAT_002f82ae)[iVar2] = 0;
    }
    DAT_002f822e = 0;
    DAT_002f8230 = 0;
    DAT_002f8232 = 0;
    DAT_002f8234 = 0;
    DAT_002f82c2 = CAL_obd_P0139_debounce_threshold;
    DAT_002f8354 = 0;
    LEA_tc_launchcontrol_revlimit = 10000;
    dev_reset_lea_magic = 0x4b4f;
  }
  return;
}



// Closed-loop fuel control state machine - enables/disables based on conditions

void closedloop(void)

{
  byte bVar1;
  
  bVar1 = lookup_2D_uint8_interpolated_noaxis(4,(ushort)coolant_stop,CAL_stft_runtime_min);
  DAT_003fd3a4 = (ushort)bVar1 * 200;
  if ((idle_flags & 8) == 0) {
    bVar1 = lookup_3D_uint8_fixed
                      (8,8,engine_speed_3,load_2,CAL_stft_enrichment_step_X_engine_speed,
                       CAL_stft_enrichment_step_Y_engine_load,CAL_stft_enrichment_step);
    stft_enrichment_step = (ushort)bVar1;
    bVar1 = lookup_3D_uint8_fixed
                      (8,8,engine_speed_3,load_2,CAL_stft_enleanment_step_X_engine_speed,
                       CAL_stft_enleanment_step_Y_engine_load,CAL_stft_enleanment_step);
    stft_enleanment_step = (ushort)bVar1;
    bVar1 = lookup_3D_uint8_fixed
                      (8,8,engine_speed_3,load_2,CAL_stft_enrichment_initial_X_engine_speed,
                       CAL_stft_enrichment_initial_Y_engine_load,CAL_stft_enrichment_initial);
    stft_enrichment_initial = (ushort)bVar1;
    bVar1 = lookup_3D_uint8_fixed
                      (8,8,engine_speed_3,load_2,CAL_stft_enleanment_initial_X_engine_speed,
                       CAL_stft_enleanment_initial_Y_engine_load,CAL_stft_enleanment_initial);
    stft_enleanment_initial = (ushort)bVar1;
    DAT_003f80c0 = CAL_stft_time_between_step;
    bVar1 = lookup_2D_uint8_interpolated
                      (8,engine_speed_3,CAL_stft_time_use_adj,CAL_stft_time_use_adj_X_engine_speed);
    stft_time_use_adj = (ushort)bVar1 * 5;
  }
  else {
    stft_enrichment_step = CAL_stft_idle_enrichment_step;
    stft_enleanment_step = CAL_stft_idle_enleanment_step;
    stft_enrichment_initial = CAL_stft_idle_enrichment_initial;
    stft_enleanment_initial = CAL_stft_idle_enleanment_initial;
    DAT_003f80c0 = (u8_time_5ms)
                   (((uint)CAL_stft_idle_time_between_step * 0x4b0) / (uint)engine_speed_2);
    stft_time_use_adj = 1275;
  }
  stft_lean_threshold = CAL_stft_stoich_min;
  stft_rich_threshold = CAL_stft_stoich_max;
  if (engine_speed_period == 65535) {
    closedloop_flags = 0;
    DAT_003f8d42 = 0;
    inj_time_adj_by_stft = 0;
    DAT_003fd3a6 = 0;
  }
  else if (CAL_stft_o2_test_runtime_min <= engine_runtime) {
    if ((sensor_adc_pre_o2 < CAL_stft_o2_test_min) || (CAL_stft_o2_test_max < sensor_adc_pre_o2)) {
      closedloop_flags = closedloop_flags | 1;
    }
    if ((sensor_adc_post_o2 < CAL_stft_o2_test_min) || (CAL_stft_o2_test_max < sensor_adc_post_o2))
    {
      closedloop_flags = closedloop_flags | 4;
    }
  }
  if ((((engine_runtime < DAT_003fd3a4) || (engine_air_smooth <= CAL_stft_engine_air_min)) ||
      (afr_target != CAL_stft_afr)) || ((misfire_flags & 0x20) != 0)) {
    fuel_system_status = 1;
    if (afr_target < CAL_stft_afr) {
      fuel_system_status = 1025;
    }
    DAT_003fd3a8 = 0;
    DAT_003f8d42 = 0;
    inj_time_adj_by_stft = 0;
    closedloop_flags = closedloop_flags & 0xff1f;
    stft_time_use_adj_timer = stft_time_use_adj;
  }
  else if ((((obd_P0131_debounce_count == 0) || (obd_P0132_debounce_count == 0)) ||
           ((obd_P0134_debounce_count == 0 ||
            ((obd_P0135_debounce_count == 0 || (obd_P0201_debounce_count == 0)))))) ||
          ((obd_P0202_debounce_count == 0 ||
           ((obd_P0203_debounce_count == 0 || (obd_P0204_debounce_count == 0)))))) {
    fuel_system_status = 8;
    DAT_003f8d42 = 0;
    inj_time_adj_by_stft = 0;
    closedloop_flags = closedloop_flags & 0xff1f;
    stft_time_use_adj_timer = stft_time_use_adj;
  }
  else if ((((dfso_flags & 1) == 0) &&
           (((injtip_in == 0 && (injtip_out == 0)) && (injtip_reactive == 0)))) &&
          (((tc_flags & 2) == 0 && (DAT_003f8d3e == '\0')))) {
    if ((closedloop_flags & 1) != 0) {
      DAT_003fd3a8 = 1;
      if (((DAT_003fd60a & 2) == 0) || ((closedloop_flags & 0x40) == 0)) {
        fuel_system_status = 2;
        if ((closedloop_flags & 0x20) != 0) {
          closedloop_flags = closedloop_flags & 0xff9f | 0x80;
        }
        stft();
      }
      else {
        inj_time_adj_by_stft = DAT_003f8d42;
        closedloop_flags = closedloop_flags | 0x20;
      }
    }
  }
  else {
    fuel_system_status = 1028;
    DAT_003f8d42 = 0;
    inj_time_adj_by_stft = 0;
    closedloop_flags = closedloop_flags & 0xff1f;
    stft_time_use_adj_timer = stft_time_use_adj;
  }
  return;
}



// Short-term fuel trim calculation based on O2 sensor

void stft(void)

{
  uint uVar1;
  
  if (((engine_speed_3 < CAL_stft_lean_rpm_min) && (sensor_adc_pre_o2 < stft_lean_threshold)) &&
     (inj_time_adj_by_stft < 0)) {
    inj_time_adj_by_stft = 0;
  }
  else if (stft_rich_threshold < (short)sensor_adc_pre_o2) {
    if (((closedloop_flags & 0x80) == 0) && ((closedloop_flags & 0x40) != 0)) {
      if ((closedloop_flags & 0x100) == 0) {
        DAT_003fd3a6 = -stft_enleanment_step;
      }
      else {
        uVar1 = (int)stft_enleanment_step * (uint)CAL_stft_enleanment_step_adj;
        DAT_003fd3a6 = -((short)((int)uVar1 >> 6) + (ushort)((int)uVar1 < 0 && (uVar1 & 0x3f) != 0))
        ;
      }
    }
    else {
      DAT_003f8d30 = (ushort)DAT_003f80c0;
      stft_time_use_adj_timer = stft_time_use_adj;
      DAT_003fd3a6 = -stft_enleanment_step;
      closedloop_flags = closedloop_flags & 0xfe7f | 0x4040;
      DAT_003f8d42 = inj_time_adj_by_stft;
      inj_time_adj_by_stft = inj_time_adj_by_stft - stft_enleanment_initial;
    }
  }
  else if ((short)sensor_adc_pre_o2 < (short)stft_lean_threshold) {
    if (((closedloop_flags & 0x40) == 0) && ((closedloop_flags & 0x80) != 0)) {
      if ((closedloop_flags & 0x100) == 0) {
        DAT_003fd3a6 = stft_enrichment_step;
      }
      else {
        uVar1 = (int)stft_enrichment_step * (uint)CAL_stft_enrichment_step_adj;
        DAT_003fd3a6 = (short)((int)uVar1 >> 6) + (ushort)((int)uVar1 < 0 && (uVar1 & 0x3f) != 0);
      }
    }
    else {
      DAT_003f8d30 = (ushort)DAT_003f80c0;
      stft_time_use_adj_timer = stft_time_use_adj;
      DAT_003fd3a6 = stft_enrichment_step;
      closedloop_flags = closedloop_flags & 0xfebf | 0x8080;
      inj_time_adj_by_stft = inj_time_adj_by_stft + stft_enrichment_initial;
    }
  }
  else if ((closedloop_flags & 0x40) == 0) {
    if ((closedloop_flags & 0x80) != 0) {
      DAT_003fd3a6 = stft_enrichment_step;
    }
  }
  else {
    DAT_003fd3a6 = -stft_enleanment_step;
  }
  if ((short)CAL_stft_limit < inj_time_adj_by_stft) {
    inj_time_adj_by_stft = CAL_stft_limit;
  }
  else if ((int)inj_time_adj_by_stft < -(int)(short)CAL_stft_limit) {
    inj_time_adj_by_stft = -CAL_stft_limit;
  }
  return;
}



// STFT adjustment task (5ms)

void stft_5ms(void)

{
  if ((fuel_system_status & 2) != 0) {
    DAT_003f8d30 = DAT_003f8d30 - 1;
    if ((short)DAT_003f8d30 < 1) {
      DAT_003f8d30 = (ushort)DAT_003f80c0;
      inj_time_adj_by_stft = inj_time_adj_by_stft + DAT_003fd3a6;
      if ((short)CAL_stft_limit < inj_time_adj_by_stft) {
        inj_time_adj_by_stft = CAL_stft_limit;
      }
      else if ((int)inj_time_adj_by_stft < -(int)(short)CAL_stft_limit) {
        inj_time_adj_by_stft = -CAL_stft_limit;
      }
    }
    if (stft_time_use_adj_timer == 0) {
      closedloop_flags = closedloop_flags | 0x100;
    }
    else {
      stft_time_use_adj_timer = stft_time_use_adj_timer - 1;
    }
  }
  if (((((dfso_flags & 1) == 0) && (injtip_in == 0)) && (injtip_out == 0)) &&
     ((injtip_reactive == 0 && (CAL_stft_afr <= afr_target)))) {
    if (((fuel_system_status == 4 | 0x400) != 0) && (DAT_003f8d3e != '\0')) {
      DAT_003f8d3e = DAT_003f8d3e + -1;
    }
  }
  else {
    DAT_003f8d3e = DAT_003f9395;
  }
  return;
}



// Long-term fuel trim learning (100ms)

void ltft_100ms(void)

{
  bool bVar1;
  uint uVar2;
  uint uVar3;
  ushort uVar4;
  
  if ((maf_flow_1 < CAL_ltft_zone1_flow_max) && (engine_speed_2 < CAL_ltft_zone1_engine_speed_max))
  {
    DAT_003f8d3d = 1;
    inj_time_adj_by_ltft = 0;
  }
  else if (maf_flow_1 < CAL_ltft_zone2_flow_max) {
    DAT_003f8d3d = 2;
    uVar3 = (char)(LEA_ltft_zone2_adj ^ 0x80) * 500;
    inj_time_adj_by_ltft =
         (short)((int)uVar3 >> 7) + (ushort)((int)uVar3 < 0 && (uVar3 & 0x7f) != 0);
  }
  else if ((CAL_ltft_zone2_flow_max < maf_flow_1) && (maf_flow_1 < CAL_ltft_zone3_flow_min)) {
    DAT_003f8d3d = 4;
    uVar3 = (char)(LEA_ltft_zone2_adj ^ 0x80) * 500;
    uVar2 = (char)(LEA_ltft_zone3_adj ^ 0x80) * 500;
    inj_time_adj_by_ltft =
         (short)((int)((((int)uVar3 >> 7) + (uint)((int)uVar3 < 0 && (uVar3 & 0x7f) != 0)) *
                      ((uint)maf_flow_1 - (uint)CAL_ltft_zone2_flow_max)) /
                (int)((uint)CAL_ltft_zone3_flow_min - (uint)CAL_ltft_zone2_flow_max)) +
         (short)((int)((((int)uVar2 >> 7) + (uint)((int)uVar2 < 0 && (uVar2 & 0x7f) != 0)) *
                      ((uint)CAL_ltft_zone3_flow_min - (uint)maf_flow_1)) /
                (int)((uint)CAL_ltft_zone3_flow_min - (uint)CAL_ltft_zone2_flow_max));
  }
  else if (CAL_ltft_zone3_flow_min < maf_flow_1) {
    DAT_003f8d3d = 3;
    uVar3 = (char)(LEA_ltft_zone3_adj ^ 0x80) * 500;
    inj_time_adj_by_ltft =
         (short)((int)uVar3 >> 7) + (ushort)((int)uVar3 < 0 && (uVar3 & 0x7f) != 0);
  }
  else {
    inj_time_adj_by_ltft = 0;
    DAT_003f8d3d = 0;
  }
  if ((((((sensor_fault_flags & 0x10) == 0) && (CAL_ltft_coolant_min < coolant_smooth)) &&
       ((fuel_system_status & 2) != 0)) &&
      ((CAL_ltft_engine_air_min < engine_air_smooth &&
       ((int)(uint)(ushort)CAL_ltft_atmo_min < (int)atmo_pressure)))) &&
     (CAL_ltft_fuel_min < fuel_level_smooth)) {
    if (evap_pressure_drop_2 == '\0') {
      if (fuel_learn_timer != 0) {
        fuel_learn_timer = fuel_learn_timer - 1;
      }
      bVar1 = DAT_003f8d3c == 0;
      DAT_003f8d3c = DAT_003f8d3c + 255;
      uVar4 = closedloop_flags | 0x410;
      if (bVar1) {
        DAT_003f8d3c = CAL_ltft_time_between_step;
        if ((maf_flow_1 < CAL_ltft_zone1_flow_max) &&
           (engine_speed_2 < CAL_ltft_zone1_engine_speed_max)) {
          uVar4 = closedloop_flags & 0xcfff | 0xc10;
          if (inj_time_stft_smooth < (short)(CAL_ltft_stft_smooth_max ^ 0x8000)) {
            if ((inj_time_stft_smooth <= (short)(CAL_ltft_stft_smooth_min ^ 0x8000)) &&
               ((short)(ushort)CAL_ltft_zone1_limit_l * -10 < (int)LEA_ltft_zone1_adj)) {
              LEA_ltft_zone1_adj = LEA_ltft_zone1_adj - (ushort)CAL_ltft_zone1_step;
            }
          }
          else if ((int)LEA_ltft_zone1_adj < (short)(ushort)CAL_ltft_zone1_limit_h * 10) {
            LEA_ltft_zone1_adj = LEA_ltft_zone1_adj + (ushort)CAL_ltft_zone1_step;
          }
        }
        else if ((maf_flow_1 < CAL_ltft_zone2_flow_max) &&
                (((CAL_ltft_zone2_flow_min < maf_flow_1 &&
                  ((int)(uint)CAL_ltft_zone2_load_min < (int)load_1_smooth)) &&
                 ((int)load_1_smooth < (int)(uint)CAL_ltft_zone2_load_max)))) {
          uVar4 = closedloop_flags & 0xd7ff | 0x1410;
          if (inj_time_stft_smooth < (short)(CAL_ltft_stft_smooth_max ^ 0x8000)) {
            if ((inj_time_stft_smooth <= (short)(CAL_ltft_stft_smooth_min ^ 0x8000)) &&
               (CAL_ltft_zone2_limit_l < LEA_ltft_zone2_adj)) {
              LEA_ltft_zone2_adj = LEA_ltft_zone2_adj + 255;
            }
          }
          else if (LEA_ltft_zone2_adj < CAL_ltft_zone2_limit_h) {
            LEA_ltft_zone2_adj = LEA_ltft_zone2_adj + 1;
          }
        }
        else if ((CAL_ltft_zone3_flow_min < maf_flow_1) &&
                ((int)(uint)CAL_ltft_zone3_load_min < (int)load_1_smooth)) {
          uVar4 = closedloop_flags & 0xe7ff | 0x2410;
          if (inj_time_stft_smooth < (short)(CAL_ltft_stft_smooth_max ^ 0x8000)) {
            if ((inj_time_stft_smooth <= (short)(CAL_ltft_stft_smooth_min ^ 0x8000)) &&
               (CAL_ltft_zone3_limit_l < LEA_ltft_zone3_adj)) {
              LEA_ltft_zone3_adj = LEA_ltft_zone3_adj + 255;
            }
          }
          else if (LEA_ltft_zone3_adj < CAL_ltft_zone3_limit_h) {
            LEA_ltft_zone3_adj = LEA_ltft_zone3_adj + 1;
          }
        }
        else {
          uVar4 = closedloop_flags & 0xc7ff | 0x410;
        }
      }
    }
    else {
      uVar4 = closedloop_flags & 0xfbff | 0x10;
    }
  }
  else {
    fuel_learn_timer = 0;
    uVar4 = closedloop_flags & 0xfbef;
  }
  closedloop_flags = uVar4;
  if ((closedloop_flags & 0x800) == 0) {
    if (((closedloop_flags & 0x3000) != 0) && (DAT_003fd39a != -1)) {
      DAT_003fd39a = DAT_003fd39a + 1;
    }
  }
  else if (DAT_003fd398 != -1) {
    DAT_003fd398 = DAT_003fd398 + 1;
  }
  uVar3 = inj_time_stft_smooth_x * (0x100 - (uint)CAL_stft_smooth_reactivity);
  inj_time_stft_smooth_x =
       ((int)uVar3 >> 8) + (uint)((int)uVar3 < 0 && (uVar3 & 0xff) != 0) +
       (int)inj_time_adj_by_stft * (uint)CAL_stft_smooth_reactivity;
  inj_time_stft_smooth =
       (short)(inj_time_stft_smooth_x >> 8) +
       (ushort)((int)inj_time_stft_smooth_x < 0 && (inj_time_stft_smooth_x & 0xff) != 0);
  return;
}



// WARNING: Inlined function: push_25to31
// WARNING: Inlined function: pop_25to31
// Calculates knock sensing window timing per cylinder

void knock_window(void)

{
  byte bVar1;
  
  knock_window_start =
       lookup_3D_uint8_interpolated
                 (16,16,(ushort)engine_speed_3,(ushort)load_2,CAL_knock_window_start,
                  CAL_knock_window_start_X_engine_speed,CAL_knock_window_start_Y_engine_load);
  knock_window_width =
       lookup_3D_uint8_interpolated
                 (16,16,(ushort)engine_speed_3,(ushort)load_2,CAL_knock_window_width,
                  CAL_knock_window_width_X_engine_speed,CAL_knock_window_width_Y_engine_load);
  if (knock_window_width < 0x41) {
    knock_window_width = 64;
  }
  for (bVar1 = 0; bVar1 < 4; bVar1 = bVar1 + 1) {
    knock_window_params[bVar1] =
         ((uint)knock_window_start + knock_window_width + 0x1a & 0x7f) * 0x100 +
         ((knock_window_start + 0x1a & 0x7f) * 0x100 +
         (((int)(knock_window_start + 0x1a) >> 7) +
          (crank_tooth_pattern[(byte)"9\x03\x15\'"[bVar1]] & 0xff) + 1 & 0xff)) * 0x10000 +
         ((crank_tooth_pattern[(byte)"9\x03\x15\'"[bVar1]] & 0xff) +
          ((int)((uint)knock_window_start + knock_window_width + 0x1a) >> 7) + 1 & 0xff);
  }
  return;
}



// WARNING: Inlined function: push_25to31
// WARNING: Inlined function: pop_25to31
// Main knock detection - threshold lookup and retard calculation

void knock(void)

{
  byte bVar2;
  uint uVar1;
  byte bVar3;
  
  knock_sensitivity_threshold[0] =
       lookup_3D_uint8_interpolated
                 (16,16,(ushort)engine_speed_3,(ushort)load_2,CAL_knock_sensitivity_cylinder1,
                  CAL_knock_sensitivity_cylinder1_X_engine_speed,
                  CAL_knock_sensitivity_cylinder1_Y_engine_load);
  if (0x1f < knock_sensitivity_threshold[0]) {
    knock_sensitivity_threshold[0] = 0x1f;
  }
  knock_sensitivity_threshold[1] =
       lookup_3D_uint8_interpolated
                 (16,16,(ushort)engine_speed_3,(ushort)load_2,CAL_knock_sensitivity_cylinder2,
                  CAL_knock_sensitivity_cylinder2_X_engine_speed,
                  CAL_knock_sensitivity_cylinder2_Y_engine_load);
  if (0x1f < knock_sensitivity_threshold[1]) {
    knock_sensitivity_threshold[1] = 0x1f;
  }
  knock_sensitivity_threshold[2] =
       lookup_3D_uint8_interpolated
                 (16,16,(ushort)engine_speed_3,(ushort)load_2,CAL_knock_sensitivity_cylinder3,
                  CAL_knock_sensitivity_cylinder3_X_engine_speed,
                  CAL_knock_sensitivity_cylinder3_Y_engine_load);
  if (0x1f < knock_sensitivity_threshold[2]) {
    knock_sensitivity_threshold[2] = 0x1f;
  }
  knock_sensitivity_threshold[3] =
       lookup_3D_uint8_interpolated
                 (16,16,(ushort)engine_speed_3,(ushort)load_2,CAL_knock_sensitivity_cylinder4,
                  CAL_knock_sensitivity_cylinder4_X_engine_speed,
                  CAL_knock_sensitivity_cylinder4_Y_engine_load);
  if (0x1f < knock_sensitivity_threshold[3]) {
    knock_sensitivity_threshold[3] = 0x1f;
  }
  knock_peak_threshold =
       lookup_3D_uint8_interpolated
                 (8,8,(ushort)engine_speed_3,(ushort)load_2,CAL_knock_peak_threshold,
                  CAL_knock_peak_threshold_X_engine_speed,CAL_knock_peak_threshold_Y_engine_load);
  if (((int)dt_tps_target_2 < -(int)(short)CAL_knock_retard1_dt_tps_target_2_max) ||
     ((short)CAL_knock_retard1_dt_tps_target_2_max < dt_tps_target_2)) {
    DAT_003f8d50 = CAL_knock_retard1_dt_tps_target_2_time;
  }
  bVar2 = lookup_2D_uint8_interpolated
                    (8,engine_speed_3,CAL_knock_retard_load_min,
                     CAL_knock_retard_load_min_X_engine_speed);
  if (bVar2 < load_2) {
    knock_flags = knock_flags | 0x10;
  }
  else {
    if (CAL_knock_load_margin < bVar2) {
      bVar2 = bVar2 - CAL_knock_load_margin;
    }
    else {
      bVar2 = 0;
    }
    if (load_2 < bVar2) {
      knock_flags = knock_flags & 0xef;
    }
  }
  if ((CAL_knock_retard1_engine_speed_min < engine_speed_3) &&
     (engine_speed_3 < CAL_knock_retard1_engine_speed_max)) {
    knock_flags = knock_flags | 0x20;
  }
  else {
    if ((uint)CAL_knock_retard1_engine_speed_max + (uint)CAL_knock_speed_margin < 0x100) {
      bVar2 = CAL_knock_retard1_engine_speed_max + CAL_knock_speed_margin;
    }
    else {
      bVar2 = 0xff;
    }
    if (CAL_knock_speed_margin < CAL_knock_retard1_engine_speed_min) {
      bVar3 = CAL_knock_retard1_engine_speed_min - CAL_knock_speed_margin;
    }
    else {
      bVar3 = 0;
    }
    if ((engine_speed_3 < bVar3) || (bVar2 < engine_speed_3)) {
      knock_flags = knock_flags & 0xdf;
    }
  }
  bVar2 = lookup_2D_uint8_interpolated
                    (8,engine_speed_3,CAL_knock_retard2_corr_load_min,
                     CAL_knock_retard2_corr_load_min_X_engine_speed);
  if (bVar2 < load_2) {
    knock_flags = knock_flags | 0x40;
  }
  else {
    if (CAL_knock_load_margin < bVar2) {
      bVar2 = bVar2 - CAL_knock_load_margin;
    }
    else {
      bVar2 = 0;
    }
    if (load_2 < bVar2) {
      knock_flags = knock_flags & 0xbf;
    }
  }
  if (((knock_flags & 0x10) == 0) || ((sensor_fault_flags & 0x100) != 0)) {
    knock_flags = knock_flags & 0xfa;
  }
  else {
    bVar2 = knock_flags | 4;
    if ((((DAT_003f8d50 == 0) && ((knock_flags & 0x20) != 0)) &&
        (CAL_knock_retard1_coolant_min < coolant_smooth)) &&
       (((sensor_fault_flags & 0x20) == 0 &&
        (knock_flags = bVar2, uVar1 = abs((int)vvt_diff), bVar2 = knock_flags,
        (int)uVar1 < (int)(uint)CAL_knock_retard1_vvt_diff_max)))) {
      knock_flags = knock_flags | 1;
    }
    else {
      knock_flags = bVar2;
      knock_flags = knock_flags & 0xfe;
    }
  }
  if (((knock_flags & 0x40) == 0) || ((knock_flags & 1) == 0)) {
    knock_flags = knock_flags & 0xfd;
  }
  else {
    knock_flags = knock_flags | 2;
  }
  if (ign_adv_knock < ign_adv_base) {
    knock_ign_diff = ign_adv_base - ign_adv_knock;
  }
  else {
    knock_ign_diff = 0;
  }
  knock_cyl_worst = LEA_knock_retard2[0];
  for (bVar2 = 1; bVar2 < 4; bVar2 = bVar2 + 1) {
    if (knock_cyl_worst < LEA_knock_retard2[bVar2]) {
      knock_cyl_worst = LEA_knock_retard2[bVar2];
    }
  }
  for (bVar2 = 0; bVar2 < 4; bVar2 = bVar2 + 1) {
    if ((knock_flags & 1) == 0) {
      knock_retard1[bVar2] = 0;
    }
    else if (knock_peak_over_threshold[bVar2] != 0) {
      bVar3 = lookup_2D_uint8_interpolated
                        (8,knock_peak_over_threshold[bVar2],CAL_knock_retard1_inc,
                         CAL_knock_retard1_inc_X_peak_over_threshold);
      knock_peak_over_threshold[bVar2] = 0;
      if ((uint)CAL_knock_retard1_limit < (uint)knock_retard1[bVar2] + (uint)bVar3) {
        knock_retard1[bVar2] = CAL_knock_retard1_limit;
      }
      else {
        knock_retard1[bVar2] = (u8_angle_1_4deg)((uint)knock_retard1[bVar2] + (uint)bVar3);
      }
    }
    if ((knock_flags & 4) == 0) {
      if ((sensor_fault_flags & 0x100) == 0) {
        knock_retard2[bVar2] = 0;
      }
      else {
        knock_retard2[bVar2] = (u8_angle_1_4deg)knock_ign_diff;
      }
    }
    else if (((knock_flags & 0x20) == 0) && (CAL_knock_retard1_engine_speed_min < engine_speed_3)) {
      knock_retard2[bVar2] =
           (u8_angle_1_4deg)((uint)knock_ign_diff * ((int)(uint)knock_cyl_worst >> 8) >> 8);
    }
    else {
      knock_retard2[bVar2] =
           (u8_angle_1_4deg)((uint)knock_ign_diff * ((int)(uint)LEA_knock_retard2[bVar2] >> 8) >> 8)
      ;
    }
    if (bVar2 == 0) {
      knock_retard2_sum = (i16_angle_1_4deg)knock_retard2[0];
    }
    else {
      knock_retard2_sum = knock_retard2_sum + (ushort)knock_retard2[bVar2];
    }
  }
  return;
}



// Reads knock sensor signal level for specified cylinder

void knock_read_signal(uint8_t cyl)

{
  ushort uVar1;
  byte bVar2;
  
  if (DAT_003f8d4a < 2000) {
    DAT_003f8d4a = DAT_003f8d4a + 1;
  }
  else {
    DAT_003f8d4a = 0;
    DAT_003f8d4c = 0;
    for (bVar2 = 0; bVar2 < 4; bVar2 = bVar2 + 1) {
      (&DAT_003f8124)[bVar2] = (char)((int)(uint)(ushort)(&DAT_003f811c)[bVar2] >> 1);
      DAT_003f8d4c = DAT_003f8d4c + (ushort)(byte)(&DAT_003f8124)[bVar2];
      (&DAT_003f811c)[bVar2] = 0;
    }
  }
  uVar1 = REG_QADCB_RJURR7;
  knock_signal[cyl] = uVar1;
  if (knock_first_read[cyl] != 0) {
    knock_signal_smooth[cyl] = (uint)knock_signal[cyl] << 8;
    knock_signal_smooth_low[cyl] = knock_signal[cyl];
    knock_first_read[cyl] = 0;
  }
  knock_peak[cyl] = (uint16_t)(((uint)knock_signal[cyl] * 10) / (knock_signal_smooth_low[cyl] + 1));
  if ((ushort)knock_peak_threshold < knock_peak[cyl]) {
    knock_detected = '\x01';
    (&DAT_003f811c)[cyl] = (&DAT_003f811c)[cyl] + 1;
    if ((ushort)(knock_peak[cyl] - (ushort)knock_peak_threshold) < 0xff) {
      knock_peak_over_threshold[cyl] = (uint8_t)(knock_peak[cyl] - (ushort)knock_peak_threshold);
    }
    else {
      knock_peak_over_threshold[cyl] = 255;
    }
    knock_retard1_timer[cyl] = 255;
  }
  else {
    knock_detected = '\0';
    knock_peak_over_threshold[cyl] = 0;
  }
  if ((knock_flags & 1) == 0) {
    if (CAL_knock_signal_smooth_limit_l == 0) {
      knock_signal_smooth[cyl] = (uint)knock_signal[cyl] << 8;
    }
    else {
      knock_signal_smooth[cyl] = (uint)CAL_knock_signal_smooth_limit_l << 8;
    }
  }
  else {
    if (knock_detected == '\0') {
      knock_signal_smooth[cyl] =
           ((0x100 - (uint)CAL_knock_signal_reactivity) * knock_signal_smooth[cyl] >> 8) +
           (uint)CAL_knock_signal_reactivity * (uint)knock_signal[cyl];
    }
    else {
      knock_signal_smooth[cyl] = (uint)CAL_knock_signal_fadeout_step + knock_signal_smooth[cyl];
    }
    if (knock_signal_smooth[cyl] >> 8 < (uint)CAL_knock_signal_smooth_limit_l) {
      knock_signal_smooth[cyl] = (uint)CAL_knock_signal_smooth_limit_l << 8;
    }
  }
  knock_signal_smooth_low[cyl] = (uint16_t)(knock_signal_smooth[cyl] >> 8);
  return;
}



// Updates the per-cylinder octane scaler based on knock activity.

void knock_retard2_5ms(void)

{
  uint uVar1;
  byte bVar2;
  
  for (bVar2 = 0; bVar2 < 4; bVar2 = bVar2 + 1) {
    if (knock_retard1[bVar2] == 0) {
      if ((ushort)CAL_knock_retard2_corr_dec_step < LEA_knock_retard2[bVar2]) {
        LEA_knock_retard2[bVar2] =
             LEA_knock_retard2[bVar2] - (ushort)CAL_knock_retard2_corr_dec_step;
      }
      else {
        LEA_knock_retard2[bVar2] = 0;
      }
    }
    else {
      uVar1 = (uint)LEA_knock_retard2[bVar2] +
              (uint)knock_retard1[bVar2] * (uint)CAL_knock_retard2_corr_inc_coef;
      if (uVar1 < 0x10000) {
        LEA_knock_retard2[bVar2] = (u16_factor_1_65536)uVar1;
      }
      else {
        LEA_knock_retard2[bVar2] = 65535;
      }
    }
  }
  return;
}



// SPI PCS2: L9119D knock sensor signal conditioner

void spi_pcs2(uint param_1)

{
  ushort uVar1;
  
  uVar1 = REG_MPIOSMDR;
  REG_MPIOSMDR = uVar1 & 0xfbff;
  uVar1 = REG_MPIOSMDR;
  REG_MPIOSMDR = uVar1 & 0xf7ff;
  if (knock_sensitivity_threshold[param_1 & 0xff] < 2) {
    send_spi_pcs2(DAT_003f810a & 0x3f | 0x40);
  }
  else {
    send_spi_pcs2(DAT_003f810a & 0x3f);
    send_spi_pcs2(DAT_003f810b & 0x3f | 0x80);
  }
  uVar1 = REG_MPIOSMDR;
  REG_MPIOSMDR = uVar1 & 0xfbff | 0x400;
  (&DAT_003f80e5)[param_1 & 0xff] =
       (&DAT_000786c4)[knock_sensitivity_threshold[param_1 & 0xff]] & 0xf;
  send_spi_pcs2((&DAT_003f80e5)[param_1 & 0xff]);
  uVar1 = REG_MPIOSMDR;
  REG_MPIOSMDR = uVar1 & 0xfbff;
  uVar1 = REG_MPIOSMDR;
  REG_MPIOSMDR = uVar1 & 0xf7ff | 0x800;
  (&DAT_003f80e9)[param_1 & 0xff] =
       (byte)(&DAT_000786c4)[knock_sensitivity_threshold[param_1 & 0xff]] >> 4;
  send_spi_pcs2((&DAT_003f80e9)[param_1 & 0xff]);
  (&DAT_003f812c)[param_1 & 0xff] = knock_sensitivity_threshold[param_1 & 0xff];
  uVar1 = REG_MPIOSMDR;
  REG_MPIOSMDR = uVar1 & 0xf7ff;
  return;
}



// Knock control task (5ms)

void knock_5ms(void)

{
  ushort uVar1;
  byte bVar2;
  
  if (!engine_is_running) {
    uVar1 = REG_MPIOSMDR;
    REG_MPIOSMDR = uVar1 & 0xffdf | 0x20;
    for (bVar2 = 0; bVar2 < 4; bVar2 = bVar2 + 1) {
      knock_first_read[bVar2] = 1;
    }
  }
  if (DAT_003f8135 < 10) {
    DAT_003f8135 = DAT_003f8135 + 1;
  }
  else {
    DAT_003f8135 = '\0';
    if (DAT_003f8d50 != '\0') {
      DAT_003f8d50 = DAT_003f8d50 + -1;
    }
    for (bVar2 = 0; bVar2 < 4; bVar2 = bVar2 + 1) {
      if ((knock_retard1_timer[bVar2] != 0) && (knock_retard1_timer[bVar2] != 255)) {
        knock_retard1_timer[bVar2] = knock_retard1_timer[bVar2] + 255;
      }
    }
    if ((knock_flags & 2) != 0) {
      knock_retard2_5ms();
    }
  }
  return;
}



// Main OBD diagnostic task - processes requests and monitors

void obd_task(void)

{
  ushort uVar1;
  int iVar2;
  
  uVar1 = obd_mil_flags;
  if (engine_speed_1 == 0) {
    if ((((DAT_003f93a6 == '\0') || (LEA_obd_monitors_completeness == 0)) || (ecu_runtime < 0x97))
       || (0xf9 < ecu_runtime)) {
      uVar1 = obd_mil_flags | 8;
    }
    else if ((obd_task_scheduler & 1) != 0) {
      obd_task_scheduler = obd_task_scheduler & 0xfffe;
      DAT_003f8d5e = DAT_003f8d5e + 1;
      if (4 < DAT_003f8d5e) {
        DAT_003f8d5e = 0;
        uVar1 = obd_mil_flags ^ 8;
      }
    }
  }
  else if ((obd_mil_flags & 2) == 0) {
    if ((obd_mil_flags & 1) == 0) {
      if ((obd_mil_flags & 4) == 0) {
        uVar1 = obd_mil_flags & 0xfff7;
      }
      else if ((obd_task_scheduler & 1) != 0) {
        obd_task_scheduler = obd_task_scheduler & 0xfffe;
        DAT_003f8d5e = DAT_003f8d5e + 1;
        if (0x1c < DAT_003f8d5e) {
          uVar1 = obd_mil_flags | 8;
          if (0x1d < DAT_003f8d5e) {
            DAT_003f8d5e = 0;
            uVar1 = obd_mil_flags & 0xfff7;
          }
        }
      }
    }
    else {
      uVar1 = obd_mil_flags | 8;
    }
  }
  else if ((obd_task_scheduler & 1) != 0) {
    obd_task_scheduler = obd_task_scheduler & 0xfffe;
    DAT_003f8d5e = DAT_003f8d5e + 1;
    if (4 < DAT_003f8d5e) {
      DAT_003f8d5e = 0;
      uVar1 = obd_mil_flags ^ 8;
    }
  }
  obd_mil_flags = uVar1;
  iVar2 = obd_init_state_machine();
  if (iVar2 != 0) {
    if (DAT_003fd3d4 != '\0') {
      DAT_003fd3d4 = '\0';
      obd_clear_freeze();
    }
    if ((int)(uint)DAT_003fbf24 <
        (int)(short)(ushort)coolant_smooth - (int)(short)(ushort)coolant_stop) {
      if (DAT_003fbf25 < coolant_smooth) {
        DAT_003f8d58 = 1;
      }
    }
    obd_temp = (u8_temp_1_40c)((uint)coolant_smooth * 0xa0 >> 8);
    iVar2 = (int)(short)((int)inj_time_adj_by_stft << 3);
    iVar2 = iVar2 / 0x7d + (iVar2 >> 0x1f);
    obd_stft = ((char)iVar2 - (char)(iVar2 >> 0x1f)) + 128;
    iVar2 = (int)(short)((int)inj_time_adj_by_ltft << 3);
    iVar2 = iVar2 / 0x7d + (iVar2 >> 0x1f);
    obd_ltft = ((char)iVar2 - (char)(iVar2 >> 0x1f)) + 128;
    if (DAT_002f830e != 0) {
      obd_freeze_compare();
    }
    if (engine_is_running != false) {
      engine_has_started = true;
    }
    obd_check_misfire();
    obd_check_catalyst();
    obd_check_fuel_trim();
    obd_check_o2_slow_response();
    if ((obd_task_scheduler & 2) == 0) {
      if ((obd_task_scheduler & 4) == 0) {
        if ((obd_task_scheduler & 8) == 0) {
          if ((obd_task_scheduler & 0x10) == 0) {
            if ((obd_task_scheduler & 0x40) != 0) {
              obd_task_scheduler = obd_task_scheduler & 0xffbf;
              if ((obd_mil_flags & 1) == 0) {
                obd_mil_flags = obd_mil_flags & 0xffef;
              }
              else {
                if (engine_is_running != false) {
                  if ((obd_mil_flags & 0x10) == 0) {
                    DAT_003fd3d8 = 0;
                  }
                  DAT_003fd3d8 = DAT_003fd3d8 + wheel_speed_r_max / 0x168;
                  if (0x270fd8f0 < DAT_003fd3d8) {
                    DAT_003fd3d8 = 0x3e7fc18;
                  }
                }
                obd_mil_flags = obd_mil_flags | 0x10;
              }
            }
          }
          else {
            obd_task_scheduler = obd_task_scheduler & 0xffef;
            perf_counter();
            obd_check_ecu_internal();
            obd_check_fuel_evap_press();
            obd_check_vvl();
            obd_check_vvt();
            obd_check_pps();
            obd_check_tps_correlation();
          }
        }
        else {
          obd_task_scheduler = obd_task_scheduler & 0xfff7;
          obd_check_o2_activity();
          obd_check_crank_cam_speed();
          obd_check_idle_speed();
          obd_check_thermostat();
          obd_check_evap_leak();
          obd_check_evap_flow();
          obd_check_iumpr();
        }
      }
      else {
        obd_task_scheduler = obd_task_scheduler & 0xfffb;
        obd_check_outputs();
      }
    }
    else {
      obd_task_scheduler = obd_task_scheduler & 0xfffd;
      obd_update_dtc_list();
      DAT_003f8d60 = DAT_003f8d60 + 1;
      if (9 < DAT_003f8d60) {
        DAT_003f8d60 = 0;
        DAT_003f8d61 = DAT_003f8d61 + 1;
        if (DAT_003f8d61 < 0x80) {
          if (obd_trouble_list[DAT_003f8d61] == 0) {
            DAT_003f8d61 = 0;
          }
        }
        else {
          DAT_003f8d61 = 0;
        }
        DAT_003fd3d0 = obd_trouble_list[DAT_003f8d61];
        DAT_003f8d62 = DAT_003f8d62 + 1;
        if (DAT_003f8d62 < 0x80) {
          if (obd_pending_list[DAT_003f8d62] == 0) {
            DAT_003f8d62 = 0;
          }
        }
        else {
          DAT_003f8d62 = 0;
        }
        DAT_003fd3d2 = obd_pending_list[DAT_003f8d62];
      }
    }
  }
  return;
}



// Compares current conditions to stored freeze frame

void obd_freeze_compare(void)

{
  uint uVar1;
  
  uVar1 = abs((uint)engine_speed_1 - (uint)DAT_002f8310);
  if (((int)uVar1 < (int)(uint)DAT_003fbf2a) && (DAT_003f8d58 == DAT_002f8316)) {
    if (DAT_003fd3c8 == 0) {
      DAT_003fd3b4 = 1;
    }
  }
  else {
    DAT_003fd3c8 = DAT_003fbf2c;
  }
  return;
}



// WARNING: Inlined function: push_27to31
// WARNING: Inlined function: pop_27to31
// Sets OBD DTC with maturation counter

void obd_set_dtc(u8_obd_config *obd_config,uint8_t *obd_flags,uint8_t *engine_start_counter,
                uint8_t *warm_up_cycle_counter,uint obd_code)

{
  ushort uVar1;
  byte bVar3;
  ushort uVar2;
  
  if ((*obd_config & 0x10) != 0) {
    DAT_003f8d68 = *obd_config;
    DAT_003f8d64 = obd_code;
    obd_freeze2(DAT_003f8d68,obd_code);
  }
  bVar3 = *obd_config & 7;
  if (bVar3 == 2) {
    if (((*obd_flags & 8) == 0) && ((*obd_config & 0x40) != 0)) {
      DAT_003f8d5a = DAT_003f8d5a + '\x01';
    }
    *obd_flags = *obd_flags | 0xc;
    *engine_start_counter = 0;
    *warm_up_cycle_counter = 0;
    if ((*obd_flags & 0x10) == 0) {
      if ((*obd_flags & 0x80) == 0) {
        *obd_flags = *obd_flags | 0x80;
        obd_add_pending(obd_code & 0xffff);
      }
    }
    else {
      *obd_flags = *obd_flags | 1;
      *obd_flags = *obd_flags & 0xef;
      if (DAT_002f830e == 0) {
        DAT_002f830e = (ushort)(obd_code << 3) | *obd_config & 7;
        DAT_002f8312 = load_3;
        DAT_002f8314 = maf_flow_1;
        DAT_002f8310 = engine_speed_1;
        DAT_002f8316 = DAT_003f8d58;
        DAT_002f8317 = DAT_002f82c3;
      }
      if ((((*obd_config & 0x10) != 0) &&
          (obd_mil_flags = obd_mil_flags | 1, (LEA_obd_freeze_dtc & 7) != 2)) &&
         ((LEA_obd_freeze_dtc & 7) != 4)) {
        LEA_obd_freeze_dtc = (ushort)(obd_code << 3) | *obd_config & 7;
        LEA_obd_freeze_fuel_system_status = (uint8_t)fuel_system_status;
        LEA_obd_freeze_engine_speed = engine_speed_1;
        LEA_obd_freeze_load = load_3;
        LEA_obd_freeze_car_speed = car_speed_smooth;
        LEA_obd_freeze_maf_flow = maf_flow_1;
        LEA_obd_freeze_tps = (u8_factor_1_255)((int)(uint)sensor_adc_tps_1 >> 2);
        LEA_obd_freeze_stft = obd_stft;
        LEA_obd_freeze_ltft = obd_ltft;
        LEA_obd_freeze_coolant = obd_temp;
      }
      if ((*obd_flags & 0x80) == 0) {
        *obd_flags = *obd_flags | 0x80;
        obd_add_trouble(obd_code & 0xffff);
      }
    }
  }
  else if (bVar3 < 2) {
    if (((*obd_config & 7) != 0) && (true)) {
      if (((*obd_flags & 8) == 0) && ((*obd_config & 0x40) != 0)) {
        DAT_003f8d5a = DAT_003f8d5a + '\x01';
      }
      *obd_flags = *obd_flags | 0xd;
      *engine_start_counter = 0;
      *warm_up_cycle_counter = 0;
      if ((((*obd_config & 0x10) != 0) &&
          (uVar1 = obd_mil_flags | 1, uVar2 = obd_mil_flags & 2, obd_mil_flags = uVar1, uVar2 == 0))
         && (LEA_obd_freeze_dtc == 0)) {
        LEA_obd_freeze_dtc = (ushort)(obd_code << 3) | *obd_config & 7;
        LEA_obd_freeze_fuel_system_status = (uint8_t)fuel_system_status;
        LEA_obd_freeze_engine_speed = engine_speed_1;
        LEA_obd_freeze_load = load_3;
        LEA_obd_freeze_car_speed = car_speed_smooth;
        LEA_obd_freeze_maf_flow = maf_flow_1;
        LEA_obd_freeze_tps = (u8_factor_1_255)((int)(uint)sensor_adc_tps_1 >> 2);
        LEA_obd_freeze_stft = obd_stft;
        LEA_obd_freeze_ltft = obd_ltft;
        LEA_obd_freeze_coolant = obd_temp;
      }
      if (((*obd_flags & 0x80) == 0) && ((*obd_flags & 4) != 0)) {
        *obd_flags = *obd_flags | 0x80;
        obd_add_trouble(obd_code & 0xffff);
      }
    }
  }
  else if (bVar3 == 4) {
    if (((*obd_flags & 8) == 0) && ((*obd_config & 0x40) != 0)) {
      DAT_003f8d5a = DAT_003f8d5a + '\x01';
    }
    *obd_flags = *obd_flags | 0xd;
    *engine_start_counter = 0;
    *warm_up_cycle_counter = 0;
    if (DAT_002f830e == 0) {
      DAT_002f830e = (ushort)(obd_code << 3) | *obd_config & 7;
      DAT_002f8312 = load_3;
      DAT_002f8314 = maf_flow_1;
      DAT_002f8310 = engine_speed_1;
      DAT_002f8316 = DAT_003f8d58;
      DAT_002f8317 = DAT_002f82c3;
    }
    if ((((*obd_config & 0x10) != 0) &&
        (obd_mil_flags = obd_mil_flags | 2, (LEA_obd_freeze_dtc & 7) != 2)) &&
       ((LEA_obd_freeze_dtc & 7) != 4)) {
      LEA_obd_freeze_dtc = (ushort)(obd_code << 3) | *obd_config & 7;
      LEA_obd_freeze_fuel_system_status = (uint8_t)fuel_system_status;
      LEA_obd_freeze_engine_speed = engine_speed_1;
      LEA_obd_freeze_load = load_3;
      LEA_obd_freeze_car_speed = car_speed_smooth;
      LEA_obd_freeze_maf_flow = maf_flow_1;
      LEA_obd_freeze_tps = (u8_factor_1_255)((int)(uint)sensor_adc_tps_1 >> 2);
      LEA_obd_freeze_stft = obd_stft;
      LEA_obd_freeze_ltft = obd_ltft;
      LEA_obd_freeze_coolant = obd_temp;
    }
    if (((*obd_flags & 0x80) == 0) && ((*obd_flags & 4) != 0)) {
      *obd_flags = *obd_flags | 0x80;
      obd_add_trouble(obd_code & 0xffff);
    }
  }
  else if (bVar3 < 4) {
    if (((*obd_flags & 8) == 0) && ((*obd_config & 0x40) != 0)) {
      DAT_003f8d5a = DAT_003f8d5a + '\x01';
    }
    *obd_flags = *obd_flags | 0xc;
    *engine_start_counter = 0;
    *warm_up_cycle_counter = 0;
    if ((*obd_flags & 0x10) == 0) {
      if ((*obd_flags & 0x80) == 0) {
        *obd_flags = *obd_flags | 0x80;
        obd_add_pending(obd_code & 0xffff);
      }
    }
    else {
      *obd_flags = *obd_flags | 1;
      *obd_flags = *obd_flags & 0xef;
      if ((((*obd_config & 0x10) != 0) &&
          (uVar2 = obd_mil_flags | 1, uVar1 = obd_mil_flags & 2, obd_mil_flags = uVar2, uVar1 == 0))
         && (LEA_obd_freeze_dtc == 0)) {
        LEA_obd_freeze_dtc = (ushort)(obd_code << 3) | *obd_config & 7;
        LEA_obd_freeze_fuel_system_status = (uint8_t)fuel_system_status;
        LEA_obd_freeze_engine_speed = engine_speed_1;
        LEA_obd_freeze_load = load_3;
        LEA_obd_freeze_car_speed = car_speed_smooth;
        LEA_obd_freeze_maf_flow = maf_flow_1;
        LEA_obd_freeze_tps = (u8_factor_1_255)((int)(uint)sensor_adc_tps_1 >> 2);
        LEA_obd_freeze_stft = obd_stft;
        LEA_obd_freeze_ltft = obd_ltft;
        LEA_obd_freeze_coolant = obd_temp;
      }
      if ((*obd_flags & 0x80) == 0) {
        *obd_flags = *obd_flags | 0x80;
        obd_add_trouble(obd_code & 0xffff);
      }
    }
  }
  return;
}



// Clears OBD DTC pending/confirmed status

void obd_clr_dtc(u8_obd_config *obd_config,uint8_t *obd_flags)

{
  byte bVar1;
  
  bVar1 = *obd_config & 7;
  if (bVar1 == 2) {
    if (((*obd_flags & 8) == 0) && ((*obd_config & 0x40) != 0)) {
      DAT_003f8d5a = DAT_003f8d5a + '\x01';
    }
    *obd_flags = *obd_flags | 8;
  }
  else if (bVar1 < 2) {
    if (((*obd_config & 7) != 0) && (true)) {
      if (((*obd_flags & 8) == 0) && ((*obd_config & 0x40) != 0)) {
        DAT_003f8d5a = DAT_003f8d5a + '\x01';
      }
      *obd_flags = *obd_flags | 8;
    }
  }
  else if (bVar1 == 4) {
    if (((*obd_flags & 8) == 0) && ((*obd_config & 0x40) != 0)) {
      DAT_003f8d5a = DAT_003f8d5a + '\x01';
    }
    *obd_flags = *obd_flags | 8;
    if (((*obd_flags & 1) != 0) && ((*obd_config & 0x10) != 0)) {
      obd_mil_flags = obd_mil_flags & 0xfffd | 1;
    }
  }
  else if (bVar1 < 4) {
    if (((*obd_flags & 8) == 0) && ((*obd_config & 0x40) != 0)) {
      DAT_003f8d5a = DAT_003f8d5a + '\x01';
    }
    *obd_flags = *obd_flags | 8;
  }
  return;
}



// Stores freeze frame data for DTC

void obd_freeze2(ushort param_1,int param_2)

{
  LEA_obd_freeze2_dtc = (ushort)(param_2 << 3) | param_1 & 7;
  LEA_obd_freeze2_engine_speed = engine_speed_1;
  LEA_obd_freeze2_maf_flow = maf_flow_1;
  LEA_obd_freeze2_car_speed = car_speed_smooth;
  LEA_obd_freeze2_stft = inj_time_adj_by_stft;
  LEA_obd_freeze2_ltft = inj_time_adj_by_ltft;
  LEA_obd_freeze2_coolant = coolant_smooth;
  LEA_obd_freeze2_coolant_stop = coolant_stop;
  LEA_obd_freeze2_engine_air = engine_air_smooth;
  LEA_obd_freeze2_tps = tps;
  LEA_obd_freeze2_engine_runtime = engine_runtime;
  LEA_obd_freeze2_sensor_adc_pre_o2 = sensor_adc_pre_o2;
  LEA_obd_freeze2_sensor_adc_post_o2 = sensor_adc_post_o2;
  return;
}



// Prepares OBD data before EEPROM save

void obd_pre_save(void)

{
  DAT_003f8d59 = engine_has_started;
  if (engine_has_started) {
    DAT_002f82c3 = DAT_002f82c3 + 1;
  }
  if ((uint)((int)(short)(ushort)DAT_002f8317 + (int)(short)(ushort)DAT_003fbf27) <=
      (uint)(int)(short)(ushort)DAT_002f82c3) {
    DAT_002f830e = 0;
    DAT_002f8312 = 0;
    DAT_002f8314 = 0;
    DAT_002f8310 = 0;
    DAT_002f8316 = 0;
    DAT_002f8317 = 0;
  }
  if (DAT_003fbf26 <= DAT_003f8d5a) {
    DAT_002f8322 = DAT_002f8322 + '\x01';
    DAT_003f8d5d = 1;
  }
  obd_cyc_sensors();
  obd_cyc_outputs();
  obd_cyc_catalyst();
  obd_cyc_fuel_trim();
  obd_cyc_o2_response();
  obd_cyc_crank_cam_speed();
  obd_cyc_idle_speed();
  obd_cyc_misfire();
  obd_cyc_ecu_internal();
  obd_cyc_fuel_evap_press();
  obd_cyc_thermostat();
  obd_cyc_vvt_vvl();
  obd_cyc_evap_leak();
  obd_cyc_evap_flow();
  obd_cyc_pps();
  obd_cyc_tps_throttle();
  return;
}



// Updates OBD DTC cycle counter for self-healing

void obd_cyc_dtc(u8_obd_config *obd_config,uint8_t *obd_flags,uint8_t *engine_start_counter,
                uint8_t *warm_up_cycle_counter,uint obd_code)

{
  uint8_t uVar1;
  
  if (((((DAT_003f8d59 != '\0') && ((*obd_flags & 8) != 0)) && ((*obd_flags & 4) == 0)) &&
      (((int)(uint)DAT_002f830e >> 3 != obd_code ||
       ((DAT_003fd3b4 != '\0' && ((int)(uint)DAT_002f830e >> 3 == obd_code)))))) &&
     (uVar1 = *engine_start_counter, *engine_start_counter = uVar1 + 1, 2 < (byte)(uVar1 + 1))) {
    *obd_flags = *obd_flags & 0xfe;
  }
  if (((DAT_003f8d58 != '\0') && ((*obd_flags & 8) != 0)) &&
     (((*obd_flags & 4) == 0 &&
      ((*warm_up_cycle_counter = *warm_up_cycle_counter + 1,
       CAL_obd_warm_up_cycles_clear_freeze_frame <= *warm_up_cycle_counter &&
       (*obd_flags = *obd_flags & 0xfd, (int)(uint)LEA_obd_freeze_dtc >> 3 == obd_code)))))) {
    LEA_obd_freeze_dtc = 0;
    LEA_obd_freeze_engine_speed = 0;
    LEA_obd_freeze_fuel_system_status = 0;
    LEA_obd_freeze_load = 0;
    LEA_obd_freeze_car_speed = 0;
    LEA_obd_freeze_maf_flow = 0;
    LEA_obd_freeze_tps = 0;
    LEA_obd_freeze_stft = 0;
    LEA_obd_freeze_ltft = 0;
    LEA_obd_freeze_coolant = 0;
    DAT_003fd3d8 = 0;
  }
  if (DAT_003f8d5d != '\0') {
    if ((*obd_flags & 4) == 0) {
      if (((*obd_flags & 8) != 0) && ((*obd_flags & 0x10) != 0)) {
        *obd_flags = *obd_flags & 0xed;
      }
    }
    else if (((*obd_flags & 2) == 0) &&
            ((*obd_flags = *obd_flags | 2, (*obd_config & 7) == 2 || ((*obd_config & 7) == 3)))) {
      *obd_flags = *obd_flags | 0x10;
    }
    *obd_flags = *obd_flags & 0xfb;
  }
  *obd_flags = *obd_flags & 0x7f;
  return;
}



// Initializes OBD diagnostic state machine at startup

undefined4 obd_init_state_machine(void)

{
  undefined4 uVar1;
  
  switch(DAT_003fd3ce) {
  case '\0':
    DAT_003fd3ce = DAT_003fd3ce + '\x01';
    uVar1 = 0;
    break;
  case '\x01':
    obd_init_nop();
    DAT_003fd3ce = DAT_003fd3ce + '\x01';
    uVar1 = 0;
    break;
  case '\x02':
    obd_init_sensors();
    DAT_003fd3ce = DAT_003fd3ce + '\x01';
    uVar1 = 0;
    break;
  case '\x03':
    obd_init_outputs();
    DAT_003fd3ce = DAT_003fd3ce + '\x01';
    uVar1 = 0;
    break;
  case '\x04':
    obd_init_catalyst();
    DAT_003fd3ce = DAT_003fd3ce + '\x01';
    uVar1 = 0;
    break;
  case '\x05':
    obd_init_fuel_trim();
    DAT_003fd3ce = DAT_003fd3ce + '\x01';
    uVar1 = 0;
    break;
  case '\x06':
    obd_init_o2_response();
    DAT_003fd3ce = DAT_003fd3ce + '\x01';
    uVar1 = 0;
    break;
  case '\a':
    obd_init_crank_cam_speed();
    DAT_003fd3ce = DAT_003fd3ce + '\x01';
    uVar1 = 0;
    break;
  case '\b':
    obd_init_fuel_evap_press();
    DAT_003fd3ce = DAT_003fd3ce + '\x01';
    uVar1 = 0;
    break;
  case '\t':
    obd_init_idle_speed();
    DAT_003fd3ce = DAT_003fd3ce + '\x01';
    uVar1 = 0;
    break;
  case '\n':
    obd_init_vvt_vvl();
    DAT_003fd3ce = DAT_003fd3ce + '\x01';
    uVar1 = 0;
    break;
  case '\v':
    obd_init_misfire();
    DAT_003fd3ce = DAT_003fd3ce + '\x01';
    uVar1 = 0;
    break;
  case '\f':
    obd_init_evap_leak();
    DAT_003fd3ce = DAT_003fd3ce + '\x01';
    uVar1 = 0;
    break;
  case '\r':
    obd_init_evap_flow();
    DAT_003fd3ce = DAT_003fd3ce + '\x01';
    uVar1 = 0;
    break;
  case '\x0e':
    obd_init_ecu_internal();
    DAT_003fd3ce = DAT_003fd3ce + '\x01';
    uVar1 = 0;
    break;
  case '\x0f':
    obd_init_thermostat();
    DAT_003fd3ce = DAT_003fd3ce + '\x01';
    uVar1 = 0;
    break;
  case '\x10':
    obd_mil_flags = obd_mil_flags | 0x10;
    DAT_003fd3ce = DAT_003fd3ce + '\x01';
    uVar1 = 0;
    break;
  case '\x11':
    obd_init_pps();
    DAT_003fd3ce = DAT_003fd3ce + '\x01';
    uVar1 = 0;
    break;
  case '\x12':
    obd_init_tps_throttle();
    DAT_003fd3ce = DAT_003fd3ce + '\x01';
    uVar1 = 0;
    break;
  case '\x13':
    obd_init_iumpr();
    DAT_003fd3ce = DAT_003fd3ce + '\x01';
    uVar1 = 0;
    break;
  default:
    uVar1 = 1;
  }
  return uVar1;
}



// Initializes OBD DTC state at startup

void obd_init_dtc(byte *param_1,byte *param_2,undefined2 param_3)

{
  byte bVar1;
  
  bVar1 = *param_1 & 7;
  if (bVar1 == 2) {
    if (((*param_1 & 0x10) != 0) && ((*param_2 & 1) != 0)) {
      obd_mil_flags = obd_mil_flags | 1;
    }
    if ((*param_2 & 0x10) == 0) {
      if ((*param_2 & 2) != 0) {
        *param_2 = *param_2 | 0x80;
        obd_add_trouble(param_3);
      }
    }
    else {
      obd_add_pending(param_3);
    }
  }
  else if (bVar1 < 2) {
    if (((*param_1 & 7) != 0) && (true)) {
      if (((*param_1 & 0x10) != 0) && ((*param_2 & 1) != 0)) {
        obd_mil_flags = obd_mil_flags | 1;
      }
      if ((*param_2 & 2) != 0) {
        *param_2 = *param_2 | 0x80;
        obd_add_trouble(param_3);
      }
    }
  }
  else if (bVar1 == 4) {
    if (((*param_1 & 0x10) != 0) && ((*param_2 & 1) != 0)) {
      obd_mil_flags = obd_mil_flags | 0x10;
    }
    if ((*param_2 & 2) != 0) {
      *param_2 = *param_2 | 0x80;
      obd_add_trouble(param_3);
    }
  }
  else if (bVar1 < 4) {
    if (((*param_1 & 0x10) != 0) && ((*param_2 & 1) != 0)) {
      obd_mil_flags = obd_mil_flags | 1;
    }
    if ((*param_2 & 0x10) == 0) {
      if ((*param_2 & 2) != 0) {
        *param_2 = *param_2 | 0x80;
        obd_add_trouble(param_3);
      }
    }
    else {
      obd_add_pending(param_3);
    }
  }
  return;
}



// Catalyst efficiency monitor (P0420)

void obd_check_catalyst(void)

{
  ushort uVar1;
  int iVar2;
  byte bVar4;
  uint uVar3;
  short sVar5;
  
  DAT_003f8d71 = lookup_2D_uint8_interpolated(8,coolant_stop,&DAT_003fce72,&DAT_003fce6a);
  bVar4 = lookup_2D_uint8_fixed(8,(uint8_t)(maf_flow_1 / 100),&DAT_003fce7a);
  cat_diag_pre_o2_max_sw = (uint16_t)bVar4;
  bVar4 = lookup_2D_uint8_fixed(8,(uint8_t)(maf_flow_1 / 100),&DAT_002f82cf);
  cat_diag_pre_o2_sw = (uint16_t)bVar4;
  bVar4 = lookup_2D_uint8_fixed(8,(uint8_t)(maf_flow_1 / 100),&DAT_002f82df);
  DAT_003fd3ec = (ushort)bVar4;
  if (((((((uint)((int)(uint)maf_accumulated_2 >> 4) < (uint)DAT_003f8d71) ||
         (coolant_smooth <= DAT_003fbf54)) || (engine_air_smooth <= DAT_003fbf55)) ||
       (((int)atmo_pressure <= (int)(uint)DAT_003fbf52 || ((fuel_system_status & 2) == 0)))) ||
      ((car_speed_smooth < DAT_003fbf5f ||
       ((DAT_003fbf5e <= car_speed_smooth || (maf_flow_1 <= DAT_003fbf56)))))) ||
     ((DAT_003fbf58 <= maf_flow_1 || ((DAT_003f8d78 != 0 || (DAT_003f8d7a != 0)))))) {
    DAT_003fd3ea = DAT_003fd3ea & 0xffbc;
  }
  else if ((((((((LEA_obd_P0420_flags & 8) == 0) && ((CAL_obd_P0420 & 7) != 0)) &&
              ((LEA_obd_P0131_flags & 4) == 0)) &&
             ((((LEA_obd_P0132_flags & 4) == 0 && ((LEA_obd_P0133_flags & 4) == 0)) &&
              (((LEA_obd_P0134_flags & 4) == 0 &&
               (((LEA_obd_P0135_flags & 4) == 0 && ((LEA_obd_P0137_flags & 4) == 0)))))))) &&
            ((LEA_obd_P0138_flags & 4) == 0)) &&
           ((((LEA_obd_P0139_flags & 4) == 0 && ((LEA_obd_P0140_flags & 4) == 0)) &&
            ((LEA_obd_P0141_flags & 4) == 0)))) &&
          ((((((LEA_obd_P0116_flags & 4) == 0 && ((LEA_obd_P0500_flags & 4) == 0)) &&
             ((((LEA_obd_P0117_flags & 4) == 0 &&
               (((LEA_obd_P0118_flags & 4) == 0 && ((LEA_obd_P0107_flags & 4) == 0)))) &&
              ((LEA_obd_P0108_flags & 4) == 0)))) &&
            ((((((LEA_obd_P0171_flags & 4) == 0 && ((LEA_obd_P0172_flags & 4) == 0)) &&
               ((LEA_obd_P0300_flags & 4) == 0)) &&
              (((LEA_obd_P0301_flags & 4) == 0 && ((LEA_obd_P0302_flags & 4) == 0)))) &&
             (((LEA_obd_P0303_flags & 4) == 0 &&
              (((LEA_obd_P0101_flags & 4) == 0 && ((LEA_obd_P0102_flags & 4) == 0)))))))) &&
           (((LEA_obd_P0103_flags & 4) == 0 && ((LEA_obd_P0304_flags & 4) == 0)))))) {
    if (cat_diag_pre_o2_sw < cat_diag_pre_o2_max_sw) {
      uVar1 = DAT_003fd3ea | 0x43;
      for (sVar5 = 0; ((uint)(byte)(&DAT_002f82cf)[sVar5] < maf_flow_1 / 100 && (sVar5 < 7));
          sVar5 = sVar5 + 1) {
      }
      if (DAT_003fbf78 < (short)sensor_adc_pre_o2) {
        if (((DAT_003fd3ea & 4) != 0) || ((DAT_003fd3ea & 8) == 0)) {
          DAT_003fd3ea = uVar1;
          (&DAT_002f82d7)[sVar5] = (&DAT_002f82d7)[sVar5] + '\x01';
          uVar1 = DAT_003fd3ea & 0xfffb | 8;
        }
      }
      else if (((short)sensor_adc_pre_o2 < DAT_003fbf76) &&
              (((DAT_003fd3ea & 8) != 0 || ((DAT_003fd3ea & 4) == 0)))) {
        DAT_003fd3ea = uVar1;
        (&DAT_002f82d7)[sVar5] = (&DAT_002f82d7)[sVar5] + '\x01';
        uVar1 = DAT_003fd3ea & 0xfff7 | 4;
      }
      DAT_003fd3ea = uVar1;
      iVar2 = DAT_003fd3f0 / 0xa00 + (DAT_003fd3f0 >> 0x1f);
      if ((iVar2 - (iVar2 >> 0x1f)) + (int)DAT_003fbf7c < (int)(short)sensor_adc_post_o2) {
        if (((DAT_003fd3ea & 0x10) != 0) || ((DAT_003fd3ea & 0x20) == 0)) {
          (&DAT_002f82e7)[sVar5] = (&DAT_002f82e7)[sVar5] + '\x01';
          DAT_003fd3ea = DAT_003fd3ea & 0xffef | 0x20;
        }
      }
      else {
        iVar2 = DAT_003fd3f0 / 0xa00 + (DAT_003fd3f0 >> 0x1f);
        if (((int)(short)sensor_adc_post_o2 < (iVar2 - (iVar2 >> 0x1f)) - (int)DAT_003fbf7a) &&
           (((DAT_003fd3ea & 0x20) != 0 || ((DAT_003fd3ea & 0x10) == 0)))) {
          (&DAT_002f82e7)[sVar5] = (&DAT_002f82e7)[sVar5] + '\x01';
          DAT_003fd3ea = DAT_003fd3ea & 0xffdf | 0x10;
        }
      }
      iVar2 = DAT_003fd3f0 / 0xa00 + (DAT_003fd3f0 >> 0x1f);
      if (iVar2 - (iVar2 >> 0x1f) < (int)(short)sensor_adc_post_o2) {
        DAT_003fd3ea = DAT_003fd3ea & 0xffef;
      }
      else {
        DAT_003fd3ea = DAT_003fd3ea & 0xffdf;
      }
    }
    else {
      DAT_003fd3ea = DAT_003fd3ea & 0xffbf | 3;
      for (sVar5 = 0; ((uint)(byte)(&DAT_002f82cf)[sVar5] < maf_flow_1 / 100 && (sVar5 < 7));
          sVar5 = sVar5 + 1) {
      }
      DAT_002f82ff = DAT_002f82ff | (byte)(1 << ((int)sVar5 & 0x3fU));
    }
  }
  else {
    DAT_003fd3ea = DAT_003fd3ea & 0xffbd | 1;
  }
  if (DAT_002f82ff == 0xff) {
    for (iVar2 = 8; iVar2 < 0x10; iVar2 = iVar2 + 1) {
      DAT_003f8d72 = DAT_003f8d72 + (byte)(&DAT_002f82cf)[iVar2];
      DAT_003f8d74 = DAT_003f8d74 + (byte)(&DAT_002f82df)[iVar2];
    }
    uVar3 = ((uint)DAT_003f8d74 * 1000) / (uint)DAT_003f8d72;
    DAT_002f8352 = (ushort)uVar3;
    if ((uint)DAT_002f8272 < (uVar3 & 0xffff)) {
      DAT_002f8272 = DAT_002f8352;
      sort10(&DAT_002f8272);
    }
    if (DAT_002f8352 < DAT_003fbf7e) {
      obd_clr_dtc(&CAL_obd_P0420,&LEA_obd_P0420_flags);
      if (obd_P0420_debounce_count < CAL_obd_P0420_debounce_threshold) {
        obd_P0420_debounce_count = obd_P0420_debounce_count + 1;
      }
      DAT_002f82ff = 0;
    }
    else if (obd_P0420_debounce_count == 0) {
      obd_set_dtc(&CAL_obd_P0420,&LEA_obd_P0420_flags,&LEA_obd_P0420_engine_start_count,
                  &LEA_obd_P0420_warm_up_cycle_count,0x1a4);
      DAT_002f82ff = 0;
    }
    else {
      obd_P0420_debounce_count = obd_P0420_debounce_count + 255;
    }
    for (iVar2 = 8; iVar2 < 0x10; iVar2 = iVar2 + 1) {
      (&DAT_002f82df)[iVar2] = 0;
      (&DAT_002f82cf)[iVar2] = 0;
    }
  }
  if ((((LEA_obd_P0420_flags & 8) != 0) && ((LEA_obd_P0420_flags & 4) == 0)) ||
     (((LEA_obd_P0420_flags & 4) != 0 && ((LEA_obd_P0420_flags & 0x10) != 0)))) {
    LEA_obd_monitors_completeness = LEA_obd_monitors_completeness & 0xfe;
  }
  if (((LEA_obd_P0420_flags & 8) != 0) && ((CAL_obd_P0420 & 8) != 0)) {
    LEA_obd_P0420_flags = LEA_obd_P0420_flags & 0xf7;
  }
  return;
}



// Catalyst monitor task (5ms)

void obd_check_catalyst_5ms(void)

{
  int iVar1;
  
  iVar1 = (0xa00 - (uint)DAT_003fbf5a) * DAT_003fd3f0;
  iVar1 = iVar1 / 0xa00 + (iVar1 >> 0x1f);
  DAT_003fd3f0 = (iVar1 - (iVar1 >> 0x1f)) + (uint)DAT_003fbf5a * (uint)sensor_adc_post_o2;
  if (DAT_003f8d78 < DAT_003fcff2) {
    DAT_003f8d78 = DAT_003fcff2;
    iVar1 = DAT_003fd3f0 / 0xa00 + (DAT_003fd3f0 >> 0x1f);
    if ((int)(short)sensor_adc_post_o2 < iVar1 - (iVar1 >> 0x1f)) {
      DAT_003fd3ea = DAT_003fd3ea & 0xffdf | 0x10;
    }
  }
  else if ((DAT_003f8d78 == 0) || (DAT_003f8d76 != '\0')) {
    if (DAT_003f8d76 != '\0') {
      DAT_003f8d76 = DAT_003f8d76 + -1;
    }
  }
  else {
    DAT_003f8d78 = DAT_003f8d78 + -1;
    DAT_003f8d76 = DAT_003fbf5b;
  }
  if (((short)(ushort)DAT_003f93fe < dt_tps_target_2) ||
     ((int)dt_tps_target_2 < -(int)(short)(ushort)DAT_003f93fe)) {
    DAT_003f8d7a = DAT_003f9400;
  }
  else if ((DAT_003f8d7a != 0) && (DAT_003f8d7a = DAT_003f8d7a + -1, DAT_003f8d7a == 0)) {
    DAT_003fd3f0 = (uint)sensor_adc_post_o2 * 0xa00;
  }
  return;
}



// Initializes catalyst monitor state

void obd_init_catalyst(void)

{
  obd_P0420_debounce_count = CAL_obd_P0420_debounce_threshold;
  obd_init_dtc(&CAL_obd_P0420,&LEA_obd_P0420_flags,0x1a4);
  return;
}



// Catalyst monitor cycle counter

void obd_cyc_catalyst(void)

{
  obd_cyc_dtc(&CAL_obd_P0420,&LEA_obd_P0420_flags,&LEA_obd_P0420_engine_start_count,
              &LEA_obd_P0420_warm_up_cycle_count,0x1a4);
  return;
}



// VVT system monitor (P0011/P0012)

void obd_check_vvt(void)

{
  if ((((vvt_runtime_min < engine_runtime) && (DAT_003fe0cc != -0x80)) &&
      (obd_P0116_debounce_count != 0)) &&
     ((obd_P0117_debounce_count != 0 && (obd_P0118_debounce_count != 0)))) {
    if ((((CAL_obd_P0011 & 7) != 0) && (DAT_003fbfa8 < coolant_smooth)) &&
       (DAT_003fbfaa < engine_runtime)) {
      if ((int)vvt_diff < -(int)DAT_003fbf80) {
        if (DAT_003f8d82 < DAT_003fbfa9) {
          DAT_003f8d82 = DAT_003f8d82 + 1;
        }
        else {
          DAT_003f8d82 = 0;
          if (obd_P0011_debounce_count == 0) {
            obd_set_dtc(&CAL_obd_P0011,&LEA_obd_P0011_flags,&LEA_obd_P0011_engine_start_count,
                        &LEA_obd_P0011_warm_up_cycle_count,0xb);
          }
          else {
            obd_P0011_debounce_count = obd_P0011_debounce_count + 255;
          }
        }
      }
      else {
        obd_clr_dtc(&CAL_obd_P0011,&LEA_obd_P0011_flags);
        if (obd_P0011_debounce_count < CAL_obd_P0011_debounce_threshold) {
          obd_P0011_debounce_count = obd_P0011_debounce_count + 1;
        }
        DAT_003f8d82 = 0;
      }
    }
    if ((((CAL_obd_P0012 & 7) != 0) && (DAT_003fbfa8 < coolant_smooth)) &&
       (DAT_003fbfaa < engine_runtime)) {
      if (DAT_003fbf80 < vvt_diff) {
        if (DAT_003f8d83 < DAT_003fbfa9) {
          DAT_003f8d83 = DAT_003f8d83 + 1;
        }
        else {
          DAT_003f8d83 = 0;
          if (obd_P0012_debounce_count == 0) {
            obd_set_dtc(&CAL_obd_P0012,&LEA_obd_P0012_flags,&LEA_obd_P0012_engine_start_count,
                        &LEA_obd_P0012_warm_up_cycle_count,0xc);
          }
          else {
            obd_P0012_debounce_count = obd_P0012_debounce_count + 255;
          }
        }
      }
      else {
        obd_clr_dtc(&CAL_obd_P0012,&LEA_obd_P0012_flags);
        if (obd_P0012_debounce_count < CAL_obd_P0012_debounce_threshold) {
          obd_P0012_debounce_count = obd_P0012_debounce_count + 1;
        }
        DAT_003f8d83 = 0;
      }
    }
    if (((CAL_obd_P0016 & 7) != 0) && (vvt_rest_pos_measured == true)) {
      if (vvt_rest_pos_fault == true) {
        if (obd_P0016_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0016,&LEA_obd_P0016_flags,&LEA_obd_P0016_engine_start_count,
                      &LEA_obd_P0016_warm_up_cycle_count,0x10);
        }
        else {
          obd_P0016_debounce_count = obd_P0016_debounce_count + 255;
        }
      }
      else {
        obd_clr_dtc(&CAL_obd_P0016,&LEA_obd_P0016_flags);
        if (obd_P0016_debounce_count < CAL_obd_P0016_debounce_threshold) {
          obd_P0016_debounce_count = obd_P0016_debounce_count + 1;
        }
      }
    }
  }
  else {
    DAT_003f8d83 = 0;
    DAT_003f8d82 = 0;
  }
  if (((obd_P0011_debounce_count == 0) || (obd_P0012_debounce_count == 0)) ||
     ((obd_P0016_debounce_count == 0 ||
      (((obd_P0076_debounce_count == 0 || (obd_P0077_debounce_count == 0)) ||
       (obd_P0340_debounce_count == 0)))))) {
    sensor_fault_flags = sensor_fault_flags | 0x20;
  }
  else {
    sensor_fault_flags = sensor_fault_flags & 0xffdf;
  }
  return;
}



// VVL system monitor (P0076/P0077)

void obd_check_vvl(void)

{
  if ((((CAL_obd_P2647 & 7) == 0) || (!engine_is_running)) || ((shutdown_flags & 1) == 0)) {
    DAT_003f8d81 = DAT_003fbf3e;
  }
  else if (!vvl_is_high_cam) {
    DAT_003f8d80 = DAT_003fbf3e;
    if (DAT_003f8d81 == '\0') {
      if (sensor_adc_oil_vvtl < 0x201) {
        obd_clr_dtc(&CAL_obd_P2647,&LEA_obd_P2647_flags);
        if (obd_P2647_debounce_count < CAL_obd_P2647_debounce_threshold) {
          obd_P2647_debounce_count = obd_P2647_debounce_count + 1;
        }
      }
      else if (obd_P2647_debounce_count == 0) {
        obd_set_dtc(&CAL_obd_P2647,&LEA_obd_P2647_flags,&LEA_obd_P2647_engine_start_count,
                    &LEA_obd_P2647_warm_up_cycle_count,0xa57);
      }
      else {
        obd_P2647_debounce_count = obd_P2647_debounce_count + 255;
      }
    }
    else {
      DAT_003f8d81 = DAT_003f8d81 + -1;
    }
  }
  if ((((CAL_obd_P2646 & 7) == 0) || (engine_is_running == false)) || ((shutdown_flags & 1) == 0)) {
    DAT_003f8d80 = DAT_003fbf3e;
  }
  else if (vvl_is_high_cam == true) {
    DAT_003f8d81 = DAT_003fbf3e;
    if (DAT_003f8d80 == '\0') {
      if (sensor_adc_oil_vvtl < 0x200) {
        if (obd_P2646_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P2646,&LEA_obd_P2646_flags,&LEA_obd_P2646_engine_start_count,
                      &LEA_obd_P2646_warm_up_cycle_count,0xa56);
        }
        else {
          obd_P2646_debounce_count = obd_P2646_debounce_count + 255;
        }
      }
      else {
        obd_clr_dtc(&CAL_obd_P2646,&LEA_obd_P2646_flags);
        if (obd_P2646_debounce_count < CAL_obd_P2646_debounce_threshold) {
          obd_P2646_debounce_count = obd_P2646_debounce_count + 1;
        }
      }
    }
    else {
      DAT_003f8d80 = DAT_003f8d80 + -1;
    }
  }
  return;
}



// Initializes VVT/VVL monitor state

void obd_init_vvt_vvl(void)

{
  obd_P0011_debounce_count = CAL_obd_P0011_debounce_threshold;
  obd_P0012_debounce_count = CAL_obd_P0012_debounce_threshold;
  obd_P0016_debounce_count = CAL_obd_P0016_debounce_threshold;
  obd_P2646_debounce_count = CAL_obd_P2646_debounce_threshold;
  obd_P2647_debounce_count = CAL_obd_P2647_debounce_threshold;
  obd_init_dtc(&CAL_obd_P0011,&LEA_obd_P0011_flags,0xb);
  obd_init_dtc(&CAL_obd_P0012,&LEA_obd_P0012_flags,0xc);
  obd_init_dtc(&CAL_obd_P0016,&LEA_obd_P0016_flags,0x10);
  obd_init_dtc(&CAL_obd_P2646,&LEA_obd_P2646_flags,0xa56);
  obd_init_dtc(&CAL_obd_P2647,&LEA_obd_P2647_flags,0xa57);
  return;
}



// VVT/VVL monitor cycle counter

void obd_cyc_vvt_vvl(void)

{
  obd_cyc_dtc(&CAL_obd_P0011,&LEA_obd_P0011_flags,&LEA_obd_P0011_engine_start_count,
              &LEA_obd_P0011_warm_up_cycle_count,0xb);
  obd_cyc_dtc(&CAL_obd_P0012,&LEA_obd_P0012_flags,&LEA_obd_P0012_engine_start_count,
              &LEA_obd_P0012_warm_up_cycle_count,0xc);
  obd_cyc_dtc(&CAL_obd_P0016,&LEA_obd_P0016_flags,&LEA_obd_P0016_engine_start_count,
              &LEA_obd_P0016_warm_up_cycle_count,0x10);
  obd_cyc_dtc(&CAL_obd_P2646,&LEA_obd_P2646_flags,&LEA_obd_P2646_engine_start_count,
              &LEA_obd_P2646_warm_up_cycle_count,0xa56);
  obd_cyc_dtc(&CAL_obd_P2647,&LEA_obd_P2647_flags,&LEA_obd_P2647_engine_start_count,
              &LEA_obd_P2647_warm_up_cycle_count,0xa57);
  return;
}



// Output circuit monitors (injectors, coils, solenoids)

void obd_check_outputs(void)

{
  if ((((CAL_obd_P0076 & 7) != 0) && (engine_is_running)) && ((shutdown_flags & 1) != 0)) {
    if ((DAT_003fd530 & 0x20) == 0) {
      obd_P0076_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0076,&LEA_obd_P0076_flags);
      if (obd_P0076_debounce_count < CAL_obd_P0076_debounce_threshold) {
        obd_P0076_debounce_count = obd_P0076_debounce_count + 1;
      }
    }
    else {
      DAT_003fd530 = DAT_003fd530 & 0xffdf;
      obd_P0076_fault_sample_count = obd_P0076_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0076_fault_sample_count) {
        obd_P0076_fault_sample_count = 0;
        if (obd_P0076_debounce_count != 0) {
          obd_P0076_debounce_count = obd_P0076_debounce_count + 255;
        }
        if (obd_P0076_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0076,&LEA_obd_P0076_flags,&LEA_obd_P0076_engine_start_count,
                      &LEA_obd_P0076_warm_up_cycle_count,0x4c);
        }
      }
    }
  }
  if ((((CAL_obd_P0077 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if ((DAT_003fd530 & 0x10) == 0) {
      obd_P0077_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0077,&LEA_obd_P0077_flags);
      if (obd_P0077_debounce_count < CAL_obd_P0077_debounce_threshold) {
        obd_P0077_debounce_count = obd_P0077_debounce_count + 1;
      }
    }
    else {
      DAT_003fd530 = DAT_003fd530 & 0xffef;
      obd_P0077_fault_sample_count = obd_P0077_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0077_fault_sample_count) {
        obd_P0077_fault_sample_count = 0;
        if (obd_P0077_debounce_count != 0) {
          obd_P0077_debounce_count = obd_P0077_debounce_count + 255;
        }
        if (obd_P0077_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0077,&LEA_obd_P0077_flags,&LEA_obd_P0077_engine_start_count,
                      &LEA_obd_P0077_warm_up_cycle_count,0x4d);
        }
      }
    }
  }
  if ((((CAL_obd_P0646 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if ((DAT_003fd520 & 0x200) == 0) {
      obd_P0646_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0646,&LEA_obd_P0646_flags);
      if (obd_P0646_debounce_count < CAL_obd_P0646_debounce_threshold) {
        obd_P0646_debounce_count = obd_P0646_debounce_count + 1;
      }
    }
    else {
      obd_P0646_fault_sample_count = obd_P0646_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0646_fault_sample_count) {
        obd_P0646_fault_sample_count = 0;
        if (obd_P0646_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0646,&LEA_obd_P0646_flags,&LEA_obd_P0646_engine_start_count,
                      &LEA_obd_P0646_warm_up_cycle_count,0x286);
        }
        else {
          obd_P0646_debounce_count = obd_P0646_debounce_count + 255;
        }
      }
    }
  }
  if ((((CAL_obd_P0647 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if ((DAT_003fd520 & 0x100) == 0) {
      obd_P0647_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0647,&LEA_obd_P0647_flags);
      if (obd_P0647_debounce_count < CAL_obd_P0647_debounce_threshold) {
        obd_P0647_debounce_count = obd_P0647_debounce_count + 1;
      }
    }
    else {
      obd_P0647_fault_sample_count = obd_P0647_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0647_fault_sample_count) {
        obd_P0647_fault_sample_count = 0;
        if (obd_P0647_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0647,&LEA_obd_P0647_flags,&LEA_obd_P0647_engine_start_count,
                      &LEA_obd_P0647_warm_up_cycle_count,0x287);
        }
        else {
          obd_P0647_debounce_count = obd_P0647_debounce_count + 255;
        }
      }
    }
  }
  if ((((CAL_obd_P0444 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if ((DAT_003fd532 & 0x80) == 0) {
      obd_P0444_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0444,&LEA_obd_P0444_flags);
      if (obd_P0444_debounce_count < CAL_obd_P0444_debounce_threshold) {
        obd_P0444_debounce_count = obd_P0444_debounce_count + 1;
      }
    }
    else {
      DAT_003fd532 = DAT_003fd532 & 0xff7f;
      obd_P0444_fault_sample_count = obd_P0444_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0444_fault_sample_count) {
        obd_P0444_fault_sample_count = 0;
        if (obd_P0444_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0444,&LEA_obd_P0444_flags,&LEA_obd_P0444_engine_start_count,
                      &LEA_obd_P0444_warm_up_cycle_count,0x1bc);
        }
        else {
          obd_P0444_debounce_count = obd_P0444_debounce_count + 255;
        }
      }
    }
  }
  if ((((CAL_obd_P0445 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if ((DAT_003fd532 & 0x40) == 0) {
      obd_P0445_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0445,&LEA_obd_P0445_flags);
      if (obd_P0445_debounce_count < CAL_obd_P0445_debounce_threshold) {
        obd_P0445_debounce_count = obd_P0445_debounce_count + 1;
      }
    }
    else {
      DAT_003fd532 = DAT_003fd532 & 0xffbf;
      obd_P0445_fault_sample_count = obd_P0445_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0445_fault_sample_count) {
        obd_P0445_fault_sample_count = 0;
        if (obd_P0445_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0445,&LEA_obd_P0445_flags,&LEA_obd_P0445_engine_start_count,
                      &LEA_obd_P0445_warm_up_cycle_count,0x1bd);
        }
        else {
          obd_P0445_debounce_count = obd_P0445_debounce_count + 255;
        }
      }
    }
  }
  if ((((CAL_obd_P0447 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if ((DAT_003fd532 & 0x20) == 0) {
      obd_P0447_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0447,&LEA_obd_P0447_flags);
      if (obd_P0447_debounce_count < CAL_obd_P0447_debounce_threshold) {
        obd_P0447_debounce_count = obd_P0447_debounce_count + 1;
      }
    }
    else {
      obd_P0447_fault_sample_count = obd_P0447_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0447_fault_sample_count) {
        obd_P0447_fault_sample_count = 0;
        if (obd_P0447_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0447,&LEA_obd_P0447_flags,&LEA_obd_P0447_engine_start_count,
                      &LEA_obd_P0447_warm_up_cycle_count,0x1bf);
        }
        else {
          obd_P0447_debounce_count = obd_P0447_debounce_count + 255;
        }
      }
    }
  }
  if ((((CAL_obd_P0448 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if ((DAT_003fd532 & 0x10) == 0) {
      obd_P0448_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0448,&LEA_obd_P0448_flags);
      if (obd_P0448_debounce_count < CAL_obd_P0448_debounce_threshold) {
        obd_P0448_debounce_count = obd_P0448_debounce_count + 1;
      }
    }
    else {
      obd_P0448_fault_sample_count = obd_P0448_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0448_fault_sample_count) {
        obd_P0448_fault_sample_count = 0;
        if (obd_P0448_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0448,&LEA_obd_P0448_flags,&LEA_obd_P0448_engine_start_count,
                      &LEA_obd_P0448_warm_up_cycle_count,0x1c0);
        }
        else {
          obd_P0448_debounce_count = obd_P0448_debounce_count + 255;
        }
      }
    }
  }
  if ((((CAL_obd_P0201 & 7) != 0) && (engine_is_running != false)) &&
     (((shutdown_flags & 1) != 0 && ((hc08_obd_flags & 0x20) == 0)))) {
    if ((DAT_003fd52c & 3) == 0) {
      obd_clr_dtc(&CAL_obd_P0201,&LEA_obd_P0201_flags);
      if (obd_P0201_debounce_count < CAL_obd_P0201_debounce_threshold) {
        obd_P0201_debounce_count = obd_P0201_debounce_count + 1;
      }
    }
    else if (((DAT_003fd52c & 2) == 0) && (((DAT_003fd52c & 2) == 0 || ((DAT_003fd52c & 1) == 0))))
    {
      if (((DAT_003fd52c & 2) == 0) && ((DAT_003fd52c & 1) != 0)) {
        DAT_003fd52c = DAT_003fd52c & 0xfffe;
        if (obd_P0201_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0201,&LEA_obd_P0201_flags,&LEA_obd_P0201_engine_start_count,
                      &LEA_obd_P0201_warm_up_cycle_count,0xc9);
        }
        else {
          obd_P0201_debounce_count = obd_P0201_debounce_count + 255;
        }
      }
    }
    else {
      DAT_003fd52c = DAT_003fd52c & 0xfffc;
      obd_P0201_fault_sample_count = obd_P0201_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0201_fault_sample_count) {
        obd_P0201_fault_sample_count = 0;
        if (obd_P0201_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0201,&LEA_obd_P0201_flags,&LEA_obd_P0201_engine_start_count,
                      &LEA_obd_P0201_warm_up_cycle_count,0xc9);
        }
        else {
          obd_P0201_debounce_count = obd_P0201_debounce_count + 255;
        }
      }
    }
  }
  if (((((CAL_obd_P0202 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0))
     && ((hc08_obd_flags & 0x20) == 0)) {
    if ((DAT_003fd52c & 0x30) == 0) {
      obd_P0202_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0202,&LEA_obd_P0202_flags);
      if (obd_P0202_debounce_count < CAL_obd_P0202_debounce_threshold) {
        obd_P0202_debounce_count = obd_P0202_debounce_count + 1;
      }
    }
    else if (((DAT_003fd52c & 0x20) == 0) &&
            (((DAT_003fd52c & 0x20) == 0 || ((DAT_003fd52c & 0x10) == 0)))) {
      if (((DAT_003fd52c & 0x20) == 0) && ((DAT_003fd52c & 0x10) != 0)) {
        DAT_003fd52c = DAT_003fd52c & 0xffef;
        if (obd_P0202_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0202,&LEA_obd_P0202_flags,&LEA_obd_P0202_engine_start_count,
                      &LEA_obd_P0202_warm_up_cycle_count,0xca);
        }
        else {
          obd_P0202_debounce_count = obd_P0202_debounce_count + 255;
        }
      }
    }
    else {
      DAT_003fd52c = DAT_003fd52c & 0xffcf;
      obd_P0202_fault_sample_count = obd_P0202_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0202_fault_sample_count) {
        obd_P0202_fault_sample_count = 0;
        if (obd_P0202_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0202,&LEA_obd_P0202_flags,&LEA_obd_P0202_engine_start_count,
                      &LEA_obd_P0202_warm_up_cycle_count,0xca);
        }
        else {
          obd_P0202_debounce_count = obd_P0202_debounce_count + 255;
        }
      }
    }
  }
  if ((((CAL_obd_P0203 & 7) != 0) && (engine_is_running != false)) &&
     (((shutdown_flags & 1) != 0 && ((hc08_obd_flags & 0x20) == 0)))) {
    if ((DAT_003fd52c & 0xc0) == 0) {
      obd_P0203_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0203,&LEA_obd_P0203_flags);
      if (obd_P0203_debounce_count < CAL_obd_P0203_debounce_threshold) {
        obd_P0203_debounce_count = obd_P0203_debounce_count + 1;
      }
    }
    else if (((DAT_003fd52c & 0x80) == 0) &&
            (((DAT_003fd52c & 0x80) == 0 || ((DAT_003fd52c & 0x40) == 0)))) {
      if (((DAT_003fd52c & 0x80) == 0) && ((DAT_003fd52c & 0x40) != 0)) {
        DAT_003fd52c = DAT_003fd52c & 0xffbf;
        if (obd_P0203_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0203,&LEA_obd_P0203_flags,&LEA_obd_P0203_engine_start_count,
                      &LEA_obd_P0203_warm_up_cycle_count,0xcb);
        }
        else {
          obd_P0203_debounce_count = obd_P0203_debounce_count + 255;
        }
      }
    }
    else {
      DAT_003fd52c = DAT_003fd52c & 0xff3f;
      obd_P0203_fault_sample_count = obd_P0203_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0203_fault_sample_count) {
        obd_P0203_fault_sample_count = 0;
        if (obd_P0203_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0203,&LEA_obd_P0203_flags,&LEA_obd_P0203_engine_start_count,
                      &LEA_obd_P0203_warm_up_cycle_count,0xcb);
        }
        else {
          obd_P0203_debounce_count = obd_P0203_debounce_count + 255;
        }
      }
    }
  }
  if (((((CAL_obd_P0204 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0))
     && ((hc08_obd_flags & 0x20) == 0)) {
    if ((DAT_003fd52c & 0xc) == 0) {
      obd_P0204_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0204,&LEA_obd_P0204_flags);
      if (obd_P0204_debounce_count < CAL_obd_P0204_debounce_threshold) {
        obd_P0204_debounce_count = obd_P0204_debounce_count + 1;
      }
    }
    else if (((DAT_003fd52c & 8) == 0) && (((DAT_003fd52c & 8) == 0 || ((DAT_003fd52c & 4) == 0))))
    {
      if (((DAT_003fd52c & 8) == 0) && ((DAT_003fd52c & 4) != 0)) {
        DAT_003fd52c = DAT_003fd52c & 0xfffb;
        if (obd_P0204_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0204,&LEA_obd_P0204_flags,&LEA_obd_P0204_engine_start_count,
                      &LEA_obd_P0204_warm_up_cycle_count,0xcc);
        }
        else {
          obd_P0204_debounce_count = obd_P0204_debounce_count + 255;
        }
      }
    }
    else {
      DAT_003fd52c = DAT_003fd52c & 0xfff3;
      obd_P0204_fault_sample_count = obd_P0204_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0204_fault_sample_count) {
        obd_P0204_fault_sample_count = 0;
        if (obd_P0204_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0204,&LEA_obd_P0204_flags,&LEA_obd_P0204_engine_start_count,
                      &LEA_obd_P0204_warm_up_cycle_count,0xcc);
        }
        else {
          obd_P0204_debounce_count = obd_P0204_debounce_count + 255;
        }
      }
    }
  }
  if ((((CAL_obd_P0205 & 7) != 0) && (engine_is_running != false)) &&
     (((shutdown_flags & 1) != 0 && ((hc08_obd_flags & 0x20) == 0)))) {
    if ((DAT_003fd52c & 3) == 0) {
      obd_P0205_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0205,&LEA_obd_P0205_flags);
      if (obd_P0205_debounce_count < CAL_obd_P0205_debounce_threshold) {
        obd_P0205_debounce_count = obd_P0205_debounce_count + 1;
      }
    }
    else if (((DAT_003fd52c & 2) == 0) && (((DAT_003fd52c & 2) == 0 || ((DAT_003fd52c & 1) == 0))))
    {
      if (((DAT_003fd52c & 2) == 0) && ((DAT_003fd52c & 1) != 0)) {
        DAT_003fd52c = DAT_003fd52c & 0xfffe;
        if (obd_P0205_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0205,&LEA_obd_P0205_flags,&LEA_obd_P0205_engine_start_count,
                      &LEA_obd_P0205_warm_up_cycle_count,0xcd);
        }
        else {
          obd_P0205_debounce_count = obd_P0205_debounce_count + 255;
        }
      }
    }
    else {
      DAT_003fd52c = DAT_003fd52c & 0xfffc;
      obd_P0205_fault_sample_count = obd_P0205_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0205_fault_sample_count) {
        obd_P0205_fault_sample_count = 0;
        if (obd_P0205_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0205,&LEA_obd_P0205_flags,&LEA_obd_P0205_engine_start_count,
                      &LEA_obd_P0205_warm_up_cycle_count,0xcd);
        }
        else {
          obd_P0205_debounce_count = obd_P0205_debounce_count + 255;
        }
      }
    }
  }
  if ((((CAL_obd_P0351 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if (diag_channel[0x1b].state < 2) {
      obd_P0351_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0351,&LEA_obd_P0351_flags);
      if (obd_P0351_debounce_count < CAL_obd_P0351_debounce_threshold) {
        obd_P0351_debounce_count = obd_P0351_debounce_count + 1;
      }
    }
    else {
      obd_P0351_fault_sample_count = obd_P0351_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0351_fault_sample_count) {
        obd_P0351_fault_sample_count = 0;
        if (obd_P0351_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0351,&LEA_obd_P0351_flags,&LEA_obd_P0351_engine_start_count,
                      &LEA_obd_P0351_warm_up_cycle_count,0x15f);
        }
        else {
          obd_P0351_debounce_count = obd_P0351_debounce_count + 255;
        }
      }
    }
  }
  if ((((CAL_obd_P0352 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if (diag_channel[0x1c].state < 2) {
      obd_P0352_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0352,&LEA_obd_P0352_flags);
      if (obd_P0352_debounce_count < CAL_obd_P0352_debounce_threshold) {
        obd_P0352_debounce_count = obd_P0352_debounce_count + 1;
      }
    }
    else {
      obd_P0352_fault_sample_count = obd_P0352_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0352_fault_sample_count) {
        obd_P0352_fault_sample_count = 0;
        if (obd_P0352_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0352,&LEA_obd_P0352_flags,&LEA_obd_P0352_engine_start_count,
                      &LEA_obd_P0352_warm_up_cycle_count,0x160);
        }
        else {
          obd_P0352_debounce_count = obd_P0352_debounce_count + 255;
        }
      }
    }
  }
  if ((((CAL_obd_P0353 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if (diag_channel[0x1d].state < 2) {
      obd_P0353_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0353,&LEA_obd_P0353_flags);
      if (obd_P0353_debounce_count < CAL_obd_P0353_debounce_threshold) {
        obd_P0353_debounce_count = obd_P0353_debounce_count + 1;
      }
    }
    else {
      obd_P0353_fault_sample_count = obd_P0353_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0353_fault_sample_count) {
        obd_P0353_fault_sample_count = 0;
        if (obd_P0353_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0353,&LEA_obd_P0353_flags,&LEA_obd_P0353_engine_start_count,
                      &LEA_obd_P0353_warm_up_cycle_count,0x161);
        }
        else {
          obd_P0353_debounce_count = obd_P0353_debounce_count + 255;
        }
      }
    }
  }
  if ((((CAL_obd_P0354 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if (diag_channel[0x1e].state < 2) {
      obd_P0354_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0354,&LEA_obd_P0354_flags);
      if (obd_P0354_debounce_count < CAL_obd_P0354_debounce_threshold) {
        obd_P0354_debounce_count = obd_P0354_debounce_count + 1;
      }
    }
    else {
      obd_P0354_fault_sample_count = obd_P0354_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0354_fault_sample_count) {
        obd_P0354_fault_sample_count = 0;
        if (obd_P0354_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0354,&LEA_obd_P0354_flags,&LEA_obd_P0354_engine_start_count,
                      &LEA_obd_P0354_warm_up_cycle_count,0x162);
        }
        else {
          obd_P0354_debounce_count = obd_P0354_debounce_count + 255;
        }
      }
    }
  }
  if (((CAL_obd_P0627 & 7) != 0) && ((shutdown_flags & 1) != 0)) {
    if ((DAT_003fd520 & 0x3000) == 0) {
      obd_P0627_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0627,&LEA_obd_P0627_flags);
      if (obd_P0627_debounce_count < CAL_obd_P0627_debounce_threshold) {
        obd_P0627_debounce_count = obd_P0627_debounce_count + 1;
      }
    }
    else {
      obd_P0627_fault_sample_count = obd_P0627_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0627_fault_sample_count) {
        obd_P0627_fault_sample_count = 0;
        if (obd_P0627_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0627,&LEA_obd_P0627_flags,&LEA_obd_P0627_engine_start_count,
                      &LEA_obd_P0627_warm_up_cycle_count,0x273);
        }
        else {
          obd_P0627_debounce_count = obd_P0627_debounce_count + 255;
        }
      }
    }
  }
  if ((((CAL_obd_P0480 & 7) != 0) && (engine_is_running != false)) &&
     (((shutdown_flags & 1) != 0 && (car_speed_smooth < CAL_fan_car_speed_disable)))) {
    if ((DAT_003fd520 & 0xc) == 0) {
      obd_P0480_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0480,&LEA_obd_P0480_flags);
      if (obd_P0480_debounce_count < CAL_obd_P0480_debounce_threshold) {
        obd_P0480_debounce_count = obd_P0480_debounce_count + 1;
      }
    }
    else {
      obd_P0480_fault_sample_count = obd_P0480_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0480_fault_sample_count) {
        obd_P0480_fault_sample_count = 0;
        if (obd_P0480_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0480,&LEA_obd_P0480_flags,&LEA_obd_P0480_engine_start_count,
                      &LEA_obd_P0480_warm_up_cycle_count,0x1e0);
        }
        else {
          obd_P0480_debounce_count = obd_P0480_debounce_count + 255;
        }
      }
    }
  }
  if ((((CAL_obd_P0481 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if ((DAT_003fd520 & 0xc00) == 0) {
      obd_P0481_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0481,&LEA_obd_P0481_flags);
      if (obd_P0481_debounce_count < CAL_obd_P0481_debounce_threshold) {
        obd_P0481_debounce_count = obd_P0481_debounce_count + 1;
      }
    }
    else {
      obd_P0481_fault_sample_count = obd_P0481_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0481_fault_sample_count) {
        obd_P0481_fault_sample_count = 0;
        if (obd_P0481_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0481,&LEA_obd_P0481_flags,&LEA_obd_P0481_engine_start_count,
                      &LEA_obd_P0481_warm_up_cycle_count,0x1e1);
        }
        else {
          obd_P0481_debounce_count = obd_P0481_debounce_count + 255;
        }
      }
    }
  }
  if ((((CAL_obd_P0135 & 7) != 0) && (&UNK_00002ee0 < engine_runtime)) &&
     ((shutdown_flags & 1) != 0)) {
    if (diag_channel[0x19].state < 2) {
      if (pre_o2_heater_current < CAL_obd_P0135_P0141_threshold) {
        obd_P0135_fault_sample_count = obd_P0135_fault_sample_count + 1;
        if ((short)obd_fault_sample_threshold <= (short)obd_P0135_fault_sample_count) {
          DAT_003fd534 = DAT_003fd534 & 0xffcf;
          obd_P0135_fault_sample_count = 0;
          if (obd_P0135_debounce_count == 0) {
            obd_set_dtc(&CAL_obd_P0135,&LEA_obd_P0135_flags,&LEA_obd_P0135_engine_start_count,
                        &LEA_obd_P0135_warm_up_cycle_count,0x87);
          }
          else {
            obd_P0135_debounce_count = obd_P0135_debounce_count + 255;
          }
        }
      }
      else {
        obd_P0135_fault_sample_count = 0;
        obd_clr_dtc(&CAL_obd_P0135,&LEA_obd_P0135_flags);
        if (obd_P0135_debounce_count < CAL_obd_P0135_debounce_threshold) {
          obd_P0135_debounce_count = obd_P0135_debounce_count + 1;
        }
      }
    }
    else {
      obd_set_dtc(&CAL_obd_P0135,&LEA_obd_P0135_flags,&LEA_obd_P0135_engine_start_count,
                  &LEA_obd_P0135_warm_up_cycle_count,0x87);
    }
  }
  if ((((CAL_obd_P0141 & 7) != 0) && (&UNK_00002ee0 < engine_runtime)) &&
     ((shutdown_flags & 1) != 0)) {
    if (diag_channel[0x1a].state < 2) {
      if (post_o2_heater_current < CAL_obd_P0135_P0141_threshold) {
        DAT_003fd534 = DAT_003fd534 & 0xfffc;
        obd_P0141_fault_sample_count = obd_P0141_fault_sample_count + 1;
        if ((short)obd_fault_sample_threshold <= (short)obd_P0141_fault_sample_count) {
          obd_P0141_fault_sample_count = 0;
          if (obd_P0141_debounce_count == 0) {
            obd_set_dtc(&CAL_obd_P0141,&LEA_obd_P0141_flags,&LEA_obd_P0141_engine_start_count,
                        &LEA_obd_P0141_warm_up_cycle_count,0x8d);
          }
          else {
            obd_P0141_debounce_count = obd_P0141_debounce_count + 255;
          }
        }
      }
      else {
        obd_P0141_fault_sample_count = 0;
        obd_clr_dtc(&CAL_obd_P0141,&LEA_obd_P0141_flags);
        if (obd_P0141_debounce_count < CAL_obd_P0141_debounce_threshold) {
          obd_P0141_debounce_count = obd_P0141_debounce_count + 1;
        }
      }
    }
    else {
      obd_set_dtc(&CAL_obd_P0141,&LEA_obd_P0141_flags,&LEA_obd_P0141_engine_start_count,
                  &LEA_obd_P0141_warm_up_cycle_count,0x8d);
    }
  }
  if ((((((LEA_obd_P0135_flags & 8) != 0) && ((LEA_obd_P0141_flags & 8) != 0)) &&
       ((LEA_obd_P0135_flags & 4) == 0)) && ((LEA_obd_P0141_flags & 4) == 0)) ||
     ((((LEA_obd_P0135_flags & 4) != 0 && ((LEA_obd_P0135_flags & 0x10) != 0)) &&
      (((LEA_obd_P0141_flags & 4) != 0 && ((LEA_obd_P0141_flags & 0x10) != 0)))))) {
    LEA_obd_monitors_completeness = LEA_obd_monitors_completeness & 0xbf;
  }
  if ((CAL_obd_P2602 & 7) != 0) {
    if ((DAT_003fd534 & 0x4000) == 0) {
      obd_P2602_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P2602,&LEA_obd_P2602_flags);
      if (obd_P2602_debounce_count < CAL_obd_P2602_debounce_threshold) {
        obd_P2602_debounce_count = obd_P2602_debounce_count + 1;
      }
    }
    else {
      DAT_003fd534 = DAT_003fd534 & 0xbfff;
      obd_P2602_fault_sample_count = obd_P2602_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P2602_fault_sample_count) {
        obd_P2602_fault_sample_count = 0;
        if (obd_P2602_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P2602,&LEA_obd_P2602_flags,&LEA_obd_P2602_engine_start_count,
                      &LEA_obd_P2602_warm_up_cycle_count,0xa2a);
        }
        else {
          obd_P2602_debounce_count = obd_P2602_debounce_count + 255;
        }
      }
    }
  }
  if ((((CAL_obd_P2603 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if ((DAT_003fd534 & 0x8000) == 0) {
      obd_P2603_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P2603,&LEA_obd_P2603_flags);
      if (obd_P2603_debounce_count < CAL_obd_P2603_debounce_threshold) {
        obd_P2603_debounce_count = obd_P2603_debounce_count + 1;
      }
    }
    else {
      DAT_003fd534 = DAT_003fd534 & 0x7fff;
      obd_P2603_fault_sample_count = obd_P2603_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P2603_fault_sample_count) {
        obd_P2603_fault_sample_count = 0;
        if (obd_P2603_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P2603,&LEA_obd_P2603_flags,&LEA_obd_P2603_engine_start_count,
                      &LEA_obd_P2603_warm_up_cycle_count,0xa2b);
        }
        else {
          obd_P2603_debounce_count = obd_P2603_debounce_count + 255;
        }
      }
    }
  }
  if ((((CAL_obd_P2648 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if ((DAT_003fd532 & 2) == 0) {
      obd_P2648_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P2648,&LEA_obd_P2648_flags);
      if (obd_P2648_debounce_count < CAL_obd_P2648_debounce_threshold) {
        obd_P2648_debounce_count = obd_P2648_debounce_count + 1;
      }
    }
    else {
      DAT_003fd532 = DAT_003fd532 & 0xfffd;
      obd_P2648_fault_sample_count = obd_P2648_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P2648_fault_sample_count) {
        obd_P2648_fault_sample_count = 0;
        if (obd_P2648_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P2648,&LEA_obd_P2648_flags,&LEA_obd_P2648_engine_start_count,
                      &LEA_obd_P2648_warm_up_cycle_count,0xa58);
        }
        else {
          obd_P2648_debounce_count = obd_P2648_debounce_count + 255;
        }
      }
    }
  }
  if ((((CAL_obd_P2649 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if ((DAT_003fd532 & 1) == 0) {
      obd_P2649_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P2649,&LEA_obd_P2649_flags);
      if (obd_P2649_debounce_count < CAL_obd_P2649_debounce_threshold) {
        obd_P2649_debounce_count = obd_P2649_debounce_count + 1;
      }
    }
    else {
      DAT_003fd532 = DAT_003fd532 & 0xfffe;
      obd_P2649_fault_sample_count = obd_P2649_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P2649_fault_sample_count) {
        obd_P2649_fault_sample_count = 0;
        if (obd_P2649_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P2649,&LEA_obd_P2649_flags,&LEA_obd_P2649_engine_start_count,
                      &LEA_obd_P2649_warm_up_cycle_count,0xa59);
        }
        else {
          obd_P2649_debounce_count = obd_P2649_debounce_count + 255;
        }
      }
    }
  }
  if (((obd_P0201_debounce_count == 0) || (obd_P0202_debounce_count == 0)) ||
     ((obd_P0203_debounce_count == 0 || (obd_P0204_debounce_count == 0)))) {
    sensor_fault_flags = sensor_fault_flags | 0x1000;
  }
  else {
    sensor_fault_flags = sensor_fault_flags & 0xefff;
  }
  if ((((obd_P0351_debounce_count == 0) || (obd_P0352_debounce_count == 0)) ||
      (obd_P0353_debounce_count == 0)) || (obd_P0354_debounce_count == 0)) {
    sensor_fault_flags = sensor_fault_flags | 0x2000;
  }
  else {
    sensor_fault_flags = sensor_fault_flags & 0xdfff;
  }
  if (((obd_P0076_debounce_count == 0) || (obd_P0077_debounce_count == 0)) ||
     ((obd_P0011_debounce_count == 0 || (obd_P0012_debounce_count == 0)))) {
    sensor_fault_flags = sensor_fault_flags | 0x40;
  }
  else {
    sensor_fault_flags = sensor_fault_flags & 0xffbf;
  }
  if (((obd_P2648_debounce_count == 0) || (obd_P2649_debounce_count == 0)) ||
     ((obd_P2647_debounce_count == 0 || (obd_P2646_debounce_count == 0)))) {
    sensor_fault_flags = sensor_fault_flags | 0x80;
  }
  else {
    sensor_fault_flags = sensor_fault_flags & 0xff7f;
  }
  return;
}



// Initializes output monitor state

void obd_init_outputs(void)

{
  obd_P0076_debounce_count = CAL_obd_P0076_debounce_threshold;
  obd_P0077_debounce_count = CAL_obd_P0077_debounce_threshold;
  obd_P0647_debounce_count = CAL_obd_P0647_debounce_threshold;
  obd_P0646_debounce_count = CAL_obd_P0646_debounce_threshold;
  obd_P0444_debounce_count = CAL_obd_P0444_debounce_threshold;
  obd_P0445_debounce_count = CAL_obd_P0445_debounce_threshold;
  obd_P0447_debounce_count = CAL_obd_P0447_debounce_threshold;
  obd_P0448_debounce_count = CAL_obd_P0448_debounce_threshold;
  obd_P0201_debounce_count = CAL_obd_P0201_debounce_threshold;
  obd_P0202_debounce_count = CAL_obd_P0202_debounce_threshold;
  obd_P0203_debounce_count = CAL_obd_P0203_debounce_threshold;
  obd_P0204_debounce_count = CAL_obd_P0204_debounce_threshold;
  obd_P0205_debounce_count = CAL_obd_P0205_debounce_threshold;
  obd_P0135_debounce_count = CAL_obd_P0135_debounce_threshold;
  obd_P0141_debounce_count = CAL_obd_P0141_debounce_threshold;
  obd_P0627_debounce_count = CAL_obd_P0627_debounce_threshold;
  obd_P0480_debounce_count = CAL_obd_P0480_debounce_threshold;
  obd_P0481_debounce_count = CAL_obd_P0481_debounce_threshold;
  obd_P2602_debounce_count = CAL_obd_P2602_debounce_threshold;
  obd_P2603_debounce_count = CAL_obd_P2603_debounce_threshold;
  obd_P2648_debounce_count = CAL_obd_P2648_debounce_threshold;
  obd_P2649_debounce_count = CAL_obd_P2649_debounce_threshold;
  obd_P0351_debounce_count = CAL_obd_P0351_debounce_threshold;
  obd_P0352_debounce_count = CAL_obd_P0352_debounce_threshold;
  obd_P0353_debounce_count = CAL_obd_P0353_debounce_threshold;
  obd_P0354_debounce_count = CAL_obd_P0354_debounce_threshold;
  obd_init_dtc(&CAL_obd_P0076,&LEA_obd_P0076_flags,0x4c);
  obd_init_dtc(&CAL_obd_P0077,&LEA_obd_P0077_flags,0x4d);
  obd_init_dtc(&CAL_obd_P0480,&LEA_obd_P0480_flags,0x1e0);
  obd_init_dtc(&CAL_obd_P0481,&LEA_obd_P0481_flags,0x1e1);
  obd_init_dtc(&CAL_obd_P0627,&LEA_obd_P0627_flags,0x273);
  obd_init_dtc(&CAL_obd_P0205,&LEA_obd_P0205_flags,0xcd);
  obd_init_dtc(&CAL_obd_P0204,&LEA_obd_P0204_flags,0xcc);
  obd_init_dtc(&CAL_obd_P0203,&LEA_obd_P0203_flags,0xcb);
  obd_init_dtc(&CAL_obd_P0202,&LEA_obd_P0202_flags,0xca);
  obd_init_dtc(&CAL_obd_P0135,&LEA_obd_P0135_flags,0x87);
  obd_init_dtc(&CAL_obd_P0141,&LEA_obd_P0141_flags,0x8d);
  obd_init_dtc(&CAL_obd_P0201,&LEA_obd_P0201_flags,0xc9);
  obd_init_dtc(&CAL_obd_P0445,&LEA_obd_P0445_flags,0x1bd);
  obd_init_dtc(&CAL_obd_P0444,&LEA_obd_P0444_flags,0x1bc);
  obd_init_dtc(&CAL_obd_P0447,&LEA_obd_P0447_flags,0x1bf);
  obd_init_dtc(&CAL_obd_P0448,&LEA_obd_P0448_flags,0x1c0);
  obd_init_dtc(&CAL_obd_P0646,&LEA_obd_P0646_flags,0x286);
  obd_init_dtc(&CAL_obd_P0647,&LEA_obd_P0647_flags,0x287);
  obd_init_dtc(&CAL_obd_P2602,&LEA_obd_P2602_flags,0xa2a);
  obd_init_dtc(&CAL_obd_P2603,&LEA_obd_P2603_flags,0xa2b);
  obd_init_dtc(&CAL_obd_P2648,&LEA_obd_P2648_flags,0xa58);
  obd_init_dtc(&CAL_obd_P2649,&LEA_obd_P2649_flags,0xa59);
  obd_init_dtc(&CAL_obd_P0351,&LEA_obd_P0351_flags,0x15f);
  obd_init_dtc(&CAL_obd_P0352,&LEA_obd_P0352_flags,0x160);
  obd_init_dtc(&CAL_obd_P0353,&LEA_obd_P0353_flags,0x161);
  obd_init_dtc(&CAL_obd_P0354,&LEA_obd_P0354_flags,0x162);
  return;
}



// Output monitor cycle counter

void obd_cyc_outputs(void)

{
  obd_cyc_dtc(&CAL_obd_P2602,&LEA_obd_P2602_flags,&LEA_obd_P2602_engine_start_count,
              &LEA_obd_P2602_warm_up_cycle_count,0xa2a);
  obd_cyc_dtc(&CAL_obd_P2603,&LEA_obd_P2603_flags,&LEA_obd_P2603_engine_start_count,
              &LEA_obd_P2603_warm_up_cycle_count,0xa2b);
  obd_cyc_dtc(&CAL_obd_P2648,&LEA_obd_P2648_flags,&LEA_obd_P2648_engine_start_count,
              &LEA_obd_P2648_warm_up_cycle_count,0xa58);
  obd_cyc_dtc(&CAL_obd_P2649,&LEA_obd_P2649_flags,&LEA_obd_P2649_engine_start_count,
              &LEA_obd_P2649_warm_up_cycle_count,0xa59);
  obd_cyc_dtc(&CAL_obd_P0481,&LEA_obd_P0481_flags,&LEA_obd_P0481_engine_start_count,
              &LEA_obd_P0481_warm_up_cycle_count,0x1e1);
  obd_cyc_dtc(&CAL_obd_P0480,&LEA_obd_P0480_flags,&LEA_obd_P0480_engine_start_count,
              &LEA_obd_P0480_warm_up_cycle_count,0x1e0);
  obd_cyc_dtc(&CAL_obd_P0627,&LEA_obd_P0627_flags,&LEA_obd_P0627_engine_start_count,
              &LEA_obd_P0627_warm_up_cycle_count,0x273);
  obd_cyc_dtc(&CAL_obd_P0205,&LEA_obd_P0205_flags,&LEA_obd_P0205_engine_start_count,
              &LEA_obd_P0205_warm_up_cycle_count,0xcd);
  obd_cyc_dtc(&CAL_obd_P0204,&LEA_obd_P0204_flags,&LEA_obd_P0204_engine_start_count,
              &LEA_obd_P0204_warm_up_cycle_count,0xcc);
  obd_cyc_dtc(&CAL_obd_P0203,&LEA_obd_P0203_flags,&LEA_obd_P0203_engine_start_count,
              &LEA_obd_P0203_warm_up_cycle_count,0xcb);
  obd_cyc_dtc(&CAL_obd_P0202,&LEA_obd_P0202_flags,&LEA_obd_P0202_engine_start_count,
              &LEA_obd_P0202_warm_up_cycle_count,0xca);
  obd_cyc_dtc(&CAL_obd_P0201,&LEA_obd_P0201_flags,&LEA_obd_P0201_engine_start_count,
              &LEA_obd_P0201_warm_up_cycle_count,0xc9);
  obd_cyc_dtc(&CAL_obd_P0135,&LEA_obd_P0135_flags,&LEA_obd_P0135_engine_start_count,
              &LEA_obd_P0135_warm_up_cycle_count,0x87);
  obd_cyc_dtc(&CAL_obd_P0141,&LEA_obd_P0141_flags,&LEA_obd_P0141_engine_start_count,
              &LEA_obd_P0141_warm_up_cycle_count,0x8d);
  obd_cyc_dtc(&CAL_obd_P0445,&LEA_obd_P0445_flags,&LEA_obd_P0445_engine_start_count,
              &LEA_obd_P0445_warm_up_cycle_count,0x1bd);
  obd_cyc_dtc(&CAL_obd_P0444,&LEA_obd_P0444_flags,&LEA_obd_P0444_engine_start_count,
              &LEA_obd_P0444_warm_up_cycle_count,0x1bc);
  obd_cyc_dtc(&CAL_obd_P0448,&LEA_obd_P0448_flags,&LEA_obd_P0448_engine_start_count,
              &LEA_obd_P0448_warm_up_cycle_count,0x1c0);
  obd_cyc_dtc(&CAL_obd_P0447,&LEA_obd_P0447_flags,&LEA_obd_P0447_engine_start_count,
              &LEA_obd_P0447_warm_up_cycle_count,0x1bf);
  obd_cyc_dtc(&CAL_obd_P0646,&LEA_obd_P0646_flags,&LEA_obd_P0646_engine_start_count,
              &LEA_obd_P0646_warm_up_cycle_count,0x286);
  obd_cyc_dtc(&CAL_obd_P0647,&LEA_obd_P0647_flags,&LEA_obd_P0647_engine_start_count,
              &LEA_obd_P0647_warm_up_cycle_count,0x287);
  obd_cyc_dtc(&CAL_obd_P0076,&LEA_obd_P0076_flags,&LEA_obd_P0076_engine_start_count,
              &LEA_obd_P0076_warm_up_cycle_count,0x4c);
  obd_cyc_dtc(&CAL_obd_P0077,&LEA_obd_P0077_flags,&LEA_obd_P0077_engine_start_count,
              &LEA_obd_P0076_warm_up_cycle_count,0x4d);
  obd_cyc_dtc(&CAL_obd_P0351,&LEA_obd_P0351_flags,&LEA_obd_P0351_engine_start_count,
              &LEA_obd_P0351_warm_up_cycle_count,0x15f);
  obd_cyc_dtc(&CAL_obd_P0352,&LEA_obd_P0352_flags,&LEA_obd_P0352_engine_start_count,
              &LEA_obd_P0352_warm_up_cycle_count,0x160);
  obd_cyc_dtc(&CAL_obd_P0353,&LEA_obd_P0353_flags,&LEA_obd_P0353_engine_start_count,
              &LEA_obd_P0353_warm_up_cycle_count,0x161);
  obd_cyc_dtc(&CAL_obd_P0354,&LEA_obd_P0354_flags,&LEA_obd_P0354_engine_start_count,
              &LEA_obd_P0354_warm_up_cycle_count,0x162);
  return;
}



// Main K-Line OBD task - processes request header and dispatches by mode

void obd_kline_dispatch(void)

{
  byte bVar1;
  
  obd_mil_dtc_count_update();
  if (obd_req[0] == 9) {
    if (obd_req[6] < 5) {
      if (((obd_resp_len == 0) && (obd_resp_i == 0)) && (obd_req[0xb] == 0)) {
        if (DAT_003fd780 == '\0') {
          if (DAT_003fd884 != '\0') {
            obd_kline_mode_0x09_info(obd_req[0x10]);
            obd_req[0xb] = 9;
          }
        }
        else {
          obd_mode_0x03_trouble_code();
          obd_req[0xb] = 9;
        }
      }
    }
    else if (((obd_req[0xc] == 104) && (obd_req[0xd] == 106)) && (obd_req[0xe] == 241)) {
      if (obd_req[0xf] == 1) {
        if (5 < obd_req[6]) {
          obd_req[8] = 0;
          for (bVar1 = 0; bVar1 < 5; bVar1 = bVar1 + 1) {
            obd_req[8] = obd_req[8] + obd_req[bVar1 + 0xc];
          }
          if (obd_req[8] == obd_req[0x11]) {
            obd_mode_0x01_live_data(obd_req[0x10]);
          }
          obd_req[6] = 0;
          obd_req[7] = 0;
          obd_kline_session_timer = 1000;
        }
      }
      else if (obd_req[0xf] == 2) {
        if (6 < obd_req[6]) {
          obd_req[8] = 0;
          for (bVar1 = 0; bVar1 < 6; bVar1 = bVar1 + 1) {
            obd_req[8] = obd_req[8] + obd_req[bVar1 + 0xc];
          }
          if (obd_req[8] == obd_req[0x12]) {
            obd_mode_0x02_freeze_frame(obd_req[0x10],obd_req[0x11]);
          }
          obd_req[6] = 0;
          obd_req[7] = 0;
          obd_kline_session_timer = 1000;
        }
      }
      else if (obd_req[0xf] == 3) {
        obd_req[8] = 0;
        for (bVar1 = 0; bVar1 < 4; bVar1 = bVar1 + 1) {
          obd_req[8] = obd_req[8] + obd_req[bVar1 + 0xc];
        }
        if (obd_req[8] == obd_req[0x10]) {
          obd_mode_0x03_trouble_code();
          obd_req[0xb] = 9;
        }
        obd_req[6] = 0;
        obd_req[7] = 0;
        obd_kline_session_timer = 1000;
      }
      else if (obd_req[0xf] == 4) {
        obd_req[8] = 0;
        for (bVar1 = 0; bVar1 < 4; bVar1 = bVar1 + 1) {
          obd_req[8] = obd_req[8] + obd_req[bVar1 + 0xc];
        }
        if (obd_req[8] == obd_req[0x10]) {
          obd_mode_0x04_clear();
        }
        obd_req[6] = 0;
        obd_req[7] = 0;
        obd_kline_session_timer = 1000;
      }
      else if (obd_req[0xf] == 5) {
        if (6 < obd_req[6]) {
          obd_req[8] = 0;
          for (bVar1 = 0; bVar1 < 6; bVar1 = bVar1 + 1) {
            obd_req[8] = obd_req[8] + obd_req[bVar1 + 0xc];
          }
          if (obd_req[8] == obd_req[0x12]) {
            obd_kline_mode_0x05_o2_test_results(obd_req[0x10],obd_req[0x11]);
          }
          obd_req[6] = 0;
          obd_req[7] = 0;
          obd_kline_session_timer = 1000;
        }
      }
      else if (obd_req[0xf] == 6) {
        if (5 < obd_req[6]) {
          obd_req[8] = 0;
          for (bVar1 = 0; bVar1 < 5; bVar1 = bVar1 + 1) {
            obd_req[8] = obd_req[8] + obd_req[bVar1 + 0xc];
          }
          if (obd_req[8] == obd_req[0x11]) {
            obd_mode_0x06_test_results(obd_req[0x10]);
          }
          obd_req[6] = 0;
          obd_req[7] = 0;
          obd_kline_session_timer = 1000;
        }
      }
      else if (obd_req[0xf] == 7) {
        obd_req[8] = 0;
        for (bVar1 = 0; bVar1 < 4; bVar1 = bVar1 + 1) {
          obd_req[8] = obd_req[8] + obd_req[bVar1 + 0xc];
        }
        if (obd_req[8] == obd_req[0x10]) {
          obd_mode_0x07_pending_code();
        }
        obd_req[6] = 0;
        obd_req[7] = 0;
        obd_kline_session_timer = 1000;
      }
      else if (obd_req[0xf] == 8) {
        if (10 < obd_req[6]) {
          obd_req[8] = 0;
          for (bVar1 = 0; bVar1 < 10; bVar1 = bVar1 + 1) {
            obd_req[8] = obd_req[8] + obd_req[bVar1 + 0xc];
          }
          if (obd_req[8] == obd_req[0x16]) {
            obd_mode_0x08_evap_control(obd_req[0x10]);
          }
          obd_req[6] = 0;
          obd_req[7] = 0;
          obd_kline_session_timer = 1000;
        }
      }
      else if (obd_req[0xf] == 9) {
        if (5 < obd_req[6]) {
          obd_req[8] = 0;
          for (bVar1 = 0; bVar1 < 5; bVar1 = bVar1 + 1) {
            obd_req[8] = obd_req[8] + obd_req[bVar1 + 0xc];
          }
          if (obd_req[8] == obd_req[0x11]) {
            obd_mode_0x09_informations(obd_req[0x10]);
            obd_req[0xb] = 9;
          }
          obd_req[6] = 0;
          obd_req[7] = 0;
          obd_kline_session_timer = 1000;
        }
      }
      else if ((obd_req[0xf] < 10) || (0x10 < obd_req[0xf])) {
        if (obd_req[0xf] == 17) {
          obd_req[8] = 0;
          for (bVar1 = 0; bVar1 < 4; bVar1 = bVar1 + 1) {
            obd_req[8] = obd_req[8] + obd_req[bVar1 + 0xc];
          }
          if (obd_req[8] == obd_req[0x10]) {
            reset_learn_tables();
          }
          obd_req[6] = 0;
          obd_req[7] = 0;
          obd_kline_session_timer = 1000;
        }
        else if ((obd_req[0xf] < 0x12) || (0x21 < obd_req[0xf])) {
          if (obd_req[0xf] == 34) {
            if (6 < obd_req[6]) {
              obd_req[8] = 0;
              for (bVar1 = 0; bVar1 < 6; bVar1 = bVar1 + 1) {
                obd_req[8] = obd_req[8] + obd_req[bVar1 + 0xc];
              }
              if (obd_req[8] == obd_req[0x12]) {
                obd_mode_0x22_performance_data
                          ((ushort)obd_req[0x10] * 0x100 + (ushort)obd_req[0x11]);
              }
              obd_req[6] = 0;
              obd_req[7] = 0;
              obd_kline_session_timer = 1000;
            }
          }
          else if ((obd_req[0xf] < 0x23) || (0x2e < obd_req[0xf])) {
            if (obd_req[0xf] == 47) {
              if (6 < obd_req[6]) {
                if ((obd_req[0x10] == 1) && ((obd_req[0x11] & 0x1f) == 0)) {
                  obd_req[8] = 0;
                  for (bVar1 = 0; bVar1 < 6; bVar1 = bVar1 + 1) {
                    obd_req[8] = obd_req[8] + obd_req[bVar1 + 0xc];
                  }
                  if (obd_req[8] == obd_req[0x12]) {
                    obd_mode_0x2F_test(obd_req[0x11] + 0x100,0);
                  }
                  obd_req[6] = 0;
                  obd_req[7] = 0;
                  obd_kline_session_timer = 1000;
                }
                else if (7 < obd_req[6]) {
                  obd_req[8] = 0;
                  for (bVar1 = 0; bVar1 < 7; bVar1 = bVar1 + 1) {
                    obd_req[8] = obd_req[8] + obd_req[bVar1 + 0xc];
                  }
                  if (obd_req[8] == obd_req[0x13]) {
                    obd_mode_0x2F_test((ushort)obd_req[0x10] * 0x100 + (ushort)obd_req[0x11],
                                       obd_req[0x12]);
                  }
                  obd_req[6] = 0;
                  obd_req[7] = 0;
                  obd_kline_session_timer = 1000;
                }
              }
            }
            else if (obd_req[0xf] == 59) {
              if (10 < obd_req[6]) {
                obd_req[8] = 0;
                for (bVar1 = 0; bVar1 < 10; bVar1 = bVar1 + 1) {
                  obd_req[8] = obd_req[8] + obd_req[bVar1 + 0xc];
                }
                if (obd_req[8] == obd_req[0x16]) {
                  obd_kline_mode_0x3B_vin_write
                            (obd_req[0x10],obd_req[0x11],obd_req[0x12],obd_req[0x13],obd_req[0x14],
                             obd_req[0x15]);
                }
                obd_req[6] = 0;
                obd_req[7] = 0;
                obd_kline_session_timer = 1000;
              }
            }
            else {
              obd_kline_send_negative_response();
              obd_req[6] = 0;
              obd_req[7] = 0;
              obd_kline_session_timer = 1000;
            }
          }
          else {
            obd_req[8] = 0;
            for (bVar1 = 0; bVar1 < 4; bVar1 = bVar1 + 1) {
              obd_req[8] = obd_req[8] + obd_req[bVar1 + 0xc];
            }
            if (obd_req[8] == obd_req[0x10]) {
              obd_kline_send_negative_response();
            }
            obd_req[6] = 0;
            obd_req[7] = 0;
            obd_kline_session_timer = 1000;
          }
        }
        else {
          obd_req[8] = 0;
          for (bVar1 = 0; bVar1 < 4; bVar1 = bVar1 + 1) {
            obd_req[8] = obd_req[8] + obd_req[bVar1 + 0xc];
          }
          if (obd_req[8] == obd_req[0x10]) {
            obd_kline_send_negative_response();
          }
          obd_req[6] = 0;
          obd_req[7] = 0;
          obd_kline_session_timer = 1000;
        }
      }
      else {
        obd_req[8] = 0;
        for (bVar1 = 0; bVar1 < 4; bVar1 = bVar1 + 1) {
          obd_req[8] = obd_req[8] + obd_req[bVar1 + 0xc];
        }
        if (obd_req[8] == obd_req[0x10]) {
          obd_kline_send_negative_response();
        }
        obd_req[6] = 0;
        obd_req[7] = 0;
        obd_kline_session_timer = 1000;
      }
    }
    else {
      obd_req[6] = 0;
      obd_req[7] = 0;
      obd_kline_session_timer = 1000;
    }
  }
  return;
}



// K-Line SCI state machine - processes request bytes from the OBD interface

void obd_kline_sci_handler(void)

{
  ushort uVar1;
  
  switch(obd_req[0]) {
  case '\0':
    uVar1 = REG_SC1SR;
    if ((uVar1 >> 5 & 1) == 0) {
      obd_req[3] = obd_req[3] + 1;
      if (1 < obd_req[3]) {
        obd_req[0] = obd_req[0] + 1;
        obd_req[3] = 0;
      }
    }
    else {
      obd_req[3] = 0;
    }
    break;
  case '\x01':
    uVar1 = REG_SC1SR;
    if ((uVar1 >> 5 & 1) == 1) {
      obd_req[3] = obd_req[3] + 1;
      if (obd_req[3] == 40) {
        obd_req[0] = obd_req[0] + 1;
        obd_req[1] = 0;
        obd_req[2] = 0;
        obd_req[3] = 0;
      }
    }
    else {
      obd_req[3] = 0;
    }
    break;
  case '\x02':
    obd_req[3] = obd_req[3] + 1;
    if (obd_req[3] == 0x14) {
      uVar1 = REG_SC1SR;
      if ((uVar1 >> 5 & 1) == 1) {
        obd_req[1] = (uint8_t)((int)(uint)obd_req[1] >> 1);
      }
      else {
        obd_req[1] = (byte)((int)(uint)obd_req[1] >> 1) | 0x80;
      }
    }
    else if (0x27 < obd_req[3]) {
      obd_req[2] = obd_req[2] + 1;
      if (obd_req[2] == 8) {
        obd_req[0] = obd_req[0] + 1;
      }
      obd_req[3] = 0;
    }
    break;
  case '\x03':
    obd_req[3] = obd_req[3] + 1;
    if (obd_req[3] == 40) {
      if (obd_req[1] == 51) {
        uVar1 = REG_SC1SR;
        if (uVar1 == 0) {
          uVar1 = REG_SC1DR;
        }
        obd_req[4] = 0;
        obd_req[0] = obd_req[0] + 1;
        obd_req[3] = 0;
      }
      else {
        obd_req[3] = 0;
        obd_req[0] = 0;
      }
    }
    break;
  case '\x04':
    obd_req[4] = obd_req[4] + 1;
    if (obd_req[4] == 20) {
      REG_SC1DR = 0x55;
      obd_req[0] = obd_req[0] + 1;
      obd_req[4] = 0;
    }
    break;
  case '\x05':
    obd_req[4] = obd_req[4] + 1;
    if (obd_req[4] == 2) {
      REG_SC1DR = 0x94;
      obd_req[0] = obd_req[0] + 1;
      obd_req[4] = 0;
    }
    uVar1 = REG_SC1SR;
    if ((uVar1 >> 6 & 1) == 1) {
      uVar1 = REG_SC1DR;
      obd_req[5] = (uint8_t)uVar1;
    }
    break;
  case '\x06':
    obd_req[4] = obd_req[4] + 1;
    if (obd_req[4] == 2) {
      REG_SC1DR = 0x94;
      obd_req[0] = obd_req[0] + 1;
      obd_req[4] = 0;
    }
    uVar1 = REG_SC1SR;
    if ((uVar1 >> 6 & 1) == 1) {
      uVar1 = REG_SC1DR;
      obd_req[5] = (uint8_t)uVar1;
    }
    break;
  case '\a':
    uVar1 = REG_SC1SR;
    if ((uVar1 >> 6 & 1) == 1) {
      uVar1 = REG_SC1DR;
      if ((uVar1 & 0xff) == 0x6b) {
        obd_req[0] = obd_req[0] + 1;
        obd_req[4] = 0;
      }
    }
    else {
      obd_req[4] = obd_req[4] + 1;
      if (obd_req[4] == 12) {
        obd_req[0] = 0;
        obd_req[4] = 0;
      }
    }
    break;
  case '\b':
    obd_req[4] = obd_req[4] + 1;
    if (obd_req[4] == 7) {
      REG_SC1DR = obd_req[1] ^ 0xff;
    }
    else if ((7 < obd_req[4]) && (uVar1 = REG_SC1SR, (uVar1 >> 6 & 1) == 1)) {
      uVar1 = REG_SC1DR;
      obd_req[5] = (uint8_t)uVar1;
      REG_SCC1R1 = 0x2c;
      obd_req[0] = obd_req[0] + 1;
      obd_req[4] = 0;
      obd_req[6] = 0;
      obd_req[7] = 0;
    }
    break;
  case '\t':
    if (obd_req[0xb] != 0) {
      obd_req[0xb] = obd_req[0xb] + 255;
    }
    if (obd_kline_session_timer == 0) {
      obd_req[0] = 0;
      obd_kline_session_timer = 1000;
      obd_req[1] = 0;
      obd_req[2] = 0;
      obd_req[3] = 0;
      obd_req[4] = 0;
      obd_req[5] = 0;
      obd_req[6] = 0;
      obd_req[7] = 0;
      obd_resp_len = 0;
      obd_resp_i = 0;
      obd_req[8] = 0;
      obd_req[9] = 0;
      obd_req[10] = 0;
      obd_kline_init_sci();
    }
    else {
      obd_kline_session_timer = obd_kline_session_timer - 1;
    }
    break;
  default:
    obd_req[0] = 0;
  }
  return;
}



// Initializes SCI registers for K-Line communication

void obd_kline_init_sci(void)

{
  REG_SCC1R0 = 0x78;
  REG_SCC1R1 = 0xc;
  obd_req[6] = 0;
  return;
}



// Sends OBD response frame

undefined8 send_obd_resp(undefined4 param_1,undefined4 param_2)

{
  uint uVar1;
  ushort uVar2;
  undefined4 in_MSR;
  undefined4 in_SRR1;
  
  uVar2 = REG_SCC1R1;
  if (((uVar2 >> 5 & 1) == 1) && (uVar2 = REG_SC1SR, (uVar2 >> 6 & 1) == 1)) {
    if (obd_resp_len == 0) {
      uVar2 = REG_SC1SR;
      if ((((uVar2 >> 1 & 1) == 0) && (uVar2 = REG_SC1SR, (uVar2 >> 3 & 1) == 0)) &&
         (uVar2 = REG_SC1SR, (uVar2 & 1) == 0)) {
        if (obd_req[6] < 0x80) {
          uVar2 = REG_SC1DR;
          uVar1 = (uint)obd_req[6];
          obd_req[6] = obd_req[6] + 1;
          obd_req[uVar1 + 0xc] = (uint8_t)uVar2;
        }
        obd_req[10] = 0;
      }
      else {
        uVar2 = REG_SC1DR;
        obd_req[10] = obd_req[10] + 1;
        if (1 < obd_req[10]) {
          obd_req[10] = 0;
          obd_req[0] = 0;
          obd_req[3] = 0;
          uVar2 = REG_SCC1R1;
          REG_SCC1R1 = uVar2 & 0xffdf;
        }
      }
    }
    else {
      uVar2 = REG_SC1SR;
      if ((((uVar2 >> 1 & 1) == 0) && (uVar2 = REG_SC1SR, (uVar2 >> 3 & 1) == 0)) &&
         (uVar2 = REG_SC1SR, (uVar2 & 1) == 0)) {
        if (obd_resp_i < obd_resp_len) {
          uVar2 = REG_SC1DR;
          obd_req[9] = (uint8_t)uVar2;
          if (obd_resp[obd_resp_i] == obd_req[9]) {
            obd_resp_i = obd_resp_i + 1;
            REG_SC1DR = (ushort)obd_resp[obd_resp_i];
          }
        }
        else {
          uVar2 = REG_SC1DR;
          obd_req[9] = (uint8_t)uVar2;
          if (obd_resp[obd_resp_i] == obd_req[9]) {
            obd_resp_i = 0;
            obd_resp_len = 0;
          }
          else {
            obd_resp_i = 0;
          }
        }
      }
      else {
        uVar2 = REG_SC1DR;
        obd_resp_i = 0;
        obd_req[10] = obd_req[10] + 1;
        if (1 < obd_req[10]) {
          obd_resp_len = 0;
          obd_req[10] = 0;
          obd_req[0] = 0;
          obd_req[3] = 0;
          uVar2 = REG_SCC1R1;
          REG_SCC1R1 = uVar2 & 0xffdf;
        }
      }
    }
  }
  sci_rx_handler();
  sci_tx_handler();
  uVar1 = REG_SISR3;
  REG_SISR3 = uVar1 & 0xfdffffff | 0x2000000;
  returnFromInterrupt(in_MSR,in_SRR1);
  return CONCAT44(param_1,param_2);
}



// Checks L9822E relay driver for faults (fuel pump, fans, AC, starter relays)

void L9822E_fault_check(void)

{
  if (((DAT_003f9304 ^ DAT_003f930b) & 1) == 0) {
    DAT_003fd520 = DAT_003fd520 & 0xcfff;
  }
  else if ((DAT_003f930b & 1) == 0) {
    DAT_003fd520 = DAT_003fd520 | 0x2000;
  }
  else {
    DAT_003fd520 = DAT_003fd520 | 0x1000;
  }
  if (((DAT_003f9304 ^ DAT_003f930b) & 2) == 0) {
    DAT_003fd520 = DAT_003fd520 & 0x3fff;
  }
  else if ((DAT_003f930b & 2) == 0) {
    DAT_003fd520 = DAT_003fd520 | 0x8000;
  }
  else {
    DAT_003fd520 = DAT_003fd520 | 0x4000;
  }
  if (((DAT_003f9304 ^ DAT_003f930b) & 4) == 0) {
    DAT_003fd520 = DAT_003fd520 & 0xf3ff;
  }
  else if ((DAT_003f930b & 4) == 0) {
    DAT_003fd520 = DAT_003fd520 | 0x800;
  }
  else {
    DAT_003fd520 = DAT_003fd520 | 0x400;
  }
  if (((DAT_003f9304 ^ DAT_003f930b) & 8) == 0) {
    DAT_003fd520 = DAT_003fd520 & 0xfff3;
  }
  else if ((DAT_003f930b & 8) == 0) {
    DAT_003fd520 = DAT_003fd520 | 8;
  }
  else {
    DAT_003fd520 = DAT_003fd520 | 4;
  }
  if (((DAT_003f9304 ^ DAT_003f930b) & 0x10) == 0) {
    DAT_003fd520 = DAT_003fd520 & 0xfcff;
  }
  else if ((DAT_003f930b & 0x10) == 0) {
    DAT_003fd520 = DAT_003fd520 | 0x200;
  }
  else {
    DAT_003fd520 = DAT_003fd520 | 0x100;
  }
  if (((DAT_003f9304 ^ DAT_003f930b) & 0x20) == 0) {
    DAT_003fd520 = DAT_003fd520 & 0xffcf;
  }
  else if ((DAT_003f930b & 0x20) == 0) {
    DAT_003fd520 = DAT_003fd520 | 0x20;
  }
  else {
    DAT_003fd520 = DAT_003fd520 | 0x10;
  }
  if (((DAT_003f9304 ^ DAT_003f930b) & 0x40) == 0) {
    DAT_003fd520 = DAT_003fd520 & 0xfffc;
  }
  else if ((DAT_003f930b & 0x40) == 0) {
    DAT_003fd520 = DAT_003fd520 | 2;
  }
  else {
    DAT_003fd520 = DAT_003fd520 | 1;
  }
  if (((DAT_003f9304 ^ DAT_003f930b) & 0x80) == 0) {
    DAT_003fd520 = DAT_003fd520 & 0xff3f;
  }
  else if ((DAT_003f930b & 0x80) == 0) {
    DAT_003fd520 = DAT_003fd520 | 0x80;
  }
  else {
    DAT_003fd520 = DAT_003fd520 | 0x40;
  }
  return;
}



// Checks TLE6220 high-side driver faults for injectors, VVT, VVL, and EVAP outputs

void TLE6220_fault_check(void)

{
  DAT_003fd52c = DAT_003fd52c | ~(ushort)DAT_003f8002 & 0xff;
  DAT_003fd530 = DAT_003fd530 | ~(ushort)DAT_003f8001 & 0xff;
  DAT_003fd532 = DAT_003fd532 | ~(ushort)DAT_003f8000 & 0xff;
  return;
}



// Updates performance counters (time at TPS/RPM/speed)

void perf_counter(void)

{
  if (engine_speed_2 != 0) {
    if (tps < 5) {
      LEA_perf_time_at_TPS[0] = LEA_perf_time_at_TPS[0] + 1;
    }
    else if ((tps < 5) || (0x26 < tps)) {
      if ((tps < 0x27) || (0x40 < tps)) {
        if ((tps < 0x41) || (0x59 < tps)) {
          if ((tps < 0x5a) || (0x7f < tps)) {
            if ((tps < 0x80) || (0xa6 < tps)) {
              if ((tps < 0xa7) || (0xcc < tps)) {
                if ((0xcc < tps) && (true)) {
                  LEA_perf_time_at_TPS[7] = LEA_perf_time_at_TPS[7] + 1;
                }
              }
              else {
                LEA_perf_time_at_TPS[6] = LEA_perf_time_at_TPS[6] + 1;
              }
            }
            else {
              LEA_perf_time_at_TPS[5] = LEA_perf_time_at_TPS[5] + 1;
            }
          }
          else {
            LEA_perf_time_at_TPS[4] = LEA_perf_time_at_TPS[4] + 1;
          }
        }
        else {
          LEA_perf_time_at_TPS[3] = LEA_perf_time_at_TPS[3] + 1;
        }
      }
      else {
        LEA_perf_time_at_TPS[2] = LEA_perf_time_at_TPS[2] + 1;
      }
    }
    else {
      LEA_perf_time_at_TPS[1] = LEA_perf_time_at_TPS[1] + 1;
    }
    if ((engine_speed_2 < 0x1f5) || (0x5dc < engine_speed_2)) {
      if ((engine_speed_2 < 0x5dd) || (0x9c4 < engine_speed_2)) {
        if ((engine_speed_2 < 0x9c5) || (0xdac < engine_speed_2)) {
          if ((engine_speed_2 < 0xdad) || (0x1194 < engine_speed_2)) {
            if ((engine_speed_2 < 0x1195) || (0x157c < engine_speed_2)) {
              if ((engine_speed_2 < 0x157d) || (0x1964 < engine_speed_2)) {
                if ((engine_speed_2 < 0x1965) || (7000 < engine_speed_2)) {
                  if ((7000 < engine_speed_2) && (engine_speed_2 < 0x1d4d)) {
                    LEA_perf_time_at_RPM[7] = LEA_perf_time_at_RPM[7] + 1;
                  }
                }
                else {
                  LEA_perf_time_at_RPM[6] = LEA_perf_time_at_RPM[6] + 1;
                }
              }
              else {
                LEA_perf_time_at_RPM[5] = LEA_perf_time_at_RPM[5] + 1;
              }
            }
            else {
              LEA_perf_time_at_RPM[4] = LEA_perf_time_at_RPM[4] + 1;
            }
          }
          else {
            LEA_perf_time_at_RPM[3] = LEA_perf_time_at_RPM[3] + 1;
          }
        }
        else {
          LEA_perf_time_at_RPM[2] = LEA_perf_time_at_RPM[2] + 1;
        }
      }
      else {
        LEA_perf_time_at_RPM[1] = LEA_perf_time_at_RPM[1] + 1;
      }
    }
    else {
      LEA_perf_time_at_RPM[0] = LEA_perf_time_at_RPM[0] + 1;
    }
    if (car_speed_smooth < 0x1f) {
      LEA_perf_time_at_KMH[0] = LEA_perf_time_at_KMH[0] + 1;
    }
    else if ((car_speed_smooth < 0x1f) || (0x3c < car_speed_smooth)) {
      if ((car_speed_smooth < 0x3d) || (0x5a < car_speed_smooth)) {
        if ((car_speed_smooth < 0x5b) || (0x78 < car_speed_smooth)) {
          if ((car_speed_smooth < 0x79) || (0x96 < car_speed_smooth)) {
            if ((car_speed_smooth < 0x97) || (0xb4 < car_speed_smooth)) {
              if ((car_speed_smooth < 0xb5) || (0xd2 < car_speed_smooth)) {
                if ((0xd2 < car_speed_smooth) && (car_speed_smooth < 0xf1)) {
                  LEA_perf_time_at_KMH[7] = LEA_perf_time_at_KMH[7] + 1;
                }
              }
              else {
                LEA_perf_time_at_KMH[6] = LEA_perf_time_at_KMH[6] + 1;
              }
            }
            else {
              LEA_perf_time_at_KMH[5] = LEA_perf_time_at_KMH[5] + 1;
            }
          }
          else {
            LEA_perf_time_at_KMH[4] = LEA_perf_time_at_KMH[4] + 1;
          }
        }
        else {
          LEA_perf_time_at_KMH[3] = LEA_perf_time_at_KMH[3] + 1;
        }
      }
      else {
        LEA_perf_time_at_KMH[2] = LEA_perf_time_at_KMH[2] + 1;
      }
    }
    else {
      LEA_perf_time_at_KMH[1] = LEA_perf_time_at_KMH[1] + 1;
    }
    if ((coolant_smooth < 0xe9) || (0xf0 < coolant_smooth)) {
      if ((coolant_smooth < 0xf1) || (0xf8 < coolant_smooth)) {
        if ((coolant_smooth < 0xf9) || (0xfe < coolant_smooth)) {
          if (coolant_smooth == 255) {
            LEA_perf_time_at_coolant_temp[3] = LEA_perf_time_at_coolant_temp[3] + 1;
          }
        }
        else {
          LEA_perf_time_at_coolant_temp[2] = LEA_perf_time_at_coolant_temp[2] + 1;
        }
      }
      else {
        LEA_perf_time_at_coolant_temp[1] = LEA_perf_time_at_coolant_temp[1] + 1;
      }
    }
    else {
      LEA_perf_time_at_coolant_temp[0] = LEA_perf_time_at_coolant_temp[0] + 1;
    }
  }
  if (((((LEA_perf_time_at_TPS[0] == 4294967294) || (LEA_perf_time_at_TPS[1] == 4294967294)) ||
       (LEA_perf_time_at_TPS[2] == 4294967294)) ||
      ((((LEA_perf_time_at_TPS[3] == 4294967294 || (LEA_perf_time_at_TPS[4] == 4294967294)) ||
        ((LEA_perf_time_at_TPS[5] == 4294967294 ||
         ((LEA_perf_time_at_TPS[6] == 4294967294 || (LEA_perf_time_at_TPS[7] == 4294967294)))))) ||
       (LEA_perf_time_at_RPM[0] == 4294967294)))) ||
     (((((LEA_perf_time_at_RPM[1] == 4294967294 || (LEA_perf_time_at_RPM[2] == 4294967294)) ||
        (LEA_perf_time_at_RPM[3] == 4294967294)) ||
       ((LEA_perf_time_at_RPM[4] == 4294967294 || (LEA_perf_time_at_RPM[5] == 4294967294)))) ||
      ((((LEA_perf_time_at_RPM[6] == 4294967294 ||
         ((LEA_perf_time_at_RPM[7] == 4294967294 || (LEA_perf_time_at_KMH[0] == 4294967294)))) ||
        (LEA_perf_time_at_KMH[1] == 4294967294)) ||
       ((((((LEA_perf_time_at_KMH[2] == 4294967294 || (LEA_perf_time_at_KMH[3] == 4294967294)) ||
           (LEA_perf_time_at_KMH[4] == 4294967294)) ||
          ((LEA_perf_time_at_KMH[5] == 4294967294 || (LEA_perf_time_at_KMH[6] == 4294967294)))) ||
         (LEA_perf_time_at_KMH[7] == 4294967294)) ||
        (((LEA_perf_time_at_coolant_temp[0] == 4294967294 ||
          (LEA_perf_time_at_coolant_temp[1] == 4294967294)) ||
         ((LEA_perf_time_at_coolant_temp[2] == 4294967294 ||
          (LEA_perf_time_at_coolant_temp[3] == 4294967294)))))))))))) {
    LEA_perf_time_at_TPS[0] = 0;
    LEA_perf_time_at_TPS[1] = 0;
    LEA_perf_time_at_TPS[2] = 0;
    LEA_perf_time_at_TPS[3] = 0;
    LEA_perf_time_at_TPS[4] = 0;
    LEA_perf_time_at_TPS[5] = 0;
    LEA_perf_time_at_TPS[6] = 0;
    LEA_perf_time_at_TPS[7] = 0;
    LEA_perf_time_at_RPM[0] = 0;
    LEA_perf_time_at_RPM[1] = 0;
    LEA_perf_time_at_RPM[2] = 0;
    LEA_perf_time_at_RPM[3] = 0;
    LEA_perf_time_at_RPM[4] = 0;
    LEA_perf_time_at_RPM[5] = 0;
    LEA_perf_time_at_RPM[6] = 0;
    LEA_perf_time_at_RPM[7] = 0;
    LEA_perf_time_at_KMH[0] = 0;
    LEA_perf_time_at_KMH[1] = 0;
    LEA_perf_time_at_KMH[2] = 0;
    LEA_perf_time_at_KMH[3] = 0;
    LEA_perf_time_at_KMH[4] = 0;
    LEA_perf_time_at_KMH[5] = 0;
    LEA_perf_time_at_KMH[6] = 0;
    LEA_perf_time_at_KMH[7] = 0;
    LEA_perf_time_at_coolant_temp[0] = 0;
    LEA_perf_time_at_coolant_temp[1] = 0;
    LEA_perf_time_at_coolant_temp[2] = 0;
    LEA_perf_time_at_coolant_temp[3] = 0;
  }
  if ((DAT_003f81c0 != '\0') && (DAT_003f81c0 = DAT_003f81c0 + -1, DAT_003fd542 < engine_speed_2)) {
    DAT_003fd542 = engine_speed_2;
  }
  if (DAT_003f81c0 == '\0') {
    DAT_003f81c0 = '2';
    if (LEA_perf_max_engine_speed[0] < DAT_003fd542) {
      LEA_perf_max_engine_speed[4] = LEA_perf_max_engine_speed[3];
      LEA_perf_max_engine_speed[3] = LEA_perf_max_engine_speed[2];
      LEA_perf_max_engine_speed[2] = LEA_perf_max_engine_speed[1];
      LEA_perf_max_engine_speed[1] = LEA_perf_max_engine_speed[0];
      LEA_perf_max_engine_speed[0] = DAT_003fd542;
      LEA_perf_max_engine_speed_5_coolant_temp = coolant_smooth;
      LEA_perf_max_engine_speed_5_run_timer = LEA_perf_engine_run_timer;
    }
    else if ((LEA_perf_max_engine_speed[1] < DAT_003fd542) &&
            (DAT_003fd542 < LEA_perf_max_engine_speed[0])) {
      LEA_perf_max_engine_speed[4] = LEA_perf_max_engine_speed[3];
      LEA_perf_max_engine_speed[3] = LEA_perf_max_engine_speed[2];
      LEA_perf_max_engine_speed[2] = LEA_perf_max_engine_speed[1];
      LEA_perf_max_engine_speed[1] = DAT_003fd542;
      LEA_perf_max_engine_speed_4_coolant_temp = coolant_smooth;
      LEA_perf_max_engine_speed_4_run_timer = LEA_perf_engine_run_timer;
    }
    else if ((LEA_perf_max_engine_speed[2] < DAT_003fd542) &&
            (DAT_003fd542 < LEA_perf_max_engine_speed[1])) {
      LEA_perf_max_engine_speed[4] = LEA_perf_max_engine_speed[3];
      LEA_perf_max_engine_speed[3] = LEA_perf_max_engine_speed[2];
      LEA_perf_max_engine_speed[2] = DAT_003fd542;
      LEA_perf_max_engine_speed_3_coolant_temp = coolant_smooth;
      LEA_perf_max_engine_speed_3_run_timer = LEA_perf_engine_run_timer;
    }
    else if ((LEA_perf_max_engine_speed[3] < DAT_003fd542) &&
            (DAT_003fd542 < LEA_perf_max_engine_speed[2])) {
      LEA_perf_max_engine_speed[4] = LEA_perf_max_engine_speed[3];
      LEA_perf_max_engine_speed[3] = DAT_003fd542;
      LEA_perf_max_engine_speed_2_coolant_temp = coolant_smooth;
      LEA_perf_max_engine_speed_2_run_timer = LEA_perf_engine_run_timer;
    }
    else if ((LEA_perf_max_engine_speed[4] < DAT_003fd542) &&
            (DAT_003fd542 < LEA_perf_max_engine_speed[3])) {
      LEA_perf_max_engine_speed[4] = DAT_003fd542;
      LEA_perf_max_engine_speed_1_coolant_temp = coolant_smooth;
      LEA_perf_max_engine_speed_1_run_timer = LEA_perf_engine_run_timer;
    }
    DAT_003fd542 = 0;
  }
  if (car_speed_smooth != 255) {
    if (LEA_perf_max_vehicle_speed[0] < car_speed_smooth) {
      if (DAT_003fd538 == '\x01') {
        DAT_003fd540 = DAT_003fd540 + 1;
      }
      else {
        DAT_003fd540 = 0;
        DAT_003fd538 = '\x01';
      }
      if (0x14 < DAT_003fd540) {
        LEA_perf_max_vehicle_speed[4] = LEA_perf_max_vehicle_speed[3];
        LEA_perf_max_vehicle_speed[3] = LEA_perf_max_vehicle_speed[2];
        LEA_perf_max_vehicle_speed[2] = LEA_perf_max_vehicle_speed[1];
        LEA_perf_max_vehicle_speed[1] = LEA_perf_max_vehicle_speed[0];
        LEA_perf_max_vehicle_speed[0] = car_speed_smooth;
        DAT_003fd540 = 0;
      }
    }
    else if ((LEA_perf_max_vehicle_speed[1] < car_speed_smooth) &&
            (car_speed_smooth < LEA_perf_max_vehicle_speed[0])) {
      if (DAT_003fd538 == '\x02') {
        DAT_003fd540 = DAT_003fd540 + 1;
      }
      else {
        DAT_003fd540 = 0;
        DAT_003fd538 = '\x02';
      }
      if (0x14 < DAT_003fd540) {
        LEA_perf_max_vehicle_speed[4] = LEA_perf_max_vehicle_speed[3];
        LEA_perf_max_vehicle_speed[3] = LEA_perf_max_vehicle_speed[2];
        LEA_perf_max_vehicle_speed[2] = LEA_perf_max_vehicle_speed[1];
        LEA_perf_max_vehicle_speed[1] = car_speed_smooth;
        DAT_003fd540 = 0;
      }
    }
    else if ((LEA_perf_max_vehicle_speed[2] < car_speed_smooth) &&
            (car_speed_smooth < LEA_perf_max_vehicle_speed[1])) {
      if (DAT_003fd538 == '\x03') {
        DAT_003fd540 = DAT_003fd540 + 1;
      }
      else {
        DAT_003fd540 = 0;
        DAT_003fd538 = '\x03';
      }
      if (0x14 < DAT_003fd540) {
        LEA_perf_max_vehicle_speed[4] = LEA_perf_max_vehicle_speed[3];
        LEA_perf_max_vehicle_speed[3] = LEA_perf_max_vehicle_speed[2];
        LEA_perf_max_vehicle_speed[2] = car_speed_smooth;
        DAT_003fd540 = 0;
      }
    }
    else if ((LEA_perf_max_vehicle_speed[3] < car_speed_smooth) &&
            (car_speed_smooth < LEA_perf_max_vehicle_speed[2])) {
      if (DAT_003fd538 == '\x04') {
        DAT_003fd540 = DAT_003fd540 + 1;
      }
      else {
        DAT_003fd540 = 0;
        DAT_003fd538 = '\x04';
      }
      if (0x14 < DAT_003fd540) {
        LEA_perf_max_vehicle_speed[4] = LEA_perf_max_vehicle_speed[3];
        LEA_perf_max_vehicle_speed[3] = car_speed_smooth;
        DAT_003fd540 = 0;
      }
    }
    else if ((LEA_perf_max_vehicle_speed[4] < car_speed_smooth) &&
            (car_speed_smooth < LEA_perf_max_vehicle_speed[3])) {
      if (DAT_003fd538 == '\x05') {
        DAT_003fd540 = DAT_003fd540 + 1;
      }
      else {
        DAT_003fd540 = 0;
        DAT_003fd538 = '\x05';
      }
      if (0x14 < DAT_003fd540) {
        LEA_perf_max_vehicle_speed[4] = car_speed_smooth;
        DAT_003fd540 = 0;
      }
    }
    else {
      DAT_003fd538 = '\0';
    }
  }
  if (engine_speed_2 != 0) {
    if (LEA_perf_engine_run_timer == 4294967295) {
      LEA_perf_engine_run_timer = 0;
    }
    else {
      LEA_perf_engine_run_timer = LEA_perf_engine_run_timer + 1;
    }
    if (DAT_002f8354 < DAT_003fe0bc) {
      DAT_002f8354 = DAT_003fe0bc;
    }
  }
  if (car_speed_smooth == 0) {
    DAT_003fd544 = 0;
    if (DAT_003f947a < engine_speed_2) {
      DAT_003fd547 = DAT_003fd547 | 7;
    }
    else {
      DAT_003fd547 = DAT_003fd547 & 0xf8;
    }
  }
  else if ((DAT_003fd547 & 1) != 0) {
    DAT_003fd544 = DAT_003fd544 + 1;
    if (DAT_003fd544 < 0xff) {
      if (((99 < car_speed_smooth) && (car_speed_smooth < 0x78)) && ((DAT_003fd547 & 2) != 0)) {
        DAT_003fd547 = DAT_003fd547 & 0xfd;
        LEA_perf_number_of_standing_starts = LEA_perf_number_of_standing_starts + 1;
        DAT_003fd545 = DAT_003fd544;
      }
      if (((0x9f < car_speed_smooth) && (car_speed_smooth < 0xb4)) && ((DAT_003fd547 & 4) != 0)) {
        DAT_003fd547 = DAT_003fd547 & 0xfb;
        DAT_003fd546 = DAT_003fd544;
      }
    }
    else {
      DAT_003fd547 = DAT_003fd547 & 0xf8;
      DAT_003fd544 = 0;
    }
  }
  if ((DAT_003fd545 != 0) &&
     (LEA_perf_last_standing_start[0] = DAT_003fd545,
     DAT_003fd545 < LEA_perf_fastest_standing_start[0])) {
    LEA_perf_fastest_standing_start[0] = DAT_003fd545;
  }
  if (((100 < DAT_003fd546) && (DAT_003fd545 < DAT_003fd546)) &&
     (LEA_perf_last_standing_start[1] = DAT_003fd546,
     DAT_003fd546 < LEA_perf_fastest_standing_start[1])) {
    LEA_perf_fastest_standing_start[1] = DAT_003fd546;
  }
  return;
}



// EVAP flow monitor (P0441)

void obd_check_evap_flow(void)

{
  ushort uVar1;
  ushort uVar2;
  
  if ((vacuum_smooth < DAT_003fc060) || (evap_purge_command < DAT_003fc056)) {
    DAT_003f8e6c = DAT_003fc05c;
    DAT_003f8e6e = '\0';
    DAT_003f8e6d = '\0';
  }
  else if ((int)evap_pressure_smooth < -(int)DAT_003fc058) {
    if (DAT_003f8e6d == '\x04') {
      if (DAT_003f8e6c == '\0') {
        DAT_003f8e6e = '\x04';
      }
    }
    else {
      DAT_003f8e6c = DAT_003fc05c;
      DAT_003f8e6e = '\0';
      DAT_003f8e6d = '\x04';
    }
  }
  else if ((int)evap_pressure_smooth < -(int)DAT_003fc05a) {
    if (DAT_003f8e6d == '\x03') {
      if (DAT_003f8e6c == '\0') {
        DAT_003f8e6e = '\x03';
      }
    }
    else {
      DAT_003f8e6c = DAT_003fc05c;
      DAT_003f8e6e = '\0';
      DAT_003f8e6d = '\x03';
    }
  }
  else if (-(int)CAL_evap_leak_vacuum_min < (int)evap_pressure_smooth) {
    if (DAT_003f8e6d == '\x01') {
      if (DAT_003f8e6c == '\0') {
        DAT_003f8e6e = '\x01';
      }
    }
    else {
      DAT_003f8e6c = DAT_003fc05c;
      DAT_003f8e6e = '\0';
      DAT_003f8e6d = '\x01';
    }
  }
  else if (DAT_003f8e6d == '\x02') {
    if (DAT_003f8e6c == '\0') {
      DAT_003f8e6e = '\x02';
    }
  }
  else {
    DAT_003f8e6c = DAT_003fc05c;
    DAT_003f8e6e = '\0';
    DAT_003f8e6d = '\x02';
  }
  if (((((evap_flags & 0x200) == 0) || ((LEA_obd_P0455_flags & 8) != 0)) ||
      ((DAT_003fd580 & 0x2000) != 0)) && ((DAT_003fd580 & 0x40) == 0)) {
    uVar1 = DAT_003fd580 & 0xefff;
  }
  else {
    uVar1 = DAT_003fd580 | 0x1000;
    if (DAT_003f8e6e == '\x03') {
      if ((DAT_003fd580 & 0x40) != 0) {
        if ((DAT_003fd580 & 0x80) == 0) {
          uVar1 = DAT_003fd580 | 0x5000;
        }
        DAT_003fd580 = uVar1;
        uVar1 = DAT_003fd580 & 0xffbf;
      }
      DAT_003fd580 = uVar1;
      obd_clr_dtc(&CAL_obd_P0455,&LEA_obd_P0455_flags);
      obd_clr_dtc(&CAL_obd_P0441,&LEA_obd_P0441_flags);
      uVar1 = DAT_003fd580;
    }
    else if ((DAT_003f8e6e == '\x02') || (DAT_003f8e6e == '\x01')) {
      if ((DAT_003fd580 & 0x40) == 0) {
        uVar1 = DAT_003fd580 | 0x3000;
      }
      else {
        if (((DAT_003fd580 & 0x80) == 0) || (DAT_003f8e6e != '\x01')) {
          if ((DAT_003f8e6e == '\x02') || (DAT_003f8e6e == '\x01')) {
            uVar1 = DAT_003fd580 | 0x3000;
          }
        }
        else {
          uVar1 = DAT_003fd580 | 0x1100;
        }
        DAT_003fd580 = uVar1;
        uVar1 = DAT_003fd580 & 0xffbf;
      }
    }
  }
  DAT_003fd580 = uVar1;
  if (((DAT_003fd580 & 0x4000) == 0) && ((DAT_003fd580 & 0x2000) == 0)) {
    if ((DAT_003fd580 & 0x8000) != 0) {
      DAT_003f8e6a = DAT_003fc05d;
    }
    DAT_003fd580 = DAT_003fd580 & 0x7fff;
    if (DAT_003f8e6a == '\0') {
      evap_flags = evap_flags & 0xdfff;
    }
    DAT_003f8e6b = DAT_003fc05e;
  }
  else {
    if ((DAT_003fd580 & 0x8000) == 0) {
      DAT_003f8e6a = DAT_003fc05d;
    }
    uVar1 = DAT_003fd580 | 0x8000;
    evap_flags = evap_flags | 0x2000;
    if (((((car_speed_smooth == 0) || (load_2 <= DAT_003f8e6b)) || (DAT_003f8e6e == '\x04')) ||
        ((vacuum_smooth < DAT_003fc060 || (evap_purge_command < DAT_003fc056)))) ||
       ((DAT_003f8e6a == '\0' && (DAT_003f8e6e != '\0')))) {
      if (DAT_003f8e6e == '\x04') {
        uVar1 = DAT_003fd580 & 0x9fff | 0x8000;
      }
      else if ((DAT_003f8e6e != '\0') && (DAT_003f8e6a == '\0')) {
        if ((DAT_003fd580 & 0x4000) != 0) {
          uVar1 = DAT_003fd580 & 0xbfff | 0x8200;
        }
        DAT_003fd580 = uVar1;
        uVar1 = DAT_003fd580;
        if ((DAT_003fd580 & 0x2000) != 0) {
          if ((CAL_obd_P0455 & 7) != 0) {
            if (obd_P0455_debounce_count != 0) {
              obd_P0455_debounce_count = obd_P0455_debounce_count + 255;
            }
            if (obd_P0455_debounce_count == 0) {
              obd_set_dtc(&CAL_obd_P0455,&LEA_obd_P0455_flags,&LEA_obd_P0455_engine_start_count,
                          &LEA_obd_P0455_warm_up_cycle_count,0x1c7);
            }
          }
          uVar1 = DAT_003fd580 & 0xdfff;
        }
      }
      DAT_003fd580 = uVar1;
      uVar1 = REG_MPWMSM0_SCR;
      REG_MPWMSM0_SCR = uVar1 & 0xf7ff;
      DAT_003f8e6a = DAT_003fc05d;
      DAT_003f8e6b = DAT_003fc05e;
    }
    else {
      uVar2 = REG_MPWMSM0_SCR;
      REG_MPWMSM0_SCR = uVar2 & 0xf7ff | 0x800;
      DAT_003f8e6b = DAT_003fc05f;
      DAT_003fd580 = uVar1;
    }
  }
  if ((CAL_obd_P0441 & 7) != 0) {
    if (((int)evap_leak_pressure_min < -(int)DAT_003fc05a) || ((DAT_003fd580 & 0x100) != 0)) {
      if (obd_P0441_debounce_count != 0) {
        obd_P0441_debounce_count = obd_P0441_debounce_count + 255;
      }
      if (obd_P0441_debounce_count == 0) {
        obd_set_dtc(&CAL_obd_P0441,&LEA_obd_P0441_flags,&LEA_obd_P0441_engine_start_count,
                    &LEA_obd_P0441_warm_up_cycle_count,0x1b9);
        DAT_003fd580 = DAT_003fd580 & 0xfeff;
        evap_leak_pressure_min = 0;
      }
    }
    else {
      if (obd_P0441_debounce_count < CAL_obd_P0441_debounce_threshold) {
        obd_P0441_debounce_count = obd_P0441_debounce_count + 1;
      }
      if (evap_leak_state == 5) {
        obd_clr_dtc(&CAL_obd_P0441,&LEA_obd_P0441_flags);
      }
    }
  }
  if ((CAL_obd_P0446 & 7) != 0) {
    if ((((int)evap_pressure_smooth < -(int)DAT_003fc058) && (evap_state == '\x01')) &&
       ((evap_flags & 0x2000) == 0)) {
      if (DAT_003f8e6f == '\0') {
        if (obd_P0446_debounce_count != 0) {
          obd_P0446_debounce_count = obd_P0446_debounce_count + 255;
        }
        if (obd_P0446_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0446,&LEA_obd_P0446_flags,&LEA_obd_P0446_engine_start_count,
                      &LEA_obd_P0446_warm_up_cycle_count,0x1be);
          DAT_003fd580 = DAT_003fd580 | 0x400;
        }
      }
    }
    else {
      DAT_003f8e6f = DAT_003fc05c;
      if ((DAT_003fd580 & 0x200) == 0) {
        if (obd_P0446_debounce_count < CAL_obd_P0446_debounce_threshold) {
          obd_P0446_debounce_count = obd_P0446_debounce_count + 1;
        }
        if (((((DAT_003fd580 & 0x80) != 0) || (evap_leak_state == 5)) ||
            (DAT_003f94ca >> 1 < evap_purge_command)) && ((LEA_obd_P0446_flags & 8) == 0)) {
          obd_clr_dtc(&CAL_obd_P0446,&LEA_obd_P0446_flags);
        }
      }
      else {
        if (obd_P0446_debounce_count != 0) {
          obd_P0446_debounce_count = obd_P0446_debounce_count + 255;
        }
        if (obd_P0446_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0446,&LEA_obd_P0446_flags,&LEA_obd_P0446_engine_start_count,
                      &LEA_obd_P0446_warm_up_cycle_count,0x1be);
          DAT_003fd580 = DAT_003fd580 & 0xfdff;
        }
      }
    }
  }
  return;
}



// EVAP flow monitor task (100ms)

void obd_check_evap_flow_100ms(void)

{
  if (DAT_003f8e6a != '\0') {
    DAT_003f8e6a = DAT_003f8e6a + -1;
  }
  if (DAT_003f8e6c != '\0') {
    DAT_003f8e6c = DAT_003f8e6c + -1;
  }
  if (DAT_003f8e6f != '\0') {
    DAT_003f8e6f = DAT_003f8e6f + -1;
  }
  return;
}



// Initializes EVAP flow monitor state

void obd_init_evap_flow(void)

{
  obd_P0441_debounce_count = CAL_obd_P0441_debounce_threshold;
  obd_P0446_debounce_count = CAL_obd_P0446_debounce_threshold;
  obd_init_dtc(&CAL_obd_P0441,&LEA_obd_P0441_flags,0x1b9);
  obd_init_dtc(&CAL_obd_P0446,&LEA_obd_P0446_flags,0x1be);
  return;
}



// EVAP flow monitor cycle counter

void obd_cyc_evap_flow(void)

{
  obd_cyc_dtc(&CAL_obd_P0441,&LEA_obd_P0441_flags,&LEA_obd_P0441_engine_start_count,
              &LEA_obd_P0441_warm_up_cycle_count,0x1b9);
  obd_cyc_dtc(&CAL_obd_P0446,&LEA_obd_P0446_flags,&LEA_obd_P0446_engine_start_count,
              &LEA_obd_P0446_warm_up_cycle_count,0x1be);
  return;
}



// Crank/cam sensor monitors (P0335/P0340/P0500)

void obd_check_crank_cam_speed(void)

{
  if (DAT_003f8e72 < car_speed_smooth) {
    DAT_003f8e72 = car_speed_smooth;
  }
  if (((CAL_obd_P0500 & 7) != 0) && (engine_is_running)) {
    if (((dfso_flags & 1) == 0) ||
       (((engine_speed_3 < DAT_003fbf9f || (DAT_003fbffa < engine_speed_3)) ||
        (atmo_pressure < DAT_003fc02a)))) {
      DAT_003f8e70 = DAT_003fbf98;
    }
    else if (DAT_003f8e70 != 0) {
      DAT_003f8e70 = DAT_003f8e70 + -1;
    }
    if (DAT_003f8e70 == 0) {
      if (car_speed_smooth < DAT_003fbf9c) {
        if (obd_P0500_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0500,&LEA_obd_P0500_flags,&LEA_obd_P0500_engine_start_count,
                      &LEA_obd_P0500_warm_up_cycle_count,500);
        }
        else {
          obd_P0500_debounce_count = obd_P0500_debounce_count + 255;
        }
      }
      else {
        obd_clr_dtc(&CAL_obd_P0500,&LEA_obd_P0500_flags);
        if (obd_P0500_debounce_count < CAL_obd_P0500_debounce_threshold) {
          obd_P0500_debounce_count = obd_P0500_debounce_count + 1;
        }
      }
    }
  }
  if (((CAL_obd_P0335 & 7) != 0) && ((shutdown_flags & 1) != 0)) {
    if ((DAT_003fbf9d < DAT_003fe189) || (DAT_003fbf9d < DAT_003fe188)) {
      if (obd_P0335_debounce_count == 0) {
        obd_set_dtc(&CAL_obd_P0335,&LEA_obd_P0335_flags,&LEA_obd_P0335_engine_start_count,
                    &LEA_obd_P0335_warm_up_cycle_count,0x14f);
      }
      else {
        obd_P0335_debounce_count = obd_P0335_debounce_count + 255;
      }
    }
    else {
      obd_clr_dtc(&CAL_obd_P0335,&LEA_obd_P0335_flags);
      if (obd_P0335_debounce_count < CAL_obd_P0335_debounce_threshold) {
        obd_P0335_debounce_count = obd_P0335_debounce_count + 1;
      }
    }
  }
  if ((engine_is_running == false) && (DAT_003fe188 < DAT_003fbf9d)) {
    obd_P0335_debounce_count = CAL_obd_P0335_debounce_threshold;
  }
  if ((((CAL_obd_P0340 & 7) != 0) && ((shutdown_flags & 1) != 0)) && (engine_is_running != false)) {
    if ((DAT_003fe0cc == -0x80) || (DAT_003fe0cc == -1)) {
      if (obd_P0340_debounce_count == 0) {
        obd_set_dtc(&CAL_obd_P0340,&LEA_obd_P0340_flags,&LEA_obd_P0340_engine_start_count,
                    &LEA_obd_P0340_warm_up_cycle_count,0x154);
      }
      else {
        obd_P0340_debounce_count = obd_P0340_debounce_count + 255;
      }
    }
    else {
      obd_clr_dtc(&CAL_obd_P0340,&LEA_obd_P0340_flags);
      if (obd_P0340_debounce_count < CAL_obd_P0340_debounce_threshold) {
        obd_P0340_debounce_count = obd_P0340_debounce_count + 1;
      }
    }
  }
  return;
}



// Initializes crank/cam monitor state

void obd_init_crank_cam_speed(void)

{
  obd_P0335_debounce_count = CAL_obd_P0335_debounce_threshold;
  obd_P0500_debounce_count = CAL_obd_P0500_debounce_threshold;
  obd_P0340_debounce_count = CAL_obd_P0340_debounce_threshold;
  DAT_003f8e70 = DAT_003fbf98;
  obd_init_dtc(&CAL_obd_P0335,&LEA_obd_P0335_flags,0x14f);
  obd_init_dtc(&CAL_obd_P0500,&LEA_obd_P0500_flags,500);
  obd_init_dtc(&CAL_obd_P0340,&LEA_obd_P0340_flags,0x154);
  return;
}



// Crank/cam monitor cycle counter

void obd_cyc_crank_cam_speed(void)

{
  obd_cyc_dtc(&CAL_obd_P0335,&LEA_obd_P0335_flags,&LEA_obd_P0335_engine_start_count,
              &LEA_obd_P0335_warm_up_cycle_count,0x14f);
  obd_cyc_dtc(&CAL_obd_P0500,&LEA_obd_P0500_flags,&LEA_obd_P0500_engine_start_count,
              &LEA_obd_P0500_warm_up_cycle_count,500);
  obd_cyc_dtc(&CAL_obd_P0340,&LEA_obd_P0340_flags,&LEA_obd_P0340_engine_start_count,
              &LEA_obd_P0340_warm_up_cycle_count,0x154);
  return;
}



// Fuel trim monitor (P0171/P0172)

void obd_check_fuel_trim(void)

{
  int iVar1;
  
  if (atmo_pressure < 1000) {
    iVar1 = (1000 - atmo_pressure) * (int)(short)(ushort)DAT_003fbf89;
    iVar1 = iVar1 / 100 + (iVar1 >> 0x1f);
    DAT_003fd556 = DAT_003fbf82 + ((short)iVar1 - (short)(iVar1 >> 0x1f));
  }
  else {
    DAT_003fd556 = DAT_003fbf82;
  }
  if (((((((LEA_obd_P0131_flags & 4) == 0) && ((LEA_obd_P0135_flags & 4) == 0)) &&
        ((LEA_obd_P0107_flags & 4) == 0)) &&
       (((LEA_obd_P0108_flags & 4) == 0 && ((LEA_obd_P0300_flags & 4) == 0)))) &&
      ((LEA_obd_P0301_flags & 4) == 0)) &&
     (((((LEA_obd_P0302_flags & 4) == 0 && ((LEA_obd_P0303_flags & 4) == 0)) &&
       (((LEA_obd_P0304_flags & 4) == 0 &&
        ((((LEA_obd_P0111_flags & 4) == 0 && ((LEA_obd_P0112_flags & 4) == 0)) &&
         ((LEA_obd_P0113_flags & 4) == 0)))))) &&
      (((LEA_obd_P0106_flags & 4) == 0 && ((fuel_system_status & 2) != 0)))))) {
    if ((CAL_obd_P0171 & 7) != 0) {
      if ((((DAT_003fd556 < inj_time_adj_by_ltft) && (DAT_003fc022 <= DAT_003fd39a)) &&
          (maf_flow_1 < CAL_ltft_zone2_flow_max)) ||
         (((short)(ushort)DAT_003fbfb6 * 10 < (int)LEA_ltft_zone1_adj &&
          (DAT_003fc020 <= DAT_003fd398)))) {
        if (obd_P0171_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0171,&LEA_obd_P0171_flags,&LEA_obd_P0171_engine_start_count,
                      &LEA_obd_P0171_warm_up_cycle_count,0xab);
        }
        else {
          obd_P0171_debounce_count = obd_P0171_debounce_count + 255;
        }
      }
      else if ((DAT_003fc020 <= DAT_003fd398) &&
              ((DAT_003fc022 < DAT_003fd39a &&
               (obd_clr_dtc(&CAL_obd_P0171,&LEA_obd_P0171_flags),
               obd_P0171_debounce_count < CAL_obd_P0171_debounce_threshold)))) {
        obd_P0171_debounce_count = obd_P0171_debounce_count + 1;
      }
    }
    if ((CAL_obd_P0172 & 7) != 0) {
      if (((((int)inj_time_adj_by_ltft < -(int)DAT_003fbf84) && (DAT_003fc022 <= DAT_003fd39a)) &&
          (maf_flow_1 < CAL_ltft_zone2_flow_max)) ||
         (((int)LEA_ltft_zone1_adj < (short)(ushort)DAT_003fbfb7 * -10 &&
          (DAT_003fc020 <= DAT_003fd398)))) {
        if (obd_P0172_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0172,&LEA_obd_P0172_flags,&LEA_obd_P0172_engine_start_count,
                      &LEA_obd_P0172_warm_up_cycle_count,0xac);
        }
        else {
          obd_P0172_debounce_count = obd_P0172_debounce_count + 255;
        }
      }
      else if ((DAT_003fc020 <= DAT_003fd398) &&
              ((DAT_003fc022 < DAT_003fd39a &&
               (obd_clr_dtc(&CAL_obd_P0172,&LEA_obd_P0172_flags),
               obd_P0172_debounce_count < CAL_obd_P0172_debounce_threshold)))) {
        obd_P0172_debounce_count = obd_P0172_debounce_count + 1;
      }
    }
  }
  return;
}



// Initializes fuel trim monitor state

void obd_init_fuel_trim(void)

{
  obd_P0171_debounce_count = CAL_obd_P0171_debounce_threshold;
  obd_P0172_debounce_count = CAL_obd_P0172_debounce_threshold;
  obd_init_dtc(&CAL_obd_P0171,&LEA_obd_P0171_flags,0xab);
  obd_init_dtc(&CAL_obd_P0172,&LEA_obd_P0172_flags,0xac);
  return;
}



// Fuel trim monitor cycle counter

void obd_cyc_fuel_trim(void)

{
  if (((LEA_obd_P0171_flags & 4) != 0) && ((short)((ushort)DAT_003fbfb6 * 5) < LEA_ltft_zone1_adj))
  {
    LEA_ltft_zone1_adj = (ushort)DAT_003fbfb6 * 5;
  }
  if (((LEA_obd_P0172_flags & 4) != 0) && (LEA_ltft_zone1_adj < (short)((ushort)DAT_003fbfb7 * -5)))
  {
    LEA_ltft_zone1_adj = (ushort)DAT_003fbfb7 * -5;
  }
  obd_cyc_dtc(&CAL_obd_P0171,&LEA_obd_P0171_flags,&LEA_obd_P0171_engine_start_count,
              &LEA_obd_P0171_warm_up_cycle_count,0xab);
  obd_cyc_dtc(&CAL_obd_P0172,&LEA_obd_P0172_flags,&LEA_obd_P0172_engine_start_count,
              &LEA_obd_P0172_warm_up_cycle_count,0xac);
  return;
}



// Idle speed monitor (P0506/P0507)

void obd_check_idle_speed(void)

{
  uint uVar1;
  
  if (((((idle_flags & 8) != 0) && (sensor_adc_ecu_voltage < DAT_003fbfa2)) &&
      (DAT_003fbfa0 < sensor_adc_ecu_voltage)) && (engine_is_running)) {
    if ((CAL_obd_P0506 & 7) != 0) {
      if (((((ac_fan_flags & 0x400) == 0) ||
           (uVar1 = (uint)LEA_idle_flow_adj1_ac_on,
           (int)(((int)uVar1 >> 10) + (uint)((int)uVar1 < 0 && (uVar1 & 0x3ff) != 0)) <=
           (int)(uint)DAT_003fbfa5)) &&
          (((ac_fan_flags & 0x400) != 0 ||
           (uVar1 = (uint)LEA_idle_flow_adj1,
           (int)(((int)uVar1 >> 10) + (uint)((int)uVar1 < 0 && (uVar1 & 0x3ff) != 0)) <=
           (int)(uint)DAT_003fbfa5)))) ||
         ((int)((uint)DAT_003fbfc8 * -2) <= (int)engine_speed_idle_error)) {
        obd_P0506_fault_sample_count = 0;
        obd_clr_dtc(&CAL_obd_P0506,&LEA_obd_P0506_flags);
        if (obd_P0506_debounce_count < CAL_obd_P0506_debounce_threshold) {
          obd_P0506_debounce_count = obd_P0506_debounce_count + 1;
        }
      }
      else {
        obd_P0506_fault_sample_count = obd_P0506_fault_sample_count + 1;
        if (CAL_obd_P0506_P0507_fault_sample_threshold <= obd_P0506_fault_sample_count) {
          obd_P0506_fault_sample_count = 0;
          if (obd_P0506_debounce_count == 0) {
            obd_set_dtc(&CAL_obd_P0506,&LEA_obd_P0506_flags,&LEA_obd_P0506_engine_start_count,
                        &LEA_obd_P0506_warm_up_cycle_count,0x1fa);
          }
          else {
            obd_P0506_debounce_count = obd_P0506_debounce_count + 255;
          }
        }
      }
    }
    if ((CAL_obd_P0507 & 7) != 0) {
      if (((((ac_fan_flags & 0x400) == 0) ||
           (uVar1 = (uint)LEA_idle_flow_adj1_ac_on,
           (int)-(uint)DAT_003fbfa4 <=
           (int)(((int)uVar1 >> 10) + (uint)((int)uVar1 < 0 && (uVar1 & 0x3ff) != 0)))) &&
          (((ac_fan_flags & 0x400) != 0 ||
           (uVar1 = (uint)LEA_idle_flow_adj1,
           (int)-(uint)DAT_003fbfa4 <=
           (int)(((int)uVar1 >> 10) + (uint)((int)uVar1 < 0 && (uVar1 & 0x3ff) != 0)))))) ||
         ((int)engine_speed_idle_error <= (int)((uint)DAT_003fbfc7 << 1))) {
        obd_P0507_fault_sample_count = 0;
        obd_clr_dtc(&CAL_obd_P0507,&LEA_obd_P0507_flags);
        if (obd_P0507_debounce_count < CAL_obd_P0507_debounce_threshold) {
          obd_P0507_debounce_count = obd_P0507_debounce_count + 1;
        }
      }
      else {
        obd_P0507_fault_sample_count = obd_P0507_fault_sample_count + 1;
        if (CAL_obd_P0506_P0507_fault_sample_threshold <= obd_P0507_fault_sample_count) {
          obd_P0507_fault_sample_count = 0;
          if (obd_P0507_debounce_count == 0) {
            obd_set_dtc(&CAL_obd_P0507,&LEA_obd_P0507_flags,&LEA_obd_P0507_engine_start_count,
                        &LEA_obd_P0507_warm_up_cycle_count,0x1fb);
          }
          else {
            obd_P0507_debounce_count = obd_P0507_debounce_count + 255;
          }
        }
      }
    }
  }
  return;
}



// Initializes idle speed monitor state

void obd_init_idle_speed(void)

{
  obd_P0506_debounce_count = CAL_obd_P0506_debounce_threshold;
  obd_P0507_debounce_count = CAL_obd_P0507_debounce_threshold;
  obd_init_dtc(&CAL_obd_P0506,&LEA_obd_P0506_flags,0x1fa);
  obd_init_dtc(&CAL_obd_P0507,&LEA_obd_P0507_flags,0x1fb);
  return;
}



// Idle speed monitor cycle counter

void obd_cyc_idle_speed(void)

{
  if ((LEA_obd_P0506_flags & 4) != 0) {
    if ((short)(ushort)DAT_003fbfa5 < LEA_idle_flow_adj1_ac_on >> 10) {
      LEA_idle_flow_adj1_ac_on = (i16_flow_100_1024mg_s)((int)(short)(ushort)DAT_003fbfa5 << 9);
    }
    if ((short)(ushort)DAT_003fbfa5 < LEA_idle_flow_adj1 >> 10) {
      LEA_idle_flow_adj1 = (i16_flow_100_1024mg_s)((int)(short)(ushort)DAT_003fbfa5 << 9);
    }
  }
  if ((LEA_obd_P0507_flags & 4) != 0) {
    if ((int)LEA_idle_flow_adj1_ac_on >> 10 < -(int)(short)(ushort)DAT_003fbfa4) {
      LEA_idle_flow_adj1_ac_on = (ushort)DAT_003fbfa4 * -0x200;
    }
    if ((int)LEA_idle_flow_adj1 >> 10 < -(int)(short)(ushort)DAT_003fbfa4) {
      LEA_idle_flow_adj1 = (ushort)DAT_003fbfa4 * -0x200;
    }
  }
  obd_cyc_dtc(&CAL_obd_P0506,&LEA_obd_P0506_flags,&LEA_obd_P0506_engine_start_count,
              &LEA_obd_P0506_warm_up_cycle_count,0x1fa);
  obd_cyc_dtc(&CAL_obd_P0507,&LEA_obd_P0507_flags,&LEA_obd_P0507_engine_start_count,
              &LEA_obd_P0507_warm_up_cycle_count,0x1fb);
  return;
}



// EVAP leak monitor (P0442/P0455/P0456)

void obd_check_evap_leak(void)

{
  ushort uVar1;
  ushort uVar2;
  byte bVar3;
  uint uVar4;
  int iVar5;
  
  if ((CAL_obd_P0442 & 7) == 0) {
    DAT_003fd59c = DAT_003fd59c | 1;
  }
  if ((((LEA_obd_P0455_flags & 4) != 0) || ((LEA_obd_P0442_flags & 4) != 0)) ||
     ((LEA_obd_P0456_flags & 8) != 0)) {
    DAT_003fd59c = DAT_003fd59c | 2;
  }
  if ((LEA_obd_P0441_flags & 4) != 0) {
    DAT_003fd59c = DAT_003fd59c | 4;
  }
  if ((LEA_obd_P0444_flags & 4) != 0) {
    DAT_003fd59c = DAT_003fd59c | 8;
  }
  if ((LEA_obd_P0445_flags & 4) != 0) {
    DAT_003fd59c = DAT_003fd59c | 0x10;
  }
  if ((LEA_obd_P0446_flags & 4) != 0) {
    DAT_003fd59c = DAT_003fd59c | 0x20;
  }
  if ((LEA_obd_P0447_flags & 4) != 0) {
    DAT_003fd59c = DAT_003fd59c | 0x40;
  }
  if ((LEA_obd_P0448_flags & 4) != 0) {
    DAT_003fd59c = DAT_003fd59c | 0x80;
  }
  if ((LEA_obd_P0451_flags & 4) != 0) {
    DAT_003fd59c = DAT_003fd59c | 0x100;
  }
  if ((LEA_obd_P0452_flags & 4) != 0) {
    DAT_003fd59c = DAT_003fd59c | 0x200;
  }
  if ((LEA_obd_P0453_flags & 4) != 0) {
    DAT_003fd59c = DAT_003fd59c | 0x400;
  }
  if ((LEA_obd_P0461_flags & 4) != 0) {
    DAT_003fd59c = DAT_003fd59c | 0x800;
  }
  if ((LEA_obd_P0462_flags & 4) != 0) {
    DAT_003fd59c = DAT_003fd59c | 0x1000;
  }
  if ((LEA_obd_P0463_flags & 4) != 0) {
    DAT_003fd59c = DAT_003fd59c | 0x2000;
  }
  if ((LEA_obd_P0500_flags & 4) != 0) {
    DAT_003fd59c = DAT_003fd59c | 0x4000;
  }
  if (obd_P0171_debounce_count == 0) {
    DAT_003fd59c = DAT_003fd59c | 0x8000;
  }
  if (obd_P0172_debounce_count == 0) {
    DAT_003fd59c = DAT_003fd59c | 0x10000;
  }
  if (engine_air_stop < CAL_evap_leak_engine_air_stop_max) {
    DAT_003fd59c = DAT_003fd59c | 0x40000;
  }
  if (DAT_003fd59c != 0) {
    DAT_003fd580 = DAT_003fd580 | 2;
  }
  if ((((((DAT_003fd580 & 2) == 0) && (CAL_evap_leak_atmo_pressure_min < atmo_pressure)) &&
       (((((LEA_obd_P0442_flags & 8) == 0 && ((evap_flags & 0x200) == 0)) || (DAT_003f8e82 == 0)) &&
        (((fuel_level_smooth < CAL_evap_leak_fuel_level_max &&
          (CAL_evap_leak_fuel_level_min < fuel_level_smooth)) &&
         ((CAL_evap_leak_coolant_min < coolant_smooth &&
          ((engine_air_smooth < CAL_evap_leak_engine_air_max && ((DAT_003fd580 & 0x6040) == 0)))))))
        ))) || ((DAT_003fd580 & 1) != 0)) &&
     ((((car_speed_smooth == 0 && ((fuel_system_status & 2) != 0)) && ((idle_flags & 8) != 0)) &&
      ((shutdown_flags & 1) != 0)))) {
    DAT_003fd580 = DAT_003fd580 | 4;
  }
  else {
    DAT_003fd580 = DAT_003fd580 & 0xfffb;
  }
  if (((DAT_003fd580 & 4) == 0) || ((DAT_003fd580 & 8) == 0)) {
    if ((obd_mode_0x2F_state == '\x18') ||
       ((obd_mode_0x08_state == '\x18' || (DAT_003fbfbe == '\x06')))) {
      if (obd_mode_0x2F_value == '\0') {
        uVar1 = REG_MPWMSM0_SCR;
        REG_MPWMSM0_SCR = uVar1 & 0xf7ff;
      }
      else {
        uVar1 = REG_MPWMSM0_SCR;
        REG_MPWMSM0_SCR = uVar1 & 0xf7ff | 0x800;
      }
    }
    else {
      uVar1 = REG_MPWMSM0_SCR;
      REG_MPWMSM0_SCR = uVar1 & 0xf7ff;
    }
    DAT_003fd580 = DAT_003fd580 & 0xffcf;
    evap_leak_state = 0;
    DAT_003fd594 = CAL_evap_leak_initial_delay;
    if ((((idle_flags & 8) == 0) || (car_speed_smooth != 0)) &&
       (((LEA_obd_P0442_flags & 8) != 0 || ((evap_flags & 0x200) != 0)))) {
      DAT_003f8e82 = CAL_evap_leak_cooldown;
    }
    else if (DAT_003f8e82 != 0) {
      DAT_003f8e82 = DAT_003f8e82 - 1;
    }
    if (CAL_evap_leak_force != 0) {
      DAT_003fd580 = DAT_003fd580 | 1;
    }
    evap_pressure_drop_max_leak_test = 255;
    uVar1 = DAT_003fd580;
  }
  else {
    uVar1 = DAT_003fd580 | 0x10;
    if (evap_leak_state == 3) {
      uVar1 = DAT_003fd580 | 0x30;
      if (evap_leak_vacuum_target < evap_pressure) {
        if ((int)evap_leak_vacuum_target + (int)DAT_003f81c8 < (int)evap_pressure) {
          DAT_003f8e84 = evap_pressure_drop_2;
          evap_pressure_drop_max_leak_test = 255;
        }
        else {
          iVar5 = (int)((uint)DAT_003f8e84 * ((int)evap_pressure - (int)evap_leak_vacuum_target)) /
                  (int)DAT_003f81c8 + ((int)(uint)DAT_003f8e88 >> 2);
          if (iVar5 < 2) {
            evap_pressure_drop_max_leak_test = 2;
          }
          else if (iVar5 < 0x100) {
            evap_pressure_drop_max_leak_test = (u8_pressure_4mbar)iVar5;
          }
          else {
            evap_pressure_drop_max_leak_test = 255;
          }
          if (DAT_003f8e88 != 0xff) {
            DAT_003f8e88 = DAT_003f8e88 + 1;
          }
        }
        if (DAT_003f8e86 == 0) {
          if ((((DAT_003fd580 & 0x800) == 0) &&
              ((short)CAL_evap_leak_purge_min < evap_purge_command)) ||
             ((short)CAL_evap_leak_purge_retry_min < evap_purge_command)) {
            uVar1 = DAT_003fd580 | 0x70;
          }
          DAT_003fd580 = uVar1;
          uVar1 = DAT_003fd580 & 0xfffe;
        }
        else {
          DAT_003f8e86 = DAT_003f8e86 - 1;
          if (CAL_evap_leak_gross_pressure < evap_pressure) {
            DAT_003fd580 = uVar1;
            obd_clr_dtc(&CAL_obd_P0455,&LEA_obd_P0455_flags);
            uVar1 = DAT_003fd580 | 0x80;
          }
          else if ((int)evap_pressure < -(int)CAL_evap_leak_vacuum_min) {
            uVar1 = DAT_003fd580 | 0x830;
          }
        }
      }
      else {
        DAT_003fd580 = uVar1 & 0xffdf;
        DAT_003fd595 = CAL_evap_leak_settle_time;
        obd_clr_dtc(&CAL_obd_P0455,&LEA_obd_P0455_flags);
        evap_leak_state = evap_leak_state + 1;
        uVar1 = DAT_003fd580;
      }
    }
    else {
      DAT_003fd580 = uVar1;
      if (evap_leak_state < 3) {
        if (evap_leak_state == 1) {
          if (DAT_003fd595 == 0) {
            uVar4 = (uint)sensor_adc_evap * (uint)CAL_sensor_evap_gain;
            DAT_003fd0d6 = ((short)((int)uVar4 >> 10) +
                           (ushort)((int)uVar4 < 0 && (uVar4 & 0x3ff) != 0)) -
                           CAL_sensor_evap_offset;
            evap_leak_pressure_max = 0;
            evap_leak_pressure_min = 0;
            evap_leak_baseline_timer = CAL_evap_leak_baseline_time;
            evap_leak_state = 2;
          }
          else {
            DAT_003fd595 = DAT_003fd595 + 255;
          }
        }
        else if (evap_leak_state == 0) {
          if (true) {
            if (DAT_003fd594 == 0) {
              uVar2 = REG_MPWMSM0_SCR;
              REG_MPWMSM0_SCR = uVar2 & 0xf7ff | 0x800;
              DAT_003fd595 = CAL_evap_leak_settle_time;
              evap_leak_state = 1;
            }
            else {
              DAT_003fd594 = DAT_003fd594 + 255;
            }
          }
        }
        else {
          if (evap_leak_baseline_timer == 0) {
            bVar3 = lookup_3D_uint8_interpolated
                              (8,16,evap_leak_pressure_ripple & 0xff,(ushort)fuel_level_smooth,
                               CAL_evap_leak_pressure_margin,
                               CAL_evap_leak_pressure_margin_X_pressure_ripple,
                               CAL_evap_leak_pressure_margin_Y_fuel_level);
            evap_leak_vacuum_target = evap_leak_pressure_min - (ushort)bVar3;
            DAT_003f8e86 = (ushort)CAL_evap_leak_purge_time;
            DAT_003f8e88 = 0;
            evap_leak_state = evap_leak_state + 1;
            DAT_003fd580 = DAT_003fd580 & 0xf7ff;
          }
          else {
            evap_leak_baseline_timer = evap_leak_baseline_timer + 255;
          }
          if (evap_leak_pressure_max < evap_pressure) {
            evap_leak_pressure_max = evap_pressure;
          }
          if (evap_pressure < evap_leak_pressure_min) {
            evap_leak_pressure_min = evap_pressure;
          }
          uVar1 = DAT_003fd580;
          if (evap_leak_pressure_max < evap_leak_pressure_min) {
            evap_leak_pressure_ripple = 0;
          }
          else {
            evap_leak_pressure_ripple = evap_leak_pressure_max - evap_leak_pressure_min;
          }
        }
      }
      else if (evap_leak_state == 5) {
        evap_leak_pressure_rise =
             (evap_pressure - evap_reference) -
             (short)(((int)evap_leak_pressure_ripple *
                     (int)(short)(CAL_evap_leak_P0456_time - evap_leak_P0456_timer)) /
                    (int)(short)(ushort)CAL_evap_leak_baseline_time);
        if (evap_leak_P0456_timer != 0) {
          evap_leak_P0456_timer = evap_leak_P0456_timer - 1;
        }
        if (evap_leak_P0442_timer == 0) {
          obd_clr_dtc(&CAL_obd_P0442,&LEA_obd_P0442_flags);
          if (obd_P0442_debounce_count < CAL_obd_P0442_debounce_threshold) {
            obd_P0442_debounce_count = obd_P0442_debounce_count + 1;
          }
          if (evap_leak_P0456_timer == 0) {
            obd_clr_dtc(&CAL_obd_P0456,&LEA_obd_P0456_flags);
            if (obd_P0456_debounce_count < CAL_obd_P0456_debounce_threshold) {
              obd_P0456_debounce_count = obd_P0456_debounce_count + 1;
            }
            if (((int)(uint)DAT_002f829a < (int)evap_leak_pressure_rise) &&
               (0 < evap_leak_pressure_rise)) {
              DAT_002f829a = evap_leak_pressure_rise;
              sort10(&DAT_002f829a);
            }
            uVar1 = DAT_003fd580 & 0xfffe;
          }
          else {
            uVar1 = DAT_003fd580;
            if ((short)(ushort)evap_leak_P0456_threshold < evap_leak_pressure_rise) {
              if (obd_P0456_debounce_count != 0) {
                obd_P0456_debounce_count = obd_P0456_debounce_count + 255;
              }
              if (obd_P0456_debounce_count == 0) {
                obd_set_dtc(&CAL_obd_P0456,&LEA_obd_P0456_flags,&LEA_obd_P0456_engine_start_count,
                            &LEA_obd_P0456_warm_up_cycle_count,0x1c8);
                uVar1 = DAT_003fd580 & 0xfffe;
              }
            }
          }
        }
        else {
          evap_leak_P0442_timer = evap_leak_P0442_timer + 255;
          evap_leak_result = evap_leak_pressure_rise;
          if ((short)(ushort)evap_leak_P0442_threshold < evap_leak_pressure_rise) {
            if (obd_P0442_debounce_count != 0) {
              obd_P0442_debounce_count = obd_P0442_debounce_count + 255;
            }
            if (obd_P0442_debounce_count == 0) {
              obd_set_dtc(&CAL_obd_P0442,&LEA_obd_P0442_flags,&LEA_obd_P0442_engine_start_count,
                          &LEA_obd_P0442_warm_up_cycle_count,0x1ba);
              uVar1 = DAT_003fd580 & 0xfffe;
            }
          }
        }
      }
      else if ((evap_leak_state < 5) && (evap_pressure_drop_2 == 0)) {
        if (DAT_003fd595 == 0) {
          inj_time_adj_by_stft = 0;
          evap_reference = evap_pressure;
          evap_leak_P0442_timer = CAL_evap_leak_P0442_time;
          evap_leak_P0456_timer = CAL_evap_leak_P0456_time;
          evap_leak_P0456_threshold =
               lookup_2D_uint8_interpolated
                         (16,fuel_level_smooth,CAL_evap_leak_P0456_threshold,
                          CAL_evap_leak_P0456_threshold_X_fuel_level);
          evap_leak_P0442_threshold =
               lookup_2D_uint8_interpolated
                         (16,fuel_level_smooth,CAL_evap_leak_P0442_threshold,
                          CAL_evap_leak_P0442_threshold_X_fuel_level);
          evap_leak_state = evap_leak_state + 1;
          uVar1 = DAT_003fd580;
        }
        else {
          DAT_003fd595 = DAT_003fd595 + 255;
        }
      }
    }
  }
  DAT_003fd580 = uVar1;
  if ((((LEA_obd_P0442_flags & 8) != 0) && ((LEA_obd_P0442_flags & 4) == 0)) ||
     (((LEA_obd_P0442_flags & 4) != 0 && ((LEA_obd_P0442_flags & 0x10) != 0)))) {
    LEA_obd_monitors_completeness = LEA_obd_monitors_completeness & 0xfb;
  }
  if ((((((LEA_obd_P0442_flags & 8) != 0) && ((LEA_obd_P0455_flags & 8) != 0)) &&
       ((LEA_obd_P0456_flags & 8) != 0)) &&
      (((CAL_obd_P0445 & 8) != 0 && ((CAL_obd_P0455 & 8) != 0)))) && ((CAL_obd_P0456 & 8) != 0)) {
    LEA_obd_P0442_flags = LEA_obd_P0442_flags & 0xf7;
    LEA_obd_P0455_flags = LEA_obd_P0455_flags & 0xf7;
    LEA_obd_P0456_flags = LEA_obd_P0456_flags & 0xf7;
  }
  return;
}



// Initializes EVAP leak monitor state

void obd_init_evap_leak(void)

{
  obd_P0442_debounce_count = CAL_obd_P0442_debounce_threshold;
  obd_P0455_debounce_count = CAL_obd_P0455_debounce_threshold;
  obd_P0456_debounce_count = CAL_obd_P0456_debounce_threshold;
  obd_init_dtc(&CAL_obd_P0442,&LEA_obd_P0442_flags,0x1ba);
  obd_init_dtc(&CAL_obd_P0455,&LEA_obd_P0455_flags,0x1c7);
  obd_init_dtc(&CAL_obd_P0456,&LEA_obd_P0456_flags,0x1c8);
  DAT_003fd594 = CAL_evap_leak_initial_delay;
  return;
}



// EVAP leak monitor cycle counter

void obd_cyc_evap_leak(void)

{
  obd_cyc_dtc(&CAL_obd_P0442,&LEA_obd_P0442_flags,&LEA_obd_P0442_engine_start_count,
              &LEA_obd_P0442_warm_up_cycle_count,0x1ba);
  obd_cyc_dtc(&CAL_obd_P0455,&LEA_obd_P0455_flags,&LEA_obd_P0455_engine_start_count,
              &LEA_obd_P0455_warm_up_cycle_count,0x1c7);
  obd_cyc_dtc(&CAL_obd_P0456,&LEA_obd_P0456_flags,&LEA_obd_P0456_engine_start_count,
              &LEA_obd_P0456_warm_up_cycle_count,0x1c8);
  return;
}



// ECU internal fault monitors (P0601/P0606)

void obd_check_ecu_internal(void)

{
  if ((CAL_obd_P0601 & 7) != 0) {
    if ((DAT_003fd5a0 & 1) == 0) {
      obd_clr_dtc(&CAL_obd_P0601,&LEA_obd_P0601_flags);
    }
    else {
      DAT_003fd5a0 = DAT_003fd5a0 & 0xfffe;
      obd_set_dtc(&CAL_obd_P0601,&LEA_obd_P0601_flags,&LEA_obd_P0601_engine_start_count,
                  &LEA_obd_P0601_warm_up_cycle_count,0x259);
    }
  }
  if ((CAL_obd_P0606 & 7) != 0) {
    if ((DAT_003fd5a0 & 2) == 0) {
      obd_clr_dtc(&CAL_obd_P0606,&LEA_obd_P0606_flags);
    }
    else {
      DAT_003fd5a0 = DAT_003fd5a0 & 0xfffd;
      obd_set_dtc(&CAL_obd_P0606,&LEA_obd_P0606_flags,&LEA_obd_P0606_engine_start_count,
                  &LEA_obd_P0606_warm_up_cycle_count,0x25e);
    }
  }
  return;
}



// Initializes ECU internal monitor state

void obd_init_ecu_internal(void)

{
  byte bVar1;
  
  obd_init_dtc(&CAL_obd_P0601,&LEA_obd_P0601_flags,0x259);
  obd_init_dtc(&CAL_obd_P0606,&LEA_obd_P0606_flags,0x25e);
  obd_init_dtc(&CAL_obd_P0630,&LEA_obd_P0630_flags,0x276);
  DAT_003fd5a0 = DAT_003fd5a0 | 4;
  for (bVar1 = 0; bVar1 < 0x11; bVar1 = bVar1 + 1) {
    if (LEA_ecu_VIN[bVar1] != CAL_ecu_generic_VIN[bVar1]) {
      DAT_003fd5a0 = DAT_003fd5a0 & 0xfffb;
      bVar1 = 0x11;
    }
  }
  if ((CAL_obd_P0630 & 7) != 0) {
    if ((DAT_003fd5a0 & 4) == 0) {
      obd_clr_dtc(&CAL_obd_P0630,&LEA_obd_P0630_flags);
    }
    else {
      DAT_003fd5a0 = DAT_003fd5a0 & 0xfffb;
      obd_set_dtc(&CAL_obd_P0630,&LEA_obd_P0630_flags,&LEA_obd_P0630_engine_start_count,
                  &LEA_obd_P0630_warm_up_cycle_count,0x276);
    }
  }
  return;
}



// ECU internal monitor cycle counter

void obd_cyc_ecu_internal(void)

{
  obd_cyc_dtc(&CAL_obd_P0601,&LEA_obd_P0601_flags,&LEA_obd_P0601_engine_start_count,
              &LEA_obd_P0601_warm_up_cycle_count,0x259);
  obd_cyc_dtc(&CAL_obd_P0606,&LEA_obd_P0606_flags,&LEA_obd_P0606_engine_start_count,
              &LEA_obd_P0606_warm_up_cycle_count,0x25e);
  obd_cyc_dtc(&CAL_obd_P0630,&LEA_obd_P0630_flags,&LEA_obd_P0630_engine_start_count,
              &LEA_obd_P0630_warm_up_cycle_count,0x276);
  return;
}



// Misfire monitor (P0300-P0304, P1301/P1302)

void obd_check_misfire(void)

{
  int iVar1;
  uint16_t uVar3;
  byte bVar4;
  uint8_t uVar5;
  uint uVar2;
  ushort uVar6;
  
  iVar1 = (int)(uint)engine_speed_3 >> 4;
  uVar3 = lookup_3D_uint16_interpolated
                    (16,16,engine_speed_2,(uint16_t)load_1_smooth,CAL_misfire_threshold,
                     CAL_misfire_threshold_X_engine_speed,CAL_misfire_threshold_Y_engine_load);
  misfire_threshold = uVar3 ^ 0x8000;
  misfire_unused =
       lookup_3D_uint8_interpolated_noaxis
                 (33,5,3,(ushort)engine_speed_3,(ushort)load_2,CAL_misfire_unused);
  bVar4 = lookup_2D_uint8_interpolated_noaxis
                    (3,(ushort)engine_speed_3,CAL_misfire_cat_threshold_adj);
  misfire_cat_threshold_adj =
       (u8_time_us)
       ((int)(((uint)CAL_misfire_dfso_count_max[iVar1] - (uint)misfire_dfso_count[iVar1]) *
             (int)(short)(ushort)bVar4) / (int)(uint)CAL_misfire_dfso_count_max[iVar1]);
  uVar5 = lookup_2D_uint8_interpolated_noaxis
                    (3,(ushort)engine_speed_3,CAL_misfire_cat_threshold_base);
  misfire_cat_threshold = misfire_cat_threshold_adj + uVar5;
  obd_P1302_threshold =
       lookup_3D_uint8_interpolated
                 (8,8,(ushort)engine_speed_3,(ushort)load_2,CAL_obd_P1302_threshold,
                  CAL_obd_P1302_threshold_X_engine_speed,CAL_obd_P1302_threshold_Y_engine_load);
  obd_P1301_threshold = CAL_obd_P1301_threshold;
  misfire_load_min =
       lookup_2D_uint8_interpolated_noaxis(3,(ushort)engine_speed_3,CAL_misfire_load_min);
  if ((((LEA_obd_P0101_flags & 4) == 0) && ((LEA_obd_P0102_flags & 4) == 0)) &&
     ((LEA_obd_P0103_flags & 4) == 0)) {
    misfire_flags = misfire_flags & 0xfff7;
  }
  else {
    misfire_flags = misfire_flags | 8;
  }
  uVar2 = abs(misfire_dt_unused);
  if (((int)CAL_misfire_eval_dt_unused_max < (int)uVar2) ||
     (uVar2 = abs(dt_engine_speed), (int)(short)CAL_misfire_eval_dt_engine_speed_max < (int)uVar2))
  {
    misfire_flags = misfire_flags | 0x10;
    misfire_eval_speed_transient_timer = CAL_misfire_eval_speed_transient_delay;
  }
  else if (misfire_eval_speed_transient_timer == 0) {
    misfire_flags = misfire_flags & 0xffef;
  }
  if ((((((misfire_flags & 0x20) != 0) || (coolant_smooth < CAL_misfire_eval_coolant_low)) ||
       ((CAL_misfire_eval_coolant_high < coolant_smooth ||
        ((((engine_speed_3 < CAL_misfire_eval_engine_speed_low ||
           (CAL_misfire_eval_engine_speed_high < engine_speed_3)) ||
          (revlimit_misfire_eval < engine_speed_2)) ||
         ((fuel_level_smooth < CAL_misfire_eval_fuel_level_min || ((tc_flags & 2) != 0)))))))) ||
      ((load_2 < misfire_load_min && ((misfire_flags & 8) == 0)))) || ((dfso_flags & 1) != 0)) {
    misfire_eval_inhibit_timer = CAL_misfire_eval_inhibit_delay;
  }
  if ((misfire_eval_inhibit_timer == 0) && (misfire_eval_speed_transient_timer == 0)) {
    misfire_flags = misfire_flags | 2;
  }
  else {
    misfire_flags = misfire_flags & 0xfffd;
  }
  misfire_dead_cylinder_penalty = 0;
  for (bVar4 = 0; bVar4 < 4; bVar4 = bVar4 + 1) {
    if (misfire_cat_timer[bVar4] == 0) {
      misfire_dead_cylinder_penalty = misfire_dead_cylinder_penalty + 250;
    }
  }
  if (engine_is_running == false) {
    obd_P1301_debounce_count = 1;
    obd_P1302_debounce_count = 1;
    misfire_flags = misfire_flags & 0xcfff;
  }
  uVar3 = misfire_flags;
  if ((misfire_flags & 0x4000) != 0) {
    uVar3 = misfire_flags & 0xbfff;
    if (misfire_dead_cylinder_penalty < misfire_cat_total_count) {
      misfire_cat_max_result = misfire_cat_total_count;
    }
    else {
      misfire_cat_max_result = misfire_dead_cylinder_penalty;
    }
    if ((CAL_obd_P1302 & 7) != 0) {
      if (((uint)obd_P1302_threshold << 1 < (uint)misfire_cat_max_result) &&
         (((misfire_flags & 2) != 0 || ((misfire_flags & 0x20) != 0)))) {
        if (obd_P1302_debounce_count == 0) {
          misfire_flags = uVar3;
          obd_set_dtc(&CAL_obd_P1302,&LEA_obd_P1302_flags,&LEA_obd_P1302_engine_start_count,
                      &LEA_obd_P1302_warm_up_cycle_count,0x516);
          uVar3 = misfire_flags;
          if ((misfire_cylinder_cut_timer == 0) && (CAL_misfire_use_cylinder_cut != false)) {
            if (((misfire_cat_timer[0] == 0) || (misfire_cat_timer[2] == 0)) ||
               ((((uint)misfire_cat_count_prev[3] + (uint)misfire_cat_count_prev[1] <=
                  (uint)misfire_cat_count_prev[0] + (uint)misfire_cat_count_prev[2] &&
                 (misfire_cat_timer[3] != 0)) && (misfire_cat_timer[1] != 0)))) {
              uVar3 = misfire_flags | 0x260;
            }
            else {
              uVar3 = misfire_flags | 0x1a0;
            }
          }
        }
        else {
          obd_P1302_debounce_count = obd_P1302_debounce_count + 255;
          if (obd_P1302_debounce_count == 0) {
            misfire_flags = uVar3;
            obd_set_dtc(&CAL_obd_P1302,&LEA_obd_P1302_flags,&LEA_obd_P1302_engine_start_count,
                        &LEA_obd_P1302_warm_up_cycle_count,0x516);
            uVar3 = misfire_flags;
          }
        }
      }
      else {
        misfire_cylinder_cut_timer = CAL_misfire_cylinder_cut_delay;
        misfire_flags = uVar3;
        obd_clr_dtc(&CAL_obd_P1302,&LEA_obd_P1302_flags);
        uVar3 = misfire_flags;
        if ((misfire_flags & 0x2000) == 0) {
          obd_P1302_debounce_count = CAL_obd_P1302_debounce_threshold;
          uVar3 = misfire_flags | 0x2000;
        }
      }
    }
  }
  misfire_flags = uVar3;
  if ((misfire_flags & 0x8000) != 0) {
    uVar6 = misfire_flags & 0x7fff;
    if ((misfire_flags & 0x20) == 0) {
      if (misfire_dead_cylinder_penalty < misfire_total_count) {
        misfire_max_result = misfire_total_count;
      }
      else {
        misfire_max_result = misfire_dead_cylinder_penalty;
      }
    }
    else {
      misfire_max_result = misfire_cat_max_result;
    }
    misfire_flags = uVar6;
    if (LEA_misfire_max_result_history[0] < misfire_max_result) {
      LEA_misfire_max_result_history[0] = misfire_max_result;
      sort10(LEA_misfire_max_result_history);
    }
    if ((CAL_obd_P1301 & 7) != 0) {
      if (obd_P1301_threshold < misfire_max_result) {
        if ((obd_P1301_debounce_count != 0) &&
           (obd_P1301_debounce_count = obd_P1301_debounce_count + 255, obd_P1301_debounce_count == 0
           )) {
          obd_set_dtc(&CAL_obd_P1301,&LEA_obd_P1301_flags,&LEA_obd_P1301_engine_start_count,
                      &LEA_obd_P1301_warm_up_cycle_count,0x515);
        }
      }
      else {
        obd_clr_dtc(&CAL_obd_P1301,&LEA_obd_P1301_flags);
        if ((misfire_flags & 0x1000) == 0) {
          obd_P1301_debounce_count = CAL_obd_P1301_debounce_threshold;
          misfire_flags = misfire_flags | 0x1000;
        }
      }
    }
  }
  DAT_003f8e9e = 0;
  if (((CAL_obd_P0301 & 7) != 0) && ((LEA_obd_P0340_flags & 4) == 0)) {
    if (((misfire_count_prev[0] < 6) ||
        (((LEA_obd_P1301_flags & 1) == 0 || ((obd_P1301_flags_prev & 1) != 0)))) &&
       (((misfire_cat_count_prev[0] < 3 && (misfire_cat_timer[0] != 0)) ||
        (((LEA_obd_P1302_flags & 1) == 0 || ((obd_P1302_flags_prev & 1) != 0)))))) {
      obd_clr_dtc(&CAL_obd_P0301,&LEA_obd_P0301_flags);
    }
    else {
      obd_set_dtc(&CAL_obd_P0301,&LEA_obd_P0301_flags,&LEA_obd_P0301_engine_start_count,
                  &LEA_obd_P0301_warm_up_cycle_count,0x12d);
      DAT_003f8e9e = DAT_003f8e9e + 1;
    }
  }
  if (((CAL_obd_P0302 & 7) != 0) && ((LEA_obd_P0340_flags & 4) == 0)) {
    if (((misfire_count_prev[3] < 6) ||
        (((LEA_obd_P1301_flags & 1) == 0 || ((obd_P1301_flags_prev & 1) != 0)))) &&
       (((misfire_cat_count_prev[3] < 3 && (misfire_cat_timer[3] != 0)) ||
        (((LEA_obd_P1302_flags & 1) == 0 || ((obd_P1302_flags_prev & 1) != 0)))))) {
      obd_clr_dtc(&CAL_obd_P0302,&LEA_obd_P0302_flags);
    }
    else {
      obd_set_dtc(&CAL_obd_P0302,&LEA_obd_P0302_flags,&LEA_obd_P0302_engine_start_count,
                  &LEA_obd_P0302_warm_up_cycle_count,0x12e);
      DAT_003f8e9e = DAT_003f8e9e + 1;
    }
  }
  if (((CAL_obd_P0303 & 7) != 0) && ((LEA_obd_P0340_flags & 4) == 0)) {
    if (((misfire_count_prev[1] < 6) ||
        (((LEA_obd_P1301_flags & 1) == 0 || ((obd_P1301_flags_prev & 1) != 0)))) &&
       (((misfire_cat_count_prev[1] < 3 && (misfire_cat_timer[1] != 0)) ||
        (((LEA_obd_P1302_flags & 1) == 0 || ((obd_P1302_flags_prev & 1) != 0)))))) {
      obd_clr_dtc(&CAL_obd_P0303,&LEA_obd_P0303_flags);
    }
    else {
      obd_set_dtc(&CAL_obd_P0303,&LEA_obd_P0303_flags,&LEA_obd_P0303_engine_start_count,
                  &LEA_obd_P0303_warm_up_cycle_count,0x12f);
      DAT_003f8e9e = DAT_003f8e9e + 1;
    }
  }
  if (((CAL_obd_P0304 & 7) != 0) && ((LEA_obd_P0340_flags & 4) == 0)) {
    if (((misfire_count_prev[2] < 6) ||
        (((LEA_obd_P1301_flags & 1) == 0 || ((obd_P1301_flags_prev & 1) != 0)))) &&
       (((misfire_cat_count_prev[2] < 3 && (misfire_cat_timer[2] != 0)) ||
        (((LEA_obd_P1302_flags & 1) == 0 || ((obd_P1302_flags_prev & 1) != 0)))))) {
      obd_clr_dtc(&CAL_obd_P0304,&LEA_obd_P0304_flags);
    }
    else {
      obd_set_dtc(&CAL_obd_P0304,&LEA_obd_P0304_flags,&LEA_obd_P0304_engine_start_count,
                  &LEA_obd_P0304_warm_up_cycle_count,0x130);
      DAT_003f8e9e = DAT_003f8e9e + 1;
    }
  }
  if ((CAL_obd_P0300 & 7) != 0) {
    if ((DAT_003f8e9e < 2) &&
       (((LEA_obd_P0340_flags & 4) == 0 ||
        (((LEA_obd_P1301_flags & 1) == 0 && ((LEA_obd_P1302_flags & 1) == 0)))))) {
      obd_clr_dtc(&CAL_obd_P0300,&LEA_obd_P0300_flags);
    }
    else {
      obd_set_dtc(&CAL_obd_P0300,&LEA_obd_P0300_flags,&LEA_obd_P0300_engine_start_count,
                  &LEA_obd_P0300_warm_up_cycle_count,300);
    }
  }
  obd_P1301_flags_prev = LEA_obd_P1301_flags;
  obd_P1302_flags_prev = LEA_obd_P1302_flags;
  return;
}



// Initializes misfire monitor state

void obd_init_misfire(void)

{
  DAT_003f8e90 = DAT_003fc490;
  DAT_003f8e91 = DAT_003fc488;
  DAT_003f8e92 = DAT_003fc489;
  DAT_003f8e93 = DAT_003fc48a;
  DAT_003f8e94 = DAT_003fc48b;
  obd_P1301_debounce_count = 1;
  obd_P1302_debounce_count = 1;
  obd_init_dtc(&CAL_obd_P0300,&LEA_obd_P0300_flags,300);
  obd_init_dtc(&CAL_obd_P0301,&LEA_obd_P0301_flags,0x12d);
  obd_init_dtc(&CAL_obd_P0302,&LEA_obd_P0302_flags,0x12e);
  obd_init_dtc(&CAL_obd_P0303,&LEA_obd_P0303_flags,0x12f);
  obd_init_dtc(&CAL_obd_P0304,&LEA_obd_P0304_flags,0x130);
  obd_init_dtc(&CAL_obd_P1301,&LEA_obd_P1301_flags,0x515);
  obd_init_dtc(&CAL_obd_P1302,&LEA_obd_P1302_flags,0x516);
  return;
}



// Misfire monitor cycle counter

void obd_cyc_misfire(void)

{
  obd_cyc_dtc(&CAL_obd_P0300,&LEA_obd_P0300_flags,&LEA_obd_P0300_engine_start_count,
              &LEA_obd_P0300_warm_up_cycle_count,300);
  obd_cyc_dtc(&CAL_obd_P0301,&LEA_obd_P0301_flags,&LEA_obd_P0301_engine_start_count,
              &LEA_obd_P0301_warm_up_cycle_count,0x12d);
  obd_cyc_dtc(&CAL_obd_P0302,&LEA_obd_P0302_flags,&LEA_obd_P0302_engine_start_count,
              &LEA_obd_P0302_warm_up_cycle_count,0x12e);
  obd_cyc_dtc(&CAL_obd_P0303,&LEA_obd_P0303_flags,&LEA_obd_P0303_engine_start_count,
              &LEA_obd_P0303_warm_up_cycle_count,0x12f);
  obd_cyc_dtc(&CAL_obd_P0304,&LEA_obd_P0304_flags,&LEA_obd_P0304_engine_start_count,
              &LEA_obd_P0304_warm_up_cycle_count,0x130);
  obd_cyc_dtc(&CAL_obd_P1301,&LEA_obd_P1301_flags,&LEA_obd_P1301_engine_start_count,
              &LEA_obd_P1301_warm_up_cycle_count,0x515);
  obd_cyc_dtc(&CAL_obd_P1302,&LEA_obd_P1302_flags,&LEA_obd_P1302_engine_start_count,
              &LEA_obd_P1302_warm_up_cycle_count,0x516);
  return;
}



// Misfire monitor task (5ms)

void obd_check_misfire_5ms(void)

{
  uint uVar1;
  
  if (misfire_eval_inhibit_timer != 0) {
    misfire_eval_inhibit_timer = misfire_eval_inhibit_timer - 1;
  }
  if (misfire_eval_speed_transient_timer != 0) {
    misfire_eval_speed_transient_timer = misfire_eval_speed_transient_timer - 1;
  }
  if (misfire_cylinder_cut_timer != 0) {
    misfire_cylinder_cut_timer = misfire_cylinder_cut_timer - 1;
  }
  uVar1 = (0x100 - (uint)DAT_003f81d0) * DAT_003f81d4;
  DAT_003f81d4 = ((int)uVar1 >> 8) + (uint)((int)uVar1 < 0 && (uVar1 & 0xff) != 0) +
                 (uint)DAT_003f81d0 * (uint)load_2;
  DAT_003f8ea0 = (short)(DAT_003f81d4 >> 8) +
                 (ushort)((int)DAT_003f81d4 < 0 && (DAT_003f81d4 & 0xff) != 0);
  return;
}



// O2 sensor activity monitor (P0134/P0140)

void obd_check_o2_activity(void)

{
  if (engine_runtime < CAL_stft_o2_test_runtime_min) {
    o2_flags = o2_flags & 0xff3f;
    closedloop_flags = closedloop_flags & 0xfff5;
    DAT_003f8eb2 = 0;
    DAT_003f8eb4 = 0;
  }
  else {
    if (((idle_flags & 8) != 0) ||
       (((fuel_system_status & 2) == 0 && ((closedloop_flags & 1) != 0)))) {
      o2_flags = o2_flags & 0xff3f;
      DAT_003f8eb2 = 0;
      DAT_003f8eb4 = 0;
    }
    if (DAT_003f8eb2 < DAT_003fc024) {
      if (DAT_003fc030 < engine_runtime) {
        if (sensor_adc_pre_o2 < DAT_003fc02e) {
          o2_flags = o2_flags | 0x80;
        }
        if (DAT_003fc02c < sensor_adc_pre_o2) {
          o2_flags = o2_flags | 0x40;
        }
        if (((o2_flags & 0x80) != 0) && ((o2_flags & 0x40) != 0)) {
          closedloop_flags = closedloop_flags | 2;
        }
      }
    }
    else if ((CAL_obd_P0134 & 7) != 0) {
      if ((closedloop_flags & 2) == 0) {
        if (obd_P0134_debounce_count != 0) {
          obd_P0134_debounce_count = obd_P0134_debounce_count + 255;
          DAT_003f8eb2 = 0;
          o2_flags = o2_flags & 0xff3f;
        }
        if (obd_P0134_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0134,&LEA_obd_P0134_flags,&LEA_obd_P0134_engine_start_count,
                      &LEA_obd_P0134_warm_up_cycle_count,0x86);
        }
      }
      else {
        obd_clr_dtc(&CAL_obd_P0134,&LEA_obd_P0134_flags);
        if (obd_P0134_debounce_count < CAL_obd_P0134_debounce_threshold) {
          obd_P0134_debounce_count = obd_P0134_debounce_count + 1;
        }
      }
    }
    if (DAT_003f8eb4 < DAT_003fc026) {
      if ((closedloop_flags & 4) != 0) {
        closedloop_flags = closedloop_flags | 8;
      }
    }
    else if ((CAL_obd_P0140 & 7) != 0) {
      if ((closedloop_flags & 8) == 0) {
        if (obd_P0140_debounce_count != 0) {
          obd_P0140_debounce_count = obd_P0140_debounce_count + 255;
        }
        if (obd_P0140_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0140,&LEA_obd_P0140_flags,&LEA_obd_P0140_engine_start_count,
                      &LEA_obd_P0140_warm_up_cycle_count,0x8c);
        }
      }
      else {
        obd_clr_dtc(&CAL_obd_P0140,&LEA_obd_P0140_flags);
        if (obd_P0140_debounce_count < CAL_obd_P0140_debounce_threshold) {
          obd_P0140_debounce_count = obd_P0140_debounce_count + 1;
        }
      }
    }
  }
  return;
}



// O2 sensor response time monitor (P0133/P0139)

void obd_check_o2_slow_response(void)

{
  ushort uVar1;
  uint uVar2;
  
  if (DAT_003fd61e != -1) {
    DAT_003fd61e = (short)(engine_runtime / 200);
  }
  if (((((((car_speed_smooth < DAT_003fbf86) || (DAT_003fbf87 <= car_speed_smooth)) ||
         ((int)load_1_smooth <= (int)(uint)DAT_003fbfd2)) ||
        (((int)(uint)DAT_003fbfd4 <= (int)load_1_smooth || (engine_speed_3 <= DAT_003fbfd6)))) ||
       ((DAT_003fbfd7 <= engine_speed_3 ||
        ((engine_runtime <= DAT_003fc028 || (coolant_smooth <= DAT_003fbfc9)))))) ||
      (((closedloop_flags & 1) == 0 ||
       (((((((LEA_obd_P0116_flags & 4) != 0 || ((LEA_obd_P0117_flags & 4) != 0)) ||
           ((LEA_obd_P0118_flags & 4) != 0)) ||
          ((((LEA_obd_P0131_flags & 4) != 0 || ((LEA_obd_P0132_flags & 4) != 0)) ||
           (((LEA_obd_P0134_flags & 4) != 0 ||
            (((LEA_obd_P0135_flags & 4) != 0 || ((LEA_obd_P0101_flags & 4) != 0)))))))) ||
         ((LEA_obd_P0102_flags & 4) != 0)) ||
        ((((LEA_obd_P0103_flags & 4) != 0 || ((LEA_obd_P0335_flags & 4) != 0)) ||
         ((LEA_obd_P0500_flags & 4) != 0)))))))) ||
     ((((fuel_system_status & 2) == 0 || (DAT_003f8eb6 != '\0')) ||
      (((int)(uint)DAT_003f949a <= DAT_003f8eb8 ||
       (((closedloop_flags & 0x400) == 0 && (DAT_003fbf8e == '\0')))))))) {
    uVar1 = o2_flags & 0xfffc;
  }
  else {
    uVar1 = o2_flags | 1;
    if ((o2_flags & 2) != 0) {
      o2_flags = o2_flags & 0xfffd | 1;
      if ((o2_rich2lean_total_time != 0) &&
         (LEA_o2_rich2lean_avg_time =
               (u16_time_5ms)(o2_rich2lean_total_time / o2_rich2lean_switch_count),
         (uint)DAT_002f8236 < (o2_rich2lean_total_time / o2_rich2lean_switch_count & 0xffff))) {
        DAT_002f8236 = LEA_o2_rich2lean_avg_time;
        sort10(&DAT_002f8236);
      }
      if ((o2_lean2rich_total_time != 0) &&
         (LEA_o2_lean2rich_avg_time =
               (u16_time_5ms)(o2_lean2rich_total_time / o2_lean2rich_switch_count),
         (uint)DAT_002f824a < (o2_lean2rich_total_time / o2_lean2rich_switch_count & 0xffff))) {
        DAT_002f824a = LEA_o2_lean2rich_avg_time;
        sort10(&DAT_002f824a);
      }
      if ((DAT_003f8ebc != 0) && (DAT_002f82ae < DAT_003f8ebc)) {
        DAT_002f82ae = DAT_003f8ebc;
        sort10(&DAT_002f82ae);
      }
      if ((LEA_o2_lean2rich_avg_time == 0) || (LEA_o2_rich2lean_avg_time == 0)) {
        LEA_o2_switch_time_ratio = 0;
      }
      else {
        uVar2 = ((uint)LEA_o2_lean2rich_avg_time * 100) / (uint)LEA_o2_rich2lean_avg_time;
        if (uVar2 < 0x100) {
          LEA_o2_switch_time_ratio = (u16_factor_1_100)uVar2;
        }
        else {
          LEA_o2_switch_time_ratio = 255;
        }
        if (DAT_002f825e < LEA_o2_switch_time_ratio) {
          DAT_002f825e = LEA_o2_switch_time_ratio;
          sort10(&DAT_002f825e);
        }
      }
      uVar1 = o2_flags;
      if ((CAL_obd_P0133 & 7) != 0) {
        if ((((CAL_obd_P0133_threshold1_lean2rich < LEA_o2_lean2rich_avg_time) &&
             (CAL_obd_P0133_threshold1_rich2lean < LEA_o2_rich2lean_avg_time)) ||
            ((CAL_obd_P0133_threshold2_lean2rich < LEA_o2_lean2rich_avg_time &&
             (CAL_obd_P0133_threshold2_ratio < LEA_o2_switch_time_ratio)))) ||
           (((CAL_obd_P0133_threshold3_rich2lean < LEA_o2_rich2lean_avg_time &&
             (LEA_o2_switch_time_ratio < CAL_obd_P0133_threshold3_ratio)) ||
            ((o2_flags & 0x100) != 0)))) {
          if (obd_P0133_debounce_count != 0) {
            obd_P0133_debounce_count = obd_P0133_debounce_count + 255;
            cat_diag_pre_o2_timer = DAT_003fbfea;
            o2_flags = o2_flags & 0xfeff;
            o2_lean2rich_total_time = 0;
            o2_rich2lean_total_time = 0;
            o2_lean2rich_switch_count = 0;
            o2_rich2lean_switch_count = 0;
          }
          uVar1 = o2_flags;
          if (obd_P0133_debounce_count == 0) {
            obd_set_dtc(&CAL_obd_P0133,&LEA_obd_P0133_flags,&LEA_obd_P0133_engine_start_count,
                        &LEA_obd_P0133_warm_up_cycle_count,0x85);
            uVar1 = o2_flags;
          }
        }
        else {
          obd_clr_dtc(&CAL_obd_P0133,&LEA_obd_P0133_flags);
          uVar1 = o2_flags;
          if (obd_P0133_debounce_count < CAL_obd_P0133_debounce_threshold) {
            obd_P0133_debounce_count = obd_P0133_debounce_count + 1;
          }
        }
      }
    }
  }
  o2_flags = uVar1;
  if ((((LEA_obd_P0133_flags & 8) != 0) && ((LEA_obd_P0133_flags & 4) == 0)) ||
     (((LEA_obd_P0133_flags & 4) != 0 && ((LEA_obd_P0133_flags & 0x10) != 0)))) {
    LEA_obd_monitors_completeness = LEA_obd_monitors_completeness & 0xdf;
  }
  if (((LEA_obd_P0133_flags & 8) != 0) && ((CAL_obd_P0133 & 8) != 0)) {
    LEA_obd_P0133_flags = LEA_obd_P0133_flags & 0xf7;
    cat_diag_pre_o2_timer = DAT_003fbfea;
    o2_flags = o2_flags & 0xfeff;
    o2_lean2rich_total_time = 0;
    o2_rich2lean_total_time = 0;
    o2_lean2rich_switch_count = 0;
    o2_rich2lean_switch_count = 0;
  }
  if ((((((((CAL_obd_P0139 & 7) == 0) || ((LEA_obd_P0139_flags & 8) != 0)) ||
         ((LEA_obd_P0301_flags & 4) != 0)) ||
        (((LEA_obd_P0302_flags & 4) != 0 || ((LEA_obd_P0303_flags & 4) != 0)))) ||
       ((LEA_obd_P0304_flags & 4) != 0)) ||
      ((((LEA_obd_P1301_flags & 4) != 0 || ((LEA_obd_P1302_flags & 4) != 0)) ||
       (((LEA_obd_P0201_flags & 4) != 0 ||
        ((((LEA_obd_P0202_flags & 4) != 0 || ((LEA_obd_P0203_flags & 4) != 0)) ||
         ((LEA_obd_P0204_flags & 4) != 0)))))))) ||
     ((coolant_smooth <= DAT_003fbfc9 || (engine_runtime <= DAT_003fc028)))) {
    DAT_003fd60a = DAT_003fd60a & 0xfffc;
    DAT_003fd61c = DAT_003fc054;
    DAT_003fd61a = DAT_003fc036;
    uVar1 = DAT_003fd60a;
    if ((closedloop_flags & 4) != 0) {
      if (DAT_003fc032 < sensor_adc_post_o2) {
        DAT_003fd60a = DAT_003fd60a | 0x80;
      }
      uVar1 = DAT_003fd60a;
      if (sensor_adc_post_o2 < DAT_003fc034) {
        uVar1 = DAT_003fd60a | 0x40;
      }
    }
  }
  else {
    uVar1 = DAT_003fd60a | 1;
    if ((DAT_003fd60a & 0x3c) == 0) {
      if ((((DAT_003fd60a & 0x100) != 0) && ((DAT_003fd60a & 0x200) != 0)) &&
         (((DAT_003fd60a & 0x40) != 0 && ((DAT_003fd60a & 0x80) != 0)))) {
        DAT_003fd60a = uVar1;
        obd_clr_dtc(&CAL_obd_P0139,&LEA_obd_P0139_flags);
        if (obd_P0139_debounce_count < CAL_obd_P0139_debounce_threshold) {
          obd_P0139_debounce_count = obd_P0139_debounce_count + 1;
        }
        DAT_003fd61c = DAT_003fc054;
        DAT_003fd61a = DAT_003fc036;
        uVar1 = DAT_003fd60a;
      }
    }
    else if (obd_P0139_debounce_count != 0) {
      obd_P0139_debounce_count = obd_P0139_debounce_count - 1;
      if (obd_P0139_debounce_count < DAT_002f82c2) {
        DAT_002f82c2 = obd_P0139_debounce_count;
      }
      DAT_003fd60a = uVar1;
      if (obd_P0139_debounce_count == 0) {
        obd_set_dtc(&CAL_obd_P0139,&LEA_obd_P0139_flags,&LEA_obd_P0139_engine_start_count,
                    &LEA_obd_P0139_warm_up_cycle_count,0x8b);
      }
      DAT_003fd61c = DAT_003fc054;
      DAT_003fd61a = DAT_003fc036;
      uVar1 = DAT_003fd60a & 0xffc3;
    }
  }
  DAT_003fd60a = uVar1;
  if (((LEA_obd_P0139_flags & 8) != 0) && ((CAL_obd_P0139 & 8) != 0)) {
    LEA_obd_P0139_flags = LEA_obd_P0139_flags & 0xf7;
    DAT_003fd60a = DAT_003fd60a & 0xfc3f;
  }
  return;
}



// O2 response monitor task (5ms)

void obd_check_o2_slow_response_5ms(void)

{
  char unaff_r30;
  byte bVar1;
  
  if ((o2_flags & 1) != 0) {
    if (cat_diag_pre_o2_timer == 0) {
      DAT_003fdce8 = DAT_003fdce8 | 0x10;
      if ((LEA_obd_P0133_flags & 8) == 0) {
        if ((o2_rich2lean_switch_count < DAT_003fbf88) || (o2_lean2rich_switch_count < DAT_003fbf88)
           ) {
          o2_rich2lean_total_time = 0;
          o2_lean2rich_total_time = 0;
          o2_flags = o2_flags | 0x100;
        }
        o2_flags = o2_flags & 0xffc3 | 2;
      }
    }
    else {
      cat_diag_pre_o2_timer = cat_diag_pre_o2_timer - 1;
      if ((LEA_obd_P0133_flags & 8) == 0) {
        if (DAT_002f834e < sensor_adc_pre_o2) {
          DAT_002f834e = sensor_adc_pre_o2;
        }
        else if (sensor_adc_pre_o2 < DAT_002f8350) {
          DAT_002f8350 = sensor_adc_pre_o2;
        }
        if (DAT_003fc02c < sensor_adc_pre_o2) {
          o2_flags = o2_flags & 0xffcb | 8;
        }
        else if (sensor_adc_pre_o2 < DAT_003fc02e) {
          o2_flags = o2_flags & 0xffd3 | 0x10;
        }
        else if ((DAT_003fc02e < sensor_adc_pre_o2) && (sensor_adc_pre_o2 < DAT_003fc02c)) {
          if (((o2_flags & 0x10) == 0) && ((o2_flags & 0x20) == 0)) {
            if (((o2_flags & 8) != 0) || ((o2_flags & 4) != 0)) {
              o2_lean2rich_total_time = o2_lean2rich_total_time + 1;
              if ((o2_lean2rich_switch_count != 255) && ((o2_flags & 8) != 0)) {
                o2_lean2rich_switch_count = o2_lean2rich_switch_count + 1;
              }
              o2_flags = o2_flags & 0xfff7 | 4;
            }
          }
          else {
            o2_rich2lean_total_time = o2_rich2lean_total_time + 1;
            if ((o2_rich2lean_switch_count != 0xff) && ((o2_flags & 0x10) != 0)) {
              o2_rich2lean_switch_count = o2_rich2lean_switch_count + 1;
            }
            o2_flags = o2_flags & 0xffef | 0x20;
          }
        }
        if ((DAT_003fbf88 <= o2_rich2lean_switch_count) &&
           (DAT_003fbf88 <= o2_lean2rich_switch_count)) {
          o2_flags = o2_flags & 0xffc3 | 2;
          DAT_003f8ebc = DAT_003fbfea - cat_diag_pre_o2_timer;
        }
      }
    }
  }
  if (load_use_alphaN == 0) {
    if (DAT_003f8eb6 != '\0') {
      DAT_003f8eb6 = DAT_003f8eb6 + -1;
    }
  }
  else {
    DAT_003f8eb6 = DAT_003f949b;
  }
  if (unaff_r30 == '\0') {
    for (bVar1 = 9; bVar1 != 0; bVar1 = bVar1 - 1) {
      (&DAT_003f81d8)[bVar1] = (&DAT_003f81d8)[bVar1 - 1];
    }
    DAT_003f81d8 = load_1_smooth;
  }
  if (DAT_003f81fc < (int)DAT_003f81d8) {
    DAT_003f8eb8 = DAT_003f81d8 - DAT_003f81fc;
  }
  else {
    DAT_003f8eb8 = DAT_003f81fc - DAT_003f81d8;
  }
  if (DAT_003fc030 < engine_runtime) {
    if (DAT_003f8eb2 < DAT_003fc024) {
      DAT_003f8eb2 = DAT_003f8eb2 + 1;
    }
    if (DAT_003f8eb4 < DAT_003fc026) {
      DAT_003f8eb4 = DAT_003f8eb4 + 1;
    }
  }
  if ((DAT_003fd60a & 1) == 0) {
    DAT_003fd60a = DAT_003fd60a & 0xfffd;
    return;
  }
  if ((DAT_003fd60a & 0x80) == 0) {
    if (DAT_003fc02c < sensor_adc_pre_o2) {
      if (DAT_003fd61c == 0) {
        DAT_003fd60a = DAT_003fd60a | 0x20;
        DAT_003fd61c = DAT_003fc054;
      }
      else {
        DAT_003fd61c = DAT_003fd61c + -1;
        if (DAT_003fc032 < sensor_adc_post_o2) {
          DAT_003fd60a = DAT_003fd60a | 0x80;
        }
      }
    }
    else {
      DAT_003fd61c = DAT_003fc054;
    }
  }
  if ((DAT_003fd60a & 0x40) == 0) {
    if (sensor_adc_pre_o2 < DAT_003fc02e) {
      if (DAT_003fd61a == 0) {
        DAT_003fd60a = DAT_003fd60a | 0x10;
        DAT_003fd61a = DAT_003fc036;
      }
      else {
        DAT_003fd61a = DAT_003fd61a + -1;
        if (sensor_adc_post_o2 < DAT_003fc034) {
          DAT_003fd60a = DAT_003fd60a | 0x40;
        }
      }
    }
    else {
      DAT_003fd61a = DAT_003fc036;
    }
  }
  if ((DAT_003fd60a & 0x200) == 0) {
    if (post_o2_state == 2) {
      if ((sensor_adc_post_o2 < DAT_003fc034) && ((idle_flags & 8) != 0)) {
        DAT_003fd60a = DAT_003fd60a | 2;
        if ((closedloop_flags & 0x20) != 0) {
          post_o2_state = 3;
        }
      }
      else {
        DAT_003fd60a = DAT_003fd60a & 0xfffd;
        post_o2_state = 0;
        DAT_003fd60c = 0;
      }
    }
    else {
      if (post_o2_state < 2) {
        if (post_o2_state == 0) {
          if ((((dfso_flags & 1) != 0) && (sensor_adc_post_o2 < DAT_003fc034)) &&
             (car_speed_smooth != 0)) {
            post_o2_state = 1;
          }
          goto LAB_0004ffd8;
        }
        if (true) {
          if (((idle_flags & 8) == 0) || ((dfso_flags & 1) != 0)) {
            if (((short)(ushort)CAL_idle_flow_pps_max < (short)pps) || (engine_is_running == false))
            {
              post_o2_state = 0;
            }
          }
          else {
            post_o2_state = post_o2_state + 1;
          }
          goto LAB_0004ffd8;
        }
      }
      else if (post_o2_state < 4) {
        if ((((closedloop_flags & 0x20) == 0) || ((idle_flags & 8) == 0)) ||
           (sensor_adc_pre_o2 <= DAT_003fc02c)) {
          DAT_003fd60a = DAT_003fd60a & 0xfffd;
          post_o2_state = 0;
          DAT_003fd60c = 0;
        }
        else {
          if ((DAT_003fc034 < sensor_adc_post_o2) && (sensor_adc_post_o2 < DAT_003fc032)) {
            DAT_003fd60c = DAT_003fd60c + 1;
            if (DAT_003fbfc2 <= DAT_003fd60c) {
              DAT_003fd610 = DAT_003fd610 + DAT_003fbfc2;
              DAT_003fd60a = DAT_003fd60a & 0xfffd;
              DAT_003fd60c = 0;
              post_o2_state = 0;
              DAT_003fd614 = DAT_003fd614 + 1;
            }
            if ((uint)DAT_003fbfc2 * (uint)DAT_003fbfbf <= (uint)DAT_003fd610) {
              DAT_003fd60a = DAT_003fd60a | 8;
              if (DAT_002f821a < DAT_003fd610) {
                DAT_002f821a = DAT_003fd610;
                sort10(&DAT_002f821a);
              }
              DAT_003fd60a = DAT_003fd60a & 0xfffd;
              post_o2_state = 0;
              DAT_003fd60c = 0;
              DAT_003fd614 = 0;
              DAT_003fd610 = 0;
            }
          }
          else if (DAT_003fc032 < sensor_adc_post_o2) {
            DAT_003fd610 = DAT_003fd610 + DAT_003fd60c;
            DAT_003fd614 = DAT_003fd614 + 1;
            DAT_003fd60a = DAT_003fd60a & 0xfffd;
            post_o2_state = 0;
            DAT_003fd60c = 0;
          }
          else if (sensor_adc_post_o2 < DAT_003fc034) {
            DAT_003fd60c = 0;
          }
          if (((DAT_003fd610 < DAT_003fbfc2) && (DAT_003fd614 == 1)) ||
             ((DAT_003fbfbf <= DAT_003fd614 && ((DAT_003fd60a & 8) == 0)))) {
            DAT_003fd60a = DAT_003fd60a | 0x200;
            if (DAT_002f821a < DAT_003fd610) {
              DAT_002f821a = DAT_003fd610;
              sort10(&DAT_002f821a);
            }
            post_o2_state = 0;
            DAT_003fd60c = 0;
            DAT_003fd614 = 0;
            DAT_003fd610 = 0;
          }
        }
        goto LAB_0004ffd8;
      }
      DAT_003fd60a = DAT_003fd60a & 0xfffd;
      post_o2_state = 0;
      DAT_003fd60c = 0;
    }
  }
LAB_0004ffd8:
  if ((DAT_003fd60a & 0x100) == 0) {
    if (DAT_003fd621 == '\x01') {
      if ((dfso_flags & 1) == 0) {
        DAT_003fd60e = 0;
        DAT_003fd621 = '\0';
      }
      else if ((DAT_003fc034 < sensor_adc_post_o2) && (sensor_adc_post_o2 < DAT_003fc032)) {
        DAT_003fd60e = DAT_003fd60e + 1;
        if (DAT_003fbfc4 <= DAT_003fd60e) {
          DAT_003fd612 = DAT_003fd612 + DAT_003fbfc4;
          DAT_003fd60e = 0;
          DAT_003fd621 = '\0';
          DAT_003fd615 = DAT_003fd615 + 1;
        }
        if ((uint)DAT_003fbfc4 * (uint)DAT_003fbfbf <= (uint)DAT_003fd612) {
          DAT_003fd60a = DAT_003fd60a | 4;
          if (DAT_002f8206 < DAT_003fd612) {
            DAT_002f8206 = DAT_003fd612;
            sort10(&DAT_002f8206);
          }
          DAT_003fd621 = '\0';
          DAT_003fd60e = 0;
          DAT_003fd615 = 0;
          DAT_003fd612 = 0;
        }
      }
      else if (DAT_003fc032 < sensor_adc_post_o2) {
        DAT_003fd60e = 0;
      }
      else if (sensor_adc_post_o2 < DAT_003fc034) {
        DAT_003fd612 = DAT_003fd612 + DAT_003fd60e;
        DAT_003fd615 = DAT_003fd615 + 1;
        DAT_003fd621 = '\0';
        DAT_003fd60e = 0;
      }
      if (((DAT_003fd612 < DAT_003fbfc4) && (DAT_003fd615 == 1)) ||
         ((DAT_003fbfbf <= DAT_003fd615 && ((DAT_003fd60a & 4) == 0)))) {
        DAT_003fd60a = DAT_003fd60a | 0x100;
        if (DAT_002f8206 < DAT_003fd612) {
          DAT_002f8206 = DAT_003fd612;
          sort10(&DAT_002f8206);
        }
        DAT_003fd621 = '\0';
        DAT_003fd60e = 0;
        DAT_003fd615 = 0;
        DAT_003fd612 = 0;
      }
    }
    else if ((DAT_003fd621 != '\0') || (false)) {
      DAT_003fd60e = 0;
      DAT_003fd621 = '\0';
    }
    else if ((DAT_003fc032 < sensor_adc_post_o2) && ((dfso_flags & 1) != 0)) {
      DAT_003fd621 = '\x01';
    }
  }
  return;
}



// Initializes O2 response DTCs (P0133/P0134/P0139/P0140)

void obd_init_o2_response(void)

{
  cat_diag_pre_o2_timer = DAT_003fbfea;
  obd_P0133_debounce_count = CAL_obd_P0133_debounce_threshold;
  obd_P0134_debounce_count = CAL_obd_P0134_debounce_threshold;
  obd_P0139_debounce_count = CAL_obd_P0139_debounce_threshold;
  obd_P0140_debounce_count = CAL_obd_P0140_debounce_threshold;
  obd_init_dtc(&CAL_obd_P0133,&LEA_obd_P0133_flags,0x85);
  obd_init_dtc(&CAL_obd_P0134,&LEA_obd_P0134_flags,0x86);
  obd_init_dtc(&CAL_obd_P0139,&LEA_obd_P0139_flags,0x8b);
  obd_init_dtc(&CAL_obd_P0140,&LEA_obd_P0140_flags,0x8c);
  return;
}



// O2 response monitor cycle counter

void obd_cyc_o2_response(void)

{
  obd_cyc_dtc(&CAL_obd_P0133,&LEA_obd_P0133_flags,&LEA_obd_P0133_engine_start_count,
              &LEA_obd_P0133_warm_up_cycle_count,0x85);
  obd_cyc_dtc(&CAL_obd_P0134,&LEA_obd_P0134_flags,&LEA_obd_P0134_engine_start_count,
              &LEA_obd_P0134_warm_up_cycle_count,0x86);
  obd_cyc_dtc(&CAL_obd_P0139,&LEA_obd_P0139_flags,&LEA_obd_P0139_engine_start_count,
              &LEA_obd_P0139_warm_up_cycle_count,0x8b);
  obd_cyc_dtc(&CAL_obd_P0140,&LEA_obd_P0140_flags,&LEA_obd_P0140_engine_start_count,
              &LEA_obd_P0140_warm_up_cycle_count,0x8c);
  return;
}



// Updates OBD trouble code list display

void obd_update_dtc_list(void)

{
  uint uVar1;
  int iVar2;
  
  obd_fault_sample_threshold = (u16_time_100ms)CAL_obd_fault_sample_threshold;
  if (((((((CAL_obd_P0101 & 7) != 0) && (engine_is_running)) && (DAT_003fdb6c != '\0')) &&
       ((DAT_003fdb7c != '\0' && (DAT_003fdb7d != '\0')))) && (DAT_003fdb7e != '\0')) &&
     (DAT_003fbfcf <= engine_speed_3)) {
    if (((DAT_003fbf3f < tps) && ((int)load_1_smooth < (int)(uint)DAT_003fbf42)) ||
       ((tps < DAT_003fbf40 && ((int)(uint)DAT_003fbf44 < (int)load_1_smooth)))) {
      obd_P0101_fault_sample_count = obd_P0101_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0101_fault_sample_count) {
        if (obd_P0101_debounce_count != 0) {
          obd_P0101_debounce_count = obd_P0101_debounce_count + 255;
        }
        if (obd_P0101_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0101,&LEA_obd_P0101_flags,&LEA_obd_P0101_engine_start_count,
                      &LEA_obd_P0101_warm_up_cycle_count,0x65);
        }
        else {
          obd_P0101_fault_sample_count = 0;
        }
      }
    }
    else {
      obd_P0101_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0101,&LEA_obd_P0101_flags);
      if (obd_P0101_debounce_count < CAL_obd_P0101_debounce_threshold) {
        obd_P0101_debounce_count = obd_P0101_debounce_count + 1;
      }
    }
  }
  if (((CAL_obd_P0102 & 7) != 0) && (engine_is_running != false)) {
    if (sensor_adc_maf1 < CAL_obd_P0102_threshold) {
      obd_P0102_fault_sample_count = obd_P0102_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0102_fault_sample_count) {
        obd_P0102_fault_sample_count = 0;
        if (obd_P0102_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0102,&LEA_obd_P0102_flags,&LEA_obd_P0102_engine_start_count,
                      &LEA_obd_P0102_warm_up_cycle_count,0x66);
        }
        else {
          obd_P0102_debounce_count = obd_P0102_debounce_count + 255;
        }
      }
    }
    else {
      obd_P0102_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0102,&LEA_obd_P0102_flags);
      if (obd_P0102_debounce_count < CAL_obd_P0102_debounce_threshold) {
        obd_P0102_debounce_count = obd_P0102_debounce_count + 1;
      }
    }
  }
  if (((CAL_obd_P0103 & 7) != 0) && (engine_is_running != false)) {
    if (CAL_obd_P0103_threshold < sensor_adc_maf1) {
      obd_P0103_fault_sample_count = obd_P0103_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0103_fault_sample_count) {
        obd_P0103_fault_sample_count = 0;
        if (obd_P0103_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0103,&LEA_obd_P0103_flags,&LEA_obd_P0103_engine_start_count,
                      &LEA_obd_P0103_warm_up_cycle_count,0x67);
        }
        else {
          obd_P0103_debounce_count = obd_P0103_debounce_count + 255;
        }
      }
    }
    else {
      obd_P0103_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0103,&LEA_obd_P0103_flags);
      if (obd_P0103_debounce_count < CAL_obd_P0103_debounce_threshold) {
        obd_P0103_debounce_count = obd_P0103_debounce_count + 1;
      }
    }
  }
  if (((((((CAL_obd_P0106 & 7) != 0) && (DAT_003fc039 < engine_speed_3)) &&
        (engine_speed_3 < DAT_003fc03a)) &&
       (((DAT_003fc03b < tps && (obd_P0101_debounce_count != 0)) &&
        ((obd_P0102_debounce_count != 0 &&
         ((obd_P0103_debounce_count != 0 && (DAT_003fdb6c != '\0')))))))) && (DAT_003fdb7c != '\0'))
     && (((DAT_003fdb7d != '\0' && (DAT_003fdb7e != '\0')) && (DAT_003fdb81 != '\0')))) {
    iVar2 = (int)(load_1_smooth * DAT_003fc03c) / 0x21c +
            ((int)(load_1_smooth * DAT_003fc03c) >> 0x1f);
    DAT_003fd658 = (short)iVar2 - (short)(iVar2 >> 0x1f);
    DAT_003f8f1e = atmo_pressure - DAT_003fd658;
    if ((DAT_003fc01c < DAT_003f8f1e) || ((int)DAT_003f8f1e < -(int)DAT_003fc01e)) {
      obd_P0106_fault_sample_count = obd_P0106_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0106_fault_sample_count) {
        if (obd_P0106_debounce_count != 0) {
          obd_P0106_debounce_count = obd_P0106_debounce_count + 255;
        }
        if (obd_P0106_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0106,&LEA_obd_P0106_flags,&LEA_obd_P0106_engine_start_count,
                      &LEA_obd_P0106_warm_up_cycle_count,0x6a);
        }
        else {
          obd_P0106_fault_sample_count = 0;
        }
      }
    }
    else {
      obd_P0106_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0106,&LEA_obd_P0106_flags);
      if (obd_P0106_debounce_count < CAL_obd_P0106_debounce_threshold) {
        obd_P0106_debounce_count = obd_P0106_debounce_count + 1;
      }
    }
  }
  if (((CAL_obd_P0107 & 7) != 0) && (engine_is_running != false)) {
    if (sensor_adc_baro < CAL_obd_P0107_threshold) {
      obd_P0107_fault_sample_count = obd_P0107_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0107_fault_sample_count) {
        obd_P0107_fault_sample_count = 0;
        if (obd_P0107_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0107,&LEA_obd_P0107_flags,&LEA_obd_P0107_engine_start_count,
                      &LEA_obd_P0107_warm_up_cycle_count,0x6b);
        }
        else {
          obd_P0107_debounce_count = obd_P0107_debounce_count + 255;
        }
      }
    }
    else {
      obd_P0107_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0107,&LEA_obd_P0107_flags);
      if (obd_P0107_debounce_count < CAL_obd_P0107_debounce_threshold) {
        obd_P0107_debounce_count = obd_P0107_debounce_count + 1;
      }
    }
  }
  if (((CAL_obd_P0108 & 7) != 0) && (engine_is_running != false)) {
    if (CAL_obd_P0108_threshold < sensor_adc_baro) {
      obd_P0108_fault_sample_count = obd_P0108_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0108_fault_sample_count) {
        obd_P0108_fault_sample_count = 0;
        if (obd_P0108_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0108,&LEA_obd_P0108_flags,&LEA_obd_P0108_engine_start_count,
                      &LEA_obd_P0108_warm_up_cycle_count,0x6c);
        }
        else {
          obd_P0108_debounce_count = obd_P0108_debounce_count + 255;
        }
      }
    }
    else {
      obd_P0108_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0108,&LEA_obd_P0108_flags);
      if (obd_P0108_debounce_count < CAL_obd_P0108_debounce_threshold) {
        obd_P0108_debounce_count = obd_P0108_debounce_count + 1;
      }
    }
  }
  if (((CAL_obd_P0131 & 7) != 0) && (engine_is_running != false)) {
    if ((sensor_adc_pre_o2 < CAL_obd_P0131_threshold) && ((dfso_flags & 2) == 0)) {
      obd_P0131_fault_sample_count = obd_P0131_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0131_fault_sample_count) {
        obd_P0131_fault_sample_count = 0;
        if (obd_P0131_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0131,&LEA_obd_P0131_flags,&LEA_obd_P0131_engine_start_count,
                      &LEA_obd_P0131_warm_up_cycle_count,0x83);
        }
        else {
          obd_P0131_debounce_count = obd_P0131_debounce_count + 255;
        }
      }
    }
    else {
      obd_P0131_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0131,&LEA_obd_P0131_flags);
      if (obd_P0131_debounce_count < CAL_obd_P0131_debounce_threshold) {
        obd_P0131_debounce_count = obd_P0131_debounce_count + 1;
      }
    }
  }
  if (((CAL_obd_P0132 & 7) != 0) && (engine_is_running != false)) {
    if (CAL_obd_P0132_threshold < sensor_adc_pre_o2) {
      obd_P0132_fault_sample_count = obd_P0132_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0132_fault_sample_count) {
        obd_P0132_fault_sample_count = 0;
        if (obd_P0132_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0132,&LEA_obd_P0132_flags,&LEA_obd_P0132_engine_start_count,
                      &LEA_obd_P0132_warm_up_cycle_count,0x84);
        }
        else {
          obd_P0132_debounce_count = obd_P0132_debounce_count + 255;
        }
      }
    }
    else {
      obd_P0132_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0132,&LEA_obd_P0132_flags);
      if (obd_P0132_debounce_count < CAL_obd_P0132_debounce_threshold) {
        obd_P0132_debounce_count = obd_P0132_debounce_count + 1;
      }
    }
  }
  if (((CAL_obd_P0137 & 7) != 0) && (engine_is_running != false)) {
    if ((sensor_adc_post_o2 < CAL_obd_P0137_threshold) && ((dfso_flags & 2) == 0)) {
      obd_P0137_fault_sample_count = obd_P0137_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0137_fault_sample_count) {
        obd_P0137_fault_sample_count = 0;
        if (obd_P0137_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0137,&LEA_obd_P0137_flags,&LEA_obd_P0137_engine_start_count,
                      &LEA_obd_P0137_warm_up_cycle_count,0x89);
        }
        else {
          obd_P0137_debounce_count = obd_P0137_debounce_count + 255;
        }
      }
    }
    else {
      obd_P0137_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0137,&LEA_obd_P0137_flags);
      if (obd_P0137_debounce_count < CAL_obd_P0137_debounce_threshold) {
        obd_P0137_debounce_count = obd_P0137_debounce_count + 1;
      }
    }
  }
  if (((CAL_obd_P0138 & 7) != 0) && (engine_is_running != false)) {
    if (CAL_obd_P0138_threshold < sensor_adc_post_o2) {
      obd_P0138_fault_sample_count = obd_P0138_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0138_fault_sample_count) {
        obd_P0138_fault_sample_count = 0;
        if (obd_P0138_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0138,&LEA_obd_P0138_flags,&LEA_obd_P0138_engine_start_count,
                      &LEA_obd_P0138_warm_up_cycle_count,0x8a);
        }
        else {
          obd_P0138_debounce_count = obd_P0138_debounce_count + 255;
        }
      }
    }
    else {
      obd_P0138_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0138,&LEA_obd_P0138_flags);
      if (obd_P0138_debounce_count < CAL_obd_P0138_debounce_threshold) {
        obd_P0138_debounce_count = obd_P0138_debounce_count + 1;
      }
    }
  }
  if (((CAL_obd_P0111 & 7) != 0) && (engine_is_running != false)) {
    if (((engine_runtime < DAT_003fc040) &&
        ((coolant_smooth < DAT_003fc042 && (DAT_003fc043 < engine_air_smooth)))) ||
       (uVar1 = abs((uint)engine_air - (uint)engine_air_smooth),
       (int)(uint)DAT_003fc03e < (int)uVar1)) {
      obd_P0111_fault_sample_count = obd_P0111_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0111_fault_sample_count) {
        obd_P0111_fault_sample_count = 0;
        if (obd_P0111_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0111,&LEA_obd_P0111_flags,&LEA_obd_P0111_engine_start_count,
                      &LEA_obd_P0111_warm_up_cycle_count,0x6f);
        }
        else {
          obd_P0111_debounce_count = obd_P0111_debounce_count + 255;
        }
      }
    }
    else {
      obd_P0111_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0111,&LEA_obd_P0111_flags);
      if (obd_P0111_debounce_count < CAL_obd_P0111_debounce_threshold) {
        obd_P0111_debounce_count = obd_P0111_debounce_count + 1;
      }
    }
  }
  if (((CAL_obd_P0112 & 7) != 0) && (engine_is_running != false)) {
    if (sensor_adc_engine_air < CAL_obd_P0112_threshold) {
      obd_P0112_fault_sample_count = obd_P0112_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0112_fault_sample_count) {
        obd_P0112_fault_sample_count = 0;
        if (obd_P0112_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0112,&LEA_obd_P0112_flags,&LEA_obd_P0112_engine_start_count,
                      &LEA_obd_P0112_warm_up_cycle_count,0x70);
        }
        else {
          obd_P0112_debounce_count = obd_P0112_debounce_count + 255;
        }
      }
    }
    else {
      obd_P0112_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0112,&LEA_obd_P0112_flags);
      if (obd_P0112_debounce_count < CAL_obd_P0112_debounce_threshold) {
        obd_P0112_debounce_count = obd_P0112_debounce_count + 1;
      }
    }
  }
  if (((CAL_obd_P0113 & 7) != 0) && (engine_is_running != false)) {
    if (CAL_obd_P0113_threshold < sensor_adc_engine_air) {
      obd_P0113_fault_sample_count = obd_P0113_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0113_fault_sample_count) {
        obd_P0113_fault_sample_count = 0;
        if (obd_P0113_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0113,&LEA_obd_P0113_flags,&LEA_obd_P0113_engine_start_count,
                      &LEA_obd_P0113_warm_up_cycle_count,0x71);
        }
        else {
          obd_P0113_debounce_count = obd_P0113_debounce_count + 255;
        }
      }
    }
    else {
      obd_P0113_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0113,&LEA_obd_P0113_flags);
      if (obd_P0113_debounce_count < CAL_obd_P0113_debounce_threshold) {
        obd_P0113_debounce_count = obd_P0113_debounce_count + 1;
      }
    }
  }
  if (((CAL_obd_P0116 & 7) != 0) && (engine_is_running != false)) {
    if ((((uint)CAL_obd_P0116_engine_runtime_min * 200 < engine_runtime) &&
        (coolant_smooth < CAL_obd_P0116_threshold)) ||
       (uVar1 = abs((uint)coolant - (uint)coolant_smooth), (int)(uint)DAT_003fc03f < (int)uVar1)) {
      obd_P0116_fault_sample_count = obd_P0116_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0116_fault_sample_count) {
        obd_P0116_fault_sample_count = 0;
        if (obd_P0116_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0116,&LEA_obd_P0116_flags,&LEA_obd_P0116_engine_start_count,
                      &LEA_obd_P0116_warm_up_cycle_count,0x74);
        }
        else {
          obd_P0116_debounce_count = obd_P0116_debounce_count + 255;
        }
      }
    }
    else {
      obd_P0116_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0116,&LEA_obd_P0116_flags);
      if (obd_P0116_debounce_count < CAL_obd_P0116_debounce_threshold) {
        obd_P0116_debounce_count = obd_P0116_debounce_count + 1;
      }
    }
  }
  if (((CAL_obd_P0117 & 7) != 0) && (engine_is_running != false)) {
    if (sensor_adc_coolant < CAL_obd_P0117_threshold) {
      obd_P0117_fault_sample_count = obd_P0117_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0117_fault_sample_count) {
        obd_P0117_fault_sample_count = 0;
        if (obd_P0117_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0117,&LEA_obd_P0117_flags,&LEA_obd_P0117_engine_start_count,
                      &LEA_obd_P0117_warm_up_cycle_count,0x75);
        }
        else {
          obd_P0117_debounce_count = obd_P0117_debounce_count + 255;
        }
      }
    }
    else {
      obd_P0117_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0117,&LEA_obd_P0117_flags);
      if (obd_P0117_debounce_count < CAL_obd_P0117_debounce_threshold) {
        obd_P0117_debounce_count = obd_P0117_debounce_count + 1;
      }
    }
  }
  if (((CAL_obd_P0118 & 7) != 0) && (engine_is_running != false)) {
    if (CAL_obd_P0118_threshold < sensor_adc_coolant) {
      obd_P0118_fault_sample_count = obd_P0118_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0118_fault_sample_count) {
        obd_P0118_fault_sample_count = 0;
        if (obd_P0118_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0118,&LEA_obd_P0118_flags,&LEA_obd_P0118_engine_start_count,
                      &LEA_obd_P0118_warm_up_cycle_count,0x76);
        }
        else {
          obd_P0118_debounce_count = obd_P0118_debounce_count + 255;
        }
      }
    }
    else {
      obd_P0118_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0118,&LEA_obd_P0118_flags);
      if (obd_P0118_debounce_count < CAL_obd_P0118_debounce_threshold) {
        obd_P0118_debounce_count = obd_P0118_debounce_count + 1;
      }
    }
  }
  if (((CAL_obd_P0237 & 7) != 0) && (engine_is_running != false)) {
    if (sensor_adc_map < CAL_obd_P0237_threshold) {
      obd_P0237_fault_sample_count = obd_P0237_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0237_fault_sample_count) {
        obd_P0237_fault_sample_count = 0;
        if (obd_P0237_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0237,&LEA_obd_P0237_flags,&LEA_obd_P0237_engine_start_count,
                      &LEA_obd_P0237_warm_up_cycle_count,0xed);
        }
        else {
          obd_P0237_debounce_count = obd_P0237_debounce_count + 255;
        }
      }
    }
    else {
      obd_P0237_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0237,&LEA_obd_P0237_flags);
      if (obd_P0237_debounce_count < CAL_obd_P0237_debounce_threshold) {
        obd_P0237_debounce_count = obd_P0237_debounce_count + 1;
      }
    }
  }
  if (((CAL_obd_P0238 & 7) != 0) && (engine_is_running != false)) {
    if (CAL_obd_P0238_threshold < sensor_adc_map) {
      obd_P0238_fault_sample_count = obd_P0238_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0238_fault_sample_count) {
        obd_P0238_fault_sample_count = 0;
        if (obd_P0238_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0238,&LEA_obd_P0238_flags,&LEA_obd_P0238_engine_start_count,
                      &LEA_obd_P0238_warm_up_cycle_count,0xee);
        }
        else {
          obd_P0238_debounce_count = obd_P0238_debounce_count + 255;
        }
      }
    }
    else {
      obd_P0238_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0238,&LEA_obd_P0238_flags);
      if (obd_P0238_debounce_count < CAL_obd_P0238_debounce_threshold) {
        obd_P0238_debounce_count = obd_P0238_debounce_count + 1;
      }
    }
  }
  if (((CAL_obd_P0452 & 7) != 0) && (engine_is_running != false)) {
    if (sensor_adc_evap < CAL_obd_P0452_threshold) {
      obd_P0452_fault_sample_count = obd_P0452_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0452_fault_sample_count) {
        obd_P0452_fault_sample_count = 0;
        if (obd_P0452_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0452,&LEA_obd_P0452_flags,&LEA_obd_P0452_engine_start_count,
                      &LEA_obd_P0452_warm_up_cycle_count,0x1c4);
        }
        else {
          obd_P0452_debounce_count = obd_P0452_debounce_count + 255;
        }
      }
    }
    else {
      obd_P0452_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0452,&LEA_obd_P0452_flags);
      if (obd_P0452_debounce_count < CAL_obd_P0452_debounce_threshold) {
        obd_P0452_debounce_count = obd_P0452_debounce_count + 1;
      }
    }
  }
  if (((CAL_obd_P0453 & 7) != 0) && (engine_is_running != false)) {
    if (CAL_obd_P0453_threshold < sensor_adc_evap) {
      obd_P0453_fault_sample_count = obd_P0453_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0453_fault_sample_count) {
        obd_P0453_fault_sample_count = 0;
        if (obd_P0453_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0453,&LEA_obd_P0453_flags,&LEA_obd_P0453_engine_start_count,
                      &LEA_obd_P0453_warm_up_cycle_count,0x1c5);
        }
        else {
          obd_P0453_debounce_count = obd_P0453_debounce_count + 255;
        }
      }
    }
    else {
      obd_P0453_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0453,&LEA_obd_P0453_flags);
      if (obd_P0453_debounce_count < CAL_obd_P0453_debounce_threshold) {
        obd_P0453_debounce_count = obd_P0453_debounce_count + 1;
      }
    }
  }
  if (((CAL_obd_P0327 & 7) != 0) && (engine_is_running != false)) {
    if (sensor_adc_knock < DAT_003fc086) {
      obd_P0327_fault_sample_count = obd_P0327_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0327_fault_sample_count) {
        obd_P0327_fault_sample_count = 0;
        if (obd_P0327_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0327,&LEA_obd_P0327_flags,&LEA_obd_P0327_engine_start_count,
                      &LEA_obd_P0327_warm_up_cycle_count,0x147);
        }
        else {
          obd_P0327_debounce_count = obd_P0327_debounce_count + 255;
        }
      }
    }
    else {
      obd_P0327_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0327,&LEA_obd_P0327_flags);
      if (obd_P0327_debounce_count < CAL_obd_P0327_debounce_threshold) {
        obd_P0327_debounce_count = obd_P0327_debounce_count + 1;
      }
    }
  }
  if (((CAL_obd_P0328 & 7) != 0) && (engine_is_running != false)) {
    if (DAT_003fc084 < sensor_adc_knock) {
      obd_P0328_fault_sample_count = obd_P0328_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0328_fault_sample_count) {
        obd_P0328_fault_sample_count = 0;
        if (obd_P0328_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0328,&LEA_obd_P0328_flags,&LEA_obd_P0328_engine_start_count,
                      &LEA_obd_P0328_warm_up_cycle_count,0x148);
        }
        else {
          obd_P0328_debounce_count = obd_P0328_debounce_count + 255;
        }
      }
    }
    else {
      obd_P0328_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0328,&LEA_obd_P0328_flags);
      if (obd_P0328_debounce_count < CAL_obd_P0328_debounce_threshold) {
        obd_P0328_debounce_count = obd_P0328_debounce_count + 1;
      }
    }
  }
  if (((CAL_obd_P0462 & 7) != 0) && (engine_is_running != false)) {
    if (sensor_adc_fuel_level < CAL_obd_P0462_threshold) {
      obd_P0462_fault_sample_count = obd_P0462_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0462_fault_sample_count) {
        obd_P0462_fault_sample_count = 0;
        if (obd_P0462_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0462,&LEA_obd_P0462_flags,&LEA_obd_P0462_engine_start_count,
                      &LEA_obd_P0462_warm_up_cycle_count,0x1ce);
        }
        else {
          obd_P0462_debounce_count = obd_P0462_debounce_count + 255;
        }
      }
    }
    else {
      obd_P0462_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0462,&LEA_obd_P0462_flags);
      if (obd_P0462_debounce_count < CAL_obd_P0462_debounce_threshold) {
        obd_P0462_debounce_count = obd_P0462_debounce_count + 1;
      }
    }
  }
  if (((CAL_obd_P0463 & 7) != 0) && (engine_is_running != false)) {
    if (CAL_obd_P0463_threshold < sensor_adc_fuel_level) {
      obd_P0463_fault_sample_count = obd_P0463_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0463_fault_sample_count) {
        obd_P0463_fault_sample_count = 0;
        if (obd_P0463_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0463,&LEA_obd_P0463_flags,&LEA_obd_P0463_engine_start_count,
                      &LEA_obd_P0463_warm_up_cycle_count,0x1cf);
        }
        else {
          obd_P0463_debounce_count = obd_P0463_debounce_count + 255;
        }
      }
    }
    else {
      obd_P0463_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0463,&LEA_obd_P0463_flags);
      if (obd_P0463_debounce_count < CAL_obd_P0463_debounce_threshold) {
        obd_P0463_debounce_count = obd_P0463_debounce_count + 1;
      }
    }
  }
  if ((((CAL_obd_P0562 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if ((sensor_adc_ecu_voltage < CAL_obd_P0562_threshold) && ((shutdown_flags & 1) != 0)) {
      obd_P0562_fault_sample_count = obd_P0562_fault_sample_count + 1;
      if ((short)(ushort)CAL_obd_P0562_fault_sample_threshold <= (short)obd_P0562_fault_sample_count
         ) {
        obd_P0562_fault_sample_count = 0;
        if (obd_P0562_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0562,&LEA_obd_P0562_flags,&LEA_obd_P0562_engine_start_count,
                      &LEA_obd_P0562_warm_up_cycle_count,0x232);
        }
        else {
          obd_P0562_debounce_count = obd_P0562_debounce_count + 255;
        }
      }
    }
    else {
      obd_P0562_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0562,&LEA_obd_P0562_flags);
      if (obd_P0562_debounce_count < CAL_obd_P0562_debounce_threshold) {
        obd_P0562_debounce_count = obd_P0562_debounce_count + 1;
      }
    }
  }
  if ((((CAL_obd_P0563 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if (CAL_obd_P0563_threshold < sensor_adc_ecu_voltage) {
      obd_P0563_fault_sample_count = obd_P0563_fault_sample_count + 1;
      if ((short)(ushort)CAL_obd_P0563_fault_sample_threshold <= (short)obd_P0563_fault_sample_count
         ) {
        obd_P0563_fault_sample_count = 0;
        if (obd_P0563_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0563,&LEA_obd_P0563_flags,&LEA_obd_P0563_engine_start_count,
                      &LEA_obd_P0563_warm_up_cycle_count,0x233);
        }
        else {
          obd_P0563_debounce_count = obd_P0563_debounce_count + 255;
        }
      }
    }
    else {
      obd_P0563_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0563,&LEA_obd_P0563_flags);
      if (obd_P0563_debounce_count < CAL_obd_P0563_debounce_threshold) {
        obd_P0563_debounce_count = obd_P0563_debounce_count + 1;
      }
    }
  }
  if (((obd_P0101_debounce_count == 0) || (obd_P0102_debounce_count == 0)) ||
     (obd_P0103_debounce_count == 0)) {
    sensor_fault_flags = sensor_fault_flags | 0x10;
    flags_to_hc08 = flags_to_hc08 | 0x20;
  }
  else {
    sensor_fault_flags = sensor_fault_flags & 0xffef;
  }
  if (((obd_P0112_debounce_count == 0) || (obd_P0113_debounce_count == 0)) ||
     (obd_P0111_debounce_count == 0)) {
    sensor_fault_flags = sensor_fault_flags | 1;
  }
  else {
    sensor_fault_flags = sensor_fault_flags & 0xfffe;
  }
  if (((obd_P0117_debounce_count == 0) || (obd_P0118_debounce_count == 0)) ||
     (obd_P0116_debounce_count == 0)) {
    sensor_fault_flags = sensor_fault_flags | 2;
  }
  else {
    sensor_fault_flags = sensor_fault_flags & 0xfffd;
  }
  if (((obd_P0106_debounce_count == 0) || (obd_P0107_debounce_count == 0)) ||
     (obd_P0108_debounce_count == 0)) {
    sensor_fault_flags = sensor_fault_flags | 8;
  }
  else {
    sensor_fault_flags = sensor_fault_flags & 0xfff7;
  }
  if (((obd_P0131_debounce_count == 0) || (obd_P0132_debounce_count == 0)) ||
     (obd_P0133_debounce_count == 0)) {
    sensor_fault_flags = sensor_fault_flags | 0x800;
  }
  else {
    sensor_fault_flags = sensor_fault_flags & 0xf7ff;
  }
  if (obd_P0500_debounce_count == 0) {
    sensor_fault_flags = sensor_fault_flags | 0x200;
  }
  else {
    sensor_fault_flags = sensor_fault_flags & 0xfdff;
  }
  if ((obd_P0506_debounce_count == 0) || (obd_P0507_debounce_count == 0)) {
    sensor_fault_flags = sensor_fault_flags | 0x400;
  }
  else {
    sensor_fault_flags = sensor_fault_flags & 0xfbff;
  }
  if ((obd_P0327_debounce_count == 0) || (obd_P0328_debounce_count == 0)) {
    sensor_fault_flags = sensor_fault_flags | 0x100;
  }
  else {
    sensor_fault_flags = sensor_fault_flags & 0xfeff;
  }
  return;
}



// Initializes sensor range DTCs

void obd_init_sensors(void)

{
  obd_P0101_debounce_count = CAL_obd_P0101_debounce_threshold;
  obd_P0102_debounce_count = CAL_obd_P0102_debounce_threshold;
  obd_P0103_debounce_count = CAL_obd_P0103_debounce_threshold;
  obd_P0106_debounce_count = CAL_obd_P0106_debounce_threshold;
  obd_P0107_debounce_count = CAL_obd_P0107_debounce_threshold;
  obd_P0108_debounce_count = CAL_obd_P0108_debounce_threshold;
  obd_P0111_debounce_count = CAL_obd_P0111_debounce_threshold;
  obd_P0112_debounce_count = CAL_obd_P0112_debounce_threshold;
  obd_P0113_debounce_count = CAL_obd_P0113_debounce_threshold;
  obd_P0116_debounce_count = CAL_obd_P0116_debounce_threshold;
  obd_P0117_debounce_count = CAL_obd_P0117_debounce_threshold;
  obd_P0118_debounce_count = CAL_obd_P0118_debounce_threshold;
  obd_P0131_debounce_count = CAL_obd_P0131_debounce_threshold;
  obd_P0132_debounce_count = CAL_obd_P0132_debounce_threshold;
  obd_P0137_debounce_count = CAL_obd_P0137_debounce_threshold;
  obd_P0138_debounce_count = CAL_obd_P0138_debounce_threshold;
  obd_P0237_debounce_count = CAL_obd_P0237_debounce_threshold;
  obd_P0238_debounce_count = CAL_obd_P0238_debounce_threshold;
  obd_P0327_debounce_count = CAL_obd_P0327_debounce_threshold;
  obd_P0328_debounce_count = CAL_obd_P0328_debounce_threshold;
  obd_P0563_debounce_count = CAL_obd_P0563_debounce_threshold;
  obd_P0562_debounce_count = CAL_obd_P0562_debounce_threshold;
  obd_P0453_debounce_count = CAL_obd_P0453_debounce_threshold;
  obd_P0452_debounce_count = CAL_obd_P0452_debounce_threshold;
  obd_P0463_debounce_count = CAL_obd_P0463_debounce_threshold;
  obd_P0462_debounce_count = CAL_obd_P0462_debounce_threshold;
  obd_init_dtc(&CAL_obd_P0563,&LEA_obd_P0563_flags,0x233);
  obd_init_dtc(&CAL_obd_P0562,&LEA_obd_P0562_flags,0x232);
  obd_init_dtc(&CAL_obd_P0463,&LEA_obd_P0463_flags,0x1cf);
  obd_init_dtc(&CAL_obd_P0462,&LEA_obd_P0462_flags,0x1ce);
  obd_init_dtc(&CAL_obd_P0453,&LEA_obd_P0453_flags,0x1c5);
  obd_init_dtc(&CAL_obd_P0452,&LEA_obd_P0452_flags,0x1c4);
  obd_init_dtc(&CAL_obd_P0101,&LEA_obd_P0101_flags,0x65);
  obd_init_dtc(&CAL_obd_P0102,&LEA_obd_P0102_flags,0x66);
  obd_init_dtc(&CAL_obd_P0103,&LEA_obd_P0103_flags,0x67);
  obd_init_dtc(&CAL_obd_P0118,&LEA_obd_P0118_flags,0x76);
  obd_init_dtc(&CAL_obd_P0117,&LEA_obd_P0117_flags,0x75);
  obd_init_dtc(&CAL_obd_P0116,&LEA_obd_P0116_flags,0x74);
  obd_init_dtc(&CAL_obd_P0113,&LEA_obd_P0113_flags,0x71);
  obd_init_dtc(&CAL_obd_P0112,&LEA_obd_P0112_flags,0x70);
  obd_init_dtc(&CAL_obd_P0111,&LEA_obd_P0111_flags,0x6f);
  obd_init_dtc(&CAL_obd_P0138,&LEA_obd_P0138_flags,0x8a);
  obd_init_dtc(&CAL_obd_P0137,&LEA_obd_P0137_flags,0x89);
  obd_init_dtc(&CAL_obd_P0238,&LEA_obd_P0238_flags,0xee);
  obd_init_dtc(&CAL_obd_P0237,&LEA_obd_P0237_flags,0xed);
  obd_init_dtc(&CAL_obd_P0132,&LEA_obd_P0132_flags,0x84);
  obd_init_dtc(&CAL_obd_P0131,&LEA_obd_P0131_flags,0x83);
  obd_init_dtc(&CAL_obd_P0106,&LEA_obd_P0106_flags,0x6a);
  obd_init_dtc(&CAL_obd_P0108,&LEA_obd_P0108_flags,0x6c);
  obd_init_dtc(&CAL_obd_P0107,&LEA_obd_P0107_flags,0x6b);
  obd_init_dtc(&CAL_obd_P0328,&LEA_obd_P0328_flags,0x148);
  obd_init_dtc(&CAL_obd_P0327,&LEA_obd_P0327_flags,0x147);
  return;
}



// Sensor monitor cycle counter

void obd_cyc_sensors(void)

{
  obd_cyc_dtc(&CAL_obd_P0563,&LEA_obd_P0563_flags,&LEA_obd_P0563_engine_start_count,
              &LEA_obd_P0563_warm_up_cycle_count,0x233);
  obd_cyc_dtc(&CAL_obd_P0562,&LEA_obd_P0562_flags,&LEA_obd_P0562_engine_start_count,
              &LEA_obd_P0562_warm_up_cycle_count,0x232);
  obd_cyc_dtc(&CAL_obd_P0453,&LEA_obd_P0453_flags,&LEA_obd_P0453_engine_start_count,
              &LEA_obd_P0453_warm_up_cycle_count,0x1c5);
  obd_cyc_dtc(&CAL_obd_P0452,&LEA_obd_P0452_flags,&LEA_obd_P0452_engine_start_count,
              &LEA_obd_P0452_warm_up_cycle_count,0x1c4);
  obd_cyc_dtc(&CAL_obd_P0463,&LEA_obd_P0463_flags,&LEA_obd_P0463_engine_start_count,
              &LEA_obd_P0463_warm_up_cycle_count,0x1cf);
  obd_cyc_dtc(&CAL_obd_P0462,&LEA_obd_P0462_flags,&LEA_obd_P0462_engine_start_count,
              &LEA_obd_P0462_warm_up_cycle_count,0x1ce);
  obd_cyc_dtc(&CAL_obd_P0101,&LEA_obd_P0101_flags,&LEA_obd_P0101_engine_start_count,
              &LEA_obd_P0101_warm_up_cycle_count,0x65);
  obd_cyc_dtc(&CAL_obd_P0102,&LEA_obd_P0102_flags,&LEA_obd_P0102_engine_start_count,
              &LEA_obd_P0102_warm_up_cycle_count,0x66);
  obd_cyc_dtc(&CAL_obd_P0103,&LEA_obd_P0103_flags,&LEA_obd_P0103_engine_start_count,
              &LEA_obd_P0103_warm_up_cycle_count,0x67);
  obd_cyc_dtc(&CAL_obd_P0118,&LEA_obd_P0118_flags,&LEA_obd_P0118_engine_start_count,
              &LEA_obd_P0118_warm_up_cycle_count,0x76);
  obd_cyc_dtc(&CAL_obd_P0117,&LEA_obd_P0117_flags,&LEA_obd_P0117_engine_start_count,
              &LEA_obd_P0117_warm_up_cycle_count,0x75);
  obd_cyc_dtc(&CAL_obd_P0116,&LEA_obd_P0116_flags,&LEA_obd_P0116_engine_start_count,
              &LEA_obd_P0116_warm_up_cycle_count,0x74);
  obd_cyc_dtc(&CAL_obd_P0113,&LEA_obd_P0113_flags,&LEA_obd_P0113_engine_start_count,
              &LEA_obd_P0113_warm_up_cycle_count,0x71);
  obd_cyc_dtc(&CAL_obd_P0112,&LEA_obd_P0112_flags,&LEA_obd_P0112_engine_start_count,
              &LEA_obd_P0112_warm_up_cycle_count,0x70);
  obd_cyc_dtc(&CAL_obd_P0111,&LEA_obd_P0111_flags,&LEA_obd_P0111_engine_start_count,
              &LEA_obd_P0111_warm_up_cycle_count,0x6f);
  obd_cyc_dtc(&CAL_obd_P0138,&LEA_obd_P0138_flags,&LEA_obd_P0138_engine_start_count,
              &LEA_obd_P0138_warm_up_cycle_count,0x8a);
  obd_cyc_dtc(&CAL_obd_P0137,&LEA_obd_P0137_flags,&LEA_obd_P0137_engine_start_count,
              &LEA_obd_P0137_warm_up_cycle_count,0x89);
  obd_cyc_dtc(&CAL_obd_P0238,&LEA_obd_P0238_flags,&LEA_obd_P0238_engine_start_count,
              &LEA_obd_P0238_warm_up_cycle_count,0xee);
  obd_cyc_dtc(&CAL_obd_P0237,&LEA_obd_P0237_flags,&LEA_obd_P0237_engine_start_count,
              &LEA_obd_P0237_warm_up_cycle_count,0xed);
  obd_cyc_dtc(&CAL_obd_P0328,&LEA_obd_P0328_flags,&LEA_obd_P0328_engine_start_count,
              &LEA_obd_P0328_warm_up_cycle_count,0x148);
  obd_cyc_dtc(&CAL_obd_P0327,&LEA_obd_P0327_flags,&LEA_obd_P0327_engine_start_count,
              &LEA_obd_P0327_warm_up_cycle_count,0x147);
  obd_cyc_dtc(&CAL_obd_P0132,&LEA_obd_P0132_flags,&LEA_obd_P0132_engine_start_count,
              &LEA_obd_P0132_warm_up_cycle_count,0x84);
  obd_cyc_dtc(&CAL_obd_P0131,&LEA_obd_P0131_flags,&LEA_obd_P0131_engine_start_count,
              &LEA_obd_P0131_warm_up_cycle_count,0x83);
  obd_cyc_dtc(&CAL_obd_P0106,&LEA_obd_P0106_flags,&LEA_obd_P0106_engine_start_count,
              &LEA_obd_P0106_warm_up_cycle_count,0x6a);
  obd_cyc_dtc(&CAL_obd_P0108,&LEA_obd_P0108_flags,&LEA_obd_P0108_engine_start_count,
              &LEA_obd_P0108_warm_up_cycle_count,0x6c);
  obd_cyc_dtc(&CAL_obd_P0107,&LEA_obd_P0107_flags,&LEA_obd_P0107_engine_start_count,
              &LEA_obd_P0107_warm_up_cycle_count,0x6b);
  return;
}



// Thermostat monitor (P0128)

void obd_check_thermostat(void)

{
  if ((idle_flags & 8) == 0) {
    DAT_003fd66c = lookup_2D_uint8_interpolated
                             (8,load_2,CAL_obd_P0128_air_mass_factor,
                              CAL_obd_P0128_air_mass_factor_X_engine_load);
  }
  else {
    DAT_003fd66c = 255;
  }
  if ((((((CAL_obd_P0128 & 7) != 0) && (obd_P0117_debounce_count != 0)) &&
       (obd_P0118_debounce_count != 0)) &&
      ((obd_P0116_debounce_count != 0 && (DAT_003fc083 < coolant_stop)))) &&
     ((LEA_obd_P0128_flags & 8) == 0)) {
    if (((uint)DAT_003fd65c < DAT_003fd668 >> 0x10) && (coolant_smooth < CAL_obd_P0128_threshold)) {
      if (obd_P0128_debounce_count == 0) {
        obd_set_dtc(&CAL_obd_P0128,&LEA_obd_P0128_flags,&LEA_obd_P0128_engine_start_count,
                    &LEA_obd_P0128_warm_up_cycle_count,0x80);
      }
      else {
        obd_P0128_debounce_count = obd_P0128_debounce_count + 255;
      }
    }
    else if ((CAL_obd_P0128_threshold < coolant_smooth) &&
            (obd_clr_dtc(&CAL_obd_P0128,&LEA_obd_P0128_flags),
            obd_P0128_debounce_count < CAL_obd_P0128_debounce_threshold)) {
      obd_P0128_debounce_count = obd_P0128_debounce_count + 1;
    }
  }
  return;
}



// Initializes thermostat monitor state

void obd_init_thermostat(void)

{
  obd_P0128_debounce_count = CAL_obd_P0128_debounce_threshold;
  obd_init_dtc(&CAL_obd_P0128,&LEA_obd_P0128_flags,0x80);
  return;
}



// Thermostat monitor cycle counter

void obd_cyc_thermostat(void)

{
  obd_cyc_dtc(&CAL_obd_P0128,&LEA_obd_P0128_flags,&LEA_obd_P0128_engine_start_count,
              &LEA_obd_P0128_warm_up_cycle_count,0x80);
  return;
}



// Fuel tank/EVAP pressure monitors (P0451-P0453/P0462/P0463)

void obd_check_fuel_evap_press(void)

{
  byte bVar1;
  uint uVar2;
  
  fuel_level_smooth = smooth_fuel_level(fuel_level);
  uVar2 = abs((uint)fuel_level - (uint)fuel_level_smooth);
  DAT_003f8f3c = (byte)uVar2;
  evap_pressure_smooth = smooth_evap_pressure((int)evap_pressure);
  uVar2 = abs((int)evap_pressure - (int)evap_pressure_smooth);
  DAT_003f8f3e = (short)uVar2;
  if ((((car_speed_smooth == 0) && ((idle_flags & 8) != 0)) && ((DAT_003fd580 & 0x10) != 0)) &&
     ((DAT_003fd676 & 2) == 0)) {
    if (DAT_003fd677 == '\0') {
      if ((DAT_003fd676 & 0x20) == 0) {
        DAT_003fd676 = DAT_003fd676 | 0x20;
        DAT_003f8f2a = fuel_level_smooth;
        DAT_003f8f2e = 0;
      }
      else if (DAT_003f8f2e < DAT_003fc09c) {
        DAT_003f8f2e = DAT_003f8f2e + 1;
        if (DAT_003fc0a1 < DAT_003f8f3c) {
          DAT_003fd678 = DAT_003fd678 + 1;
        }
        if (DAT_003fc0a2 < DAT_003f8f3e) {
          DAT_003fd679 = DAT_003fd679 + 1;
        }
      }
      else {
        if (DAT_003f8f2a <= fuel_level_smooth) {
          DAT_003f8f2c = (ushort)fuel_level_smooth - (ushort)DAT_003f8f2a;
        }
        if (DAT_003f8f2c < (short)(ushort)DAT_003fc09e) {
          DAT_003fd676 = DAT_003fd676 | 2;
        }
        else {
          DAT_003fd676 = DAT_003fd676 & 0xdf;
          DAT_003fd679 = 0;
          DAT_003f8f2c = 0;
          DAT_003fd678 = 0;
        }
      }
    }
    else {
      DAT_003fd677 = DAT_003fd677 + -1;
    }
  }
  else {
    DAT_003fd677 = DAT_003fc09d;
  }
  if ((car_speed_smooth == 0) || ((DAT_003fd676 & 1) != 0)) {
    if (car_speed_smooth == 0) {
      if (DAT_003f8201 == '\0') {
        DAT_003f8f30 = DAT_003fc0a6;
        DAT_003f8f32 = DAT_003fc0a8;
      }
      else {
        DAT_003f8201 = DAT_003f8201 + -1;
      }
    }
  }
  else {
    DAT_003f8201 = -6;
    if (fuel_level < DAT_003fc0a4) {
      if (DAT_003fc0a5 < fuel_level) {
        DAT_003f8f30 = DAT_003fc0a6;
        DAT_003f8f32 = DAT_003fc0a8;
        if (DAT_003f8f34 == 0) {
          DAT_003f8f36 = fuel_level;
          DAT_003f8f35 = fuel_level;
          DAT_003f8f3a = evap_pressure;
          DAT_003f8f38 = evap_pressure;
        }
        if (DAT_003f8200 != '\0') {
          DAT_003f8200 = DAT_003f8200 + -1;
        }
        if (((uint16_t_003fd2a6 & 1) != 0) && (DAT_003f8200 == '\0')) {
          DAT_003f8f34 = DAT_003f8f34 + 1;
          uint16_t_003fd2a6 = uint16_t_003fd2a6 & 0xfffe;
          DAT_003f8200 = '2';
        }
        if (fuel_level < DAT_003f8f35) {
          DAT_003f8f35 = fuel_level;
        }
        if (DAT_003f8f36 < fuel_level) {
          DAT_003f8f36 = fuel_level;
        }
        if (evap_pressure < DAT_003f8f38) {
          DAT_003f8f38 = evap_pressure;
        }
        if (DAT_003f8f3a < evap_pressure) {
          DAT_003f8f3a = evap_pressure;
        }
        if (DAT_003fc0ac <= DAT_003f8f34) {
          bVar1 = DAT_003fd676 | 1;
          if ((int)((uint)DAT_003f8f36 - (uint)DAT_003f8f35) < (int)(uint)DAT_003fc0ad) {
            bVar1 = DAT_003fd676 | 0x11;
          }
          DAT_003fd676 = bVar1;
          if (((int)DAT_003f8f3a - (int)DAT_003f8f38 < (int)DAT_003fc0ae) &&
             (obd_P0455_debounce_count != 0)) {
            DAT_003fd676 = DAT_003fd676 | 0x40;
          }
        }
      }
      else {
        DAT_003f8f32 = DAT_003fc0a8;
        if ((DAT_003fc0aa < engine_speed_3) && (DAT_003fc0ab < load_2)) {
          if (DAT_003f8f30 == 0) {
            DAT_003fd676 = DAT_003fd676 | 9;
          }
          else {
            DAT_003f8f30 = DAT_003f8f30 + -1;
          }
        }
      }
    }
    else {
      DAT_003f8f30 = DAT_003fc0a6;
      if ((DAT_003fc0aa < engine_speed_3) && (DAT_003fc0ab < load_2)) {
        if (DAT_003f8f32 == 0) {
          DAT_003fd676 = DAT_003fd676 | 5;
        }
        else {
          DAT_003f8f32 = DAT_003f8f32 + -1;
        }
      }
    }
  }
  if ((((DAT_003fd676 & 2) != 0) && ((DAT_003fd676 & 1) != 0)) && (obd_P0500_debounce_count != 0)) {
    if ((CAL_obd_P0461 & 7) != 0) {
      if ((DAT_003fc09f < DAT_003fd678) || ((DAT_003fd676 & 0x1c) != 0)) {
        if (obd_P0461_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0461,&LEA_obd_P0461_flags,&LEA_obd_P0461_engine_start_count,
                      &LEA_obd_P0461_warm_up_cycle_count,0x1cd);
        }
        else {
          obd_P0461_debounce_count = obd_P0461_debounce_count + 255;
        }
      }
      else {
        obd_clr_dtc(&CAL_obd_P0461,&LEA_obd_P0461_flags);
        if (obd_P0461_debounce_count < CAL_obd_P0461_debounce_threshold) {
          obd_P0461_debounce_count = obd_P0461_debounce_count + 1;
        }
      }
    }
    if ((CAL_obd_P0451 & 7) != 0) {
      if ((DAT_003fc0a0 < DAT_003fd679) || ((DAT_003fd676 & 0x40) != 0)) {
        if (obd_P0451_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0451,&LEA_obd_P0451_flags,&LEA_obd_P0451_engine_start_count,
                      &LEA_obd_P0451_warm_up_cycle_count,0x1c3);
        }
        else {
          obd_P0451_debounce_count = obd_P0451_debounce_count + 255;
        }
      }
      else {
        obd_clr_dtc(&CAL_obd_P0451,&LEA_obd_P0451_flags);
        if (obd_P0451_debounce_count < CAL_obd_P0451_debounce_threshold) {
          obd_P0451_debounce_count = obd_P0451_debounce_count + 1;
        }
      }
    }
    DAT_003fd676 = DAT_003fd676 & 0x80;
    DAT_003f8f34 = 0;
    DAT_003fd679 = 0;
    DAT_003fd678 = 0;
    DAT_003f8f2e = 0;
    DAT_003f8f30 = DAT_003fc0a6;
    DAT_003f8f32 = DAT_003fc0a8;
  }
  return;
}



// Initializes fuel/EVAP pressure monitor state

void obd_init_fuel_evap_press(void)

{
  fuel_level_smooth_x = (uint)fuel_level << 8;
  evap_pressure_smooth_x = (int)evap_pressure << 8;
  obd_P0461_debounce_count = CAL_obd_P0461_debounce_threshold;
  obd_P0451_debounce_count = CAL_obd_P0451_debounce_threshold;
  obd_init_dtc(&CAL_obd_P0461,&LEA_obd_P0461_flags,0x1cd);
  obd_init_dtc(&CAL_obd_P0451,&LEA_obd_P0451_flags,0x1c3);
  return;
}



// Fuel/EVAP pressure monitor cycle counter

void obd_cyc_fuel_evap_press(void)

{
  obd_cyc_dtc(&CAL_obd_P0461,&LEA_obd_P0461_flags,&LEA_obd_P0461_engine_start_count,
              &LEA_obd_P0461_warm_up_cycle_count,0x1cd);
  obd_cyc_dtc(&CAL_obd_P0451,&LEA_obd_P0451_flags,&LEA_obd_P0451_engine_start_count,
              &LEA_obd_P0451_warm_up_cycle_count,0x1c3);
  return;
}



// Encodes integer to BCD format for display

int bcd_encode(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = 0;
  iVar1 = 1000;
  do {
    iVar2 = iVar2 * 0x10 + param_1 / iVar1;
    param_1 = param_1 - (param_1 / iVar1) * iVar1;
    iVar1 = iVar1 / 10 + (iVar1 >> 0x1f);
    iVar1 = iVar1 - (iVar1 >> 0x1f);
  } while (iVar1 != 0);
  return iVar2;
}



// Sends K-Line negative response 0x7f

void obd_kline_send_negative_response(void)

{
  builtin_memcpy(obd_resp,"Hk\x10\x7f\x12T",6);
  obd_resp_len = 5;
  obd_resp_i = 0;
  REG_SC1DR = 0x48;
  return;
}



// K-Line mode 0x05 - returns stored O2 sensor test results

void obd_kline_mode_0x05_o2_test_results(undefined1 param_1,char param_2)

{
  if (param_2 == '\x01') {
    switch(param_1) {
    case 0:
      obd_resp[3] = 69;
      obd_resp[4] = 0;
      obd_resp[5] = 1;
      obd_resp[6] = DAT_003f8208;
      obd_resp[7] = DAT_003f8f40;
      obd_resp[8] = DAT_003f8f41;
      obd_resp[9] = DAT_003f8f42;
      obd_resp[10] = DAT_003f8208 + 9 + DAT_003f8f40 + DAT_003f8f41 + DAT_003f8f42;
      obd_resp_len = 10;
      REG_SC1DR = 0x48;
      break;
    case 1:
      obd_resp[3] = 69;
      obd_resp[4] = 1;
      obd_resp[5] = 1;
      obd_resp[6] = (uint8_t)CAL_stft_stoich_max;
      obd_resp[7] = obd_resp[6] + 10;
      obd_resp_len = 7;
      REG_SC1DR = 0x48;
      break;
    case 2:
      obd_resp[3] = 69;
      obd_resp[4] = 2;
      obd_resp[5] = 1;
      obd_resp[6] = (uint8_t)CAL_stft_stoich_min;
      obd_resp[7] = obd_resp[6] + 11;
      obd_resp_len = 7;
      REG_SC1DR = 0x48;
      break;
    case 3:
      obd_resp[3] = 69;
      obd_resp[4] = 3;
      obd_resp[5] = 1;
      obd_resp[6] = (uint8_t)DAT_003fc02e;
      obd_resp[7] = obd_resp[6] + 12;
      obd_resp_len = 7;
      REG_SC1DR = 0x48;
      break;
    case 4:
      obd_resp[3] = 69;
      obd_resp[4] = 4;
      obd_resp[5] = 1;
      obd_resp[6] = (uint8_t)DAT_003fc02c;
      obd_resp[7] = obd_resp[6] + 13;
      obd_resp_len = 7;
      REG_SC1DR = 0x48;
      break;
    case 5:
      obd_resp[3] = 69;
      obd_resp[4] = 5;
      obd_resp[5] = 1;
      obd_resp[6] = (uint8_t)LEA_o2_lean2rich_avg_time;
      obd_resp[7] = 0;
      obd_resp[8] = (uint8_t)CAL_obd_P0133_threshold1_lean2rich;
      obd_resp[9] = obd_resp[6] + 14 + obd_resp[8];
      obd_resp_len = 9;
      REG_SC1DR = 0x48;
      break;
    case 6:
      obd_resp[3] = 69;
      obd_resp[4] = 6;
      obd_resp[5] = 1;
      obd_resp[6] = (uint8_t)LEA_o2_rich2lean_avg_time;
      obd_resp[7] = 0;
      obd_resp[8] = (uint8_t)CAL_obd_P0133_threshold1_rich2lean;
      obd_resp[9] = obd_resp[6] + 15 + obd_resp[8];
      obd_resp_len = 9;
      REG_SC1DR = 0x48;
      break;
    case 7:
      obd_resp[3] = 69;
      obd_resp[4] = 7;
      obd_resp[5] = 1;
      obd_resp[6] = (uint8_t)DAT_002f8350;
      obd_resp[7] = obd_resp[6] + 16;
      obd_resp_len = 7;
      REG_SC1DR = 0x48;
      break;
    case 8:
      obd_resp[3] = 69;
      obd_resp[4] = 8;
      obd_resp[5] = 1;
      obd_resp[6] = (uint8_t)DAT_002f834e;
      obd_resp[7] = obd_resp[6] + 17;
      obd_resp_len = 7;
      REG_SC1DR = 0x48;
      break;
    default:
      obd_resp[3] = 127;
      obd_resp[4] = 18;
      obd_resp[5] = 84;
      obd_resp_len = 5;
      REG_SC1DR = 0x48;
    }
  }
  else {
    obd_resp[3] = 127;
    obd_resp[4] = 18;
    obd_resp[5] = 84;
    obd_resp_len = 5;
    REG_SC1DR = 0x48;
  }
  obd_resp[2] = 16;
  obd_resp[1] = 107;
  obd_resp[0] = 72;
  obd_resp_i = 0;
  return;
}



// OBD Mode 01: Returns current live data PIDs

void obd_mode_0x01_live_data(uint8_t param_1)

{
  uint16_t value;
  int iVar1;
  
  if (false) {
switchD_0005637c_caseD_8:
    builtin_memcpy(obd_resp,"Hk\x10\x7f\x12",5);
    obd_resp[5] = 84;
    obd_resp_len = 5;
    obd_resp_i = 0;
    REG_SC1DR = 0x48;
  }
  else {
    switch(param_1) {
    case '\0':
      builtin_memcpy(obd_resp,"Hk\x10A",5);
      obd_resp[5] = obd_mode_0x01_pids_supported_01_08;
      obd_resp[6] = obd_mode_0x01_pids_supported_09_10;
      obd_resp[7] = obd_mode_0x01_pids_supported_11_18;
      obd_resp[8] = obd_mode_0x01_pids_supported_19_20;
      obd_resp[9] = obd_mode_0x01_pids_supported_01_08 + 4 + obd_mode_0x01_pids_supported_09_10 +
                    obd_mode_0x01_pids_supported_11_18 + obd_mode_0x01_pids_supported_19_20;
      obd_resp_len = 9;
      obd_resp_i = 0;
      REG_SC1DR = 0x48;
      break;
    case '\x01':
      builtin_memcpy(obd_resp,"Hk\x10A\x01",5);
      obd_resp[5] = obd_mil_dtc_count;
      obd_resp[6] = CAL_obd_monitors[0];
      obd_resp[7] = CAL_obd_monitors[1];
      obd_resp[8] = LEA_obd_monitors_completeness;
      obd_resp[9] = obd_mil_dtc_count + 5 + CAL_obd_monitors[0] + CAL_obd_monitors[1] +
                    LEA_obd_monitors_completeness;
      obd_resp_len = 9;
      obd_resp_i = 0;
      REG_SC1DR = 0x48;
      break;
    case '\x02':
      value = bcd_encode((int)(uint)LEA_obd_freeze_dtc >> 3);
      obd_kline_mode_0x01_send_uint16(param_1,value);
      break;
    case '\x03':
      obd_kline_mode_0x01_send_uint16(param_1,fuel_system_status << 8);
      break;
    case '\x04':
      if (engine_speed_1 == 0) {
        obd_kline_mode_0x01_send_uint8(param_1,0);
      }
      else {
        obd_kline_mode_0x01_send_uint8(param_1,load_3);
      }
      break;
    case '\x05':
      obd_kline_mode_0x01_send_uint8(param_1,(uint8_t)((uint)coolant * 0xa0 >> 8));
      break;
    case '\x06':
      obd_kline_mode_0x01_send_uint8(param_1,obd_stft);
      break;
    case '\a':
      obd_kline_mode_0x01_send_uint8(param_1,obd_ltft);
      break;
    default:
      goto switchD_0005637c_caseD_8;
    case '\f':
      obd_kline_mode_0x01_send_uint16(param_1,engine_speed_1);
      break;
    case '\r':
      obd_kline_mode_0x01_send_uint8(param_1,car_speed_smooth);
      break;
    case '\x0e':
      obd_kline_mode_0x01_send_uint8(param_1,(char)((int)ign_adv_final / 2) + 128);
      break;
    case '\x0f':
      obd_kline_mode_0x01_send_uint8(param_1,(uint8_t)((uint)engine_air * 0xa0 >> 8));
      break;
    case '\x10':
      obd_kline_mode_0x01_send_uint16(param_1,maf_flow_1);
      break;
    case '\x11':
      obd_kline_mode_0x01_send_uint8(param_1,(uint8_t)((int)(uint)sensor_adc_tps_1 >> 2));
      break;
    case '\x13':
      obd_kline_mode_0x01_send_uint8(param_1,DAT_003fbfbd);
      break;
    case '\x14':
      if (sensor_adc_pre_o2 < 0x105) {
        DAT_003f8f4a = (uint8_t)(((uint)sensor_adc_pre_o2 * 0xff) / 0x105);
      }
      else {
        DAT_003f8f4a = 255;
      }
      builtin_memcpy(obd_resp,"Hk\x10A\x14",5);
      obd_resp[5] = DAT_003f8f4a;
      obd_resp[6] = obd_stft;
      obd_resp[7] = DAT_003f8f4a + 24 + obd_stft;
      obd_resp_len = 7;
      obd_resp_i = 0;
      REG_SC1DR = 0x48;
      break;
    case '\x15':
      if (sensor_adc_post_o2 < 0x105) {
        DAT_003f8f4a = (uint8_t)(((uint)sensor_adc_post_o2 * 0xff) / 0x105);
      }
      else {
        DAT_003f8f4a = 255;
      }
      builtin_memcpy(obd_resp,"Hk\x10A\x15",5);
      obd_resp[5] = DAT_003f8f4a;
      obd_resp[6] = 255;
      obd_resp[7] = DAT_003f8f4a + 24;
      obd_resp_len = 7;
      obd_resp_i = 0;
      REG_SC1DR = 0x48;
      break;
    case '\x1c':
      obd_kline_mode_0x01_send_uint8(param_1,DAT_003fbfbe);
      break;
    case '\x1f':
      obd_kline_mode_0x01_send_uint16(param_1,(uint16_t)(engine_runtime / 200));
      break;
    case ' ':
      builtin_memcpy(obd_resp,"Hk\x10A ",5);
      obd_resp[5] = obd_mode_0x01_pids_supported_21_28;
      obd_resp[6] = obd_mode_0x01_pids_supported_29_30;
      obd_resp[7] = obd_mode_0x01_pids_supported_31_38;
      obd_resp[8] = obd_mode_0x01_pids_supported_39_40;
      obd_resp[9] = obd_mode_0x01_pids_supported_21_28 + 36 + obd_mode_0x01_pids_supported_29_30 +
                    obd_mode_0x01_pids_supported_31_38 + obd_mode_0x01_pids_supported_39_40;
      obd_resp_len = 9;
      obd_resp_i = 0;
      REG_SC1DR = 0x48;
      break;
    case '!':
      obd_kline_mode_0x01_send_uint16(param_1,(uint16_t)(DAT_003fd3d8 / 10000));
      break;
    case '.':
      obd_kline_mode_0x01_send_uint8(param_1,(uint8_t)evap_purge_command);
      break;
    case '/':
      obd_kline_mode_0x01_send_uint8(param_1,DAT_003fd2ac);
      break;
    case '3':
      iVar1 = (int)atmo_pressure / 10 + ((int)atmo_pressure >> 0x1f);
      obd_kline_mode_0x01_send_uint8(param_1,(char)iVar1 - (char)(iVar1 >> 0x1f));
      break;
    case '@':
      builtin_memcpy(obd_resp,"Hk\x10A@",5);
      obd_resp[5] = obd_mode_0x01_pids_supported_41_48;
      obd_resp[6] = obd_mode_0x01_pids_supported_49_50;
      obd_resp[7] = obd_mode_0x01_pids_supported_51_58;
      obd_resp[8] = obd_mode_0x01_pids_supported_59_60;
      obd_resp[9] = obd_mode_0x01_pids_supported_41_48 + 68 + obd_mode_0x01_pids_supported_49_50 +
                    obd_mode_0x01_pids_supported_51_58 + obd_mode_0x01_pids_supported_59_60;
      obd_resp_len = 9;
      obd_resp_i = 0;
      REG_SC1DR = 0x48;
      break;
    case 'B':
      obd_kline_mode_0x01_send_uint16(param_1,sensor_adc_ecu_voltage * 0x12);
      break;
    case 'C':
      if (engine_speed_1 == 0) {
        obd_kline_mode_0x01_send_uint16(param_1,0);
      }
      else {
        obd_kline_mode_0x01_send_uint16(param_1,(ushort)load_4);
      }
      break;
    case 'E':
      obd_kline_mode_0x01_send_uint8
                (param_1,(uint8_t)((int)((uint)sensor_adc_tps_1 - (uint)tps_1_range_corrected_low)
                                  >> 2));
      break;
    case 'G':
      obd_kline_mode_0x01_send_uint8(param_1,(uint8_t)((int)(uint)sensor_adc_tps_2 >> 2));
      break;
    case 'I':
      obd_kline_mode_0x01_send_uint8(param_1,(uint8_t)((int)(uint)sensor_adc_pps_1 >> 2));
      break;
    case 'J':
      obd_kline_mode_0x01_send_uint8(param_1,(uint8_t)((int)(uint)sensor_adc_pps_2 >> 2));
    }
  }
  return;
}



// K-Line mode 0x01 response - PID plus 1 data byte

void obd_kline_mode_0x01_send_uint8(uint8_t pid,uint8_t value)

{
  builtin_memcpy(obd_resp,"Hk\x10A",4);
  obd_resp[4] = pid;
  obd_resp[5] = value;
  obd_resp[6] = pid + 4 + value;
  obd_resp_len = 6;
  obd_resp_i = 0;
  REG_SC1DR = 0x48;
  return;
}



// K-Line mode 0x01 response - PID plus 2 data bytes

void obd_kline_mode_0x01_send_uint16(uint8_t pid,uint16_t value)

{
  builtin_memcpy(obd_resp,"Hk\x10A",4);
  obd_resp[4] = pid;
  obd_resp._5_2_ = value;
  obd_resp[7] = pid + 4 + (char)(value >> 8) + (char)value;
  obd_resp_len = 7;
  obd_resp_i = 0;
  REG_SC1DR = 0x48;
  return;
}



// OBD Mode 02: Returns freeze frame data

void obd_mode_0x02_freeze_frame(uint param_1,undefined4 param_2)

{
  uint16_t uVar1;
  uint8_t uVar2;
  uint8_t uVar3;
  
  if (false) {
switchD_00057714_caseD_1:
    builtin_memcpy(obd_resp,"Hk\x10\x7f\x12",5);
    obd_resp_len = 5;
    obd_resp_i = 0;
    REG_SC1DR = 0x48;
    obd_resp[5] = 84;
  }
  else {
    uVar3 = (uint8_t)param_1;
    uVar2 = (uint8_t)param_2;
    switch(param_1 & 0xff) {
    case 0:
      builtin_memcpy(obd_resp,"Hk\x10B",4);
      obd_resp[6] = obd_mode_0x02_pids_supported_01_08;
      obd_resp[7] = obd_mode_0x02_pids_supported_09_10;
      obd_resp[8] = obd_mode_0x02_pids_supported_11_18;
      obd_resp[9] = obd_mode_0x02_pids_supported_19_20;
      obd_resp[10] = uVar3 + 5 + uVar2 + obd_mode_0x02_pids_supported_01_08 +
                     obd_mode_0x02_pids_supported_09_10 + obd_mode_0x02_pids_supported_11_18 +
                     obd_mode_0x02_pids_supported_19_20;
      obd_resp_len = 10;
      obd_resp_i = 0;
      REG_SC1DR = 0x48;
      obd_resp[4] = uVar3;
      obd_resp[5] = uVar2;
      break;
    default:
      goto switchD_00057714_caseD_1;
    case 2:
      uVar1 = bcd_encode((int)(uint)LEA_obd_freeze_dtc >> 3);
      obd_kline_mode_0x02_send_2bytes(uVar3,uVar2,uVar1);
      break;
    case 3:
      obd_kline_mode_0x02_send_2bytes(uVar3,uVar2,(ushort)LEA_obd_freeze_fuel_system_status << 8);
      break;
    case 4:
      obd_kline_mode_0x02_send_1byte(param_1,param_2,LEA_obd_freeze_load);
      break;
    case 5:
      obd_kline_mode_0x02_send_1byte(param_1,param_2,LEA_obd_freeze_coolant);
      break;
    case 6:
      obd_kline_mode_0x02_send_1byte(param_1,param_2,LEA_obd_freeze_stft);
      break;
    case 7:
      obd_kline_mode_0x02_send_1byte(param_1,param_2,LEA_obd_freeze_ltft);
      break;
    case 0xc:
      obd_kline_mode_0x02_send_2bytes(uVar3,uVar2,LEA_obd_freeze_engine_speed);
      break;
    case 0xd:
      obd_kline_mode_0x02_send_1byte(param_1,param_2,LEA_obd_freeze_car_speed);
      break;
    case 0x10:
      obd_kline_mode_0x02_send_2bytes(uVar3,uVar2,LEA_obd_freeze_maf_flow);
      break;
    case 0x11:
      obd_kline_mode_0x02_send_1byte(param_1,param_2,LEA_obd_freeze_tps);
    }
  }
  return;
}



// Sends 1-byte mode 0x02 freeze frame response

void obd_kline_mode_0x02_send_1byte(uint8_t param_1,uint8_t param_2,uint8_t param_3)

{
  builtin_memcpy(obd_resp,"Hk\x10B",4);
  obd_resp[4] = param_1;
  obd_resp[5] = param_2;
  obd_resp[6] = param_3;
  obd_resp[7] = param_1 + 5 + param_2 + param_3;
  obd_resp_len = 7;
  obd_resp_i = 0;
  REG_SC1DR = 0x48;
  return;
}



// Sends 2 data bytes of a mode 0x02 freeze frame response (header + PID + 16-bit value + checksum)

void obd_kline_mode_0x02_send_2bytes(uint8_t param_1,uint8_t param_2,uint16_t param_3)

{
  builtin_memcpy(obd_resp,"Hk\x10B",4);
  obd_resp[4] = param_1;
  obd_resp[5] = param_2;
  obd_resp._6_2_ = param_3;
  obd_resp[8] = param_1 + 5 + param_2 + (char)(param_3 >> 8) + (char)param_3;
  obd_resp_len = 8;
  obd_resp_i = 0;
  REG_SC1DR = 0x48;
  return;
}



// OBD Mode 03: Returns confirmed DTCs

void obd_mode_0x03_trouble_code(void)

{
  byte bVar1;
  uint uVar2;
  byte bVar3;
  
  builtin_memcpy(obd_resp,"Hk\x10C",4);
  if (obd_trouble_list_count == 0) {
    bVar1 = 0;
    DAT_003fd780 = 0;
  }
  else if ((int)((uint)obd_trouble_list_count - (uint)DAT_003fd780) < 4) {
    if (DAT_003fd780 < obd_trouble_list_count) {
      bVar1 = obd_trouble_list_count - DAT_003fd780;
    }
    else {
      bVar1 = 0;
      DAT_003fd780 = 0;
    }
  }
  else {
    bVar1 = 3;
  }
  for (bVar3 = 0; bVar3 < bVar1; bVar3 = bVar3 + 1) {
    uVar2 = bcd_encode(obd_trouble_list[(uint)DAT_003fd780 + (uint)bVar3]);
    obd_resp[(uint)bVar3 * 2 + 4] = (uint8_t)((uVar2 & 0xffff) >> 8);
    obd_resp[(uint)bVar3 * 2 + 5] = (uint8_t)(uVar2 & 0xffff);
  }
  DAT_003fd780 = DAT_003fd780 + bVar1;
  if (obd_trouble_list_count <= DAT_003fd780) {
    DAT_003fd780 = 0;
  }
  for (; bVar1 < 3; bVar1 = bVar1 + 1) {
    obd_resp[(uint)bVar1 * 2 + 4] = 0;
    obd_resp[(uint)bVar1 * 2 + 5] = 0;
  }
  obd_resp[10] = obd_resp[0] + obd_resp[1] + obd_resp[2] + obd_resp[3] + obd_resp[4] + obd_resp[5] +
                 obd_resp[6] + obd_resp[7] + obd_resp[8] + obd_resp[9];
  obd_resp_len = 10;
  obd_resp_i = 0;
  REG_SC1DR = (ushort)obd_resp[0];
  return;
}



// Updates obd_mil_dtc_count: combines DTC count with MIL status (bit 7)

void obd_mil_dtc_count_update(void)

{
  if ((obd_mil_flags & 3) == 0) {
    obd_mil_dtc_count = obd_trouble_list_count;
  }
  else {
    obd_mil_dtc_count = obd_trouble_list_count | 0x80;
  }
  return;
}



// Empty OBD initialization stub

void obd_init_nop(void)

{
  return;
}



// Adds DTC to confirmed trouble code list

void obd_add_trouble(uint16_t param_1)

{
  if (obd_trouble_list_count < 0x7f) {
    obd_trouble_list[obd_trouble_list_count] = param_1;
    obd_trouble_list_count = obd_trouble_list_count + 1;
  }
  return;
}



// OBD Mode 04: Clears all DTCs and resets monitors

void obd_mode_0x04_clear(void)

{
  builtin_memcpy(obd_resp,"Hk\x10D",4);
  obd_resp[4] = 7;
  obd_resp_len = 4;
  obd_resp_i = 0;
  REG_SC1DR = 0x48;
  obd_clear_freeze();
  return;
}



// Clears all freeze frame data

void obd_clear_freeze(void)

{
  byte bVar1;
  
  for (bVar1 = 8; bVar1 < 0x10; bVar1 = bVar1 + 1) {
    (&DAT_002f82df)[bVar1] = 0;
    (&DAT_002f82cf)[bVar1] = 0;
  }
  DAT_002f8352 = 0;
  DAT_002f82ff = 0;
  cat_diag_pre_o2_timer = DAT_003fbfea;
  DAT_002f834e = 0;
  DAT_002f8350 = 0x3ff;
  o2_flags = o2_flags & 0xfeff;
  o2_lean2rich_total_time = 0;
  o2_rich2lean_total_time = 0;
  o2_lean2rich_switch_count = 0;
  o2_rich2lean_switch_count = 0;
  DAT_003fd61c = DAT_003fc054;
  DAT_003fd61a = DAT_003fc036;
  DAT_003fd60a = 0;
  DAT_003fd621 = 0;
  DAT_003fd60e = 0;
  DAT_003fd615 = 0;
  DAT_003fd612 = 0;
  post_o2_state = 0;
  DAT_003fd60c = 0;
  DAT_003fd614 = 0;
  DAT_003fd610 = 0;
  LEA_obd_monitors_completeness = CAL_obd_monitors[1];
  LEA_obd_freeze_dtc = 0;
  LEA_obd_freeze_fuel_system_status = 0;
  LEA_obd_freeze_engine_speed = 0;
  LEA_obd_freeze_load = 0;
  LEA_obd_freeze_car_speed = 0;
  LEA_obd_freeze_maf_flow = 0;
  LEA_obd_freeze_stft = 0;
  LEA_obd_freeze_ltft = 0;
  LEA_obd_freeze_coolant = 0;
  DAT_003fd3b4 = 0;
  DAT_002f8322 = 0;
  obd_mil_flags = 0;
  LEA_obd_P0011_flags = 0;
  LEA_obd_P0011_engine_start_count = 3;
  LEA_obd_P0011_warm_up_cycle_count = 40;
  LEA_obd_P0012_flags = 0;
  LEA_obd_P0012_engine_start_count = 3;
  LEA_obd_P0012_warm_up_cycle_count = 40;
  LEA_obd_P0016_flags = 0;
  LEA_obd_P0016_engine_start_count = 3;
  LEA_obd_P0016_warm_up_cycle_count = 40;
  LEA_obd_P0076_flags = 0;
  LEA_obd_P0076_engine_start_count = 3;
  LEA_obd_P0076_warm_up_cycle_count = 40;
  LEA_obd_P0077_flags = 0;
  LEA_obd_P0077_engine_start_count = 3;
  LEA_obd_P0077_warm_up_cycle_count = 40;
  LEA_obd_P0101_flags = 0;
  LEA_obd_P0101_engine_start_count = 3;
  LEA_obd_P0101_warm_up_cycle_count = 40;
  LEA_obd_P0102_flags = 0;
  LEA_obd_P0102_engine_start_count = 3;
  LEA_obd_P0102_warm_up_cycle_count = 40;
  LEA_obd_P0103_flags = 0;
  LEA_obd_P0103_engine_start_count = 3;
  LEA_obd_P0103_warm_up_cycle_count = 40;
  LEA_obd_P0106_flags = 0;
  LEA_obd_P0106_engine_start_count = 3;
  LEA_obd_P0106_warm_up_cycle_count = 40;
  LEA_obd_P0107_flags = 0;
  LEA_obd_P0107_engine_start_count = 3;
  LEA_obd_P0107_warm_up_cycle_count = 40;
  LEA_obd_P0108_flags = 0;
  LEA_obd_P0108_engine_start_count = 3;
  LEA_obd_P0108_warm_up_cycle_count = 40;
  LEA_obd_P0111_flags = 0;
  LEA_obd_P0111_engine_start_count = 3;
  LEA_obd_P0111_warm_up_cycle_count = 40;
  LEA_obd_P0112_flags = 0;
  LEA_obd_P0112_engine_start_count = 3;
  LEA_obd_P0112_warm_up_cycle_count = 40;
  LEA_obd_P0113_flags = 0;
  LEA_obd_P0113_engine_start_count = 3;
  LEA_obd_P0113_warm_up_cycle_count = 40;
  LEA_obd_P0116_flags = 0;
  LEA_obd_P0116_engine_start_count = 3;
  LEA_obd_P0116_warm_up_cycle_count = 40;
  LEA_obd_P0117_flags = 0;
  LEA_obd_P0117_engine_start_count = 3;
  LEA_obd_P0117_warm_up_cycle_count = 40;
  LEA_obd_P0118_flags = 0;
  LEA_obd_P0118_engine_start_count = 3;
  LEA_obd_P0118_warm_up_cycle_count = 40;
  LEA_obd_P0122_flags = 0;
  LEA_obd_P0122_engine_start_count = 3;
  LEA_obd_P0122_warm_up_cycle_count = 40;
  LEA_obd_P0123_flags = 0;
  LEA_obd_P0123_engine_start_count = 3;
  LEA_obd_P0123_warm_up_cycle_count = 40;
  LEA_obd_P0128_flags = 0;
  LEA_obd_P0128_engine_start_count = 3;
  LEA_obd_P0128_warm_up_cycle_count = 40;
  LEA_obd_P0131_flags = 0;
  LEA_obd_P0131_engine_start_count = 3;
  LEA_obd_P0131_warm_up_cycle_count = 40;
  LEA_obd_P0132_flags = 0;
  LEA_obd_P0132_engine_start_count = 3;
  LEA_obd_P0132_warm_up_cycle_count = 40;
  LEA_obd_P0133_flags = 0;
  LEA_obd_P0133_engine_start_count = 3;
  LEA_obd_P0133_warm_up_cycle_count = 40;
  LEA_obd_P0134_flags = 0;
  LEA_obd_P0134_engine_start_count = 3;
  LEA_obd_P0134_warm_up_cycle_count = 40;
  LEA_obd_P0135_flags = 0;
  LEA_obd_P0135_engine_start_count = 3;
  LEA_obd_P0135_warm_up_cycle_count = 40;
  LEA_obd_P0137_flags = 0;
  LEA_obd_P0137_engine_start_count = 3;
  LEA_obd_P0137_warm_up_cycle_count = 40;
  LEA_obd_P0138_flags = 0;
  LEA_obd_P0138_engine_start_count = 3;
  LEA_obd_P0138_warm_up_cycle_count = 40;
  LEA_obd_P0139_flags = 0;
  LEA_obd_P0139_engine_start_count = 3;
  LEA_obd_P0139_warm_up_cycle_count = 40;
  LEA_obd_P0140_flags = 0;
  LEA_obd_P0140_engine_start_count = 3;
  LEA_obd_P0140_warm_up_cycle_count = 40;
  LEA_obd_P0141_flags = 0;
  LEA_obd_P0141_engine_start_count = 3;
  LEA_obd_P0141_warm_up_cycle_count = 40;
  LEA_obd_P0171_flags = 0;
  LEA_obd_P0171_engine_start_count = 3;
  LEA_obd_P0171_warm_up_cycle_count = 40;
  LEA_obd_P0172_flags = 0;
  LEA_obd_P0172_engine_start_count = 3;
  LEA_obd_P0172_warm_up_cycle_count = 40;
  LEA_obd_P0201_flags = 0;
  LEA_obd_P0201_engine_start_count = 3;
  LEA_obd_P0201_warm_up_cycle_count = 40;
  LEA_obd_P0202_flags = 0;
  LEA_obd_P0202_engine_start_count = 3;
  LEA_obd_P0202_warm_up_cycle_count = 40;
  LEA_obd_P0203_flags = 0;
  LEA_obd_P0203_engine_start_count = 3;
  LEA_obd_P0203_warm_up_cycle_count = 40;
  LEA_obd_P0204_flags = 0;
  LEA_obd_P0204_engine_start_count = 3;
  LEA_obd_P0204_warm_up_cycle_count = 40;
  LEA_obd_P0222_flags = 0;
  LEA_obd_P0222_engine_start_count = 3;
  LEA_obd_P0222_warm_up_cycle_count = 40;
  LEA_obd_P0223_flags = 0;
  LEA_obd_P0223_engine_start_count = 3;
  LEA_obd_P0223_warm_up_cycle_count = 40;
  LEA_obd_P0237_flags = 0;
  LEA_obd_P0237_engine_start_count = 3;
  LEA_obd_P0237_warm_up_cycle_count = 40;
  LEA_obd_P0238_flags = 0;
  LEA_obd_P0238_engine_start_count = 3;
  LEA_obd_P0238_warm_up_cycle_count = 40;
  LEA_obd_P0300_flags = 0;
  LEA_obd_P0300_engine_start_count = 3;
  LEA_obd_P0300_warm_up_cycle_count = 40;
  LEA_obd_P0301_flags = 0;
  LEA_obd_P0301_engine_start_count = 3;
  LEA_obd_P0301_warm_up_cycle_count = 40;
  LEA_obd_P0302_flags = 0;
  LEA_obd_P0302_engine_start_count = 3;
  LEA_obd_P0302_warm_up_cycle_count = 40;
  LEA_obd_P0303_flags = 0;
  LEA_obd_P0303_engine_start_count = 3;
  LEA_obd_P0303_warm_up_cycle_count = 40;
  LEA_obd_P0304_flags = 0;
  LEA_obd_P0304_engine_start_count = 3;
  LEA_obd_P0304_warm_up_cycle_count = 40;
  LEA_obd_P0327_flags = 0;
  LEA_obd_P0327_engine_start_count = 3;
  LEA_obd_P0327_warm_up_cycle_count = 40;
  LEA_obd_P0328_flags = 0;
  LEA_obd_P0328_engine_start_count = 3;
  LEA_obd_P0328_warm_up_cycle_count = 40;
  LEA_obd_P0335_flags = 0;
  LEA_obd_P0335_engine_start_count = 3;
  LEA_obd_P0335_warm_up_cycle_count = 40;
  LEA_obd_P0340_flags = 0;
  LEA_obd_P0340_engine_start_count = 3;
  LEA_obd_P0340_warm_up_cycle_count = 40;
  LEA_obd_P1301_flags = 0;
  LEA_obd_P1301_engine_start_count = 3;
  LEA_obd_P1301_warm_up_cycle_count = 40;
  LEA_obd_P1302_flags = 0;
  LEA_obd_P1302_engine_start_count = 3;
  LEA_obd_P1302_warm_up_cycle_count = 40;
  LEA_obd_P0351_flags = 0;
  LEA_obd_P0351_engine_start_count = 3;
  LEA_obd_P0351_warm_up_cycle_count = 40;
  LEA_obd_P0352_flags = 0;
  LEA_obd_P0352_engine_start_count = 3;
  LEA_obd_P0352_warm_up_cycle_count = 40;
  LEA_obd_P0353_flags = 0;
  LEA_obd_P0353_engine_start_count = 3;
  LEA_obd_P0353_warm_up_cycle_count = 40;
  LEA_obd_P0354_flags = 0;
  LEA_obd_P0354_engine_start_count = 3;
  LEA_obd_P0354_warm_up_cycle_count = 40;
  LEA_obd_P0420_flags = 0;
  LEA_obd_P0420_engine_start_count = 3;
  LEA_obd_P0420_warm_up_cycle_count = 40;
  LEA_obd_P0441_flags = 0;
  LEA_obd_P0441_engine_start_count = 3;
  LEA_obd_P0441_warm_up_cycle_count = 40;
  LEA_obd_P0442_flags = 0;
  LEA_obd_P0442_engine_start_count = 3;
  LEA_obd_P0442_warm_up_cycle_count = 40;
  LEA_obd_P0444_flags = 0;
  LEA_obd_P0444_engine_start_count = 3;
  LEA_obd_P0444_warm_up_cycle_count = 40;
  LEA_obd_P0445_flags = 0;
  LEA_obd_P0445_engine_start_count = 3;
  LEA_obd_P0445_warm_up_cycle_count = 40;
  LEA_obd_P0446_flags = 0;
  LEA_obd_P0446_engine_start_count = 3;
  LEA_obd_P0446_warm_up_cycle_count = 40;
  LEA_obd_P0447_flags = 0;
  LEA_obd_P0447_engine_start_count = 3;
  LEA_obd_P0447_warm_up_cycle_count = 40;
  LEA_obd_P0448_flags = 0;
  LEA_obd_P0448_engine_start_count = 3;
  LEA_obd_P0448_warm_up_cycle_count = 40;
  LEA_obd_P0451_flags = 0;
  LEA_obd_P0451_engine_start_count = 3;
  LEA_obd_P0451_warm_up_cycle_count = 40;
  LEA_obd_P0452_flags = 0;
  LEA_obd_P0452_engine_start_count = 3;
  LEA_obd_P0452_warm_up_cycle_count = 40;
  LEA_obd_P0453_flags = 0;
  LEA_obd_P0453_engine_start_count = 3;
  LEA_obd_P0453_warm_up_cycle_count = 40;
  LEA_obd_P0455_flags = 0;
  LEA_obd_P0455_engine_start_count = 3;
  LEA_obd_P0455_warm_up_cycle_count = 40;
  LEA_obd_P0456_flags = 0;
  LEA_obd_P0456_engine_start_count = 3;
  LEA_obd_P0456_warm_up_cycle_count = 40;
  LEA_obd_P0461_flags = 0;
  LEA_obd_P0461_engine_start_count = 3;
  LEA_obd_P0461_warm_up_cycle_count = 40;
  LEA_obd_P0462_flags = 0;
  LEA_obd_P0462_engine_start_count = 3;
  LEA_obd_P0462_warm_up_cycle_count = 40;
  LEA_obd_P0463_flags = 0;
  LEA_obd_P0463_engine_start_count = 3;
  LEA_obd_P0463_warm_up_cycle_count = 40;
  LEA_obd_P0480_flags = 0;
  LEA_obd_P0480_engine_start_count = 3;
  LEA_obd_P0480_warm_up_cycle_count = 40;
  LEA_obd_P0481_flags = 0;
  LEA_obd_P0481_engine_start_count = 3;
  LEA_obd_P0481_warm_up_cycle_count = 40;
  LEA_obd_P0500_flags = 0;
  LEA_obd_P0500_engine_start_count = 3;
  LEA_obd_P0500_warm_up_cycle_count = 40;
  LEA_obd_P0506_flags = 0;
  LEA_obd_P0506_engine_start_count = 3;
  LEA_obd_P0506_warm_up_cycle_count = 40;
  LEA_obd_P0507_flags = 0;
  LEA_obd_P0507_engine_start_count = 3;
  LEA_obd_P0507_warm_up_cycle_count = 40;
  LEA_obd_P0562_flags = 0;
  LEA_obd_P0562_engine_start_count = 3;
  LEA_obd_P0562_warm_up_cycle_count = 40;
  LEA_obd_P0563_flags = 0;
  LEA_obd_P0563_engine_start_count = 3;
  LEA_obd_P0563_warm_up_cycle_count = 40;
  LEA_obd_P0601_flags = 0;
  LEA_obd_P0601_engine_start_count = 3;
  LEA_obd_P0601_warm_up_cycle_count = 40;
  LEA_obd_P0606_flags = 0;
  LEA_obd_P0606_engine_start_count = 3;
  LEA_obd_P0606_warm_up_cycle_count = 40;
  LEA_obd_P0627_flags = 0;
  LEA_obd_P0627_engine_start_count = 3;
  LEA_obd_P0627_warm_up_cycle_count = 40;
  LEA_obd_P0630_flags = 0;
  LEA_obd_P0630_engine_start_count = 3;
  LEA_obd_P0630_warm_up_cycle_count = 40;
  LEA_obd_P0638_flags = 0;
  LEA_obd_P0638_engine_start_count = 3;
  LEA_obd_P0638_warm_up_cycle_count = 40;
  LEA_obd_P0646_flags = 0;
  LEA_obd_P0646_engine_start_count = 3;
  LEA_obd_P0646_warm_up_cycle_count = 40;
  LEA_obd_P0647_flags = 0;
  LEA_obd_P0647_engine_start_count = 3;
  LEA_obd_P0647_warm_up_cycle_count = 40;
  LEA_obd_P2122_flags = 0;
  LEA_obd_P2122_engine_start_count = 3;
  LEA_obd_P2122_warm_up_cycle_count = 40;
  LEA_obd_P2123_flags = 0;
  LEA_obd_P2123_engine_start_count = 3;
  LEA_obd_P2123_warm_up_cycle_count = 40;
  LEA_obd_P2127_flags = 0;
  LEA_obd_P2127_engine_start_count = 3;
  LEA_obd_P2127_warm_up_cycle_count = 40;
  LEA_obd_P2128_flags = 0;
  LEA_obd_P2128_engine_start_count = 3;
  LEA_obd_P2128_warm_up_cycle_count = 40;
  LEA_obd_P2135_flags = 0;
  LEA_obd_P2135_engine_start_count = 3;
  LEA_obd_P2135_warm_up_cycle_count = 40;
  LEA_obd_P2138_flags = 0;
  LEA_obd_P2138_engine_start_count = 3;
  LEA_obd_P2138_warm_up_cycle_count = 40;
  LEA_obd_P2173_flags = 0;
  LEA_obd_P2173_engine_start_count = 3;
  LEA_obd_P2173_warm_up_cycle_count = 40;
  LEA_obd_P2602_flags = 0;
  LEA_obd_P2602_engine_start_count = 3;
  LEA_obd_P2602_warm_up_cycle_count = 40;
  LEA_obd_P2603_flags = 0;
  LEA_obd_P2603_engine_start_count = 3;
  LEA_obd_P2603_warm_up_cycle_count = 40;
  LEA_obd_P2646_flags = 0;
  LEA_obd_P2646_engine_start_count = 3;
  LEA_obd_P2646_warm_up_cycle_count = 40;
  LEA_obd_P2647_flags = 0;
  LEA_obd_P2647_engine_start_count = 3;
  LEA_obd_P2647_warm_up_cycle_count = 40;
  LEA_obd_P2648_flags = 0;
  LEA_obd_P2648_engine_start_count = 3;
  LEA_obd_P2648_warm_up_cycle_count = 40;
  LEA_obd_P2649_flags = 0;
  LEA_obd_P2649_engine_start_count = 3;
  LEA_obd_P2649_warm_up_cycle_count = 40;
  LEA_obd_P2104_flags = 0;
  LEA_obd_P2104_engine_start_count = 3;
  LEA_obd_P2104_warm_up_cycle_count = 40;
  LEA_obd_P2105_flags = 0;
  LEA_obd_P2105_engine_start_count = 3;
  LEA_obd_P2105_warm_up_cycle_count = 40;
  LEA_obd_P2106_flags = 0;
  LEA_obd_P2106_engine_start_count = 3;
  LEA_obd_P2106_warm_up_cycle_count = 40;
  LEA_obd_P2107_flags = 0;
  LEA_obd_P2107_engine_start_count = 3;
  LEA_obd_P2107_warm_up_cycle_count = 40;
  LEA_obd_P2100_flags = 0;
  LEA_obd_P2100_engine_start_count = 3;
  LEA_obd_P2100_warm_up_cycle_count = 40;
  LEA_obd_P2102_flags = 0;
  LEA_obd_P2102_engine_start_count = 3;
  LEA_obd_P2102_warm_up_cycle_count = 40;
  LEA_obd_P2103_flags = 0;
  LEA_obd_P2103_engine_start_count = 3;
  LEA_obd_P2103_warm_up_cycle_count = 40;
  LEA_obd_P2108_flags = 0;
  LEA_obd_P2108_engine_start_count = 3;
  LEA_obd_P2108_warm_up_cycle_count = 40;
  obd_pending_list_count = 0;
  obd_trouble_list_count = 0;
  for (bVar1 = 0; bVar1 < 0x80; bVar1 = bVar1 + 1) {
    obd_pending_list[bVar1] = 0;
    obd_trouble_list[bVar1] = 0;
  }
  DAT_003fd3ce = 1;
  obd_init_state_machine();
  DAT_003fd3d8 = 0;
  return;
}



// OBD Mode 09: Returns vehicle information (VIN, calibration ID)

void obd_mode_0x09_informations(undefined1 param_1)

{
  ushort uVar1;
  
  uVar1 = obd_resp._8_2_;
  if (false) {
switchD_00059b7c_caseD_7:
    obd_resp[3] = 127;
    obd_resp[4] = 18;
    obd_resp[5] = 84;
    obd_resp_len = 5;
    REG_SC1DR = 0x48;
  }
  else {
    switch(param_1) {
    case 0:
      obd_resp[3] = 73;
      obd_resp[4] = 0;
      obd_resp[5] = 1;
      obd_resp[6] = obd_mode_0x09_pids_supported_01_08;
      obd_resp[7] = obd_mode_0x09_pids_supported_09_10;
      uVar1 = CONCAT11(obd_mode_0x09_pids_supported_11_18,obd_mode_0x09_pids_supported_19_20);
      obd_resp[10] = obd_mode_0x09_pids_supported_01_08 + 13 + obd_mode_0x09_pids_supported_09_10 +
                     obd_mode_0x09_pids_supported_11_18 + obd_mode_0x09_pids_supported_19_20;
      obd_resp_len = 10;
      REG_SC1DR = 0x48;
      break;
    case 1:
      obd_resp[3] = 73;
      obd_resp[4] = 1;
      obd_resp[5] = 5;
      obd_resp[6] = 18;
      obd_resp_len = 6;
      REG_SC1DR = 0x48;
      break;
    case 2:
      builtin_memcpy(obd_resp + 3,"I\x02\x01",4);
      DAT_003fd884 = 1;
      obd_resp[7] = 0;
      obd_resp[10] = LEA_ecu_VIN[0] + 15;
      obd_resp_len = 10;
      REG_SC1DR = 0x48;
      uVar1 = (ushort)(byte)LEA_ecu_VIN[0];
      break;
    case 3:
      obd_resp[3] = 73;
      obd_resp[4] = 3;
      obd_resp[5] = 4;
      obd_resp[6] = 19;
      obd_resp_len = 6;
      REG_SC1DR = 0x48;
      break;
    case 4:
      obd_resp[3] = 73;
      obd_resp[4] = 4;
      obd_resp[5] = 1;
      DAT_003fd884 = 1;
      obd_resp[6] = DAT_003fc97a;
      obd_resp[7] = DAT_003fc97b;
      obd_resp[10] = DAT_003fc97a + 17 + DAT_003fc97b + DAT_003fc97c + DAT_003fc97d;
      obd_resp_len = 10;
      REG_SC1DR = 0x48;
      uVar1 = CONCAT11(DAT_003fc97c,DAT_003fc97d);
      break;
    case 5:
      obd_resp[3] = 73;
      obd_resp[4] = 5;
      obd_resp[5] = 1;
      obd_resp[6] = 18;
      obd_resp_len = 6;
      REG_SC1DR = 0x48;
      break;
    case 6:
      builtin_memcpy(obd_resp + 3,"I\x06\x01",4);
      DAT_003fd884 = 0;
      obd_resp[7] = 0;
      obd_resp[10] = (char)(ecu_CRC_computed >> 8) + '\x13' + (char)ecu_CRC_computed;
      obd_resp_len = 10;
      REG_SC1DR = 0x48;
      uVar1 = ecu_CRC_computed;
      break;
    default:
      goto switchD_00059b7c_caseD_7;
    case 8:
      obd_resp[3] = 73;
      obd_resp[4] = 8;
      obd_resp[5] = 1;
      DAT_003fd884 = 1;
      obd_resp[6] = (uint8_t)(LEA_obd_iumpr_obdcond_count >> 8);
      obd_resp[7] = (uint8_t)LEA_obd_iumpr_obdcond_count;
      obd_resp[10] = obd_resp[6] + 21 + obd_resp[7] + (char)(LEA_obd_iumpr_ignition_count >> 8) +
                     (char)LEA_obd_iumpr_ignition_count;
      obd_resp_len = 10;
      REG_SC1DR = 0x48;
      uVar1 = LEA_obd_iumpr_ignition_count;
    }
  }
  obd_resp[8] = (uint8_t)(uVar1 >> 8);
  obd_resp[9] = (uint8_t)uVar1;
  obd_resp[2] = 16;
  obd_resp[1] = 107;
  obd_resp[0] = 72;
  obd_resp_i = 0;
  return;
}



// K-Line mode 0x09 - sends VIN in 4-byte chunks from LEA storage

void obd_kline_mode_0x09_info(byte param_1)

{
  int iVar1;
  uint8_t uVar2;
  
  iVar1 = (DAT_003fd884 & 0x3f) * 4;
  uVar2 = DAT_003fd884 + 1;
  if (param_1 == 4) {
    obd_resp[3] = 73;
    obd_resp[4] = 4;
    obd_resp[6] = (&DAT_003fc97a)[iVar1];
    obd_resp[7] = (&DAT_003fc97b)[iVar1];
    obd_resp[8] = (&DAT_003fc97c)[iVar1];
    obd_resp[9] = (&DAT_003fc97d)[iVar1];
    obd_resp[10] = DAT_003fd884 + 0x11 + obd_resp[6] + obd_resp[7] + obd_resp[8] + obd_resp[9];
    obd_resp_len = 10;
    REG_SC1DR = 0x48;
    obd_resp[5] = uVar2;
    DAT_003fd884 = uVar2;
    if (uVar2 == 4) {
      DAT_003fd884 = 0;
    }
  }
  else {
    if (param_1 < 4) {
      if (param_1 == 2) {
        obd_resp[6] = *(uint8_t *)((int)&LEA_idle_flow_adj1 + iVar1 + 1);
        obd_resp[7] = *(uint8_t *)(&LEA_idle_flow_adj1_ac_on + (DAT_003fd884 & 0x3f) * 2);
        obd_resp[8] = *(uint8_t *)((int)&LEA_idle_flow_adj1_ac_on + iVar1 + 1);
        obd_resp[9] = LEA_ecu_VIN[iVar1];
        obd_resp[10] = DAT_003fd884 + 0xf + obd_resp[6] + obd_resp[7] + obd_resp[8] + obd_resp[9];
        REG_SC1DR = 0x48;
        if (uVar2 != 5) {
          obd_resp_len = 10;
          obd_resp_i = 0;
          builtin_memcpy(obd_resp,"Hk\x10I\x02",5);
          obd_resp[5] = uVar2;
          DAT_003fd884 = uVar2;
          return;
        }
        obd_resp_len = 10;
        obd_resp_i = 0;
        builtin_memcpy(obd_resp,"Hk\x10I\x02",5);
        obd_resp[5] = uVar2;
        DAT_003fd884 = 0;
        return;
      }
    }
    else if (param_1 == 8) {
      if (uVar2 == 2) {
        builtin_memcpy(obd_resp,"Hk\x10I\b",5);
        obd_resp[6] = (uint8_t)((ushort)DAT_003fddd6 >> 8);
        obd_resp[7] = (uint8_t)DAT_003fddd6;
        obd_resp[8] = (uint8_t)((ushort)DAT_003fddd4 >> 8);
        obd_resp[9] = (uint8_t)DAT_003fddd4;
        obd_resp[10] = DAT_003fd884 + 0x15 + obd_resp[6] + obd_resp[7] + obd_resp[8] + obd_resp[9];
        obd_resp[5] = uVar2;
      }
      else if (uVar2 == 3) {
        builtin_memcpy(obd_resp,"Hk\x10I\b",5);
        obd_resp[6] = 0;
        obd_resp[7] = 0;
        obd_resp[8] = 0;
        obd_resp[9] = 0;
        obd_resp[10] = DAT_003fd884 + 0x15;
        obd_resp[5] = uVar2;
      }
      else if (uVar2 == 4) {
        builtin_memcpy(obd_resp,"Hk\x10I\b",5);
        obd_resp[6] = (uint8_t)((ushort)DAT_003fddce >> 8);
        obd_resp[7] = (uint8_t)DAT_003fddce;
        obd_resp[8] = (uint8_t)((ushort)DAT_003fddcc >> 8);
        obd_resp[9] = (uint8_t)DAT_003fddcc;
        obd_resp[10] = DAT_003fd884 + 0x15 + obd_resp[6] + obd_resp[7] + obd_resp[8] + obd_resp[9];
        obd_resp[5] = uVar2;
      }
      else if (uVar2 == 5) {
        builtin_memcpy(obd_resp,"Hk\x10I\b",5);
        obd_resp[6] = 0;
        obd_resp[7] = 0;
        obd_resp[8] = 0;
        obd_resp[9] = 0;
        obd_resp[10] = DAT_003fd884 + 0x15;
        obd_resp[5] = uVar2;
      }
      else if (uVar2 == 6) {
        builtin_memcpy(obd_resp,"Hk\x10I\b",5);
        obd_resp[6] = (uint8_t)((ushort)DAT_003fddde >> 8);
        obd_resp[7] = (uint8_t)DAT_003fddde;
        obd_resp[8] = (uint8_t)((ushort)DAT_003fdddc >> 8);
        obd_resp[9] = (uint8_t)DAT_003fdddc;
        obd_resp[10] = DAT_003fd884 + 0x15 + obd_resp[6] + obd_resp[7] + obd_resp[8] + obd_resp[9];
        obd_resp[5] = uVar2;
      }
      else if (uVar2 == 7) {
        builtin_memcpy(obd_resp,"Hk\x10I\b",5);
        obd_resp[6] = 0;
        obd_resp[7] = 0;
        obd_resp[8] = 0;
        obd_resp[9] = 0;
        obd_resp[10] = DAT_003fd884 + 0x15;
        obd_resp[5] = uVar2;
      }
      else if (uVar2 == 8) {
        builtin_memcpy(obd_resp,"Hk\x10I\b",5);
        obd_resp[6] = (uint8_t)((ushort)DAT_003fdde6 >> 8);
        obd_resp[7] = (uint8_t)DAT_003fdde6;
        obd_resp[8] = (uint8_t)((ushort)DAT_003fdde4 >> 8);
        obd_resp[9] = (uint8_t)DAT_003fdde4;
        obd_resp[10] = DAT_003fd884 + 0x15 + obd_resp[6] + obd_resp[7] + obd_resp[8] + obd_resp[9];
        obd_resp[5] = uVar2;
      }
      REG_SC1DR = (ushort)obd_resp[0];
      if (uVar2 != 8) {
        obd_resp_len = 10;
        obd_resp_i = 0;
        DAT_003fd884 = uVar2;
        return;
      }
      obd_resp_len = 10;
      obd_resp_i = 0;
      DAT_003fd884 = 0;
      return;
    }
    obd_resp[3] = 127;
    obd_resp[4] = 18;
    obd_resp_len = 5;
    REG_SC1DR = 0x48;
    DAT_003fd884 = 0;
    obd_resp[5] = 84;
  }
  obd_resp[2] = 16;
  obd_resp[1] = 107;
  obd_resp[0] = 72;
  obd_resp_i = 0;
  return;
}



// OBD Mode 06: Returns test results for specific monitor

void obd_mode_0x06_test_results(byte param_1)

{
  uint uVar1;
  uint16_t uVar2;
  
  if (param_1 == 3) {
    uVar2 = evap_leak_pressure_rise;
    if (evap_leak_pressure_rise < 0) {
      uVar2 = 0;
    }
    obd_resp[3] = 70;
    obd_resp[4] = 3;
    obd_resp[5] = 1;
    obd_resp[8] = 0;
    obd_resp[9] = evap_leak_P0456_threshold;
    obd_resp[10] = (uint8_t)(uVar2 >> 8) + 13 + (uint8_t)uVar2 + evap_leak_P0456_threshold;
    obd_resp_len = 10;
    REG_SC1DR = 0x48;
    goto LAB_0005d074;
  }
  if (param_1 < 3) {
    if (param_1 == 1) {
      obd_resp[3] = 70;
      obd_resp[4] = 1;
      obd_resp[5] = 1;
      obd_resp[8] = (uint8_t)((ushort)DAT_003fbf7e >> 8);
      obd_resp[9] = (uint8_t)DAT_003fbf7e;
      obd_resp[10] = (uint8_t)(DAT_002f8352 >> 8) + 11 + (uint8_t)DAT_002f8352 + obd_resp[8] +
                     obd_resp[9];
      obd_resp_len = 10;
      REG_SC1DR = 0x48;
      uVar2 = DAT_002f8352;
      goto LAB_0005d074;
    }
    if (param_1 != 0) {
      uVar2 = evap_leak_result;
      if (evap_leak_result < 0) {
        uVar2 = 0;
      }
      obd_resp[3] = 70;
      obd_resp[4] = 2;
      obd_resp[5] = 1;
      obd_resp[8] = 0;
      obd_resp[9] = evap_leak_P0442_threshold;
      obd_resp[10] = (uint8_t)(uVar2 >> 8) + 12 + (uint8_t)uVar2 + evap_leak_P0442_threshold;
      obd_resp_len = 10;
      REG_SC1DR = 0x48;
      goto LAB_0005d074;
    }
    if (true) {
      obd_resp[3] = 70;
      obd_resp[4] = 0;
      obd_resp[5] = 255;
      uVar2 = CONCAT11(obd_mode_0x06_pids_supported_01_08,obd_mode_0x06_pids_supported_09_10);
      obd_resp[8] = obd_mode_0x06_pids_supported_11_18;
      obd_resp[9] = obd_mode_0x06_pids_supported_19_20;
      obd_resp[10] = obd_mode_0x06_pids_supported_01_08 + 8 + obd_mode_0x06_pids_supported_09_10 +
                     obd_mode_0x06_pids_supported_11_18 + obd_mode_0x06_pids_supported_19_20;
      obd_resp_len = 10;
      REG_SC1DR = 0x48;
      goto LAB_0005d074;
    }
  }
  else {
    if (param_1 == 5) {
      obd_resp[3] = 70;
      obd_resp[4] = 5;
      obd_resp[5] = 1;
      obd_resp[8] = 0;
      obd_resp[9] = obd_P1301_threshold;
      obd_resp[10] = (char)(misfire_max_result >> 8) + '\x0f' + (char)misfire_max_result +
                     obd_P1301_threshold;
      obd_resp_len = 10;
      REG_SC1DR = 0x48;
      uVar2 = misfire_max_result;
      goto LAB_0005d074;
    }
    if (param_1 < 5) {
      uVar1 = abs((int)inj_time_adj_by_ltft);
      obd_resp[3] = 70;
      obd_resp[4] = 4;
      obd_resp[5] = 1;
      uVar2 = (uint16_t)uVar1;
      obd_resp[8] = (uint8_t)((ushort)DAT_003fbf82 >> 8);
      obd_resp[9] = (uint8_t)DAT_003fbf82;
      obd_resp[10] = (char)((uVar1 & 0xffff) >> 8) + '\x0e' + (char)(uVar1 & 0xffff) + obd_resp[8] +
                     obd_resp[9];
      obd_resp_len = 10;
      REG_SC1DR = 0x48;
      goto LAB_0005d074;
    }
  }
  obd_resp[3] = 127;
  obd_resp[4] = 18;
  obd_resp[5] = 84;
  obd_resp_len = 5;
  REG_SC1DR = 0x48;
  uVar2 = obd_resp._6_2_;
LAB_0005d074:
  obd_resp[6] = (uint8_t)(uVar2 >> 8);
  obd_resp[7] = (uint8_t)uVar2;
  obd_resp[2] = 16;
  obd_resp[1] = 107;
  obd_resp[0] = 72;
  obd_resp_i = 0;
  return;
}



// OBD Mode 07: Returns pending DTCs

void obd_mode_0x07_pending_code(void)

{
  byte bVar1;
  uint uVar2;
  byte bVar3;
  
  builtin_memcpy(obd_resp,"Hk\x10G",4);
  if (obd_pending_list_count == 0) {
    bVar1 = 0;
    DAT_003f8f60 = 0;
  }
  else if ((int)((uint)obd_pending_list_count - (uint)DAT_003f8f60) < 4) {
    if (DAT_003f8f60 < obd_pending_list_count) {
      bVar1 = obd_pending_list_count - DAT_003f8f60;
    }
    else {
      bVar1 = 0;
      DAT_003f8f60 = 0;
    }
  }
  else {
    bVar1 = 3;
  }
  for (bVar3 = 0; bVar3 < bVar1; bVar3 = bVar3 + 1) {
    uVar2 = bcd_encode(obd_pending_list[(uint)DAT_003f8f60 + (uint)bVar3]);
    obd_resp[(uint)bVar3 * 2 + 4] = (uint8_t)((uVar2 & 0xffff) >> 8);
    obd_resp[(uint)bVar3 * 2 + 5] = (uint8_t)(uVar2 & 0xffff);
  }
  DAT_003f8f60 = DAT_003f8f60 + bVar1;
  if (obd_pending_list_count <= DAT_003f8f60) {
    DAT_003f8f60 = 0;
  }
  for (; bVar1 < 3; bVar1 = bVar1 + 1) {
    obd_resp[(uint)bVar1 * 2 + 4] = 0;
    obd_resp[(uint)bVar1 * 2 + 5] = 0;
  }
  obd_resp[10] = obd_resp[0] + obd_resp[1] + obd_resp[2] + obd_resp[3] + obd_resp[4] + obd_resp[5] +
                 obd_resp[6] + obd_resp[7] + obd_resp[8] + obd_resp[9];
  obd_resp_len = 10;
  obd_resp_i = 0;
  REG_SC1DR = (ushort)obd_resp[0];
  return;
}



// Adds DTC to pending trouble code list

void obd_add_pending(uint16_t param_1)

{
  if (obd_pending_list_count < 0x7f) {
    obd_pending_list[obd_pending_list_count] = param_1;
    obd_pending_list_count = obd_pending_list_count + 1;
  }
  return;
}



// OBD Mode 08: Controls EVAP system test

void obd_mode_0x08_evap_control(char param_1)

{
  if (param_1 == '\x01') {
    if ((engine_speed_1 == 0) && (DAT_003fbff8 != 0)) {
      obd_resp[3] = 72;
      obd_resp[4] = 1;
      obd_resp[5] = 0;
      obd_resp[6] = 0;
      obd_resp[7] = 0;
      obd_resp[8] = 0;
      obd_resp[9] = 0;
      obd_resp[10] = 12;
      obd_resp_len = 10;
      REG_SC1DR = 0x48;
      obd_mode_0x08_state = 0x18;
      obd_mode_0x08_timer = DAT_003fbff8;
      obd_mode_0x2F_value = 0xff;
    }
    else {
      obd_resp[3] = 127;
      obd_resp[4] = 8;
      obd_resp[5] = 34;
      obd_resp[6] = 108;
      obd_resp_len = 6;
      REG_SC1DR = 0x48;
      obd_mode_0x2F_value = 0;
      obd_mode_0x08_state = 0;
    }
  }
  else if ((param_1 != '\0') || (false)) {
    obd_resp[3] = 127;
    obd_resp[4] = 18;
    obd_resp[5] = 84;
    obd_resp_len = 5;
    REG_SC1DR = 0x48;
  }
  else {
    obd_resp[3] = 72;
    obd_resp[4] = 0;
    obd_resp[5] = 0;
    obd_resp[6] = obd_mode_0x08_pids_supported_01_08;
    obd_resp[7] = obd_mode_0x08_pids_supported_09_10;
    obd_resp[8] = obd_mode_0x08_pids_supported_11_18;
    obd_resp[9] = obd_mode_0x08_pids_supported_19_20;
    obd_resp[10] = obd_mode_0x08_pids_supported_01_08 + 11 + obd_mode_0x08_pids_supported_09_10 +
                   obd_mode_0x08_pids_supported_11_18 + obd_mode_0x08_pids_supported_19_20;
    obd_resp_len = 10;
    REG_SC1DR = 0x48;
  }
  obd_resp[2] = 16;
  obd_resp[1] = 107;
  obd_resp[0] = 72;
  obd_resp_i = 0;
  return;
}



// OBD Mode 08 EVAP test handler (5ms)

void obd_mode_0x08_evap_control_5ms(void)

{
  if (obd_mode_0x08_timer != 0) {
    obd_mode_0x08_timer = obd_mode_0x08_timer - 1;
  }
  if (obd_mode_0x08_state == 0x18) {
    if (obd_mode_0x08_timer == 0) {
      obd_mode_0x2F_value = 0;
      obd_mode_0x08_state = 0;
    }
  }
  else if ((0x17 < obd_mode_0x08_state) || (obd_mode_0x08_state != 0)) {
    obd_mode_0x08_state = 0;
  }
  return;
}



// OBD Mode 22: Returns extended performance data (Lotus-specific)

void obd_mode_0x22_performance_data(uint16 *param_1)

{
  int iVar1;
  
  if (false) {
switchD_0005dcb4_caseD_202:
    builtin_memcpy(obd_resp,"Hk\x10\x7f\x11",5);
    obd_resp[5] = 83;
    obd_resp_len = 5;
    obd_resp_i = 0;
    REG_SC1DR = 0x48;
  }
  else {
    switch((uint)param_1 & 0xffff) {
    case 0x200:
      builtin_memcpy(obd_resp,"Hk\x10b\x02",6);
      obd_resp[6] = obd_mode_0x22_pids_supported_0201_0208;
      obd_resp[7] = obd_mode_0x22_pids_supported_0209_0210;
      obd_resp[8] = obd_mode_0x22_pids_supported_0211_0218;
      obd_resp[9] = obd_mode_0x22_pids_supported_0219_0220;
      obd_resp[10] = obd_mode_0x22_pids_supported_0201_0208 + 39 +
                     obd_mode_0x22_pids_supported_0209_0210 + obd_mode_0x22_pids_supported_0211_0218
                     + obd_mode_0x22_pids_supported_0219_0220;
      obd_resp_len = 10;
      obd_resp_i = 0;
      REG_SC1DR = 0x48;
      break;
    case 0x201:
      obd_kline_mode_0x22_send_uint8(param_1,evap_leak_state);
      break;
    default:
      goto switchD_0005dcb4_caseD_202;
    case 0x203:
      obd_kline_mode_0x22_send_uint32(param_1,(int)LEA_idle_flow_adj1);
      break;
    case 0x204:
      obd_kline_mode_0x22_send_uint8(param_1,idle_flow_target);
      break;
    case 0x205:
      obd_kline_mode_0x22_send_uint16(param_1,(uint16_t)inj_time_final_1);
      break;
    case 0x206:
      obd_kline_mode_0x22_send_uint8(param_1,idle_status);
      break;
    case 0x207:
      obd_kline_mode_0x22_send_uint16(param_1,vvt_target_smooth);
      break;
    case 0x208:
      obd_kline_mode_0x22_send_uint16(param_1,vvt_pos);
      break;
    case 0x209:
      obd_kline_mode_0x22_send_uint8(param_1,vvl_is_high_cam);
      break;
    case 0x20a:
      obd_kline_mode_0x22_send_uint16(param_1,cat_diag_pre_o2_sw);
      break;
    case 0x20b:
      obd_kline_mode_0x22_send_uint16(param_1,cat_diag_pre_o2_max_sw);
      break;
    case 0x20c:
      obd_kline_mode_0x22_send_uint8(param_1,car_gear_current);
      break;
    case 0x20d:
      iVar1 = (idle_speed_target + -600) / 5 + (idle_speed_target + -600 >> 0x1f);
      obd_kline_mode_0x22_send_uint8(param_1,(char)iVar1 - (char)(iVar1 >> 0x1f));
      break;
    case 0x20e:
      obd_kline_mode_0x22_send_4bytes(param_1,0xffe0);
      break;
    case 0x20f:
      obd_kline_mode_0x22_send_4bytes(param_1,&DAT_0000ffe4);
      break;
    case 0x210:
      obd_kline_mode_0x22_send_4bytes(param_1,&DAT_0000ffe8);
      break;
    case 0x211:
      obd_kline_mode_0x22_send_4bytes(param_1,&DAT_0000ffec);
      break;
    case 0x212:
      obd_kline_mode_0x22_send_uint16(param_1,evap_pressure);
      break;
    case 0x213:
      obd_kline_mode_0x22_send_uint16(param_1,afr_target);
      break;
    case 0x214:
      obd_kline_mode_0x22_send_uint8(param_1,L9822E_outputs);
      break;
    case 0x215:
    case 0x216:
      break;
    case 0x218:
      obd_kline_mode_0x22_send_uint16(param_1,LEA_knock_retard2[0]);
      break;
    case 0x219:
      obd_kline_mode_0x22_send_uint16(param_1,LEA_knock_retard2[1]);
      break;
    case 0x21a:
      obd_kline_mode_0x22_send_uint16(param_1,LEA_knock_retard2[2]);
      break;
    case 0x21b:
      obd_kline_mode_0x22_send_uint16(param_1,LEA_knock_retard2[3]);
      break;
    case 0x21c:
      obd_kline_mode_0x22_send_4bytes(param_1,&DAT_003fc97a);
      break;
    case 0x21d:
      obd_kline_mode_0x22_send_4bytes(param_1,&DAT_003fc97e);
      break;
    case 0x21e:
      obd_kline_mode_0x22_send_4bytes(param_1,&DAT_003fc982);
      break;
    case 0x21f:
      obd_kline_mode_0x22_send_4bytes(param_1,&DAT_003fc986);
      break;
    case 0x220:
      builtin_memcpy(obd_resp,"Hk\x10b\x02 ",6);
      obd_resp[6] = obd_mode_0x22_pids_supported_0221_0228;
      obd_resp[7] = obd_mode_0x22_pids_supported_0229_0230;
      obd_resp[8] = obd_mode_0x22_pids_supported_0231_0238;
      obd_resp[9] = obd_mode_0x22_pids_supported_0239_0240;
      obd_resp[10] = obd_mode_0x22_pids_supported_0221_0228 + 71 +
                     obd_mode_0x22_pids_supported_0229_0230 + obd_mode_0x22_pids_supported_0231_0238
                     + obd_mode_0x22_pids_supported_0239_0240;
      obd_resp_len = 10;
      obd_resp_i = 0;
      REG_SC1DR = 0x48;
      break;
    case 0x221:
      obd_kline_mode_0x22_send_4bytes(param_1,&DAT_003fc98a);
      break;
    case 0x222:
      obd_kline_mode_0x22_send_4bytes(param_1,&DAT_003fc98e);
      break;
    case 0x223:
      obd_kline_mode_0x22_send_4bytes(param_1,&DAT_003fc992);
      break;
    case 0x224:
      obd_kline_mode_0x22_send_4bytes(param_1,&DAT_003fc996);
      break;
    case 0x225:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_time_at_TPS[0]);
      break;
    case 0x226:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_time_at_TPS[1]);
      break;
    case 0x227:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_time_at_TPS[2]);
      break;
    case 0x228:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_time_at_TPS[3]);
      break;
    case 0x229:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_time_at_TPS[4]);
      break;
    case 0x22a:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_time_at_TPS[5]);
      break;
    case 0x22b:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_time_at_TPS[6]);
      break;
    case 0x22c:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_time_at_TPS[7]);
      break;
    case 0x22d:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_time_at_RPM[0]);
      break;
    case 0x22e:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_time_at_RPM[1]);
      break;
    case 0x22f:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_time_at_RPM[2]);
      break;
    case 0x230:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_time_at_RPM[3]);
      break;
    case 0x231:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_time_at_RPM[4]);
      break;
    case 0x232:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_time_at_RPM[5]);
      break;
    case 0x233:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_time_at_RPM[6]);
      break;
    case 0x234:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_time_at_RPM[7]);
      break;
    case 0x235:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_time_at_KMH[0]);
      break;
    case 0x236:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_time_at_KMH[1]);
      break;
    case 0x237:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_time_at_KMH[2]);
      break;
    case 0x238:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_time_at_KMH[3]);
      break;
    case 0x239:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_time_at_KMH[4]);
      break;
    case 0x23a:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_time_at_KMH[5]);
      break;
    case 0x23b:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_time_at_KMH[6]);
      break;
    case 0x23c:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_time_at_KMH[7]);
      break;
    case 0x240:
      builtin_memcpy(obd_resp,"Hk\x10b\x02 ",6);
      obd_resp[6] = obd_mode_0x22_pids_supported_0241_0248;
      obd_resp[7] = obd_mode_0x22_pids_supported_0249_0250;
      obd_resp[8] = obd_mode_0x22_pids_supported_0251_0258;
      obd_resp[9] = obd_mode_0x22_pids_supported_0259_0260;
      obd_resp[10] = obd_mode_0x22_pids_supported_0241_0248 + 71 +
                     obd_mode_0x22_pids_supported_0249_0250 + obd_mode_0x22_pids_supported_0251_0258
                     + obd_mode_0x22_pids_supported_0259_0260;
      obd_resp_len = 10;
      obd_resp_i = 0;
      REG_SC1DR = 0x48;
      break;
    case 0x246:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_time_at_coolant_temp[0]);
      break;
    case 0x247:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_time_at_coolant_temp[1]);
      break;
    case 0x248:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_time_at_coolant_temp[2]);
      break;
    case 0x249:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_time_at_coolant_temp[3]);
      break;
    case 0x24e:
      obd_kline_mode_0x22_send_uint16(param_1,LEA_perf_max_engine_speed[0]);
      break;
    case 0x24f:
      obd_kline_mode_0x22_send_uint16(param_1,LEA_perf_max_engine_speed[1]);
      break;
    case 0x250:
      obd_kline_mode_0x22_send_uint16(param_1,LEA_perf_max_engine_speed[2]);
      break;
    case 0x251:
      obd_kline_mode_0x22_send_uint16(param_1,LEA_perf_max_engine_speed[3]);
      break;
    case 0x252:
      obd_kline_mode_0x22_send_uint16(param_1,LEA_perf_max_engine_speed[4]);
      break;
    case 0x253:
      obd_kline_mode_0x22_send_uint8(param_1,LEA_perf_max_engine_speed_5_coolant_temp);
      break;
    case 0x255:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_max_engine_speed_5_run_timer);
      break;
    case 0x256:
      obd_kline_mode_0x22_send_uint8(param_1,LEA_perf_max_engine_speed_4_coolant_temp);
      break;
    case 600:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_max_engine_speed_4_run_timer);
      break;
    case 0x259:
      obd_kline_mode_0x22_send_uint8(param_1,LEA_perf_max_engine_speed_3_coolant_temp);
      break;
    case 0x25b:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_max_engine_speed_3_run_timer);
      break;
    case 0x25c:
      obd_kline_mode_0x22_send_uint8(param_1,LEA_perf_max_engine_speed_2_coolant_temp);
      break;
    case 0x25e:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_max_engine_speed_2_run_timer);
      break;
    case 0x25f:
      obd_kline_mode_0x22_send_uint8(param_1,LEA_perf_max_engine_speed_1_coolant_temp);
      break;
    case 0x260:
      builtin_memcpy(obd_resp,"Hk\x10b\x02 ",6);
      obd_resp[6] = obd_mode_0x22_pids_supported_0261_0268;
      obd_resp[7] = obd_mode_0x22_pids_supported_0269_0270;
      obd_resp[8] = obd_mode_0x22_pids_supported_0271_0278;
      obd_resp[9] = obd_mode_0x22_pids_supported_0279_0280;
      obd_resp[10] = obd_mode_0x22_pids_supported_0261_0268 + 71 +
                     obd_mode_0x22_pids_supported_0269_0270 + obd_mode_0x22_pids_supported_0271_0278
                     + obd_mode_0x22_pids_supported_0279_0280;
      obd_resp_len = 10;
      obd_resp_i = 0;
      REG_SC1DR = 0x48;
      break;
    case 0x262:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_max_engine_speed_1_run_timer);
      break;
    case 0x263:
      obd_kline_mode_0x22_send_uint8(param_1,LEA_perf_max_vehicle_speed[0]);
      break;
    case 0x264:
      obd_kline_mode_0x22_send_uint8(param_1,LEA_perf_max_vehicle_speed[1]);
      break;
    case 0x265:
      obd_kline_mode_0x22_send_uint8(param_1,LEA_perf_max_vehicle_speed[2]);
      break;
    case 0x266:
      obd_kline_mode_0x22_send_uint8(param_1,LEA_perf_max_vehicle_speed[3]);
      break;
    case 0x267:
      obd_kline_mode_0x22_send_uint8(param_1,LEA_perf_max_vehicle_speed[4]);
      break;
    case 0x268:
      obd_kline_mode_0x22_send_uint8(param_1,LEA_perf_fastest_standing_start[0]);
      break;
    case 0x269:
      obd_kline_mode_0x22_send_uint8(param_1,LEA_perf_fastest_standing_start[1]);
      break;
    case 0x26a:
      obd_kline_mode_0x22_send_uint8(param_1,LEA_perf_last_standing_start[0]);
      break;
    case 0x26b:
      obd_kline_mode_0x22_send_uint8(param_1,LEA_perf_last_standing_start[1]);
      break;
    case 0x26c:
      obd_kline_mode_0x22_send_uint32(param_1,LEA_perf_engine_run_timer);
      break;
    case 0x26d:
      obd_kline_mode_0x22_send_uint16(param_1,LEA_perf_number_of_standing_starts);
    }
  }
  return;
}



// Sends 1-byte mode 0x22 performance data response

void obd_kline_mode_0x22_send_uint8(uint16 *pid,uint8_t value)

{
  builtin_memcpy(obd_resp,"Hk\x10b",4);
  obd_resp[4] = (uint8_t)((uint)pid >> 8);
  obd_resp[5] = (uint8_t)pid;
  obd_resp[6] = value;
  obd_resp[7] = obd_resp[4] + 37 + (uint8_t)pid + value;
  obd_resp_len = 7;
  obd_resp_i = 0;
  REG_SC1DR = 0x48;
  return;
}



// Sends 4-byte mode 0x22 performance data response

void obd_kline_mode_0x22_send_uint32(uint16 *pid,uint32_t value)

{
  builtin_memcpy(obd_resp,"Hk\x10b",4);
  obd_resp[4] = (uint8_t)((uint)pid >> 8);
  obd_resp[5] = (uint8_t)pid;
  obd_resp[6] = (uint8_t)(value >> 0x18);
  obd_resp[7] = (uint8_t)(value >> 0x10);
  obd_resp[8] = (uint8_t)(value >> 8);
  obd_resp[9] = (uint8_t)value;
  obd_resp[10] = obd_resp[4] + 37 + (uint8_t)pid + obd_resp[6] + obd_resp[7] + obd_resp[8] +
                 (uint8_t)value;
  obd_resp_len = 10;
  obd_resp_i = 0;
  REG_SC1DR = 0x48;
  return;
}



// Sends 2-byte mode 0x22 performance data response

void obd_kline_mode_0x22_send_uint16(uint16 *pid,uint16_t value)

{
  builtin_memcpy(obd_resp,"Hk\x10b",4);
  obd_resp[4] = (uint8_t)((uint)pid >> 8);
  obd_resp[5] = (uint8_t)pid;
  obd_resp._6_2_ = value;
  obd_resp[8] = obd_resp[4] + 37 + (uint8_t)pid + (char)(value >> 8) + (char)value;
  obd_resp_len = 8;
  obd_resp_i = 0;
  REG_SC1DR = 0x48;
  return;
}



// K-Line mode 0x22 response - PID plus 4 data bytes read from a pointer

void obd_kline_mode_0x22_send_4bytes(undefined4 param_1,uint8_t *param_2)

{
  builtin_memcpy(obd_resp,"Hk\x10b",4);
  obd_resp[4] = (uint8_t)((uint)param_1 >> 8);
  obd_resp[5] = (uint8_t)param_1;
  obd_resp[6] = *param_2;
  obd_resp[7] = param_2[1];
  obd_resp[8] = param_2[2];
  obd_resp[9] = param_2[3];
  obd_resp[10] = obd_resp[4] + 37 + (uint8_t)param_1 + *param_2 + param_2[1] + param_2[2] +
                 param_2[3];
  obd_resp_len = 10;
  obd_resp_i = 0;
  REG_SC1DR = 0x48;
  return;
}



// WARNING: Inlined function: push_22to31
// WARNING: Inlined function: pop_22to31
// OBD Mode 2F: Output test/control (Lotus-specific)

void obd_mode_0x2F_test(uint param_1,uint param_2)

{
  ushort uVar1;
  undefined1 uVar2;
  
  if (false) {
switchD_0005f6a8_caseD_105:
    builtin_memcpy(obd_resp,"Hk\x10\x7f\x12",5);
    obd_resp[5] = 84;
    obd_resp_len = 5;
    obd_resp_i = 0;
    REG_SC1DR = 0x48;
  }
  else {
    uVar2 = (undefined1)param_2;
    switch(param_1 & 0xffff) {
    case 0x100:
      builtin_memcpy(obd_resp,"Hk\x10o\x01",6);
      obd_resp[6] = DAT_003f85b8;
      obd_resp[7] = obd_mode_0x2F_pids_supported_09_10;
      obd_resp[8] = obd_mode_0x2F_pids_supported_11_18;
      obd_resp[9] = DAT_003f85b9;
      obd_resp[10] = DAT_003f85b8 + 51 + obd_mode_0x2F_pids_supported_09_10 +
                     obd_mode_0x2F_pids_supported_11_18 + DAT_003f85b9;
      obd_resp_len = 10;
      obd_resp_i = 0;
      REG_SC1DR = 0x48;
      break;
    case 0x101:
      if (((DAT_003fda9c == 0) && (engine_speed_1 == 0)) && (DAT_003fbff6 != 0)) {
        uVar1 = REG_CPR1_B;
        REG_CPR1_B = uVar1 & 0xfff3 | 0xc;
        uVar1 = REG_CIER_B;
        REG_CIER_B = uVar1 & 0xfffd;
        uVar1 = REG_CFSR3_B;
        REG_CFSR3_B = uVar1 & 0xff0f | 0xe0;
        REG_TPU3B_CH1_PARAM0 = 0x89;
        REG_TPU3B_CH1_PARAM1 = 0;
        REG_TPU3B_CH1_PARAM2 = 0xec;
        REG_TPU3B_CH1_PARAM3 = 0;
        uVar1 = REG_HSQR1_B;
        REG_HSQR1_B = uVar1 & 0xfff3;
        uVar1 = REG_CPR1_B;
        REG_CPR1_B = uVar1 & 0xfff3 | 4;
        uVar1 = REG_HSRR1_B;
        REG_HSRR1_B = uVar1 & 0xfff3 | 4;
        do {
          uVar1 = REG_HSRR1_B;
        } while (uVar1 != 0);
        obd_mode_0x2F_timer = DAT_003fbff6;
        obd_mode_0x2F_state = 1;
        obd_mode_0x2F_value = uVar2;
        obd_kline_mode_0x2F_send_uint8(param_1,param_2);
      }
      else {
        obd_kline_send_not_supported();
      }
      break;
    case 0x102:
      if (((DAT_003fda9c == 0) && (engine_speed_1 == 0)) && (DAT_003fbff6 != 0)) {
        uVar1 = REG_CPR1_B;
        REG_CPR1_B = uVar1 & 0xffcf | 0x30;
        uVar1 = REG_CIER_B;
        REG_CIER_B = uVar1 & 0xfffb;
        uVar1 = REG_CFSR3_B;
        REG_CFSR3_B = uVar1 & 0xf0ff | 0xe00;
        REG_TPU3B_CH2_PARAM0 = 0x89;
        REG_TPU3B_CH2_PARAM1 = 0;
        REG_TPU3B_CH2_PARAM2 = 0xec;
        REG_TPU3B_CH2_PARAM3 = 0;
        uVar1 = REG_HSQR1_B;
        REG_HSQR1_B = uVar1 & 0xffcf;
        uVar1 = REG_CPR1_B;
        REG_CPR1_B = uVar1 & 0xffcf | 0x10;
        uVar1 = REG_HSRR1_B;
        REG_HSRR1_B = uVar1 & 0xffcf | 0x10;
        do {
          uVar1 = REG_HSRR1_B;
        } while (uVar1 != 0);
        obd_mode_0x2F_state = 2;
        obd_mode_0x2F_timer = DAT_003fbff6;
        obd_mode_0x2F_value = uVar2;
        obd_kline_mode_0x2F_send_uint8(param_1,param_2);
      }
      else {
        obd_kline_send_not_supported();
      }
      break;
    case 0x103:
      if (((DAT_003fda9c == 0) && (engine_speed_1 == 0)) && (DAT_003fbff6 != 0)) {
        uVar1 = REG_CPR1_B;
        REG_CPR1_B = uVar1 & 0xff3f | 0xc0;
        uVar1 = REG_CIER_B;
        REG_CIER_B = uVar1 & 0xfff7;
        uVar1 = REG_CFSR3_B;
        REG_CFSR3_B = uVar1 & 0xfff | 0xe000;
        REG_TPU3B_CH3_PARAM0 = 0x89;
        REG_TPU3B_CH3_PARAM1 = 0;
        REG_TPU3B_CH3_PARAM2 = 0xec;
        REG_TPU3B_CH3_PARAM3 = 0;
        uVar1 = REG_HSQR1_B;
        REG_HSQR1_B = uVar1 & 0xff3f;
        uVar1 = REG_CPR1_B;
        REG_CPR1_B = uVar1 & 0xff3f | 0x40;
        uVar1 = REG_HSRR1_B;
        REG_HSRR1_B = uVar1 & 0xff3f | 0x40;
        do {
          uVar1 = REG_HSRR1_B;
        } while (uVar1 != 0);
        obd_mode_0x2F_state = 3;
        obd_mode_0x2F_timer = DAT_003fbff6;
        obd_mode_0x2F_value = uVar2;
        obd_kline_mode_0x2F_send_uint8(param_1,param_2);
      }
      else {
        obd_kline_send_not_supported();
      }
      break;
    case 0x104:
      if (((DAT_003fda9c == 0) && (engine_speed_1 == 0)) && (DAT_003fbff6 != 0)) {
        uVar1 = REG_CPR1_B;
        REG_CPR1_B = uVar1 & 0xfcff | 0x300;
        uVar1 = REG_CIER_B;
        REG_CIER_B = uVar1 & 0xffef;
        uVar1 = REG_CFSR2_B;
        REG_CFSR2_B = uVar1 & 0xfff0 | 0xe;
        REG_TPU3B_CH4_PARAM0 = 0x89;
        REG_TPU3B_CH4_PARAM1 = 0;
        REG_TPU3B_CH4_PARAM2 = 0xec;
        REG_TPU3B_CH4_PARAM3 = 0;
        uVar1 = REG_HSQR1_B;
        REG_HSQR1_B = uVar1 & 0xfcff;
        uVar1 = REG_CPR1_B;
        REG_CPR1_B = uVar1 & 0xfcff | 0x100;
        uVar1 = REG_HSRR1_B;
        REG_HSRR1_B = uVar1 & 0xfcff | 0x100;
        do {
          uVar1 = REG_HSRR1_B;
        } while (uVar1 != 0);
        obd_mode_0x2F_state = 4;
        obd_mode_0x2F_timer = DAT_003fbff6;
        obd_mode_0x2F_value = uVar2;
        obd_kline_mode_0x2F_send_uint8(param_1,param_2);
      }
      else {
        obd_kline_send_not_supported();
      }
      break;
    default:
      goto switchD_0005f6a8_caseD_105;
    case 0x120:
      builtin_memcpy(obd_resp,"Hk\x10o\x01 ",6);
      obd_resp[6] = DAT_003f85ba;
      obd_resp[7] = obd_mode_0x2F_pids_supported_29_30;
      obd_resp[8] = obd_mode_0x2F_pids_supported_31_38;
      obd_resp[9] = DAT_003f85bb;
      obd_resp[10] = DAT_003f85ba + 83 + obd_mode_0x2F_pids_supported_29_30 +
                     obd_mode_0x2F_pids_supported_31_38 + DAT_003f85bb;
      obd_resp_len = 10;
      obd_resp_i = 0;
      REG_SC1DR = 0x48;
      break;
    case 0x121:
      if ((DAT_003fda9c == 0) && (engine_speed_1 == 0)) {
        obd_mode_0x2F_value = uVar2;
        if ((param_2 & 0xff) < 4) {
          obd_mode_0x2F_value = 4;
        }
        obd_mode_0x2F_state = 9;
        obd_mode_0x2F_timer = DAT_003fbfec;
        obd_kline_mode_0x2F_send_uint8(param_1,param_2);
      }
      else {
        obd_kline_send_not_supported();
      }
      break;
    case 0x122:
      if ((DAT_003fda9c == 0) && (engine_speed_1 == 0)) {
        obd_mode_0x2F_value = uVar2;
        if ((param_2 & 0xff) < 4) {
          obd_mode_0x2F_value = 4;
        }
        obd_mode_0x2F_state = 10;
        obd_mode_0x2F_timer = DAT_003fbfee;
        obd_kline_mode_0x2F_send_uint8(param_1,param_2);
      }
      else {
        obd_kline_send_not_supported();
      }
      break;
    case 0x125:
      if (((DAT_003fda9c == 0) && (engine_speed_1 == 0)) && (DAT_003fc006 != 0)) {
        obd_mode_0x2F_value = uVar2;
        if ((param_2 & 0xff) < 4) {
          obd_mode_0x2F_value = 4;
        }
        obd_mode_0x2F_state = 0xc;
        obd_mode_0x2F_timer = DAT_003fc006;
        obd_kline_mode_0x2F_send_uint8(param_1,param_2);
      }
      else {
        obd_kline_send_not_supported();
      }
      break;
    case 0x126:
      if (((DAT_003fda9c == 0) && (engine_speed_1 == 0)) && (DAT_003fc008 != 0)) {
        obd_mode_0x2F_value = uVar2;
        if ((param_2 & 0xff) < 4) {
          obd_mode_0x2F_value = 4;
        }
        obd_mode_0x2F_timer = DAT_003fc008;
        obd_mode_0x2F_state = 0xb;
        obd_kline_mode_0x2F_send_uint8(param_1,param_2);
      }
      else {
        obd_kline_send_not_supported();
      }
      break;
    case 0x127:
      obd_mode_0x2F_value = uVar2;
      if ((param_2 & 0xff) < 4) {
        obd_mode_0x2F_value = 4;
      }
      obd_mode_0x2F_state = 0xd;
      obd_mode_0x2F_timer = DAT_003fbff8;
      obd_kline_mode_0x2F_send_uint8(param_1,param_2);
      break;
    case 0x12a:
      obd_mode_0x2F_value = uVar2;
      if ((param_2 & 0xff) < 4) {
        obd_mode_0x2F_value = 4;
      }
      obd_mode_0x2F_state = 0xe;
      obd_mode_0x2F_timer = DAT_003fc000;
      obd_kline_mode_0x2F_send_uint8(param_1,param_2);
      break;
    case 0x140:
      builtin_memcpy(obd_resp,"Hk\x10o\x01@",6);
      obd_resp[6] = DAT_003f85bc;
      obd_resp[7] = DAT_003f85bd;
      obd_resp[8] = obd_mode_0x2F_pids_supported_51_58;
      obd_resp[9] = DAT_003f85be;
      obd_resp[10] = DAT_003f85bc + 115 + DAT_003f85bd + obd_mode_0x2F_pids_supported_51_58 +
                     DAT_003f85be;
      obd_resp_len = 10;
      obd_resp_i = 0;
      REG_SC1DR = 0x48;
      break;
    case 0x141:
      if (((DAT_003fda9c == 0) && (engine_speed_1 == 0)) && (DAT_003fc010 != 0)) {
        DAT_003fda9e = (param_2 & 0xff) != 0;
        DAT_003fda9f = 1;
        obd_mode_0x2F_state = 0xf;
        obd_mode_0x2F_timer = DAT_003fc010;
        obd_mode_0x2F_value = uVar2;
        obd_kline_mode_0x2F_send_uint8(param_1,param_2);
      }
      else {
        obd_kline_send_not_supported();
      }
      break;
    case 0x142:
      if (DAT_003fbf6a == 0) {
        obd_kline_send_not_supported();
      }
      else {
        obd_mode_0x2F_state = 0x16;
        obd_mode_0x2F_timer = DAT_003fbf6a;
        obd_mode_0x2F_value = uVar2;
        obd_kline_mode_0x2F_send_uint8(param_1,param_2);
      }
      break;
    case 0x143:
      if (((DAT_003fda9c == 0) && (engine_speed_1 == 0)) && (DAT_003fc012 != 0)) {
        obd_mode_0x2F_state = 0x15;
        obd_mode_0x2F_timer = DAT_003fc012;
        obd_mode_0x2F_value = uVar2;
        obd_kline_mode_0x2F_send_uint8(param_1,param_2);
      }
      else {
        obd_kline_send_not_supported();
      }
      break;
    case 0x144:
      if (((DAT_003fda9c == 0) && (engine_speed_1 == 0)) && (DAT_003fc014 != 0)) {
        obd_mode_0x2F_state = 0x14;
        obd_mode_0x2F_timer = DAT_003fc014;
        obd_mode_0x2F_value = uVar2;
        obd_kline_mode_0x2F_send_uint8(param_1,param_2);
      }
      else {
        obd_kline_send_not_supported();
      }
      break;
    case 0x146:
      if (((DAT_003fda9c == 0) && (engine_speed_1 == 0)) && (DAT_003fc016 != 0)) {
        if ((param_2 & 0xff) == 0) {
          DAT_003fda9e = 0;
        }
        else {
          DAT_003fda9e = 0x10;
        }
        DAT_003fda9f = 0x10;
        obd_mode_0x2F_state = 0x10;
        obd_mode_0x2F_timer = DAT_003fc016;
        obd_mode_0x2F_value = uVar2;
        obd_kline_mode_0x2F_send_uint8(param_1,param_2);
      }
      else {
        obd_kline_send_not_supported();
      }
      break;
    case 0x147:
      if (((DAT_003fda9c == 0) && (engine_speed_1 == 0)) && (DAT_003fc018 != 0)) {
        obd_mode_0x2F_state = 0x11;
        obd_mode_0x2F_timer = DAT_003fc018;
        obd_mode_0x2F_value = uVar2;
        obd_kline_mode_0x2F_send_uint8(param_1,param_2);
      }
      else {
        obd_kline_send_not_supported();
      }
      break;
    case 0x148:
      if (((DAT_003fda9c == 0) && (engine_speed_1 == 0)) && (DAT_003fc018 != 0)) {
        obd_mode_0x2F_state = 0x17;
        obd_mode_0x2F_timer = DAT_003fc018;
        obd_mode_0x2F_value = uVar2;
        obd_kline_mode_0x2F_send_uint8(param_1,param_2);
      }
      else {
        obd_kline_send_not_supported();
      }
      break;
    case 0x149:
      if (((DAT_003fda9c == 0) && (engine_speed_1 == 0)) && (DAT_003fbff8 != 0)) {
        obd_mode_0x2F_state = 0x18;
        obd_mode_0x2F_timer = DAT_003fbff8;
        obd_mode_0x2F_value = uVar2;
        obd_kline_mode_0x2F_send_uint8(param_1,param_2);
      }
      else {
        obd_kline_send_not_supported();
      }
      break;
    case 0x14a:
      if (((DAT_003fda9c == 0) && (engine_speed_1 == 0)) && (DAT_003fc01a != 0)) {
        if ((param_2 & 0xff) == 0) {
          DAT_003fda9e = 0;
        }
        else {
          DAT_003fda9e = 8;
        }
        DAT_003fda9f = 8;
        obd_mode_0x2F_state = 0x12;
        obd_mode_0x2F_timer = DAT_003fc01a;
        obd_mode_0x2F_value = uVar2;
        obd_kline_mode_0x2F_send_uint8(param_1,param_2);
      }
      else {
        obd_kline_send_not_supported();
      }
      break;
    case 0x14b:
      if (((DAT_003fda9c == 0) && (engine_speed_1 == 0)) && (DAT_003fc01a != 0)) {
        if ((param_2 & 0xff) == 0) {
          DAT_003fda9e = 0;
        }
        else {
          DAT_003fda9e = 4;
        }
        DAT_003fda9f = 4;
        obd_mode_0x2F_state = 0x13;
        obd_mode_0x2F_timer = DAT_003fc01a;
        obd_mode_0x2F_value = uVar2;
        obd_kline_mode_0x2F_send_uint8(param_1,param_2);
      }
      else {
        obd_kline_send_not_supported();
      }
      break;
    case 0x160:
      builtin_memcpy(obd_resp,"Hk\x10o\x01`",6);
      obd_resp[6] = obd_mode_0x2F_pids_supported_61_68;
      obd_resp[7] = obd_mode_0x2F_pids_supported_69_70;
      obd_resp[8] = obd_mode_0x2F_pids_supported_71_78;
      obd_resp[9] = obd_mode_0x2F_pids_supported_79_80;
      obd_resp[10] = obd_mode_0x2F_pids_supported_61_68 + 147 + obd_mode_0x2F_pids_supported_69_70 +
                     obd_mode_0x2F_pids_supported_71_78 + obd_mode_0x2F_pids_supported_79_80;
      obd_resp_len = 10;
      obd_resp_i = 0;
      REG_SC1DR = 0x48;
      break;
    case 0x161:
      if (((DAT_003fda9c == 0) && (engine_speed_1 == 0)) && (DAT_003fc00e != 0)) {
        uVar1 = REG_CPR1_A;
        REG_CPR1_A = uVar1 & 0xfff3 | 0xc;
        uVar1 = REG_CIER_A;
        REG_CIER_A = uVar1 & 0xfffd;
        uVar1 = REG_CFSR3_A;
        REG_CFSR3_A = uVar1 & 0xff0f | 0xe0;
        REG_TPU3A_CH1_PARAM0 = 0x89;
        REG_TPU3A_CH1_PARAM1 = 0;
        REG_TPU3A_CH1_PARAM2 = 0xec;
        REG_TPU3A_CH1_PARAM3 = 0;
        uVar1 = REG_HSQR1_A;
        REG_HSQR1_A = uVar1 & 0xfff3;
        uVar1 = REG_CPR1_A;
        REG_CPR1_A = uVar1 & 0xfff3 | 4;
        uVar1 = REG_HSRR1_A;
        REG_HSRR1_A = uVar1 & 0xfff3 | 4;
        do {
          uVar1 = REG_HSRR1_A;
        } while (uVar1 != 0);
        uVar1 = REG_CPR1_A;
        REG_CPR1_A = uVar1 & 0xfcff | 0x300;
        uVar1 = REG_CIER_A;
        REG_CIER_A = uVar1 & 0xffef;
        uVar1 = REG_CFSR2_A;
        REG_CFSR2_A = uVar1 & 0xfff0 | 0xe;
        REG_TPU3A_CH4_PARAM0 = 0x89;
        REG_TPU3A_CH4_PARAM1 = 0;
        REG_TPU3A_CH4_PARAM2 = 0xec;
        REG_TPU3A_CH4_PARAM3 = 0;
        uVar1 = REG_HSQR1_A;
        REG_HSQR1_A = uVar1 & 0xfcff;
        uVar1 = REG_CPR1_A;
        REG_CPR1_A = uVar1 & 0xfcff | 0x100;
        uVar1 = REG_HSRR1_A;
        REG_HSRR1_A = uVar1 & 0xfcff | 0x100;
        do {
          uVar1 = REG_HSRR1_A;
        } while (uVar1 != 0);
        obd_mode_0x2F_state = 5;
        obd_mode_0x2F_timer = DAT_003fc00e;
        obd_mode_0x2F_value = uVar2;
        obd_kline_mode_0x2F_send_uint8(param_1,param_2);
      }
      else {
        obd_kline_send_not_supported();
      }
      break;
    case 0x162:
      if (((DAT_003fda9c == 0) && (engine_speed_1 == 0)) && (DAT_003fc00e != 0)) {
        uVar1 = REG_CPR1_A;
        REG_CPR1_A = uVar1 & 0xffcf | 0x30;
        uVar1 = REG_CIER_A;
        REG_CIER_A = uVar1 & 0xfffb;
        uVar1 = REG_CFSR3_A;
        REG_CFSR3_A = uVar1 & 0xf0ff | 0xe00;
        REG_TPU3A_CH2_PARAM0 = 0x89;
        REG_TPU3A_CH2_PARAM1 = 0;
        REG_TPU3A_CH2_PARAM2 = 0xec;
        REG_TPU3A_CH2_PARAM3 = 0;
        uVar1 = REG_HSQR1_A;
        REG_HSQR1_A = uVar1 & 0xffcf;
        uVar1 = REG_CPR1_A;
        REG_CPR1_A = uVar1 & 0xffcf | 0x10;
        uVar1 = REG_HSRR1_A;
        REG_HSRR1_A = uVar1 & 0xffcf | 0x10;
        do {
          uVar1 = REG_HSRR1_A;
        } while (uVar1 != 0);
        uVar1 = REG_CPR1_A;
        REG_CPR1_A = uVar1 & 0xff3f | 0xc0;
        uVar1 = REG_CIER_A;
        REG_CIER_A = uVar1 & 0xfff7;
        uVar1 = REG_CFSR3_A;
        REG_CFSR3_A = uVar1 & 0xfff | 0xe000;
        REG_TPU3A_CH3_PARAM0 = 0x89;
        REG_TPU3A_CH3_PARAM1 = 0;
        REG_TPU3A_CH3_PARAM2 = 0xec;
        REG_TPU3A_CH3_PARAM3 = 0;
        uVar1 = REG_HSQR1_A;
        REG_HSQR1_A = uVar1 & 0xff3f;
        uVar1 = REG_CPR1_A;
        REG_CPR1_A = uVar1 & 0xff3f | 0x40;
        uVar1 = REG_HSRR1_A;
        REG_HSRR1_A = uVar1 & 0xff3f | 0x40;
        do {
          uVar1 = REG_HSRR1_A;
        } while (uVar1 != 0);
        obd_mode_0x2F_state = 6;
        obd_mode_0x2F_timer = DAT_003fc00e;
        obd_mode_0x2F_value = uVar2;
        obd_kline_mode_0x2F_send_uint8(param_1,param_2);
      }
      else {
        obd_kline_send_not_supported();
      }
      break;
    case 0x163:
      if (((DAT_003fda9c == 0) && (engine_speed_1 == 0)) && (DAT_003fc00e != 0)) {
        uVar1 = REG_CPR1_A;
        REG_CPR1_A = uVar1 & 0xff3f | 0xc0;
        uVar1 = REG_CIER_A;
        REG_CIER_A = uVar1 & 0xfff7;
        uVar1 = REG_CFSR3_A;
        REG_CFSR3_A = uVar1 & 0xfff | 0xe000;
        REG_TPU3A_CH3_PARAM0 = 0x89;
        REG_TPU3A_CH3_PARAM1 = 0;
        REG_TPU3A_CH3_PARAM2 = 0xec;
        REG_TPU3A_CH3_PARAM3 = 0;
        uVar1 = REG_HSQR1_A;
        REG_HSQR1_A = uVar1 & 0xff3f;
        uVar1 = REG_CPR1_A;
        REG_CPR1_A = uVar1 & 0xff3f | 0x40;
        uVar1 = REG_HSRR1_A;
        REG_HSRR1_A = uVar1 & 0xff3f | 0x40;
        do {
          uVar1 = REG_HSRR1_A;
        } while (uVar1 != 0);
        obd_mode_0x2F_state = 7;
        obd_mode_0x2F_timer = DAT_003fc00e;
        obd_mode_0x2F_value = uVar2;
        obd_kline_mode_0x2F_send_uint8(param_1,param_2);
      }
      else {
        obd_kline_send_not_supported();
      }
      break;
    case 0x164:
      if (((DAT_003fda9c == 0) && (engine_speed_1 == 0)) && (DAT_003fc00e != 0)) {
        uVar1 = REG_CPR1_A;
        REG_CPR1_A = uVar1 & 0xfcff | 0x300;
        uVar1 = REG_CIER_A;
        REG_CIER_A = uVar1 & 0xffef;
        uVar1 = REG_CFSR2_A;
        REG_CFSR2_A = uVar1 & 0xfff0 | 0xe;
        REG_TPU3A_CH4_PARAM0 = 0x89;
        REG_TPU3A_CH4_PARAM1 = 0;
        REG_TPU3A_CH4_PARAM2 = 0xec;
        REG_TPU3A_CH4_PARAM3 = 0;
        uVar1 = REG_HSQR1_A;
        REG_HSQR1_A = uVar1 & 0xfcff;
        uVar1 = REG_CPR1_A;
        REG_CPR1_A = uVar1 & 0xfcff | 0x100;
        uVar1 = REG_HSRR1_A;
        REG_HSRR1_A = uVar1 & 0xfcff | 0x100;
        do {
          uVar1 = REG_HSRR1_A;
        } while (uVar1 != 0);
        obd_mode_0x2F_state = 8;
        obd_mode_0x2F_timer = DAT_003fc00e;
        obd_mode_0x2F_value = uVar2;
        obd_kline_mode_0x2F_send_uint8(param_1,param_2);
      }
      else {
        obd_kline_send_not_supported();
      }
    }
  }
  return;
}



// Sends K-Line not-supported response 0x7f 0x21 0x63

void obd_kline_send_not_supported(void)

{
  builtin_memcpy(obd_resp,"Hk\x10\x7f!c",6);
  obd_resp_len = 5;
  obd_resp_i = 0;
  REG_SC1DR = 0x48;
  return;
}



// K-Line mode 0x2F response - PID plus 1 data byte

void obd_kline_mode_0x2F_send_uint8(undefined4 param_1,uint8_t param_2)

{
  builtin_memcpy(obd_resp,"Hk\x10o",4);
  obd_resp[4] = (uint8_t)((uint)param_1 >> 8);
  obd_resp[5] = (uint8_t)param_1;
  obd_resp[6] = param_2;
  obd_resp[7] = obd_resp[4] + 50 + (uint8_t)param_1 + param_2;
  obd_resp_len = 7;
  obd_resp_i = 0;
  REG_SC1DR = 0x48;
  return;
}



// WARNING: Inlined function: push_24to31
// WARNING: Inlined function: pop_24to31
// OBD Mode 2F test handler (5ms)

void obd_mode_0x2F_test_5ms(void)

{
  ushort uVar1;
  
  if (engine_speed_1 == 0) {
    if (DAT_003fda9c != 0) {
      DAT_003fda9c = DAT_003fda9c + -1;
    }
  }
  else {
    DAT_003fda9c = DAT_003fbff0;
    obd_mode_0x2F_pulse_interval = 1;
    obd_mode_0x2F_timer = 0;
  }
  if (obd_mode_0x2F_timer != 0) {
    obd_mode_0x2F_timer = obd_mode_0x2F_timer - 1;
  }
  switch(obd_mode_0x2F_state) {
  case 0:
    break;
  case 1:
    obd_mode_0x2F_pulse_interval = obd_mode_0x2F_pulse_interval + 255;
    if (obd_mode_0x2F_pulse_interval == 0) {
      if (obd_mode_0x2F_timer == 0) {
        obd_mode_0x2F_state = 0;
        uVar1 = REG_CIER_B;
        REG_CIER_B = uVar1 | 2;
      }
      else {
        obd_mode_0x2F_pulse_interval = DAT_003fbff2;
        uVar1 = REG_CFSR3_B;
        if ((uVar1 >> 4 & 0xf) == 0xe) {
          REG_TPU3B_CH1_PARAM1 = DAT_003fbff4;
          uVar1 = REG_HSRR1_B;
          REG_HSRR1_B = uVar1 & 0xfff3 | 4;
          do {
            uVar1 = REG_HSRR1_B;
          } while (uVar1 != 0);
        }
        DAT_003f92d0 = 1;
        spi_pcs1();
        DAT_003f92d0 = 0;
        TLE6220_fault_check();
        if ((DAT_003fd52c & 1) != 0) {
          REG_TPU3B_CH1_PARAM1 = 100;
          uVar1 = REG_HSRR1_B;
          REG_HSRR1_B = uVar1 & 0xfff3 | 4;
          do {
            uVar1 = REG_HSRR1_B;
          } while (uVar1 != 0);
        }
      }
    }
    break;
  case 2:
    obd_mode_0x2F_pulse_interval = obd_mode_0x2F_pulse_interval + 255;
    if (obd_mode_0x2F_pulse_interval == 0) {
      if (obd_mode_0x2F_timer == 0) {
        obd_mode_0x2F_state = 0;
        uVar1 = REG_CIER_B;
        REG_CIER_B = uVar1 | 4;
      }
      else {
        obd_mode_0x2F_pulse_interval = DAT_003fbff2;
        uVar1 = REG_CFSR3_B;
        if ((uVar1 >> 8 & 0xf) == 0xe) {
          REG_TPU3B_CH2_PARAM1 = DAT_003fbff4;
          uVar1 = REG_HSRR1_B;
          REG_HSRR1_B = uVar1 & 0xffcf | 0x10;
          do {
            uVar1 = REG_HSRR1_B;
          } while (uVar1 != 0);
        }
        DAT_003f92d0 = 1;
        spi_pcs1();
        DAT_003f92d0 = 0;
        TLE6220_fault_check();
        if ((DAT_003fd52c & 0x10) != 0) {
          REG_TPU3B_CH2_PARAM1 = 100;
          uVar1 = REG_HSRR1_B;
          REG_HSRR1_B = uVar1 & 0xffcf | 0x10;
          do {
            uVar1 = REG_HSRR1_B;
          } while (uVar1 != 0);
        }
      }
    }
    break;
  case 3:
    obd_mode_0x2F_pulse_interval = obd_mode_0x2F_pulse_interval + 255;
    if (obd_mode_0x2F_pulse_interval == 0) {
      if (obd_mode_0x2F_timer == 0) {
        obd_mode_0x2F_state = 0;
        uVar1 = REG_CIER_B;
        REG_CIER_B = uVar1 | 8;
      }
      else {
        obd_mode_0x2F_pulse_interval = DAT_003fbff2;
        uVar1 = REG_CFSR3_B;
        if (uVar1 >> 0xc == 0xe) {
          REG_TPU3B_CH3_PARAM1 = DAT_003fbff4;
          uVar1 = REG_HSRR1_B;
          REG_HSRR1_B = uVar1 & 0xff3f | 0x40;
          do {
            uVar1 = REG_HSRR1_B;
          } while (uVar1 != 0);
        }
        DAT_003f92d0 = 1;
        spi_pcs1();
        DAT_003f92d0 = 0;
        TLE6220_fault_check();
        if ((DAT_003fd52c & 0x40) != 0) {
          REG_TPU3B_CH3_PARAM1 = 100;
          uVar1 = REG_HSRR1_B;
          REG_HSRR1_B = uVar1 & 0xff3f | 0x40;
          do {
            uVar1 = REG_HSRR1_B;
          } while (uVar1 != 0);
        }
      }
    }
    break;
  case 4:
    obd_mode_0x2F_pulse_interval = obd_mode_0x2F_pulse_interval + 255;
    if (obd_mode_0x2F_pulse_interval == 0) {
      if (obd_mode_0x2F_timer == 0) {
        obd_mode_0x2F_state = 0;
        uVar1 = REG_CIER_B;
        REG_CIER_B = uVar1 | 0x10;
      }
      else {
        obd_mode_0x2F_pulse_interval = DAT_003fbff2;
        uVar1 = REG_CFSR2_B;
        if ((uVar1 & 0xf) == 0xe) {
          REG_TPU3B_CH4_PARAM1 = DAT_003fbff4;
          uVar1 = REG_HSRR1_B;
          REG_HSRR1_B = uVar1 & 0xfcff | 0x100;
          do {
            uVar1 = REG_HSRR1_B;
          } while (uVar1 != 0);
        }
        DAT_003f92d0 = 1;
        spi_pcs1();
        DAT_003f92d0 = 0;
        TLE6220_fault_check();
        if ((DAT_003fd52c & 4) != 0) {
          REG_TPU3B_CH4_PARAM1 = 100;
          uVar1 = REG_HSRR1_B;
          REG_HSRR1_B = uVar1 & 0xfcff | 0x100;
          do {
            uVar1 = REG_HSRR1_B;
          } while (uVar1 != 0);
        }
      }
    }
    break;
  case 5:
    obd_mode_0x2F_pulse_interval = obd_mode_0x2F_pulse_interval + 255;
    if (obd_mode_0x2F_pulse_interval == 0) {
      if (obd_mode_0x2F_timer == 0) {
        obd_mode_0x2F_state = 0;
        uVar1 = REG_CIER_A;
        REG_CIER_A = uVar1 | 0x12;
      }
      else {
        uVar1 = REG_CFSR3_A;
        if ((uVar1 >> 4 & 0xf) == 0xe) {
          REG_TPU3A_CH1_PARAM1 = (ushort)((int)((uint)ign_dwell_time * 10) >> 4);
          uVar1 = REG_HSRR1_A;
          REG_HSRR1_A = uVar1 & 0xfff3 | 4;
          do {
            uVar1 = REG_HSRR1_A;
          } while (uVar1 != 0);
        }
        uVar1 = REG_CFSR2_A;
        if ((uVar1 & 0xf) == 0xe) {
          REG_TPU3A_CH4_PARAM1 = (ushort)((int)((uint)ign_dwell_time * 10) >> 4);
          uVar1 = REG_HSRR1_A;
          REG_HSRR1_A = uVar1 & 0xfcff | 0x100;
          do {
            uVar1 = REG_HSRR1_A;
          } while (uVar1 != 0);
        }
        obd_mode_0x2F_pulse_interval = DAT_003fc00d;
      }
    }
    break;
  case 6:
    obd_mode_0x2F_pulse_interval = obd_mode_0x2F_pulse_interval + 255;
    if (obd_mode_0x2F_pulse_interval == 0) {
      if (obd_mode_0x2F_timer == 0) {
        obd_mode_0x2F_state = 0;
        uVar1 = REG_CIER_A;
        REG_CIER_A = uVar1 | 0xc;
      }
      else {
        uVar1 = REG_CFSR3_A;
        if ((uVar1 >> 8 & 0xf) == 0xe) {
          REG_TPU3A_CH2_PARAM1 = (ushort)((int)((uint)ign_dwell_time * 10) >> 4);
          uVar1 = REG_HSRR1_A;
          REG_HSRR1_A = uVar1 & 0xffcf | 0x10;
          do {
            uVar1 = REG_HSRR1_A;
          } while (uVar1 != 0);
        }
        uVar1 = REG_CFSR3_A;
        if (uVar1 >> 0xc == 0xe) {
          REG_TPU3A_CH3_PARAM1 = (ushort)((int)((uint)ign_dwell_time * 10) >> 4);
          uVar1 = REG_HSRR1_A;
          REG_HSRR1_A = uVar1 & 0xff3f | 0x40;
          do {
            uVar1 = REG_HSRR1_A;
          } while (uVar1 != 0);
        }
        obd_mode_0x2F_pulse_interval = DAT_003fc00d;
      }
    }
    break;
  case 7:
    obd_mode_0x2F_pulse_interval = obd_mode_0x2F_pulse_interval + 255;
    if (obd_mode_0x2F_pulse_interval == 0) {
      if (obd_mode_0x2F_timer == 0) {
        obd_mode_0x2F_state = 0;
        uVar1 = REG_CIER_A;
        REG_CIER_A = uVar1 | 8;
      }
      else {
        uVar1 = REG_CFSR3_A;
        if (uVar1 >> 0xc == 0xe) {
          REG_TPU3A_CH3_PARAM1 = (ushort)((int)((uint)ign_dwell_time * 10) >> 4);
          uVar1 = REG_HSRR1_A;
          REG_HSRR1_A = uVar1 & 0xff3f | 0x40;
          do {
            uVar1 = REG_HSRR1_A;
          } while (uVar1 != 0);
        }
        obd_mode_0x2F_pulse_interval = DAT_003fc00d;
      }
    }
    break;
  case 8:
    obd_mode_0x2F_pulse_interval = obd_mode_0x2F_pulse_interval + 255;
    if (obd_mode_0x2F_pulse_interval == 0) {
      if (obd_mode_0x2F_timer == 0) {
        obd_mode_0x2F_state = 0;
        uVar1 = REG_CIER_A;
        REG_CIER_A = uVar1 | 0x10;
      }
      else {
        uVar1 = REG_CFSR2_A;
        if ((uVar1 & 0xf) == 0xe) {
          REG_TPU3A_CH4_PARAM1 = (ushort)((int)((uint)ign_dwell_time * 10) >> 4);
          uVar1 = REG_HSRR1_A;
          REG_HSRR1_A = uVar1 & 0xfcff | 0x100;
          do {
            uVar1 = REG_HSRR1_A;
          } while (uVar1 != 0);
        }
        obd_mode_0x2F_pulse_interval = DAT_003fc00d;
      }
    }
    break;
  case 9:
    if (obd_mode_0x2F_timer == 0) {
      obd_mode_0x2F_value = 0;
      obd_mode_0x2F_state = 0;
    }
    break;
  case 10:
    if (obd_mode_0x2F_timer == 0) {
      obd_mode_0x2F_value = 0;
      obd_mode_0x2F_state = 0;
    }
    break;
  case 0xb:
    if (obd_mode_0x2F_timer == 0) {
      obd_mode_0x2F_value = 0;
      obd_mode_0x2F_state = 0;
    }
    break;
  case 0xc:
    if (obd_mode_0x2F_timer == 0) {
      obd_mode_0x2F_value = 0;
      obd_mode_0x2F_state = 0;
    }
    break;
  case 0xd:
    if (obd_mode_0x2F_timer == 0) {
      obd_mode_0x2F_value = 0;
      obd_mode_0x2F_state = 0;
    }
    break;
  case 0xe:
    if (obd_mode_0x2F_timer == 0) {
      obd_mode_0x2F_value = 0;
      DAT_003f92d7 = 0;
      obd_mode_0x2F_state = 0;
    }
    else {
      DAT_003f92d7 = obd_mode_0x2F_value;
    }
    break;
  case 0xf:
    if (obd_mode_0x2F_timer == 0) {
      DAT_003fda9f = 0;
      DAT_003fda9e = 0;
      obd_mode_0x2F_state = 0;
    }
    break;
  case 0x10:
    if (obd_mode_0x2F_timer == 0) {
      DAT_003fda9f = 0;
      DAT_003fda9e = 0;
      obd_mode_0x2F_state = 0;
    }
    break;
  case 0x11:
    if (obd_mode_0x2F_timer == 0) {
      obd_mode_0x2F_value = 0;
      obd_mode_0x2F_state = 0;
    }
    break;
  case 0x12:
    if (obd_mode_0x2F_timer == 0) {
      DAT_003fda9f = 0;
      DAT_003fda9e = 0;
      obd_mode_0x2F_state = 0;
    }
    break;
  case 0x13:
    if (obd_mode_0x2F_timer == 0) {
      DAT_003fda9f = 0;
      DAT_003fda9e = 0;
      obd_mode_0x2F_state = 0;
    }
    break;
  case 0x14:
    if (obd_mode_0x2F_timer == 0) {
      DAT_003fda9f = 0;
      DAT_003fda9e = 0;
      obd_mode_0x2F_state = 0;
    }
    break;
  case 0x15:
    if (obd_mode_0x2F_timer == 0) {
      DAT_003fda9f = 0;
      DAT_003fda9e = 0;
      obd_mode_0x2F_state = 0;
    }
    break;
  case 0x16:
    if (obd_mode_0x2F_timer == 0) {
      DAT_003fda9f = 0;
      DAT_003fda9e = 0;
      obd_mode_0x2F_state = 0;
    }
    break;
  case 0x17:
    if (obd_mode_0x2F_timer == 0) {
      obd_mode_0x2F_value = 0;
      obd_mode_0x2F_state = 0;
    }
    break;
  case 0x18:
    if (obd_mode_0x2F_timer == 0) {
      obd_mode_0x2F_value = 0;
      obd_mode_0x2F_state = 0;
    }
    break;
  default:
    obd_mode_0x2F_state = 0;
  }
  return;
}



// K-Line mode 0x3B - writes VIN bytes to LEA storage

void obd_kline_mode_0x3B_vin_write
               (uint param_1,char param_2,char param_3,char param_4,char param_5,char param_6)

{
  uint uVar1;
  byte bVar2;
  
  uVar1 = param_1 & 0xff;
  if (uVar1 == 2) {
    LEA_ecu_VIN[0xf] = param_2;
    LEA_ecu_VIN[0x10] = param_3;
    obd_kline_send_vin_ack(param_1);
    if ((((LEA_ecu_VIN[0xd] == '9') && (LEA_ecu_VIN[0xe] == '9')) && (LEA_ecu_VIN[0xf] == '9')) &&
       (LEA_ecu_VIN[0x10] == '9')) {
      for (bVar2 = 0; bVar2 < 0x1e; bVar2 = bVar2 + 1) {
        LEA_base[bVar2] = '1';
      }
    }
  }
  else if ((uVar1 < 2) && (uVar1 != 0)) {
    LEA_ecu_VIN[8] = param_2;
    LEA_ecu_VIN[0xb] = param_3;
    LEA_ecu_VIN[0xc] = param_4;
    LEA_ecu_VIN[0xd] = param_5;
    LEA_ecu_VIN[0xe] = param_6;
    obd_kline_send_vin_ack(param_1);
    if (LEA_ecu_VIN[0xd] == '6') {
      LEA_ecu_VIN[9] = '6';
    }
    else if (LEA_ecu_VIN[0xd] == '7') {
      LEA_ecu_VIN[9] = '7';
    }
  }
  else {
    builtin_memcpy(obd_resp,"Hk\x10\x7f\x12",5);
    obd_resp[5] = 84;
    obd_resp_len = 5;
    obd_resp_i = 0;
    REG_SC1DR = 0x48;
  }
  return;
}



// Sends K-Line mode 0x3B VIN acknowledgement 0x7b

void obd_kline_send_vin_ack(uint8_t param_1)

{
  builtin_memcpy(obd_resp,"Hk\x10{",4);
  obd_resp[4] = param_1;
  obd_resp[5] = param_1 + 62;
  obd_resp_len = 5;
  obd_resp_i = 0;
  REG_SC1DR = 0x48;
  return;
}



// Initializes instruction BAT0 for memory translation, enables instruction MMU (IR bit in MSR), and
// configures instruction cache

void init_ibat_icache(void)

{
  return;
}



// Initializes SIU and UIMB module configuration registers (SIUMCR, UMCR) after reset

void init_siu(void)

{
  uint uVar1;
  
  uVar1 = REG_UMCR;
  REG_UMCR = uVar1 & 0x9fffffff | 0x60000000;
  uVar1 = REG_SIUMCR;
  REG_SIUMCR = uVar1 & 0xffffffdf | 0x20;
  uVar1 = REG_SIUMCR;
  REG_SIUMCR = uVar1 & 0xffffffef | 0x10;
  init_ibat_icache();
  return;
}



// Infinite loop for fatal error conditions

void infinite_loop(void)

{
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// PPS processing task (5ms)

void pps_5ms(void)

{
  sensor_adc_pps_1 = read_adc_pps_1();
  sensor_adc_pps_2 = read_adc_pps_2();
  pps_check(sensor_adc_pps_1,sensor_adc_pps_2);
  dev_pps_1 = convert_pps_1((int)(short)sensor_adc_pps_1);
  dev_pps_2 = convert_pps_2((int)(short)sensor_adc_pps_2);
  dev_pps_1_smooth = smooth_pps_1((int)(short)dev_pps_1);
  dev_pps_2_smooth = smooth_pps_2((int)(short)dev_pps_2);
  pps = pps_min;
  if ((CAL_idle_flow_pps_max < pps_min) && (pps_min < 0x400)) {
    pps_tps_target = lookup_2D_uint16_interpolated(16,pps_min,CAL_tps_target,CAL_tps_target_X_pps);
  }
  else {
    pps_tps_target = 0;
  }
  return;
}



// PPS offset learning task (5ms)

void pps_offset_5ms(void)

{
  pps_offset_timer = pps_offset_timer - 1;
  if ((short)pps_offset_timer < 1) {
    pps_offset_timer = (u16_time_5ms)CAL_sensor_pps_offset_time_between_step;
    learn_pps_1_offset((int)(short)sensor_adc_pps_1);
    learn_pps_2_offset((int)(short)sensor_adc_pps_2);
  }
  return;
}



// PPS sensor monitors (P2122/P2123/P2127/P2128)

void obd_check_pps(void)

{
  if ((CAL_obd_P2138 & 7) != 0) {
    if ((DAT_003fe048 & 4) == 0) {
      DAT_003f8f8a = 0;
      obd_clr_dtc(&CAL_obd_P2138,&LEA_obd_P2138_flags);
      if (DAT_003f8f88 < DAT_003fc469) {
        DAT_003f8f88 = DAT_003f8f88 + 1;
      }
    }
    else {
      obd_set_dtc(&CAL_obd_P2138,&LEA_obd_P2138_flags,&LEA_obd_P2138_engine_start_count,
                  &LEA_obd_P2138_warm_up_cycle_count,0x85a);
      DAT_003f8f88 = 0;
    }
  }
  if ((CAL_obd_P2122 & 7) != 0) {
    if (((DAT_003fe048 & 1) == 0) || (diag_channel[1].result != 1)) {
      DAT_003f8f8e = 0;
      obd_clr_dtc(&CAL_obd_P2122,&LEA_obd_P2122_flags);
      if (DAT_003f8f8c < DAT_003fc45f) {
        DAT_003f8f8c = DAT_003f8f8c + 1;
      }
    }
    else {
      obd_set_dtc(&CAL_obd_P2122,&LEA_obd_P2122_flags,&LEA_obd_P2122_engine_start_count,
                  &LEA_obd_P2122_warm_up_cycle_count,0x84a);
      DAT_003f8f8c = 0;
    }
  }
  if ((CAL_obd_P2123 & 7) != 0) {
    if (((DAT_003fe048 & 1) == 0) || (diag_channel[1].result != 2)) {
      DAT_003f8f92 = 0;
      obd_clr_dtc(&CAL_obd_P2123,&LEA_obd_P2123_flags);
      if (DAT_003f8f90 < DAT_003fc460) {
        DAT_003f8f90 = DAT_003f8f90 + 1;
      }
    }
    else {
      obd_set_dtc(&CAL_obd_P2123,&LEA_obd_P2123_flags,&LEA_obd_P2123_engine_start_count,
                  &LEA_obd_P2123_warm_up_cycle_count,0x84b);
      DAT_003f8f90 = 0;
    }
  }
  if ((CAL_obd_P2127 & 7) != 0) {
    if (((DAT_003fe048 & 2) == 0) || (diag_channel[2].result != 3)) {
      DAT_003f8f96 = 0;
      obd_clr_dtc(&CAL_obd_P2127,&LEA_obd_P2127_flags);
      if (DAT_003f8f94 < DAT_003fc461) {
        DAT_003f8f94 = DAT_003f8f94 + 1;
      }
    }
    else {
      obd_set_dtc(&CAL_obd_P2127,&LEA_obd_P2127_flags,&LEA_obd_P2127_engine_start_count,
                  &LEA_obd_P2127_warm_up_cycle_count,0x84f);
      DAT_003f8f94 = 0;
    }
  }
  if ((CAL_obd_P2128 & 7) != 0) {
    if (((DAT_003fe048 & 2) == 0) || (diag_channel[2].result != 4)) {
      DAT_003f8f9a = 0;
      obd_clr_dtc(&CAL_obd_P2128,&LEA_obd_P2128_flags);
      if (DAT_003f8f98 < DAT_003fc462) {
        DAT_003f8f98 = DAT_003f8f98 + 1;
      }
    }
    else {
      obd_set_dtc(&CAL_obd_P2128,&LEA_obd_P2128_flags,&LEA_obd_P2128_engine_start_count,
                  &LEA_obd_P2128_warm_up_cycle_count,0x850);
      DAT_003f8f98 = 0;
    }
  }
  if ((((DAT_003f8f88 == 0) || (DAT_003f8f8c == 0)) || (DAT_003f8f90 == 0)) ||
     ((DAT_003f8f94 == 0 || (DAT_003f8f98 == 0)))) {
    sensor_fault_flags = sensor_fault_flags | 0x4000;
  }
  return;
}



// Initializes PPS monitor state

void obd_init_pps(void)

{
  DAT_003f8f88 = DAT_003fc469;
  DAT_003f8f8c = DAT_003fc45f;
  DAT_003f8f90 = DAT_003fc460;
  DAT_003f8f94 = DAT_003fc461;
  DAT_003f8f98 = DAT_003fc462;
  obd_init_dtc(&CAL_obd_P2138,&LEA_obd_P2138_flags,0x85a);
  obd_init_dtc(&CAL_obd_P2122,&LEA_obd_P2122_flags,0x84a);
  obd_init_dtc(&CAL_obd_P2123,&LEA_obd_P2123_flags,0x84b);
  obd_init_dtc(&CAL_obd_P2127,&LEA_obd_P2127_flags,0x84f);
  obd_init_dtc(&CAL_obd_P2128,&LEA_obd_P2128_flags,0x850);
  return;
}



// PPS monitor cycle counter

void obd_cyc_pps(void)

{
  obd_cyc_dtc(&CAL_obd_P2138,&LEA_obd_P2138_flags,&LEA_obd_P2138_engine_start_count,
              &LEA_obd_P2138_warm_up_cycle_count,0x85a);
  obd_cyc_dtc(&CAL_obd_P2122,&LEA_obd_P2122_flags,&LEA_obd_P2122_engine_start_count,
              &LEA_obd_P2122_warm_up_cycle_count,0x84a);
  obd_cyc_dtc(&CAL_obd_P2123,&LEA_obd_P2123_flags,&LEA_obd_P2123_engine_start_count,
              &LEA_obd_P2123_warm_up_cycle_count,0x84b);
  obd_cyc_dtc(&CAL_obd_P2127,&LEA_obd_P2127_flags,&LEA_obd_P2127_engine_start_count,
              &LEA_obd_P2127_warm_up_cycle_count,0x84f);
  obd_cyc_dtc(&CAL_obd_P2128,&LEA_obd_P2128_flags,&LEA_obd_P2128_engine_start_count,
              &LEA_obd_P2128_warm_up_cycle_count,0x850);
  return;
}



// Initializes TPS state system - filters and warmup counters

void init_tps_state(void)

{
  DAT_003fdb50 = 1;
  DAT_003fdb51 = 1;
  DAT_003fdb52 = 0xf;
  filter_init_all();
  return;
}



// TPS/throttle state machine dispatcher

void tps_state_machine_dispatch(void)

{
  (*(code *)tps_state_table[tps_state_machine])();
  return;
}



// TPS state: Motor off - throttle closed

void tps_state_motor_off(void)

{
  ushort uVar1;
  
  REG_MPWMSM18_PULR = 0;
  uVar1 = REG_MPWMSM19_SCR;
  REG_MPWMSM19_SCR = uVar1 & 0xf7ff | 0x800;
  uVar1 = REG_MPWMSM17_SCR;
  REG_MPWMSM17_SCR = uVar1 & 0xf7ff;
  tps_state_motor_off_timer = 100;
  tps_state_machine = tps_state_machine + 1;
  return;
}



// TPS state: ADC capture for sensor reading

void tps_state_adc_capture(void)

{
  tps_state_motor_off_timer = tps_state_motor_off_timer + 255;
  if (tps_state_motor_off_timer == 0) {
    dev_tps_rest_position = REG_QADCA_RJURR0;
    tps_state_machine = tps_state_machine + 1;
  }
  return;
}



// TPS state: Motor drives to test position and checks stability

void tps_state_test_spring(void)

{
  ushort uVar1;
  u16_factor_1_1023 uVar2;
  int iVar3;
  uint uVar4;
  uint16_t uVar5;
  
  uVar4 = abs((uint)tps_state_test_target - (uint)tps_1_smooth);
  uVar2 = tps_1_smooth_history[1];
  if ((int)uVar4 < 6) {
    tps_state_test_target = 120;
  }
  tps_diff = tps_state_test_target - tps_1_smooth;
  tps_1_smooth_history[0] = tps_1_smooth_history[1];
  tps_1_smooth_history[1] = tps_1_smooth_history[2];
  tps_1_smooth_history[2] = tps_1_smooth_history[3];
  tps_1_smooth_history[3] = tps_1_smooth;
  if (DAT_003fdb52 == '\0') {
    tps_dt = adc_filter_update(&filter_tps_diff,tps_1_smooth - uVar2);
  }
  else {
    tps_dt = 0;
    DAT_003fdb52 = DAT_003fdb52 + -1;
  }
  iVar3 = (int)((uint)CAL_tps_ctrl_p_gain * (int)(short)tps_diff) / 100 +
          ((int)((uint)CAL_tps_ctrl_p_gain * (int)(short)tps_diff) >> 0x1f);
  tps_ctrl_p = iVar3 - (iVar3 >> 0x1f);
  tps_ctrl_i_sum = tps_ctrl_i_sum + (short)tps_diff;
  iVar3 = (int)(short)(tps_dt * CAL_tps_ctrl_d_gain) / 10 +
          ((int)(short)(tps_dt * CAL_tps_ctrl_d_gain) >> 0x1f);
  tps_ctrl_d = (short)iVar3 - (short)(iVar3 >> 0x1f);
  DAT_003fdb36 = CAL_tps_ctrl_i_gain;
  DAT_003fdb38 = (uint)CAL_tps_ctrl_i_limit;
  iVar3 = (int)((uint)CAL_tps_ctrl_i_gain * tps_ctrl_i_sum) / 10000 +
          ((int)((uint)CAL_tps_ctrl_i_gain * tps_ctrl_i_sum) >> 0x1f);
  tps_ctrl_i = iVar3 - (iVar3 >> 0x1f);
  uVar4 = abs(tps_ctrl_i);
  if ((int)DAT_003fdb38 < (int)uVar4) {
    if (tps_ctrl_i < 1) {
      tps_ctrl_i = -DAT_003fdb38;
      tps_ctrl_i_sum = (int)(DAT_003fdb38 * -10000) / (int)(uint)DAT_003fdb36;
    }
    else {
      tps_ctrl_i = DAT_003fdb38;
      tps_ctrl_i_sum = (int)(DAT_003fdb38 * 10000) / (int)(uint)DAT_003fdb36;
    }
  }
  uVar5 = lookup_2D_uint16_interpolated
                    (16,tps_1_smooth,CAL_tps_motor_duty_cycle,CAL_tps_motor_duty_cycle_X_tps);
  DAT_003fdb58 = uVar5 - 1024;
  tps_output = DAT_003fdb58 + (((short)tps_ctrl_p + (short)tps_ctrl_i) - tps_ctrl_d);
  uVar1 = REG_QADCB_RJURR10;
  DAT_003fdb5c = (tps_output * 0x3ff) / (int)(uint)uVar1;
  if (DAT_003fdb5c < 0) {
    iVar3 = (int)(DAT_003fdb5c * (uint)CAL_tps_period) / 0x3ff +
            ((int)(DAT_003fdb5c * (uint)CAL_tps_period) >> 0x1f);
    DAT_003fdb20 = -((short)iVar3 - (short)(iVar3 >> 0x1f));
    uVar1 = REG_MPWMSM19_SCR;
    REG_MPWMSM19_SCR = uVar1 & 0xf7ff | 0x800;
  }
  else {
    iVar3 = (int)(DAT_003fdb5c * (uint)CAL_tps_period) / 0x3ff +
            ((int)(DAT_003fdb5c * (uint)CAL_tps_period) >> 0x1f);
    DAT_003fdb20 = (short)iVar3 - (short)(iVar3 >> 0x1f);
    uVar1 = REG_MPWMSM19_SCR;
    REG_MPWMSM19_SCR = uVar1 & 0xf7ff;
  }
  DAT_003fdb24 = (undefined1)(((uint)DAT_003fdb20 * 100) / (uint)CAL_tps_period);
  if (((uint)CAL_tps_period * 0x32) / 100 < (uint)DAT_003fdb20) {
    if (DAT_003fdb26 != 0) {
      DAT_003fdb26 = DAT_003fdb26 + -1;
    }
  }
  else {
    DAT_003fdb26 = 100;
  }
  if (DAT_003fdb26 == 0) {
    DAT_003fdb20 = (ushort)(((uint)CAL_tps_period * 0x32) / 100);
  }
  REG_MPWMSM18_PULR = DAT_003fdb20;
  uVar1 = REG_MPWMSM17_SCR;
  REG_MPWMSM17_SCR = uVar1 & 0xf7ff | 0x800;
  if (tps_state_test_timer == 0) {
    if (tps_state_test_passed == 0) {
      tps_state_test_failed = 1;
      tps_state_machine = 4;
    }
  }
  else {
    tps_state_test_timer = tps_state_test_timer - 1;
    if (((tps_state_test_sample_tps_1 != 0) && (tps_state_test_sample_timer == 1)) &&
       (uVar4 = abs((uint)tps_state_test_sample_tps_1 - (uint)tps_1_smooth), (int)uVar4 < 3)) {
      tps_state_machine = tps_state_machine + 1;
      tps_state_test_passed = 1;
    }
  }
  if ((tps_state_test_target < 0x91) &&
     (tps_state_test_sample_timer = tps_state_test_sample_timer + 255,
     tps_state_test_sample_timer == 0)) {
    tps_state_test_sample_timer = 10;
    tps_state_test_sample_tps_1 = tps_1_smooth;
    tps_state_test_sample_tps_2 = REG_QADCA_RJURR1;
  }
  return;
}



// TPS state: Throttle calibration procedure

void tps_state_calibration(void)

{
  int iVar1;
  uint uVar2;
  
  if (((int)(CAL_sensor_tps_1_offset - 0x14) < (int)(uint)tps_state_test_sample_tps_1) &&
     ((uint)tps_state_test_sample_tps_1 < CAL_sensor_tps_1_offset + 0x14)) {
    iVar1 = ((int)(short)LEA_sensor_tps_1_offset - (int)(short)tps_state_test_sample_tps_1) * 0x32;
    iVar1 = iVar1 / 100 + (iVar1 >> 0x1f);
    LEA_sensor_tps_1_offset = LEA_sensor_tps_1_offset - ((short)iVar1 - (short)(iVar1 >> 0x1f));
  }
  else {
    LEA_sensor_tps_1_offset = CAL_sensor_tps_1_offset;
  }
  if (((int)(CAL_sensor_tps_2_offset - 0x14) < (int)(uint)tps_state_test_sample_tps_2) &&
     ((uint)tps_state_test_sample_tps_2 < CAL_sensor_tps_2_offset + 0x14)) {
    iVar1 = ((int)(short)LEA_sensor_tps_2_offset - (int)(short)tps_state_test_sample_tps_2) * 0x32;
    iVar1 = iVar1 / 100 + (iVar1 >> 0x1f);
    LEA_sensor_tps_2_offset = LEA_sensor_tps_2_offset - ((short)iVar1 - (short)(iVar1 >> 0x1f));
  }
  else {
    LEA_sensor_tps_2_offset = CAL_sensor_tps_2_offset;
  }
  iVar1 = (uint)LEA_sensor_tps_1_offset * 0x3ff +
          (uint)DAT_003f9422 * ((uint)DAT_003f940e - (uint)LEA_sensor_tps_1_offset);
  iVar1 = iVar1 / 0x3ff + (iVar1 >> 0x1f);
  tps_1_range_corrected_low = (short)iVar1 - (short)(iVar1 >> 0x1f);
  iVar1 = (uint)LEA_sensor_tps_1_offset * 0x3ff +
          (uint)DAT_003f9424 * ((uint)DAT_003f940e - (uint)LEA_sensor_tps_1_offset);
  iVar1 = iVar1 / 0x3ff + (iVar1 >> 0x1f);
  tps_1_range_corrected_high = (short)iVar1 - (short)(iVar1 >> 0x1f);
  iVar1 = (uint)LEA_sensor_tps_2_offset * 0x3ff +
          (uint)DAT_003f9426 * ((uint)DAT_003f9412 - (uint)LEA_sensor_tps_2_offset);
  iVar1 = iVar1 / 0x3ff + (iVar1 >> 0x1f);
  tps_2_range_corrected_low = (short)iVar1 - (short)(iVar1 >> 0x1f);
  iVar1 = (uint)LEA_sensor_tps_2_offset * 0x3ff +
          (uint)DAT_003f9428 * ((uint)DAT_003f9412 - (uint)LEA_sensor_tps_2_offset);
  iVar1 = iVar1 / 0x3ff + (iVar1 >> 0x1f);
  tps_2_range_corrected_high = (short)iVar1 - (short)(iVar1 >> 0x1f);
  uVar2 = abs((uint)tps_1_range_corrected_high - (uint)tps_1_range_corrected_low);
  tps_1_gain_corrected = (ushort)(0x10000 / (int)uVar2);
  uVar2 = abs((uint)tps_2_range_corrected_high - (uint)tps_2_range_corrected_low);
  tps_2_gain_computed = (short)(0x10000 / (int)uVar2);
  uVar2 = (uint)tps_1_gain_corrected *
          ((uint)dev_tps_rest_position - (uint)tps_1_range_corrected_low);
  dev_tps_rest_position = (short)((int)uVar2 >> 6) + (ushort)((int)uVar2 < 0 && (uVar2 & 0x3f) != 0)
  ;
  REG_MPWMSM18_PULR = 0;
  tps_state_machine = tps_state_machine + 1;
  return;
}



// TPS state: Active throttle motor control

void tps_state_motor_control(void)

{
  ushort uVar1;
  u16_factor_1_1023 uVar2;
  uint uVar3;
  int iVar4;
  uint16_t uVar5;
  
  sensor_adc_tps_1 = read_adc_tps_1();
  sensor_adc_tps_2 = read_adc_tps_2();
  if ((tps_state_sweep_enable == 0) || (engine_speed_1 != 0)) {
    DAT_003fdb64 = (int)(short)pps_tps_target + (uint)idle_tps_target;
    if ((short)CAL_tps_limit_h < DAT_003fdb64) {
      tps_target = CAL_tps_limit_h;
    }
    else if (DAT_003fdb64 < (short)CAL_tps_limit_l) {
      tps_target = CAL_tps_limit_l;
    }
    else {
      tps_target = (u16_factor_1_1023)DAT_003fdb64;
    }
  }
  else {
    tps_state_sweep_timer = tps_state_sweep_timer + 255;
    if (tps_state_sweep_timer == 0) {
      tps_state_sweep_timer = tps_state_sweep_time_between_step;
      if (tps_state_sweep_direction == 0) {
        tps_target = tps_target + tps_state_sweep_step;
        if ((int)(uint)tps_state_sweep_limit_h < (int)(short)tps_target) {
          tps_target = tps_state_sweep_limit_h;
          tps_state_sweep_direction = 1;
        }
      }
      else {
        tps_target = tps_target - tps_state_sweep_step;
        if ((short)tps_target < (short)tps_state_sweep_limit_l) {
          tps_target = tps_state_sweep_limit_l;
          tps_state_sweep_direction = 0;
        }
      }
    }
  }
  tps_target_smooth_dec =
       lookup_2D_uint8_interpolated
                 (8,(uint8_t)((short)tps_target >> 2),CAL_tps_smooth_dec,
                  CAL_tps_smooth_dec_X_tps_target);
  tps_target_smooth_inc =
       lookup_2D_uint8_interpolated
                 (8,(uint8_t)((short)tps_target >> 2),CAL_tps_smooth_inc,
                  CAL_tps_smooth_inc_X_tps_target);
  if (((tps_target_smooth_inc == 255) && ((short)tps_target_smooth < (short)tps_target)) ||
     ((tps_target_smooth_dec == 255 && ((short)tps_target < (short)tps_target_smooth)))) {
    tps_target_smooth = tps_target;
  }
  tps_smooth_timer = tps_smooth_timer - 1;
  if ((short)tps_smooth_timer < 1) {
    tps_smooth_timer = CAL_tps_smooth_time_between_step;
    if ((short)tps_target_smooth < (short)tps_target) {
      uVar3 = abs((int)(short)tps_target - (int)(short)tps_target_smooth);
      if ((int)(uint)tps_target_smooth_inc < (int)uVar3) {
        DAT_003fdb62 = 1;
        flags_to_hc08 = flags_to_hc08 | 4;
        if ((int)((int)(short)tps_target_smooth + (uint)tps_target_smooth_inc) < 0x400) {
          tps_target_smooth = tps_target_smooth + tps_target_smooth_inc;
        }
        else {
          tps_target_smooth = 1023;
        }
      }
      else {
        tps_target_smooth = tps_target;
        DAT_003fdb62 = 0;
        flags_to_hc08 = flags_to_hc08 & 0xfb;
      }
    }
    else if ((short)tps_target < (short)tps_target_smooth) {
      uVar3 = abs((int)(short)tps_target - (int)(short)tps_target_smooth);
      if ((int)(uint)tps_target_smooth_dec < (int)uVar3) {
        DAT_003fdb62 = 1;
        flags_to_hc08 = flags_to_hc08 | 4;
        if ((int)((int)(short)tps_target_smooth - (uint)tps_target_smooth_dec) < 0) {
          tps_target_smooth = 0;
        }
        else {
          tps_target_smooth = tps_target_smooth - tps_target_smooth_dec;
        }
      }
      else {
        tps_target_smooth = tps_target;
        DAT_003fdb62 = 0;
        flags_to_hc08 = flags_to_hc08 & 0xfb;
      }
    }
    else {
      tps_target_smooth = tps_target;
      DAT_003fdb62 = 0;
      flags_to_hc08 = flags_to_hc08 & 0xfb;
    }
  }
  tps_check(tps_1_smooth,sensor_adc_tps_2);
  uVar2 = tps_1_smooth_history[1];
  if ((int)(uint)DAT_003fe056 < (int)(short)tps_target_smooth) {
    tps_target_smooth = DAT_003fe056;
  }
  if (DAT_003fe056 == DAT_003fbfe4) {
    DAT_003fdb60 = tps_max;
  }
  else {
    DAT_003fdb60 = tps_1_smooth;
  }
  if (((DAT_003fe05b != '\0') || (DAT_003fe06a != '\0')) &&
     ((int)(uint)DAT_003f9526 < (int)(short)tps_target_smooth)) {
    tps_target_smooth = DAT_003f9526;
  }
  tps_diff = tps_target_smooth - tps_max;
  tps_1_smooth_history[0] = tps_1_smooth_history[1];
  tps_1_smooth_history[1] = tps_1_smooth_history[2];
  tps_1_smooth_history[2] = tps_1_smooth_history[3];
  tps_1_smooth_history[3] = DAT_003fdb60;
  if (DAT_003fdb52 == '\0') {
    tps_dt = adc_filter_update(&filter_tps_diff,DAT_003fdb60 - uVar2);
  }
  else {
    tps_dt = 0;
    DAT_003fdb52 = DAT_003fdb52 + -1;
  }
  iVar4 = (int)((uint)CAL_tps_ctrl_p_gain * (int)(short)tps_diff) / 100 +
          ((int)((uint)CAL_tps_ctrl_p_gain * (int)(short)tps_diff) >> 0x1f);
  tps_ctrl_p = iVar4 - (iVar4 >> 0x1f);
  tps_ctrl_i_sum = tps_ctrl_i_sum + (short)tps_diff;
  iVar4 = (int)(short)(tps_dt * CAL_tps_ctrl_d_gain) / 10 +
          ((int)(short)(tps_dt * CAL_tps_ctrl_d_gain) >> 0x1f);
  tps_ctrl_d = (short)iVar4 - (short)(iVar4 >> 0x1f);
  DAT_003fdb36 = CAL_tps_ctrl_i_gain;
  DAT_003fdb38 = (uint)CAL_tps_ctrl_i_limit;
  iVar4 = (int)((uint)CAL_tps_ctrl_i_gain * tps_ctrl_i_sum) / 10000 +
          ((int)((uint)CAL_tps_ctrl_i_gain * tps_ctrl_i_sum) >> 0x1f);
  tps_ctrl_i = iVar4 - (iVar4 >> 0x1f);
  uVar3 = abs(tps_ctrl_i);
  if ((int)DAT_003fdb38 < (int)uVar3) {
    if (tps_ctrl_i < 1) {
      tps_ctrl_i = -DAT_003fdb38;
      tps_ctrl_i_sum = (int)(DAT_003fdb38 * -10000) / (int)(uint)DAT_003fdb36;
    }
    else {
      tps_ctrl_i = DAT_003fdb38;
      tps_ctrl_i_sum = (int)(DAT_003fdb38 * 10000) / (int)(uint)DAT_003fdb36;
    }
  }
  uVar5 = lookup_2D_uint16_interpolated
                    (16,tps_1_smooth,CAL_tps_motor_duty_cycle,CAL_tps_motor_duty_cycle_X_tps);
  DAT_003fdb58 = uVar5 - 1024;
  tps_output = (uVar5 - 1024) + (((short)tps_ctrl_p + (short)tps_ctrl_i) - tps_ctrl_d);
  DAT_003fdb5c = (tps_output * 0x3ff) / (int)(uint)sensor_adc_ecu_voltage;
  if (DAT_003fdb5c < 0) {
    iVar4 = (int)(DAT_003fdb5c * (uint)CAL_tps_period) / 0x3ff +
            ((int)(DAT_003fdb5c * (uint)CAL_tps_period) >> 0x1f);
    DAT_003fdb20 = -((short)iVar4 - (short)(iVar4 >> 0x1f));
    uVar1 = REG_MPWMSM19_SCR;
    REG_MPWMSM19_SCR = uVar1 & 0xf7ff | 0x800;
  }
  else {
    iVar4 = (int)(DAT_003fdb5c * (uint)CAL_tps_period) / 0x3ff +
            ((int)(DAT_003fdb5c * (uint)CAL_tps_period) >> 0x1f);
    DAT_003fdb20 = (short)iVar4 - (short)(iVar4 >> 0x1f);
    uVar1 = REG_MPWMSM19_SCR;
    REG_MPWMSM19_SCR = uVar1 & 0xf7ff;
  }
  DAT_003fdb24 = (char)(((uint)DAT_003fdb20 * 100) / (uint)CAL_tps_period);
  if (((uint)CAL_tps_period * 0x32) / 100 < (uint)DAT_003fdb20) {
    if (DAT_003fdb26 != 0) {
      DAT_003fdb26 = DAT_003fdb26 + -1;
    }
  }
  else {
    DAT_003fdb26 = 100;
  }
  if (DAT_003fdb26 == 0) {
    DAT_003fdb20 = (ushort)(((uint)CAL_tps_period * 0x32) / 100);
  }
  if ((((sensor_fault_flags & 0x8000) == 0) && (DAT_003fe06e == '\0')) &&
     ((tps_both_fault == false && ((DAT_003fdb8a == '\0' && (tps_state_test_failed == 0)))))) {
    if (((shutdown_flags & 1) == 0) && (engine_speed_1 == 0)) {
      REG_MPWMSM18_PULR = 0;
    }
    else {
      REG_MPWMSM18_PULR = DAT_003fdb20;
      flags_to_hc08 = flags_to_hc08 & 0xef;
    }
  }
  else {
    REG_MPWMSM18_PULR = 0;
    uVar1 = REG_MPWMSM19_SCR;
    REG_MPWMSM19_SCR = uVar1 & 0xf7ff | 0x800;
    uVar1 = REG_MPWMSM17_SCR;
    REG_MPWMSM17_SCR = uVar1 & 0xf7ff;
    flags_to_hc08 = flags_to_hc08 | 0x10;
  }
  return;
}



// TPS/PPS correlation monitor (P2135/P2138/P2173)

void obd_check_tps_correlation(void)

{
  uint uVar1;
  
  if ((CAL_obd_P2135 & 7) != 0) {
    if ((DAT_003fdff4 & 0x40) == 0) {
      DAT_003f8fb8 = 0;
      obd_clr_dtc(&CAL_obd_P2135,&LEA_obd_P2135_flags);
      if (DAT_003fdb81 < DAT_003fc466) {
        DAT_003fdb81 = DAT_003fdb81 + 1;
      }
    }
    else {
      obd_set_dtc(&CAL_obd_P2135,&LEA_obd_P2135_flags,&LEA_obd_P2135_engine_start_count,
                  &LEA_obd_P2135_warm_up_cycle_count,0x857);
      DAT_003fdb81 = 0;
    }
  }
  if ((CAL_obd_P0122 & 7) != 0) {
    if (((DAT_003fdff4 & 1) == 0) || (diag_channel[4].result != 6)) {
      DAT_003f8fb0 = 0;
      obd_clr_dtc(&CAL_obd_P0122,&LEA_obd_P0122_flags);
      if (DAT_003fdb6c < DAT_003fc432) {
        DAT_003fdb6c = DAT_003fdb6c + 1;
      }
    }
    else {
      obd_set_dtc(&CAL_obd_P0122,&LEA_obd_P0122_flags,&LEA_obd_P0122_engine_start_count,
                  &LEA_obd_P0122_warm_up_cycle_count,0x7a);
      DAT_003fdb6c = 0;
    }
  }
  if ((CAL_obd_P0123 & 7) != 0) {
    if (((DAT_003fdff4 & 1) == 0) || (diag_channel[4].result != 7)) {
      DAT_003f8fb2 = 0;
      obd_clr_dtc(&CAL_obd_P0123,&LEA_obd_P0123_flags);
      if (DAT_003fdb7c < DAT_003fc433) {
        DAT_003fdb7c = DAT_003fdb7c + 1;
      }
    }
    else {
      obd_set_dtc(&CAL_obd_P0123,&LEA_obd_P0123_flags,&LEA_obd_P0123_engine_start_count,
                  &LEA_obd_P0123_warm_up_cycle_count,0x7b);
      DAT_003fdb7c = 0;
    }
  }
  if ((CAL_obd_P0222 & 7) != 0) {
    if (((DAT_003fdff4 & 2) == 0) || (diag_channel[5].result != 8)) {
      DAT_003f8fb4 = 0;
      obd_clr_dtc(&CAL_obd_P0222,&LEA_obd_P0222_flags);
      if (DAT_003fdb7d < DAT_003fc464) {
        DAT_003fdb7d = DAT_003fdb7d + 1;
      }
    }
    else {
      obd_set_dtc(&CAL_obd_P0222,&LEA_obd_P0222_flags,&LEA_obd_P0222_engine_start_count,
                  &LEA_obd_P0222_warm_up_cycle_count,0xde);
      DAT_003fdb7d = 0;
    }
  }
  if ((CAL_obd_P0223 & 7) != 0) {
    if (((DAT_003fdff4 & 2) == 0) || (diag_channel[5].result != 9)) {
      DAT_003f8fb6 = 0;
      obd_clr_dtc(&CAL_obd_P0223,&LEA_obd_P0223_flags);
      if (DAT_003fdb7e < DAT_003fc465) {
        DAT_003fdb7e = DAT_003fdb7e + 1;
      }
    }
    else {
      obd_set_dtc(&CAL_obd_P0223,&LEA_obd_P0223_flags,&LEA_obd_P0223_engine_start_count,
                  &LEA_obd_P0223_warm_up_cycle_count,0xdf);
      DAT_003fdb7e = 0;
    }
  }
  if ((((((CAL_obd_P0638 & 7) != 0) && (engine_is_running != false)) &&
       ((sensor_fault_flags & 4) == 0)) && ((sensor_fault_flags & 0x4000) == 0)) ||
     (tps_state_test_failed != 0)) {
    if ((((-(int)(short)CAL_load_use_alphaN_dt_tps_target_1_negative_min < (int)dt_tps_target_1) &&
         (dt_tps_target_1 < (short)CAL_load_use_alphaN_dt_tps_target_1_positive_min)) &&
        (uVar1 = abs((int)(short)tps_diff), (int)(uint)CAL_obd_P0638_threshold < (int)uVar1)) ||
       (tps_state_test_failed != 0)) {
      obd_P0638_fault_sample_count = obd_P0638_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P0638_fault_sample_count) {
        if (obd_P0638_debounce_count != 0) {
          obd_P0638_debounce_count = obd_P0638_debounce_count + 255;
        }
        if (obd_P0638_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P0638,&LEA_obd_P0638_flags,&LEA_obd_P0638_engine_start_count,
                      &LEA_obd_P0638_warm_up_cycle_count,0x27e);
        }
        else {
          obd_P0638_fault_sample_count = 0;
        }
      }
    }
    else {
      obd_P0638_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P0638,&LEA_obd_P0638_flags);
      if (obd_P0638_debounce_count < CAL_obd_P0638_debounce_threshold) {
        obd_P0638_debounce_count = obd_P0638_debounce_count + 1;
      }
    }
  }
  if (((CAL_obd_P2173 & 7) != 0) && (engine_is_running != false)) {
    if (((sensor_fault_flags & 0x10) == 0) &&
       (((load_use_alphaN == 0 && ((int)(uint)DAT_003fbfe8 < (int)load_diff)) &&
        ((short)(ushort)CAL_load_alphaN_adj_corr_limit_h <= (short)load_alphaN_adj)))) {
      obd_P2173_fault_sample_count = obd_P2173_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P2173_fault_sample_count) {
        if (obd_P2173_debounce_count != 0) {
          obd_P2173_debounce_count = obd_P2173_debounce_count + 255;
        }
        if (obd_P2173_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P2173,&LEA_obd_P2173_flags,&LEA_obd_P2173_engine_start_count,
                      &LEA_obd_P2173_warm_up_cycle_count,0x87d);
        }
        else {
          obd_P2173_fault_sample_count = 0;
        }
      }
    }
    else {
      obd_P2173_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P2173,&LEA_obd_P2173_flags);
      if (obd_P2173_debounce_count < CAL_obd_P2173_debounce_threshold) {
        obd_P2173_debounce_count = obd_P2173_debounce_count + 1;
      }
    }
  }
  if ((((CAL_obd_P2104 & 7) != 0) && (engine_is_running != false)) &&
     (((sensor_fault_flags & 4) == 0 &&
      (((sensor_fault_flags & 0x4000) == 0 && ((sensor_fault_flags & 0x8000) == 0)))))) {
    if ((hc08_obd_flags & 0x10) == 0) {
      obd_P2104_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P2104,&LEA_obd_P2104_flags);
      if (obd_P2104_debounce_count < CAL_obd_P2104_debounce_threshold) {
        obd_P2104_debounce_count = obd_P2104_debounce_count + 1;
      }
    }
    else {
      obd_P2104_fault_sample_count = obd_P2104_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P2104_fault_sample_count) {
        if (obd_P2104_debounce_count != 0) {
          obd_P2104_debounce_count = obd_P2104_debounce_count + 255;
        }
        if (obd_P2104_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P2104,&LEA_obd_P2104_flags,&LEA_obd_P2104_engine_start_count,
                      &LEA_obd_P2104_warm_up_cycle_count,0x838);
        }
        else {
          obd_P2104_fault_sample_count = 0;
        }
      }
    }
  }
  if (((((CAL_obd_P2105 & 7) != 0) && ((sensor_fault_flags & 4) == 0)) &&
      ((sensor_fault_flags & 0x4000) == 0)) && ((sensor_fault_flags & 0x8000) == 0)) {
    if ((hc08_obd_flags & 0x20) == 0) {
      obd_P2105_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P2105,&LEA_obd_P2105_flags);
      if (obd_P2105_debounce_count < CAL_obd_P2105_debounce_threshold) {
        obd_P2105_debounce_count = obd_P2105_debounce_count + 1;
      }
    }
    else {
      obd_P2105_fault_sample_count = obd_P2105_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P2105_fault_sample_count) {
        if (obd_P2105_debounce_count != 0) {
          obd_P2105_debounce_count = obd_P2105_debounce_count + 255;
        }
        if (obd_P2105_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P2105,&LEA_obd_P2105_flags,&LEA_obd_P2105_engine_start_count,
                      &LEA_obd_P2105_warm_up_cycle_count,0x839);
        }
        else {
          obd_P2105_fault_sample_count = 0;
        }
      }
    }
  }
  if ((CAL_obd_P2107 & 7) != 0) {
    if (((hc08_obd_flags & 0x40) == 0) && ((hc08_obd_flags & 0x80) == 0)) {
      obd_P2107_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P2107,&LEA_obd_P2107_flags);
      if (obd_P2107_debounce_count < CAL_obd_P2107_debounce_threshold) {
        obd_P2107_debounce_count = obd_P2107_debounce_count + 1;
      }
    }
    else {
      obd_P2107_fault_sample_count = obd_P2107_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P2107_fault_sample_count) {
        if (obd_P2107_debounce_count != 0) {
          obd_P2107_debounce_count = obd_P2107_debounce_count + 255;
        }
        if (obd_P2107_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P2107,&LEA_obd_P2107_flags,&LEA_obd_P2107_engine_start_count,
                      &LEA_obd_P2107_warm_up_cycle_count,0x83b);
          DAT_003fdb8a = 1;
        }
        else {
          obd_P2107_fault_sample_count = 0;
        }
      }
    }
  }
  if (((CAL_obd_P2106 & 7) != 0) && (engine_is_running != false)) {
    if ((DAT_003fe05b == '\0') && (DAT_003fe06a == '\0')) {
      obd_P2106_fault_sample_count = 0;
      obd_clr_dtc(&CAL_obd_P2106,&LEA_obd_P2106_flags);
      if (obd_P2106_debounce_count < CAL_obd_P2106_debounce_threshold) {
        obd_P2106_debounce_count = obd_P2106_debounce_count + 1;
      }
    }
    else {
      obd_P2106_fault_sample_count = obd_P2106_fault_sample_count + 1;
      if ((short)obd_fault_sample_threshold <= (short)obd_P2106_fault_sample_count) {
        if (obd_P2106_debounce_count != 0) {
          obd_P2106_debounce_count = obd_P2106_debounce_count + 255;
        }
        if (obd_P2106_debounce_count == 0) {
          obd_set_dtc(&CAL_obd_P2106,&LEA_obd_P2106_flags,&LEA_obd_P2106_engine_start_count,
                      &LEA_obd_P2106_warm_up_cycle_count,0x83a);
        }
        else {
          obd_P2106_fault_sample_count = 0;
        }
      }
    }
  }
  if (((CAL_obd_P2100 & 7) != 0) && ((hc08_obd_flags & 0x10) == 0)) {
    if ((DAT_003f930c & 0x10) == 0) {
      obd_clr_dtc(&CAL_obd_P2100,&LEA_obd_P2100_flags);
      if (obd_P2100_debounce_count < CAL_obd_P2100_debounce_threshold) {
        obd_P2100_debounce_count = obd_P2100_debounce_count + 1;
      }
    }
    else if (obd_P2100_debounce_count == 0) {
      obd_set_dtc(&CAL_obd_P2100,&LEA_obd_P2100_flags,&LEA_obd_P2100_engine_start_count,
                  &LEA_obd_P2100_warm_up_cycle_count,0x834);
    }
    else {
      obd_P2100_debounce_count = obd_P2100_debounce_count + 255;
    }
    DAT_003f930c = DAT_003f930c & 0xef;
  }
  if ((CAL_obd_P2102 & 7) != 0) {
    if ((DAT_003f930c & 8) == 0) {
      obd_clr_dtc(&CAL_obd_P2102,&LEA_obd_P2102_flags);
      if (obd_P2102_debounce_count < CAL_obd_P2102_debounce_threshold) {
        obd_P2102_debounce_count = obd_P2102_debounce_count + 1;
      }
    }
    else if (obd_P2102_debounce_count == 0) {
      obd_set_dtc(&CAL_obd_P2102,&LEA_obd_P2102_flags,&LEA_obd_P2102_engine_start_count,
                  &LEA_obd_P2102_warm_up_cycle_count,0x836);
    }
    else {
      obd_P2102_debounce_count = obd_P2102_debounce_count + 255;
    }
    DAT_003f930c = DAT_003f930c & 0xf7;
  }
  if ((CAL_obd_P2103 & 7) != 0) {
    if ((DAT_003f930c & 4) == 0) {
      obd_clr_dtc(&CAL_obd_P2103,&LEA_obd_P2103_flags);
      if (obd_P2103_debounce_count < CAL_obd_P2103_debounce_threshold) {
        obd_P2103_debounce_count = obd_P2103_debounce_count + 1;
      }
    }
    else if (obd_P2103_debounce_count == 0) {
      obd_set_dtc(&CAL_obd_P2103,&LEA_obd_P2103_flags,&LEA_obd_P2103_engine_start_count,
                  &LEA_obd_P2103_warm_up_cycle_count,0x837);
    }
    else {
      obd_P2103_debounce_count = obd_P2103_debounce_count + 255;
    }
    DAT_003f930c = DAT_003f930c & 0xfb;
  }
  if ((CAL_obd_P2108 & 7) != 0) {
    if ((DAT_003f930c & 1) == 0) {
      obd_clr_dtc(&CAL_obd_P2108,&LEA_obd_P2108_flags);
      if (obd_P2108_debounce_count < CAL_obd_P2108_debounce_threshold) {
        obd_P2108_debounce_count = obd_P2108_debounce_count + 1;
      }
    }
    else if (obd_P2108_debounce_count == 0) {
      obd_set_dtc(&CAL_obd_P2108,&LEA_obd_P2108_flags,&LEA_obd_P2108_engine_start_count,
                  &LEA_obd_P2108_warm_up_cycle_count,0x83c);
    }
    else {
      obd_P2108_debounce_count = obd_P2108_debounce_count + 255;
    }
    DAT_003f930c = DAT_003f930c & 0xfe;
  }
  if ((((DAT_003fdb81 == 0) || (DAT_003fdb6c == 0)) || (DAT_003fdb7c == 0)) ||
     ((DAT_003fdb7d == 0 || (DAT_003fdb7e == 0)))) {
    sensor_fault_flags = sensor_fault_flags | 4;
  }
  if ((obd_P0638_debounce_count == 0) || (obd_P2173_debounce_count == 0)) {
    sensor_fault_flags = sensor_fault_flags | 0x8000;
  }
  if (obd_P2173_debounce_count == 0) {
    flags_to_hc08 = flags_to_hc08 | 0x20;
  }
  if (obd_P2106_debounce_count == 0) {
    flags_to_hc08 = flags_to_hc08 | 8;
  }
  return;
}



// Initializes TPS/throttle monitor state

void obd_init_tps_throttle(void)

{
  DAT_003fdb6c = DAT_003fc432;
  DAT_003fdb7c = DAT_003fc433;
  DAT_003fdb7d = DAT_003fc464;
  DAT_003fdb7e = DAT_003fc465;
  obd_P0638_debounce_count = CAL_obd_P0638_debounce_threshold;
  obd_P2173_debounce_count = CAL_obd_P2173_debounce_threshold;
  DAT_003fdb81 = DAT_003fc466;
  obd_P2104_debounce_count = CAL_obd_P2104_debounce_threshold;
  obd_P2105_debounce_count = CAL_obd_P2105_debounce_threshold;
  obd_P2106_debounce_count = CAL_obd_P2106_debounce_threshold;
  obd_P2107_debounce_count = CAL_obd_P2107_debounce_threshold;
  obd_P2100_debounce_count = CAL_obd_P2100_debounce_threshold;
  obd_P2102_debounce_count = CAL_obd_P2102_debounce_threshold;
  obd_P2103_debounce_count = CAL_obd_P2103_debounce_threshold;
  obd_P2108_debounce_count = CAL_obd_P2108_debounce_threshold;
  obd_init_dtc(&CAL_obd_P0222,&LEA_obd_P0222_flags,0xde);
  obd_init_dtc(&CAL_obd_P0223,&LEA_obd_P0223_flags,0xdf);
  obd_init_dtc(&CAL_obd_P0123,&LEA_obd_P0123_flags,0x7b);
  obd_init_dtc(&CAL_obd_P0122,&LEA_obd_P0122_flags,0x7a);
  obd_init_dtc(&CAL_obd_P0638,&LEA_obd_P0638_flags,0x27e);
  obd_init_dtc(&CAL_obd_P2173,&LEA_obd_P2173_flags,0x87d);
  obd_init_dtc(&CAL_obd_P2135,&LEA_obd_P2135_flags,0x857);
  obd_init_dtc(&CAL_obd_P2104,&LEA_obd_P2104_flags,0x838);
  obd_init_dtc(&CAL_obd_P2105,&LEA_obd_P2105_flags,0x839);
  obd_init_dtc(&CAL_obd_P2106,&LEA_obd_P2106_flags,0x83a);
  obd_init_dtc(&CAL_obd_P2107,&LEA_obd_P2107_flags,0x83b);
  obd_init_dtc(&CAL_obd_P2100,&LEA_obd_P2100_flags,0x834);
  obd_init_dtc(&CAL_obd_P2102,&LEA_obd_P2102_flags,0x836);
  obd_init_dtc(&CAL_obd_P2103,&LEA_obd_P2103_flags,0x837);
  obd_init_dtc(&CAL_obd_P2108,&LEA_obd_P2108_flags,0x83c);
  return;
}



// TPS/throttle monitor cycle counter

void obd_cyc_tps_throttle(void)

{
  obd_cyc_dtc(&CAL_obd_P0123,&LEA_obd_P0123_flags,&LEA_obd_P0123_engine_start_count,
              &LEA_obd_P0123_warm_up_cycle_count,0x7b);
  obd_cyc_dtc(&CAL_obd_P0122,&LEA_obd_P0122_flags,&LEA_obd_P0122_engine_start_count,
              &LEA_obd_P0122_warm_up_cycle_count,0x7a);
  obd_cyc_dtc(&CAL_obd_P0223,&LEA_obd_P0223_flags,&LEA_obd_P0223_engine_start_count,
              &LEA_obd_P0223_warm_up_cycle_count,0xdf);
  obd_cyc_dtc(&CAL_obd_P0222,&LEA_obd_P0222_flags,&LEA_obd_P0222_engine_start_count,
              &LEA_obd_P0222_warm_up_cycle_count,0xde);
  obd_cyc_dtc(&CAL_obd_P0638,&LEA_obd_P0638_flags,&LEA_obd_P0638_engine_start_count,
              &LEA_obd_P0638_warm_up_cycle_count,0x27e);
  obd_cyc_dtc(&CAL_obd_P2173,&LEA_obd_P2173_flags,&LEA_obd_P2173_engine_start_count,
              &LEA_obd_P2173_warm_up_cycle_count,0x87d);
  obd_cyc_dtc(&CAL_obd_P2135,&LEA_obd_P2135_flags,&LEA_obd_P2135_engine_start_count,
              &LEA_obd_P2135_warm_up_cycle_count,0x857);
  obd_cyc_dtc(&CAL_obd_P2104,&LEA_obd_P2104_flags,&LEA_obd_P2104_engine_start_count,
              &LEA_obd_P2104_warm_up_cycle_count,0x838);
  obd_cyc_dtc(&CAL_obd_P2105,&LEA_obd_P2105_flags,&LEA_obd_P2105_engine_start_count,
              &LEA_obd_P2105_warm_up_cycle_count,0x839);
  obd_cyc_dtc(&CAL_obd_P2106,&LEA_obd_P2106_flags,&LEA_obd_P2106_engine_start_count,
              &LEA_obd_P2106_warm_up_cycle_count,0x83a);
  obd_cyc_dtc(&CAL_obd_P2107,&LEA_obd_P2107_flags,&LEA_obd_P2107_engine_start_count,
              &LEA_obd_P2107_warm_up_cycle_count,0x83b);
  obd_cyc_dtc(&CAL_obd_P2100,&LEA_obd_P2100_flags,&LEA_obd_P2100_engine_start_count,
              &LEA_obd_P2100_warm_up_cycle_count,0x834);
  obd_cyc_dtc(&CAL_obd_P2102,&LEA_obd_P2102_flags,&LEA_obd_P2102_engine_start_count,
              &LEA_obd_P2102_warm_up_cycle_count,0x836);
  obd_cyc_dtc(&CAL_obd_P2103,&LEA_obd_P2103_flags,&LEA_obd_P2103_engine_start_count,
              &LEA_obd_P2103_warm_up_cycle_count,0x837);
  obd_cyc_dtc(&CAL_obd_P2108,&LEA_obd_P2108_flags,&LEA_obd_P2108_engine_start_count,
              &LEA_obd_P2108_warm_up_cycle_count,0x83c);
  return;
}



// Updates 2nd-order IIR (biquad) filter with Q15 fixed-point coefficients

int16_t adc_filter_update(struct_filter_4th_order *filter,int16_t sample)

{
  filter->state[0] = filter->state[1];
  filter->state[1] = (int)sample - (int)(short)((int)filter->coef[0] * filter->state[0] >> 0xf);
  filter->state[2] = filter->state[3];
  filter->state[3] = filter->state[4];
  filter->state[4] =
       (int)(short)((int)filter->coef[1] * filter->state[1] +
                    (int)filter->coef[2] * filter->state[0] >> 0xf) -
       (int)(short)((int)filter->coef[3] * filter->state[3] +
                    (int)filter->coef[4] * filter->state[2] >> 0xf);
  return (int16_t)((int)filter->coef[5] * filter->state[4] +
                   (int)filter->coef[6] * filter->state[3] + (int)filter->coef[7] * filter->state[2]
                  >> 0xf);
}



// Initializes 2nd-order filter state structure

void filter_init_2nd_order
               (struct_filter_2nd_order *filter,int16_t c0,int16_t c1,int16_t c2,int16_t c3,
               int16_t c4)

{
  filter->state[0] = 0;
  filter->state[1] = 0;
  filter->state[2] = 0;
  filter->coef[0] = c0;
  filter->coef[1] = c1;
  filter->coef[2] = c2;
  filter->coef[3] = c3;
  filter->coef[4] = c4;
  return;
}



// Initializes 4th-order filter state structure

void filter_init_4th_order
               (struct_filter_4th_order *filter,int16_t c0,int16_t c1,int16_t c2,int16_t c3,
               int16_t c4,int16_t c5,int16_t c6,int16_t c7)

{
  filter->state[0] = 0;
  filter->state[1] = 0;
  filter->state[2] = 0;
  filter->state[3] = 0;
  filter->state[4] = 0;
  filter->coef[0] = c0;
  filter->coef[1] = c1;
  filter->coef[2] = c2;
  filter->coef[3] = c3;
  filter->coef[4] = c4;
  filter->coef[5] = c5;
  filter->coef[6] = c6;
  filter->coef[7] = c7;
  return;
}



// Initializes all ADC filter states

void filter_init_all(void)

{
  filter_init_4th_order(&filter_tps,5581,19173,19173,16403,14548,17205,29327,17205);
  filter_init_4th_order(&filter_unused_1,5581,19173,19173,16403,14548,17205,29327,17205);
  filter_init_4th_order(&filter_tps_diff,5581,19173,19173,16403,14548,17205,29327,17205);
  filter_init_4th_order(&filter_unused_2,5581,19173,19173,16403,14548,17205,29327,17205);
  filter_init_2nd_order(&filter_unused_3,-23551,9242,519,1038,519);
  filter_init_2nd_order(&filter_unused_4,-23551,9242,519,1038,519);
  return;
}



// Initializes IUMPR monitor state for O2/catalyst/VVT/EVAP

void obd_init_iumpr(void)

{
  byte bVar2;
  uint uVar1;
  
  if (((DAT_003fc08f <= coolant_smooth) && (coolant_smooth <= DAT_003fc090)) &&
     ((uint)coolant_smooth <= (uint)engine_air_smooth + (uint)DAT_003fc093)) {
    DAT_003fdce8 = DAT_003fdce8 | 8;
  }
  DAT_003f8fc8 = DAT_003fc09a;
  DAT_003f8fca = DAT_003fc094;
  DAT_003f8fcc = DAT_003fc096;
  DAT_003f8fce = DAT_003fc098;
  for (bVar2 = 0; bVar2 < 6; bVar2 = bVar2 + 1) {
    iumpr_monitor[bVar2].pass_count = LEA_obd_iumpr_pass_count[bVar2];
    iumpr_monitor[bVar2].passed = 0;
    iumpr_monitor[bVar2].fail_count = LEA_obd_iumpr_fail_count[bVar2];
    iumpr_monitor[bVar2].failed = 0;
    iumpr_monitor[bVar2].sensor_error = 0;
    iumpr_monitor[bVar2].ready = 0;
    iumpr_monitor[bVar2].test_id = (&DAT_003f87dc)[bVar2];
    if (bVar2 < DAT_003f87d8) {
      iumpr_monitor[bVar2].state = 0;
    }
    else if ((bVar2 < DAT_003f87d8) || ((uint)DAT_003f87d8 + (uint)DAT_003f87d9 <= (uint)bVar2)) {
      if (((uint)bVar2 < (uint)DAT_003f87d8 + (uint)DAT_003f87d9) ||
         ((uint)DAT_003f87d8 + (uint)DAT_003f87d9 + (uint)DAT_003f87da <= (uint)bVar2)) {
        iumpr_monitor[bVar2].state = 3;
      }
      else {
        iumpr_monitor[bVar2].state = 2;
      }
    }
    else {
      iumpr_monitor[bVar2].state = 1;
    }
  }
  for (uVar1 = 0; (uVar1 & 0xff) < 6; uVar1 = uVar1 + 1) {
    iumpr_ratio(uVar1);
  }
  return;
}



// Updates IUMPR (In-Use Monitor Performance Ratio) counters for O2/catalyst/VVT/EVAP monitors

void obd_check_iumpr(void)

{
  byte bVar1;
  uint uVar2;
  
  if (((((DAT_003fdce8 & 1) == 0) && (obd_P0335_debounce_count != 0)) &&
      (obd_P0340_debounce_count != 0)) && (DAT_003fc08a <= engine_runtime)) {
    if (LEA_obd_iumpr_ignition_count < 0xffff) {
      LEA_obd_iumpr_ignition_count = LEA_obd_iumpr_ignition_count + 1;
    }
    else {
      LEA_obd_iumpr_ignition_count = 0;
    }
    DAT_003fdce8 = DAT_003fdce8 | 1;
  }
  if (((engine_is_running) && ((int)(uint)DAT_003fc08c < (int)atmo_pressure)) &&
     (DAT_003fc08e < engine_air_smooth)) {
    if (DAT_003f8fca != 0) {
      DAT_003f8fca = DAT_003f8fca + -1;
    }
    if ((DAT_003f8fce != 0) && (DAT_003fc091 <= car_speed_smooth)) {
      DAT_003f8fce = DAT_003f8fce + -1;
    }
    if (((DAT_003f8fc8 == 0) || ((short)(ushort)CAL_idle_flow_pps_max <= (short)pps)) ||
       (DAT_003fc092 < car_speed_smooth)) {
      if (DAT_003f8fc8 != 0) {
        DAT_003f8fc8 = DAT_003fc09a;
      }
    }
    else {
      DAT_003f8fc8 = DAT_003f8fc8 + -1;
    }
  }
  else if (DAT_003f8fc8 != 0) {
    DAT_003f8fc8 = DAT_003fc09a;
  }
  if (((engine_is_running) && (DAT_003f8fcc != 0)) &&
     (((int)(uint)DAT_003fc08c < (int)atmo_pressure &&
      ((DAT_003fc088 < engine_air_smooth && (engine_air_smooth < DAT_003fc089)))))) {
    DAT_003f8fcc = DAT_003f8fcc + -1;
  }
  if (((((((LEA_obd_P0500_flags & 0x14) != 0) || ((LEA_obd_P0111_flags & 0x14) != 0)) ||
        ((LEA_obd_P0112_flags & 0x14) != 0)) ||
       ((((LEA_obd_P0113_flags & 0x14) != 0 || ((LEA_obd_P0106_flags & 0x14) != 0)) ||
        (((LEA_obd_P0107_flags & 0x14) != 0 ||
         (((LEA_obd_P0108_flags & 0x14) != 0 || ((LEA_obd_P0116_flags & 0x14) != 0)))))))) ||
      ((LEA_obd_P0117_flags & 0x14) != 0)) ||
     ((((((LEA_obd_P0118_flags & 0x14) != 0 || ((LEA_obd_P2122_flags & 0x14) != 0)) ||
        ((LEA_obd_P2123_flags & 0x14) != 0)) ||
       (((LEA_obd_P2127_flags & 0x14) != 0 || ((LEA_obd_P2128_flags & 0x14) != 0)))) ||
      ((LEA_obd_P2138_flags & 0x14) != 0)))) {
    DAT_003fdce8 = DAT_003fdce8 | 4;
  }
  if ((((DAT_003fdce8 & 2) == 0) && ((DAT_003fdce8 & 4) == 0)) &&
     ((DAT_003f8fca == 0 && ((DAT_003f8fce == 0 && (DAT_003f8fc8 == 0)))))) {
    if (LEA_obd_iumpr_obdcond_count < 0xffff) {
      LEA_obd_iumpr_obdcond_count = LEA_obd_iumpr_obdcond_count + 1;
    }
    else {
      LEA_obd_iumpr_obdcond_count = 0;
    }
    DAT_003fdce8 = DAT_003fdce8 | 2;
  }
  for (bVar1 = 0; bVar1 < 6; bVar1 = bVar1 + 1) {
    if ((*iumpr_list[bVar1] & 0x94) == 0) {
      if ((*iumpr_list[bVar1] & 8) != 0) {
        iumpr_monitor[bVar1].ready = 1;
      }
    }
    else {
      iumpr_monitor[bVar1].sensor_error = 1;
    }
  }
  for (uVar2 = 0; (uVar2 & 0xff) < 6; uVar2 = uVar2 + 1) {
    if (iumpr_monitor[uVar2 & 0xff].test_id == 133) {
      if (((iumpr_monitor[uVar2 & 0xff].ready != 0) && (iumpr_monitor[uVar2 & 0xff].failed == 0)) &&
         ((iumpr_monitor[uVar2 & 0xff].sensor_error == 0 &&
          (((DAT_003fdce8 & 4) == 0 && ((DAT_003fdce8 & 0x10) != 0)))))) {
        iumpr_fail(uVar2);
      }
    }
    else if ((((iumpr_monitor[uVar2 & 0xff].ready != 0) && (iumpr_monitor[uVar2 & 0xff].failed == 0)
              ) && (iumpr_monitor[uVar2 & 0xff].sensor_error == 0)) && ((DAT_003fdce8 & 4) == 0)) {
      iumpr_fail(uVar2);
    }
    if (iumpr_monitor[uVar2 & 0xff].state == 3) {
      if ((((DAT_003fdce8 & 2) != 0) && (iumpr_monitor[uVar2 & 0xff].passed == 0)) &&
         (((iumpr_monitor[uVar2 & 0xff].sensor_error == 0 &&
           ((DAT_003f8fcc == 0 && ((DAT_003fdce8 & 8) != 0)))) && ((DAT_003fdce8 & 4) == 0)))) {
        iumpr_pass(uVar2);
      }
    }
    else if (((((DAT_003fdce8 & 2) != 0) && (iumpr_monitor[uVar2 & 0xff].passed == 0)) &&
             (iumpr_monitor[uVar2 & 0xff].sensor_error == 0)) && ((DAT_003fdce8 & 4) == 0)) {
      iumpr_pass(uVar2);
    }
  }
  return;
}



// Increments IUMPR fail counter for specified monitor index

void iumpr_fail(uint param_1)

{
  if (iumpr_monitor[param_1 & 0xff].fail_count < 0xffff) {
    iumpr_monitor[param_1 & 0xff].fail_count = iumpr_monitor[param_1 & 0xff].fail_count + 1;
  }
  else {
    iumpr_monitor[param_1 & 0xff].pass_count =
         (uint16_t)((int)(uint)iumpr_monitor[param_1 & 0xff].pass_count >> 1);
    iumpr_monitor[param_1 & 0xff].fail_count =
         (uint16_t)((int)(uint)iumpr_monitor[param_1 & 0xff].fail_count >> 1);
    iumpr_monitor[param_1 & 0xff].fail_count = iumpr_monitor[param_1 & 0xff].fail_count + 1;
  }
  LEA_obd_iumpr_fail_count[param_1 & 0xff] = iumpr_monitor[param_1 & 0xff].fail_count;
  LEA_obd_iumpr_pass_count[param_1 & 0xff] = iumpr_monitor[param_1 & 0xff].pass_count;
  iumpr_monitor[param_1 & 0xff].failed = 1;
  iumpr_ratio(param_1);
  return;
}



// Increments IUMPR pass counter for specified monitor index

void iumpr_pass(uint param_1)

{
  if (iumpr_monitor[param_1 & 0xff].pass_count < 0xffff) {
    iumpr_monitor[param_1 & 0xff].pass_count = iumpr_monitor[param_1 & 0xff].pass_count + 1;
  }
  else {
    iumpr_monitor[param_1 & 0xff].pass_count =
         (uint16_t)((int)(uint)iumpr_monitor[param_1 & 0xff].pass_count >> 1);
    iumpr_monitor[param_1 & 0xff].fail_count =
         (uint16_t)((int)(uint)iumpr_monitor[param_1 & 0xff].fail_count >> 1);
    iumpr_monitor[param_1 & 0xff].pass_count = iumpr_monitor[param_1 & 0xff].pass_count + 1;
  }
  LEA_obd_iumpr_fail_count[param_1 & 0xff] = iumpr_monitor[param_1 & 0xff].fail_count;
  LEA_obd_iumpr_pass_count[param_1 & 0xff] = iumpr_monitor[param_1 & 0xff].pass_count;
  iumpr_monitor[param_1 & 0xff].passed = 1;
  iumpr_ratio(param_1);
  return;
}



// Calculates IUMPR fail/pass ratio for specified monitor index

void iumpr_ratio(uint param_1)

{
  uint uVar1;
  
  if (iumpr_monitor[param_1 & 0xff].fail_count == 0) {
    iumpr_monitor[param_1 & 0xff].ratio = 0;
  }
  else if ((iumpr_monitor[param_1 & 0xff].pass_count == 0) &&
          (iumpr_monitor[param_1 & 0xff].fail_count != 0)) {
    iumpr_monitor[param_1 & 0xff].ratio = 65535;
  }
  else {
    uVar1 = ((uint)iumpr_monitor[param_1 & 0xff].fail_count * 0x2005) /
            (uint)iumpr_monitor[param_1 & 0xff].pass_count;
    if (uVar1 < 0x10000) {
      iumpr_monitor[param_1 & 0xff].ratio = (uint16_t)uVar1;
    }
    else {
      iumpr_monitor[param_1 & 0xff].ratio = 65535;
    }
  }
  iumpr_best(param_1);
  return;
}



// WARNING: Inlined function: push_26to31
// WARNING: Inlined function: pop_26to31
// Finds best IUMPR ratio among monitors with same state

void iumpr_best(uint param_1)

{
  byte bVar1;
  uint16_t uVar2;
  uint16_t uVar3;
  uint16_t uVar4;
  uint16_t uVar5;
  byte bVar6;
  
  uVar5 = iumpr_monitor[param_1 & 0xff].ratio;
  uVar3 = iumpr_monitor[param_1 & 0xff].fail_count;
  uVar4 = iumpr_monitor[param_1 & 0xff].pass_count;
  uVar2 = iumpr_monitor[param_1 & 0xff].test_id;
  bVar1 = iumpr_monitor[param_1 & 0xff].state;
  for (bVar6 = 0; bVar6 < 6; bVar6 = bVar6 + 1) {
    if ((bVar1 == iumpr_monitor[bVar6].state) &&
       ((iumpr_monitor[bVar6].ratio < uVar5 ||
        ((uVar5 == iumpr_monitor[bVar6].ratio && (uVar4 < iumpr_monitor[bVar6].pass_count)))))) {
      uVar5 = iumpr_monitor[bVar6].ratio;
      uVar2 = iumpr_monitor[bVar6].test_id;
      uVar4 = iumpr_monitor[bVar6].pass_count;
      uVar3 = iumpr_monitor[bVar6].fail_count;
    }
  }
  *(uint16_t *)(&DAT_003fddca + (uint)bVar1 * 8) = uVar2;
  (&DAT_003fddce)[(uint)bVar1 * 4] = uVar3;
  (&DAT_003fddcc)[(uint)bVar1 * 4] = uVar4;
  *(uint16_t *)(&DAT_003fddd0 + (uint)bVar1 * 8) = uVar5;
  return;
}



// WARNING: Inlined function: push_27to31
// WARNING: Inlined function: pop_27to31
// Main traction control logic - wheel slip detection and intervention

void traction_control(void)

{
  uint uVar1;
  byte bVar3;
  uint uVar2;
  ushort uVar4;
  int iVar5;
  uint unaff_r31;
  
  if (wheel_period_fl == 65535) {
    wheel_speed_fl = 0;
  }
  else {
    wheel_speed_fl =
         (u16_speed_1_100kph)
         (((uint)CAL_tc_front_tyre_circumference * 360000) /
         ((uint)wheel_period_fl * (uint)CAL_tc_abs_ring_teeth_count));
  }
  if (wheel_period_fr == 65535) {
    wheel_speed_fr = 0;
  }
  else {
    wheel_speed_fr =
         (u16_speed_1_100kph)
         (((uint)CAL_tc_front_tyre_circumference * 360000) /
         ((uint)wheel_period_fr * (uint)CAL_tc_abs_ring_teeth_count));
  }
  if (wheel_period_rl == 65535) {
    wheel_speed_rl = 0;
  }
  else {
    wheel_speed_rl =
         (u16_speed_1_100kph)
         (((uint)CAL_tc_rear_tyre_circumference * 360000) /
         ((uint)wheel_period_rl * (uint)CAL_tc_abs_ring_teeth_count));
  }
  if (wheel_period_rr == 65535) {
    wheel_speed_rr = 0;
  }
  else {
    wheel_speed_rr =
         (u16_speed_1_100kph)
         (((uint)CAL_tc_rear_tyre_circumference * 360000) /
         ((uint)wheel_period_rr * (uint)CAL_tc_abs_ring_teeth_count));
  }
  if (wheel_speed_fr < wheel_speed_fl) {
    wheel_speed_f_max_1 = wheel_speed_fl;
  }
  else {
    wheel_speed_f_max_1 = wheel_speed_fr;
  }
  wheel_speed_f_max_2 = (u8_speed_kph)(wheel_speed_f_max_1 / 100);
  if (wheel_speed_rr < wheel_speed_rl) {
    wheel_speed_r_max = wheel_speed_rl;
    uVar4 = wheel_period_rl;
  }
  else {
    wheel_speed_r_max = wheel_speed_rr;
    uVar4 = wheel_period_rr;
  }
  uVar1 = abs((int)(short)wheel_speed_rl - (int)(short)wheel_speed_rr);
  wheel_speed_rear_diff = (u16_speed_1_100kph)uVar1;
  uVar1 = abs((int)(short)wheel_speed_fl - (int)(short)wheel_speed_fr);
  wheel_speed_front_diff = (u16_speed_1_100kph)uVar1;
  wheel_speed_diff = wheel_speed_front_diff;
  if (wheel_speed_rear_diff <= wheel_speed_front_diff) {
    wheel_speed_diff = wheel_speed_rear_diff;
  }
  if ((uVar4 == 0xffff) || ((sensor_fault_flags & 0x200) != 0)) {
    car_speed_smooth = 0;
  }
  else {
    if (CAL_tc_abs_ring_teeth_count == 0) {
      uVar1 = (0x100 - (uint)CAL_tc_car_speed_reactivity) * car_speed_smooth_x;
      car_speed_smooth_x =
           ((int)uVar1 >> 8) + (uint)((int)uVar1 < 0 && (uVar1 & 0xff) != 0) +
           (uint)CAL_tc_car_speed_reactivity *
           (((uint)CAL_tc_rear_tyre_circumference * 36000) / (uint)uVar4);
    }
    else {
      uVar1 = (0x100 - (uint)CAL_tc_car_speed_reactivity) * car_speed_smooth_x;
      car_speed_smooth_x =
           ((int)uVar1 >> 8) + (uint)((int)uVar1 < 0 && (uVar1 & 0xff) != 0) +
           (uint)CAL_tc_car_speed_reactivity *
           (((uint)CAL_tc_rear_tyre_circumference * 36000) /
           ((uint)uVar4 * (uint)CAL_tc_abs_ring_teeth_count));
    }
    if ((int)(((int)car_speed_smooth_x >> 8) +
             (uint)((int)car_speed_smooth_x < 0 && (car_speed_smooth_x & 0xff) != 0)) < 0xa00) {
      iVar5 = (int)car_speed_smooth_x / 0xa00 + ((int)car_speed_smooth_x >> 0x1f);
      car_speed_smooth = (char)iVar5 - (char)(iVar5 >> 0x1f);
    }
    else {
      car_speed_smooth = 255;
    }
  }
  if (wheel_speed_f_max_1 < wheel_speed_r_max) {
    iVar5 = ((uint)wheel_speed_r_max * 100) / (uint)wheel_speed_f_max_1 - 100;
    if (iVar5 < 0x100) {
      tc_slip = (u8_factor_1_100)iVar5;
    }
    else {
      tc_slip = 255;
    }
  }
  else {
    tc_slip = 0;
  }
  uVar4 = (short)pps >> 2;
  if ((tc_flags & 0x80) == 0) {
    tc_min_speed = CAL_tc_front_speed_min;
    bVar3 = lookup_3D_uint8_interpolated
                      (4,4,(ushort)wheel_speed_f_max_2,uVar4 & 0xff,CAL_tc_slip_target_base,
                       CAL_tc_slip_target_base_X_speed_front,CAL_tc_slip_target_base_Y_pps);
    unaff_r31 = (uint)bVar3;
  }
  else {
    if (LEA_tc_launchcontrol_revlimit < 0x2134) {
      if (sensor_adc_tc_knob < 0x3b1) {
        iVar5 = (0xe6 - (uint)tc_slip_target) *
                ((uint)LEA_tc_launchcontrol_revlimit / (uint)CAL_misc_gears[0]);
        iVar5 = iVar5 / 0xff + (iVar5 >> 0x1f);
        tc_min_speed = (char)iVar5 - (char)(iVar5 >> 0x1f);
      }
      else {
        tc_min_speed = (byte)((((uint)LEA_tc_launchcontrol_revlimit / (uint)CAL_misc_gears[0]) *
                              0xe6) / 0xff);
      }
    }
    else {
      tc_min_speed = CAL_tc_front_speed_min;
    }
    if (sensor_adc_tc_knob < 0x30) {
      tc_state = 0;
      bVar3 = lookup_3D_uint8_interpolated
                        (4,4,(ushort)wheel_speed_f_max_2,uVar4 & 0xff,CAL_tc_slip_target_base,
                         CAL_tc_slip_target_base_X_speed_front,CAL_tc_slip_target_base_Y_pps);
      unaff_r31 = (uint)bVar3;
      tc_flags = tc_flags | 8;
    }
    else if (sensor_adc_tc_knob < 0x3b1) {
      tc_state = 1;
      bVar3 = lookup_3D_uint8_interpolated
                        (4,4,(ushort)wheel_speed_f_max_2,uVar4 & 0xff,CAL_tc_slip_target_base,
                         CAL_tc_slip_target_base_X_speed_front,CAL_tc_slip_target_base_Y_pps);
      unaff_r31 = (int)(uint)sensor_adc_tc_knob >> (bVar3 + 5 & 0x3f) & 0xffff;
      tc_flags = tc_flags | 8;
    }
    else {
      tc_state = 3;
      tc_flags = tc_flags & 0xf7;
    }
  }
  tc_slip_target = (u8_factor_1_100)unaff_r31;
  if ((tc_flags & 4) == 0) {
    if ((unaff_r31 & 0xffff) + (uint)CAL_tc_slip_target_adj < 0xff) {
      tc_slip_target = tc_slip_target + CAL_tc_slip_target_adj;
    }
    else {
      tc_slip_target = 255;
    }
  }
  if (tc_slip_target < tc_slip) {
    uVar1 = (uint)tc_slip - (uint)tc_slip_target & 0xff;
  }
  else {
    uVar1 = 0;
  }
  if (uVar1 < tc_slip_diff_smooth) {
    uVar2 = (0x100 - (uint)CAL_tc_slip_reactivity) * tc_slip_diff_smooth_x;
    tc_slip_diff_smooth_x =
         ((int)uVar2 >> 8) + (uint)((int)uVar2 < 0 && (uVar2 & 0xff) != 0) +
         CAL_tc_slip_reactivity * uVar1;
    tc_slip_diff_smooth =
         (char)(tc_slip_diff_smooth_x >> 8) +
         ((int)tc_slip_diff_smooth_x < 0 && (tc_slip_diff_smooth_x & 0xff) != 0);
  }
  else {
    tc_slip_diff_smooth = (u8_factor_1_100)uVar1;
  }
  if ((((CAL_tc_mode == 0) || (CAL_tc_front_speed_max <= wheel_speed_f_max_2)) ||
      (wheel_speed_f_max_2 <= tc_min_speed)) ||
     (((engine_speed_2 <= CAL_tc_engine_speed_min || ((dfso_flags & 1) != 0)) ||
      (((tc_flags & 8) == 0 || (LEA_tc_button_fitted != true)))))) {
    tc_flags = tc_flags & 0xfc;
    ign_adv_adj_by_tc = 255;
    tc_fuelcut = 255;
  }
  else {
    if (CAL_tc_slip_min < tc_slip_diff_smooth) {
      tc_flags = tc_flags | 3;
      tc_fuelcut = lookup_2D_uint8_interpolated
                             (16,tc_slip_diff_smooth,CAL_tc_fuelcut,CAL_tc_fuelcut_X_slip);
      uVar1 = (int)((uint)tc_slip_diff_smooth * (uint)CAL_tc_slip_to_retard_ratio) >> 6;
      if (uVar1 < 0x100) {
        tc_retard_adj2 = (u8_factor_1_255)uVar1;
      }
      else {
        tc_retard_adj2 = 255;
      }
    }
    else {
      tc_flags = tc_flags & 0xfd | 1;
      tc_retard_adj2 = 0;
      tc_fuelcut = 255;
    }
    if ((int)(0xff - ((uint)tc_retard_adj2 + (uint)tc_retard_adj1)) <
        (int)(uint)CAL_tc_ign_adv_adj_limit) {
      ign_adv_adj_by_tc = CAL_tc_ign_adv_adj_limit;
    }
    else {
      ign_adv_adj_by_tc = 255 - (tc_retard_adj1 + tc_retard_adj2);
    }
  }
  return;
}



// Traction control task (5ms)

void traction_control_5ms(void)

{
  byte bVar1;
  
  if (((LEA_obd_iumpr_ignition_count < 6) && ((DAT_003fd520 & 0x20) == 0)) && (10 < ecu_runtime)) {
    LEA_tc_button_fitted = true;
  }
  bVar1 = tc_flags;
  if (((sensor_adc_tc_button < 400) && ((tc_flags & 0x10) == 0)) && (LEA_tc_button_fitted == true))
  {
    if (CAL_tc_mode == 2) {
      if ((tc_flags & 0x80) == 0) {
        DAT_003f8804 = DAT_003f8804 + -1;
        if (DAT_003f8804 == 0) {
          bVar1 = tc_flags | 0x90;
        }
      }
      else {
        tc_state = '\0';
        DAT_003f8804 = 400;
        bVar1 = tc_flags & 0x7f | 0x18;
      }
    }
    else if (CAL_tc_mode == 1) {
      if (tc_state == '\x03') {
        tc_state = '\0';
        DAT_003f8804 = 400;
        bVar1 = tc_flags & 0x7f | 0x18;
      }
      else {
        DAT_003f8804 = DAT_003f8804 + -1;
        bVar1 = tc_flags & 0x7f;
        if (DAT_003f8804 == 0) {
          tc_state = '\x03';
          bVar1 = tc_flags & 0x77 | 0x10;
        }
      }
    }
  }
  else if (600 < sensor_adc_tc_button) {
    DAT_003f8804 = 400;
    bVar1 = tc_flags & 0xef;
  }
  tc_flags = bVar1;
  if (((tc_flags & 8) == 0) &&
     ((5 < LEA_obd_iumpr_ignition_count || (LEA_tc_button_fitted == true)))) {
    tc_flags = tc_flags | 0x20;
    L9822E_outputs = L9822E_outputs | 0x20;
  }
  else {
    if ((tc_flags & 2) == 0) {
      DAT_003f8fe4 = DAT_003f8fe4 + 1;
      if (0x31 < DAT_003f8fe4) {
        tc_flags = tc_flags & 0xdf;
        DAT_003f8fe4 = 0;
      }
    }
    else if ((tc_flags & 0x40) == 0) {
      tc_flags = tc_flags ^ 0x60;
      DAT_003f8fe4 = 0;
    }
    else {
      DAT_003f8fe4 = DAT_003f8fe4 + 1;
      if (0x31 < DAT_003f8fe4) {
        tc_flags = tc_flags ^ 0x40;
      }
    }
    if (((tc_flags & 0x80) == 0) && ((tc_flags & 0x20) == 0)) {
      L9822E_outputs = L9822E_outputs & 0xdf;
    }
    else {
      L9822E_outputs = L9822E_outputs | 0x20;
    }
  }
  if (CAL_tc_slip_adj_left_right_enable < wheel_speed_diff) {
    if (tc_slip_target_adj_timer == 0) {
      tc_flags = tc_flags | 4;
    }
    else {
      tc_slip_target_adj_timer = tc_slip_target_adj_timer - 1;
    }
  }
  else {
    tc_flags = tc_flags & 0xfb;
    tc_slip_target_adj_timer = CAL_tc_slip_target_adj_time;
  }
  if ((tc_flags & 2) == 0) {
    tc_step_timer = CAL_tc_time_between_step;
    if (tc_retard_adj1 != 0) {
      tc_retard_adj1 = tc_retard_adj1 + 255;
    }
  }
  else if (tc_step_timer == 0) {
    tc_step_timer = CAL_tc_time_between_step;
    if (CAL_tc_ign_adv_adj_limit < ign_adv_adj_by_tc) {
      tc_retard_adj1 = tc_retard_adj1 + 1;
    }
    else if (tc_retard_adj1 != 0) {
      tc_retard_adj1 = tc_retard_adj1 + 255;
    }
  }
  else {
    tc_step_timer = tc_step_timer - 1;
  }
  if ((((engine_speed_2 == 0) && (CAL_tc_mode == 2)) && (LEA_tc_button_fitted == true)) &&
     (0x3b6 < pps_min)) {
    if (DAT_003f8802 == 0) {
      LEA_tc_launchcontrol_revlimit = sensor_adc_tc_knob * 8 + 1000;
      if (LEA_tc_launchcontrol_revlimit < 0x2135) {
        if (LEA_tc_launchcontrol_revlimit < 2000) {
          LEA_tc_launchcontrol_revlimit = 2000;
        }
      }
      else {
        LEA_tc_launchcontrol_revlimit = 8500;
      }
    }
    else {
      DAT_003f8802 = DAT_003f8802 + -1;
    }
  }
  else {
    DAT_003f8802 = 1000;
  }
  return;
}



// Initializes HC08 safety processor communication

void hc08_init(void)

{
  ushort uVar1;
  
  DAT_003f8fe8 = 0;
  sci2_init();
  uVar1 = REG_MPIOSMDR;
  REG_MPIOSMDR = uVar1 & 0xbfff;
  uVar1 = REG_MPIOSMDDR;
  REG_MPIOSMDDR = uVar1 | 0x4000;
  uVar1 = REG_MPIOSMDR;
  REG_MPIOSMDR = uVar1 & 0xbfff | 0x4000;
  flags_to_hc08 = 0;
  hc08_crc16 = 0x8779;
  return;
}



// Enables EEPROM write operations by clearing /WP pin via MPIO

void eeprom_wp_pin_enable(void)

{
  ushort uVar1;
  
  uVar1 = REG_MPIOSMDR;
  REG_MPIOSMDR = uVar1 & 0xbfff;
  return;
}



// Disables EEPROM write operations by setting /WP pin via MPIO

void eeprom_wp_pin_disable(void)

{
  ushort uVar1;
  
  uVar1 = REG_MPIOSMDR;
  REG_MPIOSMDR = uVar1 & 0xbfff | 0x4000;
  return;
}



// Validates HC08 message CRC

bool hc08_check_CRC(void)

{
  return hc08_crc16 == 0x7886;
}



// HC08 communication handler

void hc08_com(void)

{
  if (hc08_send_timer == 0) {
    hc08_send_timer = 20;
    hc08_send_status();
  }
  hc08_recv();
  return;
}



// Checks if SCI2 has pending data

bool sci2_hasmore(void)

{
  return DAT_003f9009 != '\0';
}



// Initializes SCI2 for HC08 communication

void sci2_init(void)

{
  ushort uVar1;
  
  REG_SCC2R1 = 0;
  REG_SCC2R0 = 0x40;
  uVar1 = REG_SCC2R1;
  REG_SCC2R1 = uVar1 & 0xfff7 | 8;
  uVar1 = REG_SCC2R1;
  REG_SCC2R1 = uVar1 & 0xfffb | 4;
  REG_SC2DR = 0;
  do {
    uVar1 = REG_SC2SR;
  } while ((uVar1 >> 7 & 1) == 0);
  REG_SC2DR = 0;
  do {
    uVar1 = REG_SC2SR;
  } while ((uVar1 >> 7 & 1) == 0);
  REG_SC2DR = 0;
  do {
    uVar1 = REG_SC2SR;
  } while ((uVar1 >> 7 & 1) == 0);
  DAT_003f900b = 0;
  DAT_003f900a = 0;
  DAT_003f9009 = 0;
  uVar1 = REG_SCC2R1;
  REG_SCC2R1 = uVar1 & 0xffdf | 0x20;
  hc08_parse_len = 0;
  DAT_003f9006 = 0;
  return;
}



// Reads character from SCI2

char sci2_getchar(void)

{
  uint uVar1;
  
  do {
  } while (DAT_003f9009 == '\0');
  uVar1 = (uint)DAT_003f900a;
  DAT_003f9009 = DAT_003f9009 + -1;
  if (DAT_003f900a < 0x1f) {
    DAT_003f900a = DAT_003f900a + 1;
  }
  else {
    DAT_003f900a = '\0';
  }
  return sci2_rx_buffer[uVar1];
}



// SCI receive interrupt handler

void sci_rx_handler(void)

{
  ushort uVar1;
  
  uVar1 = REG_SC2SR;
  if (((uVar1 >> 6 & 1) != 0) && (uVar1 = REG_SC2DR, DAT_003f9009 < 0x20)) {
    sci2_rx_buffer[DAT_003f900b] = (char)uVar1;
    if (DAT_003f900b < 0x1f) {
      DAT_003f900b = DAT_003f900b + 1;
    }
    else {
      DAT_003f900b = 0;
    }
    DAT_003f9009 = DAT_003f9009 + 1;
  }
  return;
}



// Sends character via SCI2

void sci2_send(int param_1,byte param_2)

{
  ushort uVar1;
  byte bVar2;
  
  uVar1 = REG_SCC2R1;
  REG_SCC2R1 = uVar1 & 0xff7f;
  for (bVar2 = 0; bVar2 < param_2; bVar2 = bVar2 + 1) {
    sci2_tx_buffer[bVar2] = *(char *)(param_1 + (uint)bVar2);
  }
  DAT_003f9007 = param_2;
  DAT_003f9008 = 0;
  uVar1 = REG_SCC2R1;
  REG_SCC2R1 = uVar1 & 0xff7f | 0x80;
  return;
}



// SCI transmit interrupt handler

void sci_tx_handler(void)

{
  ushort uVar1;
  byte bVar2;
  
  uVar1 = REG_SCC2R1;
  if (((uVar1 >> 7 & 1) == 1) && (uVar1 = REG_SC2SR, (uVar1 >> 8 & 1) == 1)) {
    bVar2 = DAT_003f9008 + 1;
    REG_SC2DR = (ushort)(byte)sci2_tx_buffer[DAT_003f9008];
    DAT_003f9008 = bVar2;
    if (bVar2 == DAT_003f9007) {
      uVar1 = REG_SCC2R1;
      REG_SCC2R1 = uVar1 & 0xff7f;
    }
  }
  return;
}



// Parses HC08 safety processor messages

undefined4 hc08_parse(byte param_1)

{
  uint uVar1;
  
  if (0x13 < hc08_parse_len) {
    hc08_parse_len = 0;
  }
  if (hc08_parse_timer == 0) {
    hc08_parse_len = 0;
  }
  hc08_parse_timer = 6;
  if (hc08_parse_len == 0) {
    hc08_parse_len = 1;
    hc08_parse_sum = param_1;
    hc08_parse_buf[0] = param_1;
  }
  else if (hc08_parse_len == 1) {
    hc08_parse_len = 2;
    hc08_parse_sum = hc08_parse_sum + param_1;
    hc08_parse_buf[1] = param_1;
  }
  else if ((hc08_parse_len < 2) || ((byte)hc08_parse_buf[0] + 1 < (uint)hc08_parse_len)) {
    if ((uint)hc08_parse_len == (byte)hc08_parse_buf[0] + 2) {
      uVar1 = (uint)hc08_parse_len;
      hc08_parse_buf[hc08_parse_len] = param_1;
      hc08_parse_len = 0;
      if ((param_1 == (byte)~hc08_parse_sum) && ((&hc08_parse_sum)[uVar1] == DAT_003f9006)) {
        hc08_parse_len = 0;
        return 1;
      }
    }
    else {
      hc08_parse_len = 0;
    }
  }
  else {
    uVar1 = (uint)hc08_parse_len;
    hc08_parse_len = hc08_parse_len + 1;
    hc08_parse_buf[uVar1] = param_1;
    hc08_parse_sum = hc08_parse_sum + param_1;
  }
  return 0;
}



// WARNING: Inlined function: push_27to31
// WARNING: Inlined function: pop_27to31
// Sends message to HC08 processor

void hc08_send(byte *param_1,byte param_2)

{
  byte bVar1;
  byte *pbVar2;
  int iVar3;
  byte *pbVar4;
  
  *param_1 = param_2;
  DAT_003f9006 = DAT_003f9006 + 1;
  param_1[param_2 + 1] = DAT_003f9006;
  pbVar4 = param_1 + param_2 + 2;
  *pbVar4 = 0;
  pbVar2 = param_1;
  for (iVar3 = 0; iVar3 <= (int)(param_2 + 1); iVar3 = iVar3 + 1) {
    bVar1 = *pbVar2;
    pbVar2 = pbVar2 + 1;
    *pbVar4 = *pbVar4 + bVar1;
  }
  *pbVar4 = ~*pbVar4;
  sci2_send(param_1,param_2 + 3);
  return;
}



// Sends status to HC08 processor

void hc08_send_status(void)

{
  undefined1 uStack_18;
  undefined1 local_17;
  undefined1 local_16;
  
  local_17 = 0x81;
  local_16 = flags_to_hc08;
  hc08_send(&uStack_18,2);
  return;
}



// Receives message from HC08 processor

void hc08_recv(void)

{
  int iVar1;
  undefined1 uVar2;
  
  while (iVar1 = sci2_hasmore(), iVar1 != 0) {
    uVar2 = sci2_getchar();
    iVar1 = hc08_parse(uVar2);
    if (iVar1 != 0) {
      hc08_recv_timer = 100;
      if (hc08_parse_buf[1] == -0x7f) {
        hc08_pps = hc08_parse_buf[3];
        hc08_tps = hc08_parse_buf[4];
        hc08_tps_target = hc08_parse_buf[5];
        hc08_PTB1_maf = hc08_parse_buf[6];
        hc08_PTB2_tps_1 = hc08_parse_buf[7];
        hc08_PTB3_tps_2 = hc08_parse_buf[8];
        hc08_PTB4_pps_1 = hc08_parse_buf[9];
        hc08_PTB5_pps_2 = hc08_parse_buf[10];
        hc08_PTB6 = hc08_parse_buf[0xb];
        hc08_PTB7 = hc08_parse_buf[0xc];
        hc08_crc16 = CONCAT11(hc08_parse_buf[0xd],hc08_parse_buf[0xe]);
        iVar1 = hc08_check_CRC();
        if (iVar1 == 0) {
          hc08_parse_buf[2] = hc08_parse_buf[2] | 0x40;
        }
        hc08_obd_flags = hc08_parse_buf[2];
      }
      else if (((byte)hc08_parse_buf[1] < 0x81) && (0x7f < (byte)hc08_parse_buf[1])) {
        hc08_crc16 = CONCAT11(hc08_parse_buf[2],hc08_parse_buf[3]);
      }
    }
  }
  if (hc08_recv_timer == 0) {
    hc08_obd_flags = hc08_obd_flags | 0x80;
  }
  return;
}



// Sets diagnostic state for a channel (PPS, TPS, O2 heater, misfire) with confirm/clear thresholds

void diag_set(uint param_1,byte param_2)

{
  byte bVar1;
  
  bVar1 = diag_channel[param_1 & 0xff].state;
  if (bVar1 == 2) {
    if (param_2 == 0) {
      diag_channel[param_1 & 0xff].state = 3;
    }
    else {
      diag_channel[param_1 & 0xff].result = param_2;
      DAT_003fdfd3 = 1;
      (&DAT_003fdfd4)[param_2] = 1;
    }
  }
  else if (bVar1 < 2) {
    if (bVar1 == 0) {
      diag_channel[param_1 & 0xff].result = param_2;
      if (param_2 != 0) {
        diag_channel[param_1 & 0xff].confirm_count = diag_channel[param_1 & 0xff].confirm_count + 1;
        if (diag_channel[param_1 & 0xff].confirm_count <
            diag_channel[param_1 & 0xff].confirm_threshold) {
          diag_channel[param_1 & 0xff].state = 1;
        }
        else {
          diag_channel[param_1 & 0xff].state = 2;
          diag_channel[param_1 & 0xff].clear_count = 0;
        }
      }
    }
    else if (true) {
      diag_channel[param_1 & 0xff].result = param_2;
      if (param_2 == 0) {
        if (diag_channel[param_1 & 0xff].confirm_count != 0) {
          diag_channel[param_1 & 0xff].confirm_count =
               diag_channel[param_1 & 0xff].confirm_count - 1;
        }
        if (diag_channel[param_1 & 0xff].confirm_count == 0) {
          diag_channel[param_1 & 0xff].state = 0;
          diag_channel[param_1 & 0xff].clear_count = 0;
        }
      }
      else {
        diag_channel[param_1 & 0xff].confirm_count = diag_channel[param_1 & 0xff].confirm_count + 1;
        diag_channel[param_1 & 0xff].clear_count = 0;
        if (diag_channel[param_1 & 0xff].confirm_threshold <=
            diag_channel[param_1 & 0xff].confirm_count) {
          diag_channel[param_1 & 0xff].state = 2;
          diag_channel[param_1 & 0xff].clear_count = 0;
        }
      }
    }
  }
  else if (bVar1 < 4) {
    if (param_2 == 0) {
      diag_channel[param_1 & 0xff].clear_count = diag_channel[param_1 & 0xff].clear_count + 1;
      if (diag_channel[param_1 & 0xff].clear_threshold <= diag_channel[param_1 & 0xff].clear_count)
      {
        diag_channel[param_1 & 0xff].state = 0;
        diag_channel[param_1 & 0xff].confirm_count = 0;
        diag_channel[param_1 & 0xff].clear_count = 0;
        (&DAT_003fdfd4)[diag_channel[param_1 & 0xff].result] = 0;
        diag_channel[param_1 & 0xff].result = 0;
      }
    }
    else {
      diag_channel[param_1 & 0xff].state = 2;
      diag_channel[param_1 & 0xff].result = param_2;
      diag_channel[param_1 & 0xff].clear_count = 0;
    }
  }
  return;
}



// Initializes diagnostic state machine for 31 channels with confirm/clear thresholds and counters

void init_diag(void)

{
  int iVar1;
  
  DAT_003fdfd3 = 0;
  for (iVar1 = 0; iVar1 < 0x1e; iVar1 = iVar1 + 1) {
    (&DAT_003fdfd4)[iVar1] = 0;
  }
  for (iVar1 = 0; iVar1 < 0x1f; iVar1 = iVar1 + 1) {
    diag_channel[iVar1].result = 0;
    diag_channel[iVar1].state = 0;
    diag_channel[iVar1].confirm_threshold = 180;
    diag_channel[iVar1].clear_threshold = 1000;
    diag_channel[iVar1].confirm_count = 0;
    diag_channel[iVar1].clear_count = 0;
  }
  diag_channel[4].confirm_threshold = 500;
  diag_channel[4].clear_threshold = 2000;
  diag_channel[5].confirm_threshold = 500;
  diag_channel[5].clear_threshold = 2000;
  diag_channel[8].confirm_threshold = 500;
  diag_channel[8].clear_threshold = 2000;
  diag_channel[1].confirm_threshold = 100;
  diag_channel[1].clear_threshold = 400;
  diag_channel[2].confirm_threshold = 100;
  diag_channel[2].clear_threshold = 400;
  diag_channel[3].confirm_threshold = 100;
  diag_channel[3].clear_threshold = 400;
  diag_channel[0x13].confirm_threshold = 500;
  diag_channel[0x14].confirm_threshold = 500;
  diag_channel[0x15].confirm_threshold = 500;
  diag_channel[0x16].confirm_threshold = 500;
  diag_channel[0xb].confirm_threshold = 500;
  diag_channel[0xb].clear_threshold = 500;
  diag_channel[0x19].confirm_threshold = (ushort)CAL_obd_P0135_debounce_threshold;
  diag_channel[0x19].clear_threshold = 10000;
  diag_channel[0x1a].confirm_threshold = (ushort)CAL_obd_P0141_debounce_threshold;
  diag_channel[0x1a].clear_threshold = 10000;
  diag_channel[0x1b].confirm_threshold = 1;
  diag_channel[0x1b].clear_threshold = 1;
  diag_channel[0x1c].confirm_threshold = 1;
  diag_channel[0x1c].clear_threshold = 1;
  diag_channel[0x1d].confirm_threshold = 1;
  diag_channel[0x1d].clear_threshold = 1;
  diag_channel[0x1e].confirm_threshold = 1;
  diag_channel[0x1e].clear_threshold = 1;
  return;
}



// Validates PPS sensor readings for faults

void pps_check(ushort param_1,ushort param_2)

{
  uint uVar1;
  short sVar2;
  int iVar3;
  int iVar4;
  
  DAT_003fe059 = out_range(param_1,pps_1_range_high,pps_1_range_low);
  DAT_003fe05a = out_range(param_2,pps_2_range_high,pps_2_range_low);
  if (DAT_003fe059 == 0) {
    if ((int)(short)LEA_sensor_pps_1_offset < (int)(uint)param_1) {
      pps_1 = convert_pps_1((int)(short)param_1);
      pps_1_history[2] = pps_1_history[1];
      pps_1_history[1] = pps_1_history[0];
      pps_1_history[0] = pps_1;
    }
    else {
      pps_1 = 0;
    }
    diag_set(1,0);
    DAT_003fe04e = pps_1_history[2];
  }
  else {
    if (DAT_003fe059 == 2) {
      diag_set(1,2);
    }
    else {
      diag_set(1,1);
    }
    pps_1 = DAT_003fe04e;
  }
  if (DAT_003fe05a == 0) {
    if ((int)(short)LEA_sensor_pps_2_offset < (int)(uint)param_2) {
      pps_2 = convert_pps_2((int)(short)param_2);
      pps_2_history[2] = pps_2_history[1];
      pps_2_history[1] = pps_2_history[0];
      pps_2_history[0] = pps_2;
    }
    else {
      pps_2 = 0;
    }
    diag_set(2,0);
    DAT_003fe050 = pps_2_history[2];
  }
  else {
    if (DAT_003fe05a == 2) {
      diag_set(2,4);
    }
    else {
      diag_set(2,3);
    }
    pps_2 = DAT_003fe050;
  }
  uVar1 = (uint)CAL_sensor_pps_1_gain * ((uint)sensor_adc_pps_1 - (uint)CAL_sensor_pps_1_offset);
  sVar2 = (short)((int)uVar1 >> 6) + (ushort)((int)uVar1 < 0 && (uVar1 & 0x3f) != 0);
  iVar4 = (int)sVar2;
  if (iVar4 < 0) {
    iVar4 = 0;
  }
  else if (0x3ff < sVar2) {
    iVar4 = 0x3ff;
  }
  uVar1 = (uint)CAL_sensor_pps_2_gain * ((uint)sensor_adc_pps_2 - (uint)CAL_sensor_pps_2_offset);
  sVar2 = (short)((int)uVar1 >> 6) + (ushort)((int)uVar1 < 0 && (uVar1 & 0x3f) != 0);
  iVar3 = (int)sVar2;
  if (iVar3 < 0) {
    iVar3 = 0;
  }
  else if (0x3ff < sVar2) {
    iVar3 = 0x3ff;
  }
  pps_diff = (short)iVar4 - (short)iVar3;
  pps_correlation_state =
       pps_sensor_correlation_check(DAT_003fe059,DAT_003fe05a,iVar4,iVar3,CAL_sensor_pps_match_max);
  if ((1 < diag_channel[1].state) || (1 < diag_channel[2].state)) {
    DAT_003fe05b = 1;
  }
  if ((diag_channel[1].state < 2) || (diag_channel[2].state < 2)) {
    DAT_003fe06e = 0;
  }
  else {
    DAT_003fe06e = 1;
  }
  if (pps_correlation_state == 2) {
    diag_set(3,5);
    if (pps_1 < pps_2) {
      pps_min = pps_1;
      flags_to_hc08 = flags_to_hc08 | 1;
    }
    else {
      pps_min = pps_2;
      flags_to_hc08 = flags_to_hc08 & 0xfe;
    }
  }
  else if (pps_correlation_state < 2) {
    if (pps_correlation_state == 0) {
      diag_set(3,0);
      if (diag_channel[1].state == 3) {
        if (diag_channel[2].state != 3) {
          pps_min = pps_2;
          flags_to_hc08 = flags_to_hc08 & 0xfe;
        }
      }
      else {
        pps_min = pps_1;
        flags_to_hc08 = flags_to_hc08 | 1;
      }
    }
    else if (true) {
      if ((1 < diag_channel[1].state) && (1 < diag_channel[2].state)) {
        pps_min = 0;
      }
      if (DAT_003fe059 == 0) {
        if (diag_channel[1].state < 2) {
          pps_min = pps_1;
          flags_to_hc08 = flags_to_hc08 | 1;
        }
        else if (diag_channel[1].state == 3) {
          pps_min = DAT_003fe050;
          flags_to_hc08 = flags_to_hc08 & 0xfe;
        }
      }
      if (DAT_003fe05a == 0) {
        if (diag_channel[2].state < 2) {
          pps_min = pps_2;
          flags_to_hc08 = flags_to_hc08 & 0xfe;
        }
        else if (diag_channel[2].state == 3) {
          pps_min = DAT_003fe04e;
          flags_to_hc08 = flags_to_hc08 | 1;
        }
      }
    }
  }
  else if ((pps_correlation_state < 4) &&
          ((diag_channel[1].state < 2 || (diag_channel[2].state < 2)))) {
    if ((diag_channel[1].state < 2) && (diag_channel[2].state < 2)) {
      if (DAT_003fe04e < DAT_003fe050) {
        pps_min = DAT_003fe04e;
        flags_to_hc08 = flags_to_hc08 | 1;
      }
      else {
        pps_min = DAT_003fe050;
        flags_to_hc08 = flags_to_hc08 & 0xfe;
      }
    }
    else if ((diag_channel[1].state < 2) && (1 < diag_channel[2].state)) {
      pps_min = DAT_003fe04e;
      flags_to_hc08 = flags_to_hc08 | 1;
    }
    else if ((1 < diag_channel[1].state) && (diag_channel[2].state < 2)) {
      pps_min = DAT_003fe050;
      flags_to_hc08 = flags_to_hc08 & 0xfe;
    }
  }
  if ((1 < diag_channel[1].state) || (1 < diag_channel[2].state)) {
    DAT_003fe05b = 1;
  }
  if ((diag_channel[1].state < 2) || (diag_channel[2].state < 2)) {
    DAT_003fe06e = 0;
  }
  else {
    DAT_003fe06e = 1;
  }
  if (diag_channel[1].state < 2) {
    DAT_003fe048 = DAT_003fe048 & 0xfe;
    flags_to_hc08 = flags_to_hc08 & 0xbf;
  }
  else {
    DAT_003fe048 = DAT_003fe048 | 1;
    flags_to_hc08 = flags_to_hc08 | 0x40;
  }
  if (diag_channel[2].state < 2) {
    DAT_003fe048 = DAT_003fe048 & 0xfd;
    flags_to_hc08 = flags_to_hc08 & 0xbf;
  }
  else {
    DAT_003fe048 = DAT_003fe048 | 2;
    flags_to_hc08 = flags_to_hc08 | 0x40;
  }
  if (diag_channel[3].state < 2) {
    DAT_003fe048 = DAT_003fe048 & 0xfb;
  }
  else {
    DAT_003fe048 = DAT_003fe048 | 4;
    DAT_003fe05b = 1;
  }
  return;
}



// Checks dual PPS sensor status and correlation

undefined4
pps_sensor_correlation_check(char param_1,char param_2,short param_3,short param_4,ushort param_5)

{
  undefined4 uVar1;
  uint uVar2;
  
  if ((param_1 == '\0') || (param_2 == '\0')) {
    if ((param_1 == '\0') && (param_2 == '\0')) {
      if ((false) || (false)) {
        uVar1 = 0;
      }
      else {
        uVar2 = abs((int)param_3 - (int)param_4);
        if ((int)(uint)param_5 < (int)uVar2) {
          uVar1 = 2;
        }
        else {
          uVar1 = 0;
        }
      }
    }
    else {
      uVar1 = 1;
    }
  }
  else {
    uVar1 = 3;
  }
  return uVar1;
}



// Checks dual TPS sensor status and correlation with throttle limit

undefined4
tps_sensor_correlation_check(char param_1,char param_2,short param_3,short param_4,ushort param_5)

{
  undefined4 uVar1;
  uint uVar2;
  
  if ((param_1 == '\0') || (param_2 == '\0')) {
    if ((param_1 == '\0') && (param_2 == '\0')) {
      if ((false) || (false)) {
        uVar1 = 0;
      }
      else {
        uVar2 = abs((int)param_3 - (int)param_4);
        if (((int)(uint)param_5 < (int)uVar2) && ((int)param_4 < (int)(uint)DAT_003fbfe4)) {
          uVar1 = 2;
        }
        else {
          uVar1 = 0;
        }
      }
    }
    else {
      uVar1 = 1;
    }
  }
  else {
    uVar1 = 3;
  }
  return uVar1;
}



// Checks if value is outside range. Returns: 0=in range, 1=below low, 2=above high

uint8_t out_range(uint16_t value,uint16_t high,uint16_t low)

{
  uint8_t uVar1;
  
  if (high < value) {
    uVar1 = 2;
  }
  else if (value < low) {
    uVar1 = 1;
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}



// Initializes PPS sensor fault checking state

void pps_check_init(void)

{
  int iVar1;
  
  init_diag();
  DAT_003fdff4 = 0;
  DAT_003fe048 = 0;
  DAT_003fe054 = 0;
  DAT_003fe052 = 0;
  DAT_003fe050 = 0;
  DAT_003fe04e = 0;
  pps_2 = 0;
  pps_1 = 0;
  DAT_003fe056 = 0x3ff;
  pps_correlation_state = 0;
  DAT_003fe05a = 0;
  DAT_003fe059 = 0;
  DAT_003fe05b = 0;
  tps_max = 0;
  DAT_003fe068 = 0;
  DAT_003fe066 = 0;
  DAT_003fe064 = 0;
  DAT_003fe062 = 0;
  tps_2 = 0;
  tps_1 = 0;
  DAT_003fe06a = 0;
  tps_correlation_state = 0;
  DAT_003fe06d = 0;
  DAT_003fe06c = 0;
  DAT_003fe06e = 0;
  DAT_003fe06f = 0;
  tps_both_fault = false;
  DAT_003fe071 = 0;
  pps_1_range_high = CAL_misc_pps_1_range_high;
  pps_1_range_low = CAL_misc_pps_1_range_low;
  pps_2_range_high = CAL_misc_pps_2_range_high;
  pps_2_range_low = CAL_misc_pps_2_range_low;
  tps_1_range_high = CAL_misc_tps_1_range_high;
  tps_1_range_low = CAL_misc_tps_1_range_low;
  tps_2_range_high = CAL_misc_tps_2_range_high;
  tps_2_range_low = CAL_misc_tps_2_range_low;
  for (iVar1 = 0; iVar1 < 4; iVar1 = iVar1 + 1) {
    pps_2_history[iVar1] = 0;
    pps_1_history[iVar1] = 0;
    tps_2_history[iVar1] = 0;
    tps_1_history[iVar1] = 0;
  }
  return;
}



// Validates TPS sensor readings for faults

void tps_check(ushort param_1,ushort param_2)

{
  uint uVar1;
  
  DAT_003fe06c = out_range(param_1,tps_1_range_high,tps_1_range_low);
  DAT_003fe06d = out_range(param_2,tps_2_range_high,tps_2_range_low);
  if (DAT_003fe06c == 0) {
    if (LEA_sensor_tps_1_offset < param_1) {
      uVar1 = (uint)tps_1_gain_corrected * ((uint)param_1 - (uint)tps_1_range_corrected_low);
      tps_1 = (short)((int)uVar1 >> 6) + (ushort)((int)uVar1 < 0 && (uVar1 & 0x3f) != 0);
      tps_1_history[2] = tps_1_history[1];
      tps_1_history[1] = tps_1_history[0];
      tps_1_history[0] = tps_1;
    }
    diag_set(4,0);
    DAT_003fe062 = tps_1_history[2];
  }
  else {
    if (DAT_003fe06c == 2) {
      diag_set(4,7);
    }
    else {
      diag_set(4,6);
    }
    tps_1 = DAT_003fe062;
  }
  if (DAT_003fe06d == 0) {
    if (LEA_sensor_tps_2_offset < param_2) {
      uVar1 = abs((uint)param_2 - (uint)tps_2_range_corrected_low);
      uVar1 = tps_2_gain_computed * uVar1;
      tps_2 = (short)((int)uVar1 >> 6) + (ushort)((int)uVar1 < 0 && (uVar1 & 0x3f) != 0);
      tps_2_history[2] = tps_2_history[1];
      tps_2_history[1] = tps_2_history[0];
      tps_2_history[0] = tps_2;
    }
    diag_set(5,0);
    DAT_003fe064 = tps_2_history[2];
  }
  else {
    if (DAT_003fe06d == 2) {
      diag_set(5,9);
    }
    else {
      diag_set(5,8);
    }
    tps_2 = DAT_003fe064;
  }
  tps_correlation_state =
       tps_sensor_correlation_check
                 (DAT_003fe06c,DAT_003fe06d,(int)(short)tps_1,(int)(short)tps_2,
                  CAL_sensor_tps_match_max);
  if (tps_correlation_state == 2) {
    diag_set(8,10);
    if ((short)tps_2 < (short)tps_1) {
      tps_max = tps_1;
      flags_to_hc08 = flags_to_hc08 | 2;
      DAT_003fe056 = 0x3ff;
    }
    else {
      tps_max = tps_2;
      flags_to_hc08 = flags_to_hc08 & 0xfd;
      DAT_003fe056 = DAT_003fbfe4;
    }
  }
  else if (tps_correlation_state < 2) {
    if (tps_correlation_state == 0) {
      diag_set(8,0);
      if (((diag_channel[4].state < 2) && (diag_channel[5].state < 2)) &&
         (diag_channel[8].state < 2)) {
        tps_max = tps_1;
        flags_to_hc08 = flags_to_hc08 | 2;
        DAT_003fe056 = 0x3ff;
      }
      else if (diag_channel[4].state == 3) {
        if (diag_channel[5].state != 3) {
          tps_max = tps_2;
          flags_to_hc08 = flags_to_hc08 & 0xfd;
          DAT_003fe056 = DAT_003fbfe4;
        }
      }
      else {
        tps_max = tps_1;
        flags_to_hc08 = flags_to_hc08 | 2;
        DAT_003fe056 = 0x3ff;
      }
    }
    else if (true) {
      if ((1 < diag_channel[4].state) && (1 < diag_channel[5].state)) {
        DAT_003fe056 = DAT_003fbfe4;
      }
      if (DAT_003fe06c == 0) {
        if (diag_channel[4].state < 2) {
          tps_max = tps_1;
          flags_to_hc08 = flags_to_hc08 | 2;
          DAT_003fe056 = 0x3ff;
        }
        else if (diag_channel[4].state == 3) {
          tps_max = DAT_003fe064;
          flags_to_hc08 = flags_to_hc08 & 0xfd;
          DAT_003fe056 = DAT_003fbfe4;
        }
      }
      if (DAT_003fe06d == 0) {
        if (diag_channel[5].state < 2) {
          tps_max = tps_2;
          flags_to_hc08 = flags_to_hc08 & 0xfd;
          DAT_003fe056 = DAT_003fbfe4;
        }
        else if (diag_channel[5].state == 3) {
          tps_max = DAT_003fe062;
          flags_to_hc08 = flags_to_hc08 | 2;
          DAT_003fe056 = 0x3ff;
        }
      }
    }
  }
  else if ((tps_correlation_state < 4) &&
          ((diag_channel[4].state < 2 || (diag_channel[5].state < 2)))) {
    if ((diag_channel[4].state < 2) && (diag_channel[5].state < 2)) {
      if ((short)DAT_003fe064 < (short)DAT_003fe062) {
        tps_max = DAT_003fe062;
        flags_to_hc08 = flags_to_hc08 | 2;
        DAT_003fe056 = 0x3ff;
      }
      else {
        tps_max = DAT_003fe064;
        flags_to_hc08 = flags_to_hc08 & 0xfd;
        DAT_003fe056 = DAT_003fbfe4;
      }
    }
    else if ((diag_channel[4].state < 2) && (1 < diag_channel[5].state)) {
      tps_max = DAT_003fe062;
      flags_to_hc08 = flags_to_hc08 | 2;
      DAT_003fe056 = 0x3ff;
    }
    else if ((1 < diag_channel[4].state) && (diag_channel[5].state < 2)) {
      tps_max = DAT_003fe064;
      flags_to_hc08 = flags_to_hc08 & 0xfd;
      DAT_003fe056 = DAT_003fbfe4;
    }
  }
  if ((1 < diag_channel[4].state) || (1 < diag_channel[5].state)) {
    DAT_003fe06a = 1;
  }
  if ((diag_channel[4].state < 2) || (diag_channel[5].state < 2)) {
    tps_both_fault = false;
  }
  else {
    tps_both_fault = true;
  }
  if (diag_channel[4].state < 2) {
    DAT_003fdff4 = DAT_003fdff4 & 0xfe;
    flags_to_hc08 = flags_to_hc08 & 0x7f;
  }
  else {
    DAT_003fdff4 = DAT_003fdff4 | 1;
    flags_to_hc08 = flags_to_hc08 | 0x80;
  }
  if (diag_channel[5].state < 2) {
    DAT_003fdff4 = DAT_003fdff4 & 0xfd;
    flags_to_hc08 = flags_to_hc08 & 0x7f;
  }
  else {
    DAT_003fdff4 = DAT_003fdff4 | 2;
    flags_to_hc08 = flags_to_hc08 | 0x80;
  }
  if (diag_channel[8].state < 2) {
    DAT_003fdff4 = DAT_003fdff4 & 0xbf;
  }
  else {
    DAT_003fdff4 = DAT_003fdff4 | 0x40;
    DAT_003fe06a = 1;
  }
  return;
}



// Resets all ECU learned/adaptive tables to defaults

void reset_learn_tables(void)

{
  int iVar1;
  int iVar2;
  
  for (iVar2 = 0; iVar2 < 0x10; iVar2 = iVar2 + 1) {
    for (iVar1 = 0; iVar1 < 4; iVar1 = iVar1 + 1) {
      LEA_misfire_stroke_time[iVar1][iVar2] = misfire_stroke_time_baseline[iVar1][iVar2];
    }
  }
  for (iVar2 = 0; iVar2 < 0x10; iVar2 = iVar2 + 1) {
    misfire_dfso_count[iVar2] = 0;
    (&DAT_002f82ef)[iVar2] = 0;
  }
  for (iVar2 = 0; iVar2 < 4; iVar2 = iVar2 + 1) {
    LEA_knock_retard2[iVar2] = 0;
  }
  LEA_idle_flow_adj1 = 0;
  LEA_idle_flow_adj1_ac_on = 0;
  LEA_ecu_engine_speed_byte_coefficient = CAL_ecu_engine_speed_byte_coefficient;
  LEA_ecu_engine_speed_byte_offset = CAL_ecu_engine_speed_byte_offset;
  DAT_002f8024 = 0;
  DAT_002f8026 = 0;
  for (iVar2 = 8; iVar2 < 0x28; iVar2 = iVar2 + 1) {
    *(u8_factor_1_500 *)((int)&LEA_ecu_engine_speed_byte_coefficient + iVar2) =
         CAL_obd_P1302_threshold[iVar2 + 0x38];
  }
  for (iVar2 = 0x28; iVar2 < 0x128; iVar2 = iVar2 + 1) {
    *(undefined1 *)((int)&LEA_ecu_engine_speed_byte_coefficient + iVar2) = 100;
  }
  LEA_ltft_zone1_adj = 0;
  LEA_ltft_zone3_adj = 128;
  LEA_ltft_zone2_adj = 128;
  builtin_memcpy(obd_resp,"Hk\x10Q\x14",5);
  obd_resp_len = 4;
  obd_resp_i = 0;
  REG_SC1DR = 0x48;
  return;
}



// Asserts chip select via TPU-B (drives CS low)

void eeprom_cs_assert(void)

{
  ushort uVar1;
  
  uVar1 = REG_HSRR0_B;
  REG_HSRR0_B = uVar1 & 0xcfff | 0x2000;
  do {
    uVar1 = REG_HSRR0_B;
  } while (uVar1 != 0);
  return;
}



// Deasserts chip select via TPU-B (drives CS high)

void eeprom_cs_deassert(void)

{
  ushort uVar1;
  
  uVar1 = REG_HSRR0_B;
  REG_HSRR0_B = uVar1 & 0xcfff | 0x1000;
  do {
    uVar1 = REG_HSRR0_B;
  } while (uVar1 != 0);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

uint8_t eeprom_status(void)

{
  char cStack_8;
  uint8_t local_7;
  char local_6 [6];
  
  local_6[0] = '\x05';
  local_6[1] = 0;
  eeprom_command(local_6,&cStack_8,2);
  return local_7;
}



// WARNING: Unknown calling convention
// Sends WREN command (0x06) to enable EEPROM write latch

void eeprom_write_enable(void)

{
  byte bVar1;
  char acStack_18 [20];
  
  do {
    bVar1 = eeprom_status();
  } while ((bVar1 & 1) != 0);
  acStack_18[1] = 6;
  eeprom_command(acStack_18 + 1,acStack_18,1);
  return;
}



// Reads single byte from EEPROM

char eeprom_read_byte(uint addr)

{
  byte bVar1;
  char acStack_18 [3];
  char local_15;
  char local_14;
  undefined1 local_13;
  undefined1 local_12;
  undefined1 local_11;
  
  do {
    bVar1 = eeprom_status();
  } while ((bVar1 & 1) != 0);
  local_14 = '\x03';
  local_13 = (undefined1)(addr >> 8);
  local_12 = (undefined1)addr;
  local_11 = 0;
  eeprom_command(&local_14,acStack_18,4);
  return local_15;
}



// Writes single byte to EEPROM

void eeprom_write_byte(char c,uint addr)

{
  byte bVar1;
  char acStack_17 [4];
  char local_13;
  undefined1 local_12;
  undefined1 local_11;
  char local_10;
  
  do {
    bVar1 = eeprom_status();
  } while ((bVar1 & 1) != 0);
  eeprom_write_enable();
  local_13 = '\x02';
  local_12 = (undefined1)(addr >> 8);
  local_11 = (undefined1)addr;
  local_10 = c;
  eeprom_command(&local_13,acStack_17,4);
  return;
}



// Writes buffer to EEPROM

void eeprom_write(char *buffer,ushort size)

{
  ushort uVar1;
  uint addr;
  
  uVar1 = REG_PORTQS;
  REG_PORTQS = uVar1 & 0xfffb;
  for (addr = 0; (addr & 0xffff) < (uint)size; addr = addr + 1) {
    eeprom_write_byte(buffer[addr & 0xffff],addr);
    REG_SWSR = 0x556c;
    REG_SWSR = 0xaa39;
  }
  uVar1 = REG_PORTQS;
  REG_PORTQS = uVar1 & 0xfffb | 4;
  return;
}



// Reads buffer from EEPROM at specified address

void eeprom_read(char *buffer,ushort size)

{
  ushort uVar1;
  char cVar2;
  uint addr;
  
  uVar1 = REG_PORTQS;
  REG_PORTQS = uVar1 & 0xfffb;
  for (addr = 0; (addr & 0xffff) < (uint)size; addr = addr + 1) {
    cVar2 = eeprom_read_byte(addr);
    buffer[addr & 0xffff] = cVar2;
    REG_SWSR = 0x556c;
    REG_SWSR = 0xaa39;
  }
  uVar1 = REG_PORTQS;
  REG_PORTQS = uVar1 & 0xfffb | 4;
  return;
}



// WARNING: Inlined function: push_26to31
// WARNING: Inlined function: pop_26to31
// Copies current values to data logging buffer

void log_copy(void)

{
  char cVar1;
  char *pcVar2;
  char *pcVar3;
  char cVar4;
  struct_varptr *psVar5;
  int iVar6;
  undefined1 *puVar7;
  
  pcVar2 = log_data;
  for (psVar5 = log_varptr_list; psVar5->ptr != (void *)0x0; psVar5 = psVar5 + 1) {
    pcVar3 = (char *)psVar5->ptr;
    for (cVar4 = *(char *)&psVar5->size_le; cVar4 != '\0'; cVar4 = cVar4 + -1) {
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
      *pcVar2 = cVar1;
      pcVar2 = pcVar2 + 1;
    }
  }
  for (iVar6 = 0; iVar6 < 8; iVar6 = iVar6 + 1) {
    puVar7 = (undefined1 *)struct_varptr_ARRAY_0007601c[uint16_t_ARRAY_003f95fc[iVar6] & 0x3ff].ptr;
    if (*(char *)&struct_varptr_ARRAY_0007601c[uint16_t_ARRAY_003f95fc[iVar6] & 0x3ff].size_le ==
        '\x01') {
      (&DAT_003f8b08)[iVar6 * 2] = 0;
      (&DAT_003f8b09)[iVar6 * 2] = *puVar7;
    }
    else if (*(char *)&struct_varptr_ARRAY_0007601c[uint16_t_ARRAY_003f95fc[iVar6] & 0x3ff].size_le
             == '\x02') {
      (&DAT_003f8b08)[iVar6 * 2] = *puVar7;
      (&DAT_003f8b09)[iVar6 * 2] = puVar7[1];
    }
    else if (*(char *)&struct_varptr_ARRAY_0007601c[uint16_t_ARRAY_003f95fc[iVar6] & 0x3ff].size_le
             == '\x04') {
      (&DAT_003f8b08)[iVar6 * 2] = puVar7[2];
      (&DAT_003f8b09)[iVar6 * 2] = puVar7[3];
    }
  }
  return;
}



// Initializes CAN-B module for TPMS communication

void init_can_b(void)

{
  ushort uVar1;
  
  uVar1 = REG_CANMCR_B;
  REG_CANMCR_B = uVar1 | 0x200;
  do {
    uVar1 = REG_CANMCR_B;
  } while ((uVar1 & 0x200) != 0);
  uVar1 = REG_CANMCR_B;
  REG_CANMCR_B = uVar1 | 0x1000;
  do {
    uVar1 = REG_CANMCR_B;
  } while ((uVar1 & 0x900) != 0x900);
  REG_CANCTRL0_B = 0;
  REG_CANCTRL1_B = 4;
  REG_CTRL2_B = 0xf6;
  REG_PRESDIV_B = 1;
  REG_CANB_MB0_CS = 0;
  REG_CANB_MB0_ID_HI = 0;
  REG_CANB_MB0_ID_LO = 0;
  uVar1 = REG_CANB_MB0_CS;
  REG_CANB_MB0_CS = uVar1 | 0x80;
  REG_CANB_MB1_CS = 0;
  REG_CANB_MB1_ID_HI = 0;
  REG_CANB_MB1_ID_LO = 0;
  uVar1 = REG_CANB_MB1_CS;
  REG_CANB_MB1_CS = uVar1 | 0x80;
  REG_CANB_MB2_CS = 0;
  REG_CANB_MB2_ID_HI = 0;
  REG_CANB_MB2_ID_LO = 0;
  uVar1 = REG_CANB_MB2_CS;
  REG_CANB_MB2_CS = uVar1 | 0x80;
  REG_CANB_MB3_CS = 0;
  REG_CANB_MB3_ID_HI = 0;
  REG_CANB_MB3_ID_LO = 0;
  uVar1 = REG_CANB_MB3_CS;
  REG_CANB_MB3_CS = uVar1 | 0x80;
  REG_CANB_MB4_CS = 0;
  REG_CANB_MB4_ID_HI = 0;
  REG_CANB_MB4_ID_LO = 0;
  uVar1 = REG_CANB_MB4_CS;
  REG_CANB_MB4_CS = uVar1 | 0x80;
  REG_CANB_MB5_CS = 0;
  REG_CANB_MB5_ID_HI = 0;
  REG_CANB_MB5_ID_LO = 0;
  uVar1 = REG_CANB_MB5_CS;
  REG_CANB_MB5_CS = uVar1 | 0x80;
  REG_CANB_MB6_CS = 0;
  REG_CANB_MB6_ID_HI = 0;
  REG_CANB_MB6_ID_LO = 0;
  uVar1 = REG_CANB_MB6_CS;
  REG_CANB_MB6_CS = uVar1 | 0x80;
  REG_CANB_MB7_CS = 0;
  REG_CANB_MB7_ID_HI = 0;
  REG_CANB_MB7_ID_LO = 0;
  uVar1 = REG_CANB_MB7_CS;
  REG_CANB_MB7_CS = uVar1 | 0x80;
  REG_CANB_MB8_CS = 0;
  REG_CANB_MB8_ID_HI = 0;
  REG_CANB_MB8_ID_LO = 0;
  uVar1 = REG_CANB_MB8_CS;
  REG_CANB_MB8_CS = uVar1 | 0x80;
  REG_CANB_MB9_CS = 0;
  REG_CANB_MB9_ID_HI = 0;
  REG_CANB_MB9_ID_LO = 0;
  uVar1 = REG_CANB_MB9_CS;
  REG_CANB_MB9_CS = uVar1 | 0x80;
  REG_CANB_MB10_CS = 0;
  REG_CANB_MB10_ID_HI = 0;
  REG_CANB_MB10_ID_LO = 0;
  uVar1 = REG_CANB_MB10_CS;
  REG_CANB_MB10_CS = uVar1 | 0x80;
  REG_CANB_MB11_CS = 0;
  REG_CANB_MB11_ID_HI = 0;
  REG_CANB_MB11_ID_LO = 0;
  uVar1 = REG_CANB_MB11_CS;
  REG_CANB_MB11_CS = uVar1 | 0x80;
  REG_CANB_MB12_CS = 0;
  REG_CANB_MB12_ID_HI = 0;
  REG_CANB_MB12_ID_LO = 0;
  uVar1 = REG_CANB_MB12_CS;
  REG_CANB_MB12_CS = uVar1 | 0x80;
  REG_CANB_MB13_CS = 0;
  REG_CANB_MB13_ID_HI = 0;
  REG_CANB_MB13_ID_LO = 0;
  uVar1 = REG_CANB_MB13_CS;
  REG_CANB_MB13_CS = uVar1 | 0x40;
  REG_CANB_MB14_CS = 0;
  REG_CANB_MB14_ID_HI = 0x1000;
  REG_CANB_MB14_ID_LO = 0;
  uVar1 = REG_CANB_MB14_CS;
  REG_CANB_MB14_CS = uVar1 | 0x40;
  REG_CANB_MB15_CS = 0;
  REG_CANB_MB15_ID_HI = 0xa00;
  REG_CANB_MB15_ID_LO = 0;
  uVar1 = REG_CANB_MB15_CS;
  REG_CANB_MB15_CS = uVar1 | 0x40;
  REG_RXGMSKHI_B = 0xff0f;
  REG_RXGMSKLO_B = 0xfffe;
  REG_RX14MSKHI_B = 0xffef;
  REG_RX14MSKLO_B = 0xfffe;
  REG_RX15MSKHI_B = 0xff0f;
  REG_RX15MSKLO_B = 0xfffe;
  uVar1 = REG_ESTAT_B;
  REG_ESTAT_B = uVar1 & 0xfff8;
  REG_CANICR_B = 0;
  uVar1 = REG_CANICR_B;
  REG_CANICR_B = uVar1 & 0xf8ff | 0x500;
  uVar1 = REG_CANICR_B;
  REG_CANICR_B = uVar1 & 0xff3f | 0x80;
  REG_IMASK_B = 0xe00f;
  uVar1 = REG_CANMCR_B;
  REG_CANMCR_B = uVar1 & 0xefff;
  return;
}



// CAN-B MB00 streams multi-frame responses for the dev channel (counterpart of black91
// can_a_mb00_send_obd_multiframe - OBD is K-Line in white99)

void can_b_mb00_send_dev_multiframe(void)

{
  byte bVar1;
  byte *pbVar2;
  short sVar3;
  ushort uVar4;
  
  uVar4 = REG_CANB_MB0_CS;
  uVar4 = REG_IFLAG_B;
  REG_IFLAG_B = uVar4 & 0xfffe;
  if (DAT_003f9066 != 0) {
    DAT_003f9078 = &REG_CANB_MB0_DATA0;
    REG_CANB_MB0_CS = 0x88;
    REG_CANB_MB0_ID_HI = 0xf400;
    uVar4 = DAT_003f9066;
    if (DAT_003f9066 < 9) {
      for (; uVar4 != 0; uVar4 = uVar4 - 1) {
        bVar1 = *DAT_003f9058;
        DAT_003f9058 = DAT_003f9058 + 1;
        pbVar2 = DAT_003f9078 + 1;
        *DAT_003f9078 = bVar1;
        DAT_003f9078 = pbVar2;
      }
      REG_CANB_MB0_CS = DAT_003f9066 + 0xc0;
      DAT_003f9066 = 0;
    }
    else {
      for (sVar3 = 8; sVar3 != 0; sVar3 = sVar3 + -1) {
        bVar1 = *DAT_003f9058;
        DAT_003f9058 = DAT_003f9058 + 1;
        pbVar2 = DAT_003f9078 + 1;
        *DAT_003f9078 = bVar1;
        DAT_003f9078 = pbVar2;
      }
      REG_CANB_MB0_CS = 200;
      DAT_003f9066 = DAT_003f9066 - 8;
    }
  }
  return;
}



// CAN-B MB01: Unused message buffer

void can_b_mb01_unused(void)

{
  ushort uVar1;
  
  uVar1 = REG_CANB_MB1_CS;
  uVar1 = REG_IFLAG_B;
  REG_IFLAG_B = uVar1 & 0xfffd;
  return;
}



// CAN-B MB02: Unused message buffer

void can_b_mb02_unused(void)

{
  ushort uVar1;
  
  uVar1 = REG_CANB_MB2_CS;
  uVar1 = REG_IFLAG_B;
  REG_IFLAG_B = uVar1 & 0xfffb;
  return;
}



// CAN-B MB3 tx-complete: continues streaming 0x101 response frames (0x1b header, rolling data from
// the parked cursor)

void can_b_mb03_send_0x101_cont(void)

{
  byte bVar1;
  ushort uVar2;
  byte *pbVar3;
  short sVar4;
  
  uVar2 = REG_CANB_MB3_CS;
  uVar2 = REG_IFLAG_B;
  REG_IFLAG_B = uVar2 & 0xfff7;
  if (DAT_003f9070 != 0) {
    REG_CANB_MB3_CS = 0x88;
    REG_CANB_MB3_ID_HI = 0x2020;
    if (DAT_003f9070 < 5) {
      REG_CANB_MB3_DATA0 = 0x1b;
      DAT_003f9078 = &REG_CANB_MB3_DATA2;
      REG_CANB_MB3_DATA1 = DAT_003f9070;
      DAT_003f9070 = DAT_003f9070 + 1;
      for (sVar4 = 0; sVar4 < 6; sVar4 = sVar4 + 1) {
        bVar1 = *DAT_003f906c;
        DAT_003f906c = DAT_003f906c + 1;
        pbVar3 = DAT_003f9078 + 1;
        *DAT_003f9078 = bVar1;
        DAT_003f9078 = pbVar3;
      }
      REG_CANB_MB3_CS = 200;
    }
    else {
      REG_CANB_MB3_DATA0 = 0x1b;
      REG_CANB_MB3_DATA1 = DAT_003f9070;
      REG_CANB_MB3_DATA2 = 0xf;
      DAT_003f9078 = &REG_CANB_MB3_DATA4;
      REG_CANB_MB3_DATA3 = 0xff;
      for (sVar4 = 0; sVar4 < 4; sVar4 = sVar4 + 1) {
        pbVar3 = DAT_003f9078 + 1;
        *DAT_003f9078 = 0;
        DAT_003f9078 = pbVar3;
      }
      REG_CANB_MB3_CS = 200;
      DAT_003f9070 = 0;
    }
  }
  return;
}



// CAN-B MB04: Unused message buffer

void can_b_mb04_unused(void)

{
  ushort uVar1;
  
  uVar1 = REG_CANB_MB4_CS;
  uVar1 = REG_IFLAG_B;
  REG_IFLAG_B = uVar1 & 0xffef;
  return;
}



// CAN-B MB5 unused: clears IFLAG_B bit 5

void can_b_mb05_unused(void)

{
  ushort uVar1;
  
  uVar1 = REG_CANB_MB5_CS;
  uVar1 = REG_IFLAG_B;
  REG_IFLAG_B = uVar1 & 0xffdf;
  return;
}



// CAN-B MB06: Unused message buffer

void can_b_mb06_unused(void)

{
  ushort uVar1;
  
  uVar1 = REG_CANB_MB6_CS;
  uVar1 = REG_IFLAG_B;
  REG_IFLAG_B = uVar1 & 0xffbf;
  return;
}



// CAN-B MB7 unused: clears IFLAG_B bit 7

void can_b_mb07_unused(void)

{
  ushort uVar1;
  
  uVar1 = REG_CANB_MB7_CS;
  uVar1 = REG_IFLAG_B;
  REG_IFLAG_B = uVar1 & 0xff7f;
  return;
}



// CAN-B MB08: Unused message buffer

void can_b_mb08_unused(void)

{
  ushort uVar1;
  
  uVar1 = REG_IFLAG_B;
  REG_IFLAG_B = uVar1 & 0xfeff;
  return;
}



// CAN-B MB9 unused: clears IFLAG_B bit 9

void can_b_mb09_unused(void)

{
  ushort uVar1;
  
  uVar1 = REG_IFLAG_B;
  REG_IFLAG_B = uVar1 & 0xfdff;
  return;
}



// CAN-B MB10: Unused message buffer

void can_b_mb10_unused(void)

{
  ushort uVar1;
  
  uVar1 = REG_IFLAG_B;
  REG_IFLAG_B = uVar1 & 0xfbff;
  return;
}



// CAN-B MB11: Unused message buffer

void can_b_mb11_unused(void)

{
  ushort uVar1;
  
  uVar1 = REG_IFLAG_B;
  REG_IFLAG_B = uVar1 & 0xf7ff;
  return;
}



// CAN-B MB12: Unused message buffer

void can_b_mb12_unused(void)

{
  ushort uVar1;
  
  uVar1 = REG_IFLAG_B;
  REG_IFLAG_B = uVar1 & 0xefff;
  return;
}



// CAN-B MB13 receive: parks the shared rx data cursor (MB ID left 0 in init_can_b)

void can_b_mb13_recv(void)

{
  ushort uVar1;
  
  uVar1 = REG_CANB_MB13_CS;
  while ((uVar1 & 0x10) != 0) {
    uVar1 = REG_CANB_MB13_CS;
  }
  uVar1 = REG_CANB_MB13_CS;
  if ((uVar1 & 0x60) == 0x60) {
    REG_CANB_MB13_CS = 0x40;
    DAT_003f9068 = REG_TIMER_B;
  }
  else {
    uVar1 = REG_CANB_MB13_CS;
    if ((uVar1 & 0x20) != 0) {
      can_b_rx_data_ptr = &REG_CANB_MB13_DATA0;
    }
  }
  uVar1 = REG_IFLAG_B;
  REG_IFLAG_B = uVar1 & 0xdfff;
  return;
}



// CAN-B MB14 receive (ID 0x80): parks the shared rx data cursor

void can_b_mb14_recv_0x80(void)

{
  ushort uVar1;
  
  uVar1 = REG_CANB_MB14_CS;
  while ((uVar1 & 0x10) != 0) {
    uVar1 = REG_CANB_MB14_CS;
  }
  uVar1 = REG_CANB_MB14_CS;
  if ((uVar1 & 0x60) == 0x60) {
    REG_CANB_MB14_CS = 0x40;
    DAT_003f9068 = REG_TIMER_B;
  }
  else {
    uVar1 = REG_CANB_MB14_CS;
    if ((uVar1 & 0x20) != 0) {
      can_b_rx_data_ptr = &REG_CANB_MB14_DATA0;
    }
  }
  uVar1 = REG_IFLAG_B;
  REG_IFLAG_B = uVar1 & 0xbfff;
  return;
}



// CAN-B MB15 receive: dev interface (IDs 0x50-0x57), replies on MB0/MB1 (0x7a0). Register set is
// CAN-B; label was shifted from the CAN-A handler

void can_b_mb15_recv_dev(void)

{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  byte bVar4;
  byte bVar5;
  undefined2 uVar6;
  undefined4 uVar7;
  void **ppvVar8;
  byte *pbVar9;
  ushort uVar10;
  short sVar11;
  
  uVar10 = REG_CANB_MB15_CS;
  while ((uVar10 & 0x10) != 0) {
    uVar10 = REG_CANB_MB15_CS;
  }
  uVar10 = REG_CANB_MB15_CS;
  if ((uVar10 & 0x60) == 0x60) {
    REG_CANB_MB15_CS = 0x40;
    DAT_003f9068 = REG_TIMER_B;
  }
  else {
    uVar10 = REG_CANB_MB15_CS;
    if ((uVar10 & 0x20) != 0) {
      can_b_rx_data_ptr = &REG_CANB_MB15_DATA0;
      uVar10 = REG_CANB_MB15_ID_HI;
      if ((int)(uint)uVar10 >> 5 == 0x50) {
        uVar10 = REG_CANB_MB15_CS;
        if ((uVar10 & 0xf) == 4) {
          DAT_003f9058 = (byte *)Ram003075f6;
          REG_CANB_MB15_CS = 0x40;
          DAT_003f9068 = REG_TIMER_B;
          DAT_003f9078 = &REG_CANB_MB0_DATA0;
          REG_CANB_MB0_CS = 0x88;
          REG_CANB_MB0_ID_HI = 0xf400;
          Ram00307506 = *(undefined4 *)DAT_003f9058;
          REG_CANB_MB0_CS = 0xc4;
        }
        else {
          REG_CANB_MB15_CS = 0x40;
          DAT_003f9068 = REG_TIMER_B;
        }
      }
      else {
        uVar10 = REG_CANB_MB15_ID_HI;
        if ((int)(uint)uVar10 >> 5 == 0x51) {
          uVar10 = REG_CANB_MB15_CS;
          if ((uVar10 & 0xf) == 4) {
            DAT_003f9058 = (byte *)Ram003075f6;
            REG_CANB_MB15_CS = 0x40;
            DAT_003f9068 = REG_TIMER_B;
            DAT_003f9078 = &REG_CANB_MB0_DATA0;
            REG_CANB_MB0_CS = 0x88;
            REG_CANB_MB0_ID_HI = 0xf400;
            Ram00307506 = *(undefined2 *)DAT_003f9058;
            REG_CANB_MB0_CS = 0xc2;
          }
          else {
            uVar10 = REG_CANB_MB15_CS;
            if ((uVar10 & 0xf) == 6) {
              bVar1 = REG_CANB_MB15_DATA0;
              bVar2 = REG_CANB_MB15_DATA1;
              bVar3 = REG_CANB_MB15_DATA2;
              bVar4 = REG_CANB_MB15_DATA3;
              can_b_rx_data_ptr = &REG_CANB_MB15_DATA5;
              bVar5 = REG_CANB_MB15_DATA4;
              DAT_003f9074 = (struct_varptr *)CONCAT31(CONCAT21(CONCAT11(bVar2,bVar3),bVar4),bVar5);
              bVar2 = REG_CANB_MB15_DATA5;
              REG_CANB_MB15_CS = 0x40;
              DAT_003f9068 = REG_TIMER_B;
              DAT_003f9060 = DAT_003f9074;
              if (bVar2 == 1) {
                REG_CANB_MB1_CS = 0x88;
                REG_CANB_MB1_ID_HI = (ushort)bVar1 << 8 | 0x20;
                DAT_003f9078 = &REG_CANB_MB1_DATA1;
                REG_CANB_MB1_DATA0 = 10;
                REG_CANB_MB1_DATA1 = *(byte *)&DAT_003f9074->ptr;
                REG_CANB_MB1_CS = 0xc2;
              }
              else if (bVar2 == 2) {
                REG_CANB_MB1_CS = 0x88;
                REG_CANB_MB1_ID_HI = (ushort)bVar1 << 8 | 0x20;
                REG_CANB_MB1_DATA0 = 10;
                DAT_003f9060 = (struct_varptr *)((int)&DAT_003f9074->ptr + 1);
                DAT_003f9078 = &REG_CANB_MB1_DATA2;
                REG_CANB_MB1_DATA1 = *(byte *)&DAT_003f9074->ptr;
                REG_CANB_MB1_DATA2 = *(byte *)&DAT_003f9060->ptr;
                REG_CANB_MB1_CS = 0xc3;
              }
              else if (bVar2 == 4) {
                REG_CANB_MB1_CS = 0x88;
                REG_CANB_MB1_ID_HI = (ushort)bVar1 << 8 | 0x20;
                REG_CANB_MB1_DATA0 = 10;
                REG_CANB_MB1_DATA1 = *(byte *)&DAT_003f9074->ptr;
                REG_CANB_MB1_DATA2 = *(byte *)((int)&DAT_003f9074->ptr + 1);
                DAT_003f9060 = (struct_varptr *)((int)&DAT_003f9074->ptr + 3);
                DAT_003f9078 = &REG_CANB_MB1_DATA4;
                REG_CANB_MB1_DATA3 = *(byte *)((int)&DAT_003f9074->ptr + 2);
                REG_CANB_MB1_DATA4 = *(byte *)&DAT_003f9060->ptr;
                REG_CANB_MB1_CS = 0xc5;
              }
            }
            else {
              REG_CANB_MB15_CS = 0x40;
              DAT_003f9068 = REG_TIMER_B;
            }
          }
        }
        else {
          uVar10 = REG_CANB_MB15_ID_HI;
          if ((int)(uint)uVar10 >> 5 == 0x52) {
            uVar10 = REG_CANB_MB15_CS;
            if ((uVar10 & 0xf) == 4) {
              DAT_003f9058 = (byte *)Ram003075f6;
              REG_CANB_MB15_CS = 0x40;
              DAT_003f9068 = REG_TIMER_B;
              DAT_003f9078 = &REG_CANB_MB0_DATA0;
              REG_CANB_MB0_CS = 0x88;
              REG_CANB_MB0_ID_HI = 0xf400;
              REG_CANB_MB0_DATA0 = *DAT_003f9058;
              REG_CANB_MB0_CS = 0xc1;
            }
            else {
              uVar10 = REG_CANB_MB15_CS;
              if ((uVar10 & 0xf) == 7) {
                bVar1 = REG_CANB_MB15_DATA0;
                bVar2 = REG_CANB_MB15_DATA1;
                bVar3 = REG_CANB_MB15_DATA2;
                bVar4 = REG_CANB_MB15_DATA3;
                bVar5 = REG_CANB_MB15_DATA4;
                DAT_003f9074 = (struct_varptr *)
                               CONCAT31(CONCAT21(CONCAT11(bVar2,bVar3),bVar4),bVar5);
                can_b_rx_data_ptr = &REG_CANB_MB15_DATA7;
                bVar2 = REG_CANB_MB15_DATA6;
                uVar10 = (ushort)bVar2;
                REG_CANB_MB15_CS = 0x40;
                DAT_003f9068 = REG_TIMER_B;
                DAT_003f9060 = DAT_003f9074;
                DAT_003f9078 = &REG_CANB_MB1_DATA0;
                REG_CANB_MB1_CS = 0x88;
                REG_CANB_MB1_ID_HI = (ushort)bVar1 << 8 | 0x40;
                if (8 < bVar2) {
                  uVar10 = 8;
                }
                for (; uVar10 != 0; uVar10 = uVar10 - 1) {
                  ppvVar8 = &DAT_003f9060->ptr;
                  DAT_003f9060 = (struct_varptr *)((int)&DAT_003f9060->ptr + 1);
                  pbVar9 = DAT_003f9078 + 1;
                  *DAT_003f9078 = *(byte *)ppvVar8;
                  DAT_003f9078 = pbVar9;
                }
                REG_CANB_MB1_CS = 200;
              }
              else {
                REG_CANB_MB15_CS = 0x40;
                DAT_003f9068 = REG_TIMER_B;
              }
            }
          }
          else {
            uVar10 = REG_CANB_MB15_ID_HI;
            if ((int)(uint)uVar10 >> 5 == 0x53) {
              uVar10 = REG_CANB_MB15_CS;
              if ((uVar10 & 0xf) == 5) {
                DAT_003f9064 = 0;
                can_b_rx_data_ptr = &REG_CANB_MB15_DATA4;
                DAT_003f9058 = (byte *)Ram003075f6;
                bVar1 = REG_CANB_MB15_DATA4;
                DAT_003f9066 = (ushort)bVar1;
                REG_CANB_MB15_CS = 0x40;
                DAT_003f9068 = REG_TIMER_B;
                DAT_003f9078 = &REG_CANB_MB0_DATA0;
                REG_CANB_MB0_CS = 0x88;
                REG_CANB_MB0_ID_HI = 0xf400;
                uVar10 = DAT_003f9066;
                if (DAT_003f9066 < 9) {
                  for (; uVar10 != 0; uVar10 = uVar10 - 1) {
                    bVar1 = *DAT_003f9058;
                    DAT_003f9058 = DAT_003f9058 + 1;
                    pbVar9 = DAT_003f9078 + 1;
                    *DAT_003f9078 = bVar1;
                    DAT_003f9078 = pbVar9;
                  }
                  REG_CANB_MB0_CS = DAT_003f9066 + 0xc0;
                  DAT_003f9066 = 0;
                }
                else {
                  for (sVar11 = 8; sVar11 != 0; sVar11 = sVar11 + -1) {
                    bVar1 = *DAT_003f9058;
                    DAT_003f9058 = DAT_003f9058 + 1;
                    pbVar9 = DAT_003f9078 + 1;
                    *DAT_003f9078 = bVar1;
                    DAT_003f9078 = pbVar9;
                  }
                  REG_CANB_MB0_CS = 200;
                  DAT_003f9066 = DAT_003f9066 - 8;
                }
              }
              else {
                uVar10 = REG_CANB_MB15_CS;
                if ((uVar10 & 0xf) == 6) {
                  DAT_003f9064 = 0;
                  can_b_rx_data_ptr = &REG_CANB_MB15_DATA4;
                  DAT_003f9058 = (byte *)Ram003075f6;
                  DAT_003f9066 = Ram003075fa;
                  REG_CANB_MB15_CS = 0x40;
                  DAT_003f9068 = REG_TIMER_B;
                  DAT_003f9078 = &REG_CANB_MB0_DATA0;
                  REG_CANB_MB0_CS = 0x88;
                  REG_CANB_MB0_ID_HI = 0xf400;
                  uVar10 = DAT_003f9066;
                  if (DAT_003f9066 < 9) {
                    for (; uVar10 != 0; uVar10 = uVar10 - 1) {
                      bVar1 = *DAT_003f9058;
                      DAT_003f9058 = DAT_003f9058 + 1;
                      pbVar9 = DAT_003f9078 + 1;
                      *DAT_003f9078 = bVar1;
                      DAT_003f9078 = pbVar9;
                    }
                    REG_CANB_MB0_CS = DAT_003f9066 + 0xc0;
                    DAT_003f9066 = 0;
                  }
                  else {
                    for (sVar11 = 8; sVar11 != 0; sVar11 = sVar11 + -1) {
                      bVar1 = *DAT_003f9058;
                      DAT_003f9058 = DAT_003f9058 + 1;
                      pbVar9 = DAT_003f9078 + 1;
                      *DAT_003f9078 = bVar1;
                      DAT_003f9078 = pbVar9;
                    }
                    REG_CANB_MB0_CS = 200;
                    DAT_003f9066 = DAT_003f9066 - 8;
                  }
                }
                else {
                  uVar10 = REG_CANB_MB15_CS;
                  if ((uVar10 & 0xf) == 4) {
                    DAT_003f9058 = (byte *)Ram003075f6;
                    REG_CANB_MB15_CS = 0x40;
                    DAT_003f9068 = REG_TIMER_B;
                    DAT_003f9078 = &REG_CANB_MB0_DATA0;
                    REG_CANB_MB0_CS = 0x88;
                    REG_CANB_MB0_ID_HI = 0xf400;
                    Ram00307506 = 0x7601c;
                    REG_CANB_MB0_CS = 0xc4;
                  }
                  else {
                    uVar10 = REG_CANB_MB15_CS;
                    if ((uVar10 & 0xf) == 1) {
                      bVar1 = REG_CANB_MB15_DATA0;
                      REG_CANB_MB15_CS = 0x40;
                      DAT_003f9068 = REG_TIMER_B;
                      REG_CANB_MB1_CS = 0x88;
                      REG_CANB_MB1_ID_HI = (ushort)bVar1 << 8 | 0x60;
                      DAT_003f9060 = struct_varptr_ARRAY_0007601c;
                      REG_CANB_MB1_DATA0 = 10;
                      REG_CANB_MB1_DATA1 = 0;
                      REG_CANB_MB1_DATA2 = 7;
                      REG_CANB_MB1_DATA3 = 0x60;
                      REG_CANB_MB1_DATA4 = 0x1c;
                      DAT_003f9078 = &REG_CANB_MB1_DATA6;
                      REG_CANB_MB1_DATA5 = 0;
                      REG_CANB_MB1_CS = 0xc6;
                    }
                    else {
                      REG_CANB_MB15_CS = 0x40;
                      DAT_003f9068 = REG_TIMER_B;
                    }
                  }
                }
              }
            }
            else {
              uVar10 = REG_CANB_MB15_ID_HI;
              if ((int)(uint)uVar10 >> 5 == 0x54) {
                uVar10 = REG_CANB_MB15_CS;
                if ((uVar10 & 0xf) == 8) {
                  can_b_rx_data_ptr = &REG_CANB_MB15_DATA4;
                  DAT_003f905c = (byte *)Ram003075f6;
                  REG_CANB_MB15_CS = 0x40;
                  DAT_003f9068 = REG_TIMER_B;
                  DAT_003f9078 = &REG_CANB_MB0_DATA0;
                  uVar7 = Ram003075fa;
                  *(undefined4 *)DAT_003f905c = uVar7;
                }
                else {
                  REG_CANB_MB15_CS = 0x40;
                  DAT_003f9068 = REG_TIMER_B;
                }
              }
              else {
                uVar10 = REG_CANB_MB15_ID_HI;
                if ((int)(uint)uVar10 >> 5 == 0x55) {
                  uVar10 = REG_CANB_MB15_CS;
                  if ((uVar10 & 0xf) == 6) {
                    can_b_rx_data_ptr = &REG_CANB_MB15_DATA4;
                    DAT_003f905c = (byte *)Ram003075f6;
                    REG_CANB_MB15_CS = 0x40;
                    DAT_003f9068 = REG_TIMER_B;
                    uVar6 = Ram003075fa;
                    *(undefined2 *)DAT_003f905c = uVar6;
                  }
                  else {
                    REG_CANB_MB15_CS = 0x40;
                    DAT_003f9068 = REG_TIMER_B;
                  }
                }
                else {
                  uVar10 = REG_CANB_MB15_ID_HI;
                  if ((int)(uint)uVar10 >> 5 == 0x56) {
                    uVar10 = REG_CANB_MB15_CS;
                    if ((uVar10 & 0xf) == 5) {
                      can_b_rx_data_ptr = &REG_CANB_MB15_DATA4;
                      DAT_003f905c = (byte *)Ram003075f6;
                      REG_CANB_MB15_CS = 0x40;
                      DAT_003f9068 = REG_TIMER_B;
                      bVar1 = REG_CANB_MB15_DATA4;
                      *DAT_003f905c = bVar1;
                    }
                    else {
                      REG_CANB_MB15_CS = 0x40;
                      DAT_003f9068 = REG_TIMER_B;
                    }
                  }
                  else {
                    uVar10 = REG_CANB_MB15_ID_HI;
                    if ((int)(uint)uVar10 >> 5 == 0x57) {
                      if (DAT_003f9064 == 0) {
                        uVar10 = REG_CANB_MB15_CS;
                        if ((uVar10 & 0xf) == 5) {
                          can_b_rx_data_ptr = &REG_CANB_MB15_DATA4;
                          DAT_003f905c = (byte *)Ram003075f6;
                          bVar1 = REG_CANB_MB15_DATA4;
                          DAT_003f9064 = (ushort)bVar1;
                          REG_CANB_MB15_CS = 0x40;
                          DAT_003f9068 = REG_TIMER_B;
                        }
                        else {
                          REG_CANB_MB15_CS = 0x40;
                          DAT_003f9068 = REG_TIMER_B;
                        }
                      }
                      else {
                        uVar10 = REG_CANB_MB15_CS;
                        for (uVar10 = uVar10 & 0xf; uVar10 != 0; uVar10 = uVar10 - 1) {
                          bVar1 = *can_b_rx_data_ptr;
                          pbVar9 = DAT_003f905c + 1;
                          can_b_rx_data_ptr = can_b_rx_data_ptr + 1;
                          *DAT_003f905c = bVar1;
                          DAT_003f905c = pbVar9;
                          DAT_003f9064 = DAT_003f9064 - 1;
                        }
                        REG_CANB_MB15_CS = 0x40;
                        DAT_003f9068 = REG_TIMER_B;
                      }
                    }
                    else {
                      REG_CANB_MB15_CS = 0x40;
                      DAT_003f9068 = REG_TIMER_B;
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
  uVar10 = REG_IFLAG_B;
  REG_IFLAG_B = uVar10 & 0x7fff;
  return;
}



// CAN-B: Clears wake-up error flags

void can_b_wake_error_clear(void)

{
  ushort uVar1;
  
  uVar1 = REG_ESTAT_B;
  REG_ESTAT_B = uVar1 & 0xfffb;
  return;
}



// CAN-B: Clears receive warning flags

void can_b_rx_warning_clear(void)

{
  ushort uVar1;
  
  uVar1 = REG_ESTAT_B;
  REG_ESTAT_B = uVar1 & 0xfffd;
  return;
}



// ISR: CAN-B interrupt - handles TPMS message buffers

undefined8 isr_can_b(undefined4 param_1,undefined4 param_2)

{
  ushort uVar1;
  uint uVar2;
  ushort uVar3;
  undefined4 in_MSR;
  undefined4 in_SRR1;
  
  uVar1 = REG_IFLAG_B;
  uVar3 = REG_IMASK_B;
  uVar1 = uVar1 & uVar3;
  if (uVar1 < 0x100) {
    if (uVar1 < 0x10) {
      if (uVar1 < 4) {
        if (uVar1 < 2) {
          can_b_mb00_send_dev_multiframe();
        }
        else {
          can_b_mb01_unused();
        }
      }
      else if (uVar1 < 8) {
        can_b_mb02_unused();
      }
      else {
        can_b_mb03_send_0x101_cont();
      }
    }
    else if (uVar1 < 0x40) {
      if (uVar1 < 0x20) {
        can_b_mb04_unused();
      }
      else {
        can_b_mb05_unused();
      }
    }
    else if (uVar1 < 0x80) {
      can_b_mb06_unused();
    }
    else {
      can_b_mb07_unused();
    }
  }
  else if (uVar1 < 0x1000) {
    if (uVar1 < 0x400) {
      if (uVar1 < 0x200) {
        can_b_mb08_unused();
      }
      else {
        can_b_mb09_unused();
      }
    }
    else if (uVar1 < 0x800) {
      can_b_mb10_unused();
    }
    else {
      can_b_mb11_unused();
    }
  }
  else if (uVar1 < 0x4000) {
    if (uVar1 < 0x2000) {
      can_b_mb12_unused();
    }
    else {
      can_b_mb13_recv();
    }
  }
  else if (uVar1 < 0x8000) {
    can_b_mb14_recv_0x80();
  }
  else {
    can_b_mb15_recv_dev();
  }
  uVar1 = REG_ESTAT_B;
  if ((uVar1 >> 1 & 1) == 1) {
    can_b_rx_warning_clear();
  }
  uVar1 = REG_ESTAT_B;
  if ((uVar1 >> 2 & 1) == 1) {
    can_b_wake_error_clear();
  }
  uVar2 = REG_SISR3;
  REG_SISR3 = uVar2 & 0xbfffffff | 0x40000000;
  returnFromInterrupt(in_MSR,in_SRR1);
  return CONCAT44(param_1,param_2);
}



// Initializes CAN-A module for OBD diagnostics and cluster communication

void init_can_a(void)

{
  ushort uVar1;
  
  uVar1 = REG_CANMCR_A;
  REG_CANMCR_A = uVar1 | 0x200;
  do {
    uVar1 = REG_CANMCR_A;
  } while ((uVar1 & 0x200) != 0);
  uVar1 = REG_CANMCR_A;
  REG_CANMCR_A = uVar1 | 0x1000;
  do {
    uVar1 = REG_CANMCR_A;
  } while ((uVar1 & 0x900) != 0x900);
  REG_CANCTRL0_A = 0;
  REG_CANCTRL1_A = 4;
  REG_CTRL2_A = 0xf6;
  REG_PRESDIV_A = 1;
  REG_CANA_MB0_CS = 0;
  REG_CANA_MB0_ID_HI = 0;
  REG_CANA_MB0_ID_LO = 0;
  uVar1 = REG_CANA_MB0_CS;
  REG_CANA_MB0_CS = uVar1 | 0x80;
  REG_CANA_MB1_CS = 0;
  REG_CANA_MB1_ID_HI = 0;
  REG_CANA_MB1_ID_LO = 0;
  uVar1 = REG_CANA_MB1_CS;
  REG_CANA_MB1_CS = uVar1 | 0x80;
  REG_CANA_MB2_CS = 0;
  REG_CANA_MB2_ID_HI = 0;
  REG_CANA_MB2_ID_LO = 0;
  uVar1 = REG_CANA_MB2_CS;
  REG_CANA_MB2_CS = uVar1 | 0x80;
  REG_CANA_MB3_CS = 0;
  REG_CANA_MB3_ID_HI = 0;
  REG_CANA_MB3_ID_LO = 0;
  uVar1 = REG_CANA_MB3_CS;
  REG_CANA_MB3_CS = uVar1 | 0x80;
  REG_CANA_MB4_CS = 0;
  REG_CANA_MB4_ID_HI = 0;
  REG_CANA_MB4_ID_LO = 0;
  uVar1 = REG_CANA_MB4_CS;
  REG_CANA_MB4_CS = uVar1 | 0x80;
  REG_CANA_MB5_CS = 0;
  REG_CANA_MB5_ID_HI = 0;
  REG_CANA_MB5_ID_LO = 0;
  uVar1 = REG_CANA_MB5_CS;
  REG_CANA_MB5_CS = uVar1 | 0x80;
  REG_CANA_MB6_CS = 0;
  REG_CANA_MB6_ID_HI = 0x6200;
  REG_CANA_MB6_ID_LO = 0;
  uVar1 = REG_CANA_MB6_CS;
  REG_CANA_MB6_CS = uVar1 | 0x40;
  REG_CANA_MB7_CS = 0;
  REG_CANA_MB7_ID_HI = 0;
  REG_CANA_MB7_ID_LO = 0;
  uVar1 = REG_CANA_MB7_CS;
  REG_CANA_MB7_CS = uVar1 | 0x80;
  REG_CANA_MB8_CS = 0;
  REG_CANA_MB8_ID_HI = 0;
  REG_CANA_MB8_ID_LO = 0;
  uVar1 = REG_CANA_MB8_CS;
  REG_CANA_MB8_CS = uVar1 | 0x80;
  REG_CANA_MB9_CS = 0;
  REG_CANA_MB9_ID_HI = 0;
  REG_CANA_MB9_ID_LO = 0;
  uVar1 = REG_CANA_MB9_CS;
  REG_CANA_MB9_CS = uVar1 | 0x80;
  REG_CANA_MB10_CS = 0;
  REG_CANA_MB10_ID_HI = 0;
  REG_CANA_MB10_ID_LO = 0;
  uVar1 = REG_CANA_MB10_CS;
  REG_CANA_MB10_CS = uVar1 | 0x80;
  REG_CANA_MB11_CS = 0;
  REG_CANA_MB11_ID_HI = 0;
  REG_CANA_MB11_ID_LO = 0;
  uVar1 = REG_CANA_MB11_CS;
  REG_CANA_MB11_CS = uVar1 | 0x80;
  REG_CANA_MB12_CS = 0;
  REG_CANA_MB12_ID_HI = 0;
  REG_CANA_MB12_ID_LO = 0;
  uVar1 = REG_CANA_MB12_CS;
  REG_CANA_MB12_CS = uVar1 | 0x80;
  REG_CANA_MB13_CS = 0;
  REG_CANA_MB13_ID_HI = 0;
  REG_CANA_MB13_ID_LO = 0;
  uVar1 = REG_CANA_MB13_CS;
  REG_CANA_MB13_CS = uVar1 | 0x40;
  REG_CANA_MB14_CS = 0;
  REG_CANA_MB14_ID_HI = 0x1000;
  REG_CANA_MB14_ID_LO = 0;
  uVar1 = REG_CANA_MB14_CS;
  REG_CANA_MB14_CS = uVar1 | 0x40;
  REG_CANA_MB15_CS = 0;
  REG_CANA_MB15_ID_HI = 0xa00;
  REG_CANA_MB15_ID_LO = 0;
  uVar1 = REG_CANA_MB15_CS;
  REG_CANA_MB15_CS = uVar1 | 0x40;
  REG_RXGMSKHI_A = 0xff0f;
  REG_RXGMSKLO_A = 0xfffe;
  REG_RX14MSKHI_A = 0xffef;
  REG_RX14MSKLO_A = 0xfffe;
  REG_RX15MSKHI_A = 0xff0f;
  REG_RX15MSKLO_A = 0xfffe;
  uVar1 = REG_ESTAT_A;
  REG_ESTAT_A = uVar1 & 0xfff8;
  REG_CANICR_A = 0;
  uVar1 = REG_CANICR_A;
  REG_CANICR_A = uVar1 & 0xf8ff | 0x400;
  uVar1 = REG_CANICR_A;
  REG_CANICR_A = uVar1 & 0xff3f | 0x80;
  if (dev_unlocked) {
    REG_IMASK_A = 0xe1ff;
  }
  else {
    REG_IMASK_A = 0x61ff;
  }
  uVar1 = REG_CANMCR_A;
  REG_CANMCR_A = uVar1 & 0xefff;
  return;
}



// MB0 tx-complete: continues streaming dev bulk-read responses on 0x7a0 (black91's
// can_a_mb00_send_obd_multiframe plays this role and is equally misnamed there)

void can_a_mb00_send_dev_read_cont(void)

{
  byte bVar1;
  byte *pbVar2;
  short sVar3;
  ushort uVar4;
  
  uVar4 = REG_CANA_MB0_CS;
  uVar4 = REG_IFLAG_A;
  REG_IFLAG_A = uVar4 & 0xfffe;
  if (DAT_003f908e != 0) {
    DAT_003f9098 = &REG_CANA_MB0_DATA0;
    REG_CANA_MB0_CS = 0x88;
    REG_CANA_MB0_ID_HI = 0xf400;
    uVar4 = DAT_003f908e;
    if (DAT_003f908e < 9) {
      for (; uVar4 != 0; uVar4 = uVar4 - 1) {
        bVar1 = *DAT_003f9080;
        DAT_003f9080 = DAT_003f9080 + 1;
        pbVar2 = DAT_003f9098 + 1;
        *DAT_003f9098 = bVar1;
        DAT_003f9098 = pbVar2;
      }
      REG_CANA_MB0_CS = DAT_003f908e + 0xc0;
      DAT_003f908e = 0;
    }
    else {
      for (sVar3 = 8; sVar3 != 0; sVar3 = sVar3 + -1) {
        bVar1 = *DAT_003f9080;
        DAT_003f9080 = DAT_003f9080 + 1;
        pbVar2 = DAT_003f9098 + 1;
        *DAT_003f9098 = bVar1;
        DAT_003f9098 = pbVar2;
      }
      REG_CANA_MB0_CS = 200;
      DAT_003f908e = DAT_003f908e - 8;
    }
  }
  return;
}



// CAN-A MB01: Unused message buffer

void can_a_mb01_unused(void)

{
  ushort uVar1;
  
  uVar1 = REG_CANA_MB1_CS;
  uVar1 = REG_IFLAG_A;
  REG_IFLAG_A = uVar1 & 0xfffd;
  return;
}



// CAN-A: Sends data logging frames

void can_a_mb02_send_log(void)

{
  byte bVar1;
  ushort uVar2;
  byte *pbVar3;
  short sVar4;
  
  uVar2 = REG_CANA_MB2_CS;
  uVar2 = REG_IFLAG_A;
  REG_IFLAG_A = uVar2 & 0xfffb;
  if (log_canid[DAT_003fe0ac] != 0) {
    DAT_003f9098 = &REG_CANA_MB2_DATA0;
    REG_CANA_MB2_CS = 0x88;
    REG_CANA_MB2_ID_HI = (ushort)((int)(short)log_canid[DAT_003fe0ac] << 5);
    for (sVar4 = 0; sVar4 < 8; sVar4 = sVar4 + 1) {
      bVar1 = *DAT_003fe0b0;
      pbVar3 = DAT_003f9098 + 1;
      DAT_003fe0b0 = DAT_003fe0b0 + 1;
      *DAT_003f9098 = bVar1;
      DAT_003f9098 = pbVar3;
    }
    REG_CANA_MB2_CS = 200;
    DAT_003fe0ac = DAT_003fe0ac + 1;
  }
  return;
}



// CAN-A MB03: Unused message buffer

void can_a_mb03_unused(void)

{
  ushort uVar1;
  
  uVar1 = REG_CANA_MB3_CS;
  uVar1 = REG_IFLAG_A;
  REG_IFLAG_A = uVar1 & 0xfff7;
  return;
}



// CAN-A MB4 unused: clears IFLAG_A bit 4

void can_a_mb04_unused(void)

{
  ushort uVar1;
  
  uVar1 = REG_CANA_MB4_CS;
  uVar1 = REG_IFLAG_A;
  REG_IFLAG_A = uVar1 & 0xffef;
  return;
}



// CAN-A MB05: Unused message buffer

void can_a_mb05_unused(void)

{
  ushort uVar1;
  
  uVar1 = REG_CANA_MB5_CS;
  uVar1 = REG_IFLAG_A;
  REG_IFLAG_A = uVar1 & 0xffdf;
  return;
}



// WARNING: Inlined function: push_24to31
// WARNING: Inlined function: pop_24to31
// CAN-A: Receives ID 0x310 messages

void can_a_mb06_recv_0x310(void)

{
  ushort uVar1;
  byte bVar2;
  byte bVar3;
  byte bVar4;
  byte bVar5;
  byte bVar6;
  byte bVar7;
  byte bVar8;
  byte bVar9;
  
  uVar1 = REG_IFLAG_A;
  REG_IFLAG_A = uVar1 & 0xffbf;
  uVar1 = REG_CANA_MB6_CS;
  if ((uVar1 & 0xf0) == 0x80) {
    do {
      uVar1 = REG_CANA_MB6_CS;
    } while ((uVar1 & 0x10) != 0);
  }
  uVar1 = REG_CANA_MB6_CS;
  if ((uVar1 & 0x60) == 0x60) {
    REG_CANA_MB6_CS = 0x40;
  }
  else {
    uVar1 = REG_CANA_MB6_CS;
    if (((uVar1 & 0x20) != 0) && (uVar1 = REG_CANA_MB6_ID_HI, (int)(uint)uVar1 >> 5 == 0x310)) {
      bVar2 = REG_CANA_MB6_DATA0;
      bVar3 = REG_CANA_MB6_DATA1;
      bVar4 = REG_CANA_MB6_DATA2;
      bVar5 = REG_CANA_MB6_DATA3;
      bVar6 = REG_CANA_MB6_DATA4;
      bVar7 = REG_CANA_MB6_DATA5;
      bVar8 = REG_CANA_MB6_DATA6;
      bVar9 = REG_CANA_MB6_DATA7;
      DAT_003fe0bc = CONCAT11(bVar2,bVar3);
      DAT_003fe0c4 = CONCAT11(bVar4,bVar5);
      DAT_003fe0c6 = CONCAT11(bVar6,bVar7);
      DAT_003fe0c8 = CONCAT11(bVar8,bVar9);
    }
  }
  return;
}



// CAN-A MB07: Unused message buffer

void can_a_mb07_unused(void)

{
  ushort uVar1;
  
  uVar1 = REG_IFLAG_A;
  REG_IFLAG_A = uVar1 & 0xff7f;
  return;
}



// CAN-A MB8 unused: clears IFLAG_A bit 8

void can_a_mb08_unused(void)

{
  ushort uVar1;
  
  uVar1 = REG_IFLAG_A;
  REG_IFLAG_A = uVar1 & 0xfeff;
  return;
}



// CAN-A MB09: Unused message buffer

void can_a_mb09_unused(void)

{
  ushort uVar1;
  
  uVar1 = REG_IFLAG_A;
  REG_IFLAG_A = uVar1 & 0xfdff;
  return;
}



// CAN-A MB10: Unused message buffer

void can_a_mb10_unused(void)

{
  ushort uVar1;
  
  uVar1 = REG_IFLAG_A;
  REG_IFLAG_A = uVar1 & 0xfbff;
  return;
}



// CAN-A MB11: Unused message buffer

void can_a_mb11_unused(void)

{
  ushort uVar1;
  
  uVar1 = REG_IFLAG_A;
  REG_IFLAG_A = uVar1 & 0xf7ff;
  return;
}



// CAN-A MB12: Unused message buffer

void can_a_mb12_unused(void)

{
  ushort uVar1;
  
  uVar1 = REG_IFLAG_A;
  REG_IFLAG_A = uVar1 & 0xefff;
  return;
}



// CAN-A: Receives ID 0x100 messages (external input)

void can_a_mb13_recv_0x100(void)

{
  byte bVar1;
  ushort uVar2;
  byte *pbVar3;
  short sVar4;
  
  uVar2 = REG_CANA_MB13_CS;
  while ((uVar2 & 0x10) != 0) {
    uVar2 = REG_CANA_MB13_CS;
  }
  uVar2 = REG_CANA_MB13_CS;
  if ((uVar2 & 0x60) == 0x60) {
    REG_CANA_MB13_CS = 0x40;
    DAT_003f9090 = REG_TIMER_A;
  }
  else {
    uVar2 = REG_CANA_MB13_CS;
    if ((uVar2 & 0x20) != 0) {
      DAT_003f909c = &REG_CANA_MB13_DATA0;
      uVar2 = REG_CANA_MB13_ID_HI;
      if ((int)(uint)uVar2 >> 5 == 0x100) {
        if (DAT_003fe0b4 == '\x01') {
          REG_CANA_MB13_CS = 0x40;
          DAT_003f9090 = REG_TIMER_A;
        }
        else {
          DAT_003f909c = &REG_CANA_MB13_DATA1;
          bVar1 = REG_CANA_MB13_DATA0;
          if (bVar1 == 2) {
            REG_CANA_MB13_CS = 0x40;
            DAT_003f9090 = REG_TIMER_A;
            DAT_003fe0b8 = &DAT_003f8a88;
            REG_CANA_MB3_CS = 0x88;
            REG_CANA_MB3_ID_HI = 0x2020;
            REG_CANA_MB3_DATA0 = 0x1b;
            DAT_003fe09c = 2;
            DAT_003f9098 = &REG_CANA_MB3_DATA2;
            REG_CANA_MB3_DATA1 = 1;
            for (sVar4 = 0; sVar4 < 6; sVar4 = sVar4 + 1) {
              bVar1 = *DAT_003fe0b8;
              pbVar3 = DAT_003f9098 + 1;
              DAT_003fe0b8 = DAT_003fe0b8 + 1;
              *DAT_003f9098 = bVar1;
              DAT_003f9098 = pbVar3;
            }
            REG_CANA_MB3_CS = 200;
          }
          else {
            REG_CANA_MB13_CS = 0x40;
            DAT_003f9090 = REG_TIMER_A;
          }
        }
      }
      else {
        REG_CANA_MB13_CS = 0x40;
        DAT_003f9090 = REG_TIMER_A;
      }
    }
  }
  uVar2 = REG_IFLAG_A;
  REG_IFLAG_A = uVar2 & 0xdfff;
  return;
}



// CAN-A: Receives logging configuration requests

void can_a_mb14_recv_log(void)

{
  byte bVar1;
  ushort uVar2;
  byte *pbVar3;
  short sVar4;
  
  uVar2 = REG_CANA_MB14_CS;
  while ((uVar2 & 0x10) != 0) {
    uVar2 = REG_CANA_MB14_CS;
  }
  uVar2 = REG_CANA_MB14_CS;
  if ((uVar2 & 0x60) == 0x60) {
    REG_CANA_MB14_CS = 0x40;
    DAT_003f9090 = REG_TIMER_A;
  }
  else {
    uVar2 = REG_CANA_MB14_CS;
    if ((uVar2 & 0x20) != 0) {
      DAT_003f909c = &REG_CANA_MB14_DATA0;
      uVar2 = REG_CANA_MB14_ID_HI;
      if ((int)(uint)uVar2 >> 5 == 0x80) {
        DAT_003fe0b4 = 1;
        DAT_003f909c = &REG_CANA_MB14_DATA1;
        DAT_003fe0ad = REG_CANA_MB14_DATA1;
        REG_CANA_MB14_CS = 0x40;
        DAT_003f9090 = REG_TIMER_A;
        if (((DAT_003fe0ad == 7) || (DAT_003fe0ad == 6)) || (DAT_003fe0ad == 5)) {
          DAT_003fe0ac = 1;
          log_canid[0] = 512;
          log_canid[1] = 516;
          log_canid[2] = 520;
          log_canid[3] = 524;
          log_canid[4] = 528;
          log_canid[5] = 532;
          log_canid[6] = 536;
          log_canid[7] = 540;
          log_canid[8] = 544;
          log_canid[9] = 548;
          log_canid[10] = 552;
          log_canid[0xb] = 556;
          log_canid[0xc] = 0;
          DAT_003fe0b0 = log_data;
          DAT_003f9098 = &REG_CANA_MB2_DATA0;
          REG_CANA_MB2_CS = 0x88;
          REG_CANA_MB2_ID_HI = 0x4000;
          for (sVar4 = 0; sVar4 < 8; sVar4 = sVar4 + 1) {
            bVar1 = *DAT_003fe0b0;
            pbVar3 = DAT_003f9098 + 1;
            DAT_003fe0b0 = (char *)((byte *)DAT_003fe0b0 + 1);
            *DAT_003f9098 = bVar1;
            DAT_003f9098 = pbVar3;
          }
          REG_CANA_MB2_CS = 200;
        }
        else if ((DAT_003fe0ad == 4) || (DAT_003fe0ad == 2)) {
          DAT_003fe0ac = 1;
          log_canid[0] = 512;
          log_canid[1] = 516;
          log_canid[2] = 520;
          log_canid[3] = 524;
          log_canid[4] = 528;
          log_canid[5] = 532;
          log_canid[6] = 536;
          log_canid[7] = 540;
          log_canid[8] = 544;
          log_canid[9] = 548;
          log_canid[10] = 552;
          log_canid[0xb] = 556;
          log_canid[0xc] = 560;
          log_canid[0xd] = 564;
          log_canid[0xe] = 568;
          log_canid[0xf] = 572;
          log_canid[0x10] = 576;
          log_canid[0x11] = 580;
          log_canid[0x12] = 584;
          log_canid[0x13] = 588;
          log_canid[0x14] = 592;
          log_canid[0x15] = 596;
          log_canid[0x16] = 600;
          log_canid[0x17] = 604;
          log_canid[0x18] = 608;
          log_canid[0x19] = 612;
          log_canid[0x1a] = 616;
          log_canid[0x1b] = 620;
          log_canid[0x1c] = 624;
          log_canid[0x1d] = 628;
          log_canid[0x1e] = 632;
          log_canid[0x1f] = 636;
          log_canid[0x20] = 640;
          log_canid[0x21] = 644;
          log_canid[0x22] = 648;
          log_canid[0x23] = 652;
          log_canid[0x24] = 0;
          DAT_003fe0b0 = log_data;
          DAT_003f9098 = &REG_CANA_MB2_DATA0;
          REG_CANA_MB2_CS = 0x88;
          REG_CANA_MB2_ID_HI = 0x4000;
          for (sVar4 = 0; sVar4 < 8; sVar4 = sVar4 + 1) {
            bVar1 = *DAT_003fe0b0;
            pbVar3 = DAT_003f9098 + 1;
            DAT_003fe0b0 = (char *)((byte *)DAT_003fe0b0 + 1);
            *DAT_003f9098 = bVar1;
            DAT_003f9098 = pbVar3;
          }
          REG_CANA_MB2_CS = 200;
        }
        else if ((DAT_003fe0ad == 3) || (DAT_003fe0ad == 1)) {
          DAT_003fe0ac = 1;
          log_canid[0] = 512;
          log_canid[1] = 516;
          log_canid[2] = 520;
          log_canid[3] = 524;
          log_canid[4] = 528;
          log_canid[5] = 532;
          log_canid[6] = 536;
          log_canid[7] = 540;
          log_canid[8] = 544;
          log_canid[9] = 548;
          log_canid[10] = 552;
          log_canid[0xb] = 556;
          log_canid[0xc] = 560;
          log_canid[0xd] = 564;
          log_canid[0xe] = 568;
          log_canid[0xf] = 572;
          log_canid[0x10] = 576;
          log_canid[0x11] = 580;
          log_canid[0x12] = 584;
          log_canid[0x13] = 588;
          log_canid[0x14] = 592;
          log_canid[0x15] = 596;
          log_canid[0x16] = 600;
          log_canid[0x17] = 604;
          log_canid[0x18] = 608;
          log_canid[0x19] = 612;
          log_canid[0x1a] = 616;
          log_canid[0x1b] = 620;
          log_canid[0x1c] = 624;
          log_canid[0x1d] = 628;
          log_canid[0x1e] = 632;
          log_canid[0x1f] = 636;
          log_canid[0x20] = 640;
          log_canid[0x21] = 644;
          log_canid[0x22] = 648;
          log_canid[0x23] = 652;
          log_canid[0x24] = 656;
          log_canid[0x25] = 660;
          log_canid[0x26] = 664;
          log_canid[0x27] = 668;
          log_canid[0x28] = 672;
          log_canid[0x29] = 676;
          log_canid[0x2a] = 680;
          log_canid[0x2b] = 684;
          log_canid[0x2c] = 0;
          DAT_003fe0b0 = log_data;
          DAT_003f9098 = &REG_CANA_MB2_DATA0;
          REG_CANA_MB2_CS = 0x88;
          REG_CANA_MB2_ID_HI = 0x4000;
          for (sVar4 = 0; sVar4 < 8; sVar4 = sVar4 + 1) {
            bVar1 = *DAT_003fe0b0;
            pbVar3 = DAT_003f9098 + 1;
            DAT_003fe0b0 = (char *)((byte *)DAT_003fe0b0 + 1);
            *DAT_003f9098 = bVar1;
            DAT_003f9098 = pbVar3;
          }
          REG_CANA_MB2_CS = 200;
        }
      }
      else {
        REG_CANA_MB14_CS = 0x40;
        DAT_003f9090 = REG_TIMER_A;
      }
    }
  }
  uVar2 = REG_IFLAG_A;
  REG_IFLAG_A = uVar2 & 0xbfff;
  return;
}



// CAN-A: Receives dev commands for RAM read/write, used by external tools when ECU unlocked

void can_a_mb15_recv_dev(void)

{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  byte bVar4;
  byte bVar5;
  undefined2 uVar6;
  undefined4 uVar7;
  void **ppvVar8;
  byte *pbVar9;
  ushort uVar10;
  short sVar11;
  
  uVar10 = REG_CANA_MB15_CS;
  while ((uVar10 & 0x10) != 0) {
    uVar10 = REG_CANA_MB15_CS;
  }
  uVar10 = REG_CANA_MB15_CS;
  if ((uVar10 & 0x60) == 0x60) {
    REG_CANA_MB15_CS = 0x40;
    DAT_003f9090 = REG_TIMER_A;
  }
  else {
    uVar10 = REG_CANA_MB15_CS;
    if ((uVar10 & 0x20) != 0) {
      DAT_003f909c = &REG_CANA_MB15_DATA0;
      uVar10 = REG_CANA_MB15_ID_HI;
      if ((int)(uint)uVar10 >> 5 == 0x50) {
        uVar10 = REG_CANA_MB15_CS;
        if ((uVar10 & 0xf) == 4) {
          DAT_003f9080 = (byte *)Ram003071f6;
          REG_CANA_MB15_CS = 0x40;
          DAT_003f9090 = REG_TIMER_A;
          DAT_003f9098 = &REG_CANA_MB0_DATA0;
          REG_CANA_MB0_CS = 0x88;
          REG_CANA_MB0_ID_HI = 0xf400;
          Ram00307106 = *(undefined4 *)DAT_003f9080;
          REG_CANA_MB0_CS = 0xc4;
        }
        else {
          REG_CANA_MB15_CS = 0x40;
          DAT_003f9090 = REG_TIMER_A;
        }
      }
      else {
        uVar10 = REG_CANA_MB15_ID_HI;
        if ((int)(uint)uVar10 >> 5 == 0x51) {
          uVar10 = REG_CANA_MB15_CS;
          if ((uVar10 & 0xf) == 4) {
            DAT_003f9080 = (byte *)Ram003071f6;
            REG_CANA_MB15_CS = 0x40;
            DAT_003f9090 = REG_TIMER_A;
            DAT_003f9098 = &REG_CANA_MB0_DATA0;
            REG_CANA_MB0_CS = 0x88;
            REG_CANA_MB0_ID_HI = 0xf400;
            Ram00307106 = *(undefined2 *)DAT_003f9080;
            REG_CANA_MB0_CS = 0xc2;
          }
          else {
            uVar10 = REG_CANA_MB15_CS;
            if ((uVar10 & 0xf) == 6) {
              bVar1 = REG_CANA_MB15_DATA0;
              bVar2 = REG_CANA_MB15_DATA1;
              bVar3 = REG_CANA_MB15_DATA2;
              bVar4 = REG_CANA_MB15_DATA3;
              DAT_003f909c = &REG_CANA_MB15_DATA5;
              bVar5 = REG_CANA_MB15_DATA4;
              PTR_DAT_003f9094 =
                   (struct_varptr *)CONCAT31(CONCAT21(CONCAT11(bVar2,bVar3),bVar4),bVar5);
              bVar2 = REG_CANA_MB15_DATA5;
              REG_CANA_MB15_CS = 0x40;
              DAT_003f9090 = REG_TIMER_A;
              PTR_DAT_003f9088 = PTR_DAT_003f9094;
              if (bVar2 == 1) {
                REG_CANA_MB1_CS = 0x88;
                REG_CANA_MB1_ID_HI = (ushort)bVar1 << 8 | 0x20;
                DAT_003f9098 = &REG_CANA_MB1_DATA1;
                REG_CANA_MB1_DATA0 = 10;
                REG_CANA_MB1_DATA1 = *(byte *)&PTR_DAT_003f9094->ptr;
                REG_CANA_MB1_CS = 0xc2;
              }
              else if (bVar2 == 2) {
                REG_CANA_MB1_CS = 0x88;
                REG_CANA_MB1_ID_HI = (ushort)bVar1 << 8 | 0x20;
                REG_CANA_MB1_DATA0 = 10;
                PTR_DAT_003f9088 = (struct_varptr *)((int)&PTR_DAT_003f9094->ptr + 1);
                DAT_003f9098 = &REG_CANA_MB1_DATA2;
                REG_CANA_MB1_DATA1 = *(byte *)&PTR_DAT_003f9094->ptr;
                REG_CANA_MB1_DATA2 = *(byte *)&PTR_DAT_003f9088->ptr;
                REG_CANA_MB1_CS = 0xc3;
              }
              else if (bVar2 == 4) {
                REG_CANA_MB1_CS = 0x88;
                REG_CANA_MB1_ID_HI = (ushort)bVar1 << 8 | 0x20;
                REG_CANA_MB1_DATA0 = 10;
                REG_CANA_MB1_DATA1 = *(byte *)&PTR_DAT_003f9094->ptr;
                REG_CANA_MB1_DATA2 = *(byte *)((int)&PTR_DAT_003f9094->ptr + 1);
                PTR_DAT_003f9088 = (struct_varptr *)((int)&PTR_DAT_003f9094->ptr + 3);
                DAT_003f9098 = &REG_CANA_MB1_DATA4;
                REG_CANA_MB1_DATA3 = *(byte *)((int)&PTR_DAT_003f9094->ptr + 2);
                REG_CANA_MB1_DATA4 = *(byte *)&PTR_DAT_003f9088->ptr;
                REG_CANA_MB1_CS = 0xc5;
              }
            }
            else {
              REG_CANA_MB15_CS = 0x40;
              DAT_003f9090 = REG_TIMER_A;
            }
          }
        }
        else {
          uVar10 = REG_CANA_MB15_ID_HI;
          if ((int)(uint)uVar10 >> 5 == 0x52) {
            uVar10 = REG_CANA_MB15_CS;
            if ((uVar10 & 0xf) == 4) {
              DAT_003f9080 = (byte *)Ram003071f6;
              REG_CANA_MB15_CS = 0x40;
              DAT_003f9090 = REG_TIMER_A;
              DAT_003f9098 = &REG_CANA_MB0_DATA0;
              REG_CANA_MB0_CS = 0x88;
              REG_CANA_MB0_ID_HI = 0xf400;
              REG_CANA_MB0_DATA0 = *DAT_003f9080;
              REG_CANA_MB0_CS = 0xc1;
            }
            else {
              uVar10 = REG_CANA_MB15_CS;
              if ((uVar10 & 0xf) == 7) {
                bVar1 = REG_CANA_MB15_DATA0;
                bVar2 = REG_CANA_MB15_DATA1;
                bVar3 = REG_CANA_MB15_DATA2;
                bVar4 = REG_CANA_MB15_DATA3;
                bVar5 = REG_CANA_MB15_DATA4;
                PTR_DAT_003f9094 =
                     (struct_varptr *)CONCAT31(CONCAT21(CONCAT11(bVar2,bVar3),bVar4),bVar5);
                DAT_003f909c = &REG_CANA_MB15_DATA7;
                bVar2 = REG_CANA_MB15_DATA6;
                uVar10 = (ushort)bVar2;
                REG_CANA_MB15_CS = 0x40;
                DAT_003f9090 = REG_TIMER_A;
                PTR_DAT_003f9088 = PTR_DAT_003f9094;
                DAT_003f9098 = &REG_CANA_MB1_DATA0;
                REG_CANA_MB1_CS = 0x88;
                REG_CANA_MB1_ID_HI = (ushort)bVar1 << 8 | 0x40;
                if (8 < bVar2) {
                  uVar10 = 8;
                }
                for (; uVar10 != 0; uVar10 = uVar10 - 1) {
                  ppvVar8 = &PTR_DAT_003f9088->ptr;
                  PTR_DAT_003f9088 = (struct_varptr *)((int)&PTR_DAT_003f9088->ptr + 1);
                  pbVar9 = DAT_003f9098 + 1;
                  *DAT_003f9098 = *(byte *)ppvVar8;
                  DAT_003f9098 = pbVar9;
                }
                REG_CANA_MB1_CS = 200;
              }
              else {
                REG_CANA_MB15_CS = 0x40;
                DAT_003f9090 = REG_TIMER_A;
              }
            }
          }
          else {
            uVar10 = REG_CANA_MB15_ID_HI;
            if ((int)(uint)uVar10 >> 5 == 0x53) {
              uVar10 = REG_CANA_MB15_CS;
              if ((uVar10 & 0xf) == 5) {
                DAT_003f908c = 0;
                DAT_003f909c = &REG_CANA_MB15_DATA4;
                DAT_003f9080 = (byte *)Ram003071f6;
                bVar1 = REG_CANA_MB15_DATA4;
                DAT_003f908e = (ushort)bVar1;
                REG_CANA_MB15_CS = 0x40;
                DAT_003f9090 = REG_TIMER_A;
                DAT_003f9098 = &REG_CANA_MB0_DATA0;
                REG_CANA_MB0_CS = 0x88;
                REG_CANA_MB0_ID_HI = 0xf400;
                uVar10 = DAT_003f908e;
                if (DAT_003f908e < 9) {
                  for (; uVar10 != 0; uVar10 = uVar10 - 1) {
                    bVar1 = *DAT_003f9080;
                    DAT_003f9080 = DAT_003f9080 + 1;
                    pbVar9 = DAT_003f9098 + 1;
                    *DAT_003f9098 = bVar1;
                    DAT_003f9098 = pbVar9;
                  }
                  REG_CANA_MB0_CS = DAT_003f908e + 0xc0;
                  DAT_003f908e = 0;
                }
                else {
                  for (sVar11 = 8; sVar11 != 0; sVar11 = sVar11 + -1) {
                    bVar1 = *DAT_003f9080;
                    DAT_003f9080 = DAT_003f9080 + 1;
                    pbVar9 = DAT_003f9098 + 1;
                    *DAT_003f9098 = bVar1;
                    DAT_003f9098 = pbVar9;
                  }
                  REG_CANA_MB0_CS = 200;
                  DAT_003f908e = DAT_003f908e - 8;
                }
              }
              else {
                uVar10 = REG_CANA_MB15_CS;
                if ((uVar10 & 0xf) == 6) {
                  DAT_003f908c = 0;
                  DAT_003f909c = &REG_CANA_MB15_DATA4;
                  DAT_003f9080 = (byte *)Ram003071f6;
                  DAT_003f908e = Ram003071fa;
                  REG_CANA_MB15_CS = 0x40;
                  DAT_003f9090 = REG_TIMER_A;
                  DAT_003f9098 = &REG_CANA_MB0_DATA0;
                  REG_CANA_MB0_CS = 0x88;
                  REG_CANA_MB0_ID_HI = 0xf400;
                  uVar10 = DAT_003f908e;
                  if (DAT_003f908e < 9) {
                    for (; uVar10 != 0; uVar10 = uVar10 - 1) {
                      bVar1 = *DAT_003f9080;
                      DAT_003f9080 = DAT_003f9080 + 1;
                      pbVar9 = DAT_003f9098 + 1;
                      *DAT_003f9098 = bVar1;
                      DAT_003f9098 = pbVar9;
                    }
                    REG_CANA_MB0_CS = DAT_003f908e + 0xc0;
                    DAT_003f908e = 0;
                  }
                  else {
                    for (sVar11 = 8; sVar11 != 0; sVar11 = sVar11 + -1) {
                      bVar1 = *DAT_003f9080;
                      DAT_003f9080 = DAT_003f9080 + 1;
                      pbVar9 = DAT_003f9098 + 1;
                      *DAT_003f9098 = bVar1;
                      DAT_003f9098 = pbVar9;
                    }
                    REG_CANA_MB0_CS = 200;
                    DAT_003f908e = DAT_003f908e - 8;
                  }
                }
                else {
                  uVar10 = REG_CANA_MB15_CS;
                  if ((uVar10 & 0xf) == 4) {
                    DAT_003f9080 = (byte *)Ram003071f6;
                    REG_CANA_MB15_CS = 0x40;
                    DAT_003f9090 = REG_TIMER_A;
                    DAT_003f9098 = &REG_CANA_MB0_DATA0;
                    REG_CANA_MB0_CS = 0x88;
                    REG_CANA_MB0_ID_HI = 0xf400;
                    Ram00307106 = 0x7601c;
                    REG_CANA_MB0_CS = 0xc4;
                  }
                  else {
                    uVar10 = REG_CANA_MB15_CS;
                    if ((uVar10 & 0xf) == 1) {
                      bVar1 = REG_CANA_MB15_DATA0;
                      REG_CANA_MB15_CS = 0x40;
                      DAT_003f9090 = REG_TIMER_A;
                      REG_CANA_MB1_CS = 0x88;
                      REG_CANA_MB1_ID_HI = (ushort)bVar1 << 8 | 0x60;
                      PTR_DAT_003f9088 = struct_varptr_ARRAY_0007601c;
                      REG_CANA_MB1_DATA0 = 10;
                      REG_CANA_MB1_DATA1 = 0;
                      REG_CANA_MB1_DATA2 = 7;
                      REG_CANA_MB1_DATA3 = 0x60;
                      REG_CANA_MB1_DATA4 = 0x1c;
                      DAT_003f9098 = &REG_CANA_MB1_DATA6;
                      REG_CANA_MB1_DATA5 = 0;
                      REG_CANA_MB1_CS = 0xc6;
                    }
                    else {
                      REG_CANA_MB15_CS = 0x40;
                      DAT_003f9090 = REG_TIMER_A;
                    }
                  }
                }
              }
            }
            else {
              uVar10 = REG_CANA_MB15_ID_HI;
              if ((int)(uint)uVar10 >> 5 == 0x54) {
                uVar10 = REG_CANA_MB15_CS;
                if ((uVar10 & 0xf) == 8) {
                  DAT_003f909c = &REG_CANA_MB15_DATA4;
                  DAT_003f9084 = (byte *)Ram003071f6;
                  REG_CANA_MB15_CS = 0x40;
                  DAT_003f9090 = REG_TIMER_A;
                  DAT_003f9098 = &REG_CANA_MB0_DATA0;
                  uVar7 = Ram003071fa;
                  *(undefined4 *)DAT_003f9084 = uVar7;
                }
                else {
                  REG_CANA_MB15_CS = 0x40;
                  DAT_003f9090 = REG_TIMER_A;
                }
              }
              else {
                uVar10 = REG_CANA_MB15_ID_HI;
                if ((int)(uint)uVar10 >> 5 == 0x55) {
                  uVar10 = REG_CANA_MB15_CS;
                  if ((uVar10 & 0xf) == 6) {
                    DAT_003f909c = &REG_CANA_MB15_DATA4;
                    DAT_003f9084 = (byte *)Ram003071f6;
                    REG_CANA_MB15_CS = 0x40;
                    DAT_003f9090 = REG_TIMER_A;
                    uVar6 = Ram003071fa;
                    *(undefined2 *)DAT_003f9084 = uVar6;
                  }
                  else {
                    REG_CANA_MB15_CS = 0x40;
                    DAT_003f9090 = REG_TIMER_A;
                  }
                }
                else {
                  uVar10 = REG_CANA_MB15_ID_HI;
                  if ((int)(uint)uVar10 >> 5 == 0x56) {
                    uVar10 = REG_CANA_MB15_CS;
                    if ((uVar10 & 0xf) == 5) {
                      DAT_003f909c = &REG_CANA_MB15_DATA4;
                      DAT_003f9084 = (byte *)Ram003071f6;
                      REG_CANA_MB15_CS = 0x40;
                      DAT_003f9090 = REG_TIMER_A;
                      bVar1 = REG_CANA_MB15_DATA4;
                      *DAT_003f9084 = bVar1;
                    }
                    else {
                      REG_CANA_MB15_CS = 0x40;
                      DAT_003f9090 = REG_TIMER_A;
                    }
                  }
                  else {
                    uVar10 = REG_CANA_MB15_ID_HI;
                    if ((int)(uint)uVar10 >> 5 == 0x57) {
                      if (DAT_003f908c == 0) {
                        uVar10 = REG_CANA_MB15_CS;
                        if ((uVar10 & 0xf) == 5) {
                          DAT_003f909c = &REG_CANA_MB15_DATA4;
                          DAT_003f9084 = (byte *)Ram003071f6;
                          bVar1 = REG_CANA_MB15_DATA4;
                          DAT_003f908c = (ushort)bVar1;
                          REG_CANA_MB15_CS = 0x40;
                          DAT_003f9090 = REG_TIMER_A;
                        }
                        else {
                          REG_CANA_MB15_CS = 0x40;
                          DAT_003f9090 = REG_TIMER_A;
                        }
                      }
                      else {
                        uVar10 = REG_CANA_MB15_CS;
                        for (uVar10 = uVar10 & 0xf; uVar10 != 0; uVar10 = uVar10 - 1) {
                          bVar1 = *DAT_003f909c;
                          pbVar9 = DAT_003f9084 + 1;
                          DAT_003f909c = DAT_003f909c + 1;
                          *DAT_003f9084 = bVar1;
                          DAT_003f9084 = pbVar9;
                          DAT_003f908c = DAT_003f908c - 1;
                        }
                        REG_CANA_MB15_CS = 0x40;
                        DAT_003f9090 = REG_TIMER_A;
                      }
                    }
                    else {
                      REG_CANA_MB15_CS = 0x40;
                      DAT_003f9090 = REG_TIMER_A;
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
  uVar10 = REG_IFLAG_A;
  REG_IFLAG_A = uVar10 & 0x7fff;
  return;
}



// CAN-A: Clears wake-up error flags

void can_a_wake_error_clear(void)

{
  ushort uVar1;
  
  uVar1 = REG_ESTAT_A;
  REG_ESTAT_A = uVar1 & 0xfffb;
  return;
}



// CAN-A: Clears receive warning flags

void can_a_rx_warning_clear(void)

{
  ushort uVar1;
  
  uVar1 = REG_ESTAT_A;
  REG_ESTAT_A = uVar1 & 0xfffd;
  return;
}



// CAN-A: Sends engine data to instrument cluster (RPM, speed, temps)

void can_a_send_cluster(undefined2 *param_1)

{
  REG_CANA_MB4_CS = 0x88;
  REG_CANA_MB4_ID_HI = 0x8000;
  Ram00307146 = *param_1;
  Ram00307148 = param_1[1];
  REG_CANA_MB4_DATA4 = *(byte *)(param_1 + 2);
  REG_CANA_MB4_DATA5 = *(byte *)((int)param_1 + 5);
  REG_CANA_MB4_DATA6 = *(byte *)(param_1 + 3);
  REG_CANA_MB4_DATA7 = *(byte *)((int)param_1 + 7);
  REG_CANA_MB4_CS = 200;
  return;
}



// ISR: CAN-A interrupt - handles OBD and cluster message buffers

undefined8 isr_can_a(undefined4 param_1,undefined4 param_2)

{
  ushort uVar1;
  uint uVar2;
  ushort uVar3;
  undefined4 in_MSR;
  undefined4 in_SRR1;
  
  uVar1 = REG_IFLAG_A;
  uVar3 = REG_IMASK_A;
  uVar1 = uVar1 & uVar3;
  if (uVar1 != 0) {
    if (uVar1 < 0x100) {
      if (uVar1 < 0x10) {
        if (uVar1 < 4) {
          if (uVar1 < 2) {
            can_a_mb00_send_dev_read_cont();
          }
          else {
            can_a_mb01_unused();
          }
        }
        else if (uVar1 < 8) {
          can_a_mb02_send_log();
        }
        else {
          can_a_mb03_unused();
        }
      }
      else if (uVar1 < 0x40) {
        if (uVar1 < 0x20) {
          can_a_mb04_unused();
        }
        else {
          can_a_mb05_unused();
        }
      }
      else if (uVar1 < 0x80) {
        can_a_mb06_recv_0x310();
      }
      else {
        can_a_mb07_unused();
      }
    }
    else if (uVar1 < 0x1000) {
      if (uVar1 < 0x400) {
        if (uVar1 < 0x200) {
          can_a_mb08_unused();
        }
        else {
          can_a_mb09_unused();
        }
      }
      else if (uVar1 < 0x800) {
        can_a_mb10_unused();
      }
      else {
        can_a_mb11_unused();
      }
    }
    else if (uVar1 < 0x4000) {
      if (uVar1 < 0x2000) {
        can_a_mb12_unused();
      }
      else {
        can_a_mb13_recv_0x100();
      }
    }
    else if (uVar1 < 0x8000) {
      can_a_mb14_recv_log();
    }
    else {
      can_a_mb15_recv_dev();
    }
  }
  uVar1 = REG_ESTAT_A;
  if ((uVar1 >> 1 & 1) == 1) {
    can_a_rx_warning_clear();
  }
  uVar1 = REG_ESTAT_A;
  if ((uVar1 >> 2 & 1) == 1) {
    can_a_wake_error_clear();
  }
  uVar1 = REG_IFLAG_B;
  uVar3 = REG_IMASK_B;
  uVar1 = uVar1 & uVar3;
  if (uVar1 != 0) {
    if (uVar1 < 0x100) {
      if (uVar1 < 0x10) {
        if (uVar1 < 4) {
          if (uVar1 < 2) {
            can_b_mb00_send_dev_multiframe();
          }
          else {
            can_b_mb01_unused();
          }
        }
        else if (uVar1 < 8) {
          can_b_mb02_unused();
        }
        else {
          can_b_mb03_send_0x101_cont();
        }
      }
      else if (uVar1 < 0x40) {
        if (uVar1 < 0x20) {
          can_b_mb04_unused();
        }
        else {
          can_b_mb05_unused();
        }
      }
      else if (uVar1 < 0x80) {
        can_b_mb06_unused();
      }
      else {
        can_b_mb07_unused();
      }
    }
    else if (uVar1 < 0x1000) {
      if (uVar1 < 0x400) {
        if (uVar1 < 0x200) {
          can_b_mb08_unused();
        }
        else {
          can_b_mb09_unused();
        }
      }
      else if (uVar1 < 0x800) {
        can_b_mb10_unused();
      }
      else {
        can_b_mb11_unused();
      }
    }
    else if (uVar1 < 0x4000) {
      if (uVar1 < 0x2000) {
        can_b_mb12_unused();
      }
      else {
        can_b_mb13_recv();
      }
    }
    else if (uVar1 < 0x8000) {
      can_b_mb14_recv_0x80();
    }
    else {
      can_b_mb15_recv_dev();
    }
  }
  uVar1 = REG_ESTAT_B;
  if ((uVar1 >> 1 & 1) == 1) {
    can_b_rx_warning_clear();
  }
  uVar1 = REG_ESTAT_B;
  if ((uVar1 >> 2 & 1) == 1) {
    can_b_wake_error_clear();
  }
  uVar2 = REG_SISR3;
  REG_SISR3 = uVar2 & 0x7fffffff | 0x80000000;
  returnFromInterrupt(in_MSR,in_SRR1);
  return CONCAT44(param_1,param_2);
}



// ISR: Crankshaft synchronization - establishes engine position reference

void isr_crank_sync(void)

{
  ushort uVar1;
  
  uVar1 = REG_CISR_A;
  REG_CISR_A = uVar1 & 0xfffe;
  uVar1 = REG_TPU3A_CH15_PARAM6;
  if (((((uVar1 & 0x8000) != 0) && (DAT_003fe182 == '\x02')) && (DAT_003fe0cc != 0xff)) &&
     (DAT_003fe189 != -1)) {
    DAT_003fe189 = DAT_003fe189 + '\x01';
  }
  if (DAT_003fe0cc == 0xff) {
    REG_TPU3A_CH0_PARAM1 = 0x150;
    REG_TPU3B_CH0_PARAM1 = 0x150;
    DAT_003fd200 = '\0';
  }
  else {
    if (DAT_003fe188 == DAT_003fd200) {
      if (DAT_003fe182 == '\x02') {
        DAT_003fe0cc = 0;
      }
    }
    else if (DAT_003fe182 == '\x02') {
      DAT_003fe190 = DAT_003fe190 + 0x10000;
      if ((DAT_003fe0cc != 0xff) && (DAT_003fe0cc = DAT_003fe0cc + 1, DAT_003fbf9e <= DAT_003fe0cc))
      {
        DAT_003fe0cc = 0x80;
      }
    }
    else if (DAT_003fd200 != '\0') {
      DAT_003f90b8 = '\x01';
      DAT_003fe190 = DAT_003fe190 + 0x1000;
    }
    uVar1 = REG_TPU3A_CH15_PARAM6;
    if (((uVar1 & 0xff00) == 0) && (DAT_003f90b8 == '\0')) {
      DAT_003fe189 = '\0';
      if (DAT_003fd200 == '\0') {
        if (DAT_003fe188 == '\x02') {
          REG_TPU3A_CH0_PARAM1 = 0x221;
          REG_TPU3B_CH0_PARAM1 = 0x221;
          DAT_003fd200 = '\x01';
        }
      }
      else if (DAT_003fd200 == '\x01') {
        REG_TPU3A_CH0_PARAM1 = 0x243;
        REG_TPU3B_CH0_PARAM1 = 0x243;
        DAT_003fd200 = '\x02';
        if (DAT_003fd228 < 0xffe) {
          DAT_003fd228 = DAT_003fd228 + 1;
        }
      }
      else {
        REG_TPU3A_CH0_PARAM1 = 0x221;
        REG_TPU3B_CH0_PARAM1 = 0x221;
        DAT_003fd200 = '\x01';
      }
    }
    else {
      DAT_003f90b8 = '\0';
      REG_TPU3A_CH0_PARAM1 = 0x121;
      REG_TPU3B_CH0_PARAM1 = 0x121;
      DAT_003fd200 = '\0';
    }
  }
  DAT_003fe188 = 0;
  return;
}



// ISR: Cylinder 1 ignition coil dwell and fire timing

void isr_ignition_coil1(void)

{
  byte bVar1;
  ushort uVar2;
  byte bVar3;
  
  uVar2 = REG_CISR_A;
  REG_CISR_A = uVar2 & 0xfffd;
  uVar2 = REG_CFSR3_A;
  if ((uVar2 >> 4 & 0xf) == 0xe) {
    if ((DAT_003fe184 & 1) != 0) {
      uVar2 = REG_CFSR3_A;
      REG_CFSR3_A = uVar2 & 0xff0f;
      uVar2 = REG_CFSR3_A;
      REG_CFSR3_A = uVar2 & 0xff0f | 0xc0;
      REG_TPU3A_CH1_PARAM0 = 0xb02;
      Ram00304118 = DAT_003f8020;
      uVar2 = REG_HSQR1_A;
      REG_HSQR1_A = uVar2 & 0xfff3 | 4;
      uVar2 = REG_HSRR1_A;
      REG_HSRR1_A = uVar2 & 0xfff3 | 8;
      uVar2 = REG_CPR1_A;
      REG_CPR1_A = uVar2 & 0xfff3 | 0xc;
      do {
        uVar2 = REG_HSRR1_A;
      } while (uVar2 != 0);
      ign_coil_isr_phase[0] = 0;
    }
  }
  else {
    ign_coil_isr_phase[0] = ign_coil_isr_phase[0] + 1;
    if (ign_coil_isr_phase[0] < 2) {
      ign_feedback_coil_id = 1;
      bVar1 = ign_feedback_pending_flags | 1;
      if ((ign_feedback_pending_flags & 2) != 0) {
        ign_feedback_missed_flags = ign_feedback_missed_flags | 2;
      }
      if ((ign_feedback_pending_flags & 4) != 0) {
        ign_feedback_missed_flags = ign_feedback_missed_flags | 4;
      }
      bVar3 = ign_feedback_pending_flags & 8;
      ign_feedback_pending_flags = bVar1;
      if (bVar3 != 0) {
        ign_feedback_missed_flags = ign_feedback_missed_flags | 8;
      }
    }
    else {
      ign_coil_isr_phase[0] = 0;
      uVar2 = REG_HSRR1_A;
      REG_HSRR1_A = uVar2 & 0xfff3 | 0xc;
      do {
        uVar2 = REG_HSRR1_A;
      } while (uVar2 != 0);
      uVar2 = REG_CISR_A;
      REG_CISR_A = uVar2 & 0xfffd;
      if (knock_retard1_timer[0] == 255) {
        knock_retard1_timer[0] = CAL_knock_retard1_time_between_step;
      }
      else if (knock_retard1_timer[0] == 0) {
        if (CAL_knock_retard1_dec < knock_retard1[0]) {
          knock_retard1[0] = knock_retard1[0] - CAL_knock_retard1_dec;
        }
        else {
          knock_retard1[0] = 0;
        }
      }
      Ram00304148 = DAT_003f802c;
      uVar2 = REG_HSRR1_A;
      REG_HSRR1_A = uVar2 & 0xfcff | 0x200;
      do {
        uVar2 = REG_HSRR1_A;
      } while (uVar2 != 0);
    }
  }
  return;
}



// ISR: Cylinder 4 ignition coil dwell and fire timing

void isr_ignition_coil4(void)

{
  byte bVar1;
  ushort uVar2;
  byte bVar3;
  
  uVar2 = REG_CISR_A;
  REG_CISR_A = uVar2 & 0xfffb;
  uVar2 = REG_CFSR3_A;
  if ((uVar2 >> 8 & 0xf) == 0xe) {
    if ((DAT_003fe184 & 2) != 0) {
      uVar2 = REG_CFSR3_A;
      REG_CFSR3_A = uVar2 & 0xf0ff;
      uVar2 = REG_CFSR3_A;
      REG_CFSR3_A = uVar2 & 0xf0ff | 0xc00;
      REG_TPU3A_CH2_PARAM0 = 0xb02;
      Ram00304128 = DAT_003f8024;
      uVar2 = REG_HSQR1_A;
      REG_HSQR1_A = uVar2 & 0xffcf | 0x10;
      uVar2 = REG_HSRR1_A;
      REG_HSRR1_A = uVar2 & 0xffcf | 0x20;
      uVar2 = REG_CPR1_A;
      REG_CPR1_A = uVar2 & 0xffcf | 0x30;
      do {
        uVar2 = REG_HSRR1_A;
      } while (uVar2 != 0);
      ign_coil_isr_phase[1] = 0;
    }
  }
  else {
    ign_coil_isr_phase[1] = ign_coil_isr_phase[1] + 1;
    if (ign_coil_isr_phase[1] < 2) {
      ign_feedback_coil_id = 2;
      bVar1 = ign_feedback_pending_flags | 2;
      if ((ign_feedback_pending_flags & 1) != 0) {
        ign_feedback_missed_flags = ign_feedback_missed_flags | 1;
      }
      if ((ign_feedback_pending_flags & 4) != 0) {
        ign_feedback_missed_flags = ign_feedback_missed_flags | 4;
      }
      bVar3 = ign_feedback_pending_flags & 8;
      ign_feedback_pending_flags = bVar1;
      if (bVar3 != 0) {
        ign_feedback_missed_flags = ign_feedback_missed_flags | 8;
      }
    }
    else {
      ign_coil_isr_phase[1] = 0;
      uVar2 = REG_HSRR1_A;
      REG_HSRR1_A = uVar2 & 0xffcf | 0x30;
      do {
        uVar2 = REG_HSRR1_A;
      } while (uVar2 != 0);
      uVar2 = REG_CISR_A;
      REG_CISR_A = uVar2 & 0xfffb;
      if (knock_retard1_timer[3] == 255) {
        knock_retard1_timer[3] = CAL_knock_retard1_time_between_step;
      }
      else if (knock_retard1_timer[3] == 0) {
        if (CAL_knock_retard1_dec < knock_retard1[3]) {
          knock_retard1[3] = knock_retard1[3] - CAL_knock_retard1_dec;
        }
        else {
          knock_retard1[3] = 0;
        }
      }
      Ram00304138 = DAT_003f8028;
      uVar2 = REG_HSRR1_A;
      REG_HSRR1_A = uVar2 & 0xff3f | 0x80;
      do {
        uVar2 = REG_HSRR1_A;
      } while (uVar2 != 0);
    }
  }
  return;
}



// ISR: Cylinder 2 ignition coil dwell and fire timing

void isr_ignition_coil2(void)

{
  byte bVar1;
  ushort uVar2;
  byte bVar3;
  
  uVar2 = REG_CISR_A;
  REG_CISR_A = uVar2 & 0xfff7;
  uVar2 = REG_CFSR3_A;
  if (uVar2 >> 0xc == 0xe) {
    if ((DAT_003fe184 & 4) != 0) {
      uVar2 = REG_CFSR3_A;
      REG_CFSR3_A = uVar2 & 0xfff;
      uVar2 = REG_CFSR3_A;
      REG_CFSR3_A = uVar2 & 0xfff | 0xc000;
      REG_TPU3A_CH3_PARAM0 = 0xb02;
      Ram00304138 = DAT_003f8028;
      uVar2 = REG_HSQR1_A;
      REG_HSQR1_A = uVar2 & 0xff3f | 0x40;
      uVar2 = REG_HSRR1_A;
      REG_HSRR1_A = uVar2 & 0xff3f | 0x80;
      uVar2 = REG_CPR1_A;
      REG_CPR1_A = uVar2 & 0xff3f | 0xc0;
      do {
        uVar2 = REG_HSRR1_A;
      } while (uVar2 != 0);
      ign_coil_isr_phase[2] = 0;
    }
  }
  else {
    ign_coil_isr_phase[2] = ign_coil_isr_phase[2] + 1;
    if (ign_coil_isr_phase[2] < 2) {
      ign_feedback_coil_id = 3;
      bVar1 = ign_feedback_pending_flags | 4;
      if ((ign_feedback_pending_flags & 1) != 0) {
        ign_feedback_missed_flags = ign_feedback_missed_flags | 1;
      }
      if ((ign_feedback_pending_flags & 2) != 0) {
        ign_feedback_missed_flags = ign_feedback_missed_flags | 2;
      }
      bVar3 = ign_feedback_pending_flags & 8;
      ign_feedback_pending_flags = bVar1;
      if (bVar3 != 0) {
        ign_feedback_missed_flags = ign_feedback_missed_flags | 8;
      }
    }
    else {
      ign_coil_isr_phase[2] = 0;
      uVar2 = REG_HSRR1_A;
      REG_HSRR1_A = uVar2 & 0xff3f | 0xc0;
      do {
        uVar2 = REG_HSRR1_A;
      } while (uVar2 != 0);
      uVar2 = REG_CISR_A;
      REG_CISR_A = uVar2 & 0xfff7;
      if (knock_retard1_timer[1] == 255) {
        knock_retard1_timer[1] = CAL_knock_retard1_time_between_step;
      }
      else if (knock_retard1_timer[1] == 0) {
        if (CAL_knock_retard1_dec < knock_retard1[1]) {
          knock_retard1[1] = knock_retard1[1] - CAL_knock_retard1_dec;
        }
        else {
          knock_retard1[1] = 0;
        }
      }
      Ram00304128 = DAT_003f8024;
      uVar2 = REG_HSRR1_A;
      REG_HSRR1_A = uVar2 & 0xffcf | 0x20;
      do {
        uVar2 = REG_HSRR1_A;
      } while (uVar2 != 0);
    }
  }
  return;
}



// ISR: Cylinder 3 ignition coil dwell and fire timing

void isr_ignition_coil3(void)

{
  byte bVar1;
  ushort uVar2;
  byte bVar3;
  
  uVar2 = REG_CISR_A;
  REG_CISR_A = uVar2 & 0xffef;
  uVar2 = REG_CFSR2_A;
  if ((uVar2 & 0xf) == 0xe) {
    if ((DAT_003fe184 & 8) != 0) {
      uVar2 = REG_CFSR2_A;
      REG_CFSR2_A = uVar2 & 0xfff0;
      uVar2 = REG_CFSR2_A;
      REG_CFSR2_A = uVar2 & 0xfff0 | 0xc;
      uVar2 = REG_HSQR1_A;
      REG_HSQR1_A = uVar2 & 0xfcff | 0x100;
      REG_TPU3A_CH4_PARAM0 = 0xb02;
      Ram00304148 = DAT_003f802c;
      uVar2 = REG_HSRR1_A;
      REG_HSRR1_A = uVar2 & 0xfcff | 0x200;
      uVar2 = REG_CPR1_A;
      REG_CPR1_A = uVar2 & 0xfcff | 0x300;
      do {
        uVar2 = REG_HSRR1_A;
      } while (uVar2 != 0);
      ign_coil_isr_phase[3] = 0;
    }
  }
  else {
    ign_coil_isr_phase[3] = ign_coil_isr_phase[3] + 1;
    if (ign_coil_isr_phase[3] < 2) {
      ign_feedback_coil_id = 4;
      bVar1 = ign_feedback_pending_flags | 8;
      if ((ign_feedback_pending_flags & 1) != 0) {
        ign_feedback_missed_flags = ign_feedback_missed_flags | 1;
      }
      if ((ign_feedback_pending_flags & 2) != 0) {
        ign_feedback_missed_flags = ign_feedback_missed_flags | 2;
      }
      bVar3 = ign_feedback_pending_flags & 4;
      ign_feedback_pending_flags = bVar1;
      if (bVar3 != 0) {
        ign_feedback_missed_flags = ign_feedback_missed_flags | 4;
      }
    }
    else {
      ign_coil_isr_phase[3] = 0;
      uVar2 = REG_HSRR1_A;
      REG_HSRR1_A = uVar2 & 0xfcff | 0x300;
      do {
        uVar2 = REG_HSRR1_A;
      } while (uVar2 != 0);
      uVar2 = REG_CISR_A;
      REG_CISR_A = uVar2 & 0xffef;
      if (knock_retard1_timer[2] == 255) {
        knock_retard1_timer[2] = CAL_knock_retard1_time_between_step;
      }
      else if (knock_retard1_timer[2] == 0) {
        if (CAL_knock_retard1_dec < knock_retard1[2]) {
          knock_retard1[2] = knock_retard1[2] - CAL_knock_retard1_dec;
        }
        else {
          knock_retard1[2] = 0;
        }
      }
      Ram00304118 = DAT_003f8020;
      uVar2 = REG_HSRR1_A;
      REG_HSRR1_A = uVar2 & 0xfff3 | 8;
      do {
        uVar2 = REG_HSRR1_A;
      } while (uVar2 != 0);
    }
  }
  return;
}



// ISR: TPU-A channel 5 interrupt flag clear

void isr_tpu_a_ch5_clear(void)

{
  ushort uVar1;
  
  uVar1 = REG_CISR_A;
  REG_CISR_A = uVar1 & 0xffdf;
  return;
}



// ISR: TPU-A channel 6 interrupt flag clear

void isr_tpu_a_ch6_clear(void)

{
  ushort uVar1;
  
  uVar1 = REG_CISR_A;
  REG_CISR_A = uVar1 & 0xffbf;
  return;
}



// ISR: Knock sensor window timing for signal capture

void isr_knock_window(void)

{
  ushort uVar1;
  
  uVar1 = REG_CISR_A;
  REG_CISR_A = uVar1 & 0xff7f;
  uVar1 = REG_CFSR2_A;
  REG_CFSR2_A = uVar1 & 0xfff | 0xc000;
  uVar1 = REG_CFSR2_A;
  if (uVar1 >> 0xc == 0xe) {
    uVar1 = REG_CFSR2_A;
    REG_CFSR2_A = uVar1 & 0xfff;
    uVar1 = REG_CFSR2_A;
    REG_CFSR2_A = uVar1 & 0xfff | 0xc000;
    uVar1 = REG_HSQR1_A;
    REG_HSQR1_A = uVar1 & 0x3fff | 0x8000;
    REG_TPU3A_CH7_PARAM0 = 0xb02;
    REG_TPU3A_CH7_PARAM4 = 0xff37;
    REG_TPU3A_CH7_PARAM5 = 0x1038;
    uVar1 = REG_HSRR1_A;
    REG_HSRR1_A = uVar1 & 0x3fff | 0x8000;
    uVar1 = REG_CPR1_A;
    REG_CPR1_A = uVar1 & 0x3fff | 0x4000;
    do {
      uVar1 = REG_HSRR1_A;
    } while (uVar1 != 0);
    DAT_003f90a4 = 0;
  }
  else {
    DAT_003f90a4 = DAT_003f90a4 + 1;
    if (1 < DAT_003f90a4) {
      DAT_003f90a4 = 0;
      Ram00304178 = knock_window_params[DAT_003f90ba];
      DAT_003f90ba = DAT_003f90ba + 1 & 3;
      uVar1 = REG_HSRR1_A;
      REG_HSRR1_A = uVar1 & 0x3fff | 0x8000;
      uVar1 = REG_CPR1_A;
      REG_CPR1_A = uVar1 & 0x3fff | 0x4000;
    }
  }
  return;
}



// ISR: Rear-right wheel speed sensor pulse

void isr_wheel_speed_rr(void)

{
  ushort uVar1;
  
  uVar1 = REG_CISR_A;
  REG_CISR_A = uVar1 & 0xfeff;
  uVar1 = REG_TPU3A_CH8_PARAM4;
  if ((uVar1 & 0xff) == 0) {
    wheel_period_rr = REG_TPU3A_CH8_PARAM5;
    REG_TPU3A_CH8_PARAM4 = 0xff00;
  }
  else {
    wheel_period_rr = 65535;
    REG_TPU3A_CH8_PARAM4 = 0xff00;
  }
  return;
}



// ISR: Crankshaft position - calculates engine speed and schedules events

void isr_crank_position(void)

{
  ushort uVar1;
  undefined *puVar2;
  ushort uVar3;
  ushort uVar4;
  
  uVar3 = REG_CISR_A;
  REG_CISR_A = uVar3 & 0xfdff;
  uVar4 = REG_TPU3A_CH15_PARAM6;
  DAT_003f90b4 = REG_TPU3A_CH0_PARAM0;
  uVar3 = REG_TPU3A_CH9_PARAM4;
  if ((uVar3 & 0xff) == 0) {
    uVar3 = REG_TPU3A_CH9_PARAM5;
    puVar2 = (undefined *)(uint)uVar3;
    DAT_003f90ac = puVar2 + (int)DAT_003f90ac;
  }
  else {
    REG_TPU3A_CH9_PARAM4 = 0xff00;
    puVar2 = (undefined *)0xffff;
    engine_speed_period = 65535;
    DAT_003f90ac = (undefined *)0x0;
  }
  DAT_003f90b6 = uVar4;
  if (DAT_003f8b28 != '\0') {
    DAT_003f8b28 = '\0';
    init_cranking_injection();
  }
  fuelpump_timer = CAL_ecu_fuelpump_prime;
  uVar3 = (ushort)puVar2;
  if (DAT_003fe182 == '\0') {
    DAT_003fe190 = 0;
    DAT_003fe0cc = 0;
    DAT_003f90b9 = '\0';
    DAT_003fe18a = 0;
    DAT_003fe184 = 0;
    DAT_003fe18c = 0;
    uVar1 = uVar3;
    if ((puVar2 < &UNK_0000f424) && ((undefined *)((uint)DAT_003f8b2a * 0xffff >> 0xf) < puVar2)) {
      DAT_003fe182 = '\x01';
    }
  }
  else {
    uVar1 = DAT_003f8b2a;
    if (DAT_003fe182 == '\x01') {
      if ((undefined *)((uint)DAT_003f8b2a * 0xffff >> 0xf) < puVar2) {
        DAT_003f90b9 = '\0';
        DAT_003fe18c = DAT_003fe18c + 1;
        DAT_003fe18a = DAT_003fe18a + 1;
        if (DAT_003fe18a == 0x44) {
          DAT_003fe18a = 0;
        }
        DAT_003f8b2c = (ushort)((uint)puVar2 / 3);
        if ((DAT_003fe18a == 0x22) || (DAT_003fe18a == 0)) {
          DAT_003fe18c = 0;
        }
        else {
          DAT_003fe190 = DAT_003fe190 + 1;
          if (2 < DAT_003fe18c) {
            DAT_003fe182 = '\0';
          }
        }
      }
      else {
        DAT_003fe18a = DAT_003fe18a + 1;
        if (DAT_003fe18a == 0x44) {
          DAT_003fe18a = 0;
        }
        DAT_003f8b2c = uVar3;
        if (DAT_003fe18a == 10) {
          if (DAT_003f90b9 != '\0') {
            DAT_003fe18a = 0x2c;
            DAT_003fe190 = DAT_003fe190 + 0x10;
          }
        }
        else if (DAT_003fe18a == 0x2c) {
          if (DAT_003f90b9 == '\0') {
            DAT_003fe190 = DAT_003fe190 + 0x100;
            if ((DAT_003fe0cc != 0xff) && (DAT_003fe0cc = DAT_003fe0cc + 1, 3 < DAT_003fe0cc)) {
              DAT_003fe0cc = 0x80;
            }
          }
          else {
            DAT_003fe0cc = 0;
          }
        }
      }
      DAT_003f8b2a = uVar3;
      if (DAT_003fe182 != '\0') {
        schedule_ignition_coils();
        schedule_injection();
        if ((DAT_003fe184 == 0xff) && ((DAT_003fe0cc == 0 || (DAT_003fe0cc == 0x80)))) {
          if ((DAT_003fe0cc == 0x80) ||
             ((dev_unlocked == false &&
              ((ecu_CRC_computed != CAL_ecu_CRC_stored ||
               (((DAT_003f937d != '4' && (DAT_003f937e != '4')) && (DAT_003f937f != '4')))))))) {
            DAT_003fe0cc = 0xff;
          }
          DAT_003fe182 = '\x02';
        }
      }
      uVar4 = (ushort)DAT_003fe18a;
      uVar1 = DAT_003f8b2a;
    }
  }
  DAT_003f8b2a = uVar1;
  if (((uVar4 == 0) || (uVar4 == 9)) ||
     ((uVar4 == 0x12 ||
      ((((uVar4 == 0x1b || (uVar4 == 0x22)) || (uVar4 == 0x2b)) ||
       ((uVar4 == 0x34 || (uVar4 == 0x3d)))))))) {
    if (uVar4 == 9) {
      knock_cyl_i = 2;
    }
    else if (uVar4 == 0x1b) {
      knock_cyl_i = 3;
    }
    else if (uVar4 == 0x2b) {
      knock_cyl_i = 0;
    }
    else if (uVar4 == 0x3d) {
      knock_cyl_i = 1;
    }
    if (((uVar4 == 9) || (uVar4 == 0x1b)) || ((uVar4 == 0x2b || (uVar4 == 0x3d)))) {
      if (DAT_003f92d0 == '\0') {
        spi_pcs2(knock_cyl_i);
      }
      else {
        DAT_003f80d8 = knock_cyl_i;
      }
    }
    else {
      knock_read_signal(knock_cyl_i - 1 & 3);
    }
  }
  if ((((uVar4 == 5) || (uVar4 == 0xe)) || (uVar4 == 0x17)) ||
     (((uVar4 == 0x20 || (uVar4 == 0x27)) ||
      ((uVar4 == 0x30 || ((uVar4 == 0x39 || (uVar4 == 0x42)))))))) {
    if (DAT_003f90ac < (undefined *)0xffff) {
      if (engine_speed_period == 65535) {
        engine_speed_period = 65534;
      }
      else {
        engine_speed_period = (u16_time_4us)DAT_003f90ac;
      }
    }
    else {
      engine_speed_period = 65535;
    }
    DAT_003f90ac = (undefined *)0x0;
    on_crank_tooth();
  }
  return;
}



// ISR: Camshaft position - determines engine cycle phase for sequential injection

void isr_cam_position(void)

{
  ushort uVar1;
  uint uVar2;
  
  uVar1 = REG_CISR_A;
  REG_CISR_A = uVar1 & 0xfbff;
  if (DAT_003fe188 != -1) {
    DAT_003fe188 = DAT_003fe188 + '\x01';
  }
  if (DAT_003f90b9 != -1) {
    DAT_003f90b9 = DAT_003f90b9 + '\x01';
  }
  DAT_003f90b0 = REG_TPU3A_CH10_PARAM4;
  DAT_003f90b2 = REG_TPU3A_CH0_PARAM5;
  if ((engine_is_running) && (DAT_003fe0cc != -0x80)) {
    uVar2 = (uint)DAT_003f90b0 - (uint)DAT_003f90b4 & 0xffff;
    if (0x7fff < uVar2) {
      DAT_003f90b4 = DAT_003f90b4 - DAT_003f90b2;
      uVar2 = (uint)DAT_003f90b0 - (uint)DAT_003f90b4 & 0xffff;
      DAT_003f90b6 = DAT_003f90b6 - 1;
    }
    if (DAT_003f90b6 < 0x37) {
      if (DAT_003f90b6 < 0x25) {
        if (0x14 < DAT_003f90b6) {
          DAT_003f90b6 = DAT_003f90b6 - 0x15;
        }
      }
      else {
        DAT_003f90b6 = DAT_003f90b6 - 0x25;
      }
    }
    else {
      DAT_003f90b6 = DAT_003f90b6 - 0x37;
    }
    vvt_pos = 0xdc - ((short)((uVar2 * 0x28) / (uint)DAT_003f90b2) + DAT_003f90b6 * 0x28);
    vvt_cam_updated = true;
  }
  else {
    vvt_pos = 0;
  }
  return;
}



// ISR: Front-left wheel speed sensor pulse

void isr_wheel_speed_fl(void)

{
  ushort uVar1;
  
  uVar1 = REG_CISR_A;
  REG_CISR_A = uVar1 & 0xf7ff;
  uVar1 = REG_TPU3A_CH11_PARAM4;
  if ((uVar1 & 0xff) == 0) {
    wheel_period_fl = REG_TPU3A_CH11_PARAM5;
    REG_TPU3A_CH11_PARAM4 = 0xff00;
  }
  else {
    wheel_period_fl = 65535;
    REG_TPU3A_CH11_PARAM4 = 0xff00;
  }
  return;
}



// ISR: Front-right wheel speed sensor pulse

void isr_wheel_speed_fr(void)

{
  ushort uVar1;
  
  uVar1 = REG_CISR_A;
  REG_CISR_A = uVar1 & 0xefff;
  uVar1 = REG_TPU3A_CH12_PARAM4;
  if ((uVar1 & 0xff) == 0) {
    wheel_period_fr = REG_TPU3A_CH12_PARAM5;
    REG_TPU3A_CH12_PARAM4 = 0xff00;
  }
  else {
    wheel_period_fr = 65535;
    REG_TPU3A_CH12_PARAM4 = 0xff00;
  }
  return;
}



// ISR: Rear-left wheel speed sensor pulse

void isr_wheel_speed_rl(void)

{
  ushort uVar1;
  
  uVar1 = REG_CISR_A;
  REG_CISR_A = uVar1 & 0xdfff;
  uVar1 = REG_TPU3A_CH13_PARAM4;
  if ((uVar1 & 0xff) == 0) {
    wheel_period_rl = REG_TPU3A_CH13_PARAM5;
    REG_TPU3A_CH13_PARAM4 = 0xff00;
  }
  else {
    wheel_period_rl = 65535;
    REG_TPU3A_CH13_PARAM4 = 0xff00;
  }
  return;
}



// ISR: Synchronized MAF/MAP sampling at specific crank angles

void isr_maf_map_sample(void)

{
  ushort uVar1;
  
  uVar1 = REG_CISR_A;
  REG_CISR_A = uVar1 & 0xbfff;
  maf_adc_history_i = maf_adc_history_i + 1U & 0x1f;
  uVar1 = REG_QADCA_RJURR11;
  maf_adc_history[maf_adc_history_i] = uVar1;
  map_adc_history_i = map_adc_history_i + 1U & 0x1f;
  uVar1 = REG_QADCA_RJURR10;
  map_adc_history[map_adc_history_i] = uVar1;
  DAT_003f90a5 = DAT_003f90a5 + 1;
  if (1 < DAT_003f90a5) {
    DAT_003f90a5 = 0;
    Ram003041e8 = (&PTR_DAT_0007b070)[(int)maf_adc_history_i / 2];
    uVar1 = REG_HSRR0_A;
    REG_HSRR0_A = uVar1 & 0xcfff | 0x2000;
    do {
      uVar1 = REG_HSRR0_A;
    } while (uVar1 != 0);
  }
  return;
}



// ISR: Misfire detection per cylinder combustion event

void isr_misfire(void)

{
  ushort uVar1;
  ushort uVar2;
  uint uVar3;
  int iVar4;
  byte bVar5;
  uint unaff_r31;
  
  misfire_i = (uint8_t)((int)(uint)engine_speed_3 >> 4);
  uVar1 = REG_CISR_A;
  REG_CISR_A = uVar1 & 0x7fff;
  uVar2 = REG_TPU3A_CH15_PARAM6;
  uVar1 = REG_TPU3A_CH15_PARAM4;
  if ((uVar1 & 0xff) == 0) {
    if ((((uVar2 == 2) || (uVar2 == 0x14)) || (uVar2 == 0x24)) || (uVar2 == 0x36)) {
      misfire_stroke_time_tpu = REG_TPU3A_CH15_PARAM5;
    }
  }
  else {
    uVar1 = REG_TPU3A_CH15_PARAM4;
    REG_TPU3A_CH15_PARAM4 = uVar1 & 0xff00;
    misfire_stroke_time_tpu = 65535;
  }
  if (uVar2 == 5) {
    REG_TPU3A_CH15_PARAM1 = 0xf00;
    unaff_r31 = 0;
  }
  else if (uVar2 == 0x17) {
    REG_TPU3A_CH15_PARAM1 = 0xd00;
    unaff_r31 = 1;
  }
  else if (uVar2 == 0x27) {
    REG_TPU3A_CH15_PARAM1 = 0xf00;
    unaff_r31 = 2;
  }
  else if (uVar2 == 0x39) {
    REG_TPU3A_CH15_PARAM1 = 0xd00;
    unaff_r31 = 3;
  }
  if ((uVar2 & 0xff00) == 0) {
    if (((uVar2 == 5) || (uVar2 == 0x17)) || ((uVar2 == 0x27 || (uVar2 == 0x39)))) {
      misfire_stroke_time_prev[unaff_r31 & 0xff] = misfire_stroke_time[unaff_r31 & 0xff];
      misfire_stroke_time[unaff_r31 & 0xff] = misfire_stroke_time_tpu;
      uVar3 = (uint)misfire_stroke_time[unaff_r31 & 0xff] -
              (uint)misfire_stroke_time_prev[unaff_r31 & 0xff];
      misfire_stroke_time_dt[unaff_r31 & 0xff] =
           (short)((int)uVar3 >> 2) + (ushort)((int)uVar3 < 0 && (uVar3 & 3) != 0);
      misfire_stroke_time_smooth[unaff_r31 & 0xff] =
           misfire_stroke_time[unaff_r31 & 0xff] - misfire_stroke_time_dt[unaff_r31 & 0xff];
      misfire_stroke_cyl_diff[unaff_r31 & 0xff] =
           misfire_stroke_time_smooth[unaff_r31 & 0xff] -
           misfire_stroke_time[(unaff_r31 & 0xff) - 1 & 3];
      misfire_stroke_diff_1[unaff_r31 & 0xff] =
           misfire_stroke_cyl_diff[unaff_r31 & 0xff] -
           (LEA_misfire_stroke_time[unaff_r31 & 0xff][misfire_i] >> 4);
      misfire_stroke_diff_2[unaff_r31 & 0xff] =
           misfire_stroke_diff_1[unaff_r31 & 0xff] -
           misfire_stroke_diff_1[(unaff_r31 & 0xff) - 1 & 3];
      if (((dfso_flags & 1) != 0) && ((misfire_flags & 0x10) == 0)) {
        if (misfire_stroke_diff_1[unaff_r31 & 0xff] < 1) {
          if (misfire_stroke_diff_1[unaff_r31 & 0xff] < 0) {
            iVar4 = (uint)misfire_i * 2 + (unaff_r31 & 0xff) * 0x20;
            *(short *)(LEA_base + iVar4 + 0x154) = *(short *)(LEA_base + iVar4 + 0x154) + -1;
          }
        }
        else {
          iVar4 = (uint)misfire_i * 2 + (unaff_r31 & 0xff) * 0x20;
          *(short *)(LEA_base + iVar4 + 0x154) = *(short *)(LEA_base + iVar4 + 0x154) + 1;
        }
      }
      if ((misfire_flags & 2) != 0) {
        if ((short)(ushort)misfire_cat_threshold < misfire_stroke_diff_2[unaff_r31 & 0xff]) {
          if (misfire_cat_timer[unaff_r31 & 0xff] != 0) {
            misfire_cat_timer[unaff_r31 & 0xff] = misfire_cat_timer[unaff_r31 & 0xff] - 1;
          }
        }
        else {
          misfire_cat_timer[unaff_r31 & 0xff] = misfire_cat_timer_max;
        }
        if ((misfire_flags & 8) == 0) {
          if ((short)misfire_threshold < misfire_stroke_diff_1[unaff_r31 & 0xff]) {
            if ((((misfire_count[0] == 0) && (misfire_count[1] == 0)) && (misfire_count[2] == 0)) &&
               (misfire_count[3] == 0)) {
              misfire_window_count = 0;
              misfire_cat_window_count = 0;
            }
            misfire_count[unaff_r31 & 0xff] = misfire_count[unaff_r31 & 0xff] + 1;
            misfire_cat_count[unaff_r31 & 0xff] = misfire_cat_count[unaff_r31 & 0xff] + 1;
            misfire_event_flags[unaff_r31 & 0xff] = 1;
          }
          else {
            misfire_event_flags[unaff_r31 & 0xff] = 0;
          }
          if (misfire_cat_window_count < 400) {
            misfire_cat_window_count = misfire_cat_window_count + 1;
          }
          else {
            misfire_cat_window_count = 0;
            iVar4 = 0;
            for (bVar5 = 0; bVar5 < 4; bVar5 = bVar5 + 1) {
              misfire_cat_count_prev[bVar5] = misfire_cat_count[bVar5];
              iVar4 = iVar4 + (uint)misfire_cat_count[bVar5];
              misfire_cat_count[bVar5] = 0;
            }
            misfire_cat_total_count = (uint16_t)((uint)(iVar4 * 10) >> 2);
            misfire_flags = misfire_flags | 0x4000;
          }
          if (misfire_window_count < 2000) {
            misfire_window_count = misfire_window_count + 1;
          }
          else {
            misfire_window_count = 0;
            uVar3 = 0;
            for (bVar5 = 0; bVar5 < 4; bVar5 = bVar5 + 1) {
              misfire_count_prev[bVar5] = misfire_count[bVar5];
              uVar3 = uVar3 + misfire_count[bVar5];
              misfire_count[bVar5] = 0;
            }
            misfire_total_count = (uint16_t)(uVar3 >> 1);
            misfire_flags = misfire_flags | 0x8000;
          }
        }
      }
    }
    else {
      REG_TPU3A_CH15_PARAM1 = 0x300;
    }
  }
  return;
}



// Schedules next ignition events based on crank angle

void schedule_ignition_coils(void)

{
  ushort uVar1;
  int iVar2;
  
  iVar2 = (int)ign_adv_final + ((uint)ign_dwell_time * 0x28) / (uint)DAT_003f8b2c + 0x27;
  iVar2 = iVar2 / 0x28 + (iVar2 >> 0x1f);
  DAT_003fe18d = (char)iVar2 - (char)(iVar2 >> 0x1f);
  if ((((uint)DAT_003fe18a == 0x37 - DAT_003fe18d) || ((uint)DAT_003fe18a == 0x15 - DAT_003fe18d))
     && ((DAT_003fe184 & 1) == 0)) {
    iVar2 = (uint)DAT_003f8b2c * (((uint)DAT_003fe18d * 0x28 - (int)ign_adv_final) + 0x14);
    iVar2 = iVar2 / 0x28 + (iVar2 >> 0x1f);
    DAT_003fe18e = (short)iVar2 - (short)(iVar2 >> 0x1f);
    uVar1 = REG_CFSR3_A;
    REG_CFSR3_A = uVar1 & 0xff0f;
    uVar1 = REG_CFSR3_A;
    REG_CFSR3_A = uVar1 & 0xff0f | 0xe0;
    uVar1 = REG_HSQR1_A;
    REG_HSQR1_A = uVar1 & 0xfff3;
    REG_TPU3A_CH1_PARAM0 = 0x89;
    REG_TPU3A_CH1_PARAM1 = DAT_003fe18e;
    REG_TPU3A_CH1_PARAM2 = 0xec;
    REG_TPU3A_CH1_PARAM3 = 0;
    uVar1 = REG_CPR1_A;
    REG_CPR1_A = uVar1 & 0xfff3 | 0xc;
    uVar1 = REG_HSRR1_A;
    REG_HSRR1_A = uVar1 & 0xfff3 | 4;
    do {
      uVar1 = REG_HSRR1_A;
    } while (uVar1 != 0);
    uVar1 = REG_CFSR2_A;
    REG_CFSR2_A = uVar1 & 0xfff0;
    uVar1 = REG_CPR1_A;
    REG_CPR1_A = uVar1 & 0xfcff;
    uVar1 = REG_CFSR2_A;
    REG_CFSR2_A = uVar1 & 0xfff0 | 0xe;
    REG_TPU3A_CH4_PARAM0 = 0x89;
    REG_TPU3A_CH4_PARAM1 = DAT_003fe18e;
    REG_TPU3A_CH4_PARAM2 = 0xec;
    REG_TPU3A_CH4_PARAM3 = 0;
    uVar1 = REG_HSQR1_A;
    REG_HSQR1_A = uVar1 & 0xfcff;
    uVar1 = REG_CPR1_A;
    REG_CPR1_A = uVar1 & 0xfcff | 0x300;
    uVar1 = REG_HSRR1_A;
    REG_HSRR1_A = uVar1 & 0xfcff | 0x100;
    do {
      uVar1 = REG_HSRR1_A;
    } while (uVar1 != 0);
    if (engine_is_running) {
      DAT_003fe184 = DAT_003fe184 | 9;
    }
  }
  else {
    if (3 < DAT_003fe18d) {
      DAT_003fe18d = 3;
    }
    if ((((uint)DAT_003fe18a == 3 - DAT_003fe18d) || ((uint)DAT_003fe18a == 0x25 - DAT_003fe18d)) &&
       ((DAT_003fe184 & 4) == 0)) {
      iVar2 = (uint)DAT_003f8b2c * (((uint)DAT_003fe18d * 0x28 - (int)ign_adv_final) + 0x14);
      iVar2 = iVar2 / 0x28 + (iVar2 >> 0x1f);
      DAT_003fe18e = (short)iVar2 - (short)(iVar2 >> 0x1f);
      uVar1 = REG_CFSR3_A;
      REG_CFSR3_A = uVar1 & 0xf0ff;
      uVar1 = REG_CFSR3_A;
      REG_CFSR3_A = uVar1 & 0xf0ff | 0xe00;
      REG_TPU3A_CH2_PARAM0 = 0x89;
      REG_TPU3A_CH2_PARAM1 = DAT_003fe18e;
      REG_TPU3A_CH2_PARAM2 = 0xec;
      REG_TPU3A_CH2_PARAM3 = 0;
      uVar1 = REG_HSQR1_A;
      REG_HSQR1_A = uVar1 & 0xffcf;
      uVar1 = REG_HSRR1_A;
      REG_HSRR1_A = uVar1 & 0xffcf | 0x10;
      uVar1 = REG_CPR1_A;
      REG_CPR1_A = uVar1 & 0xffcf | 0x30;
      do {
        uVar1 = REG_HSRR1_A;
      } while (uVar1 != 0);
      uVar1 = REG_CFSR3_A;
      REG_CFSR3_A = uVar1 & 0xfff;
      uVar1 = REG_CFSR3_A;
      REG_CFSR3_A = uVar1 & 0xfff | 0xe000;
      REG_TPU3A_CH3_PARAM0 = 0x89;
      REG_TPU3A_CH3_PARAM1 = DAT_003fe18e;
      REG_TPU3A_CH3_PARAM2 = 0xec;
      REG_TPU3A_CH3_PARAM3 = 0;
      uVar1 = REG_HSQR1_A;
      REG_HSQR1_A = uVar1 & 0xff3f;
      uVar1 = REG_HSRR1_A;
      REG_HSRR1_A = uVar1 & 0xff3f | 0x40;
      uVar1 = REG_CPR1_A;
      REG_CPR1_A = uVar1 & 0xff3f | 0xc0;
      do {
        uVar1 = REG_HSRR1_A;
      } while (uVar1 != 0);
      if (engine_is_running) {
        DAT_003fe184 = DAT_003fe184 | 6;
      }
    }
  }
  return;
}



// ISR: TPU-A interrupt dispatcher - routes to channel-specific handlers

undefined8 isr_tpu_a(undefined4 param_1,undefined4 param_2)

{
  ushort uVar1;
  uint uVar2;
  ushort uVar3;
  undefined4 in_MSR;
  undefined4 in_SRR1;
  
  uVar1 = REG_CISR_A;
  uVar3 = REG_CIER_A;
  uVar1 = uVar1 & uVar3;
  while( true ) {
    if (uVar1 == 0) break;
    if ((uVar1 & 1) == 0) {
      if ((uVar1 & 2) == 0) {
        if ((uVar1 & 4) == 0) {
          if ((uVar1 & 8) == 0) {
            if ((uVar1 & 0x10) == 0) {
              if ((uVar1 & 0x20) == 0) {
                if ((uVar1 & 0x40) == 0) {
                  if ((uVar1 & 0x80) == 0) {
                    if ((uVar1 & 0x100) == 0) {
                      if ((uVar1 & 0x200) == 0) {
                        if ((uVar1 & 0x400) == 0) {
                          if ((uVar1 & 0x800) == 0) {
                            if ((uVar1 & 0x1000) == 0) {
                              if ((uVar1 & 0x2000) == 0) {
                                if ((uVar1 & 0x4000) == 0) {
                                  if ((uVar1 & 0x8000) != 0) {
                                    isr_misfire();
                                  }
                                }
                                else {
                                  isr_maf_map_sample();
                                }
                              }
                              else {
                                isr_wheel_speed_rl();
                              }
                            }
                            else {
                              isr_wheel_speed_fr();
                            }
                          }
                          else {
                            isr_wheel_speed_fl();
                          }
                        }
                        else {
                          isr_cam_position();
                        }
                      }
                      else {
                        isr_crank_position();
                      }
                    }
                    else {
                      isr_wheel_speed_rr();
                    }
                  }
                  else {
                    isr_knock_window();
                  }
                }
                else {
                  isr_tpu_a_ch6_clear();
                }
              }
              else {
                isr_tpu_a_ch5_clear();
              }
            }
            else {
              isr_ignition_coil3();
            }
          }
          else {
            isr_ignition_coil2();
          }
        }
        else {
          isr_ignition_coil4();
        }
      }
      else {
        isr_ignition_coil1();
      }
    }
    else {
      isr_crank_sync();
    }
    uVar1 = REG_CISR_A;
    uVar3 = REG_CIER_A;
    uVar1 = uVar1 & uVar3;
  }
  uVar2 = REG_SISR2;
  REG_SISR2 = uVar2 & 0xffbfffff | 0x400000;
  returnFromInterrupt(in_MSR,in_SRR1);
  return CONCAT44(param_1,param_2);
}



// Walks CRT cleanup linked list of destructor callbacks

void cleanup_callbacks(void)

{
  undefined4 *puVar1;
  int unaff_r13;
  
  while (puVar1 = *(undefined4 **)(unaff_r13 + -0x7ffe), puVar1 != (undefined4 *)0x0) {
    *(undefined4 *)(unaff_r13 + -0x7ffe) = *puVar1;
    (*(code *)puVar1[1])(puVar1[2],0xffffffff);
  }
  return;
}



// WARNING: This is an inlined function
// Saves registers r20-r31 to stack

void push_20to31(void)

{
  int in_r11;
  undefined4 unaff_r20;
  undefined4 unaff_r21;
  undefined4 unaff_r22;
  undefined4 unaff_r23;
  undefined4 unaff_r24;
  undefined4 unaff_r25;
  undefined4 unaff_r26;
  undefined4 unaff_r27;
  undefined4 unaff_r28;
  undefined4 unaff_r29;
  undefined4 unaff_r30;
  undefined4 unaff_r31;
  
  *(undefined4 *)(in_r11 + -0x30) = unaff_r20;
  *(undefined4 *)(in_r11 + -0x2c) = unaff_r21;
  *(undefined4 *)(in_r11 + -0x28) = unaff_r22;
  *(undefined4 *)(in_r11 + -0x24) = unaff_r23;
  *(undefined4 *)(in_r11 + -0x20) = unaff_r24;
  *(undefined4 *)(in_r11 + -0x1c) = unaff_r25;
  *(undefined4 *)(in_r11 + -0x18) = unaff_r26;
  *(undefined4 *)(in_r11 + -0x14) = unaff_r27;
  *(undefined4 *)(in_r11 + -0x10) = unaff_r28;
  *(undefined4 *)(in_r11 + -0xc) = unaff_r29;
  *(undefined4 *)(in_r11 + -8) = unaff_r30;
  *(undefined4 *)(in_r11 + -4) = unaff_r31;
  return;
}



// WARNING: This is an inlined function
// Saves registers r22-r31 to stack

void push_22to31(void)

{
  int in_r11;
  undefined4 unaff_r22;
  undefined4 unaff_r23;
  undefined4 unaff_r24;
  undefined4 unaff_r25;
  undefined4 unaff_r26;
  undefined4 unaff_r27;
  undefined4 unaff_r28;
  undefined4 unaff_r29;
  undefined4 unaff_r30;
  undefined4 unaff_r31;
  
  *(undefined4 *)(in_r11 + -0x28) = unaff_r22;
  *(undefined4 *)(in_r11 + -0x24) = unaff_r23;
  *(undefined4 *)(in_r11 + -0x20) = unaff_r24;
  *(undefined4 *)(in_r11 + -0x1c) = unaff_r25;
  *(undefined4 *)(in_r11 + -0x18) = unaff_r26;
  *(undefined4 *)(in_r11 + -0x14) = unaff_r27;
  *(undefined4 *)(in_r11 + -0x10) = unaff_r28;
  *(undefined4 *)(in_r11 + -0xc) = unaff_r29;
  *(undefined4 *)(in_r11 + -8) = unaff_r30;
  *(undefined4 *)(in_r11 + -4) = unaff_r31;
  return;
}



// WARNING: This is an inlined function
// Saves registers r23-r31 to stack

void push_23to31(void)

{
  int in_r11;
  undefined4 unaff_r23;
  undefined4 unaff_r24;
  undefined4 unaff_r25;
  undefined4 unaff_r26;
  undefined4 unaff_r27;
  undefined4 unaff_r28;
  undefined4 unaff_r29;
  undefined4 unaff_r30;
  undefined4 unaff_r31;
  
  *(undefined4 *)(in_r11 + -0x24) = unaff_r23;
  *(undefined4 *)(in_r11 + -0x20) = unaff_r24;
  *(undefined4 *)(in_r11 + -0x1c) = unaff_r25;
  *(undefined4 *)(in_r11 + -0x18) = unaff_r26;
  *(undefined4 *)(in_r11 + -0x14) = unaff_r27;
  *(undefined4 *)(in_r11 + -0x10) = unaff_r28;
  *(undefined4 *)(in_r11 + -0xc) = unaff_r29;
  *(undefined4 *)(in_r11 + -8) = unaff_r30;
  *(undefined4 *)(in_r11 + -4) = unaff_r31;
  return;
}



// WARNING: This is an inlined function
// Saves registers r24-r31 to stack

void push_24to31(void)

{
  int in_r11;
  undefined4 unaff_r24;
  undefined4 unaff_r25;
  undefined4 unaff_r26;
  undefined4 unaff_r27;
  undefined4 unaff_r28;
  undefined4 unaff_r29;
  undefined4 unaff_r30;
  undefined4 unaff_r31;
  
  *(undefined4 *)(in_r11 + -0x20) = unaff_r24;
  *(undefined4 *)(in_r11 + -0x1c) = unaff_r25;
  *(undefined4 *)(in_r11 + -0x18) = unaff_r26;
  *(undefined4 *)(in_r11 + -0x14) = unaff_r27;
  *(undefined4 *)(in_r11 + -0x10) = unaff_r28;
  *(undefined4 *)(in_r11 + -0xc) = unaff_r29;
  *(undefined4 *)(in_r11 + -8) = unaff_r30;
  *(undefined4 *)(in_r11 + -4) = unaff_r31;
  return;
}



// WARNING: This is an inlined function
// Saves registers r25-r31 to stack

void push_25to31(void)

{
  int in_r11;
  undefined4 unaff_r25;
  undefined4 unaff_r26;
  undefined4 unaff_r27;
  undefined4 unaff_r28;
  undefined4 unaff_r29;
  undefined4 unaff_r30;
  undefined4 unaff_r31;
  
  *(undefined4 *)(in_r11 + -0x1c) = unaff_r25;
  *(undefined4 *)(in_r11 + -0x18) = unaff_r26;
  *(undefined4 *)(in_r11 + -0x14) = unaff_r27;
  *(undefined4 *)(in_r11 + -0x10) = unaff_r28;
  *(undefined4 *)(in_r11 + -0xc) = unaff_r29;
  *(undefined4 *)(in_r11 + -8) = unaff_r30;
  *(undefined4 *)(in_r11 + -4) = unaff_r31;
  return;
}



// WARNING: This is an inlined function
// Saves registers r26-r31 to stack

void push_26to31(void)

{
  int in_r11;
  undefined4 unaff_r26;
  undefined4 unaff_r27;
  undefined4 unaff_r28;
  undefined4 unaff_r29;
  undefined4 unaff_r30;
  undefined4 unaff_r31;
  
  *(undefined4 *)(in_r11 + -0x18) = unaff_r26;
  *(undefined4 *)(in_r11 + -0x14) = unaff_r27;
  *(undefined4 *)(in_r11 + -0x10) = unaff_r28;
  *(undefined4 *)(in_r11 + -0xc) = unaff_r29;
  *(undefined4 *)(in_r11 + -8) = unaff_r30;
  *(undefined4 *)(in_r11 + -4) = unaff_r31;
  return;
}



// WARNING: This is an inlined function
// Saves registers r27-r31 to stack

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
// Restores registers r20-r31 from stack

void pop_20to31(void)

{
  return;
}



// WARNING: This is an inlined function
// Restores registers r22-r31 from stack

void pop_22to31(void)

{
  return;
}



// WARNING: This is an inlined function
// Restores registers r23-r31 from stack

void pop_23to31(void)

{
  return;
}



// WARNING: This is an inlined function
// Restores registers r24-r31 from stack

void pop_24to31(void)

{
  return;
}



// WARNING: This is an inlined function
// Restores registers r25-r31 from stack

void pop_25to31(void)

{
  return;
}



// WARNING: This is an inlined function
// Restores registers r26-r31 from stack

void pop_26to31(void)

{
  return;
}



// WARNING: This is an inlined function
// Restores registers r27-r31 from stack

void pop_27to31(void)

{
  return;
}



// CRT exit() implementation: runs atexit callbacks, cleanup list, then calls atexit_handlers

void exit(int __status)

{
  undefined **ppuVar1;
  int iVar2;
  int unaff_r13;
  
  if (*(int *)(unaff_r13 + -0x7ff6) == 0) {
    while (0 < *(int *)(unaff_r13 + -0x7fe6)) {
      iVar2 = *(int *)(unaff_r13 + -0x7fe6) + -1;
      *(int *)(unaff_r13 + -0x7fe6) = iVar2;
      (**(code **)(&DAT_003f90c0 + iVar2 * 4))();
    }
    cleanup_callbacks();
    for (ppuVar1 = &PTR_cleanup_callbacks_0007b0b0; (code *)*ppuVar1 != (code *)0x0;
        ppuVar1 = ppuVar1 + 1) {
      (*(code *)*ppuVar1)();
    }
    if (*(code **)(unaff_r13 + -0x7ff2) != (code *)0x0) {
      (**(code **)(unaff_r13 + -0x7ff2))();
      *(undefined4 *)(unaff_r13 + -0x7ff2) = 0;
    }
  }
  atexit_handlers(__status);
  return;
}



// Runs registered atexit() functions, then dead_end()

void atexit_handlers(void)

{
  int iVar1;
  int unaff_r13;
  
  while (0 < *(int *)(unaff_r13 + -0x7fe2)) {
    iVar1 = *(int *)(unaff_r13 + -0x7fe2) + -1;
    *(int *)(unaff_r13 + -0x7fe2) = iVar1;
    (**(code **)(&DAT_003f91c0 + iVar1 * 4))();
  }
  if (*(code **)(unaff_r13 + -0x7fee) != (code *)0x0) {
    (**(code **)(unaff_r13 + -0x7fee))();
    *(undefined4 *)(unaff_r13 + -0x7fee) = 0;
  }
  dead_end();
  return;
}



// Returns absolute value of integer

uint abs(int v)

{
  return (v >> 0x1f ^ v) - (v >> 0x1f);
}



// Compares two memory blocks, returns -1/0/1 at first mismatch

int memcmp(char *a,char *b,uint size)

{
  int iVar1;
  byte *pbVar2;
  byte *pbVar3;
  
  pbVar2 = (byte *)(a + -1);
  pbVar3 = (byte *)(b + -1);
  iVar1 = size + 1;
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


