#define 3 0x3
#define 16 0x10
#define 1 0x1
#define 0 0x0
#define 2 0x2
#define 4 0x4
#define 5 0x5
#define 6 0x6
#define 0x14 0x14
#define 8 0x8
#define 20 0x14
#define 32 0x20
#define 10 0xa
#define 0x16 0x16
#define 0x9 0x9
#define 720 0x2d0
#define 2560 0xa00
#define 1013 0x3f5
#define 298 0x12a
#define 233 0xe9
#define 1200 0x4b0
#define 31 0x1f
#define '%' 0x25
#define ' ' 0x20
#define 'S' 0x53
#define 'l' 0x6c
#define 'i' 0x69
#define 'p' 0x70
#define 'L' 0x4c
#define 'T' 0x54
#define 'C' 0x43
#define 'O' 0x4f
#define 'F' 0x46
#define 'N' 0x4e
#define 'a' 0x61
#define 'u' 0x75
#define 'n' 0x6e
#define 'c' 0x63
#define 'h' 0x68
#define 27300 0x6aa4
#define 37778 0x9392
#define 153 0x99
#define 10130000 0x9a9250
#define 1880424 0x1cb168
#define 290044 0x46cfc
#define 225 0xe1
#define 750 0x2ee
#define -40 0xffffffd8
#define 25 0x19
#define 127 0x7f
#define 160 0xa0
#define 180 0xb4
#define 120 0x78
#define 30 0x1e
#define 60 0x3c
#define 90 0x5a
#define 150 0x96
#define 210 0xd2
#define 240 0xf0
#define 500 0x1f4
#define 1500 0x5dc
#define 2500 0x9c4
#define 3500 0xdac
#define 4500 0x1194
#define 5500 0x157c
#define 6500 0x1964
#define 7500 0x1d4c
#define 0x258 0x258
#define 0xC8 0xc8
#define 0x7F 0x7f
#define 0x11 0x11
#define 50 0x32
#define 64 0x40
#define 26 0x1a

typedef unsigned char   undefined;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
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

typedef uint8_t u8_time_us;

typedef uint8_t u8_pressure_40mbar;

typedef int16_t i16_flow_100/1024mg/s;

typedef uint8_t u8_factor_1/256-1/2;

typedef uint8_t u8_obd_config;

typedef uint8_t u8_time_1600ms;

typedef uint8_t u8_time_25ms;

typedef uint16_t u16_factor_1/2000-2048/125;

typedef uint16_t u16_flow_mg/s;

typedef uint8_t u8_factor_1/156-14/156;

typedef uint8_t u8_speed_kph;

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

typedef struct struct_data2cluster struct_data2cluster, *Pstruct_data2cluster;

struct struct_data2cluster {
    u8_speed_kph speed_display; // Speed for cluster display (augmented for legal compliance)
    u8_speed_kph speed_odo; // Actual speed for odometer counting
    u16_rspeed_rpm rpm; // Engine RPM
    u8_factor_1/255 fuel_level; // Fuel level
    u8_temp_5/8-40c temp_coolant; // Coolant temperature
    uint8_t lights_flags[2]; // Lights flags
};

typedef uint16_t u16_factor_1/1024;

typedef int16_t i16_factor_1/2000;

typedef uint8_t u8_lambda_1/100;

typedef uint8_t u8_temp_1-40c;

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

typedef uint16_t u16_factor_1/10000;

typedef uint8_t u8_time_-10us;

typedef uint8_t u8_time_50ms;

typedef uint32_t u32_time_us;

typedef uint8_t u8_factor_10/1632;

typedef uint16_t u16_time_s;

typedef uint8_t u8_factor_1/2560;

typedef uint16_t u16_time_4us;

typedef uint16_t u16_ratio_1/10mbar/5v;

typedef int32_t i32_angle_1/4deg;

typedef uint32_t u32_time_5ms;

typedef uint8_t u8_time_10us;

typedef uint16_t u16_afr_1/100;

typedef ulonglong uint64_t;



struct_segment_bss[3] segment_bss;
struct_segment_data[7] segment_data;
uint REG_PDMCR;
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
undefined4 DAT_003f9668;
ushort REG_TBSCR;
ushort REG_RSR;
undefined1 DAT_003f96bd;
undefined1 DAT_003f96bf;
undefined1 DAT_003f96c0;
undefined1 DAT_003f8ff9;
undefined1 DAT_003f8ff8;
uint REG_SIMASK2;
ushort DAT_003fdc90;
u8_factor_1/256-1/2 dev_inj_efficiency_adj;
uint REG_SIMASK3;
u8_angle_1/4-32deg dev_ign_adv_adj;
byte DAT_003fe18e;
u8_angle_720/256deg dev_inj_angle;
byte DAT_003fe18f;
byte DAT_003f966c;
undefined1 DAT_003f96b8;
u8_angle_1/4deg dev_vvt_angle;
ushort REG_MPWMSM16_SCR;
char DAT_003f8270;
int8_t dev_afr_adj;
undefined1 L9822E_outputs;
ushort REG_MPIOSMDR;
uint REG_SIMASK;
uint16_t shutdown_flags;
ushort REG_DPTMCR;
ushort REG_RAMBAR;
undefined REG_DPTRAM;
char[2048] tpu_microcode;
ushort DAT_003f97c6;
ushort REG_TPU3A_CH10_PARAM0;
ushort REG_TPU3A_CH10_PARAM1;
ushort REG_TPU3A_CH10_PARAM2;
ushort REG_TPU3A_CH11_PARAM0;
ushort REG_TPU3A_CH11_PARAM1;
ushort REG_TPU3A_CH11_PARAM4;
ushort REG_TPU3A_CH12_PARAM0;
ushort REG_TPU3A_CH12_PARAM1;
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
char DAT_003f97ba;
byte DAT_003f9704;
char DAT_003f97c1;
char DAT_003f97c0;
char DAT_003fd7cc;
int DAT_003f97c8;
byte DAT_003fc54a;
char DAT_003f9018;
short DAT_003fd7f4;
ushort REG_TPU3B_CH0_PARAM1;
ushort REG_TPU3A_CH15_PARAM6;
ushort DAT_003f97bc;
undefined4 DAT_003f81b0;
undefined4 DAT_003f81bc;
u8_time_5ms[4] knock_retard1_timer;
u8_time_5ms CAL_knock_retard1_time_between_step;
u8_angle_1/4deg CAL_knock_retard1_dec;
uint8_t[4] ign_coil_isr_phase;
uint8_t ign_feedback_coil_id;
uint8_t ign_feedback_pending_flags;
uint16_t ign_feedback_missed_flags;
u8_angle_1/4deg[4] knock_retard1;
ushort REG_TPU3A_CH1_PARAM4;
undefined4 DAT_003f81b4;
undefined4 DAT_003f81b8;
byte DAT_003f9004;
byte DAT_003f901a;
uint32_t[4] knock_window_params;
u16_time_us wheel_period_rr;
ushort REG_TPU3A_CH8_PARAM5;
ushort DAT_003f9016;
ushort DAT_003f9014;
undefined *DAT_003f900c;
char DAT_003f8010;
char DAT_003f9019;
byte DAT_003f97c2;
short DAT_003f97bc;
byte DAT_003f97c4;
ushort DAT_003f8012;
ushort DAT_003f8014;
char DAT_003f96b8;
uint8_t DAT_003f8270;
undefined UNK_0000f424;
uint8_t knock_cyl_i;
uint16_t ecu_CRC_computed;
uint16_t CAL_ecu_CRC_stored;
bool dev_unlocked;
u16_time_5ms fuelpump_timer;
u16_time_4us engine_speed_period;
bool security_flag;
u16_time_5ms CAL_ecu_fuelpump_prime;
ushort REG_TPU3A_CH9_PARAM5;
ushort DAT_003f9010;
ushort DAT_003f9012;
char DAT_003f9704;
ushort REG_TPU3A_CH10_PARAM4;
bool vvt_cam_updated;
i16_angle_1/4deg vvt_pos;
ushort REG_TPU3A_CH0_PARAM5;
bool engine_is_running;
u16_time_us wheel_period_fl;
ushort REG_TPU3A_CH11_PARAM5;
u16_time_us wheel_period_fr;
ushort REG_TPU3A_CH12_PARAM5;
u16_time_us wheel_period_rl;
ushort REG_TPU3A_CH13_PARAM5;
ushort REG_QADCA_RJURR10;
byte DAT_003f9005;
ushort REG_QADCA_RJURR11;
pointer PTR_DAT_000786b8;
u16_voltage_5/1023v[32] map_adc_history;
int16_t maf_adc_history_i;
int16_t map_adc_history_i;
u16_voltage_5/1023v[32] maf_adc_history;
uint16_t misfire_window_count;
uint16_t[4] misfire_count_prev;
uint16_t[4] LEA_misfire_count;
uint16_t misfire_total_count;
u8_rspeed_125/4+500rpm engine_speed_3;
char[32] LEA_base;
uint16_t[4] misfire_count;
ushort REG_TPU3A_CH15_PARAM5;
i16_time_us[4][16] LEA_misfire_stroke_time;
i16_time_us[4] misfire_stroke_diff_1;
u16_time_us[4] misfire_stroke_time;
u16_time_us[4] misfire_stroke_time_prev;
uint16_t misfire_flags;
i16_time_us[4] misfire_stroke_time_smooth;
u16_time_us[4] misfire_stroke_time_dt;
i16_time_us[4] misfire_stroke_cyl_diff;
u16_time_us misfire_threshold;
uint8_t misfire_i;
u16_time_us misfire_stroke_time_tpu;
i16_time_us[4] misfire_stroke_diff_2;
uint8_t misfire_cat_threshold;
uint16_t[4] misfire_cat_timer;
uint16_t misfire_cat_timer_max;
uint16_t dfso_flags;
uint16_t misfire_cat_window_count;
uint16_t[4] misfire_cat_count;
uint8_t[4] misfire_event_flags;
uint16_t[4] misfire_cat_count_prev;
uint16_t misfire_cat_total_count;
byte DAT_003f97c5;
ushort REG_TPU3A_CH2_PARAM1;
ushort REG_TPU3A_CH2_PARAM2;
ushort REG_TPU3A_CH2_PARAM3;
i16_angle_1/4deg ign_adv_final;
ushort REG_TPU3A_CH3_PARAM1;
ushort REG_TPU3A_CH3_PARAM2;
ushort REG_TPU3A_CH3_PARAM3;
ushort REG_TPU3A_CH4_PARAM1;
ushort REG_TPU3A_CH4_PARAM2;
ushort REG_TPU3A_CH4_PARAM3;
u16_time_us ign_dwell_time;
ushort REG_TPU3A_CH1_PARAM3;
uint REG_SISR2;
short DAT_003f9876;
ushort REG_TPU3B_CH1_PARAM1;
ushort REG_HSRR1_B;
short DAT_003f9878;
ushort REG_TPU3B_CH2_PARAM1;
short DAT_003f987a;
ushort REG_TPU3B_CH3_PARAM1;
short DAT_003f987c;
ushort REG_TPU3B_CH4_PARAM1;
ushort REG_CISR_B;
ushort REG_CPR0_B;
undefined1 DAT_003f902c;
u16_angle_1/10deg DAT_003f9024;
short DAT_003f9030;
bool[4] inj_active_cyl;
short DAT_003f97b0;
ushort DAT_003f9858;
pointer PTR_DAT_000786f8;
ushort REG_TPU3B_CH1_PARAM3;
ushort REG_CIER_B;
ushort REG_CFSR1_B;
u16_angle_1/10deg inj_angle_2;
ushort REG_TPU3B_CH10_PARAM0;
ushort REG_HSQR0_B;
ushort REG_HSRR0_B;
ushort REG_TPU3B_CH10_PARAM4;
ushort REG_TPU3B_CH10_PARAM5;
undefined1 DAT_003f902d;
ushort REG_TPU3B_CH11_PARAM0;
u16_angle_1/10deg DAT_003f9026;
ushort REG_TPU3B_CH11_PARAM4;
ushort DAT_003f9870;
ushort REG_TPU3B_CH11_PARAM5;
ushort REG_TPU3B_CH2_PARAM3;
undefined1 DAT_003f902e;
u16_angle_1/10deg DAT_003f9028;
ushort REG_TPU3B_CH3_PARAM3;
ushort DAT_003f9872;
ushort REG_TPU3B_CH12_PARAM0;
ushort REG_TPU3B_CH12_PARAM4;
ushort REG_TPU3B_CH12_PARAM5;
ushort REG_CFSR0_B;
undefined1 DAT_003f902f;
u16_angle_1/10deg DAT_003f902a;
ushort DAT_003f9874;
ushort REG_TPU3B_CH4_PARAM3;
ushort REG_TPU3B_CH13_PARAM0;
ushort REG_TPU3B_CH13_PARAM4;
ushort REG_TPU3B_CH13_PARAM5;
ushort DAT_003f9024;
byte DAT_003f902c;
ushort DAT_003f9030;
byte DAT_003f9032;
char DAT_003fd9f7;
undefined1 tc_fuelcut;
uint16_t revlimit_flags;
u16_time_us inj_time_final_2;
u16_time_100ms ecu_runtime;
ushort DAT_003f9026;
byte DAT_003f902d;
char DAT_003fd9f8;
u16_time_us DAT_003f987e;
ushort DAT_003f9028;
byte DAT_003f902e;
char DAT_003fd9f9;
ushort DAT_003f902a;
byte DAT_003f902f;
char DAT_003fd9fa;
char DAT_003f9020;
char DAT_003f9021;
char DAT_003f9022;
char DAT_003f9023;
char DAT_003f97c2;
short DAT_003f9858;
short DAT_003f9870;
short DAT_003f9872;
short DAT_003f9874;
ushort REG_CANB_MB9_ID_HI;
ushort REG_CANB_MB9_ID_LO;
bool CAL_tpms_use_tpms;
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
ushort REG_IFLAG_B;
u8_pressure_40mbar tpms_pressure_fl;
u8_pressure_40mbar tpms_pressure_fr;
u8_pressure_40mbar tpms_pressure_rl;
u8_pressure_40mbar tpms_pressure_rr;
uint16_t tpms_flags;
byte REG_CANB_MB5_DATA0;
byte REG_CANB_MB5_DATA1;
byte REG_CANB_MB5_DATA2;
byte REG_CANB_MB5_DATA3;
byte REG_CANB_MB5_DATA4;
byte REG_CANB_MB5_DATA5;
byte REG_CANB_MB5_DATA6;
byte DAT_003f9038;
char DAT_003f9880;
char DAT_003fe34e;
char DAT_003fe34f;
char DAT_003fe2cb;
undefined1 DAT_003fe34d;
undefined2 DAT_003fe3ce;
byte REG_CANB_MB7_DATA0;
byte REG_CANB_MB7_DATA2;
undefined1 obd_mode_0x13_state;
undefined2 DAT_003f9892;
byte DAT_003f9894;
byte REG_CANB_MB9_DATA0;
undefined2 DAT_003f9896;
byte REG_CANB_MB9_DATA1;
byte DAT_003f9898;
byte REG_CANB_MB9_DATA2;
byte DAT_003f9899;
byte REG_CANB_MB9_DATA3;
byte DAT_003f989a;
byte REG_CANB_MB9_DATA4;
byte DAT_003f989b;
byte REG_CANB_MB9_DATA5;
byte DAT_003f989c;
byte REG_CANB_MB9_DATA6;
undefined2 DAT_003f9882;
byte REG_CANB_MB9_DATA7;
undefined2 DAT_003f9884;
undefined2 DAT_003f9886;
undefined2 DAT_003f9888;
undefined2 DAT_003f988a;
undefined2 DAT_003f988c;
undefined2 DAT_003f988e;
undefined2 DAT_003f9890;
byte REG_CANB_MB3_DATA0;
byte REG_CANB_MB3_DATA1;
byte REG_CANB_MB3_DATA2;
byte REG_CANB_MB3_DATA3;
u16_speed_1/100kph wheel_speed_r_max;
byte REG_CANB_MB3_DATA4;
byte REG_CANB_MB3_DATA5;
byte REG_CANB_MB3_DATA6;
byte REG_CANB_MB3_DATA7;
u16_rspeed_rpm engine_speed_2;
byte REG_CANB_MB4_DATA0;
byte REG_CANB_MB4_DATA1;
byte REG_CANB_MB4_DATA2;
byte REG_CANB_MB4_DATA3;
byte REG_CANB_MB4_DATA4;
byte REG_CANB_MB4_DATA5;
byte REG_CANB_MB4_DATA6;
byte REG_CANB_MB4_DATA7;
bool CAL_misc_use_tmap;
u8_temp_5/8-40c engine_air_smooth;
u8_temp_5/8-40c intake_air_smooth;
uint REG_SISR3;
ushort REG_CANA_MB15_ID_LO;
ushort REG_CANA_MB4_CS;
ushort REG_CANA_MB4_ID_HI;
ushort REG_CANA_MB4_ID_LO;
ushort REG_CANA_MB5_CS;
ushort REG_CANA_MB5_ID_HI;
ushort REG_CANA_MB5_ID_LO;
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
ushort DAT_003f904e;
byte *DAT_003f9058;
byte *DAT_003f9040;
ushort REG_IFLAG_A;
byte REG_CANA_MB0_DATA0;
byte DAT_003fea0c;
byte REG_CANA_MB2_DATA0;
uint16_t[45] log_canid;
byte *DAT_003fea10;
uint DAT_003fd898;
undefined1 DAT_003fd89c;
byte REG_CANA_MB4_DATA0;
byte REG_CANA_MB6_DATA2;
undefined2 DAT_003f98a0;
byte REG_CANA_MB6_DATA3;
undefined2 DAT_003f98a8;
byte REG_CANA_MB6_DATA4;
undefined2 DAT_003f98aa;
byte REG_CANA_MB6_DATA5;
undefined2 DAT_003f98ac;
byte REG_CANA_MB6_DATA6;
byte REG_CANA_MB6_DATA7;
byte REG_CANA_MB6_DATA0;
byte REG_CANA_MB6_DATA1;
byte DAT_003fdb09;
uint8_t DAT_003fdb0b;
uint8_t DAT_003fdb0c;
undefined1 DAT_003fdb0a;
undefined1 DAT_003fdb08;
char DAT_003fda00;
uint8_t[128] obd_resp;
uint16_t obd_resp_len;
ushort REG_TIMER_A;
byte REG_CANA_MB8_DATA0;
uint8_t[128] obd_req;
ushort DAT_003f9050;
byte *DAT_003f905c;
char DAT_003fea14;
undefined1 DAT_003fe9fc;
byte *DAT_003fea18;
undefined1 DAT_003f8f40;
byte REG_CANA_MB13_DATA0;
byte REG_CANA_MB13_DATA1;
byte REG_CANA_MB3_DATA0;
byte REG_CANA_MB3_DATA1;
byte REG_CANA_MB3_DATA2;
undefined1 DAT_003fea14;
byte DAT_003fea0d;
undefined1 DAT_003fea0c;
char *DAT_003fea10;
char[512] log_data;
byte REG_CANA_MB14_DATA0;
byte REG_CANA_MB14_DATA1;
byte REG_CANA_MB15_DATA0;
byte REG_CANA_MB15_DATA1;
byte REG_CANA_MB15_DATA2;
byte REG_CANA_MB15_DATA3;
struct_varptr *DAT_003f9054;
byte REG_CANA_MB15_DATA4;
struct_varptr *DAT_003f9048;
byte REG_CANA_MB15_DATA5;
ushort DAT_003f904c;
byte REG_CANA_MB15_DATA6;
byte REG_CANA_MB15_DATA7;
byte *DAT_003f9044;
struct_varptr[495] dev_varptr_list;
byte REG_CANA_MB1_DATA0;
byte REG_CANA_MB1_DATA1;
byte REG_CANA_MB1_DATA2;
byte REG_CANA_MB1_DATA3;
byte REG_CANA_MB1_DATA4;
byte REG_CANA_MB1_DATA5;
byte REG_CANA_MB1_DATA6;
byte REG_CANA_MB4_DATA1;
byte REG_CANA_MB4_DATA2;
byte REG_CANA_MB4_DATA4;
byte REG_CANA_MB4_DATA5;
byte REG_CANA_MB4_DATA6;
byte REG_CANA_MB4_DATA7;
ushort REG_MDASM13_SCR;
ushort REG_MDASM14_SCR;
ushort REG_MDASM15_SCR;
ushort REG_MPWMSM17_SCR;
ushort REG_MPWMSM18_PERR;
ushort REG_MPWMSM18_PULR;
ushort REG_MPWMSM18_SCR;
u16_time_25ns CAL_tps_period;
ushort REG_MPWMSM19_SCR;
ushort REG_MPWMSM0_SCR;
ushort REG_MPWMSM1_PERR;
ushort REG_MPWMSM1_PULR;
ushort REG_MPWMSM1_SCR;
ushort REG_MPWMSM2_SCR;
ushort REG_MPWMSM3_SCR;
ushort REG_MDASM27_SCR;
ushort REG_MDASM28_SCR;
ushort REG_MDASM29_SCR;
u16_time_25ns CAL_evap_period;
ushort REG_MDASM30_SCR;
ushort REG_MDASM31_SCR;
ushort REG_MPIOSMDDR;
ushort REG_MIOS14TPCR;
ushort REG_MDASM11_SCR;
ushort REG_MDASM12_SCR;
ushort REG_MCPSMSCR;
byte REG_SPCR3;
ushort REG_QSMCMMCR;
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
byte DAT_003f98b0;
undefined1 DAT_003f8190;
undefined1 DAT_003f8191;
undefined1 DAT_003f8192;
undefined1 DAT_003f9065;
undefined1 DAT_003f98b7;
undefined1 DAT_003f966c;
ushort REG_RECRAM0;
ushort REG_RECRAM1;
ushort REG_RECRAM2;
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
byte DAT_003f8194;
undefined1 DAT_003fd5d8;
int DAT_003f9060;
ushort DAT_003fd5d6;
byte DAT_003f9064;
byte DAT_003f98b8;
ushort DAT_003f98ba;
undefined2 DAT_003f98c8;
undefined2 DAT_003f98ca;
undefined2 DAT_003f98cc;
undefined DAT_0000fffe;
undefined DAT_003f98f0;
char[4] CAL_ecu_unlock_magic;
ushort REG_TPU3B_CH7_PARAM0;
ushort REG_TPU3B_CH7_PARAM2;
ushort REG_TPU3B_CH7_PARAM3;
ushort REG_TPU3B_CH8_PARAM0;
u16_time_25ns CAL_vvl_period;
ushort REG_TPU3B_CH8_PARAM2;
ushort REG_TPU3B_CH8_PARAM3;
ushort REG_TPU3B_CH9_PARAM0;
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
ushort REG_TPU3B_CH0_PARAM3;
ushort REG_TPU3B_CH1_PARAM0;
ushort REG_TPU3B_CH1_PARAM2;
ushort REG_TPU3B_CH2_PARAM0;
ushort REG_TPU3B_CH2_PARAM2;
ushort REG_TPU3B_CH3_PARAM0;
ushort REG_TPU3B_CH3_PARAM2;
ushort REG_TPU3B_CH4_PARAM0;
ushort REG_TPU3B_CH4_PARAM2;
u16_time_25ns CAL_vvt_period;
ushort REG_TPU3B_CH5_PARAM0;
ushort REG_TPU3B_CH5_PARAM1;
ushort REG_TPU3B_CH5_PARAM2;
ushort REG_TPU3B_CH6_PARAM0;
ushort REG_TPU3B_CH6_PARAM1;
ushort REG_TPU3B_CH6_PARAM2;
char DAT_003f81a0;
short DAT_003fd5d6;
short DAT_003fe79a;
char DAT_003f819e;
char DAT_003fd5ce;
char DAT_003fd5cf;
char DAT_003fd5d0;
short DAT_003f819c;
u8_time_5ms hc08_recv_timer;
uint DAT_003f9080;
char DAT_003f819f;
char DAT_003fe2cc;
short DAT_003fd9ac;
ushort DAT_003fd5bc;
uint8_t DAT_003f907d;
short DAT_003fd5be;
short DAT_003f9072;
char DAT_003fd90a;
short DAT_003f9070;
int DAT_003f9074;
u16_time_5ms hc08_send_timer;
short DAT_003fd5c0;
short DAT_003fd5c2;
short DAT_003fd5c4;
short DAT_003fd5c6;
short DAT_003fd5c8;
byte DAT_003f907c;
undefined2 dt_tps_injtip;
short DAT_003f9078;
u16_factor_1/1023 CAL_injtip_out_dt_tps_target_2_limit;
u32_time_5ms shutdown_delay_2;
byte DAT_003f9a4d;
u16_factor_1/1023 CAL_injtip_in_dt_tps_target_2_limit;
byte DAT_003f9a4c;
u16_factor_1/1023 CAL_injtip_out_dt_tps_target_2_min;
u16_factor_1/1023 CAL_injtip_in_dt_tps_target_2_min;
int DAT_003fdd58;
byte DAT_003fdd5c;
ushort DAT_003f9a34;
u16_time_5ms DAT_003f907a;
u16_time_5ms DAT_003fd5da;
ushort DAT_003fd8ee;
pointer PTR_DAT_003fd53b;
undefined1 DAT_003fdcb6;
u8_dt_factor_1/100/5ms injtip_out_adj2;
u8_dt_factor_1/100/5ms injtip_in_adj2;
uint16_t obd_task_scheduler;
u16_factor_1/1023[16] tps_target_history_1;
u16_factor_1/1023[16] tps_target_history_2;
u8_time_5ms hc08_parse_timer;
u8_time_5ms CAL_sensor_dt_tps_target_1_age;
u16_factor_1/1023 pps_tps_target;
i16_factor_1/1023 dt_tps_target_1;
i16_factor_1/1023 dt_tps_target_2;
u8_factor_1/255 load_use_alphaN_tps_min;
u8_time_5ms CAL_sensor_dt_tps_target_2_age;
uint32_t load_1_smooth_x;
u32_load_mg/stroke load_1;
u8_factor_1/256 CAL_load_reactivity;
u8_factor_1/255 tps;
u32_time_5ms engine_runtime;
ushort REG_PISCR;
u8_temp_5/8-40c coolant_smooth;
undefined1 obd_mode_0x2F_state;
undefined1 obd_mode_0x2F_value;
u16_rspeed_1/4rpm engine_speed_1;
uint8_t CAL_dfso_delay_recovery_multiplier;
uint16_t closedloop_flags;
uint16_t LEA_ecu_engine_speed_byte_coefficient;
u32_mass_mg maf_accumulated_1;
undefined2 maf_accumulated_2;
u8_factor_1/100 CAL_load_alphaN_adj_corr_limit_l;
u8_factor_1/100 CAL_load_alphaN_adj_corr_limit_h;
u8_temp_5/8-40c CAL_load_alphaN_adj_corr_coolant_min;
u16_factor_1/1023 CAL_load_alphaN_adj_corr_dt_tps_target_1_max;
undefined4 dt_engine_speed;
u16_rspeed_rpm CAL_load_alphaN_adj_corr_dt_engine_speed_max;
u8_factor_1/100 load_alphaN_maf_error;
u16_factor_1/100 CAL_load_alphaN_adj_corr_min;
u16_factor_1/100 CAL_load_alphaN_adj_corr_max;
u16_time_5ms CAL_load_alphaN_adj_corr_time_between_step;
u16_time_5ms CAL_load_alphaN_adj_corr_time_min;
u16_time_5ms CAL_sensor_o2_heater_warmup_time;
u8_time_5ms CAL_sensor_o2_heater_warmup_period;
bool pre_o2_heater_is_off;
u16_flow_10mg/s maf_flow_1;
bool post_o2_heater_is_off;
u16_time_5ms pre_o2_heater_timer;
u32_load_mg/stroke load_1_smooth;
u16_time_5ms post_o2_heater_timer;
uint8_t o2_heater_warmup_state;
undefined1 dfso_delay;
uint8_t CAL_sensor_maf_avg_size;
uint8_t CAL_sensor_map_avg_size;
uint REG_PITC;
ushort REG_QADC64MCR_A;
ushort REG_QADC64INT_A;
byte REG_PORTQA_A;
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
ushort REG_QADCA_RJURR0;
struct_filter_4th_order filter_tps;
u16_factor_1/1023 tps_1_smooth;
char DAT_003f90c8;
ushort REG_SWSR;
u8_factor_1/256 CAL_sensor_pps_reactivity;
uint32_t pps_1_smooth_x;
uint32_t pps_2_smooth_x;
uint32_t fuel_level_smooth_x;
u8_factor_1/256 CAL_sensor_fuel_reactivity;
uint32_t evap_pressure_smooth_x;
u8_factor_1/256 CAL_sensor_evap_reactivity;
ushort DAT_003fd680;
ushort DAT_003fd68c;
ushort DAT_003fd6aa;
u16_voltage_5/1023v sensor_adc_pre_o2_heater_sense;
ushort DAT_003fd6b2;
ushort DAT_003fd6b6;
u16_voltage_5/1023v sensor_adc_post_o2_heater_sense;
ushort DAT_003fd6b8;
ushort DAT_003fd6ba;
ushort DAT_003fd6bc;
ushort REG_QADCA_RJURR1;
ushort REG_QADCA_RJURR2;
ushort REG_QADCA_RJURR5;
ushort REG_QADCA_RJURR6;
ushort REG_QADCA_RJURR7;
ushort REG_QADCA_RJURR8;
ushort REG_QADCA_RJURR9;
ushort REG_QADCA_RJURR12;
ushort REG_QADCB_RJURR0;
ushort REG_QADCA_RJURR13;
ushort REG_QADCB_RJURR1;
u16_voltage_5/1023v sensor_adc_baro;
ushort REG_QADCA_RJURR14;
ushort REG_QADCB_RJURR2;
ushort REG_QADCA_RJURR15;
ushort REG_QADCB_RJURR3;
ushort REG_QADCA_RJURR16;
ushort REG_QADCB_RJURR4;
ushort REG_QADCA_RJURR17;
ushort REG_QADCB_RJURR5;
u16_voltage_5/1023v sensor_adc_tps_2;
u16_voltage_5/1023v sensor_adc_map;
ushort REG_QADCB_RJURR6;
ushort REG_QADCB_RJURR7;
ushort REG_QADCB_RJURR8;
ushort REG_QADCB_RJURR9;
u16_voltage_5/1023v sensor_adc_ac_fan_request;
ushort REG_QADCB_RJURR10;
ushort REG_QADCB_RJURR11;
u16_voltage_5/1023v sensor_adc_evap;
ushort REG_QADCB_RJURR12;
ushort REG_QADCB_RJURR13;
ushort REG_QADCB_RJURR14;
ushort REG_QADCB_RJURR16;
ushort REG_QADCB_RJURR17;
u16_voltage_5/1023v sensor_adc_tc_knob;
u16_voltage_5/1023v sensor_adc_tc_button;
u16_voltage_18/1023v sensor_adc_ign;
undefined2 sensor_adc_oil_vvtl;
u16_voltage_18/1023v sensor_adc_ecu_voltage;
undefined2 sensor_adc_knock;
u16_voltage_5/1023v sensor_adc_free_2;
u16_voltage_5/1023v sensor_adc_free_3;
u16_voltage_5/1023v sensor_adc_free_1;
u16_voltage_5/1023v sensor_adc_free_4;
u16_voltage_5/1023v sensor_adc_engine_air;
u16_voltage_5/1023v sensor_adc_intake_air;
u16_voltage_5/1023v sensor_adc_coolant;
u16_voltage_5/1023v sensor_adc_pre_o2;
u16_voltage_5/1023v sensor_adc_post_o2;
u16_voltage_5/1023v sensor_adc_fuel_level;
u16_voltage_5/1023v sensor_adc_oil_pressure;
ushort REG_QADCA_RJURR3;
ushort REG_QADCA_RJURR4;
u8_factor_1/64 CAL_sensor_pps_1_gain;
u16_voltage_5/1023v LEA_sensor_pps_1_offset;
u8_factor_1/64 CAL_sensor_pps_2_gain;
u16_voltage_5/1023v LEA_sensor_pps_2_offset;
u16_voltage_5/1023v CAL_sensor_pps_offset_diff_max;
u8_factor_1/256 CAL_sensor_pps_offset_reactivity;
u16_voltage_5/1023v CAL_sensor_pps_1_offset_limit_l;
u16_voltage_5/1023v CAL_sensor_pps_1_offset;
u16_voltage_5/1023v CAL_sensor_pps_2_offset_limit_l;
u16_voltage_5/1023v CAL_sensor_pps_2_offset;
byte DAT_003f994d;
byte DAT_003f994e;
short DAT_003fd6a2;
i16_pressure_mbar DAT_003fc520;
u8_temp_5/8-40c[33] CAL_sensor_coolant_scaling;
u8_temp_5/8-40c[33] CAL_sensor_intake_air_scaling;
u8_temp_5/8-40c[33] CAL_sensor_engine_air_scaling;
u16_factor_1/1023 tps_max;
u8_lambda_1/100[16] CAL_sensor_o2_scaling;
u8_voltage_5/1023v[16] CAL_sensor_o2_scaling_X_signal;
u8_factor_1/2560 CAL_sensor_coolant_reactivity;
u8_factor_1/2560 CAL_sensor_engine_air_reactivity;
u8_factor_1/2560 CAL_sensor_intake_air_reactivity;
i16_pressure_mbar CAL_sensor_baro_offset;
u16_ratio_mbar/5v CAL_sensor_baro_gain;
i16_pressure_mbar atmo_pressure;
u16_ratio_mbar/5v CAL_sensor_map_gain;
i16_pressure_mbar CAL_sensor_map_offset;
i16_pressure_mbar map;
u16_ratio_1/10mbar/5v CAL_sensor_evap_gain;
i16_pressure_1/10mbar CAL_sensor_evap_offset;
i16_pressure_1/10mbar evap_pressure;
u16_temp_5/8-40c coolant;
u16_temp_5/8-40c engine_air;
u16_temp_5/8-40c intake_air;
bool tps_both_fault;
u8_factor_1/255 CAL_tps_fallback;
u8_temp_5/8-40c CAL_sensor_engine_air_fallback;
u8_temp_5/8-40c CAL_sensor_coolant_fallback;
uint16_t sensor_fault_flags;
uint32_t coolant_smooth_x;
uint32_t engine_air_smooth_x;
uint32_t intake_air_smooth_x;
u8_factor_1/156-14/156 fuel_level;
u8_lambda_1/100 post_o2;
u8_lambda_1/100 pre_o2;
u8_factor_1/156-14/156[9] CAL_sensor_fuel_scaling;
uint16_t CAL_ecu_engine_speed_byte_coefficient;
uint16_t CAL_ecu_engine_speed_byte_offset;
u16_current_mA CAL_sensor_o2_heater_max;
u16_current_mA pre_o2_heater_current;
u16_current_mA post_o2_heater_current;
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
short DAT_003fd7c6;
byte DAT_003f99a7;
u16_rspeed_rpm CAL_vvl_rpm_enable;
byte DAT_003f9a6a;
uint32_t ac_fan_flags;
int DAT_003f90f0;
int DAT_003f90f4;
int DAT_003f90f8;
u8_load_4mg/stroke CAL_vvl_high_load_enable;
int DAT_003f90fc;
int DAT_003f9100;
byte DAT_003f9912;
int DAT_003f9104;
uint DAT_003f9108;
ushort DAT_003f90e8;
uint DAT_003f910c;
ushort DAT_003f90ea;
uint DAT_003f9110;
ushort DAT_003f90ec;
uint DAT_003f9114;
ushort DAT_003f90ee;
short DAT_003f9124;
uint32_t DAT_003f9128;
int DAT_003f81b0;
int DAT_003f81b4;
int DAT_003f81b8;
int DAT_003f81bc;
undefined2 ign_adv_idle_base;
uint16_t idle_flags;
i16_angle_1/4deg ign_adv_adj1;
u8_angle_1/4deg[8] CAL_ign_adv_adj4;
undefined1 ign_adv_adj4;
undefined2 ign_adv_adj2;
u8_factor_1/100[8] CAL_ign_adv_adj4_X_dt_tps_injtip;
u8_angle_1/4-32deg[16] CAL_ign_adv_adj3;
u8_rspeed_125/4+500rpm[16] CAL_ign_adv_adj3_X_engine_speed;
uint32_t[72] crank_tooth_pattern;
i16_angle_1/4deg ign_adv_adj3;
u8_factor_1/128[8] CAL_ign_adv_adj3_adj;
u8_temp_5/8-40c[8] CAL_ign_adv_adj3_adj_X_coolant;
u8_angle_1/4-32deg[16] CAL_ign_adv_idle_adj1;
u8_rspeed_4-512rpm[16] CAL_ign_adv_idle_adj1_X_idle_error;
undefined2 ign_adv_idle_adj1;
undefined2 ign_adv_idle_adj1_alternative;
u8_rspeed_4-512rpm[16] CAL_ign_adv_idle_adj1_alternative_X_idle_error;
u8_angle_1/4-32deg[16] CAL_ign_adv_idle_adj1_alternative;
i16_angle_1/4deg ign_adv_idle_adj2;
i16_rspeed_rpm engine_speed_idle_error;
i16_angle_1/4deg ign_adv_idle_adj3;
u8_angle_1/4-32deg[16] CAL_ign_adv_idle_adj3;
uint8_t[16] CAL_ign_adv_idle_adj3_X_engine_speed_dt;
u8_temp_5/8-40c coolant_stop;
u16_factor_1/1023 pps;
uint16_t ign_flags;
i16_angle_1/4deg[4] ign_adv_cyl;
u8_factor_1/128 ign_adv_adj3_adj;
u8_time_5ms ign_adv_idle_adj1_timer;
u8_time_5ms CAL_ign_adv_idle_adj1_time;
u16_time_5ms ign_cranking_timer;
int32_t engine_speed_dt;
undefined2 ign_adv_base;
undefined2 ign_adv_knock;
undefined2 ign_adv_base2;
u8_angle_1/4-32deg CAL_ign_adv_limit_l;
u8_speed_kph CAL_idle_flow_adj5_max;
u8_angle_1/4-10deg[1024] CAL_ign_adv_low_cam_base;
u8_rspeed_125/4+500rpm[32] CAL_ign_adv_low_cam_base_X_engine_speed;
u8_load_4mg/stroke[32] CAL_ign_adv_low_cam_base_Y_engine_load;
u8_angle_1/4-10deg[64] CAL_ign_adv_high_cam_base;
u8_speed_kph car_speed_smooth;
u8_rspeed_125/4+500rpm[8] CAL_ign_adv_high_cam_base_X_engine_speed;
u8_load_4mg/stroke[8] CAL_ign_adv_high_cam_base_Y_engine_load;
u8_angle_1/4deg[8] CAL_ign_adv_cranking;
u8_temp_5/8-40c[8] CAL_ign_adv_cranking_X_coolant_stop;
u8_angle_1/4deg ign_adv_cranking;
u8_angle_1/4-10deg[1024] CAL_ign_adv_low_cam_knock_safe;
u8_angle_1/4-10deg[64] CAL_ign_adv_high_cam_knock_safe;
u8_rspeed_125/4+500rpm[8] CAL_ign_adv_high_cam_knock_safe_X_engine_speed;
u8_load_4mg/stroke[8] CAL_ign_adv_high_cam_knock_safe_Y_engine_load;
u8_rspeed_125/4+500rpm[32] CAL_ign_adv_low_cam_knock_safe_X_engine_speed;
u8_load_4mg/stroke[32] CAL_ign_adv_low_cam_knock_safe_Y_engine_load;
i16_angle_1/4deg ign_adv_smooth;
u8_angle_1/4deg ign_adv_smooth_step;
u8_angle_1/4deg[128] CAL_ign_adv_smooth_step;
u8_rspeed_125/4+500rpm[8] CAL_ign_adv_smooth_step_X_engine_speed;
u8_factor_1/255[16] CAL_ign_adv_smooth_step_Y_pps;
u8_voltage_72/1023v[8] CAL_ign_dwell_base_Y_car_voltage;
u8_rspeed_125/4+500rpm[8] CAL_ign_dwell_base_X_engine_speed;
u8_time_64us[64] CAL_ign_dwell_base;
u8_temp_5/8-40c[16] CAL_ign_adv_adj1_X_engine_air;
u8_angle_1/4-32deg[16] CAL_ign_adv_adj1;
u8_temp_5/8-40c[16] CAL_ign_adv_idle_base_X_coolant;
u8_angle_1/4deg[16] CAL_ign_adv_idle_base;
u8_factor_1/255 ign_adv_adj_by_tc;
u8_angle_1/4deg CAL_ign_adv_dfso;
u8_factor_1/255[64] CAL_ign_adv_adj2;
u8_mass_8g[8] CAL_ign_adv_adj2_X_maf_accumulated;
u8_factor_1/255[8] CAL_ign_adv_adj2_Y_tps;
u8_temp_5/8-40c CAL_ign_stop_coolant_to_use_adj2_min;
u8_temp_5/8-40c CAL_ign_stop_coolant_to_use_adj2_max;
u8_angle_1/4deg CAL_ign_adv_idle_adj_ac_on;
u8_angle_1/4-32deg[16] CAL_ign_adv_idle_adj2;
u8_temp_5/8-40c[16] CAL_ign_adv_idle_adj2_X_engine_air;
bool vvl_is_high_cam;
u8_load_4mg/stroke load_2;
u8_angle_1/4deg[4] knock_retard2;
u8_angle_1/4-32deg[4] CAL_ign_adv_adj_cyl;
u8_time_10ms CAL_ign_cranking_runtime_max;
undefined1 ign_adv_smooth_timer;
byte DAT_003fc9ed;
byte DAT_003fc9ee;
byte DAT_003fc9ef;
byte DAT_003fc9f0;
struct_diag_channel[31] diag_channel;
byte DAT_003fd74c;
undefined2 DAT_003fd748;
ushort DAT_003fd75c;
int DAT_003fd758;
int DAT_003fd750;
undefined1 DAT_003fd762;
u8_afr_1/100 CAL_inj_afr_adj_per_adv_adj;
u16_rspeed_rpm revlimit_base;
int DAT_003f9134;
u32_time_us inj_time_cranking_adj;
byte DAT_003f81d7;
int DAT_003fd73c;
u32_time_us inj_time_cranking;
u8_angle_720/256deg inj_angle_1;
u32_time_us injtip_in;
undefined2 DAT_003f81d4;
u8_factor_1/64 inj_time_adj1;
u32_time_us injtip_reactive;
u8_factor_1/64 inj_time_adj3;
u8_factor_1/64 inj_time_adj2;
u16_afr_1/100 CAL_stft_afr;
u8_afr_1/20+5[256] CAL_inj_afr_base;
u8_rspeed_125/4+500rpm[16] CAL_inj_afr_base_X_engine_speed;
u8_load_4mg/stroke[16] CAL_inj_afr_base_Y_engine_load;
u16_afr_1/100 afr_target;
undefined2 inj_fuel_load_needed;
u8_factor_1/128[16] CAL_inj_time_adj2;
u8_temp_5/8-40c[16] CAL_inj_time_adj2_X_engine_air;
i16_time_us LEA_ltft_zone1_adj;
u8_time_100ms revlimit_timer_2;
uint8_t tc_flags;
u16_rspeed_rpm revlimit;
u8_rspeed_10+6000rpm[64] CAL_revlimit_speed_base;
u16_rspeed_rpm LEA_tc_launchcontrol_revlimit;
u8_speed_kph wheel_speed_f_max_2;
u8_temp_5/8-40c[8] CAL_revlimit_speed_base_X_coolant;
u8_time_100ms[8] CAL_revlimit_speed_base_Y_timer;
u16_rspeed_rpm CAL_revlimit_offset_reset_timer;
undefined1 tc_min_speed;
u16_rspeed_rpm CAL_revlimit_speed_adj_limp_reduced;
i16_factor_1/2000 inj_time_adj_by_stft;
i16_factor_1/2000 inj_time_adj_by_ltft;
u8_time_20us[16] CAL_inj_time_base;
u8_voltage_72/1023v[16] CAL_inj_time_base_X_car_voltage;
u16_time_us inj_time_base;
undefined1 inj_efficiency;
undefined2 evap_fuel_load;
u8_time_256us[16] CAL_inj_time_adj_cranking;
u8_temp_5/8-40c[16] CAL_inj_time_adj_cranking_X_coolant_stop;
u8_factor_1/32[384] CAL_inj_time_adj1;
u16_rspeed_rpm CAL_revlimit_offset_misfire_eval;
u8_temp_5/8-40c[16] CAL_inj_time_adj1_X_coolant_stop;
u16_rspeed_rpm revlimit_misfire_eval;
u8_mass_g[24] CAL_inj_time_adj1_Y_maf_accumulated;
u8_angle_720/256deg[64] CAL_inj_angle;
u8_load_4mg/stroke[8] CAL_inj_angle_Y_engine_load;
u8_rspeed_125/4+500rpm[8] CAL_inj_angle_X_engine_speed;
u32_time_us inj_time_final_1;
u8_afr_1/100 afr_adj;
u16_flow_mg/s CAL_inj_flow_rate;
u32_time_us inj_time_afr;
i16_angle_1/4deg knock_retard2_sum;
u8_factor_1/200[1024] CAL_inj_efficiency;
u8_load_4mg/stroke[32] CAL_inj_efficiency_Y_engine_load;
undefined1 inj_duty_cycle;
u8_rspeed_125/4+500rpm[32] CAL_inj_efficiency_X_engine_speed;
u8_factor_1/64[256] CAL_inj_time_adj3;
u8_load_4mg/stroke[16] CAL_inj_time_adj3_X_engine_load;
u8_temp_5/8-40c[16] CAL_inj_time_adj3_Y_coolant;
u32_time_us injtip_out;
u8_time_5ms revlimit_timer_1;
u8_time_5ms[8] CAL_idle_flow_adj_fan_low_X_on_time;
short DAT_003fd7b8;
u8_time_5ms[8] CAL_idle_flow_adj_fan_high_X_on_time;
ushort DAT_003fd7c6;
u8_flow_100mg/s[8] CAL_idle_flow_adj_fan_high;
ushort DAT_003fd7ae;
ushort DAT_003fd7b0;
u8_flow_100mg/s CAL_idle_flow_adj1_corr_limit_h;
u8_flow_100mg/s DAT_003f9144;
u8_flow_-100mg/s CAL_idle_flow_adj1_corr_limit_l;
u16_mass_g CAL_idle_flow_adj1_corr_maf_accumulated_min;
byte DAT_003fd7ab;
byte DAT_003fd7a9;
u8_flow_100mg/s CAL_idle_flow_adj1_corr_max;
byte DAT_003fd7aa;
u8_flow_-100mg/s CAL_idle_flow_adj1_corr_min;
byte DAT_003f99a8;
byte DAT_003f99a9;
undefined1 idle_flow_adj4_adj;
byte DAT_003fd7ac;
undefined1 idle_flow_adj2;
undefined2 idle_flow_adj6;
uint8_t DAT_003fd5ce;
uint8_t DAT_003fd5cf;
undefined2 idle_flow_adj3;
uint8_t DAT_003fd5d0;
undefined1 idle_flow_adj7;
ushort DAT_003fd7b4;
undefined1 idle_flow_adj5;
short DAT_002f822e;
undefined1 idle_flow_adj8_corr_step;
short DAT_002f8232;
undefined1 idle_flow_adj_ac;
short DAT_002f8230;
undefined1 idle_flow_adj_fan_low;
short DAT_002f8234;
undefined1 idle_flow_adj_fan_high;
i32_flow_100/1024mg/s idle_flow_adj8;
short DAT_003f81d8;
u8_flow_-100mg/s CAL_idle_flow_adj8_corr_limit_l;
undefined2 idle_speed_adj;
u8_time_5ms CAL_idle_flow_adj8_corr_time_between_step;
undefined1 idle_flow_adj4;
u16_flow_mg/s evap_flow;
u8_temp_5/8-40c[16] CAL_idle_speed_base_X_coolant;
u8_rspeed_4+500rpm[16] CAL_idle_speed_base;
u8_rspeed_4rpm[8] CAL_idle_speed_adj;
u8_speed_kph[8] CAL_idle_speed_adj_X_car_speed;
i16_flow_100mg/s idle_flow_adj5_or_zero;
i16_rspeed_rpm idle_speed_target;
i16_pressure_4mbar vacuum_2;
u8_factor_1/64[128] CAL_idle_flow_adj4_adj;
u8_temp_5/8-40c[16] CAL_idle_flow_adj4_adj_X_coolant;
u8_mass_4g[8] CAL_idle_flow_adj4_adj_Y_maf_accumulated;
uint8_t idle_status;
u8_pressure_4mbar[8] CAL_idle_flow_adj2_X_atmo_pressure;
u8_flow_100mg/s[8] CAL_idle_flow_adj2;
u16_rspeed_rpm CAL_idle_speed_adj_ac_on;
i16_pressure_mbar vacuum_1;
uint16_t evap_flags;
i16_flow_100/1024mg/s LEA_idle_flow_adj1;
u8_factor_1/1023 CAL_idle_flow_pps_max;
u16_factor_1/1023 idle_tps_target;
u8_factor_1/1023[64] CAL_idle_tps_engine_stop;
u8_temp_5/8-40c[16] CAL_idle_tps_engine_stop_Y_coolant;
i16_flow_100/1024mg/s LEA_idle_flow_adj1_ac_on;
u8_pressure_4mbar[4] CAL_idle_tps_engine_stop_X_atmo_pressure;
u8_flow_100mg/s idle_flow_target;
u16_factor_1/1023 CAL_idle_tps_limit_h;
u8_factor_1/1023[64] CAL_idle_tps;
u8_pressure_4mbar[8] CAL_idle_tps_Y_vacuum;
u8_flow_100mg/s[8] CAL_idle_tps_X_target_flow;
u8_flow_100mg/s CAL_idle_flow_base;
u8_flow_100-12800mg/s[8] CAL_idle_flow_adj3;
u8_voltage_72/1023v[8] CAL_idle_flow_adj3_X_car_voltage;
u8_speed_kph[8] CAL_idle_flow_adj6_X_car_speed;
u8_flow_100mg/s[8] CAL_idle_flow_adj6;
u8_rspeed_4+500rpm[8] CAL_idle_flow_adj4_X_idle_speed_target;
u8_flow_100mg/s[8] CAL_idle_flow_adj4;
u8_flow_100-12800mg/s[16] CAL_idle_flow_adj5;
u8_rspeed_4-512rpm[16] CAL_idle_flow_adj5_X_engine_speed_idle_error;
u8_flow_100mg/s[16] CAL_idle_flow_adj7;
u8_rspeed_125/4+500rpm[16] CAL_idle_flow_adj7_X_engine_speed;
u8_flow_100mg/s CAL_idle_flow_adj8_corr_limit_h;
u8_flow_100/1024mg/s[16] CAL_idle_flow_adj8_corr_step;
u8_rspeed_4-512rpm[16] CAL_idle_flow_adj8_corr_step_X_engine_speed_idle_error;
u8_rspeed_8rpm CAL_idle_flow_adj7_enable;
u8_rspeed_8rpm CAL_idle_flow_adj7_disable;
u8_flow_100mg/s[8] CAL_idle_flow_adj_ac;
u8_time_5ms[8] CAL_idle_flow_adj_ac_X_on_time;
u8_flow_100mg/s[8] CAL_idle_flow_adj_fan_low;
byte DAT_003f9144;
u8_time_5ms DAT_003f9140;
short DAT_003fd7b4;
u8_time_5ms DAT_003f9141;
u8_time_5ms CAL_idle_speed_time_between_decrement;
char DAT_003fd7ac;
u8_time_5ms CAL_idle_flow_time_between_decrement;
undefined2 DAT_003f97bc;
undefined1 DAT_003f8010;
undefined1 DAT_003f97c1;
uint8_t DAT_003fdd4c;
undefined2 DAT_003fd7f4;
char DAT_003fd7fb;
short DAT_003f8216;
u8_temp_5/8-40c engine_air_stop;
u16_voltage_5/1023v sensor_adc_maf1;
u16_voltage_5/1023v sensor_adc_maf2;
u8_mass_65536mg[17] CAL_obd_P0128_wait_air_mass;
ushort REG_TPU3A_CH0_PARAM2;
u16_time_4us CAL_misc_engine_running_enable;
u16_time_4us CAL_misc_engine_running_disable;
char DAT_003f9920;
undefined2 DAT_003f97b0;
undefined2 DAT_003f81e6;
uint16_t[15] engine_speed_period_history;
ushort DAT_003f8216;
undefined2 DAT_003fc59c;
undefined2 DAT_003fe18c;
ushort DAT_003f9148;
byte DAT_003f914a;
uint8_t CAL_misc_engine_running_crank_tooth_min;
uint8_t CAL_sensor_dt_engine_speed_age;
uint8_t CAL_ign_adv_idle_adj3_engine_speed_dt_age;
uint8_t CAL_sensor_engine_speed_period_avg_size;
u8_factor_1/256 CAL_injtip_catalyst_adj_fadeout;
u16_time_4us engine_speed_period_avg;
undefined2 dfso_count;
u8_factor_1/128 CAL_injtip_in_adj_gears_6;
short DAT_003fd834;
u32_time_us DAT_003fd82c;
u32_time_us DAT_003fd830;
u8_time_us CAL_injtip_time_base;
undefined1 injtip_in_gear;
u8_factor_1/64[16] CAL_injtip_out_adj3;
u8_factor_1/64[16] CAL_injtip_in_adj3;
u8_temp_5/8-40c[16] CAL_injtip_out_adj3_X_coolant;
u8_temp_5/8-40c[16] CAL_injtip_in_adj3_X_coolant;
undefined1 injtip_in_coolant;
undefined1 injtip_out_coolant;
undefined1 injtip_out_speed;
undefined1 injtip_in_speed;
u8_factor_1/128[16] CAL_injtip_in_adj1;
u8_rspeed_125/4+500rpm[16] CAL_injtip_in_adj1_X_engine_speed;
u8_factor_1/128[16] CAL_injtip_out_adj1;
u8_rspeed_125/4+500rpm[16] CAL_injtip_out_adj1_X_engine_speed;
u8_dt_factor_1/100/5ms[16] CAL_injtip_in_adj2;
u8_rspeed_125/4+500rpm[16] CAL_injtip_in_adj2_X_engine_speed;
uint8_t car_gear_current;
u8_dt_factor_1/100/5ms[16] CAL_injtip_out_adj2;
u8_rspeed_125/4+500rpm[16] CAL_injtip_out_adj2_X_engine_speed;
u8_temp_5/8-40c CAL_dfso_coolant_disable;
u8_temp_5/8-40c CAL_dfso_coolant_enable;
u16_rspeed_rpm CAL_dfso_engine_speed_disable;
u16_rspeed_rpm CAL_dfso_engine_speed_enable;
u8_factor_1/1023 CAL_dfso_pps_disable;
u8_factor_1/1023 CAL_dfso_pps_enable;
u8_speed_kph CAL_dfso_car_speed_disable;
u8_speed_kph CAL_dfso_car_speed_enable;
u8_time_50ms CAL_dfso_runtime_min;
uint8_t[17] CAL_injtip_catalyst_adj;
u8_time_5ms[4] CAL_dfso_delay;
u8_factor_1/255[4] CAL_dfso_delay_X_pps;
u8_factor_1/128[6] CAL_injtip_in_adj_gears;
i16_angle_1/4deg vvt_target_smooth;
i16_factor_1/256 CAL_vvt_ctrl_p_gain;
i16_angle_1/4deg vvt_diff;
u8_angle_1/4deg CAL_vvt_rest_pos_threshold;
u16_time_100ms vvt_runtime_min;
bool vvt_rest_pos_measured;
bool vvt_rest_pos_fault;
int16_t vvt_ctrl_p;
int32_t vvt_ctrl_i;
int32_t vvt_output;
i32_angle_1/4deg vvt_rest_pos_sum;
int32_t vvt_rest_pos_count;
i16_angle_1/4deg vvt_rest_pos_min;
i16_angle_1/4deg vvt_rest_pos_max;
i32_angle_1/4deg vvt_rest_pos_avg;
u16_factor_1/1024 vvt_duty_cycle;
i16_angle_1/4deg vvt_target;
u8_time_100ms[8] CAL_vvt_runtime_min;
u8_temp_5/8-40c[8] CAL_vvt_runtime_min_X_coolant_stop;
u8_angle_1/4deg[16] CAL_vvt_adv_adj;
u8_temp_5/8-40c[16] CAL_vvt_adv_adj_X_coolant;
u8_angle_1/4deg[256] CAL_vvt_adv_high_cam_base;
u8_rspeed_125/4+500rpm[16] CAL_vvt_adv_high_cam_base_X_engine_speed;
u8_load_4mg/stroke[16] CAL_vvt_adv_high_cam_base_Y_engine_load;
u8_rspeed_125/4+500rpm[16] CAL_vvt_adv_low_cam_base_X_engine_speed;
u8_load_4mg/stroke[16] CAL_vvt_adv_low_cam_base_Y_engine_load;
u8_angle_1/4deg[256] CAL_vvt_adv_low_cam_base;
u16_rspeed_rpm CAL_vvl_rpm_high_load_enable;
u16_rspeed_rpm CAL_vvl_rpm_high_load_disable;
u16_rspeed_rpm CAL_vvl_rpm_disable;
u8_load_4mg/stroke CAL_vvl_high_load_disable;
u16_factor_1/2048 CAL_vvl_duty_cycle_engaged;
u16_factor_1/2048 CAL_vvl_duty_cycle_disengaged;
u16_factor_1/2048 vvl_duty_cycle;
u8_temp_5/8-40c CAL_vvl_coolant_disable;
u8_temp_5/8-40c CAL_vvl_coolant_enable;
undefined DAT_00019000;
bool vvt_target_reached;
u8_time_5ms vvt_timer;
i16_factor_1/256 CAL_vvt_ctrl_i_gain;
uint8_t LEA_obd_P2649_flags;
uint8_t LEA_obd_P0077_flags;
char[17] LEA_ecu_VIN;
uint8_t eeprom_saved;
u16_time_s shutdown_delay_1;
u8_temp_5/8-40c[8] CAL_ecu_shutdown_delay_X_engine_air;
u8_temp_5/8-40c[8] CAL_ecu_shutdown_delay_Y_coolant;
u8_time_5s[64] CAL_ecu_shutdown_delay;
u8_voltage_72/1023v CAL_ecu_ign_min;
u16_time_5ms CAL_ecu_startrelay_runtime_max;
u8_speed_kph CAL_ac_car_speed_disable;
u8_temp_5/8-40c CAL_ac_coolant_disable;
ushort DAT_003fd5c6;
u8_speed_kph CAL_ac_car_speed_enable;
ushort DAT_003fd5c4;
u8_factor_1/255 CAL_ac_tps_enable;
undefined1 DAT_003fd5ce;
u8_factor_1/255 CAL_ac_pps_disable;
u8_time_100ms CAL_ac_pps_disable_time_min;
u8_time_5ms CAL_ac_user_disable_time_min;
u8_time_5ms CAL_ac_user_enable_time_min;
u16_time_5ms CAL_ac_runtime_min;
u8_rspeed_125/4+500rpm CAL_ac_engine_speed_disable;
u8_rspeed_125/4+500rpm CAL_ac_engine_speed_enable;
u8_temp_5/8-40c CAL_ac_coolant_enable;
uint16_t uint16_t_003fd880;
uint ratio;
u16_ratio_rpm/kph[10] CAL_misc_gears;
u16_ratio_rpm/kph[2] CAL_misc_gears_6;
u8_temp_5/8-40c CAL_misc_recirculation_pump_stop_enable;
u8_temp_5/8-40c CAL_misc_recirculation_pump_stop_disable;
ushort DAT_003fd5c0;
undefined1 DAT_003fd5cf;
short DAT_003f917a;
ushort DAT_003fd5c2;
undefined1 DAT_003fd5d0;
u8_time_s CAL_fan_high_stop_user_delay;
u8_temp_5/8-40c CAL_fan_high_ac_enable;
u8_temp_5/8-40c CAL_fan_high_ac_disable;
u16_time_5ms CAL_fan_low_stop_time_min;
u16_time_5ms CAL_fan_high_stop_time_min;
u8_temp_5/8-40c CAL_fan_low_enable;
u8_temp_5/8-40c CAL_fan_low_disable;
u8_temp_5/8-40c CAL_fan_high_enable;
u8_temp_5/8-40c CAL_fan_high_disable;
u8_speed_kph CAL_fan_car_speed_disable;
u8_temp_5/8-40c CAL_fan_low_stop_enable;
u8_temp_5/8-40c CAL_fan_low_stop_disable;
bool DAT_003fd887;
bool DAT_003fd888;
bool DAT_003fd889;
bool DAT_003fd88a;
undefined1 DAT_003fd88b;
bool DAT_003fd88c;
bool DAT_003fd88d;
bool DAT_003fd88e;
bool DAT_003fd895;
bool DAT_003fd894;
short DAT_003f9178;
u8_factor_1/255 DAT_003fd886;
char DAT_003f9184;
char DAT_003fd9b9;
ushort DAT_003f9182;
char DAT_003f9180;
byte DAT_003f917f;
u16_rspeed_rpm obd_mode_0x2F_RPM;
u8_speed_kph DAT_003fc5b1;
short DAT_003f8cba;
struct_data2cluster data2cluster;
uint8_t[2] lights_flags;
uint16_t obd_mil_flags;
u8_temp_5/8-40c CAL_misc_coolant_warning_max;
uint8_t[8] CAL_misc_shift_lights_before_revlimit_X_car_gear_current;
u16_rspeed_rpm CAL_misc_shift_lights_margin;
bool LEA_tc_button_fitted;
undefined1 shift_lights_state;
undefined1 tc_state;
byte DAT_003f8249;
byte DAT_003f8248;
byte DAT_003fd89d;
undefined1 DAT_003fd89e;
undefined1 DAT_003fd89f;
undefined1 DAT_003fd8a0;
undefined1 DAT_003fd8a1;
undefined1 DAT_003fd8a2;
undefined1 DAT_003fd8a3;
u16_rspeed_rpm CAL_misc_airbox_flap_disable;
u16_rspeed_rpm CAL_misc_airbox_flap_enable;
char DAT_003f824a;
byte DAT_003f9188;
uint16_t[256] CRC16_lookup;
ushort DAT_003fd8e2;
short DAT_003fd904;
undefined2 DAT_003fd93a;
undefined2 DAT_003fd906;
u8_time_5ms DAT_003fd90a;
byte DAT_003f9192;
ushort DAT_003fd8f2;
ushort DAT_003fd8f4;
undefined1 DAT_003fd910;
byte DAT_003fd911;
undefined DAT_003fa8c4;
undefined DAT_003fa8d4;
undefined DAT_003fa8e4;
undefined DAT_003fa8f4;
u8_factor_1/100 load_5;
u16_load_mg/stroke CAL_load_possible_max_mode22;
u8_factor_1/255 load_4;
u16_load_mg/stroke CAL_load_possible_max_absolute;
u8_factor_1/255 load_3;
u8_load_4mg/stroke[16] CAL_load_possible_max;
u8_rspeed_125/4+500rpm[16] CAL_load_possible_max_X_engine_speed;
uint8_t load_use_alphaN;
u32_load_mg/stroke load_alphaN;
u32_load_mg/stroke load_maf;
u16_rspeed_rpm CAL_load_use_alphaN_engine_speed_max;
u16_factor_1/100 load_alphaN_adj;
u8_factor_1/100[256] LEA_load_alphaN_adj;
u8_rspeed_125/4+500rpm[16] LEA_load_alphaN_adj_X_engine_speed;
u8_factor_1/255[16] LEA_load_alphaN_adj_Y_tps;
u8_load_4mg/stroke[256] CAL_load_alphaN_base;
undefined2 load_diff;
u8_rspeed_125/4+500rpm[16] CAL_load_alphaN_base_X_engine_speed;
u8_factor_1/255[16] CAL_load_alphaN_base_Y_tps;
u16_voltage_5/1023v[32] CAL_sensor_maf_scaling_X_signal;
u16_flow_10mg/s[32] CAL_sensor_maf_scaling;
u8_time_5ms CAL_load_use_alphaN_timer;
u16_flow_10mg/s maf_flow_diff;
u8_factor_1/255[16] CAL_load_use_alphaN_tps_min;
u16_flow_10mg/s maf_flow_2;
u8_rspeed_125/4+500rpm[16] CAL_load_use_alphaN_tps_min_X_engine_speed;
u16_factor_1/1023 CAL_load_use_alphaN_dt_tps_target_1_positive_min;
u16_factor_1/1023 CAL_load_use_alphaN_dt_tps_target_1_negative_min;
u8_load_4mg/stroke[16] CAL_load_alphaN_engine_stop;
u8_factor_1/255[16] CAL_load_alphaN_engine_stop_X_tps;
u8_time_100ms CAL_evap_dfso_recovery_delay;
ushort DAT_003fdc70;
short DAT_003f91b6;
u8_time_800ms CAL_evap_engine_start_delay;
u8_time_100ms DAT_003f91ba;
u8_time_1600ms CAL_evap_restart_delay;
u8_time_100ms DAT_003f8254;
u8_time_100ms CAL_evap_closedloop_delay;
short DAT_003f91be;
u8_time_100ms CAL_evap_learn_delay;
u8_time_100ms DAT_003f91c1;
u8_time_100ms CAL_evap_duty_cycle_initial_time;
uint8_t CAL_evap_purge_mode;
ushort DAT_003f9ace;
u8_time_100ms DAT_003f8255;
short DAT_003f9a76;
ushort DAT_003f9a72;
u8_time_100ms DAT_003f91bc;
ushort DAT_003f9a9a;
ushort DAT_003f9a74;
undefined2 evap_pressure_drop_inc;
uint8_t LEA_obd_P0444_flags;
uint8_t LEA_obd_P0445_flags;
undefined2 evap_pressure_drop_1;
u16_factor_1/100 evap_concentration_2;
u16_time_100ms fuel_learn_timer;
undefined4 evap_concentration_1;
undefined2 evap_purge_command;
u8_pressure_1/64mbar CAL_evap_pressure_drop_inc_limit_l;
undefined1 evap_pressure_drop_2;
uint8_t evap_leak_state;
undefined1 evap_state;
uint16_t fuel_system_status;
uint8_t LEA_obd_P0441_flags;
u8_time_100ms CAL_evap_initial_delay;
u8_time_100ms DAT_003f91c0;
char DAT_003f8254;
short DAT_003fc602;
ushort DAT_003fd748;
char DAT_003f91c1;
undefined2 evap_pressure_drop_dec;
u8_time_8us CAL_evap_inj_time_disable;
u8_time_8us CAL_evap_inj_time_enable;
u8_flow_100mg/s CAL_evap_idle_flow_disable;
u8_flow_100mg/s CAL_evap_idle_flow_enable;
u16_flow_mg/s evap_fuel_flow_correction;
undefined2 evap_fuel_flow;
i16_factor_1/2000 inj_time_stft_smooth;
u8_factor_1/255 CAL_evap_duty_cycle_limit_l;
u8_factor_1/255 CAL_evap_duty_cycle_limit_h;
i16_pressure_mbar vacuum_smooth;
u8_pressure_4mbar[16] CAL_evap_purge_X_pressure_drop;
u8_factor_1/255[256] CAL_evap_purge;
u8_pressure_4mbar[16] CAL_evap_purge_Y_vacuum;
u8_time_100ms CAL_evap_stft_stability_delay;
u8_pressure_4mbar evap_pressure_drop_max;
u8_factor_1/255 CAL_evap_duty_cycle_initial;
u8_pressure_1/64mbar CAL_evap_pressure_drop_dec_initial;
u8_pressure_4mbar evap_pressure_drop_max_vacuum;
u8_pressure_4mbar evap_pressure_drop_max_load;
u8_pressure_4mbar CAL_evap_pressure_drop_idle_limit_h;
u8_pressure_4mbar evap_pressure_drop_max_leak_test;
undefined4 evap_concentration_adj;
undefined2 evap_stft_neg;
undefined2 evap_fuel_load_prev;
undefined2 evap_duty_adj;
undefined2 evap_pwm_pulse;
uint8_t CAL_evap_flow_divisor;
undefined1 evap_flow_2;
u8_pressure_4mbar[8] CAL_evap_pressure_drop_max;
u8_pressure_4mbar[8] CAL_evap_pressure_drop_max_X_vacuum;
char DAT_003f8255;
char DAT_003f91ba;
char DAT_003f91c0;
char DAT_003f91bc;
short DAT_003f9198;
short DAT_003f9a98;
byte DAT_003f91bb;
int DAT_003fd94c;
int DAT_003f91a8;
u16_factor_1/2000 CAL_stft_limit;
uint32_t vacuum_smooth_x;
u8_factor_1/256 CAL_evap_vacuum_reactivity;
undefined2 DAT_002f8024;
undefined2 DAT_002f8026;
undefined1 DAT_002f82ff;
undefined2 DAT_002f830e;
undefined2 DAT_002f8310;
undefined1 DAT_002f8312;
undefined2 DAT_002f8314;
undefined1 DAT_002f8316;
undefined1 DAT_002f8317;
undefined1 DAT_002f8318;
undefined2 DAT_002f831a;
undefined2 DAT_002f831c;
undefined1 DAT_002f831e;
undefined1 DAT_002f831f;
undefined2 DAT_002f8320;
undefined1 DAT_002f82c3;
undefined1 DAT_002f8322;
undefined4 DAT_002f833c;
undefined2 DAT_002f8342;
undefined4 DAT_002f8344;
undefined2 DAT_002f834e;
undefined2 DAT_002f8350;
undefined2 DAT_002f8352;
undefined2 DAT_002f8356;
undefined2 DAT_002f8354;
undefined1 DAT_002f835a;
undefined2 DAT_002f8358;
undefined1 DAT_002f8366;
undefined1 DAT_002f8365;
undefined1 DAT_002f8364;
undefined2 DAT_002f8362;
undefined2 DAT_002f822e;
undefined2 DAT_002f8230;
undefined2 DAT_002f8232;
undefined2 DAT_002f8234;
undefined1 DAT_003fc9e6;
undefined1 DAT_002f82c2;
undefined2 DAT_002f835c;
undefined2 DAT_002f8206;
undefined2 DAT_002f821a;
undefined2 DAT_002f8236;
undefined2 DAT_002f824a;
undefined2 DAT_002f825e;
undefined2 DAT_002f8272;
undefined2 DAT_002f8286;
undefined2 DAT_002f829a;
undefined2 DAT_002f82ae;
undefined1 DAT_002f82cf;
undefined1 DAT_002f82df;
undefined1 DAT_002f82ef;
undefined1 DAT_003fd426;
u8_speed_kph LEA_obd_freeze2_car_speed;
u16_voltage_5/1023v LEA_obd_freeze2_sensor_adc_post_o2;
u16_voltage_5/1023v LEA_obd_freeze2_sensor_adc_pre_o2;
u32_time_5ms LEA_obd_freeze2_engine_runtime;
u8_factor_1/255 LEA_obd_freeze2_tps;
u8_temp_5/8-40c LEA_obd_freeze2_coolant;
u8_temp_5/8-40c LEA_obd_freeze2_coolant_stop;
u8_temp_5/8-40c LEA_obd_freeze2_engine_air;
i16_factor_1/2000 LEA_obd_freeze2_ltft;
i16_factor_1/2000 LEA_obd_freeze2_stft;
u16_flow_10mg/s LEA_obd_freeze2_maf_flow;
u16_rspeed_1/4rpm LEA_obd_freeze2_engine_speed;
uint16_t LEA_obd_freeze2_dtc;
uint16_t LEA_obd_freeze_dtc;
uint8_t LEA_obd_freeze_fuel_system_status;
u16_rspeed_1/4rpm LEA_obd_freeze_engine_speed;
u8_factor_1/255 LEA_obd_freeze_load;
u8_speed_kph LEA_obd_freeze_car_speed;
u16_flow_10mg/s LEA_obd_freeze_maf_flow;
u8_factor_1/255 LEA_obd_freeze_tps;
u8_factor_1/128-1 LEA_obd_freeze_stft;
u8_factor_1/128-1 LEA_obd_freeze_ltft;
u8_temp_1-40c LEA_obd_freeze_coolant;
uint8_t[2] CAL_obd_monitors;
uint8_t LEA_obd_monitors_completeness;
u16_time_5ms LEA_o2_lean2rich_avg_time;
u16_time_5ms LEA_o2_rich2lean_avg_time;
u16_factor_1/100 LEA_o2_switch_time_ratio;
uint8_t LEA_obd_P0011_engine_start_count;
uint8_t LEA_obd_P0011_warm_up_cycle_count;
uint8_t LEA_obd_P0012_engine_start_count;
uint8_t LEA_obd_P0012_warm_up_cycle_count;
uint8_t LEA_obd_P0016_engine_start_count;
uint8_t LEA_obd_P0016_warm_up_cycle_count;
uint8_t LEA_obd_P0076_engine_start_count;
uint8_t LEA_obd_P0076_warm_up_cycle_count;
uint8_t LEA_obd_P0077_engine_start_count;
uint8_t LEA_obd_P0077_warm_up_cycle_count;
u32_time_100ms[8] LEA_perf_time_at_TPS;
uint8_t LEA_obd_P0101_engine_start_count;
u32_time_100ms[8] LEA_perf_time_at_RPM;
uint8_t LEA_obd_P0101_warm_up_cycle_count;
u32_time_100ms[8] LEA_perf_time_at_KMH;
uint8_t LEA_obd_P0102_engine_start_count;
u32_time_100ms[4] LEA_perf_time_at_coolant_temp;
uint8_t LEA_obd_P0102_warm_up_cycle_count;
u16_rspeed_rpm[5] LEA_perf_max_engine_speed;
uint8_t LEA_obd_P0103_engine_start_count;
u8_temp_5/8-40c LEA_perf_max_engine_speed_5_coolant_temp;
uint8_t LEA_obd_P0103_warm_up_cycle_count;
u8_temp_5/8-40c LEA_perf_max_engine_speed_4_coolant_temp;
uint8_t LEA_obd_P0106_engine_start_count;
u8_temp_5/8-40c LEA_perf_max_engine_speed_3_coolant_temp;
uint8_t LEA_obd_P0106_warm_up_cycle_count;
u8_temp_5/8-40c LEA_perf_max_engine_speed_2_coolant_temp;
uint8_t LEA_obd_P0107_engine_start_count;
u8_temp_5/8-40c LEA_perf_max_engine_speed_1_coolant_temp;
uint8_t LEA_obd_P0107_warm_up_cycle_count;
u32_time_100ms LEA_perf_max_engine_speed_5_run_timer;
uint8_t LEA_obd_P0108_engine_start_count;
u32_time_100ms LEA_perf_max_engine_speed_4_run_timer;
uint8_t LEA_obd_P0108_warm_up_cycle_count;
u32_time_100ms LEA_perf_max_engine_speed_3_run_timer;
uint8_t LEA_obd_P0111_engine_start_count;
u32_time_100ms LEA_perf_max_engine_speed_2_run_timer;
uint8_t LEA_obd_P0111_warm_up_cycle_count;
u32_time_100ms LEA_perf_max_engine_speed_1_run_timer;
uint8_t LEA_obd_P0112_engine_start_count;
u8_speed_kph[5] LEA_perf_max_vehicle_speed;
uint8_t LEA_obd_P0112_warm_up_cycle_count;
u8_time_100ms[2] LEA_perf_fastest_standing_start;
uint8_t LEA_obd_P0113_engine_start_count;
u8_time_100ms[2] LEA_perf_last_standing_start;
uint8_t LEA_obd_P0113_warm_up_cycle_count;
u32_time_100ms LEA_perf_engine_run_timer;
uint8_t LEA_obd_P0116_engine_start_count;
uint16_t LEA_perf_number_of_standing_starts;
uint8_t LEA_obd_P0116_warm_up_cycle_count;
uint8_t LEA_obd_P0420_flags;
uint8_t LEA_obd_P0011_flags;
uint8_t LEA_obd_P0117_engine_start_count;
uint8_t LEA_obd_P0012_flags;
uint8_t LEA_obd_P0117_warm_up_cycle_count;
uint8_t LEA_obd_P0016_flags;
uint8_t LEA_obd_P0118_engine_start_count;
uint8_t LEA_obd_P0118_warm_up_cycle_count;
uint8_t LEA_obd_P2647_flags;
uint8_t LEA_obd_P0222_engine_start_count;
uint8_t LEA_obd_P2646_flags;
uint8_t LEA_obd_P0076_flags;
uint8_t LEA_obd_P0222_warm_up_cycle_count;
uint8_t LEA_obd_P0223_engine_start_count;
uint8_t LEA_obd_P0223_warm_up_cycle_count;
uint8_t LEA_obd_P0646_flags;
uint8_t LEA_obd_P0128_engine_start_count;
uint8_t LEA_obd_P0647_flags;
uint8_t LEA_obd_P0128_warm_up_cycle_count;
uint8_t LEA_obd_P0131_engine_start_count;
uint8_t LEA_obd_P0131_warm_up_cycle_count;
uint8_t LEA_obd_P0447_flags;
uint8_t LEA_obd_P0132_engine_start_count;
uint8_t LEA_obd_P0448_flags;
uint8_t LEA_obd_P0132_warm_up_cycle_count;
uint8_t LEA_obd_P0201_flags;
uint8_t LEA_obd_P0133_engine_start_count;
uint8_t LEA_obd_P0202_flags;
uint8_t LEA_obd_P0133_warm_up_cycle_count;
uint8_t LEA_obd_P0203_flags;
uint8_t LEA_obd_P0134_engine_start_count;
uint8_t LEA_obd_P0204_flags;
uint8_t LEA_obd_P0134_warm_up_cycle_count;
uint8_t LEA_obd_P0205_flags;
uint8_t LEA_obd_P0135_engine_start_count;
uint8_t LEA_obd_P0351_flags;
uint8_t LEA_obd_P0135_warm_up_cycle_count;
uint8_t LEA_obd_P0352_flags;
uint8_t LEA_obd_P0137_engine_start_count;
uint8_t LEA_obd_P0353_flags;
uint8_t LEA_obd_P0137_warm_up_cycle_count;
uint8_t LEA_obd_P0354_flags;
uint8_t LEA_obd_P0138_engine_start_count;
uint8_t LEA_obd_P0627_flags;
uint8_t LEA_obd_P0138_warm_up_cycle_count;
uint8_t LEA_obd_P0480_flags;
uint8_t LEA_obd_P0139_engine_start_count;
uint8_t LEA_obd_P0481_flags;
uint8_t LEA_obd_P0135_flags;
uint8_t LEA_obd_P0139_warm_up_cycle_count;
uint8_t LEA_obd_P0140_engine_start_count;
uint8_t LEA_obd_P0141_flags;
uint8_t LEA_obd_P0140_warm_up_cycle_count;
uint8_t LEA_obd_P2602_flags;
uint8_t LEA_obd_P0141_engine_start_count;
uint8_t LEA_obd_P2603_flags;
uint8_t LEA_obd_P0141_warm_up_cycle_count;
uint8_t LEA_obd_P2648_flags;
uint8_t LEA_obd_P0171_engine_start_count;
uint8_t LEA_obd_P0171_warm_up_cycle_count;
uint8_t LEA_obd_P0455_flags;
uint8_t LEA_obd_P0172_engine_start_count;
uint8_t LEA_obd_P0172_warm_up_cycle_count;
uint8_t LEA_obd_P0446_flags;
uint8_t LEA_obd_P0201_engine_start_count;
uint8_t LEA_obd_P0500_flags;
uint8_t LEA_obd_P0201_warm_up_cycle_count;
uint8_t LEA_obd_P0335_flags;
uint8_t LEA_obd_P0202_engine_start_count;
uint8_t LEA_obd_P0340_flags;
uint8_t LEA_obd_P0171_flags;
uint8_t LEA_obd_P0202_warm_up_cycle_count;
uint8_t LEA_obd_P0172_flags;
uint8_t LEA_obd_P0203_engine_start_count;
uint8_t LEA_obd_P0203_warm_up_cycle_count;
uint8_t LEA_obd_P0506_flags;
uint8_t LEA_obd_P0204_engine_start_count;
uint8_t LEA_obd_P0507_flags;
uint8_t LEA_obd_P0204_warm_up_cycle_count;
uint8_t LEA_obd_P0442_flags;
uint8_t LEA_obd_P0205_engine_start_count;
uint8_t LEA_obd_P0456_flags;
uint8_t LEA_obd_P0205_warm_up_cycle_count;
uint8_t LEA_obd_P0601_flags;
uint8_t LEA_obd_P0237_engine_start_count;
uint8_t LEA_obd_P0606_flags;
uint8_t LEA_obd_P0237_warm_up_cycle_count;
uint8_t LEA_obd_P1302_flags;
uint8_t LEA_obd_P0238_engine_start_count;
uint8_t LEA_obd_P1301_flags;
uint8_t LEA_obd_P0238_warm_up_cycle_count;
uint8_t LEA_obd_P0301_flags;
uint8_t LEA_obd_P0300_engine_start_count;
uint8_t LEA_obd_P0302_flags;
uint8_t LEA_obd_P0300_warm_up_cycle_count;
uint8_t LEA_obd_P0303_flags;
uint8_t LEA_obd_P0301_engine_start_count;
uint8_t LEA_obd_P0304_flags;
uint8_t LEA_obd_P0300_flags;
uint8_t LEA_obd_P0301_warm_up_cycle_count;
uint8_t LEA_obd_P0134_flags;
uint8_t LEA_obd_P0302_engine_start_count;
uint8_t LEA_obd_P0140_flags;
uint8_t LEA_obd_P0302_warm_up_cycle_count;
uint8_t LEA_obd_P0133_flags;
uint8_t LEA_obd_P0303_engine_start_count;
uint8_t LEA_obd_P0139_flags;
uint8_t LEA_obd_P0303_warm_up_cycle_count;
uint8_t LEA_obd_P0101_flags;
uint8_t LEA_obd_P0304_engine_start_count;
uint8_t LEA_obd_P0102_flags;
uint8_t LEA_obd_P0304_warm_up_cycle_count;
uint8_t LEA_obd_P0103_flags;
uint8_t LEA_obd_P0327_engine_start_count;
uint8_t LEA_obd_P0106_flags;
uint8_t LEA_obd_P0327_warm_up_cycle_count;
uint8_t LEA_obd_P0107_flags;
uint8_t LEA_obd_P0328_engine_start_count;
uint8_t LEA_obd_P0108_flags;
uint8_t LEA_obd_P0328_warm_up_cycle_count;
uint8_t LEA_obd_P0131_flags;
uint8_t LEA_obd_P0335_engine_start_count;
uint8_t LEA_obd_P0132_flags;
uint8_t LEA_obd_P0335_warm_up_cycle_count;
uint8_t LEA_obd_P0137_flags;
uint8_t LEA_obd_P0340_engine_start_count;
uint8_t LEA_obd_P0138_flags;
uint8_t LEA_obd_P0340_warm_up_cycle_count;
uint8_t LEA_obd_P0111_flags;
uint8_t LEA_obd_P0351_engine_start_count;
uint8_t LEA_obd_P0112_flags;
uint8_t LEA_obd_P0351_warm_up_cycle_count;
uint8_t LEA_obd_P0113_flags;
uint8_t LEA_obd_P0352_engine_start_count;
uint8_t LEA_obd_P0116_flags;
uint8_t LEA_obd_P0352_warm_up_cycle_count;
uint8_t LEA_obd_P0117_flags;
uint8_t LEA_obd_P0353_engine_start_count;
uint8_t LEA_obd_P0118_flags;
uint8_t LEA_obd_P0353_warm_up_cycle_count;
uint8_t LEA_obd_P0237_flags;
uint8_t LEA_obd_P0354_engine_start_count;
uint8_t LEA_obd_P0238_flags;
uint8_t LEA_obd_P0354_warm_up_cycle_count;
uint8_t LEA_obd_P1301_engine_start_count;
uint8_t LEA_obd_P0452_flags;
uint8_t LEA_obd_P1301_warm_up_cycle_count;
uint8_t LEA_obd_P0453_flags;
uint8_t LEA_obd_P0327_flags;
uint8_t LEA_obd_P1302_engine_start_count;
uint8_t LEA_obd_P0328_flags;
uint8_t LEA_obd_P1302_warm_up_cycle_count;
uint8_t LEA_obd_P0420_engine_start_count;
uint8_t LEA_obd_P0462_flags;
uint8_t LEA_obd_P0420_warm_up_cycle_count;
uint8_t LEA_obd_P0463_flags;
uint8_t LEA_obd_P0441_engine_start_count;
uint8_t LEA_obd_P0562_flags;
uint8_t LEA_obd_P0441_warm_up_cycle_count;
uint8_t LEA_obd_P0563_flags;
uint8_t LEA_obd_P0128_flags;
uint8_t LEA_obd_P0442_engine_start_count;
char[17] CAL_ecu_generic_VIN;
uint8_t LEA_obd_P0442_warm_up_cycle_count;
uint8_t LEA_obd_P0461_flags;
uint8_t LEA_obd_P0444_engine_start_count;
uint8_t LEA_obd_P0451_flags;
uint8_t LEA_obd_P0444_warm_up_cycle_count;
uint8_t LEA_obd_P2138_flags;
uint8_t LEA_obd_P0445_engine_start_count;
uint8_t LEA_obd_P2122_flags;
uint8_t LEA_obd_P0445_warm_up_cycle_count;
uint8_t LEA_obd_P2123_flags;
uint8_t LEA_obd_P0446_engine_start_count;
uint8_t LEA_obd_P2127_flags;
uint8_t LEA_obd_P0446_warm_up_cycle_count;
uint8_t LEA_obd_P2128_flags;
uint8_t LEA_obd_P0447_engine_start_count;
uint8_t LEA_obd_P2135_flags;
uint8_t LEA_obd_P0122_flags;
uint8_t LEA_obd_P0447_warm_up_cycle_count;
uint8_t LEA_obd_P0123_flags;
uint8_t LEA_obd_P0448_engine_start_count;
uint8_t LEA_obd_P0222_flags;
uint8_t LEA_obd_P0448_warm_up_cycle_count;
uint8_t LEA_obd_P0223_flags;
uint8_t LEA_obd_P0451_engine_start_count;
uint8_t LEA_obd_P0451_warm_up_cycle_count;
uint8_t LEA_obd_P0638_flags;
uint8_t LEA_obd_P0452_engine_start_count;
uint8_t LEA_obd_P2173_flags;
uint8_t LEA_obd_P0452_warm_up_cycle_count;
uint8_t LEA_obd_P2104_flags;
uint8_t LEA_obd_P0453_engine_start_count;
uint8_t LEA_obd_P2105_flags;
uint8_t LEA_obd_P0453_warm_up_cycle_count;
uint8_t LEA_obd_P2107_flags;
uint8_t LEA_obd_P0455_engine_start_count;
uint8_t LEA_obd_P2106_flags;
uint8_t LEA_obd_P0455_warm_up_cycle_count;
uint8_t LEA_obd_P2100_flags;
uint8_t LEA_obd_P0456_engine_start_count;
uint8_t LEA_obd_P2102_flags;
uint8_t LEA_obd_P0456_warm_up_cycle_count;
uint8_t LEA_obd_P2103_flags;
uint8_t LEA_obd_P0461_engine_start_count;
uint8_t LEA_obd_P2108_flags;
uint8_t LEA_obd_P0461_warm_up_cycle_count;
uint8_t LEA_obd_P0630_flags;
uint8_t LEA_obd_P0462_engine_start_count;
uint8_t LEA_obd_P0462_warm_up_cycle_count;
uint8_t LEA_obd_P0463_engine_start_count;
uint8_t LEA_obd_P0463_warm_up_cycle_count;
uint8_t LEA_obd_P0480_engine_start_count;
uint8_t LEA_obd_P0480_warm_up_cycle_count;
uint8_t LEA_obd_P0481_engine_start_count;
uint8_t LEA_obd_P0481_warm_up_cycle_count;
uint8_t LEA_obd_P0500_engine_start_count;
uint8_t LEA_obd_P0500_warm_up_cycle_count;
uint8_t LEA_obd_P0506_engine_start_count;
uint8_t LEA_obd_P0506_warm_up_cycle_count;
uint8_t LEA_obd_P0507_engine_start_count;
uint8_t LEA_obd_P0507_warm_up_cycle_count;
uint8_t LEA_obd_P0562_engine_start_count;
uint8_t LEA_obd_P0562_warm_up_cycle_count;
uint8_t LEA_obd_P0563_engine_start_count;
uint8_t LEA_obd_P0563_warm_up_cycle_count;
uint8_t LEA_obd_P0601_engine_start_count;
uint8_t LEA_obd_P0601_warm_up_cycle_count;
uint8_t LEA_obd_P0606_engine_start_count;
uint8_t LEA_obd_P0606_warm_up_cycle_count;
uint8_t LEA_obd_P0627_engine_start_count;
uint8_t LEA_obd_P0627_warm_up_cycle_count;
uint8_t LEA_obd_P0630_engine_start_count;
uint8_t LEA_obd_P0630_warm_up_cycle_count;
uint8_t LEA_obd_P0638_engine_start_count;
uint8_t LEA_obd_P0638_warm_up_cycle_count;
uint8_t LEA_obd_P0647_engine_start_count;
uint8_t LEA_obd_P0647_warm_up_cycle_count;
uint8_t LEA_obd_P0646_engine_start_count;
uint8_t LEA_obd_P0646_warm_up_cycle_count;
uint8_t LEA_obd_P2122_engine_start_count;
uint8_t LEA_obd_P2122_warm_up_cycle_count;
uint8_t LEA_obd_P2123_engine_start_count;
uint8_t LEA_obd_P2123_warm_up_cycle_count;
uint8_t LEA_obd_P2127_engine_start_count;
uint8_t LEA_obd_P2127_warm_up_cycle_count;
uint8_t LEA_obd_P2128_engine_start_count;
uint8_t LEA_obd_P2128_warm_up_cycle_count;
uint8_t LEA_obd_P2135_engine_start_count;
uint8_t LEA_obd_P2135_warm_up_cycle_count;
uint8_t LEA_obd_P2138_engine_start_count;
uint8_t LEA_obd_P2138_warm_up_cycle_count;
uint8_t LEA_obd_P2173_engine_start_count;
uint8_t LEA_obd_P2173_warm_up_cycle_count;
uint8_t LEA_obd_P2602_engine_start_count;
uint8_t LEA_obd_P2602_warm_up_cycle_count;
uint8_t LEA_obd_P2603_engine_start_count;
uint8_t LEA_obd_P2603_warm_up_cycle_count;
uint8_t LEA_obd_P2646_engine_start_count;
uint8_t LEA_obd_P2646_warm_up_cycle_count;
uint8_t LEA_obd_P2647_engine_start_count;
uint8_t LEA_obd_P2647_warm_up_cycle_count;
uint8_t LEA_obd_P2648_engine_start_count;
uint8_t LEA_obd_P2648_warm_up_cycle_count;
uint8_t LEA_obd_P2649_engine_start_count;
uint8_t LEA_obd_P2649_warm_up_cycle_count;
uint8_t LEA_obd_P2104_engine_start_count;
uint8_t LEA_obd_P2104_warm_up_cycle_count;
uint8_t LEA_obd_P2105_engine_start_count;
uint8_t LEA_obd_P2105_warm_up_cycle_count;
uint8_t LEA_obd_P2106_engine_start_count;
uint8_t LEA_obd_P2106_warm_up_cycle_count;
uint8_t LEA_obd_P2107_engine_start_count;
uint8_t LEA_obd_P2107_warm_up_cycle_count;
uint8_t LEA_obd_P2100_engine_start_count;
uint8_t LEA_obd_P2100_warm_up_cycle_count;
uint8_t LEA_obd_P2102_engine_start_count;
uint8_t LEA_obd_P2102_warm_up_cycle_count;
uint8_t LEA_obd_P2103_engine_start_count;
uint8_t LEA_obd_P2103_warm_up_cycle_count;
uint8_t LEA_obd_P2108_engine_start_count;
uint8_t LEA_obd_P2108_warm_up_cycle_count;
uint16_t[6] LEA_obd_iumpr_fail_count;
uint16_t[6] LEA_obd_iumpr_pass_count;
i16_pressure_1/10mbar LEA_evap_leak_result;
u16_voltage_5/1023v LEA_sensor_tps_1_offset;
u16_voltage_5/1023v LEA_sensor_tps_2_offset;
u16_voltage_5/1023v CAL_sensor_tps_1_offset;
u16_voltage_5/1023v CAL_sensor_tps_2_offset;
u16_factor_1/65536[4] LEA_knock_retard2;
i16_time_us[4][16] misfire_stroke_time_baseline;
uint16_t LEA_obd_iumpr_ignition_count;
uint16_t LEA_obd_iumpr_obdcond_count;
u8_factor_1/256-1/2 LEA_ltft_zone2_adj;
u8_factor_1/256-1/2 LEA_ltft_zone3_adj;
uint16_t LEA_ecu_engine_speed_byte_offset;
uint DAT_002f8568;
undefined1 DAT_003fd9b2;
undefined DAT_003f96e1;
char[32] CAL_ecu_model_name;
undefined2 dev_reset_lea_magic;
ushort DAT_003fd988;
u8_time_5ms DAT_003f8258;
i16_factor_1/2000 DAT_003f91da;
undefined2 DAT_003fd98a;
char DAT_003fdd42;
char DAT_003fdd43;
char DAT_003fdcee;
u8_time_5ms CAL_stft_time_between_step;
char DAT_003fd9fb;
u16_voltage_5/1023v CAL_stft_o2_test_min;
char DAT_003fd9f2;
u16_voltage_5/1023v CAL_stft_o2_test_max;
char DAT_003fd9f3;
u16_time_5ms CAL_stft_o2_test_runtime_min;
char DAT_003fd9f4;
u8_time_5ms CAL_stft_idle_time_between_step;
char DAT_003fd9f5;
u8_time_25ms[8] CAL_stft_time_use_adj;
char DAT_003f91d6;
u8_rspeed_125/4+500rpm[8] CAL_stft_time_use_adj_X_engine_speed;
undefined1 DAT_003fd98c;
ushort DAT_003fdcfa;
u16_time_5ms stft_time_use_adj;
u16_time_5ms stft_time_use_adj_timer;
u16_voltage_5/1023v CAL_stft_stoich_max;
u16_voltage_5/1023v CAL_stft_stoich_min;
undefined2 stft_lean_threshold;
undefined2 stft_rich_threshold;
u8_time_s[17] CAL_stft_runtime_min;
u8_temp_5/8-40c CAL_stft_engine_air_min;
undefined2 stft_enleanment_initial;
undefined2 stft_enrichment_initial;
u8_factor_1/2000[64] CAL_stft_enrichment_initial;
u8_factor_1/2000[64] CAL_stft_enleanment_initial;
u8_rspeed_125/4+500rpm[8] CAL_stft_enrichment_initial_X_engine_speed;
u8_load_4mg/stroke[8] CAL_stft_enrichment_initial_Y_engine_load;
u8_rspeed_125/4+500rpm[8] CAL_stft_enleanment_initial_X_engine_speed;
u8_load_4mg/stroke[8] CAL_stft_enleanment_initial_Y_engine_load;
u8_rspeed_125/4+500rpm[8] CAL_stft_enrichment_step_X_engine_speed;
u8_load_4mg/stroke[8] CAL_stft_enrichment_step_Y_engine_load;
u8_factor_1/2000[64] CAL_stft_enrichment_step;
u8_rspeed_125/4+500rpm[8] CAL_stft_enleanment_step_X_engine_speed;
u8_load_4mg/stroke[8] CAL_stft_enleanment_step_Y_engine_load;
u8_factor_1/2000[64] CAL_stft_enleanment_step;
undefined2 stft_enleanment_step;
undefined2 stft_enrichment_step;
u16_factor_1/2000 CAL_stft_idle_enrichment_step;
u16_factor_1/2000 CAL_stft_idle_enleanment_step;
u16_factor_1/2000 CAL_stft_idle_enrichment_initial;
u16_factor_1/2000 CAL_stft_idle_enleanment_initial;
byte DAT_003f8258;
ushort DAT_003f91c8;
short DAT_003fd98a;
u8_rspeed_125/4+500rpm CAL_stft_lean_rpm_min;
u8_factor_1/64 CAL_stft_enleanment_step_adj;
u8_factor_1/64 CAL_stft_enrichment_step_adj;
char DAT_003f9941;
undefined1 DAT_003f91d5;
u16_flow_10mg/s CAL_ltft_zone3_flow_min;
u8_time_5s DAT_003f91d4;
u16_rspeed_rpm CAL_ltft_zone1_engine_speed_max;
short DAT_003fd97c;
short DAT_003fd97e;
u8_factor_1/156-14/156 fuel_level_smooth;
u8_factor_1/156-14/156 CAL_ltft_fuel_min;
u8_temp_5/8-40c CAL_ltft_engine_air_min;
i16_pressure_mbar CAL_ltft_atmo_min;
u8_temp_5/8-40c CAL_ltft_coolant_min;
uint32_t inj_time_stft_smooth_x;
u8_time_us CAL_ltft_zone1_step;
u8_factor_1/256 CAL_stft_smooth_reactivity;
u16_factor_1/2000-2048/125 CAL_ltft_stft_smooth_max;
u16_factor_1/2000-2048/125 CAL_ltft_stft_smooth_min;
u8_factor_1/256-1/2 CAL_ltft_zone3_limit_h;
u8_factor_1/256-1/2 CAL_ltft_zone3_limit_l;
u8_factor_1/256-1/2 CAL_ltft_zone2_limit_l;
u8_factor_1/256-1/2 CAL_ltft_zone2_limit_h;
u16_flow_10mg/s CAL_ltft_zone2_flow_min;
u16_load_mg/stroke CAL_ltft_zone2_load_min;
u16_load_mg/stroke CAL_ltft_zone2_load_max;
u16_load_mg/stroke CAL_ltft_zone3_load_min;
u8_time_5s CAL_ltft_time_between_step;
u8_time_10us CAL_ltft_zone1_limit_h;
u8_time_-10us CAL_ltft_zone1_limit_l;
u16_flow_10mg/s CAL_ltft_zone2_flow_max;
u16_flow_10mg/s CAL_ltft_zone1_flow_max;
u8_rspeed_125/4+500rpm[16] CAL_knock_window_width_X_engine_speed;
u8_load_4mg/stroke[16] CAL_knock_window_width_Y_engine_load;
u8_angle_10/128+2deg knock_window_start;
u8_angle_10/128deg knock_window_width;
u8_angle_10/128+2deg[256] CAL_knock_window_start;
u8_angle_10/128deg[256] CAL_knock_window_width;
u8_rspeed_125/4+500rpm[16] CAL_knock_window_start_X_engine_speed;
u8_load_4mg/stroke[16] CAL_knock_window_start_Y_engine_load;
u8_time_5ms DAT_003f91e8;
uint8_t[256] CAL_knock_sensitivity_cylinder1;
u8_rspeed_125/4+500rpm[16] CAL_knock_sensitivity_cylinder2_X_engine_speed;
u8_rspeed_125/4+500rpm[16] CAL_knock_sensitivity_cylinder3_X_engine_speed;
u8_rspeed_125/4+500rpm[16] CAL_knock_sensitivity_cylinder4_X_engine_speed;
u8_load_4mg/stroke[16] CAL_knock_sensitivity_cylinder4_Y_engine_load;
u8_load_4mg/stroke[16] CAL_knock_sensitivity_cylinder3_Y_engine_load;
u8_load_4mg/stroke[16] CAL_knock_sensitivity_cylinder2_Y_engine_load;
u8_load_4mg/stroke[16] CAL_knock_sensitivity_cylinder1_Y_engine_load;
u8_rspeed_125/4+500rpm[16] CAL_knock_sensitivity_cylinder1_X_engine_speed;
u8_angle_1/4deg CAL_knock_retard1_limit;
uint8_t[256] CAL_knock_sensitivity_cylinder2;
u8_temp_5/8-40c CAL_knock_retard1_coolant_min;
uint8_t[256] CAL_knock_sensitivity_cylinder3;
u8_load_4mg/stroke[8] CAL_knock_retard2_corr_load_min;
uint8_t[256] CAL_knock_sensitivity_cylinder4;
u8_rspeed_125/4+500rpm[8] CAL_knock_retard2_corr_load_min_X_engine_speed;
u8_load_4mg/stroke CAL_knock_load_margin;
u8_rspeed_125/4+500rpm[8] CAL_knock_retard_load_min_X_engine_speed;
u8_load_4mg/stroke[8] CAL_knock_retard_load_min;
u8_time_5ms CAL_knock_retard1_dt_tps_target_2_time;
u16_factor_1/1023 CAL_knock_retard1_dt_tps_target_2_max;
uint8_t knock_flags;
u8_angle_1/4deg[8] CAL_knock_retard1_inc;
uint8_t[8] CAL_knock_retard1_inc_X_peak_over_threshold;
uint8_t knock_peak_threshold;
uint8_t[64] CAL_knock_peak_threshold;
u8_rspeed_125/4+500rpm[8] CAL_knock_peak_threshold_X_engine_speed;
u8_angle_1/4deg CAL_knock_retard1_vvt_diff_max;
u8_load_4mg/stroke[8] CAL_knock_peak_threshold_Y_engine_load;
u8_rspeed_125/4+500rpm CAL_knock_retard1_engine_speed_max;
u8_rspeed_125/4+500rpm CAL_knock_retard1_engine_speed_min;
u8_rspeed_125/4rpm CAL_knock_speed_margin;
undefined2 knock_ign_diff;
undefined2 knock_cyl_worst;
uint8_t[4] knock_sensitivity_threshold;
uint8_t[4] knock_peak_over_threshold;
ushort DAT_003f91e2;
uint8_t CAL_knock_signal_fadeout_step;
short DAT_003f91e4;
uint16_t[4] knock_signal;
uint16_t[4] uint16_t_ARRAY_003f82b4;
uint32_t[4] knock_signal_smooth;
uint8_t[4] uint8_t_ARRAY_003f82bc;
uint16_t[4] knock_signal_smooth_low;
uint8_t[4] knock_first_read;
uint16_t[4] knock_peak;
u8_x256 CAL_knock_signal_smooth_limit_l;
undefined1 knock_detected;
u8_factor_1/256 CAL_knock_signal_reactivity;
uint8_t CAL_knock_retard2_corr_dec_step;
uint8_t CAL_knock_retard2_corr_inc_coef;
byte DAT_003f82a2;
byte DAT_003f82a3;
undefined DAT_0007afbc;
undefined DAT_003f827d;
undefined DAT_003f8281;
undefined DAT_003f82c4;
byte DAT_003f82cd;
char DAT_003f91e8;
char DAT_003f9952;
short DAT_003f91f6;
char DAT_003fd9b8;
byte DAT_003fc4d0;
byte DAT_003fc4d1;
undefined1 DAT_003f91f0;
short DAT_002f830e;
byte DAT_003f91f8;
byte DAT_003f91f9;
uint16_t DAT_003fd9b4;
byte DAT_003f91fa;
uint16_t DAT_003fd9b6;
uint DAT_003fd9bc;
uint16_t[128] obd_trouble_list;
uint16_t[128] obd_pending_list;
bool engine_has_started;
u8_factor_1/128-1 obd_stft;
u8_factor_1/128-1 obd_ltft;
u8_temp_1-40c obd_temp;
ushort DAT_002f8310;
ushort DAT_003fc4d6;
char DAT_003f91f0;
char DAT_002f8316;
undefined1 DAT_003fd998;
short DAT_003fc4d8;
byte DAT_003f9200;
uint DAT_003f91fc;
char DAT_003f91f2;
ushort DAT_002f830e;
u8_factor_1/255 DAT_002f8312;
u16_flow_10mg/s DAT_002f8314;
u16_rspeed_1/4rpm DAT_002f8310;
u16_voltage_5/1023v sensor_adc_tps_1;
undefined1 DAT_003f91f1;
byte DAT_002f82c3;
byte DAT_002f8317;
byte DAT_003fc4d3;
byte DAT_003f91f2;
byte DAT_003fc4d2;
char DAT_002f8322;
undefined1 DAT_003f91f5;
char DAT_003f91f1;
char DAT_003fd998;
undefined4 DAT_003fd9bc;
char DAT_003f91f5;
uint8_t CAL_obd_warm_up_cycles_clear_freeze_frame;
char DAT_003fd9b2;
byte DAT_003f9209;
ushort DAT_003fd9d0;
byte DAT_003fc500;
byte DAT_003fc501;
ushort DAT_003fc4fe;
byte DAT_003fc50b;
byte DAT_003fc50a;
ushort DAT_003fc502;
ushort DAT_003fc504;
short DAT_003f9210;
short DAT_003f9212;
ushort DAT_003fd9ce;
short DAT_003fc524;
short DAT_003fc522;
int DAT_003fd9d4;
short DAT_003fc528;
short DAT_003fc526;
byte DAT_002f82ff;
ushort DAT_003f920a;
ushort DAT_003f920c;
ushort DAT_002f8352;
ushort DAT_003fc52a;
byte DAT_003f9208;
byte DAT_003fca0f;
undefined1 DAT_002f82d7;
u8_obd_config CAL_obd_P0420;
undefined1 DAT_002f82e7;
undefined DAT_003fd416;
uint16_t cat_diag_pre_o2_sw;
undefined DAT_003fd41e;
uint16_t cat_diag_pre_o2_max_sw;
byte DAT_003fc506;
char DAT_003f920e;
char DAT_003fc507;
byte DAT_003f99aa;
short DAT_003f99ac;
undefined1 DAT_003fca0f;
undefined1 DAT_003f9208;
char DAT_003fdd14;
char DAT_003fdd40;
char DAT_003fdd41;
byte DAT_003fc554;
ushort DAT_003fc556;
short DAT_003fc52c;
byte DAT_003f921a;
byte DAT_003fc555;
byte DAT_003fd9d8;
byte DAT_003fca18;
byte DAT_003f921b;
byte DAT_003fd9dd;
byte DAT_003fca19;
byte DAT_003fd9de;
byte DAT_003fca45;
char DAT_003fd9e4;
char DAT_003fd9f1;
char DAT_003fdc3b;
u8_obd_config CAL_obd_P0011;
u8_obd_config CAL_obd_P0012;
u8_obd_config CAL_obd_P0016;
char DAT_003fc4ea;
char DAT_003f9218;
char DAT_003f9219;
byte DAT_003fd9e0;
byte DAT_003fca1d;
byte DAT_003fd9df;
byte DAT_003fca1c;
u8_obd_config CAL_obd_P2647;
u8_obd_config CAL_obd_P2646;
undefined1 DAT_003fca18;
undefined1 DAT_003fd9d8;
undefined1 DAT_003fca19;
undefined1 DAT_003fd9dd;
undefined1 DAT_003fca45;
undefined1 DAT_003fd9de;
undefined1 DAT_003fca1c;
undefined1 DAT_003fd9df;
undefined1 DAT_003fca1d;
undefined1 DAT_003fd9e0;
ushort DAT_003fdc20;
short DAT_003f9220;
short DAT_003fdd44;
byte DAT_003fd9e4;
byte DAT_003fc9e9;
short DAT_003f9222;
byte DAT_003fd9f1;
uint8_t hc08_obd_flags;
byte DAT_003fc9ea;
ushort DAT_003fdc10;
short DAT_003f922a;
byte DAT_003f9228;
byte DAT_003fc9f5;
short DAT_003f9226;
uint8_t CAL_obd_P0135_confirm_threshold;
byte DAT_003f9224;
uint8_t CAL_obd_P0141_confirm_threshold;
byte DAT_003fc9f6;
ushort DAT_003fdc22;
short DAT_003f922e;
byte DAT_003f922c;
byte DAT_003fc9f7;
short DAT_003f9232;
byte DAT_003f9230;
byte DAT_003fc9f8;
short DAT_003f9258;
byte DAT_003f9256;
byte DAT_003fc9f9;
short DAT_003f925c;
byte DAT_003f925a;
byte DAT_003fc9fa;
ushort DAT_003fdc1c;
short DAT_003f9234;
byte DAT_003fd9f2;
byte DAT_003fc9fd;
u8_obd_config CAL_obd_P0076;
short DAT_003f9236;
u8_obd_config CAL_obd_P0077;
byte DAT_003fd9f3;
u8_obd_config CAL_obd_P0646;
byte DAT_003fc9fe;
u8_obd_config CAL_obd_P0647;
short DAT_003f9238;
u8_obd_config CAL_obd_P0444;
byte DAT_003fd9f4;
u8_obd_config CAL_obd_P0445;
byte DAT_003fc9ff;
u8_obd_config CAL_obd_P0447;
short DAT_003f923a;
u8_obd_config CAL_obd_P0448;
byte DAT_003fd9f5;
u8_obd_config CAL_obd_P0201;
byte DAT_003fca00;
u8_obd_config CAL_obd_P0202;
short DAT_003f923c;
u8_obd_config CAL_obd_P0203;
byte DAT_003fd9f6;
u8_obd_config CAL_obd_P0204;
byte DAT_003fca01;
u8_obd_config CAL_obd_P0205;
short DAT_003f923e;
u8_obd_config CAL_obd_P0351;
byte DAT_003fd9f7;
u8_obd_config CAL_obd_P0352;
u8_obd_config CAL_obd_P0353;
short DAT_003f9240;
u8_obd_config CAL_obd_P0354;
byte DAT_003fd9f8;
u8_obd_config CAL_obd_P0627;
u8_obd_config CAL_obd_P0480;
short DAT_003f9242;
u8_obd_config CAL_obd_P0481;
byte DAT_003fd9f9;
u8_obd_config CAL_obd_P0135;
u8_obd_config CAL_obd_P0141;
short DAT_003f9244;
u8_obd_config CAL_obd_P2602;
byte DAT_003fd9fa;
u8_obd_config CAL_obd_P2603;
u8_obd_config CAL_obd_P2648;
short DAT_003f9248;
u8_obd_config CAL_obd_P2649;
byte DAT_003f9246;
byte DAT_003fca07;
short DAT_003f924c;
byte DAT_003f924a;
byte DAT_003fca09;
short DAT_003f9250;
byte DAT_003f924e;
byte DAT_003fca0a;
short DAT_003f9252;
ushort DAT_003fdc24;
byte DAT_003fd9fb;
short DAT_003f9254;
byte DAT_003fd9fc;
short DAT_003f9260;
byte DAT_003f925e;
byte DAT_003fca16;
short DAT_003f9264;
byte DAT_003f9262;
byte DAT_003fca17;
short DAT_003f9268;
byte DAT_003f9266;
byte DAT_003fca24;
short DAT_003f926c;
byte DAT_003f926a;
byte DAT_003fca25;
char DAT_003fd9d8;
char DAT_003fd9dd;
char DAT_003fd9e0;
char DAT_003fd9df;
undefined UNK_00002ee0;
u16_current_mA CAL_obd_P0135_P0141_threshold;
undefined1 DAT_003fc9e9;
undefined1 DAT_003fd9e4;
undefined1 DAT_003fc9ea;
undefined1 DAT_003fd9f1;
undefined1 DAT_003fc9f6;
undefined1 DAT_003f9224;
undefined1 DAT_003fc9f5;
undefined1 DAT_003f9228;
undefined1 DAT_003fc9f7;
undefined1 DAT_003f922c;
undefined1 DAT_003fc9f8;
undefined1 DAT_003f9230;
undefined1 DAT_003fc9f9;
undefined1 DAT_003f9256;
undefined1 DAT_003fc9fa;
undefined1 DAT_003f925a;
undefined1 DAT_003fc9fd;
undefined1 DAT_003fd9f2;
undefined1 DAT_003fc9fe;
undefined1 DAT_003fd9f3;
undefined1 DAT_003fc9ff;
undefined1 DAT_003fd9f4;
undefined1 DAT_003fca00;
undefined1 DAT_003fd9f5;
undefined1 DAT_003fca01;
undefined1 DAT_003fd9f6;
uint8_t DAT_003fd9fb;
uint8_t DAT_003fd9fc;
undefined1 DAT_003fca07;
undefined1 DAT_003f9246;
undefined1 DAT_003fca09;
undefined1 DAT_003f924a;
undefined1 DAT_003fca0a;
undefined1 DAT_003f924e;
undefined1 DAT_003fca16;
undefined1 DAT_003f925e;
undefined1 DAT_003fca17;
undefined1 DAT_003f9262;
undefined1 DAT_003fca24;
undefined1 DAT_003f9266;
undefined1 DAT_003fca25;
undefined1 DAT_003f926a;
undefined1 DAT_003fc9ed;
undefined1 DAT_003fd9f7;
undefined1 DAT_003fc9ee;
undefined1 DAT_003fd9f8;
undefined1 DAT_003fc9ef;
undefined1 DAT_003fd9f9;
undefined1 DAT_003fc9f0;
undefined1 DAT_003fd9fa;
byte DAT_003fdb08;
undefined1 DAT_003fdb0c;
byte REG_CANA_MB7_DATA0;
byte REG_CANA_MB7_DATA1;
byte REG_CANA_MB7_DATA2;
char DAT_003fdb0a;
char DAT_003fdb08;
char DAT_003fdb09;
char DAT_003f9270;
char DAT_003fdb0b;
byte DAT_003f9271;
byte DAT_003fdb0c;
byte DAT_003f98b7;
byte DAT_003f8192;
byte DAT_003f8191;
byte DAT_003f8190;
char DAT_003f8328;
ushort DAT_003fdc32;
char DAT_003fdc28;
byte DAT_003fdc30;
byte DAT_003fdc34;
ushort DAT_003f9a26;
byte DAT_003fdc37;
byte DAT_003fdc35;
byte DAT_003fdc36;
short DAT_003fc60c;
char DAT_003fc608;
char DAT_003f927c;
char DAT_003f927e;
char DAT_003f927d;
i16_pressure_1/10mbar evap_pressure_smooth;
short DAT_003fc604;
short DAT_003fc606;
char DAT_003fc609;
char DAT_003f927a;
byte DAT_003f927b;
undefined1 DAT_003fc60b;
char DAT_003fdc4c;
undefined1 DAT_003fc60a;
short DAT_003fdc72;
short DAT_002f8358;
byte DAT_003f9278;
byte DAT_003fca30;
char DAT_003f927f;
byte DAT_003f9279;
byte DAT_003fca40;
i16_pressure_mbar CAL_evap_leak_vacuum_min;
u8_obd_config CAL_obd_P0455;
u8_obd_config CAL_obd_P0441;
u8_obd_config CAL_obd_P0446;
undefined1 DAT_003fca30;
undefined1 DAT_003f9278;
undefined1 DAT_003fca40;
undefined1 DAT_003f9279;
byte DAT_003f9282;
byte DAT_003fc54b;
byte DAT_003fc5a6;
short DAT_003fc5d6;
short DAT_003fc544;
short DAT_003f9280;
byte DAT_003fc548;
byte DAT_003fdc3c;
byte DAT_003fca2d;
byte DAT_003f97c1;
byte DAT_003fc549;
byte DAT_003f97c0;
byte DAT_003fdc38;
byte DAT_003fca2b;
byte DAT_003fdc3b;
byte DAT_003fca2c;
u8_obd_config CAL_obd_P1280;
u8_obd_config CAL_obd_P0335;
u8_obd_config CAL_obd_P0340;
undefined1 DAT_003fca2b;
undefined1 DAT_003fdc38;
undefined1 DAT_003fca2d;
undefined1 DAT_003fdc3c;
undefined1 DAT_003fca2c;
undefined1 DAT_003fdc3b;
undefined2 DAT_003fc544;
undefined2 DAT_003f9280;
u8_obd_config CAL_obd_P0171;
short DAT_003fc52e;
u8_obd_config CAL_obd_P0172;
byte DAT_003fc535;
short DAT_003fdc46;
ushort DAT_003fd97e;
ushort DAT_003fc5ce;
byte DAT_003fc562;
ushort DAT_003fd97c;
ushort DAT_003fc5cc;
byte DAT_003fdc40;
byte DAT_003fca1a;
short DAT_003fc530;
byte DAT_003fc563;
byte DAT_003fdc44;
byte DAT_003fca1b;
undefined1 DAT_003fca1a;
undefined1 DAT_003fdc40;
undefined1 DAT_003fca1b;
undefined1 DAT_003fdc44;
ushort DAT_003fc54e;
ushort DAT_003fc54c;
u8_obd_config CAL_obd_P0506;
byte DAT_003fc551;
u8_obd_config CAL_obd_P0507;
byte DAT_003fc574;
byte DAT_003f9288;
byte DAT_003fc552;
byte DAT_003fdc48;
byte DAT_003fca2e;
byte DAT_003fc550;
byte DAT_003fc573;
byte DAT_003f9289;
byte DAT_003fdc4a;
byte DAT_003fca2f;
undefined1 DAT_003fca2e;
undefined1 DAT_003fdc48;
undefined1 DAT_003fca2f;
undefined1 DAT_003fdc4a;
uint DAT_003fdc8c;
char DAT_003fdc40;
char DAT_003fdc44;
u16_time_100ms DAT_003f9292;
u8_time_100ms DAT_003fdc84;
u8_time_100ms DAT_003fdc85;
short DAT_003fdc80;
u8_time_100ms DAT_003fdc86;
ushort DAT_003fdc7c;
short DAT_003fdc8a;
ushort DAT_003f9296;
byte DAT_003f9298;
short DAT_003f8330;
byte DAT_003f9294;
u8_time_100ms DAT_003fdc87;
u16_time_100ms DAT_003fdc88;
byte DAT_003fdc7a;
byte DAT_003fdc7b;
ushort DAT_003fdc76;
byte DAT_002f8364;
byte DAT_003f9291;
byte DAT_003fca31;
byte DAT_002f8365;
ushort DAT_002f8362;
byte DAT_003f9290;
byte DAT_003fca44;
char DAT_003fc56a;
undefined DAT_003fd476;
undefined DAT_003fd47e;
undefined DAT_003fd48e;
i16_pressure_mbar CAL_evap_leak_atmo_pressure_min;
u8_factor_1/156-14/156 CAL_evap_leak_fuel_level_min;
u8_factor_1/156-14/156 CAL_evap_leak_fuel_level_max;
u8_temp_5/8-40c CAL_evap_leak_coolant_min;
u8_temp_5/8-40c CAL_evap_leak_engine_air_max;
u8_temp_5/8-40c CAL_evap_leak_engine_air_stop_max;
u8_time_100ms CAL_evap_leak_initial_delay;
u8_time_100ms CAL_evap_leak_settle_time;
u8_time_100ms CAL_evap_leak_baseline_time;
u8_time_100ms CAL_evap_leak_purge_time;
u8_time_100ms CAL_evap_leak_P0442_time;
u16_time_100ms CAL_evap_leak_P0456_time;
i16_pressure_mbar CAL_evap_leak_gross_pressure;
uint16_t CAL_evap_leak_purge_min;
uint16_t CAL_evap_leak_purge_retry_min;
u16_time_100ms CAL_evap_leak_cooldown;
uint8_t CAL_evap_leak_force;
u8_obd_config CAL_obd_P0442;
u8_obd_config CAL_obd_P0456;
i16_pressure_1/10mbar evap_leak_result;
u8_pressure_1/10mbar[16] CAL_evap_leak_P0456_threshold;
u8_pressure_1/10mbar[16] CAL_evap_leak_P0442_threshold;
u8_factor_1/255[16] CAL_evap_leak_P0442_threshold_X_fuel_level;
u8_factor_1/255[16] CAL_evap_leak_P0456_threshold_X_fuel_level;
i16_pressure_1/10mbar evap_reference;
undefined1 obd_mode_0x08_state;
undefined1 DAT_003fca31;
undefined1 DAT_003f9291;
undefined1 DAT_003fca43;
undefined1 DAT_003fdc4c;
undefined1 DAT_003fca44;
undefined1 DAT_003f9290;
u8_obd_config CAL_obd_P0601;
u8_obd_config CAL_obd_P0606;
u8_obd_config CAL_obd_P0630;
uint8_t DAT_003f92a7;
char DAT_003f92a9;
byte DAT_003f92a8;
byte DAT_003fc5e4;
byte DAT_003fdcae;
byte DAT_003f92b2;
int DAT_003f9854;
short DAT_003fc560;
short DAT_003fc55e;
short DAT_003fc558;
short DAT_003f92b6;
byte DAT_003fc53c;
byte DAT_003fc53d;
byte DAT_003fc542;
byte DAT_003fc543;
byte DAT_003fc553;
short DAT_003fc55a;
short DAT_003f92ac;
ushort DAT_003f92b4;
char DAT_003f92a5;
char DAT_003f92a6;
short DAT_003f92aa;
char DAT_003f9913;
short DAT_003fc55c;
uint16_t misfire_cat_max_result;
char DAT_003fca1f;
uint16_t misfire_max_result;
char DAT_003fca1e;
byte DAT_003f92ae;
byte DAT_003f92b8;
byte DAT_003f92b9;
undefined DAT_003fcad0;
undefined DAT_003fcf12;
undefined DAT_003fcf1c;
undefined DAT_003fd186;
undefined DAT_003fd18e;
undefined DAT_003fd196;
pointer PTR_DAT_003fd530;
u16_time_1-32768us[256] CAL_obd_misfire_threshold;
u16_rspeed_rpm[16] CAL_obd_misfire_threshold_X_engine_speed;
u16_load_mg/stroke[16] CAL_obd_misfire_threshold_Y_engine_load;
u8_obd_config CAL_obd_P1302;
u8_obd_config CAL_obd_P1301;
u8_obd_config CAL_obd_P0301;
u8_obd_config CAL_obd_P0302;
u8_obd_config CAL_obd_P0303;
u8_obd_config CAL_obd_P0304;
u8_obd_config CAL_obd_P0768;
undefined1 DAT_003fca3c;
undefined1 DAT_003f92a0;
undefined1 DAT_003fca34;
undefined1 DAT_003f92a1;
undefined1 DAT_003fca35;
undefined1 DAT_003f92a2;
undefined1 DAT_003fca36;
undefined1 DAT_003f92a3;
undefined1 DAT_003fca37;
undefined1 DAT_003f92a4;
undefined1 DAT_003f92a5;
undefined1 DAT_003f92a6;
byte DAT_003f8338;
uint DAT_003f833c;
short DAT_003f92b0;
uint16_t o2_flags;
ushort DAT_003f92c2;
ushort DAT_003f92c4;
ushort DAT_003fc5d0;
ushort DAT_003fc5dc;
ushort DAT_003fc5da;
ushort DAT_003fc5d8;
byte DAT_003fdcee;
byte DAT_003fca21;
ushort DAT_003fc5d2;
byte DAT_003f92c0;
byte DAT_003fca26;
u8_obd_config CAL_obd_P0134;
u8_obd_config CAL_obd_P0140;
short DAT_003fdd0e;
byte DAT_003fc532;
u32_time_5ms o2_lean2rich_total_time;
byte DAT_003fc533;
uint8_t o2_lean2rich_switch_count;
ushort DAT_003fc57e;
undefined1 o2_rich2lean_switch_count;
ushort DAT_003fc580;
u32_time_5ms o2_rich2lean_total_time;
byte DAT_003fc582;
byte DAT_003fc583;
ushort DAT_003fc5d4;
byte DAT_003fc575;
char DAT_003f92c6;
int DAT_003f92c8;
u16_time_5ms CAL_obd_P0133_threshold1_lean2rich;
byte DAT_003f9a46;
u16_time_5ms CAL_obd_P0133_threshold1_rich2lean;
char DAT_003fc53a;
u8_time_5ms CAL_obd_P0133_threshold2_lean2rich;
u8_factor_1/100 CAL_obd_P0133_threshold2_ratio;
u8_time_5ms CAL_obd_P0133_threshold3_rich2lean;
ushort DAT_003f92cc;
u8_factor_1/100 CAL_obd_P0133_threshold3_ratio;
byte DAT_003fdcc8;
u16_time_5ms DAT_003fc596;
byte DAT_003fdcef;
byte DAT_002f82c2;
byte DAT_003fc9e6;
undefined2 DAT_003fc600;
undefined2 DAT_003fdd0c;
undefined2 DAT_003fc5e2;
undefined2 DAT_003fdd0a;
ushort DAT_003fc5de;
ushort DAT_003fc5e0;
u16_time_5ms cat_diag_pre_o2_timer;
uint8_t CAL_obd_P0133_consecutive;
u8_obd_config CAL_obd_P0133;
u8_obd_config CAL_obd_P0139;
ushort DAT_002f834e;
ushort DAT_002f8350;
byte DAT_003fc534;
byte DAT_003fe648;
char DAT_003f9a47;
undefined4 DAT_003f8340;
int DAT_003f8364;
short DAT_003fdd0c;
short DAT_003fc600;
short DAT_003fdd0a;
short DAT_003fc5e2;
ushort DAT_003fdcfc;
ushort DAT_003fc56e;
ushort DAT_003fdd00;
byte DAT_003fdd04;
byte DAT_003fc56b;
char DAT_003fdd11;
ushort DAT_003fdcfe;
ushort DAT_003fc570;
ushort DAT_003fdd02;
byte DAT_003fdd05;
undefined1 post_o2_state;
uint8_t DAT_003fdcc8;
undefined1 DAT_003fca21;
undefined1 DAT_003fdcee;
undefined1 DAT_003fdcef;
undefined1 DAT_003fca26;
undefined1 DAT_003f92c0;
byte DAT_003fc4e5;
ushort DAT_003fdd44;
char DAT_003fe4cc;
char DAT_003fe4dc;
char DAT_003fe4dd;
char DAT_003fe4de;
byte DAT_003fc57b;
byte DAT_003fc4eb;
ushort DAT_003fc4ee;
byte DAT_003fc4ec;
ushort DAT_003fc4f0;
short DAT_003f92d2;
byte DAT_003f92d0;
byte DAT_003fc9e7;
short DAT_003f92d6;
byte DAT_003f92d4;
byte DAT_003fc9e4;
short DAT_003f92da;
byte DAT_003f92d8;
byte DAT_003fc9e5;
byte DAT_003fc5e5;
byte DAT_003fc5e6;
byte DAT_003fc5e7;
char DAT_003fe4e1;
ushort DAT_003fc5e8;
short DAT_003fdd48;
short DAT_003f932e;
short DAT_003fc5c8;
short DAT_003fc5ca;
short DAT_003f92de;
byte DAT_003f92dc;
byte DAT_003fc9d1;
short DAT_003f92e2;
byte DAT_003f92e0;
byte DAT_003fc9d2;
short DAT_003f92e6;
byte DAT_003f92e4;
byte DAT_003fc9d3;
short DAT_003f92fa;
byte DAT_003fdd42;
byte DAT_003fc9e0;
short DAT_003f92fc;
byte DAT_003fdd43;
byte DAT_003fc9e1;
short DAT_003f9300;
byte DAT_003f92fe;
byte DAT_003fc9e2;
short DAT_003f930c;
byte DAT_003f930a;
byte DAT_003fc9e3;
ushort DAT_003fc5ec;
byte DAT_003fc5ee;
byte DAT_003fc5ef;
byte DAT_003fc5ea;
short DAT_003f92ea;
byte DAT_003f92e8;
byte DAT_003fc9d5;
short DAT_003f92ee;
byte DAT_003f92ec;
byte DAT_003fc9d6;
short DAT_003f92f2;
byte DAT_003f92f0;
byte DAT_003fc9d7;
byte DAT_003fc5eb;
short DAT_003f92f4;
byte DAT_003fdd14;
byte DAT_003fc9d9;
short DAT_003f92f6;
byte DAT_003fdd40;
byte DAT_003fc9da;
short DAT_003f92f8;
byte DAT_003fdd41;
byte DAT_003fc9db;
short DAT_003f9310;
byte DAT_003f930e;
byte DAT_003fca02;
short DAT_003f9314;
byte DAT_003f9312;
byte DAT_003fca03;
short DAT_003f9318;
byte DAT_003f9316;
byte DAT_003fc9eb;
short DAT_003f931c;
u8_obd_config CAL_obd_P0101;
byte DAT_003f931a;
u8_obd_config CAL_obd_P0102;
byte DAT_003fc9ec;
u8_obd_config CAL_obd_P0103;
ushort DAT_003fc632;
u8_obd_config CAL_obd_P0106;
short DAT_003f9304;
u8_obd_config CAL_obd_P0107;
byte DAT_003f9302;
u8_obd_config CAL_obd_P0108;
byte DAT_003fc9f1;
u8_obd_config CAL_obd_P0131;
ushort DAT_003fc630;
u8_obd_config CAL_obd_P0132;
short DAT_003f9308;
u8_obd_config CAL_obd_P0137;
byte DAT_003f9306;
u8_obd_config CAL_obd_P0138;
byte DAT_003fc9f2;
u8_obd_config CAL_obd_P0111;
short DAT_003f9320;
u8_obd_config CAL_obd_P0112;
byte DAT_003f931e;
u8_obd_config CAL_obd_P0113;
byte DAT_003fca3e;
u8_obd_config CAL_obd_P0116;
short DAT_003f9324;
u8_obd_config CAL_obd_P0117;
byte DAT_003f9322;
u8_obd_config CAL_obd_P0118;
byte DAT_003fca3f;
u8_obd_config CAL_obd_P0237;
short DAT_003f932c;
u8_obd_config CAL_obd_P0238;
byte DAT_003fc51c;
u8_obd_config CAL_obd_P0452;
byte DAT_003f932a;
u8_obd_config CAL_obd_P0453;
byte DAT_003fc9f4;
u8_obd_config CAL_obd_P0327;
short DAT_003f9328;
u8_obd_config CAL_obd_P0328;
byte DAT_003fc51d;
u8_obd_config CAL_obd_P0462;
byte DAT_003f9326;
u8_obd_config CAL_obd_P0463;
byte DAT_003fc9f3;
u8_obd_config CAL_obd_P0562;
char DAT_003fdcc8;
u8_obd_config CAL_obd_P0563;
char DAT_003fdc3c;
char DAT_003fdc48;
char DAT_003fdc4a;
u16_voltage_5/1023v CAL_obd_P0102_threshold;
u16_voltage_5/1023v CAL_obd_P0103_threshold;
u16_voltage_5/1023v CAL_obd_P0131_threshold;
u16_voltage_5/1023v CAL_obd_P0132_threshold;
u16_voltage_5/1023v CAL_obd_P0137_threshold;
u16_voltage_5/1023v CAL_obd_P0138_threshold;
u16_voltage_5/1023v CAL_obd_P0107_threshold;
u16_voltage_5/1023v CAL_obd_P0108_threshold;
u16_voltage_5/1023v CAL_obd_P0112_threshold;
u16_voltage_5/1023v CAL_obd_P0113_threshold;
u16_voltage_5/1023v CAL_obd_P0117_threshold;
u16_voltage_5/1023v CAL_obd_P0118_threshold;
u16_voltage_5/1023v CAL_obd_P0237_threshold;
u16_voltage_5/1023v CAL_obd_P0238_threshold;
u16_voltage_5/1023v CAL_obd_P0452_threshold;
u16_voltage_5/1023v CAL_obd_P0453_threshold;
u16_voltage_5/1023v CAL_obd_P0462_threshold;
u16_voltage_5/1023v CAL_obd_P0463_threshold;
u16_voltage_18/1023v CAL_obd_P0562_threshold;
u16_voltage_18/1023v CAL_obd_P0563_threshold;
u16_time_s CAL_obd_P0116_engine_runtime_min;
u8_temp_5/8-40c CAL_obd_P0116_threshold;
undefined1 flags_to_hc08;
undefined1 DAT_003fc9e7;
undefined1 DAT_003f92d0;
undefined1 DAT_003fc9e4;
undefined1 DAT_003f92d4;
undefined1 DAT_003fc9e5;
undefined1 DAT_003f92d8;
undefined1 DAT_003fc9d1;
undefined1 DAT_003f92dc;
undefined1 DAT_003fc9d2;
undefined1 DAT_003f92e0;
undefined1 DAT_003fc9d3;
undefined1 DAT_003f92e4;
undefined1 DAT_003fc9d5;
undefined1 DAT_003f92e8;
undefined1 DAT_003fc9d6;
undefined1 DAT_003f92ec;
undefined1 DAT_003fc9d7;
undefined1 DAT_003f92f0;
undefined1 DAT_003fc9d9;
undefined1 DAT_003fdd14;
undefined1 DAT_003fc9da;
undefined1 DAT_003fdd40;
undefined1 DAT_003fc9db;
undefined1 DAT_003fdd41;
undefined1 DAT_003fc9e0;
undefined1 DAT_003fdd42;
undefined1 DAT_003fc9e1;
undefined1 DAT_003fdd43;
undefined1 DAT_003fc9e2;
undefined1 DAT_003f92fe;
undefined1 DAT_003fc9e3;
undefined1 DAT_003f930a;
undefined1 DAT_003fca02;
undefined1 DAT_003f930e;
undefined1 DAT_003fca03;
undefined1 DAT_003f9312;
undefined1 DAT_003fc9f1;
undefined1 DAT_003f9302;
undefined1 DAT_003fc9f2;
undefined1 DAT_003f9306;
undefined1 DAT_003fc9f3;
undefined1 DAT_003f9326;
undefined1 DAT_003fc9f4;
undefined1 DAT_003f932a;
undefined1 DAT_003fc9ec;
undefined1 DAT_003f931a;
undefined1 DAT_003fc9eb;
undefined1 DAT_003f9316;
undefined1 DAT_003fca3f;
undefined1 DAT_003f9322;
undefined1 DAT_003fca3e;
undefined1 DAT_003f931e;
uint8_t DAT_003fdd5c;
byte DAT_003fc62f;
uint DAT_003fdd58;
u8_temp_5/8-40c CAL_obd_P0128_threshold;
byte DAT_003fdd4c;
byte DAT_003f9330;
u8_factor_1/255[8] CAL_obd_P0128_air_mass_factor;
byte DAT_003fc9e8;
u8_load_4mg/stroke[8] CAL_obd_P0128_air_mass_factor_X_engine_load;
u8_obd_config CAL_obd_P0128;
undefined1 DAT_003fc9e8;
undefined1 DAT_003f9330;
byte DAT_003f934c;
short DAT_003f934e;
byte DAT_003fdd66;
char DAT_003fdd67;
byte DAT_003f933a;
byte DAT_003f933e;
byte DAT_003fc648;
byte DAT_003fc64d;
byte DAT_003fdd68;
short DAT_003fc64e;
byte DAT_003fdd69;
short DAT_003f933c;
byte DAT_003fc64a;
char DAT_003fc649;
char DAT_003f8369;
byte DAT_003fc650;
short DAT_003fc652;
short DAT_003f9340;
byte DAT_003fc656;
byte DAT_003fc657;
short DAT_003f9342;
byte DAT_003fc651;
short DAT_003fc654;
byte DAT_003f9344;
byte DAT_003f9346;
byte DAT_003f9345;
short DAT_003f934a;
short DAT_003f9348;
char DAT_003f8368;
byte DAT_003fc658;
byte DAT_003fc659;
short DAT_003fc65a;
byte DAT_003fc64b;
byte DAT_003f9338;
byte DAT_003fca3d;
byte DAT_003fc64c;
byte DAT_003f9339;
byte DAT_003fc9fb;
u8_obd_config CAL_obd_P0461;
u8_obd_config CAL_obd_P0451;
undefined1 DAT_003fca3d;
undefined1 DAT_003f9338;
undefined1 DAT_003fc9fb;
undefined1 DAT_003f9339;
undefined1 DAT_003fda00;
uint8_t DAT_003f8370;
uint8_t DAT_003f8371;
uint8_t DAT_003f8372;
uint8_t DAT_003f8373;
uint8_t DAT_003fc569;
uint8_t DAT_003f9352;
uint8_t DAT_003fc56a;
uint8_t DAT_003f8374;
uint8_t DAT_003f8375;
uint8_t DAT_003f8376;
uint8_t DAT_003f8377;
uint8_t DAT_003fd886;
uint8_t DAT_003f8378;
uint8_t DAT_003f8379;
uint8_t obd_mil_dtc_count;
uint8_t DAT_003f9350;
uint8_t DAT_003f9351;
u16_voltage_5/1023v sensor_adc_pps_1;
u16_voltage_5/1023v sensor_adc_pps_2;
u16_voltage_5/1023v tps_1_range_corrected_low;
uint8_t DAT_003f84a8;
uint8_t DAT_003f84a9;
uint8_t DAT_003f84aa;
uint8_t DAT_003f9358;
uint8_t obd_trouble_list_count;
undefined2 DAT_003fdcfa;
undefined1 DAT_003fdd11;
undefined2 DAT_003fdcfe;
undefined1 DAT_003fdd05;
undefined2 DAT_003fdcfc;
undefined1 DAT_003fdd04;
undefined1 DAT_002f83d1;
undefined1 DAT_002f83d2;
undefined1 DAT_002f83d4;
undefined1 DAT_002f83d5;
uint8_t obd_pending_list_count;
uint8_t DAT_003f84f8;
uint8_t DAT_003fdf74;
uint8_t DAT_003fdf75;
uint8_t DAT_003fdf76;
undefined2 DAT_003fe736;
undefined2 DAT_003fe734;
undefined2 DAT_003fe72e;
undefined2 DAT_003fe72c;
undefined2 DAT_003fe73e;
undefined2 DAT_003fe73c;
undefined2 DAT_003fe746;
undefined2 DAT_003fe744;
char[32] s_A129E0002_Sport_GT_240_EU_003fcf26;
uint8_t DAT_003f8520;
uint8_t DAT_003f9360;
uint8_t DAT_003f9361;
uint8_t DAT_003f8521;
short DAT_003fc5da;
short DAT_003fc5d8;
short DAT_002f8354;
short DAT_002f8356;
short DAT_003fc5e0;
short DAT_003fc5de;
short DAT_003fc570;
short DAT_003fc56e;
uint8_t DAT_003f8522;
uint8_t DAT_003f9362;
uint8_t DAT_003f9363;
uint8_t DAT_003f8523;
short DAT_002f8352;
undefined2 DAT_003fc52a;
uint8_t DAT_002f835a;
short DAT_002f8362;
ushort DAT_002f8358;
ushort DAT_003fc606;
uint8_t DAT_003f9364;
uint8_t DAT_003f9365;
uint8_t DAT_003f9366;
uint8_t DAT_003f8524;
uint8_t DAT_003f9367;
uint8_t DAT_003f9368;
uint8_t DAT_003f9369;
uint8_t DAT_003f8525;
uint8_t DAT_003f8526;
uint8_t DAT_003f936a;
uint8_t DAT_003f936b;
uint8_t DAT_003f8527;
uint8_t DAT_003f8528;
uint8_t DAT_003f936c;
uint8_t DAT_003f936d;
uint8_t DAT_003f936e;
char DAT_002f8366;
uint8_t DAT_003f8530;
uint8_t DAT_003f9370;
uint8_t DAT_003f9371;
uint8_t DAT_003f9372;
u16_time_5ms DAT_003fc5a4;
u16_time_5ms obd_mode_0x08_timer;
char DAT_003f8538;
byte DAT_003fe2cb;
undefined1 DAT_003fd9b9;
uint8_t DAT_003f8540;
uint8_t DAT_003f8541;
undefined1 DAT_003f8542;
undefined1 DAT_003f8543;
uint8_t DAT_003f8544;
uint8_t DAT_003f8545;
u16_speed_1/100kph wheel_speed_fr;
undefined1 DAT_003f8546;
u16_speed_1/100kph wheel_speed_fl;
undefined1 DAT_003f8547;
u16_speed_1/100kph wheel_speed_rl;
uint8_t DAT_003f8548;
u16_speed_1/100kph wheel_speed_rr;
uint8_t DAT_003f8549;
undefined1 DAT_003f9378;
undefined1 DAT_003f9379;
uint8_t DAT_003f854a;
uint8_t DAT_003f854b;
undefined1 DAT_003f854c;
undefined1 DAT_003f854d;
uint8_t DAT_003f854e;
uint8_t DAT_003f854f;
undefined1 DAT_003f8550;
uint8_t DAT_003f8551;
uint8_t DAT_003f937a;
undefined1 DAT_003f937b;
undefined1 DAT_003f937c;
u8_factor_1/100 tc_slip_target;
u8_factor_1/100 tc_slip;
u16_factor_1/1023 tps_target_smooth;
undefined2 pps_min;
uint8_t DAT_003f8a40;
uint8_t DAT_003f9380;
uint8_t DAT_003f9381;
uint8_t DAT_003f8a41;
short DAT_003fe18c;
u16_time_5ms DAT_003fc5a2;
uint8_t DAT_003f8a42;
uint8_t DAT_003f9382;
uint8_t DAT_003f9383;
uint8_t DAT_003f8a43;
u16_time_5ms DAT_003fc598;
u16_time_5ms DAT_003fc59a;
u16_time_5ms DAT_003fc5b2;
u16_time_5ms DAT_003fc5b4;
u16_time_5ms DAT_003fc5ac;
uint8_t DAT_003f8a44;
uint8_t DAT_003f8a45;
uint8_t DAT_003f9384;
uint8_t DAT_003f8a46;
u16_time_5ms DAT_003fc5bc;
undefined1 DAT_003fe18e;
undefined1 DAT_003fe18f;
u16_time_5ms DAT_003fc516;
u16_time_5ms DAT_003fc5be;
u16_time_5ms DAT_003fc5c0;
u16_time_5ms DAT_003fc5c2;
u16_time_5ms DAT_003fc5c4;
u16_time_5ms DAT_003fc5c6;
uint8_t DAT_003f9385;
uint8_t DAT_003f9386;
uint8_t DAT_003f9387;
uint8_t DAT_003f9388;
u16_time_5ms DAT_003fc5ba;
u16_time_5ms obd_mode_0x2F_timer;
short DAT_003fc59c;
u8_time_5ms DAT_003fc59e;
ushort DAT_003fc5a0;
u8_time_5ms DAT_003fc5b9;
u8_time_5ms obd_mode_0x2F_pulse_interval;
undefined1 tpms_session_handler_state;
short DAT_003fe190;
byte REG_CANB_MB6_DATA0;
byte DAT_003fe2c9;
byte REG_CANB_MB6_DATA1;
byte DAT_003fe2c8;
byte REG_CANB_MB6_DATA2;
byte DAT_003f9391;
byte REG_CANB_MB6_DATA3;
undefined1 DAT_003f9392;
undefined1 DAT_003fe2cd;
undefined1 DAT_003fe2d2;
char DAT_003f9392;
u8_pressure_40mbar CAL_tpms_threshold_rear;
char DAT_003f9390;
undefined2 DAT_003fe190;
undefined1 DAT_003fe2c8;
undefined1 DAT_003fe2ce;
byte DAT_003fe350;
byte DAT_003fe351;
byte DAT_003fe352;
char DAT_003f8c46;
char DAT_003f8c47;
u8_pressure_40mbar DAT_003fe2cf;
u8_pressure_40mbar DAT_003fe2d0;
u8_pressure_40mbar DAT_003fe2d1;
u8_pressure_40mbar DAT_003fe2d2;
undefined1 DAT_003fe2d3;
u8_pressure_40mbar DAT_003fe2d4;
u8_pressure_40mbar DAT_003fe2d5;
undefined1 DAT_003fe2d6;
undefined1 DAT_003fe2d7;
undefined1 DAT_003fe2d8;
undefined1 DAT_003fe2d9;
undefined1 DAT_003fe2da;
u8_pressure_40mbar CAL_tpms_pressure_front;
u8_pressure_40mbar CAL_tpms_pressure_rear;
u8_pressure_40mbar CAL_tpms_threshold_front;
char DAT_003f9393;
char DAT_003f8c48;
undefined1 DAT_003fe2cf;
undefined1 DAT_003fe2d0;
undefined1 DAT_003fe2d1;
undefined1 DAT_003fe2d4;
char DAT_003fe350;
char DAT_003f8c49;
u16_factor_1/1023 dev_pps_1_smooth;
u16_factor_1/1023 dev_pps_2_smooth;
u16_factor_1/1023 dev_pps_1;
u16_factor_1/1023 dev_pps_2;
u16_factor_1/1023[16] CAL_tps_target;
u16_factor_1/1023[16] CAL_tps_target_X_pps;
u16_time_5ms pps_offset_timer;
u8_time_5ms CAL_sensor_pps_offset_time_between_step;
byte DAT_003fe9a8;
byte DAT_003f9398;
undefined2 DAT_003f939a;
byte DAT_003fca15;
byte DAT_003f939c;
undefined2 DAT_003f939e;
byte DAT_003fca0b;
byte DAT_003f93a0;
undefined2 DAT_003f93a2;
byte DAT_003fca0c;
byte DAT_003f93a4;
undefined2 DAT_003f93a6;
byte DAT_003fca0d;
byte DAT_003f93a8;
undefined2 DAT_003f93aa;
byte DAT_003fca0e;
u8_obd_config CAL_obd_P2138;
u8_obd_config CAL_obd_P2122;
u8_obd_config CAL_obd_P2123;
u8_obd_config CAL_obd_P2127;
u8_obd_config CAL_obd_P2128;
undefined1 DAT_003fca15;
undefined1 DAT_003f9398;
undefined1 DAT_003fca0b;
undefined1 DAT_003f939c;
undefined1 DAT_003fca0c;
undefined1 DAT_003f93a0;
undefined1 DAT_003fca0d;
undefined1 DAT_003f93a4;
undefined1 DAT_003fca0e;
undefined1 DAT_003f93a8;
undefined1 DAT_003fe4b0;
undefined1 DAT_003fe4b1;
undefined1 DAT_003fe4b2;
uint8_t tps_state_machine;
pointer[5] tps_state_table;
uint8_t tps_state_motor_off_timer;
u16_factor_1/1023 dev_tps_rest_position;
char DAT_003fe4b2;
u16_factor_1/10000 DAT_003fe496;
uint DAT_003fe498;
short DAT_003fe4b8;
int DAT_003fe4bc;
ushort DAT_003fe480;
undefined1 DAT_003fe484;
short DAT_003fe486;
u16_factor_1/100 CAL_tps_ctrl_p_gain;
u16_factor_1/10000 CAL_tps_ctrl_i_gain;
u16_factor_1/10 CAL_tps_ctrl_d_gain;
uint16_t CAL_tps_ctrl_i_limit;
u16_voltage_5/1023v tps_state_test_target;
i16_factor_1/1023 tps_dt;
struct_filter_4th_order filter_tps_diff;
uint8_t tps_state_test_sample_timer;
int32_t tps_ctrl_p;
uint16_t tps_state_test_timer;
int32_t tps_ctrl_i;
int32_t tps_ctrl_i_sum;
int16_t tps_ctrl_d;
int16_t tps_output;
u16_factor_1/1023[4] tps_1_smooth_history;
uint8_t tps_state_test_passed;
u16_factor_1/1023[16] CAL_tps_motor_duty_cycle_X_tps;
u16_factor_1/1024-1024[16] CAL_tps_motor_duty_cycle;
u16_voltage_5/1023v tps_state_test_sample_tps_1;
u16_voltage_5/1023v tps_state_test_sample_tps_2;
uint8_t tps_state_test_failed;
u16_factor_1/1023 tps_diff;
ushort DAT_003f99ce;
ushort DAT_003f99ba;
ushort DAT_003f99d0;
ushort DAT_003f99d2;
ushort DAT_003f99be;
ushort DAT_003f99d4;
undefined2 tps_1_gain_corrected;
u16_voltage_5/1023v tps_2_range_corrected_low;
undefined2 tps_2_gain_computed;
u16_voltage_5/1023v tps_1_range_corrected_high;
u16_voltage_5/1023v tps_2_range_corrected_high;
int DAT_003fe4c4;
undefined1 DAT_003fe4c2;
ushort DAT_003fe9b6;
ushort DAT_003fc590;
u16_factor_1/1023 DAT_003fe4c0;
char DAT_003fe9bb;
char DAT_003fe9ca;
ushort DAT_003f9ad2;
u8_factor_1/255[8] CAL_tps_smooth_inc_X_tps_target;
u8_factor_1/255[8] CAL_tps_smooth_dec_X_tps_target;
char DAT_003fe9ce;
char DAT_003fe4ea;
u8_factor_1/1023 tps_target_smooth_dec;
uint16_t CAL_tps_smooth_time_between_step;
u8_factor_1/1023 tps_target_smooth_inc;
uint16_t tps_smooth_timer;
uint8_t tps_state_sweep_time_between_step;
uint8_t tps_state_sweep_timer;
uint8_t tps_state_sweep_step;
u16_factor_1/1023 tps_state_sweep_limit_h;
u16_factor_1/1023 tps_state_sweep_limit_l;
uint8_t tps_state_sweep_enable;
uint8_t tps_state_sweep_direction;
u16_factor_1/1023 CAL_tps_limit_l;
u16_factor_1/1023 CAL_tps_limit_h;
u16_factor_1/1023 tps_target;
u8_factor_1/1023[8] CAL_tps_smooth_dec;
u8_factor_1/1023[8] CAL_tps_smooth_inc;
byte DAT_003fe954;
byte DAT_003fe4e1;
undefined2 DAT_003f93c8;
byte DAT_003fca12;
byte DAT_003fe4cc;
undefined2 DAT_003f93c0;
byte DAT_003fc9de;
byte DAT_003fe4dc;
undefined2 DAT_003f93c2;
byte DAT_003fc9df;
byte DAT_003fe4dd;
undefined2 DAT_003f93c4;
byte DAT_003fca10;
byte DAT_003fe4de;
undefined2 DAT_003f93c6;
byte DAT_003fca11;
short DAT_003f93ca;
byte DAT_003fe4df;
byte DAT_003fca13;
ushort DAT_003fc594;
short DAT_003f93cc;
byte DAT_003fe4e0;
byte DAT_003fca46;
short DAT_003f93ce;
byte DAT_003fe4e2;
byte DAT_003fca47;
short DAT_003f93d0;
byte DAT_003fe4e3;
byte DAT_003fca48;
short DAT_003f93d4;
byte DAT_003fe4e5;
undefined1 DAT_003fe4ea;
byte DAT_003fca4a;
short DAT_003f93d2;
byte DAT_003fe4e4;
byte DAT_003fca49;
byte DAT_003fe4e6;
byte DAT_003fca4b;
byte DAT_003fe4e7;
byte DAT_003fca4c;
byte DAT_003fe4e8;
byte DAT_003fca4d;
byte DAT_003fe4e9;
byte DAT_003fca4e;
u8_obd_config CAL_obd_P2135;
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
undefined1 DAT_003fc9de;
undefined1 DAT_003fe4cc;
undefined1 DAT_003fc9df;
undefined1 DAT_003fe4dc;
undefined1 DAT_003fca10;
undefined1 DAT_003fe4dd;
undefined1 DAT_003fca11;
undefined1 DAT_003fe4de;
undefined1 DAT_003fca13;
undefined1 DAT_003fe4df;
undefined1 DAT_003fca46;
undefined1 DAT_003fe4e0;
undefined1 DAT_003fca12;
undefined1 DAT_003fe4e1;
undefined1 DAT_003fca47;
undefined1 DAT_003fe4e2;
undefined1 DAT_003fca48;
undefined1 DAT_003fe4e3;
undefined1 DAT_003fca49;
undefined1 DAT_003fe4e4;
undefined1 DAT_003fca4a;
undefined1 DAT_003fe4e5;
undefined1 DAT_003fca4b;
undefined1 DAT_003fe4e6;
undefined1 DAT_003fca4c;
undefined1 DAT_003fe4e7;
undefined1 DAT_003fca4d;
undefined1 DAT_003fe4e8;
undefined1 DAT_003fca4e;
undefined1 DAT_003fe4e9;
struct_filter_4th_order filter_unused_1;
struct_filter_4th_order filter_unused_2;
struct_filter_2nd_order filter_unused_3;
struct_filter_2nd_order filter_unused_4;
byte DAT_003fc63b;
byte DAT_003fc63c;
byte DAT_003fc63f;
undefined2 DAT_003fc646;
undefined2 DAT_003f93d8;
undefined2 DAT_003fc640;
undefined2 DAT_003f93da;
undefined2 DAT_003fc642;
undefined2 DAT_003f93dc;
undefined2 DAT_003fc644;
undefined2 DAT_003f93de;
byte DAT_003f8c90;
byte DAT_003f8c91;
byte DAT_003f8c92;
undefined2 DAT_003f8c94;
struct_iumpr_monitor[6] iumpr_monitor;
char DAT_003fdc38;
ushort DAT_003fc636;
ushort DAT_003fc638;
byte DAT_003fc63a;
short DAT_003f93da;
short DAT_003f93de;
byte DAT_003fc63d;
short DAT_003f93d8;
byte DAT_003fc63e;
short DAT_003fc646;
short DAT_003f93dc;
byte DAT_003fc634;
byte DAT_003fc635;
uint8_t *[6] iumpr_list;
undefined DAT_003fe72a;
undefined DAT_003fe730;
ushort DAT_003f93f6;
uint8_t CAL_tc_mode;
u16_length_mm CAL_tc_rear_tyre_circumference;
u16_length_mm CAL_tc_front_tyre_circumference;
uint8_t CAL_tc_abs_ring_teeth_count;
u8_factor_1/255 CAL_tc_ign_adv_adj_limit;
u8_factor_1/255 tc_retard_adj2;
u8_factor_1/255 tc_retard_adj1;
u8_factor_10/1632 CAL_tc_slip_to_retard_ratio;
uint8_t[16] CAL_tc_fuelcut;
u16_speed_1/100kph wheel_speed_rear_diff;
u8_factor_1/100[16] CAL_tc_fuelcut_X_slip;
u16_speed_1/100kph wheel_speed_front_diff;
u8_factor_1/100[16] CAL_tc_slip_target_base;
u8_speed_kph[4] CAL_tc_slip_target_base_X_speed_front;
u8_factor_1/255[4] CAL_tc_slip_target_base_Y_pps;
u8_factor_1/256 CAL_tc_car_speed_reactivity;
u16_speed_1/100kph wheel_speed_diff;
u16_speed_1/100kph wheel_speed_f_max_1;
u8_factor_1/256 CAL_tc_slip_reactivity;
u16_rspeed_rpm CAL_tc_engine_speed_min;
u8_factor_1/100 tc_slip_diff_smooth;
u8_speed_kph CAL_tc_front_speed_max;
u8_speed_kph CAL_tc_front_speed_min;
u8_factor_1/100 CAL_tc_slip_min;
u8_factor_1/100 CAL_tc_slip_target_adj;
uint32_t car_speed_smooth_x;
uint32_t tc_slip_diff_smooth_x;
short DAT_003f8cbc;
byte DAT_003f93f4;
u16_speed_1/100kph CAL_tc_slip_adj_left_right_enable;
u16_time_5ms CAL_tc_slip_target_adj_time;
u16_time_5ms CAL_tc_time_between_step;
u16_time_5ms tc_slip_target_adj_timer;
u16_time_5ms tc_step_timer;
undefined1 DAT_003f93f8;
undefined2 hc08_crc16;
char DAT_003f9419;
undefined1 DAT_003f941b;
uint8_t hc08_parse_len;
undefined1 DAT_003f941a;
ushort REG_SCC2R0;
undefined1 DAT_003f9419;
ushort REG_SCC2R1;
undefined1 DAT_003f9416;
ushort REG_SC2SR;
ushort REG_SC2DR;
byte DAT_003f941a;
char[32] sci2_rx_buffer;
byte DAT_003f9419;
byte DAT_003f941b;
byte DAT_003f9417;
undefined1 DAT_003f9418;
char[32] sci2_tx_buffer;
byte DAT_003f9418;
uint8_t hc08_parse_sum;
uint8_t DAT_003f9416;
char[20] hc08_parse_buf;
char DAT_003f9416;
char DAT_003fe78f;
char DAT_003fe790;
char DAT_003fe791;
char DAT_003fe792;
char DAT_003fe797;
char DAT_003fe798;
u8_voltage_5/255v hc08_tps_2;
u8_voltage_5/255v hc08_pps_1;
u8_voltage_5/255v hc08_pps_2;
u8_voltage_5/255v hc08_tps_1;
undefined1 DAT_003fe933;
undefined1 DAT_003fe934;
u16_factor_1/1023[3] pps_1_history;
uint8_t DAT_003fe9b9;
u16_factor_1/1023[3] pps_2_history;
u16_factor_1/1023 CAL_sensor_pps_match_max;
uint8_t DAT_003fe9ba;
u16_factor_1/1023 DAT_003fe9ae;
u16_factor_1/1023 DAT_003fe9b0;
undefined1 DAT_003fe9bb;
undefined1 DAT_003fe9ce;
u16_voltage_5/1023v pps_1_range_high;
u16_voltage_5/1023v pps_2_range_high;
u16_voltage_5/1023v pps_1_range_low;
u16_voltage_5/1023v pps_2_range_low;
undefined2 pps_diff;
undefined1 pps_correlation_state;
u16_factor_1/1023 pps_1;
u16_factor_1/1023 pps_2;
undefined1 DAT_003fe954;
u16_voltage_5/1023v CAL_misc_tps_2_range_high;
undefined1 DAT_003fe9a8;
u16_voltage_5/1023v CAL_misc_tps_1_range_high;
undefined2 DAT_003fe9b4;
u16_factor_1/1023 tps_1;
u16_factor_1/1023[3] tps_1_history;
u16_voltage_5/1023v CAL_misc_pps_2_range_high;
undefined2 DAT_003fe9b2;
u16_factor_1/1023[3] tps_2_history;
u16_voltage_5/1023v CAL_misc_pps_1_range_high;
undefined2 DAT_003fe9b0;
undefined2 DAT_003fe9ae;
u16_factor_1/1023 tps_2;
undefined2 DAT_003fe9b6;
undefined1 DAT_003fe9ba;
undefined1 DAT_003fe9b9;
undefined2 DAT_003fe9c8;
undefined2 DAT_003fe9c6;
undefined2 DAT_003fe9c4;
undefined2 DAT_003fe9c2;
undefined1 DAT_003fe9ca;
undefined1 DAT_003fe9cd;
undefined1 DAT_003fe9cc;
undefined1 DAT_003fe9cf;
undefined1 DAT_003fe9d1;
u16_voltage_5/1023v CAL_misc_pps_1_range_low;
u16_voltage_5/1023v CAL_misc_pps_2_range_low;
u16_voltage_5/1023v tps_1_range_high;
u16_voltage_5/1023v tps_1_range_low;
u16_voltage_5/1023v tps_2_range_high;
u16_voltage_5/1023v tps_2_range_low;
u16_voltage_5/1023v CAL_misc_tps_1_range_low;
u16_voltage_5/1023v CAL_misc_tps_2_range_low;
undefined1 tps_correlation_state;
uint8_t DAT_003fe9cc;
uint8_t DAT_003fe9cd;
u16_factor_1/1023 CAL_sensor_tps_match_max;
u16_factor_1/1023 DAT_003fe9c2;
u16_factor_1/1023 DAT_003fe9c4;
undefined2 DAT_003fc590;
undefined1 DAT_003f8fc0;
struct_varptr[233] log_varptr_list;
undefined1 DAT_003f8fc1;
uint16_t[8] uint16_t_ARRAY_003f9ba8;
int *DAT_003f8fd8;
int DAT_003f8fe0;
int DAT_003f8ff0;
undefined *DAT_003f8fe4;
pointer PTR_cleanup_callbacks_0007d970;
undefined DAT_003f9468;
int DAT_003f8ff4;
undefined *DAT_003f8fe8;
undefined DAT_003f9568;

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
  exit(0x784e0);
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
  DAT_003f9668 = param_1;
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
  DAT_003f96bd = 0x80;
  dev_afr_adj = 0;
  DAT_003f96bf = 0;
  DAT_003f96c0 = 0;
  DAT_003f8ff9 = 0;
  DAT_003f8ff8 = 0;
  shutdown_flags = shutdown_flags | 8;
  uVar2 = REG_MPWMSM16_SCR;
  REG_MPWMSM16_SCR = uVar2 & 0xf7ff | 0x800;
  eeprom_load();
  uVar2 = REG_RSR;
  if ((uVar2 >> 0xc & 1) == 1) {
    uVar2 = REG_RSR;
    REG_RSR = uVar2 & 0xefff | 0x1000;
    DAT_003fdc90 = DAT_003fdc90 | 2;
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
    DAT_003f966c = DAT_003fe18e | L9822E_outputs & ~DAT_003fe18f;
    DAT_003f96b8 = 1;
    L9822E_outputs = DAT_003f966c;
    spi_pcs1();
    spi_pcs0();
    spi_pcs3();
    DAT_003f96b8 = 0;
    if (DAT_003f8270 != -1) {
      spi_pcs2(DAT_003f8270);
      DAT_003f8270 = -1;
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
  short last;
  uint8_t result;
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
                 (char)((int)((int)(short)((ushort)lut[i] - (ushort)lut[i + -1]) *
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
  int i;
  uint temp;
  uint8_t result;
  
  temp = (uint)input << (shift & 0x3f) & 0xffff;
  i = (int)temp >> 8;
  if (lut[i] == lut[i + 1]) {
    result = lut[i];
  }
  else {
    temp = (int)(short)((ushort)lut[i + 1] - (ushort)lut[i]) * (temp - (int)(short)(i << 8));
    result = lut[i] + (char)(temp >> 8) + ((int)temp < 0 && (temp & 0xff) != 0);
  }
  return result;
}



// 3D table lookup with bilinear interpolation for uint8 values

uint8_t lookup_3D_uint8_interpolated
                  (uint8_t size_x,uint8_t size_y,uint16_t input_x,uint16_t input_y,uint8_t *lut,
                  uint8_t *x_axis,uint8_t *y_axis)

{
  ushort uVar1;
  ushort uVar2;
  ushort uVar3;
  ushort uVar4;
  short sVar5;
  ushort uVar6;
  uint uVar7;
  uint8_t uVar8;
  ushort uVar9;
  ushort uVar10;
  ushort uVar11;
  byte local_38;
  byte local_37;
  
  uVar7 = (uint)size_y;
  uVar6 = (ushort)size_x;
  push_23to31();
  uVar6 = uVar6 & 0xff;
  uVar1 = (ushort)uVar7 & 0xff;
  uVar2 = input_x & 0xff;
  uVar3 = input_y & 0xff;
  uVar9 = uVar6 - 1;
  uVar4 = uVar1 - 1;
  uVar11 = 0;
  uVar10 = 0;
  if ((uVar2 < *x_axis) && (uVar3 < *y_axis)) {
    uVar8 = *lut;
  }
  else if ((x_axis[(short)uVar9] < uVar2) && (y_axis[(short)uVar4] < uVar3)) {
    uVar8 = lut[(int)(short)uVar6 * (int)(short)uVar1 + -1];
  }
  else {
    for (; (y_axis[(short)uVar10] < uVar3 && ((short)uVar10 < (short)uVar4)); uVar10 = uVar10 + 1) {
    }
    if ((y_axis[(short)uVar10] < uVar3) && (uVar10 == uVar4)) {
      uVar10 = uVar10 + 1;
    }
    for (; (x_axis[(short)uVar11] < uVar2 && ((short)uVar11 < (short)uVar9)); uVar11 = uVar11 + 1) {
    }
    if ((x_axis[(short)uVar11] < uVar2) && (uVar11 == uVar9)) {
      uVar11 = uVar11 + 1;
    }
    if (((uVar2 == x_axis[(short)uVar11]) && (uVar3 == y_axis[(short)uVar10])) &&
       ((int)(short)uVar10 == (uVar7 & 0xff))) {
      uVar8 = lut[(int)(short)uVar11 + ((short)uVar10 + -1) * (int)(short)uVar6];
    }
    else if ((uVar2 == x_axis[(short)uVar11]) && (uVar3 == y_axis[(short)uVar10])) {
      uVar8 = lut[(int)(short)uVar11 + (int)(short)uVar10 * (int)(short)uVar6];
    }
    else if (((uVar3 == y_axis[(short)uVar10]) || (uVar10 == uVar1)) || (uVar10 == 0)) {
      if (uVar10 == uVar1) {
        uVar10 = uVar10 - 1;
      }
      if (uVar11 == uVar6) {
        if (x_axis[(short)uVar11 + -1] == x_axis[(short)uVar11 + -2]) {
          uVar8 = lut[((short)uVar10 + 1) * (int)(short)uVar6 + -2];
        }
        else {
          uVar8 = lut[((short)uVar10 + 1) * (int)(short)uVar6 + -1];
        }
      }
      else if (uVar11 == 0) {
        uVar8 = lut[(int)(short)uVar10 * (int)(short)uVar6];
      }
      else {
        sVar5 = uVar11 + uVar10 * uVar6;
        if (x_axis[(short)uVar11 + -1] == x_axis[(short)uVar11]) {
          uVar8 = lut[sVar5 + -1];
        }
        else {
          uVar8 = lut[sVar5 + -1] +
                  (char)((int)(((int)(short)uVar2 - (uint)x_axis[(short)uVar11 + -1]) *
                              ((uint)lut[sVar5] - (uint)lut[sVar5 + -1])) /
                        (int)((uint)x_axis[(short)uVar11] - (uint)x_axis[(short)uVar11 + -1]));
        }
      }
    }
    else if (((uVar2 == x_axis[(short)uVar11]) || (uVar11 == uVar6)) || (uVar11 == 0)) {
      if (uVar11 == uVar6) {
        uVar11 = uVar11 - 1;
      }
      sVar5 = uVar11 + uVar10 * uVar6;
      if (uVar10 == uVar1) {
        if (y_axis[(short)uVar10 + -2] == y_axis[(short)uVar10 + -1]) {
          uVar8 = lut[(int)sVar5 + (short)uVar6 * -2];
        }
        else {
          uVar8 = lut[(int)sVar5 - (int)(short)uVar6];
        }
      }
      else if (uVar10 == 0) {
        uVar8 = lut[(short)uVar11];
      }
      else if (y_axis[(short)uVar10 + -1] == y_axis[(short)uVar10]) {
        uVar8 = lut[(int)sVar5 - (int)(short)uVar6];
      }
      else {
        uVar8 = lut[(int)sVar5 - (int)(short)uVar6] +
                (char)((int)(((int)(short)uVar3 - (uint)y_axis[(short)uVar10 + -1]) *
                            ((uint)lut[sVar5] - (uint)lut[(int)sVar5 - (int)(short)uVar6])) /
                      (int)((uint)y_axis[(short)uVar10] - (uint)y_axis[(short)uVar10 + -1]));
      }
    }
    else {
      sVar5 = uVar11 + (uVar10 - 1) * uVar6;
      if (x_axis[(short)uVar11 + -1] == x_axis[(short)uVar11]) {
        local_37 = lut[sVar5];
        local_38 = lut[(int)sVar5 + (int)(short)uVar6];
      }
      else {
        local_37 = lut[sVar5 + -1] +
                   (char)((int)(((int)(short)uVar2 - (uint)x_axis[(short)uVar11 + -1]) *
                               ((uint)lut[sVar5] - (uint)lut[sVar5 + -1])) /
                         (int)((uint)x_axis[(short)uVar11] - (uint)x_axis[(short)uVar11 + -1]));
        local_38 = lut[(int)sVar5 + (int)(short)uVar9] +
                   (char)((int)(((int)(short)uVar2 - (uint)x_axis[(short)uVar11 + -1]) *
                               ((uint)lut[(int)sVar5 + (int)(short)uVar6] -
                               (uint)lut[(int)sVar5 + (int)(short)uVar9])) /
                         (int)((uint)x_axis[(short)uVar11] - (uint)x_axis[(short)uVar11 + -1]));
      }
      uVar8 = local_37 +
              (char)((int)(((int)(short)uVar3 - (uint)y_axis[(short)uVar10 + -1]) *
                          ((uint)local_38 - (uint)local_37)) /
                    (int)((uint)y_axis[(short)uVar10] - (uint)y_axis[(short)uVar10 + -1]));
    }
  }
  pop_23to31();
  return uVar8;
}



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
  uint uVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  ushort local_28;
  ushort local_26;
  
  uVar6 = (uint)input_y;
  uVar5 = (uint)input_x;
  uVar4 = (uint)size_y;
  uVar3 = (uint)size_x;
  push_24to31();
  uVar3 = uVar3 & 0xff;
  uVar1 = uVar4 & 0xff;
  uVar5 = uVar5 & 0xffff;
  uVar6 = uVar6 & 0xffff;
  uVar7 = uVar3 - 1;
  uVar2 = uVar1 - 1;
  uVar10 = 0;
  uVar9 = 0;
  if ((uVar5 < *x_axis) && (uVar6 < *y_axis)) {
    local_26 = *lut;
  }
  else if ((x_axis[uVar7] < uVar5) && (y_axis[uVar2] < uVar6)) {
    local_26 = lut[uVar3 * uVar1 + -1];
  }
  else {
    for (; (y_axis[uVar9] < uVar6 && ((int)uVar9 < (int)uVar2)); uVar9 = uVar9 + 1) {
    }
    if ((y_axis[uVar9] < uVar6) && (uVar9 == uVar2)) {
      uVar9 = uVar9 + 1;
    }
    for (; (x_axis[uVar10] < uVar5 && ((int)uVar10 < (int)uVar7)); uVar10 = uVar10 + 1) {
    }
    if ((x_axis[uVar10] < uVar5) && (uVar10 == uVar7)) {
      uVar10 = uVar10 + 1;
    }
    if (((uVar5 == x_axis[uVar10]) && (uVar6 == y_axis[uVar9])) && (uVar9 == (uVar4 & 0xff))) {
      local_26 = lut[uVar10 + (uVar9 - 1) * uVar3];
    }
    else if ((uVar5 == x_axis[uVar10]) && (uVar6 == y_axis[uVar9])) {
      local_26 = lut[uVar10 + uVar9 * uVar3];
    }
    else if (((uVar6 == y_axis[uVar9]) || (uVar9 == uVar1)) || (uVar9 == 0)) {
      if (uVar9 == uVar1) {
        uVar9 = uVar9 - 1;
      }
      if (uVar10 == uVar3) {
        if (x_axis[uVar10 - 1] == x_axis[uVar10 - 2]) {
          local_26 = lut[(uVar9 + 1) * uVar3 + -2];
        }
        else {
          local_26 = lut[(uVar9 + 1) * uVar3 + -1];
        }
      }
      else if (uVar10 == 0) {
        local_26 = lut[uVar9 * uVar3];
      }
      else {
        iVar8 = uVar10 + uVar9 * uVar3;
        if (x_axis[uVar10 - 1] == x_axis[uVar10]) {
          local_26 = lut[iVar8 + -1];
        }
        else {
          local_26 = lut[iVar8 + -1] +
                     (short)((int)((uVar5 - x_axis[uVar10 - 1]) *
                                  ((uint)lut[iVar8] - (uint)lut[iVar8 + -1])) /
                            (int)((uint)x_axis[uVar10] - (uint)x_axis[uVar10 - 1]));
        }
      }
    }
    else if (((uVar5 == x_axis[uVar10]) || (uVar10 == uVar3)) || (uVar10 == 0)) {
      if (uVar10 == uVar3) {
        uVar10 = uVar10 - 1;
      }
      iVar8 = uVar10 + uVar9 * uVar3;
      if (uVar9 == uVar1) {
        if (y_axis[uVar9 - 2] == y_axis[uVar9 - 1]) {
          local_26 = lut[iVar8 + uVar3 * -2];
        }
        else {
          local_26 = lut[iVar8 - uVar3];
        }
      }
      else if (uVar9 == 0) {
        local_26 = lut[uVar10];
      }
      else if (y_axis[uVar9 - 1] == y_axis[uVar9]) {
        local_26 = lut[iVar8 - uVar3];
      }
      else {
        local_26 = lut[iVar8 - uVar3] +
                   (short)((int)((uVar6 - y_axis[uVar9 - 1]) *
                                ((uint)lut[iVar8] - (uint)lut[iVar8 - uVar3])) /
                          (int)((uint)y_axis[uVar9] - (uint)y_axis[uVar9 - 1]));
      }
    }
    else {
      iVar8 = uVar10 + (uVar9 - 1) * uVar3;
      if (x_axis[uVar10 - 1] == x_axis[uVar10]) {
        local_26 = lut[iVar8];
        local_28 = lut[iVar8 + uVar3];
      }
      else {
        local_26 = lut[iVar8 + -1] +
                   (short)((int)((uVar5 - x_axis[uVar10 - 1]) *
                                ((uint)lut[iVar8] - (uint)lut[iVar8 + -1])) /
                          (int)((uint)x_axis[uVar10] - (uint)x_axis[uVar10 - 1]));
        local_28 = lut[iVar8 + uVar7] +
                   (short)((int)((uVar5 - x_axis[uVar10 - 1]) *
                                ((uint)lut[iVar8 + uVar3] - (uint)lut[iVar8 + uVar7])) /
                          (int)((uint)x_axis[uVar10] - (uint)x_axis[uVar10 - 1]));
      }
      local_26 = local_26 +
                 (short)((int)((uVar6 - y_axis[uVar9 - 1]) * ((uint)local_28 - (uint)local_26)) /
                        (int)((uint)y_axis[uVar9] - (uint)y_axis[uVar9 - 1]));
    }
  }
  pop_24to31();
  return local_26;
}



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
  uint uVar7;
  uint8_t uVar8;
  uint uVar9;
  uint uVar10;
  
  uVar10 = (uint)input_y;
  uVar9 = (uint)input_x;
  uVar2 = (uint)shift_y;
  uVar1 = (uint)shift_x;
  uVar7 = (uint)size_x;
  push_25to31();
  uVar1 = (uVar9 & 0xff) << (uVar1 & 0x3f);
  sVar3 = (short)uVar1;
  uVar2 = (uVar10 & 0xff) << (uVar2 & 0x3f);
  sVar4 = (short)(char)(uVar1 >> 8) + (ushort)(sVar3 < 0 && (uVar1 & 0xff) != 0);
  sVar5 = (short)(char)(uVar2 >> 8) + (ushort)((short)uVar2 < 0 && (uVar2 & 0xff) != 0);
  sVar6 = sVar4 + sVar5 * ((ushort)uVar7 & 0xff);
  uVar1 = (uint)lut[sVar6] +
          (int)(((int)sVar3 + sVar4 * -0x100) * ((uint)lut[sVar6 + 1] - (uint)lut[sVar6])) /
          ((sVar4 + 1) * 0x100 + sVar4 * -0x100);
  uVar8 = (char)uVar1 +
          (char)((int)(((int)(short)uVar2 + sVar5 * -0x100) *
                      (((uint)lut[(uVar7 & 0xff) + (int)sVar6] +
                        (int)(((int)sVar3 + sVar4 * -0x109) *
                             ((uint)lut[(int)sVar6 + (uVar7 & 0xff) + 1] -
                             (uint)lut[(uVar7 & 0xff) + (int)sVar6])) /
                        ((sVar4 + 1) * 0x100 + sVar4 * -0x109) & 0xff) - (uVar1 & 0xff))) /
                ((sVar5 + 1) * 0x100 + sVar5 * -0x100));
  pop_25to31();
  return uVar8;
}



// Loads TPU microcode from ROM to DPTRAM

void tpu_load_microcode(void)

{
  ushort r;
  
  r = REG_DPTMCR;
  REG_DPTMCR = r & 0xfeff;
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
  REG_TPU3A_CH1_PARAM1 = DAT_003f97c6;
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



// ISR: Crankshaft synchronization - establishes engine position reference

void isr_crank_sync(void)

{
  ushort uVar1;
  
  uVar1 = REG_CISR_A;
  REG_CISR_A = uVar1 & 0xfffe;
  uVar1 = REG_TPU3A_CH15_PARAM6;
  if (((((uVar1 & 0x8000) != 0) && (DAT_003f97ba == '\x02')) && (DAT_003f9704 != 0xff)) &&
     (DAT_003f97c1 != -1)) {
    DAT_003f97c1 = DAT_003f97c1 + '\x01';
  }
  if (DAT_003f9704 == 0xff) {
    REG_TPU3A_CH0_PARAM1 = 0x150;
    REG_TPU3B_CH0_PARAM1 = 0x150;
    DAT_003fd7cc = '\0';
  }
  else {
    if (DAT_003f97c0 == DAT_003fd7cc) {
      if (DAT_003f97ba == '\x02') {
        DAT_003f9704 = 0;
      }
    }
    else if (DAT_003f97ba == '\x02') {
      DAT_003f97c8 = DAT_003f97c8 + 0x10000;
      if ((DAT_003f9704 != 0xff) && (DAT_003f9704 = DAT_003f9704 + 1, DAT_003fc54a <= DAT_003f9704))
      {
        DAT_003f9704 = 0x80;
      }
    }
    else if (DAT_003fd7cc != '\0') {
      DAT_003f9018 = '\x01';
      DAT_003f97c8 = DAT_003f97c8 + 0x1000;
    }
    uVar1 = REG_TPU3A_CH15_PARAM6;
    if (((uVar1 & 0xff00) == 0) && (DAT_003f9018 == '\0')) {
      DAT_003f97c1 = '\0';
      if (DAT_003fd7cc == '\0') {
        if (DAT_003f97c0 == '\x02') {
          REG_TPU3A_CH0_PARAM1 = 0x221;
          REG_TPU3B_CH0_PARAM1 = 0x221;
          DAT_003fd7cc = '\x01';
        }
      }
      else if (DAT_003fd7cc == '\x01') {
        REG_TPU3A_CH0_PARAM1 = 0x243;
        REG_TPU3B_CH0_PARAM1 = 0x243;
        DAT_003fd7cc = '\x02';
        if (DAT_003fd7f4 < 0xffe) {
          DAT_003fd7f4 = DAT_003fd7f4 + 1;
        }
      }
      else {
        REG_TPU3A_CH0_PARAM1 = 0x221;
        REG_TPU3B_CH0_PARAM1 = 0x221;
        DAT_003fd7cc = '\x01';
      }
    }
    else {
      DAT_003f9018 = '\0';
      REG_TPU3A_CH0_PARAM1 = 0x121;
      REG_TPU3B_CH0_PARAM1 = 0x121;
      DAT_003fd7cc = '\0';
    }
  }
  DAT_003f97c0 = 0;
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
    if ((DAT_003f97bc & 1) != 0) {
      uVar2 = REG_CFSR3_A;
      REG_CFSR3_A = uVar2 & 0xff0f;
      uVar2 = REG_CFSR3_A;
      REG_CFSR3_A = uVar2 & 0xff0f | 0xc0;
      REG_TPU3A_CH1_PARAM0 = 0xb02;
      Ram00304118 = DAT_003f81b0;
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
      Ram00304148 = DAT_003f81bc;
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
    if ((DAT_003f97bc & 2) != 0) {
      uVar2 = REG_CFSR3_A;
      REG_CFSR3_A = uVar2 & 0xf0ff;
      uVar2 = REG_CFSR3_A;
      REG_CFSR3_A = uVar2 & 0xf0ff | 0xc00;
      REG_TPU3A_CH2_PARAM0 = 0xb02;
      Ram00304128 = DAT_003f81b4;
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
      Ram00304138 = DAT_003f81b8;
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
    if ((DAT_003f97bc & 4) != 0) {
      uVar2 = REG_CFSR3_A;
      REG_CFSR3_A = uVar2 & 0xfff;
      uVar2 = REG_CFSR3_A;
      REG_CFSR3_A = uVar2 & 0xfff | 0xc000;
      REG_TPU3A_CH3_PARAM0 = 0xb02;
      Ram00304138 = DAT_003f81b8;
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
      Ram00304128 = DAT_003f81b4;
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
    if ((DAT_003f97bc & 8) != 0) {
      uVar2 = REG_CFSR2_A;
      REG_CFSR2_A = uVar2 & 0xfff0;
      uVar2 = REG_CFSR2_A;
      REG_CFSR2_A = uVar2 & 0xfff0 | 0xc;
      uVar2 = REG_HSQR1_A;
      REG_HSQR1_A = uVar2 & 0xfcff | 0x100;
      REG_TPU3A_CH4_PARAM0 = 0xb02;
      Ram00304148 = DAT_003f81bc;
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
      Ram00304118 = DAT_003f81b0;
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
    DAT_003f9004 = 0;
  }
  else {
    DAT_003f9004 = DAT_003f9004 + 1;
    if (1 < DAT_003f9004) {
      DAT_003f9004 = 0;
      Ram00304178 = knock_window_params[DAT_003f901a];
      DAT_003f901a = DAT_003f901a + 1 & 3;
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
  DAT_003f9014 = REG_TPU3A_CH0_PARAM0;
  uVar3 = REG_TPU3A_CH9_PARAM4;
  if ((uVar3 & 0xff) == 0) {
    uVar3 = REG_TPU3A_CH9_PARAM5;
    puVar2 = (undefined *)(uint)uVar3;
    DAT_003f900c = puVar2 + (int)DAT_003f900c;
  }
  else {
    REG_TPU3A_CH9_PARAM4 = 0xff00;
    puVar2 = (undefined *)0xffff;
    engine_speed_period = 65535;
    DAT_003f900c = (undefined *)0x0;
  }
  DAT_003f9016 = uVar4;
  if (DAT_003f8010 != '\0') {
    DAT_003f8010 = '\0';
    init_cranking_injection();
  }
  fuelpump_timer = CAL_ecu_fuelpump_prime;
  uVar3 = (ushort)puVar2;
  if (DAT_003f97ba == '\0') {
    DAT_003f97c8 = 0;
    DAT_003f9704 = 0;
    DAT_003f9019 = '\0';
    DAT_003f97c2 = 0;
    DAT_003f97bc = 0;
    DAT_003f97c4 = 0;
    uVar1 = uVar3;
    if ((puVar2 < &UNK_0000f424) && ((undefined *)((uint)DAT_003f8012 * 0xffff >> 0xf) < puVar2)) {
      DAT_003f97ba = '\x01';
    }
  }
  else {
    uVar1 = DAT_003f8012;
    if (DAT_003f97ba == '\x01') {
      if ((undefined *)((uint)DAT_003f8012 * 0xffff >> 0xf) < puVar2) {
        DAT_003f9019 = '\0';
        DAT_003f97c4 = DAT_003f97c4 + 1;
        DAT_003f97c2 = DAT_003f97c2 + 1;
        if (DAT_003f97c2 == 0x44) {
          DAT_003f97c2 = 0;
        }
        DAT_003f8014 = (ushort)((uint)puVar2 / 3);
        if ((DAT_003f97c2 == 0x22) || (DAT_003f97c2 == 0)) {
          DAT_003f97c4 = 0;
        }
        else {
          DAT_003f97c8 = DAT_003f97c8 + 1;
          if (2 < DAT_003f97c4) {
            DAT_003f97ba = '\0';
          }
        }
      }
      else {
        DAT_003f97c2 = DAT_003f97c2 + 1;
        if (DAT_003f97c2 == 0x44) {
          DAT_003f97c2 = 0;
        }
        DAT_003f8014 = uVar3;
        if (DAT_003f97c2 == 10) {
          if (DAT_003f9019 != '\0') {
            DAT_003f97c2 = 0x2c;
            DAT_003f97c8 = DAT_003f97c8 + 0x10;
          }
        }
        else if (DAT_003f97c2 == 0x2c) {
          if (DAT_003f9019 == '\0') {
            DAT_003f97c8 = DAT_003f97c8 + 0x100;
            if ((DAT_003f9704 != 0xff) && (DAT_003f9704 = DAT_003f9704 + 1, 3 < DAT_003f9704)) {
              DAT_003f9704 = 0x80;
            }
          }
          else {
            DAT_003f9704 = 0;
          }
        }
      }
      DAT_003f8012 = uVar3;
      if (DAT_003f97ba != '\0') {
        schedule_ignition_coils();
        schedule_injection();
        if ((DAT_003f97bc == 0xff) && ((DAT_003f9704 == 0 || (DAT_003f9704 == 0x80)))) {
          if ((DAT_003f9704 == 0x80) ||
             (((ecu_CRC_computed != CAL_ecu_CRC_stored && (dev_unlocked == false)) ||
              (security_flag == true)))) {
            DAT_003f9704 = 0xff;
          }
          DAT_003f97ba = '\x02';
        }
      }
      uVar4 = (ushort)DAT_003f97c2;
      uVar1 = DAT_003f8012;
    }
  }
  DAT_003f8012 = uVar1;
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
      if (DAT_003f96b8 == '\0') {
        spi_pcs2(knock_cyl_i);
      }
      else {
        DAT_003f8270 = knock_cyl_i;
      }
    }
    else {
      knock_read_signal(knock_cyl_i - 1 & 3);
    }
  }
  if ((((uVar4 == 5) || (uVar4 == 0xe)) || (uVar4 == 0x17)) ||
     (((uVar4 == 0x20 || (uVar4 == 0x27)) ||
      ((uVar4 == 0x30 || ((uVar4 == 0x39 || (uVar4 == 0x42)))))))) {
    if (DAT_003f900c < (undefined *)0xffff) {
      if (engine_speed_period == 65535) {
        engine_speed_period = 65534;
      }
      else {
        engine_speed_period = (u16_time_4us)DAT_003f900c;
      }
    }
    else {
      engine_speed_period = 65535;
    }
    DAT_003f900c = (undefined *)0x0;
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
  if (DAT_003f97c0 != -1) {
    DAT_003f97c0 = DAT_003f97c0 + '\x01';
  }
  if (DAT_003f9019 != -1) {
    DAT_003f9019 = DAT_003f9019 + '\x01';
  }
  DAT_003f9010 = REG_TPU3A_CH10_PARAM4;
  DAT_003f9012 = REG_TPU3A_CH0_PARAM5;
  if ((engine_is_running) && (DAT_003f9704 != -0x80)) {
    uVar2 = (uint)DAT_003f9010 - (uint)DAT_003f9014 & 0xffff;
    if (0x7fff < uVar2) {
      DAT_003f9014 = DAT_003f9014 - DAT_003f9012;
      uVar2 = (uint)DAT_003f9010 - (uint)DAT_003f9014 & 0xffff;
      DAT_003f9016 = DAT_003f9016 - 1;
    }
    if (DAT_003f9016 < 0x37) {
      if (DAT_003f9016 < 0x25) {
        if (0x14 < DAT_003f9016) {
          DAT_003f9016 = DAT_003f9016 - 0x15;
        }
      }
      else {
        DAT_003f9016 = DAT_003f9016 - 0x25;
      }
    }
    else {
      DAT_003f9016 = DAT_003f9016 - 0x37;
    }
    vvt_pos = 0xdc - ((short)((uVar2 * 0x28) / (uint)DAT_003f9012) + DAT_003f9016 * 0x28);
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
  ushort adc_out;
  
  adc_out = REG_CISR_A;
  REG_CISR_A = adc_out & 0xbfff;
  maf_adc_history_i = maf_adc_history_i + 1U & 0x1f;
  adc_out = REG_QADCA_RJURR11;
  maf_adc_history[maf_adc_history_i] = adc_out;
  map_adc_history_i = map_adc_history_i + 1U & 0x1f;
  adc_out = REG_QADCA_RJURR10;
  map_adc_history[map_adc_history_i] = adc_out;
  DAT_003f9005 = DAT_003f9005 + 1;
  if (1 < DAT_003f9005) {
    DAT_003f9005 = 0;
    Ram003041e8 = (&PTR_DAT_000786b8)[(int)maf_adc_history_i / 2];
    adc_out = REG_HSRR0_A;
    REG_HSRR0_A = adc_out & 0xcfff | 0x2000;
    do {
      adc_out = REG_HSRR0_A;
    } while (adc_out != 0);
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
              LEA_misfire_count[bVar5] = (uint16_t)((int)(uint)misfire_count[bVar5] >> 1);
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
  
  iVar2 = (int)ign_adv_final + ((uint)ign_dwell_time * 0x28) / (uint)DAT_003f8014 + 0x27;
  iVar2 = iVar2 / 0x28 + (iVar2 >> 0x1f);
  DAT_003f97c5 = (char)iVar2 - (char)(iVar2 >> 0x1f);
  if ((((uint)DAT_003f97c2 == 0x37 - DAT_003f97c5) || ((uint)DAT_003f97c2 == 0x15 - DAT_003f97c5))
     && ((DAT_003f97bc & 1) == 0)) {
    iVar2 = (uint)DAT_003f8014 * (((uint)DAT_003f97c5 * 0x28 - (int)ign_adv_final) + 0x14);
    iVar2 = iVar2 / 0x28 + (iVar2 >> 0x1f);
    DAT_003f97c6 = (short)iVar2 - (short)(iVar2 >> 0x1f);
    uVar1 = REG_CFSR3_A;
    REG_CFSR3_A = uVar1 & 0xff0f;
    uVar1 = REG_CFSR3_A;
    REG_CFSR3_A = uVar1 & 0xff0f | 0xe0;
    uVar1 = REG_HSQR1_A;
    REG_HSQR1_A = uVar1 & 0xfff3;
    REG_TPU3A_CH1_PARAM0 = 0x89;
    REG_TPU3A_CH1_PARAM1 = DAT_003f97c6;
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
    REG_TPU3A_CH4_PARAM1 = DAT_003f97c6;
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
      DAT_003f97bc = DAT_003f97bc | 9;
    }
  }
  else {
    if (3 < DAT_003f97c5) {
      DAT_003f97c5 = 3;
    }
    if ((((uint)DAT_003f97c2 == 3 - DAT_003f97c5) || ((uint)DAT_003f97c2 == 0x25 - DAT_003f97c5)) &&
       ((DAT_003f97bc & 4) == 0)) {
      iVar2 = (uint)DAT_003f8014 * (((uint)DAT_003f97c5 * 0x28 - (int)ign_adv_final) + 0x14);
      iVar2 = iVar2 / 0x28 + (iVar2 >> 0x1f);
      DAT_003f97c6 = (short)iVar2 - (short)(iVar2 >> 0x1f);
      uVar1 = REG_CFSR3_A;
      REG_CFSR3_A = uVar1 & 0xf0ff;
      uVar1 = REG_CFSR3_A;
      REG_CFSR3_A = uVar1 & 0xf0ff | 0xe00;
      REG_TPU3A_CH2_PARAM0 = 0x89;
      REG_TPU3A_CH2_PARAM1 = DAT_003f97c6;
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
      REG_TPU3A_CH3_PARAM1 = DAT_003f97c6;
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
        DAT_003f97bc = DAT_003f97bc | 6;
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



// Sets cylinder 1 injector pulse width

void set_injector1_time(ushort param_1)

{
  ushort uVar1;
  
  if (param_1 < 0x8000) {
    DAT_003f9876 = 0;
  }
  else {
    DAT_003f9876 = param_1 + 0x8001;
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
    DAT_003f9878 = 0;
  }
  else {
    DAT_003f9878 = param_1 + 0x8001;
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
    DAT_003f987a = 0;
  }
  else {
    DAT_003f987a = param_1 + 0x8001;
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
    DAT_003f987c = 0;
  }
  else {
    DAT_003f987c = param_1 + 0x8001;
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
  if ((DAT_003f97bc & 0x10) == 0) {
    uVar1 = REG_CIER_B;
    REG_CIER_B = uVar1 & 0xfbff;
    uVar1 = REG_CIER_B;
    REG_CIER_B = uVar1 | 2;
    inj_active_cyl[3] = true;
    DAT_003f9024 = inj_angle_2;
    if (DAT_003f97b0 != 0) {
      DAT_003f97b0 = DAT_003f97b0 + -1;
    }
    if (DAT_003f9858 != 0) {
      REG_TPU3B_CH1_PARAM3 = DAT_003f9858;
      uVar1 = REG_HSRR1_B;
      REG_HSRR1_B = uVar1 & 0xfff3 | 4;
      do {
        uVar1 = REG_HSRR1_B;
      } while (uVar1 != 0);
      DAT_003f9858 = 0;
    }
  }
  else {
    if (inj_active_cyl[3]) {
      inj_active_cyl[3] = false;
      DAT_003f902c = 0;
      uVar1 = REG_CISR_B;
      REG_CISR_B = uVar1 & 0xfbff;
      uVar1 = REG_CFSR1_B;
      REG_CFSR1_B = uVar1 & 0xf0ff;
      uVar1 = REG_CFSR1_B;
      REG_CFSR1_B = uVar1 & 0xf0ff | 0xc00;
      uVar1 = REG_HSQR0_B;
      REG_HSQR0_B = uVar1 & 0xffcf | 0x10;
      REG_TPU3B_CH10_PARAM0 = 0xb02;
      DAT_003f9024 = inj_angle_2;
      DAT_003f9030 = inj_angle_2 + 57;
      if (0x47 < DAT_003f9030) {
        DAT_003f9030 = inj_angle_2 - 15;
      }
      REG_TPU3B_CH10_PARAM4 = (ushort)(&PTR_DAT_000786f8)[DAT_003f9030];
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
    if (DAT_003f9876 != 0) {
      set_injector1_time(DAT_003f9876);
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
  if ((DAT_003f97bc & 0x20) == 0) {
    uVar1 = REG_CIER_B;
    REG_CIER_B = uVar1 & 0xf7ff;
    uVar1 = REG_CIER_B;
    REG_CIER_B = uVar1 | 4;
    inj_active_cyl[2] = true;
    DAT_003f9026 = inj_angle_2;
    if (DAT_003f97b0 != 0) {
      DAT_003f97b0 = DAT_003f97b0 + -1;
    }
    if (DAT_003f9870 != 0) {
      REG_TPU3B_CH2_PARAM3 = DAT_003f9870;
      uVar1 = REG_HSRR1_B;
      REG_HSRR1_B = uVar1 & 0xffcf | 0x10;
      do {
        uVar1 = REG_HSRR1_B;
      } while (uVar1 != 0);
      DAT_003f9870 = 0;
    }
  }
  else {
    if (inj_active_cyl[2]) {
      inj_active_cyl[2] = false;
      DAT_003f902d = 0;
      uVar1 = REG_CISR_B;
      REG_CISR_B = uVar1 & 0xf7ff;
      uVar1 = REG_CFSR1_B;
      REG_CFSR1_B = uVar1 & 0xfff;
      uVar1 = REG_CFSR1_B;
      REG_CFSR1_B = uVar1 & 0xfff | 0xc000;
      uVar1 = REG_HSQR0_B;
      REG_HSQR0_B = uVar1 & 0xff3f | 0x40;
      REG_TPU3B_CH11_PARAM0 = 0xb02;
      DAT_003f9026 = inj_angle_2;
      DAT_003f9030 = inj_angle_2 + 39;
      if (0x47 < DAT_003f9030) {
        DAT_003f9030 = inj_angle_2 - 33;
      }
      REG_TPU3B_CH11_PARAM4 = (ushort)(&PTR_DAT_000786f8)[DAT_003f9030];
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
    if (DAT_003f9878 != 0) {
      set_injector2_time(DAT_003f9878);
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
  if ((DAT_003f97bc & 0x40) == 0) {
    uVar1 = REG_CIER_B;
    REG_CIER_B = uVar1 & 0xefff;
    uVar1 = REG_CIER_B;
    REG_CIER_B = uVar1 | 8;
    inj_active_cyl[1] = true;
    DAT_003f9028 = inj_angle_2;
    if (DAT_003f97b0 != 0) {
      DAT_003f97b0 = DAT_003f97b0 + -1;
    }
    if (DAT_003f9872 != 0) {
      REG_TPU3B_CH3_PARAM3 = DAT_003f9872;
      uVar1 = REG_HSRR1_B;
      REG_HSRR1_B = uVar1 & 0xff3f | 0x40;
      do {
        uVar1 = REG_HSRR1_B;
      } while (uVar1 != 0);
      DAT_003f9872 = 0;
    }
  }
  else {
    if (inj_active_cyl[1]) {
      inj_active_cyl[1] = false;
      DAT_003f902e = 0;
      uVar1 = REG_CISR_B;
      REG_CISR_B = uVar1 & 0xefff;
      uVar1 = REG_CFSR0_B;
      REG_CFSR0_B = uVar1 & 0xfff0;
      uVar1 = REG_CFSR0_B;
      REG_CFSR0_B = uVar1 & 0xfff0 | 0xc;
      uVar1 = REG_HSQR0_B;
      REG_HSQR0_B = uVar1 & 0xfcff | 0x100;
      REG_TPU3B_CH12_PARAM0 = 0xb02;
      DAT_003f9028 = inj_angle_2;
      DAT_003f9030 = inj_angle_2 + 3;
      if (0x47 < DAT_003f9030) {
        DAT_003f9030 = inj_angle_2 - 69;
      }
      REG_TPU3B_CH12_PARAM4 = (ushort)(&PTR_DAT_000786f8)[DAT_003f9030];
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
    if (DAT_003f987a != 0) {
      set_injector3_time(DAT_003f987a);
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
  if ((DAT_003f97bc & 0x80) == 0) {
    uVar1 = REG_CIER_B;
    REG_CIER_B = uVar1 & 0xdfff;
    uVar1 = REG_CIER_B;
    REG_CIER_B = uVar1 | 8;
    inj_active_cyl[0] = true;
    DAT_003f902a = inj_angle_2;
    if (DAT_003f97b0 != 0) {
      DAT_003f97b0 = DAT_003f97b0 + -1;
    }
    if (DAT_003f9874 != 0) {
      REG_TPU3B_CH4_PARAM3 = DAT_003f9874;
      uVar1 = REG_HSRR1_B;
      REG_HSRR1_B = uVar1 & 0xfcff | 0x100;
      do {
        uVar1 = REG_HSRR1_B;
      } while (uVar1 != 0);
      DAT_003f9874 = 0;
    }
  }
  else {
    if (inj_active_cyl[0]) {
      inj_active_cyl[0] = false;
      DAT_003f902f = 0;
      uVar1 = REG_CISR_B;
      REG_CISR_B = uVar1 & 0xdfff;
      uVar1 = REG_CFSR0_B;
      REG_CFSR0_B = uVar1 & 0xff0f;
      uVar1 = REG_CFSR0_B;
      REG_CFSR0_B = uVar1 & 0xff0f | 0xc0;
      uVar1 = REG_HSQR0_B;
      REG_HSQR0_B = uVar1 & 0xf3ff | 0x400;
      REG_TPU3B_CH13_PARAM0 = 0xb02;
      DAT_003f902a = inj_angle_2;
      DAT_003f9030 = inj_angle_2 + 21;
      if (0x47 < DAT_003f9030) {
        DAT_003f9030 = inj_angle_2 - 51;
      }
      REG_TPU3B_CH13_PARAM4 = (ushort)(&PTR_DAT_000786f8)[DAT_003f9030];
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
    if (DAT_003f987c != 0) {
      set_injector4_time(DAT_003f987c);
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
  uVar1 = (int)((int)(short)DAT_003f9024 & 0xff00U) >> 8;
  uVar2 = DAT_003f9024 & 0xff;
  DAT_003f902c = DAT_003f902c + 1;
  if (DAT_003f902c < 2) {
    DAT_003f9032 = DAT_003f9032 + 1;
    if (engine_is_running) {
      if (((((revlimit_flags & 0x10) == 0) && ((misfire_flags & 0x40) == 0)) &&
          (DAT_003fd9f7 != '\0')) && ((DAT_003f9032 < tc_fuelcut || (tc_fuelcut == 0xff)))) {
        set_injector1_time(inj_time_final_2);
      }
      else {
        if (tc_fuelcut <= DAT_003f9032) {
          DAT_003f9032 = 0;
        }
        set_injector1_time(200);
      }
      if ((short)(DAT_003f9024 & 0xff) < (short)inj_angle_2) {
        uVar3 = uVar1 + 0x80;
        if ((uVar1 + 0x80 & 0xff) < 0x80) {
          uVar2 = uVar2 + 1;
          uVar3 = uVar1 + 0x100;
        }
      }
      else if ((short)inj_angle_2 < (short)(DAT_003f9024 & 0xff)) {
        uVar3 = uVar1 - 0x80;
        if ((uVar1 - 0x80 & 0xff) < 0x80) {
          uVar2 = uVar2 - 1;
          uVar3 = uVar1;
        }
      }
      else {
        uVar3 = 0x80;
      }
      DAT_003f9024 = (ushort)((uVar3 & 0xff) << 8) | uVar2 & 0xff;
    }
  }
  else {
    DAT_003f902c = 0;
    DAT_003f9030 = (DAT_003f9024 & 0xff) + 0x39;
    if (0x47 < DAT_003f9030) {
      DAT_003f9030 = (DAT_003f9024 & 0xff) - 0xf;
    }
    if (ecu_runtime < 200) {
      Ram003045a8 = ((int)(short)DAT_003f9024 & 0xff00U) * 0x10000 +
                    ((uint)(&PTR_DAT_000786f8)[(short)DAT_003f9030] & 0xff) * 0x10000 + 3000;
      uVar2 = REG_HSRR0_B;
      REG_HSRR0_B = uVar2 & 0xffcf | 0x20;
    }
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
  uVar1 = (int)((int)(short)DAT_003f9026 & 0xff00U) >> 8;
  uVar2 = DAT_003f9026 & 0xff;
  DAT_003f902d = DAT_003f902d + 1;
  if (DAT_003f902d < 2) {
    DAT_003f9032 = DAT_003f9032 + 1;
    if (engine_is_running) {
      if (((((revlimit_flags & 0x10) == 0) && ((misfire_flags & 0x80) == 0)) &&
          (DAT_003fd9f8 != '\0')) && ((DAT_003f9032 < tc_fuelcut || (tc_fuelcut == 0xff)))) {
        set_injector2_time(inj_time_final_2);
        DAT_003f987e = inj_time_final_2;
      }
      else {
        if (tc_fuelcut <= DAT_003f9032) {
          DAT_003f9032 = 0;
        }
        set_injector2_time(200);
        DAT_003f987e = 200;
      }
      if ((short)(DAT_003f9026 & 0xff) < (short)inj_angle_2) {
        uVar3 = uVar1 + 0x80;
        if ((uVar1 + 0x80 & 0xff) < 0x80) {
          uVar2 = uVar2 + 1;
          uVar3 = uVar1 + 0x100;
        }
      }
      else if ((short)inj_angle_2 < (short)(DAT_003f9026 & 0xff)) {
        uVar3 = uVar1 - 0x80;
        if ((uVar1 - 0x80 & 0xff) < 0x80) {
          uVar2 = uVar2 - 1;
          uVar3 = uVar1;
        }
      }
      else {
        uVar3 = 0x80;
      }
      DAT_003f9026 = (ushort)((uVar3 & 0xff) << 8) | uVar2 & 0xff;
    }
  }
  else {
    DAT_003f902d = 0;
    DAT_003f9030 = (DAT_003f9026 & 0xff) + 0x27;
    if (0x47 < DAT_003f9030) {
      DAT_003f9030 = (DAT_003f9026 & 0xff) - 0x21;
    }
    Ram003045b8 = ((int)(short)DAT_003f9026 & 0xff00U) * 0x10000 +
                  ((uint)(&PTR_DAT_000786f8)[(short)DAT_003f9030] & 0xff) * 0x10000 + 3000;
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
  uVar1 = (int)((int)(short)DAT_003f9028 & 0xff00U) >> 8;
  uVar2 = DAT_003f9028 & 0xff;
  DAT_003f902e = DAT_003f902e + 1;
  if (DAT_003f902e < 2) {
    DAT_003f9032 = DAT_003f9032 + 1;
    if (engine_is_running) {
      if (((((revlimit_flags & 0x10) == 0) && ((misfire_flags & 0x100) == 0)) &&
          (DAT_003fd9f9 != '\0')) && ((DAT_003f9032 < tc_fuelcut || (tc_fuelcut == 0xff)))) {
        set_injector3_time(inj_time_final_2);
      }
      else {
        if (tc_fuelcut <= DAT_003f9032) {
          DAT_003f9032 = 0;
        }
        set_injector3_time(200);
      }
      if ((short)(DAT_003f9028 & 0xff) < (short)inj_angle_2) {
        uVar3 = uVar1 + 0x80;
        if ((uVar1 + 0x80 & 0xff) < 0x80) {
          uVar2 = uVar2 + 1;
          uVar3 = uVar1 + 0x100;
        }
      }
      else if ((short)inj_angle_2 < (short)(DAT_003f9028 & 0xff)) {
        uVar3 = uVar1 - 0x80;
        if ((uVar1 - 0x80 & 0xff) < 0x80) {
          uVar2 = uVar2 - 1;
          uVar3 = uVar1;
        }
      }
      else {
        uVar3 = 0x80;
      }
      DAT_003f9028 = (ushort)((uVar3 & 0xff) << 8) | uVar2 & 0xff;
    }
  }
  else {
    DAT_003f902e = 0;
    DAT_003f9030 = (DAT_003f9028 & 0xff) + 3;
    if (0x47 < DAT_003f9030) {
      DAT_003f9030 = (DAT_003f9028 & 0xff) - 0x45;
    }
    Ram003045c8 = ((int)(short)DAT_003f9028 & 0xff00U) * 0x10000 +
                  ((uint)(&PTR_DAT_000786f8)[(short)DAT_003f9030] & 0xff) * 0x10000 + 3000;
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
  uVar1 = (int)((int)(short)DAT_003f902a & 0xff00U) >> 8;
  uVar2 = DAT_003f902a & 0xff;
  DAT_003f902f = DAT_003f902f + 1;
  if (DAT_003f902f < 2) {
    DAT_003f9032 = DAT_003f9032 + 1;
    if (engine_is_running) {
      if (((((revlimit_flags & 0x10) == 0) && ((misfire_flags & 0x200) == 0)) &&
          (DAT_003fd9fa != '\0')) && ((DAT_003f9032 < tc_fuelcut || (tc_fuelcut == 0xff)))) {
        set_injector4_time(inj_time_final_2);
      }
      else {
        if (tc_fuelcut <= DAT_003f9032) {
          DAT_003f9032 = 0;
        }
        set_injector4_time(200);
      }
      if ((short)(DAT_003f902a & 0xff) < (short)inj_angle_2) {
        uVar3 = uVar1 + 0x80;
        if ((uVar1 + 0x80 & 0xff) < 0x80) {
          uVar2 = uVar2 + 1;
          uVar3 = uVar1 + 0x100;
        }
      }
      else if ((short)inj_angle_2 < (short)(DAT_003f902a & 0xff)) {
        uVar3 = uVar1 - 0x80;
        if ((uVar1 - 0x80 & 0xff) < 0x80) {
          uVar2 = uVar2 - 1;
          uVar3 = uVar1;
        }
      }
      else {
        uVar3 = 0x80;
      }
      DAT_003f902a = (ushort)((uVar3 & 0xff) << 8) | uVar2 & 0xff;
    }
  }
  else {
    DAT_003f902f = 0;
    DAT_003f9030 = (DAT_003f902a & 0xff) + 0x15;
    if (0x47 < DAT_003f9030) {
      DAT_003f9030 = (DAT_003f902a & 0xff) - 0x33;
    }
    Ram003045d8 = ((int)(short)DAT_003f902a & 0xff00U) * 0x10000 +
                  ((uint)(&PTR_DAT_000786f8)[(short)DAT_003f9030] & 0xff) * 0x10000 + 3000;
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
  
  DAT_003f9030 = inj_angle_2 + 57;
  if (0x47 < DAT_003f9030) {
    DAT_003f9030 = inj_angle_2 - 15;
  }
  iVar3 = (int)DAT_003f9030;
  DAT_003f9020 = (char)(&PTR_DAT_000786f8)[iVar3];
  DAT_003f9030 = inj_angle_2 + 39;
  if (0x47 < DAT_003f9030) {
    DAT_003f9030 = inj_angle_2 - 33;
  }
  iVar4 = (int)DAT_003f9030;
  DAT_003f9021 = (char)(&PTR_DAT_000786f8)[iVar4];
  DAT_003f9030 = inj_angle_2 + 3;
  if (0x47 < DAT_003f9030) {
    DAT_003f9030 = inj_angle_2 - 69;
  }
  iVar2 = (int)DAT_003f9030;
  DAT_003f9022 = (char)(&PTR_DAT_000786f8)[iVar2];
  DAT_003f9030 = inj_angle_2 + 21;
  if (0x47 < DAT_003f9030) {
    DAT_003f9030 = inj_angle_2 - 51;
  }
  DAT_003f9023 = (char)(&PTR_DAT_000786f8)[DAT_003f9030];
  if (((DAT_003f97c2 == (char)(&PTR_DAT_000786f8)[iVar3]) && ((DAT_003f97bc & 0x10) == 0)) &&
     (DAT_003f97b0 == 0)) {
    if (0x7fff < inj_time_final_2) {
      DAT_003f9858 = inj_time_final_2 + 32769;
      inj_time_final_2 = 32767;
    }
    REG_TPU3B_CH1_PARAM1 = inj_time_final_2;
    uVar1 = REG_HSRR1_B;
    REG_HSRR1_B = uVar1 & 0xfff3 | 4;
    do {
      uVar1 = REG_HSRR1_B;
    } while (uVar1 != 0);
    if (engine_is_running) {
      DAT_003f97bc = DAT_003f97bc | 0x10;
    }
  }
  else if (((DAT_003f97c2 == (char)(&PTR_DAT_000786f8)[iVar4]) && ((DAT_003f97bc & 0x20) == 0)) &&
          (DAT_003f97b0 == 0)) {
    if (0x7fff < inj_time_final_2) {
      DAT_003f9870 = inj_time_final_2 + 32769;
      inj_time_final_2 = 32767;
    }
    REG_TPU3B_CH2_PARAM1 = inj_time_final_2;
    uVar1 = REG_HSRR1_B;
    REG_HSRR1_B = uVar1 & 0xffcf | 0x10;
    do {
      uVar1 = REG_HSRR1_B;
    } while (uVar1 != 0);
    if (engine_is_running) {
      DAT_003f97bc = DAT_003f97bc | 0x20;
    }
  }
  else if (((DAT_003f97c2 == (char)(&PTR_DAT_000786f8)[iVar2]) && ((DAT_003f97bc & 0x40) == 0)) &&
          (DAT_003f97b0 == 0)) {
    if (0x7fff < inj_time_final_2) {
      DAT_003f9872 = inj_time_final_2 + 32769;
      inj_time_final_2 = 32767;
    }
    REG_TPU3B_CH3_PARAM1 = inj_time_final_2;
    uVar1 = REG_HSRR1_B;
    REG_HSRR1_B = uVar1 & 0xff3f | 0x40;
    do {
      uVar1 = REG_HSRR1_B;
    } while (uVar1 != 0);
    if (engine_is_running) {
      DAT_003f97bc = DAT_003f97bc | 0x40;
    }
  }
  else if (((DAT_003f97c2 == (char)(&PTR_DAT_000786f8)[DAT_003f9030]) &&
           ((DAT_003f97bc & 0x80) == 0)) && (DAT_003f97b0 == 0)) {
    if (0x7fff < inj_time_final_2) {
      DAT_003f9874 = inj_time_final_2 + 32769;
      inj_time_final_2 = 32767;
    }
    REG_TPU3B_CH4_PARAM1 = inj_time_final_2;
    uVar1 = REG_HSRR1_B;
    REG_HSRR1_B = uVar1 & 0xfcff | 0x100;
    do {
      uVar1 = REG_HSRR1_B;
    } while (uVar1 != 0);
    if (engine_is_running) {
      DAT_003f97bc = DAT_003f97bc | 0x80;
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
                    // Speed = 40 Mhz / (39+1) / (1+4+1+6+1+7+1) = 47.6 kbit/s
  REG_CANCTRL0_B = 0;
  REG_CANCTRL1_B = 4;
  REG_CTRL2_B = 0xf7;
  REG_PRESDIV_B = 0x27;
  REG_CANB_MB0_CS = 0;
  REG_CANB_MB0_ID_HI = 0;
  REG_CANB_MB0_ID_LO = 0;
  uVar1 = REG_CANB_MB0_CS;
  REG_CANB_MB0_CS = uVar1 | 0x80;
  REG_CANB_MB1_CS = 0;
  REG_CANB_MB1_ID_HI = 0xf800;
  REG_CANB_MB1_ID_LO = 0;
  uVar1 = REG_CANB_MB1_CS;
  REG_CANB_MB1_CS = uVar1 | 0x40;
  REG_CANB_MB2_CS = 0;
  REG_CANB_MB2_ID_HI = 0;
  REG_CANB_MB2_ID_LO = 0;
  uVar1 = REG_CANB_MB2_CS;
  REG_CANB_MB2_CS = uVar1 | 0x40;
  REG_CANB_MB3_CS = 0;
  REG_CANB_MB3_ID_HI = 0x8c00;
  REG_CANB_MB3_ID_LO = 0;
  uVar1 = REG_CANB_MB3_CS;
  REG_CANB_MB3_CS = uVar1 | 0x40;
  REG_CANB_MB4_CS = 0;
  REG_CANB_MB4_ID_HI = 0xf400;
  REG_CANB_MB4_ID_LO = 0;
  uVar1 = REG_CANB_MB4_CS;
  REG_CANB_MB4_CS = uVar1 | 0x40;
  REG_CANB_MB5_CS = 0;
  REG_CANB_MB5_ID_HI = 0xa800;
  REG_CANB_MB5_ID_LO = 0;
  uVar1 = REG_CANB_MB5_CS;
  REG_CANB_MB5_CS = uVar1 | 0x40;
  REG_CANB_MB6_CS = 0;
  REG_CANB_MB6_ID_HI = 0;
  REG_CANB_MB6_ID_LO = 0;
  uVar1 = REG_CANB_MB6_CS;
  REG_CANB_MB6_CS = uVar1 | 0x80;
  REG_CANB_MB7_CS = 0;
  REG_CANB_MB7_ID_HI = 0x4ac0;
  REG_CANB_MB7_ID_LO = 0;
  uVar1 = REG_CANB_MB7_CS;
  REG_CANB_MB7_CS = uVar1 | 0x40;
  REG_CANB_MB8_CS = 0;
  REG_CANB_MB8_ID_HI = 0x4c80;
  REG_CANB_MB8_ID_LO = 0;
  uVar1 = REG_CANB_MB8_CS;
  REG_CANB_MB8_CS = uVar1 | 0x40;
  REG_CANB_MB9_CS = 0;
  REG_CANB_MB9_ID_HI = 44000;
  REG_CANB_MB9_ID_LO = 0;
  uVar1 = REG_CANB_MB9_CS;
  REG_CANB_MB9_CS = uVar1 | 0x40;
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
  if (CAL_tpms_use_tpms) {
    REG_IMASK_B = 0x2f8;
  }
  else {
    REG_IMASK_B = 0;
  }
  uVar1 = REG_CANMCR_B;
  REG_CANMCR_B = uVar1 & 0xefff;
  return;
}



// CAN-B MB00: Unused message buffer

void can_b_mb00_unused(void)

{
  ushort uVar1;
  
  uVar1 = REG_CANB_MB0_CS;
  uVar1 = REG_IFLAG_B;
  REG_IFLAG_B = uVar1 & 0xfffe;
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



// CAN-B MB03: Unused message buffer

void can_b_mb03_unused(void)

{
  ushort uVar1;
  
  uVar1 = REG_CANB_MB3_CS;
  uVar1 = REG_IFLAG_B;
  REG_IFLAG_B = uVar1 & 0xfff7;
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



// CAN-B: Receives TPMS pressure data

void can_b_mb05_recv_tpms_pressure(void)

{
  ushort uVar1;
  byte bVar2;
  
  uVar1 = REG_IFLAG_B;
  REG_IFLAG_B = uVar1 & 0xffdf;
  do {
    uVar1 = REG_CANB_MB5_CS;
  } while ((uVar1 & 0x10) != 0);
  uVar1 = REG_CANB_MB5_CS;
  if ((uVar1 & 0x60) == 0x60) {
    REG_CANB_MB5_CS = 0;
    REG_CANB_MB5_ID_HI = 0xa800;
    uVar1 = REG_CANB_MB5_CS;
    REG_CANB_MB5_CS = uVar1 | 0x40;
  }
  else {
    uVar1 = REG_CANB_MB5_CS;
    if ((uVar1 & 0x20) != 0) {
      bVar2 = REG_CANB_MB5_DATA0;
      if ((bVar2 & 0x70) == 0x20) {
        tpms_flags = tpms_flags | 0x10;
      }
      else {
        tpms_flags = tpms_flags & 0xffef;
      }
      bVar2 = REG_CANB_MB5_DATA0;
      if ((bVar2 & 7) == 2) {
        tpms_flags = tpms_flags | 0x20;
      }
      else {
        tpms_flags = tpms_flags & 0xffdf;
      }
      bVar2 = REG_CANB_MB5_DATA1;
      if ((bVar2 & 0x70) == 0x20) {
        tpms_flags = tpms_flags | 0x40;
      }
      else {
        tpms_flags = tpms_flags & 0xffbf;
      }
      bVar2 = REG_CANB_MB5_DATA1;
      if ((bVar2 & 7) == 2) {
        tpms_flags = tpms_flags | 0x80;
      }
      else {
        tpms_flags = tpms_flags & 0xff7f;
      }
      bVar2 = REG_CANB_MB5_DATA0;
      if ((bVar2 & 0x80) == 0) {
        tpms_flags = tpms_flags & 0xfffe;
      }
      else {
        tpms_flags = tpms_flags | 1;
      }
      bVar2 = REG_CANB_MB5_DATA0;
      if ((bVar2 & 8) == 0) {
        tpms_flags = tpms_flags & 0xfffd;
      }
      else {
        tpms_flags = tpms_flags | 2;
      }
      bVar2 = REG_CANB_MB5_DATA1;
      if ((bVar2 & 0x80) == 0) {
        tpms_flags = tpms_flags & 0xfffb;
      }
      else {
        tpms_flags = tpms_flags | 4;
      }
      bVar2 = REG_CANB_MB5_DATA1;
      if ((bVar2 & 8) == 0) {
        tpms_flags = tpms_flags & 0xfff7;
      }
      else {
        tpms_flags = tpms_flags | 8;
      }
      if ((tpms_flags & 1) == 0) {
        tpms_pressure_fl = REG_CANB_MB5_DATA2;
      }
      else {
        tpms_pressure_fl = 0;
      }
      if ((tpms_flags & 2) == 0) {
        tpms_pressure_fr = REG_CANB_MB5_DATA3;
      }
      else {
        tpms_pressure_fr = 0;
      }
      if ((tpms_flags & 4) == 0) {
        tpms_pressure_rl = REG_CANB_MB5_DATA4;
      }
      else {
        tpms_pressure_rl = 0;
      }
      if ((tpms_flags & 8) == 0) {
        tpms_pressure_rr = REG_CANB_MB5_DATA5;
      }
      else {
        tpms_pressure_rr = 0;
      }
      bVar2 = REG_CANB_MB5_DATA6;
      if ((bVar2 & 0x80) == 0) {
        tpms_flags = tpms_flags & 0xfeff;
      }
      else {
        tpms_flags = tpms_flags | 0x100;
      }
    }
  }
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



// CAN-B: Receives TPMS diagnostic messages

void can_b_mb07_recv_tpms_diag(void)

{
  ushort uVar1;
  uint uVar2;
  byte bVar3;
  
  uVar1 = REG_IFLAG_B;
  REG_IFLAG_B = uVar1 & 0xff7f;
  uVar1 = REG_CANB_MB7_CS;
  while ((uVar1 & 0x10) != 0) {
    uVar1 = REG_CANB_MB7_CS;
  }
  uVar1 = REG_CANB_MB7_CS;
  if ((uVar1 & 0x60) == 0x60) {
    REG_CANB_MB7_CS = 0x40;
  }
  else {
    uVar1 = REG_CANB_MB7_CS;
    if ((uVar1 & 0x20) != 0) {
      bVar3 = REG_CANB_MB7_DATA0;
      if (((bVar3 & 0xf0) == 0xc0) && (bVar3 = REG_CANB_MB7_DATA0, (bVar3 & 0xf) != 0)) {
        for (bVar3 = 0; bVar3 < 6; bVar3 = bVar3 + 1) {
          (&DAT_003fe34d)[bVar3] = (&REG_CANB_MB7_DATA2)[bVar3];
        }
        DAT_003f9038 = 1;
        can_b_tpms_status();
        DAT_003f9880 = '\0';
      }
      else if ((DAT_003f9038 == 0) || (bVar3 = REG_CANB_MB7_DATA0, (bVar3 & 0xf0) != 0x80)) {
        DAT_003f9038 = 0;
        for (bVar3 = 0; bVar3 < 6; bVar3 = bVar3 + 1) {
          (&DAT_003fe34d)[bVar3] = (&REG_CANB_MB7_DATA2)[bVar3];
        }
        DAT_003f9880 = '\x01';
        can_b_tpms_status();
      }
      else {
        uVar2 = (uint)DAT_003f9038 * 6 & 0xff;
        for (bVar3 = 0; bVar3 < 6; bVar3 = bVar3 + 1) {
          (&DAT_003fe34d)[uVar2 & 0xff] = (&REG_CANB_MB7_DATA2)[bVar3];
          uVar2 = uVar2 + 1;
        }
        DAT_003f9038 = DAT_003f9038 + 1;
        bVar3 = REG_CANB_MB7_DATA0;
        DAT_003f9880 = (bVar3 & 0xf) == 0;
        if ((bool)DAT_003f9880) {
          DAT_003f9038 = 0;
        }
        can_b_tpms_status();
      }
    }
  }
  REG_CANB_MB7_CS = 0;
  REG_CANB_MB7_ID_HI = 0x4ac0;
  uVar1 = REG_CANB_MB7_CS;
  REG_CANB_MB7_CS = uVar1 | 0x40;
  if ((DAT_003f9880 != '\0') && (DAT_003fe34e == 'X')) {
    DAT_003fe2cb = DAT_003fe34f;
    if (DAT_003fe34f != '\0') {
      for (bVar3 = 0; bVar3 < 5; bVar3 = bVar3 + 1) {
        (&DAT_003fe3ce)[bVar3] = *(undefined2 *)(&DAT_003fe34d + (byte)(bVar3 * '\x03' + 3));
      }
    }
    if (obd_mode_0x13_state != '\0') {
      obd_mode_0x13_state = '\x02';
    }
    DAT_003f9880 = '\0';
  }
  return;
}



// CAN-B MB08: Unused message buffer

void can_b_mb08_unused(void)

{
  ushort uVar1;
  
  uVar1 = REG_CANB_MB8_CS;
  uVar1 = REG_IFLAG_B;
  REG_IFLAG_B = uVar1 & 0xfeff;
  return;
}



// CAN-B: Receives TPMS sensor ID messages

void can_b_mb09_recv_tpms_sensor(void)

{
  ushort uVar1;
  byte bVar2;
  byte bVar3;
  
  uVar1 = REG_IFLAG_B;
  REG_IFLAG_B = uVar1 & 0xfdff;
  uVar1 = REG_CANB_MB9_CS;
  while ((uVar1 & 0x10) != 0) {
    uVar1 = REG_CANB_MB9_CS;
  }
  uVar1 = REG_CANB_MB9_CS;
  if ((uVar1 & 0x60) == 0x60) {
    REG_CANB_MB9_CS = 0x40;
  }
  else {
    uVar1 = REG_CANB_MB9_CS;
    if ((uVar1 & 0x20) != 0) {
      bVar2 = REG_CANB_MB9_DATA0;
      if (bVar2 == 0x27) {
        bVar2 = REG_CANB_MB9_DATA1;
        switch(bVar2) {
        case 0:
          bVar2 = REG_CANB_MB9_DATA6;
          bVar3 = REG_CANB_MB9_DATA7;
          DAT_003f9882 = CONCAT11(bVar2,bVar3);
          break;
        case 1:
          bVar2 = REG_CANB_MB9_DATA6;
          bVar3 = REG_CANB_MB9_DATA7;
          DAT_003f9884 = CONCAT11(bVar2,bVar3);
          break;
        case 2:
          bVar2 = REG_CANB_MB9_DATA6;
          bVar3 = REG_CANB_MB9_DATA7;
          DAT_003f9886 = CONCAT11(bVar2,bVar3);
          break;
        case 3:
          bVar2 = REG_CANB_MB9_DATA6;
          bVar3 = REG_CANB_MB9_DATA7;
          DAT_003f9888 = CONCAT11(bVar2,bVar3);
          break;
        case 4:
          bVar2 = REG_CANB_MB9_DATA6;
          bVar3 = REG_CANB_MB9_DATA7;
          DAT_003f988a = CONCAT11(bVar2,bVar3);
          break;
        case 5:
          bVar2 = REG_CANB_MB9_DATA6;
          bVar3 = REG_CANB_MB9_DATA7;
          DAT_003f988c = CONCAT11(bVar2,bVar3);
          break;
        case 6:
          bVar2 = REG_CANB_MB9_DATA6;
          bVar3 = REG_CANB_MB9_DATA7;
          DAT_003f988e = CONCAT11(bVar2,bVar3);
          break;
        case 7:
          bVar2 = REG_CANB_MB9_DATA6;
          bVar3 = REG_CANB_MB9_DATA7;
          DAT_003f9890 = CONCAT11(bVar2,bVar3);
        }
      }
      else {
        bVar2 = REG_CANB_MB9_DATA0;
        if (bVar2 == 0x2f) {
          bVar2 = REG_CANB_MB9_DATA2;
          bVar3 = REG_CANB_MB9_DATA3;
          DAT_003f9892 = CONCAT11(bVar2,bVar3);
          DAT_003f9894 = REG_CANB_MB9_DATA1;
        }
        else {
          bVar2 = REG_CANB_MB9_DATA0;
          if (bVar2 == 0x2d) {
            bVar2 = REG_CANB_MB9_DATA4;
            bVar3 = REG_CANB_MB9_DATA5;
            DAT_003f9896 = CONCAT11(bVar2,bVar3);
            DAT_003f9898 = REG_CANB_MB9_DATA1;
          }
          else {
            bVar2 = REG_CANB_MB9_DATA0;
            if (bVar2 == 0x2e) {
              bVar2 = REG_CANB_MB9_DATA7;
              if ((bVar2 & 8) == 0) {
                DAT_003f9899 = DAT_003f9899 & 0xfe;
              }
              else {
                DAT_003f9899 = DAT_003f9899 | 1;
              }
              bVar2 = REG_CANB_MB9_DATA7;
              if ((bVar2 & 0x80) == 0) {
                DAT_003f9899 = DAT_003f9899 & 0xfd;
              }
              else {
                DAT_003f9899 = DAT_003f9899 | 2;
              }
              bVar2 = REG_CANB_MB9_DATA7;
              if ((bVar2 & 4) == 0) {
                DAT_003f989a = DAT_003f989a & 0xfe;
              }
              else {
                DAT_003f989a = DAT_003f989a | 1;
              }
              bVar2 = REG_CANB_MB9_DATA7;
              if ((bVar2 & 0x20) == 0) {
                DAT_003f989a = DAT_003f989a & 0xfd;
              }
              else {
                DAT_003f989a = DAT_003f989a | 2;
              }
            }
            else {
              bVar2 = REG_CANB_MB9_DATA0;
              if (bVar2 == 0x30) {
                DAT_003f989b = REG_CANB_MB9_DATA1;
                DAT_003f989c = REG_CANB_MB9_DATA2;
              }
            }
          }
        }
      }
    }
  }
  REG_CANB_MB8_CS = 0;
  REG_CANB_MB8_ID_HI = 44000;
  uVar1 = REG_CANB_MB8_CS;
  REG_CANB_MB8_CS = uVar1 | 0x40;
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



// CAN-B MB13: Unused message buffer

void can_b_mb13_unused(void)

{
  ushort uVar1;
  
  uVar1 = REG_IFLAG_B;
  REG_IFLAG_B = uVar1 & 0xdfff;
  return;
}



// CAN-B MB14: Unused message buffer

void can_b_mb14_unused(void)

{
  ushort uVar1;
  
  uVar1 = REG_IFLAG_B;
  REG_IFLAG_B = uVar1 & 0xbfff;
  return;
}



// CAN-B MB15: Unused message buffer

void can_b_mb15_unused(void)

{
  ushort uVar1;
  
  uVar1 = REG_IFLAG_B;
  REG_IFLAG_B = uVar1 & 0x7fff;
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



// CAN-B: Broadcasts RPM and vehicle speed

void can_b_send_rpm_speed(void)

{
  REG_CANB_MB3_CS = 0x80;
  REG_CANB_MB3_ID_HI = 0x8c00;
  REG_CANB_MB3_DATA0 = 0;
  REG_CANB_MB3_DATA1 = (byte)(engine_speed_2 >> 8);
  REG_CANB_MB3_DATA2 = (byte)engine_speed_2;
  if ((tpms_flags & 0x200) == 0) {
    REG_CANB_MB3_DATA3 = (byte)(wheel_speed_r_max / 10 >> 8);
    REG_CANB_MB3_DATA4 = (byte)(wheel_speed_r_max / 10);
  }
  else {
    REG_CANB_MB3_DATA3 = 1;
    REG_CANB_MB3_DATA4 = 0xf4;
  }
  REG_CANB_MB3_DATA5 = 0;
  REG_CANB_MB3_DATA6 = 0;
  REG_CANB_MB3_DATA7 = 0;
  REG_CANB_MB3_CS = 200;
  return;
}



// CAN-B: Broadcasts temperature data

void can_b_send_temp(void)

{
  byte bVar1;
  undefined2 uVar2;
  
  if (((!CAL_misc_use_tmap) && (0x90 < engine_air_smooth)) ||
     ((CAL_misc_use_tmap && (0x90 < intake_air_smooth)))) {
    uVar2 = 900;
  }
  else if (CAL_misc_use_tmap) {
    uVar2 = (undefined2)((int)((uint)intake_air_smooth * 0x32) >> 3);
  }
  else {
    uVar2 = (undefined2)((int)((uint)engine_air_smooth * 0x32) >> 3);
  }
  REG_CANB_MB4_CS = 0x80;
  REG_CANB_MB4_ID_HI = 0xf400;
  REG_CANB_MB4_DATA0 = 0;
  bVar1 = (byte)((ushort)uVar2 >> 8);
  REG_CANB_MB4_DATA1 = bVar1;
  REG_CANB_MB4_DATA2 = (byte)uVar2;
  REG_CANB_MB4_DATA3 = bVar1;
  REG_CANB_MB4_DATA4 = (byte)uVar2;
  REG_CANB_MB4_DATA5 = 0;
  REG_CANB_MB4_DATA6 = 0;
  REG_CANB_MB4_DATA7 = 0;
  REG_CANB_MB4_CS = 200;
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
          can_b_mb00_unused();
        }
        else {
          can_b_mb01_unused();
        }
      }
      else if (uVar1 < 8) {
        can_b_mb02_unused();
      }
      else {
        can_b_mb03_unused();
      }
    }
    else if (uVar1 < 0x40) {
      if (uVar1 < 0x20) {
        can_b_mb04_unused();
      }
      else {
        can_b_mb05_recv_tpms_pressure();
      }
    }
    else if (uVar1 < 0x80) {
      can_b_mb06_unused();
    }
    else {
      can_b_mb07_recv_tpms_diag();
    }
  }
  else if (uVar1 < 0x1000) {
    if (uVar1 < 0x400) {
      if (uVar1 < 0x200) {
        can_b_mb08_unused();
      }
      else {
        can_b_mb09_recv_tpms_sensor();
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
      can_b_mb13_unused();
    }
  }
  else if (uVar1 < 0x8000) {
    can_b_mb14_unused();
  }
  else {
    can_b_mb15_unused();
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
                    // Speed = 40 Mhz / (3+1) / (1+4+1+6+1+6+1) = 500 kbit/s
  REG_CANCTRL0_A = 0;
  REG_CANCTRL1_A = 4;
  REG_CTRL2_A = 0xf6;
  REG_PRESDIV_A = 3;
                    // Msg buffer 0: Tx user defined, response to 0x50
  REG_CANA_MB0_CS = 0;
  REG_CANA_MB0_ID_HI = 0;
  REG_CANA_MB0_ID_LO = 0;
  uVar1 = REG_CANA_MB0_CS;
  REG_CANA_MB0_CS = uVar1 | 0x80;
                    // Msg buffer 1: Tx 0x7a0, response to 0x50
  REG_CANA_MB1_CS = 0;
  REG_CANA_MB1_ID_HI = 0;
  REG_CANA_MB1_ID_LO = 0;
  uVar1 = REG_CANA_MB1_CS;
  REG_CANA_MB1_CS = uVar1 | 0x80;
                    // Msg buffer 2: Tx 0x200 to 0x2ac, response to 0x80
  REG_CANA_MB2_CS = 0;
  REG_CANA_MB2_ID_HI = 0;
  REG_CANA_MB2_ID_LO = 0;
  uVar1 = REG_CANA_MB2_CS;
  REG_CANA_MB2_CS = uVar1 | 0x80;
                    // Msg buffer 3: Tx 0x101, response to 0x100
  REG_CANA_MB3_CS = 0;
  REG_CANA_MB3_ID_HI = 0;
  REG_CANA_MB3_ID_LO = 0;
  uVar1 = REG_CANA_MB3_CS;
  REG_CANA_MB3_CS = uVar1 | 0x80;
                    // Msg buffer 4: Tx 0x400 and 0x401, Instruments cluster
  REG_CANA_MB4_CS = 0;
  REG_CANA_MB4_ID_HI = 0;
  REG_CANA_MB4_ID_LO = 0;
  uVar1 = REG_CANA_MB4_CS;
  REG_CANA_MB4_CS = uVar1 | 0x80;
                    // Msg buffer 5: Unused
  REG_CANA_MB5_CS = 0;
  REG_CANA_MB5_ID_HI = 0;
  REG_CANA_MB5_ID_LO = 0;
  uVar1 = REG_CANA_MB5_CS;
  REG_CANA_MB5_CS = uVar1 | 0x80;
                    // Msg buffer 6: Rx 0x310
  REG_CANA_MB6_CS = 0;
  REG_CANA_MB6_ID_HI = 0x6200;
  REG_CANA_MB6_ID_LO = 0;
  uVar1 = REG_CANA_MB6_CS;
  REG_CANA_MB6_CS = uVar1 | 0x40;
                    // Msg buffer 7: Tx 0x7E8, OBD
  REG_CANA_MB7_CS = 0;
  REG_CANA_MB7_ID_HI = 0;
  REG_CANA_MB7_ID_LO = 0;
  uVar1 = REG_CANA_MB7_CS;
  REG_CANA_MB7_CS = uVar1 | 0x80;
                    // Msg buffer 8: Rx 0x7C0, OBD
  REG_CANA_MB8_CS = 0;
  REG_CANA_MB8_ID_HI = 0xf800;
  REG_CANA_MB8_ID_LO = 0;
  uVar1 = REG_CANA_MB8_CS;
  REG_CANA_MB8_CS = uVar1 | 0x40;
                    // Msg buffer 9: Unused
  REG_CANA_MB9_CS = 0;
  REG_CANA_MB9_ID_HI = 0;
  REG_CANA_MB9_ID_LO = 0;
  uVar1 = REG_CANA_MB9_CS;
  REG_CANA_MB9_CS = uVar1 | 0x80;
                    // Msg buffer 10: Unused
  REG_CANA_MB10_CS = 0;
  REG_CANA_MB10_ID_HI = 0;
  REG_CANA_MB10_ID_LO = 0;
  uVar1 = REG_CANA_MB10_CS;
  REG_CANA_MB10_CS = uVar1 | 0x80;
                    // Msg buffer 11: Unused
  REG_CANA_MB11_CS = 0;
  REG_CANA_MB11_ID_HI = 0;
  REG_CANA_MB11_ID_LO = 0;
  uVar1 = REG_CANA_MB11_CS;
  REG_CANA_MB11_CS = uVar1 | 0x80;
                    // Msg buffer 12: Unused
  REG_CANA_MB12_CS = 0;
  REG_CANA_MB12_ID_HI = 0;
  REG_CANA_MB12_ID_LO = 0;
  uVar1 = REG_CANA_MB12_CS;
  REG_CANA_MB12_CS = uVar1 | 0x80;
                    // Msg buffer 13: Rx 0x100
  REG_CANA_MB13_CS = 0;
  REG_CANA_MB13_ID_HI = 0;
  REG_CANA_MB13_ID_LO = 0;
  uVar1 = REG_CANA_MB13_CS;
  REG_CANA_MB13_CS = uVar1 | 0x40;
                    // Msg buffer 14: Rx 0x80, log
  REG_CANA_MB14_CS = 0;
  REG_CANA_MB14_ID_HI = 0x1000;
  REG_CANA_MB14_ID_LO = 0;
  uVar1 = REG_CANA_MB14_CS;
  REG_CANA_MB14_CS = uVar1 | 0x40;
                    // Msg buffer 15: Rx 0x50, Live-tuning access
  REG_CANA_MB15_CS = 0;
  REG_CANA_MB15_ID_HI = 0xa00;
  REG_CANA_MB15_ID_LO = 0;
  uVar1 = REG_CANA_MB15_CS;
  REG_CANA_MB15_CS = uVar1 | 0x40;
                    // Mask for msg buffer 0-13: 0x7c0
  REG_RXGMSKHI_A = 0xf80f;
  REG_RXGMSKLO_A = 0xfffe;
                    // Mask for msg buffer 14: 0x7ff
  REG_RX14MSKHI_A = 0xffef;
  REG_RX14MSKLO_A = 0xfffe;
                    // Mask for msg buffer 15: 0x7f8
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



// CAN-A: Sends OBD multi-frame response (ISO-TP)

void can_a_mb00_send_obd_multiframe(void)

{
  byte bVar1;
  byte *pbVar2;
  short sVar3;
  ushort uVar4;
  
  uVar4 = REG_CANA_MB0_CS;
  uVar4 = REG_IFLAG_A;
  REG_IFLAG_A = uVar4 & 0xfffe;
  if (DAT_003f904e != 0) {
    DAT_003f9058 = &REG_CANA_MB0_DATA0;
    REG_CANA_MB0_CS = 0x88;
    REG_CANA_MB0_ID_HI = 0xf400;
    uVar4 = DAT_003f904e;
    if (DAT_003f904e < 9) {
      for (; uVar4 != 0; uVar4 = uVar4 - 1) {
        bVar1 = *DAT_003f9040;
        DAT_003f9040 = DAT_003f9040 + 1;
        pbVar2 = DAT_003f9058 + 1;
        *DAT_003f9058 = bVar1;
        DAT_003f9058 = pbVar2;
      }
      REG_CANA_MB0_CS = DAT_003f904e + 0xc0;
      DAT_003f904e = 0;
    }
    else {
      for (sVar3 = 8; sVar3 != 0; sVar3 = sVar3 + -1) {
        bVar1 = *DAT_003f9040;
        DAT_003f9040 = DAT_003f9040 + 1;
        pbVar2 = DAT_003f9058 + 1;
        *DAT_003f9058 = bVar1;
        DAT_003f9058 = pbVar2;
      }
      REG_CANA_MB0_CS = 200;
      DAT_003f904e = DAT_003f904e - 8;
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
  if (log_canid[DAT_003fea0c] != 0) {
    DAT_003f9058 = &REG_CANA_MB2_DATA0;
    REG_CANA_MB2_CS = 0x88;
    REG_CANA_MB2_ID_HI = (ushort)((int)(short)log_canid[DAT_003fea0c] << 5);
    for (sVar4 = 0; sVar4 < 8; sVar4 = sVar4 + 1) {
      bVar1 = *DAT_003fea10;
      pbVar3 = DAT_003f9058 + 1;
      DAT_003fea10 = DAT_003fea10 + 1;
      *DAT_003f9058 = bVar1;
      DAT_003f9058 = pbVar3;
    }
    REG_CANA_MB2_CS = 200;
    DAT_003fea0c = DAT_003fea0c + 1;
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



// CAN-A: Sends text messages to instrument cluster

void can_a_mb04_send_cluster_text(void)

{
  ushort uVar1;
  byte bVar2;
  
  uVar1 = REG_CANA_MB4_CS;
  uVar1 = REG_IFLAG_A;
  REG_IFLAG_A = uVar1 & 0xffef;
  if ((DAT_003fd898 & 0x40000) != 0) {
    DAT_003fd898 = DAT_003fd898 & 0xfffbffff;
    REG_CANA_MB4_CS = 0x88;
    REG_CANA_MB4_ID_HI = 0x8020;
    for (bVar2 = 0; bVar2 < 8; bVar2 = bVar2 + 1) {
      (&REG_CANA_MB4_DATA0)[bVar2] = (&DAT_003fd89c)[bVar2];
    }
    REG_CANA_MB4_CS = 200;
  }
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
  
  push_24to31();
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
      DAT_003f98a0 = CONCAT11(bVar2,bVar3);
      DAT_003f98a8 = CONCAT11(bVar4,bVar5);
      DAT_003f98aa = CONCAT11(bVar6,bVar7);
      DAT_003f98ac = CONCAT11(bVar8,bVar9);
    }
  }
  pop_24to31();
  return;
}



// CAN-A MB07: Unused message buffer

void can_a_mb07_unused(void)

{
  ushort uVar1;
  
  uVar1 = REG_CANA_MB7_CS;
  uVar1 = REG_IFLAG_A;
  REG_IFLAG_A = uVar1 & 0xff7f;
  return;
}



// CAN-A: Receives OBD diagnostic requests (ID 0x7DF/0x7E0)

void can_a_mb08_recv_obd(void)

{
  ushort uVar1;
  byte bVar2;
  
  uVar1 = REG_IFLAG_A;
  REG_IFLAG_A = uVar1 & 0xfeff;
  uVar1 = REG_CANA_MB8_CS;
  while ((uVar1 & 0x10) != 0) {
    uVar1 = REG_CANA_MB8_CS;
  }
  uVar1 = REG_CANA_MB8_CS;
  if ((uVar1 & 0x60) == 0x60) {
    REG_CANA_MB8_CS = 0x40;
    goto LAB_0002cb24;
  }
  uVar1 = REG_CANA_MB8_CS;
  if (((uVar1 & 0x20) == 0) ||
     ((uVar1 = REG_CANA_MB8_ID_HI, (int)(uint)uVar1 >> 5 != 0x7df &&
      (uVar1 = REG_CANA_MB8_ID_HI, (int)(uint)uVar1 >> 5 != 0x7e0)))) goto LAB_0002cb24;
  for (bVar2 = 0; bVar2 < 8; bVar2 = bVar2 + 1) {
    obd_req[bVar2] = (&REG_CANA_MB8_DATA0)[bVar2];
  }
  if ((obd_req[0] & 0xf0) == 0x30) {
    DAT_003fdb09 = obd_req[0] & 0xf;
    DAT_003fdb0b = obd_req[1];
    DAT_003fdb0c = obd_req[2];
    DAT_003fdb0a = 1;
    goto LAB_0002cb24;
  }
  DAT_003fdb08 = 0;
  if (false) {
switchD_0002ca20_caseD_0:
    obd_resp[0] = 0x7f;
    obd_resp[1] = obd_req[1];
    obd_resp[2] = 0x11;
    obd_resp_len = 3;
    send_obd_resp();
  }
  else {
    switch(obd_req[1]) {
    default:
      goto switchD_0002ca20_caseD_0;
    case '\x01':
      obd_mode_0x01_live_data();
      break;
    case '\x02':
      obd_mode_0x02_freeze_frame();
      break;
    case '\x03':
      obd_mode_0x03_trouble_code();
      break;
    case '\x04':
      obd_mode_0x04_clear();
      break;
    case '\x06':
      obd_mode_0x06_test_results();
      break;
    case '\a':
      obd_mode_0x07_pending_code();
      break;
    case '\b':
      obd_mode_0x08_evap_control();
      break;
    case '\t':
      obd_mode_0x09_informations();
      break;
    case '\x11':
      obd_mode_0x11_reset_learn_table();
      break;
    case '\x13':
      obd_mode_0x13_dtc_list();
      break;
    case '\x14':
      obd_mode_0x14_clear();
      break;
    case '\"':
      obd_mode_0x22_performance_data();
      break;
    case '/':
      obd_mode_0x2F_test();
      break;
    case ';':
      obd_mode_0x3B_VIN();
    }
  }
  if (DAT_003fda00 != '\0') {
    DAT_003fda00 = '\0';
    uVar1 = REG_CANA_MB8_CS;
    REG_CANA_MB8_CS = uVar1 | 0x40;
    uVar1 = REG_TIMER_A;
  }
LAB_0002cb24:
  REG_CANA_MB8_CS = 0;
  REG_CANA_MB8_ID_HI = 0xf800;
  uVar1 = REG_CANA_MB8_CS;
  REG_CANA_MB8_CS = uVar1 | 0x40;
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
    DAT_003f9050 = REG_TIMER_A;
  }
  else {
    uVar2 = REG_CANA_MB13_CS;
    if ((uVar2 & 0x20) != 0) {
      DAT_003f905c = &REG_CANA_MB13_DATA0;
      uVar2 = REG_CANA_MB13_ID_HI;
      if ((int)(uint)uVar2 >> 5 == 0x100) {
        if (DAT_003fea14 == '\x01') {
          REG_CANA_MB13_CS = 0x40;
          DAT_003f9050 = REG_TIMER_A;
        }
        else {
          DAT_003f905c = &REG_CANA_MB13_DATA1;
          bVar1 = REG_CANA_MB13_DATA0;
          if (bVar1 == 2) {
            REG_CANA_MB13_CS = 0x40;
            DAT_003f9050 = REG_TIMER_A;
            DAT_003fea18 = &DAT_003f8f40;
            REG_CANA_MB3_CS = 0x88;
            REG_CANA_MB3_ID_HI = 0x2020;
            REG_CANA_MB3_DATA0 = 0x1b;
            DAT_003fe9fc = 2;
            DAT_003f9058 = &REG_CANA_MB3_DATA2;
            REG_CANA_MB3_DATA1 = 1;
            for (sVar4 = 0; sVar4 < 6; sVar4 = sVar4 + 1) {
              bVar1 = *DAT_003fea18;
              pbVar3 = DAT_003f9058 + 1;
              DAT_003fea18 = DAT_003fea18 + 1;
              *DAT_003f9058 = bVar1;
              DAT_003f9058 = pbVar3;
            }
            REG_CANA_MB3_CS = 200;
          }
          else {
            REG_CANA_MB13_CS = 0x40;
            DAT_003f9050 = REG_TIMER_A;
          }
        }
      }
      else {
        REG_CANA_MB13_CS = 0x40;
        DAT_003f9050 = REG_TIMER_A;
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
    DAT_003f9050 = REG_TIMER_A;
  }
  else {
    uVar2 = REG_CANA_MB14_CS;
    if ((uVar2 & 0x20) != 0) {
      DAT_003f905c = &REG_CANA_MB14_DATA0;
      uVar2 = REG_CANA_MB14_ID_HI;
      if ((int)(uint)uVar2 >> 5 == 0x80) {
        DAT_003fea14 = 1;
        DAT_003f905c = &REG_CANA_MB14_DATA1;
        DAT_003fea0d = REG_CANA_MB14_DATA1;
        REG_CANA_MB14_CS = 0x40;
        DAT_003f9050 = REG_TIMER_A;
        if (((DAT_003fea0d == 7) || (DAT_003fea0d == 6)) || (DAT_003fea0d == 5)) {
          DAT_003fea0c = 1;
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
          DAT_003fea10 = log_data;
          DAT_003f9058 = &REG_CANA_MB2_DATA0;
          REG_CANA_MB2_CS = 0x88;
          REG_CANA_MB2_ID_HI = 0x4000;
          for (sVar4 = 0; sVar4 < 8; sVar4 = sVar4 + 1) {
            bVar1 = *DAT_003fea10;
            pbVar3 = DAT_003f9058 + 1;
            DAT_003fea10 = (char *)((byte *)DAT_003fea10 + 1);
            *DAT_003f9058 = bVar1;
            DAT_003f9058 = pbVar3;
          }
          REG_CANA_MB2_CS = 200;
        }
        else if ((DAT_003fea0d == 4) || (DAT_003fea0d == 2)) {
          DAT_003fea0c = 1;
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
          log_canid[0x16] = 0x258;
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
          DAT_003fea10 = log_data;
          DAT_003f9058 = &REG_CANA_MB2_DATA0;
          REG_CANA_MB2_CS = 0x88;
          REG_CANA_MB2_ID_HI = 0x4000;
          for (sVar4 = 0; sVar4 < 8; sVar4 = sVar4 + 1) {
            bVar1 = *DAT_003fea10;
            pbVar3 = DAT_003f9058 + 1;
            DAT_003fea10 = (char *)((byte *)DAT_003fea10 + 1);
            *DAT_003f9058 = bVar1;
            DAT_003f9058 = pbVar3;
          }
          REG_CANA_MB2_CS = 200;
        }
        else if ((DAT_003fea0d == 3) || (DAT_003fea0d == 1)) {
          DAT_003fea0c = 1;
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
          log_canid[0x16] = 0x258;
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
          DAT_003fea10 = log_data;
          DAT_003f9058 = &REG_CANA_MB2_DATA0;
          REG_CANA_MB2_CS = 0x88;
          REG_CANA_MB2_ID_HI = 0x4000;
          for (sVar4 = 0; sVar4 < 8; sVar4 = sVar4 + 1) {
            bVar1 = *DAT_003fea10;
            pbVar3 = DAT_003f9058 + 1;
            DAT_003fea10 = (char *)((byte *)DAT_003fea10 + 1);
            *DAT_003f9058 = bVar1;
            DAT_003f9058 = pbVar3;
          }
          REG_CANA_MB2_CS = 200;
        }
      }
      else {
        REG_CANA_MB14_CS = 0x40;
        DAT_003f9050 = REG_TIMER_A;
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
    DAT_003f9050 = REG_TIMER_A;
  }
  else {
    uVar10 = REG_CANA_MB15_CS;
    if ((uVar10 & 0x20) != 0) {
      DAT_003f905c = &REG_CANA_MB15_DATA0;
      uVar10 = REG_CANA_MB15_ID_HI;
      if ((int)(uint)uVar10 >> 5 == 0x50) {
        uVar10 = REG_CANA_MB15_CS;
        if ((uVar10 & 0xf) == 4) {
          DAT_003f9040 = (byte *)Ram003071f6;
          REG_CANA_MB15_CS = 0x40;
          DAT_003f9050 = REG_TIMER_A;
          DAT_003f9058 = &REG_CANA_MB0_DATA0;
          REG_CANA_MB0_CS = 0x88;
          REG_CANA_MB0_ID_HI = 0xf400;
          Ram00307106 = *(undefined4 *)DAT_003f9040;
          REG_CANA_MB0_CS = 0xc4;
        }
        else {
          REG_CANA_MB15_CS = 0x40;
          DAT_003f9050 = REG_TIMER_A;
        }
      }
      else {
        uVar10 = REG_CANA_MB15_ID_HI;
        if ((int)(uint)uVar10 >> 5 == 0x51) {
          uVar10 = REG_CANA_MB15_CS;
          if ((uVar10 & 0xf) == 4) {
            DAT_003f9040 = (byte *)Ram003071f6;
            REG_CANA_MB15_CS = 0x40;
            DAT_003f9050 = REG_TIMER_A;
            DAT_003f9058 = &REG_CANA_MB0_DATA0;
            REG_CANA_MB0_CS = 0x88;
            REG_CANA_MB0_ID_HI = 0xf400;
            Ram00307106 = *(undefined2 *)DAT_003f9040;
            REG_CANA_MB0_CS = 0xc2;
          }
          else {
            uVar10 = REG_CANA_MB15_CS;
            if ((uVar10 & 0xf) == 6) {
              bVar1 = REG_CANA_MB15_DATA0;
              bVar2 = REG_CANA_MB15_DATA1;
              bVar3 = REG_CANA_MB15_DATA2;
              bVar4 = REG_CANA_MB15_DATA3;
              DAT_003f905c = &REG_CANA_MB15_DATA5;
              bVar5 = REG_CANA_MB15_DATA4;
              DAT_003f9054 = (struct_varptr *)CONCAT31(CONCAT21(CONCAT11(bVar2,bVar3),bVar4),bVar5);
              bVar2 = REG_CANA_MB15_DATA5;
              REG_CANA_MB15_CS = 0x40;
              DAT_003f9050 = REG_TIMER_A;
              DAT_003f9048 = DAT_003f9054;
              if (bVar2 == 1) {
                REG_CANA_MB1_CS = 0x88;
                REG_CANA_MB1_ID_HI = (ushort)bVar1 << 8 | 0x20;
                DAT_003f9058 = &REG_CANA_MB1_DATA1;
                REG_CANA_MB1_DATA0 = 10;
                REG_CANA_MB1_DATA1 = *(byte *)&DAT_003f9054->ptr;
                REG_CANA_MB1_CS = 0xc2;
              }
              else if (bVar2 == 2) {
                REG_CANA_MB1_CS = 0x88;
                REG_CANA_MB1_ID_HI = (ushort)bVar1 << 8 | 0x20;
                REG_CANA_MB1_DATA0 = 10;
                DAT_003f9048 = (struct_varptr *)((int)&DAT_003f9054->ptr + 1);
                DAT_003f9058 = &REG_CANA_MB1_DATA2;
                REG_CANA_MB1_DATA1 = *(byte *)&DAT_003f9054->ptr;
                REG_CANA_MB1_DATA2 = *(byte *)&DAT_003f9048->ptr;
                REG_CANA_MB1_CS = 0xc3;
              }
              else if (bVar2 == 4) {
                REG_CANA_MB1_CS = 0x88;
                REG_CANA_MB1_ID_HI = (ushort)bVar1 << 8 | 0x20;
                REG_CANA_MB1_DATA0 = 10;
                REG_CANA_MB1_DATA1 = *(byte *)&DAT_003f9054->ptr;
                REG_CANA_MB1_DATA2 = *(byte *)((int)&DAT_003f9054->ptr + 1);
                DAT_003f9048 = (struct_varptr *)((int)&DAT_003f9054->ptr + 3);
                DAT_003f9058 = &REG_CANA_MB1_DATA4;
                REG_CANA_MB1_DATA3 = *(byte *)((int)&DAT_003f9054->ptr + 2);
                REG_CANA_MB1_DATA4 = *(byte *)&DAT_003f9048->ptr;
                REG_CANA_MB1_CS = 0xc5;
              }
            }
            else {
              REG_CANA_MB15_CS = 0x40;
              DAT_003f9050 = REG_TIMER_A;
            }
          }
        }
        else {
          uVar10 = REG_CANA_MB15_ID_HI;
          if ((int)(uint)uVar10 >> 5 == 0x52) {
            uVar10 = REG_CANA_MB15_CS;
            if ((uVar10 & 0xf) == 4) {
              DAT_003f9040 = (byte *)Ram003071f6;
              REG_CANA_MB15_CS = 0x40;
              DAT_003f9050 = REG_TIMER_A;
              DAT_003f9058 = &REG_CANA_MB0_DATA0;
              REG_CANA_MB0_CS = 0x88;
              REG_CANA_MB0_ID_HI = 0xf400;
              REG_CANA_MB0_DATA0 = *DAT_003f9040;
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
                DAT_003f9054 = (struct_varptr *)
                               CONCAT31(CONCAT21(CONCAT11(bVar2,bVar3),bVar4),bVar5);
                DAT_003f905c = &REG_CANA_MB15_DATA7;
                bVar2 = REG_CANA_MB15_DATA6;
                uVar10 = (ushort)bVar2;
                REG_CANA_MB15_CS = 0x40;
                DAT_003f9050 = REG_TIMER_A;
                DAT_003f9048 = DAT_003f9054;
                DAT_003f9058 = &REG_CANA_MB1_DATA0;
                REG_CANA_MB1_CS = 0x88;
                REG_CANA_MB1_ID_HI = (ushort)bVar1 << 8 | 0x40;
                if (8 < bVar2) {
                  uVar10 = 8;
                }
                for (; uVar10 != 0; uVar10 = uVar10 - 1) {
                  ppvVar8 = &DAT_003f9048->ptr;
                  DAT_003f9048 = (struct_varptr *)((int)&DAT_003f9048->ptr + 1);
                  pbVar9 = DAT_003f9058 + 1;
                  *DAT_003f9058 = *(byte *)ppvVar8;
                  DAT_003f9058 = pbVar9;
                }
                REG_CANA_MB1_CS = 200;
              }
              else {
                REG_CANA_MB15_CS = 0x40;
                DAT_003f9050 = REG_TIMER_A;
              }
            }
          }
          else {
            uVar10 = REG_CANA_MB15_ID_HI;
            if ((int)(uint)uVar10 >> 5 == 0x53) {
              uVar10 = REG_CANA_MB15_CS;
              if ((uVar10 & 0xf) == 5) {
                DAT_003f904c = 0;
                DAT_003f905c = &REG_CANA_MB15_DATA4;
                DAT_003f9040 = (byte *)Ram003071f6;
                bVar1 = REG_CANA_MB15_DATA4;
                DAT_003f904e = (ushort)bVar1;
                REG_CANA_MB15_CS = 0x40;
                DAT_003f9050 = REG_TIMER_A;
                DAT_003f9058 = &REG_CANA_MB0_DATA0;
                REG_CANA_MB0_CS = 0x88;
                REG_CANA_MB0_ID_HI = 0xf400;
                uVar10 = DAT_003f904e;
                if (DAT_003f904e < 9) {
                  for (; uVar10 != 0; uVar10 = uVar10 - 1) {
                    bVar1 = *DAT_003f9040;
                    DAT_003f9040 = DAT_003f9040 + 1;
                    pbVar9 = DAT_003f9058 + 1;
                    *DAT_003f9058 = bVar1;
                    DAT_003f9058 = pbVar9;
                  }
                  REG_CANA_MB0_CS = DAT_003f904e + 0xc0;
                  DAT_003f904e = 0;
                }
                else {
                  for (sVar11 = 8; sVar11 != 0; sVar11 = sVar11 + -1) {
                    bVar1 = *DAT_003f9040;
                    DAT_003f9040 = DAT_003f9040 + 1;
                    pbVar9 = DAT_003f9058 + 1;
                    *DAT_003f9058 = bVar1;
                    DAT_003f9058 = pbVar9;
                  }
                  REG_CANA_MB0_CS = 200;
                  DAT_003f904e = DAT_003f904e - 8;
                }
              }
              else {
                uVar10 = REG_CANA_MB15_CS;
                if ((uVar10 & 0xf) == 6) {
                  DAT_003f904c = 0;
                  DAT_003f905c = &REG_CANA_MB15_DATA4;
                  DAT_003f9040 = (byte *)Ram003071f6;
                  DAT_003f904e = Ram003071fa;
                  REG_CANA_MB15_CS = 0x40;
                  DAT_003f9050 = REG_TIMER_A;
                  DAT_003f9058 = &REG_CANA_MB0_DATA0;
                  REG_CANA_MB0_CS = 0x88;
                  REG_CANA_MB0_ID_HI = 0xf400;
                  uVar10 = DAT_003f904e;
                  if (DAT_003f904e < 9) {
                    for (; uVar10 != 0; uVar10 = uVar10 - 1) {
                      bVar1 = *DAT_003f9040;
                      DAT_003f9040 = DAT_003f9040 + 1;
                      pbVar9 = DAT_003f9058 + 1;
                      *DAT_003f9058 = bVar1;
                      DAT_003f9058 = pbVar9;
                    }
                    REG_CANA_MB0_CS = DAT_003f904e + 0xc0;
                    DAT_003f904e = 0;
                  }
                  else {
                    for (sVar11 = 8; sVar11 != 0; sVar11 = sVar11 + -1) {
                      bVar1 = *DAT_003f9040;
                      DAT_003f9040 = DAT_003f9040 + 1;
                      pbVar9 = DAT_003f9058 + 1;
                      *DAT_003f9058 = bVar1;
                      DAT_003f9058 = pbVar9;
                    }
                    REG_CANA_MB0_CS = 200;
                    DAT_003f904e = DAT_003f904e - 8;
                  }
                }
                else {
                  uVar10 = REG_CANA_MB15_CS;
                  if ((uVar10 & 0xf) == 4) {
                    DAT_003f9040 = (byte *)Ram003071f6;
                    REG_CANA_MB15_CS = 0x40;
                    DAT_003f9050 = REG_TIMER_A;
                    DAT_003f9058 = &REG_CANA_MB0_DATA0;
                    REG_CANA_MB0_CS = 0x88;
                    REG_CANA_MB0_ID_HI = 0xf400;
                    Ram00307106 = 0x7884c;
                    REG_CANA_MB0_CS = 0xc4;
                  }
                  else {
                    uVar10 = REG_CANA_MB15_CS;
                    if ((uVar10 & 0xf) == 1) {
                      bVar1 = REG_CANA_MB15_DATA0;
                      REG_CANA_MB15_CS = 0x40;
                      DAT_003f9050 = REG_TIMER_A;
                      REG_CANA_MB1_CS = 0x88;
                      REG_CANA_MB1_ID_HI = (ushort)bVar1 << 8 | 0x60;
                      DAT_003f9048 = dev_varptr_list;
                      REG_CANA_MB1_DATA0 = 10;
                      REG_CANA_MB1_DATA1 = 0;
                      REG_CANA_MB1_DATA2 = 7;
                      REG_CANA_MB1_DATA3 = 0x88;
                      REG_CANA_MB1_DATA4 = 0x4c;
                      DAT_003f9058 = &REG_CANA_MB1_DATA6;
                      REG_CANA_MB1_DATA5 = 0;
                      REG_CANA_MB1_CS = 0xc6;
                    }
                    else {
                      REG_CANA_MB15_CS = 0x40;
                      DAT_003f9050 = REG_TIMER_A;
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
                  DAT_003f905c = &REG_CANA_MB15_DATA4;
                  DAT_003f9044 = (byte *)Ram003071f6;
                  REG_CANA_MB15_CS = 0x40;
                  DAT_003f9050 = REG_TIMER_A;
                  DAT_003f9058 = &REG_CANA_MB0_DATA0;
                  uVar7 = Ram003071fa;
                  *(undefined4 *)DAT_003f9044 = uVar7;
                }
                else {
                  REG_CANA_MB15_CS = 0x40;
                  DAT_003f9050 = REG_TIMER_A;
                }
              }
              else {
                uVar10 = REG_CANA_MB15_ID_HI;
                if ((int)(uint)uVar10 >> 5 == 0x55) {
                  uVar10 = REG_CANA_MB15_CS;
                  if ((uVar10 & 0xf) == 6) {
                    DAT_003f905c = &REG_CANA_MB15_DATA4;
                    DAT_003f9044 = (byte *)Ram003071f6;
                    REG_CANA_MB15_CS = 0x40;
                    DAT_003f9050 = REG_TIMER_A;
                    uVar6 = Ram003071fa;
                    *(undefined2 *)DAT_003f9044 = uVar6;
                  }
                  else {
                    REG_CANA_MB15_CS = 0x40;
                    DAT_003f9050 = REG_TIMER_A;
                  }
                }
                else {
                  uVar10 = REG_CANA_MB15_ID_HI;
                  if ((int)(uint)uVar10 >> 5 == 0x56) {
                    uVar10 = REG_CANA_MB15_CS;
                    if ((uVar10 & 0xf) == 5) {
                      DAT_003f905c = &REG_CANA_MB15_DATA4;
                      DAT_003f9044 = (byte *)Ram003071f6;
                      REG_CANA_MB15_CS = 0x40;
                      DAT_003f9050 = REG_TIMER_A;
                      bVar1 = REG_CANA_MB15_DATA4;
                      *DAT_003f9044 = bVar1;
                    }
                    else {
                      REG_CANA_MB15_CS = 0x40;
                      DAT_003f9050 = REG_TIMER_A;
                    }
                  }
                  else {
                    uVar10 = REG_CANA_MB15_ID_HI;
                    if ((int)(uint)uVar10 >> 5 == 0x57) {
                      if (DAT_003f904c == 0) {
                        uVar10 = REG_CANA_MB15_CS;
                        if ((uVar10 & 0xf) == 5) {
                          DAT_003f905c = &REG_CANA_MB15_DATA4;
                          DAT_003f9044 = (byte *)Ram003071f6;
                          bVar1 = REG_CANA_MB15_DATA4;
                          DAT_003f904c = (ushort)bVar1;
                          REG_CANA_MB15_CS = 0x40;
                          DAT_003f9050 = REG_TIMER_A;
                        }
                        else {
                          REG_CANA_MB15_CS = 0x40;
                          DAT_003f9050 = REG_TIMER_A;
                        }
                      }
                      else {
                        uVar10 = REG_CANA_MB15_CS;
                        for (uVar10 = uVar10 & 0xf; uVar10 != 0; uVar10 = uVar10 - 1) {
                          bVar1 = *DAT_003f905c;
                          pbVar9 = DAT_003f9044 + 1;
                          DAT_003f905c = DAT_003f905c + 1;
                          *DAT_003f9044 = bVar1;
                          DAT_003f9044 = pbVar9;
                          DAT_003f904c = DAT_003f904c - 1;
                        }
                        REG_CANA_MB15_CS = 0x40;
                        DAT_003f9050 = REG_TIMER_A;
                      }
                    }
                    else {
                      REG_CANA_MB15_CS = 0x40;
                      DAT_003f9050 = REG_TIMER_A;
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

void can_a_send_cluster(byte *param_1)

{
  REG_CANA_MB4_CS = 0x88;
  REG_CANA_MB4_ID_HI = 0x8000;
  REG_CANA_MB4_DATA0 = *param_1;
  REG_CANA_MB4_DATA1 = param_1[1];
  Ram00307148 = *(undefined2 *)(param_1 + 2);
  REG_CANA_MB4_DATA4 = param_1[4];
  REG_CANA_MB4_DATA5 = param_1[5];
  REG_CANA_MB4_DATA6 = param_1[6];
  REG_CANA_MB4_DATA7 = param_1[7];
  REG_CANA_MB4_CS = 0xc8;
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
            can_a_mb00_send_obd_multiframe();
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
          can_a_mb04_send_cluster_text();
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
          can_a_mb08_recv_obd();
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
            can_b_mb00_unused();
          }
          else {
            can_b_mb01_unused();
          }
        }
        else if (uVar1 < 8) {
          can_b_mb02_unused();
        }
        else {
          can_b_mb03_unused();
        }
      }
      else if (uVar1 < 0x40) {
        if (uVar1 < 0x20) {
          can_b_mb04_unused();
        }
        else {
          can_b_mb05_recv_tpms_pressure();
        }
      }
      else if (uVar1 < 0x80) {
        can_b_mb06_unused();
      }
      else {
        can_b_mb07_recv_tpms_diag();
      }
    }
    else if (uVar1 < 0x1000) {
      if (uVar1 < 0x400) {
        if (uVar1 < 0x200) {
          can_b_mb08_unused();
        }
        else {
          can_b_mb09_recv_tpms_sensor();
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
        can_b_mb13_unused();
      }
    }
    else if (uVar1 < 0x8000) {
      can_b_mb14_unused();
    }
    else {
      can_b_mb15_unused();
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
  DAT_003f98b0 = ~(byte)uVar1;
  uVar1 = REG_RECRAM1;
  DAT_003f8190 = (char)uVar1;
  uVar1 = REG_RECRAM2;
  DAT_003f8191 = (char)uVar1;
  uVar1 = REG_RECRAM3;
  DAT_003f8192 = (char)uVar1;
  DAT_003f98b7 = DAT_003f9065;
  DAT_003f9065 = DAT_003f966c;
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
  REG_TRANRAM0 = (ushort)DAT_003f8194;
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
    if (DAT_003fd5d6 < 9) {
      if (DAT_003fd5d6 == 0) {
        DAT_003f8194 = 0x80;
        DAT_003f9060 = 0;
      }
      else {
        DAT_003f8194 = 0x80;
      }
    }
    else {
      DAT_003f8194 = 0x81;
    }
  }
  else if (DAT_003f9060 == 0) {
    DAT_003f9060 = 1;
    DAT_003fd5d6 = 0x14;
    DAT_003f8194 = 0x81;
  }
  else {
    if (DAT_003fd5d6 < 9) {
      DAT_003f8194 = 0x80;
    }
    else {
      DAT_003f8194 = 0x81;
    }
    if (DAT_003fd5d6 == 0) {
      uVar1 = REG_RECRAM0;
      DAT_003f9064 = (byte)uVar1;
      DAT_003f9060 = 0;
    }
  }
  if (DAT_003f9064 != 0) {
    DAT_003f98b8 = DAT_003f98b8 | DAT_003f9064;
    DAT_003f9064 = 0;
  }
  uVar1 = REG_RECRAM0;
  DAT_003fd5d8 = (char)uVar1;
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
  DAT_003f98ba = REG_RECRAM0;
  return;
}



// Executes EEPROM read/write command via SPI

void eeprom_command(char *in,char *out,uint size)

{
  ushort uVar1;
  byte bVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  undefined8 uVar6;
  
  uVar6 = push_27to31();
  iVar3 = (int)((ulonglong)uVar6 >> 0x20);
  uVar5 = size - 1 & 0xff;
  eeprom_cs_assert();
  REG_SPCR0 = 0xa005;
  REG_SPCR1 = 0x1a03;
  REG_SPCR2 = 0;
  REG_SPCR3 = 0;
  for (uVar4 = 0; (uVar4 & 0xff) < uVar5; uVar4 = uVar4 + 1) {
    (&REG_TRANRAM0)[uVar4 & 0xff] = (ushort)*(byte *)(iVar3 + (uVar4 & 0xff));
    (&REG_COMDRAM0)[uVar4 & 0xff] = 0xbe;
  }
  (&REG_TRANRAM0)[uVar5] = (ushort)*(byte *)(iVar3 + uVar5);
  (&REG_COMDRAM0)[uVar5] = 0x3e;
  uVar1 = REG_SPCR2;
  REG_SPCR2 = uVar1 & 0xffe0;
  uVar1 = REG_SPCR2;
  REG_SPCR2 = (ushort)(uVar5 << 8) & 0x1f00 | uVar1 & 0xe0ff;
  uVar1 = REG_SPCR1;
  REG_SPCR1 = uVar1 & 0x7fff | 0x8000;
  do {
    bVar2 = REG_SPSR;
  } while (-1 < (char)bVar2);
  bVar2 = REG_SPSR;
  REG_SPSR = bVar2 & 0x7f;
  for (uVar5 = 0; (uVar5 & 0xff) < (size & 0xff); uVar5 = uVar5 + 1) {
    *(char *)((int)uVar6 + (uVar5 & 0xff)) = (char)(&REG_RECRAM0)[uVar5 & 0xff];
  }
  eeprom_cs_deassert();
  pop_27to31();
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
  puVar5 = (undefined2 *)0x3f98ce;
  puVar4 = (undefined2 *)&DAT_0000fffe;
  iVar6 = 0xf2d;
  do {
    puVar1 = puVar4 + 1;
    puVar4 = puVar4 + 2;
    uVar2 = *puVar4;
    puVar5[1] = *puVar1;
    puVar5 = puVar5 + 2;
    *puVar5 = uVar2;
    iVar6 = iVar6 + -1;
  } while (iVar6 != 0);
  ecu_CRC_computed = CRC16(&DAT_003f98f0,0x3c92);
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
  DAT_003f98c8 = stub_return_0x102();
  DAT_003f98ca = stub_return_zero_1();
  DAT_003f98cc = stub_return_zero_2();
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
  DAT_003f81a0 = DAT_003f81a0 + -1;
  if (DAT_003f81a0 == '\0') {
    DAT_003f81a0 = '\n';
                    // Each 5ms
    if (DAT_003fd5d6 != 0) {
      DAT_003fd5d6 = DAT_003fd5d6 + -1;
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
    if (DAT_003fe79a != 0) {
      DAT_003fe79a = DAT_003fe79a + -1;
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
    DAT_003f819e = DAT_003f819e + -1;
    if (DAT_003f819e == '\0') {
      DAT_003f819e = '\x02';
                    // Each 10ms
      if (DAT_003fd5ce != -1) {
        DAT_003fd5ce = DAT_003fd5ce + '\x01';
      }
      if (DAT_003fd5cf != -1) {
        DAT_003fd5cf = DAT_003fd5cf + '\x01';
      }
      if (DAT_003fd5d0 != -1) {
        DAT_003fd5d0 = DAT_003fd5d0 + '\x01';
      }
    }
    DAT_003f819c = DAT_003f819c + -1;
    if (DAT_003f819c < 1) {
      DAT_003f819c = 0x14;
                    // Each 100ms
      obd_task_scheduler = 65535;
      if (DAT_003f9080 < 0x257fda8) {
        DAT_003f9080 = DAT_003f9080 + 1;
      }
      if (ecu_runtime != 65535) {
        ecu_runtime = ecu_runtime + 1;
      }
      DAT_003f819f = DAT_003f819f + -1;
      if (DAT_003f819f == '\0') {
        DAT_003f819f = '\x02';
                    // Each 200ms
        misfire_monitor_200ms();
      }
      cluster_task_100ms();
      evap_100ms();
      if ((dfso_flags & 1) != 0) {
        if (((misfire_flags & 0x10) == 0) &&
           ((byte)(&DAT_003fdcb6)[iVar3] < *(byte *)((int)&PTR_DAT_003fd53b + iVar3))) {
          (&DAT_003fdcb6)[iVar3] = (&DAT_003fdcb6)[iVar3] + '\x01';
        }
      }
      ltft_100ms();
      obd_check_evap_flow_100ms();
      if (DAT_003fe2cc != '\0') {
        tpms_session_handler_100ms();
      }
    }
    if (DAT_003fd9ac != 0) {
      DAT_003fd9ac = DAT_003fd9ac + -1;
    }
    if ((dfso_flags & 2) == 0) {
      if ((short)DAT_003fd5bc < (short)(ushort)dfso_delay) {
        DAT_003f907d = DAT_003f907d + 255;
        if (DAT_003f907d == 0) {
          DAT_003f907d = CAL_dfso_delay_recovery_multiplier;
          DAT_003fd5bc = DAT_003fd5bc + 1;
        }
      }
      else {
        DAT_003fd5bc = (ushort)dfso_delay;
      }
    }
    else if (DAT_003fd5bc != 0) {
      DAT_003fd5bc = DAT_003fd5bc - 1;
    }
    if ((dfso_flags & 1) == 0) {
      DAT_003fd5be = 0;
    }
    else if (DAT_003fd5be < 0x13ec) {
      DAT_003fd5be = DAT_003fd5be + 1;
    }
    if (DAT_003f9072 != 0) {
      DAT_003f9072 = DAT_003f9072 + -1;
    }
    if (DAT_003fd90a != '\0') {
      DAT_003fd90a = DAT_003fd90a + -1;
    }
    if (DAT_003f9070 != 0) {
      DAT_003f9070 = DAT_003f9070 + -1;
    }
    if (shutdown_delay_2 != 0) {
      shutdown_delay_2 = shutdown_delay_2 - 1;
    }
    if (((shutdown_flags & 1) == 0) || (engine_speed_1 != 0)) {
      DAT_003f9074 = 0;
    }
    else {
      DAT_003f9074 = DAT_003f9074 + 1;
    }
    if (DAT_003fd5c0 != -1) {
      DAT_003fd5c0 = DAT_003fd5c0 + 1;
    }
    if (DAT_003fd5c2 != -1) {
      DAT_003fd5c2 = DAT_003fd5c2 + 1;
    }
    if (DAT_003fd5c4 != 0) {
      DAT_003fd5c4 = DAT_003fd5c4 + -1;
    }
    if (DAT_003fd5c6 != 0) {
      DAT_003fd5c6 = DAT_003fd5c6 + -1;
    }
    if (DAT_003fd5c8 != 0) {
      DAT_003fd5c8 = DAT_003fd5c8 + -1;
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
      DAT_003f907c = DAT_003f907c + 1;
      if (((uint)CAL_sensor_o2_heater_warmup_period << 2) / 5 < (uint)DAT_003f907c) {
        if (DAT_003f907c < CAL_sensor_o2_heater_warmup_period) {
          uVar4 = REG_MPIOSMDR;
          REG_MPIOSMDR = uVar4 & 0xfffb;
          uVar4 = REG_MPIOSMDR;
          REG_MPIOSMDR = uVar4 & 0xfffe;
        }
        else {
          DAT_003f907c = 0;
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
      DAT_003f9078 = DAT_003f9078 + 1;
      if ((short)(ushort)DAT_003f9a4d <= DAT_003f9078) {
        DAT_003f9078 = 0;
        dt_tps_injtip = dt_tps_injtip + injtip_out_adj2;
        if (0 < (short)dt_tps_injtip) {
          dt_tps_injtip = 0;
        }
      }
    }
    else if ((0 < (short)dt_tps_injtip) &&
            (DAT_003f9078 = DAT_003f9078 + 1, (short)(ushort)DAT_003f9a4c <= DAT_003f9078)) {
      DAT_003f9078 = 0;
      dt_tps_injtip = dt_tps_injtip - injtip_in_adj2;
      if ((short)dt_tps_injtip < 0) {
        dt_tps_injtip = 0;
      }
    }
    if (dt_tps_target_2 < 0) {
      if ((int)dt_tps_target_2 < -(int)(short)CAL_injtip_out_dt_tps_target_2_min) {
        if ((int)dt_tps_target_2 < -(int)(short)CAL_injtip_out_dt_tps_target_2_limit) {
          dt_tps_injtip = -CAL_injtip_out_dt_tps_target_2_limit;
          DAT_003f9078 = 0;
        }
        else if (dt_tps_target_2 < (short)dt_tps_injtip) {
          dt_tps_injtip = dt_tps_target_2;
          DAT_003f9078 = 0;
        }
      }
    }
    else if ((short)CAL_injtip_in_dt_tps_target_2_min < dt_tps_target_2) {
      if ((short)CAL_injtip_in_dt_tps_target_2_limit < dt_tps_target_2) {
        dt_tps_injtip = CAL_injtip_in_dt_tps_target_2_limit;
        DAT_003f9078 = 0;
      }
      else if ((short)dt_tps_injtip < dt_tps_target_2) {
        dt_tps_injtip = dt_tps_target_2;
        DAT_003f9078 = 0;
      }
    }
    pps_offset_5ms();
    obd_check_catalyst_5ms();
    obd_check_o2_slow_response_5ms();
    obd_check_misfire_5ms();
    obd_mode_0x2F_test_5ms();
    obd_mode_0x08_evap_control_5ms();
    vvt_5ms();
    knock_5ms();
    traction_control_5ms();
    if (engine_is_running == false) {
      DAT_003fdd58 = 0;
      maf_accumulated_2 = 0;
      maf_accumulated_1 = 0;
    }
    else if (maf_accumulated_1 != 4294967295) {
      maf_accumulated_1 = maf_accumulated_1 + maf_flow_1 / 0x14;
      DAT_003fdd58 = DAT_003fdd58 + ((uint)maf_flow_1 * (uint)DAT_003fdd5c) / 0x13ec;
    }
    if (maf_accumulated_1 < 0x3e8000) {
      maf_accumulated_2 = (undefined2)(maf_accumulated_1 / 1000);
    }
    if (((((CAL_load_alphaN_adj_corr_coolant_min < coolant_smooth) &&
          ((int)(uint)DAT_003f9a34 < (int)DAT_003fd7f4)) &&
         (dt_tps_target_1 < (short)CAL_load_alphaN_adj_corr_dt_tps_target_1_max)) &&
        ((-(int)(short)CAL_load_alphaN_adj_corr_dt_tps_target_1_max < (int)dt_tps_target_1 &&
         (-(int)(short)CAL_load_alphaN_adj_corr_dt_engine_speed_max < dt_engine_speed)))) &&
       ((dt_engine_speed < (short)CAL_load_alphaN_adj_corr_dt_engine_speed_max &&
        ((tps <= load_use_alphaN_tps_min && ((dfso_flags & 1) == 0)))))) {
      closedloop_flags = closedloop_flags | 0x200;
      if ((DAT_003f907a == 0) && (DAT_003fd5da == 0)) {
        DAT_003fd5da = CAL_load_alphaN_adj_corr_time_between_step;
        if ((DAT_003fd8ee & 0x8000) != 0) {
          sVar2 = (DAT_003fd8ee & 0x7fff) + 0x28;
          if ((short)CAL_load_alphaN_adj_corr_min < (short)(ushort)load_alphaN_maf_error) {
            if ((short)CAL_load_alphaN_adj_corr_max <= (short)(ushort)load_alphaN_maf_error) {
              if (CAL_load_alphaN_adj_corr_limit_l <
                  *(byte *)((int)&LEA_ecu_engine_speed_byte_coefficient + (int)sVar2)) {
                *(char *)((int)&LEA_ecu_engine_speed_byte_coefficient + (int)sVar2) =
                     *(char *)((int)&LEA_ecu_engine_speed_byte_coefficient + (int)sVar2) + -1;
              }
            }
          }
          else if (*(byte *)((int)&LEA_ecu_engine_speed_byte_coefficient + (int)sVar2) <
                   CAL_load_alphaN_adj_corr_limit_h) {
            *(char *)((int)&LEA_ecu_engine_speed_byte_coefficient + (int)sVar2) =
                 *(char *)((int)&LEA_ecu_engine_speed_byte_coefficient + (int)sVar2) + '\x01';
          }
        }
      }
    }
    else {
      closedloop_flags = closedloop_flags & 0xfdff;
      DAT_003fd5da = CAL_load_alphaN_adj_corr_time_between_step;
      DAT_003f907a = CAL_load_alphaN_adj_corr_time_min;
    }
    if (DAT_003fd5da != 0) {
      DAT_003fd5da = DAT_003fd5da - 1;
    }
    if (DAT_003f907a != 0) {
      DAT_003f907a = DAT_003f907a - 1;
    }
    send_obd_resp_5ms();
    if (obd_mode_0x13_state != '\0') {
      obd_mode_0x13_dtc_list();
    }
  }
  uVar1 = REG_SISR3;
  REG_SISR3 = uVar1 & 0xffefffff | 0x100000;
  returnFromInterrupt(in_MSR,in_SRR1);
  return CONCAT44(param_1,param_2);
}



// Resets MAF averaging buffer

void reset_maf_avg(u16_voltage_5_1023v v)

{
  short i;
  
  for (i = 0x1f; 0 < i; i = i + -1) {
    maf_adc_history[i] = v;
  }
  maf_adc_history[0] = v;
  return;
}



// Reads MAF sensor raw ADC value from QADC-A channel 11 (RJURR11)

u16_voltage_5_1023v read_adc_maf(void)

{
  ushort r;
  
  r = REG_QADCA_RJURR11;
  return r;
}



// Reads MAP sensor raw ADC value from QADC-A channel 10 (RJURR10)

u16_voltage_5_1023v read_adc_map(void)

{
  ushort r;
  
  r = REG_QADCA_RJURR10;
  return r;
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
  int sum;
  ushort avg_size;
  ushort i;
  ushort j;
  
  sum = 0;
  j = map_adc_history_i;
  if (CAL_sensor_map_avg_size < 0x20) {
    if (CAL_sensor_map_avg_size == 0) {
      i = 1;
      avg_size = 1;
    }
    else {
      i = (ushort)CAL_sensor_map_avg_size;
      avg_size = i;
    }
  }
  else {
    i = 0x1f;
    avg_size = 0x1f;
  }
  for (; 0 < (short)i; i = i - 1) {
    sum = sum + (short)map_adc_history[(short)j];
    j = j - 1 & 0x1f;
  }
  return sum / (int)(short)avg_size;
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
  short i;
  
  for (i = 0; (lut[i] < value_x && ((int)i < (int)(size_x - 1))); i = i + 1) {
  }
  DAT_003f90c8 = (char)i + -1;
  return lut[(uint)size_x + (int)i];
}



// 3D table lookup without interpolation (nearest cell)

uint8_t lookup_3D_uint8_fixed
                  (uint8_t size_x,uint8_t size_y,uint8_t input_x,uint8_t input_y,uint8_t *x_axis,
                  uint8_t *y_axis,uint8_t *lut)

{
  short y;
  short x;
  
  y = 0;
  for (x = 0; (x_axis[x] < input_x && ((int)x < (int)(size_x - 1))); x = x + 1) {
  }
  for (; (y_axis[y] < input_y && ((int)y < (int)(size_y - 1))); y = y + 1) {
  }
  return lut[(int)x + (uint)size_x * (int)y];
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
  DAT_003fd680 = sensor_adc_map;
  sensor_adc_free_2 = REG_QADCA_RJURR14;
  sensor_adc_fuel_level = REG_QADCA_RJURR15;
  sensor_adc_free_3 = REG_QADCB_RJURR0;
  sensor_adc_coolant = REG_QADCB_RJURR1;
  sensor_adc_tc_button = REG_QADCB_RJURR2;
  sensor_adc_pre_o2 = REG_QADCB_RJURR3;
  sensor_adc_post_o2 = REG_QADCB_RJURR5;
  sensor_adc_pre_o2_heater_sense = REG_QADCB_RJURR4;
  sensor_adc_post_o2_heater_sense = REG_QADCB_RJURR6;
  DAT_003fd68c = REG_QADCB_RJURR7;
  sensor_adc_knock = REG_QADCB_RJURR8;
  DAT_003fd6aa = REG_QADCB_RJURR9;
  uVar1 = REG_QADCB_RJURR10;
  sensor_adc_ecu_voltage =
       (u16_voltage_18_1023v)((int)((uint)uVar1 + (uint)sensor_adc_ecu_voltage * 7) >> 3);
  sensor_adc_ign = REG_QADCB_RJURR11;
  sensor_adc_free_4 = REG_QADCB_RJURR12;
  sensor_adc_ac_fan_request = REG_QADCB_RJURR13;
  DAT_003fd6b2 = REG_QADCB_RJURR14;
  sensor_adc_tc_knob = REG_QADCA_RJURR12;
  DAT_003fd6b6 = REG_QADCA_RJURR16;
  DAT_003fd6b8 = REG_QADCA_RJURR17;
  DAT_003fd6ba = REG_QADCB_RJURR16;
  DAT_003fd6bc = REG_QADCB_RJURR17;
  return;
}



// Reads PPS1 (pedal position sensor 1) raw ADC value from QADC-A channel 3 (RJURR3)

u16_voltage_5_1023v read_adc_pps_1(void)

{
  ushort r;
  
  r = REG_QADCA_RJURR3;
  return r;
}



// Reads PPS2 (pedal position sensor 2) raw ADC value from QADC-A channel 4 (RJURR4)

u16_voltage_5_1023v read_adc_pps_2(void)

{
  ushort r;
  
  r = REG_QADCA_RJURR4;
  return r;
}



// Reads TPS1 (throttle position sensor 1) raw ADC value from QADC-A channel 0 (RJURR0)

u16_voltage_5_1023v read_adc_tps_1(void)

{
  ushort r;
  
  r = REG_QADCA_RJURR0;
  return r;
}



// Reads TPS2 (throttle position sensor 2) raw ADC value from QADC-A channel 1 (RJURR1)

u16_voltage_5_1023v read_adc_tps_2(void)

{
  ushort r;
  
  r = REG_QADCA_RJURR1;
  return r;
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



// Returns nearest cell address in 3D table for given inputs

ushort lookup_3D_uint8_get_address
                 (uint8_t size_x,uint8_t size_y,uint16_t input_x,uint16_t input_y,uint8_t *x_axis,
                 uint8_t *y_axis)

{
  short sVar1;
  short sVar2;
  uint uVar3;
  uint uVar4;
  ushort uVar5;
  uint uVar6;
  short sVar7;
  short sVar8;
  
  uVar6 = (uint)input_y;
  uVar3 = (uint)input_x;
  uVar4 = (uint)size_x;
  push_20to31();
  sVar8 = 0;
  sVar7 = 0;
  while ((((int)sVar8 < (int)((uVar4 & 0xff) - 1) && ((uint)x_axis[sVar8] < (uVar3 & 0xff))) &&
         (x_axis[sVar8 + 1] < engine_speed_3))) {
    sVar8 = sVar8 + 1;
  }
  uVar5 = (ushort)uVar3;
  if (sVar8 == 0) {
    if ((int)(short)((ushort)x_axis[1] - (ushort)*x_axis) / 2 <
        (int)(short)((uVar5 & 0xff) - (ushort)*x_axis)) {
      sVar8 = 1;
    }
    uVar3 = abs((int)(short)(uVar5 & 0xff) - (int)(short)(ushort)x_axis[sVar8]);
    sVar1 = (short)uVar3;
  }
  else if ((int)sVar8 == (uVar4 & 0xff)) {
    sVar1 = (uVar5 & 0xff) - (ushort)x_axis[sVar8];
  }
  else {
    if ((int)(short)((ushort)x_axis[sVar8 + 1] - (ushort)x_axis[sVar8]) / 2 <
        (int)(short)((uVar5 & 0xff) - (ushort)x_axis[sVar8])) {
      sVar8 = sVar8 + 1;
    }
    uVar3 = abs((int)(short)(uVar5 & 0xff) - (int)(short)(ushort)x_axis[sVar8]);
    sVar1 = (short)uVar3;
  }
  while ((((int)sVar7 < (int)(size_y - 1) && ((uint)y_axis[sVar7] < (uVar6 & 0xff))) &&
         ((uint)y_axis[sVar7 + 1] < (uVar6 & 0xff)))) {
    sVar7 = sVar7 + 1;
  }
  uVar5 = (ushort)uVar6;
  if (sVar7 == 0) {
    if ((int)(short)((ushort)y_axis[1] - (ushort)*y_axis) / 2 <
        (int)(short)((uVar5 & 0xff) - (ushort)*y_axis)) {
      sVar7 = 1;
    }
    uVar4 = abs((int)(short)(uVar5 & 0xff) - (int)(short)(ushort)y_axis[sVar7]);
    sVar2 = (short)uVar4;
  }
  else if ((int)sVar7 == (uVar4 & 0xff)) {
    sVar2 = (uVar5 & 0xff) - (ushort)y_axis[sVar7];
  }
  else {
    if ((int)(short)((ushort)y_axis[sVar7 + 1] - (ushort)y_axis[sVar7]) / 2 <
        (int)(short)((uVar5 & 0xff) - (ushort)y_axis[sVar7])) {
      sVar7 = sVar7 + 1;
    }
    uVar4 = abs((int)(short)(uVar5 & 0xff) - (int)(short)(ushort)y_axis[sVar7]);
    sVar2 = (short)uVar4;
  }
  uVar5 = sVar8 + sVar7 * 0x10;
  if ((sVar1 <= (short)(ushort)DAT_003f994d) && (sVar2 <= (short)(ushort)DAT_003f994e)) {
    uVar5 = uVar5 | 0x8000;
  }
  pop_20to31();
  return uVar5;
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
       CAL_sensor_evap_offset) - DAT_003fd6a2;
  if ((sensor_fault_flags & 8) == 0) {
    uVar2 = (uint)sensor_adc_baro * (uint)CAL_sensor_baro_gain;
    atmo_pressure =
         CAL_sensor_baro_offset +
         (short)((int)uVar2 >> 10) + (ushort)((int)uVar2 < 0 && (uVar2 & 0x3ff) != 0);
  }
  else {
    atmo_pressure = DAT_003fc520;
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



// Computes 8-bit engine speed value

uint8_t compute_engine_speed_byte(void)

{
  int r;
  
  r = ((uint)CAL_ecu_engine_speed_byte_coefficient << 3) / (uint)engine_speed_period -
      (uint)CAL_ecu_engine_speed_byte_offset;
  if (r < 0x100) {
    if (r < 0) {
      r = 0;
    }
  }
  else {
    r = 0xff;
  }
  return (uint8_t)r;
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



// Sorts 10-element uint16 array (bubble sort for statistics)

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



// Main ignition advance calculation - base timing, corrections, knock retard

void ignition(void)

{
  byte bVar2;
  int iVar1;
  uint uVar3;
  short sVar4;
  uint uVar5;
  uint uVar6;
  
  push_26to31();
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
  ign_adv_adj3 = (i16_angle_1_4deg)(char)(bVar2 ^ 0x80);
  ign_adv_adj3_adj =
       lookup_2D_uint8_interpolated
                 (8,coolant_smooth,CAL_ign_adv_adj3_adj,CAL_ign_adv_adj3_adj_X_coolant);
  uVar5 = (int)ign_adv_adj3 * (uint)ign_adv_adj3_adj;
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
  if (DAT_003fd7c6 == 0) {
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
    sVar4 = (short)(((int)DAT_003fd7c6 * (int)(short)(ushort)DAT_003f99a7) /
                   ((short)(ushort)DAT_003f9a6a * 10));
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
  DAT_003f90f0 = (int)((uint)ign_dwell_time * 0xb400) / (int)(uint)engine_speed_period;
  DAT_003f90f4 = ign_adv_cyl[0] * 0x80;
  DAT_003f90f8 = ign_adv_cyl[1] * 0x80;
  DAT_003f90fc = ign_adv_cyl[2] * 0x80;
  DAT_003f9100 = ign_adv_cyl[3] * 0x80;
  DAT_003f9104 = (uint)DAT_003f9912 * 0x80;
  iVar1 = (DAT_003f9104 + 0x21c00) - (DAT_003f90f0 + DAT_003f90f4);
  iVar1 = iVar1 / 0x28 + (iVar1 >> 0x1f);
  DAT_003f9108 = iVar1 - (iVar1 >> 0x1f);
  if ((int)DAT_003f9108 < 0) {
    iVar1 = (int)(engine_speed_period * DAT_003f9108) / 0x480 +
            ((int)(engine_speed_period * DAT_003f9108) >> 0x1f);
    DAT_003f90e8 = ign_dwell_time + ((short)iVar1 - (short)(iVar1 >> 0x1f));
    DAT_003f9108 = 0;
  }
  else if ((int)DAT_003f9108 < 0xe00) {
    DAT_003f90e8 = ign_dwell_time;
  }
  else {
    DAT_003f9108 = 0xdff;
    DAT_003f90e8 = ign_dwell_time;
  }
  iVar1 = (DAT_003f9104 + 0x21c00) - (DAT_003f90f0 + DAT_003f90f8);
  iVar1 = iVar1 / 0x28 + (iVar1 >> 0x1f);
  DAT_003f910c = iVar1 - (iVar1 >> 0x1f);
  if ((int)DAT_003f910c < 0) {
    iVar1 = (int)(engine_speed_period * DAT_003f910c) / 0x480 +
            ((int)(engine_speed_period * DAT_003f910c) >> 0x1f);
    DAT_003f90ea = ign_dwell_time + ((short)iVar1 - (short)(iVar1 >> 0x1f));
    DAT_003f910c = 0;
  }
  else if ((int)DAT_003f910c < 0xe00) {
    DAT_003f90ea = ign_dwell_time;
  }
  else {
    DAT_003f910c = 0xdff;
    DAT_003f90ea = ign_dwell_time;
  }
  iVar1 = (DAT_003f9104 + 0x21c00) - (DAT_003f90f0 + DAT_003f90fc);
  iVar1 = iVar1 / 0x28 + (iVar1 >> 0x1f);
  DAT_003f9110 = iVar1 - (iVar1 >> 0x1f);
  if ((int)DAT_003f9110 < 0) {
    iVar1 = (int)(engine_speed_period * DAT_003f9110) / 0x480 +
            ((int)(engine_speed_period * DAT_003f9110) >> 0x1f);
    DAT_003f90ec = ign_dwell_time + ((short)iVar1 - (short)(iVar1 >> 0x1f));
    DAT_003f9110 = 0;
  }
  else if ((int)DAT_003f9110 < 0xe00) {
    DAT_003f90ec = ign_dwell_time;
  }
  else {
    DAT_003f9110 = 0xdff;
    DAT_003f90ec = ign_dwell_time;
  }
  iVar1 = (DAT_003f9104 + 0x21c00) - (DAT_003f90f0 + DAT_003f9100);
  iVar1 = iVar1 / 0x28 + (iVar1 >> 0x1f);
  DAT_003f9114 = iVar1 - (iVar1 >> 0x1f);
  if ((int)DAT_003f9114 < 0) {
    iVar1 = (int)(engine_speed_period * DAT_003f9114) / 0x480 +
            ((int)(engine_speed_period * DAT_003f9114) >> 0x1f);
    DAT_003f90ee = ign_dwell_time + ((short)iVar1 - (short)(iVar1 >> 0x1f));
    DAT_003f9114 = 0;
  }
  else if ((int)DAT_003f9114 < 0xe00) {
    DAT_003f90ee = ign_dwell_time;
  }
  else {
    DAT_003f9114 = 0xdff;
    DAT_003f90ee = ign_dwell_time;
  }
  sVar4 = (short)((int)DAT_003f9108 >> 7) +
          (ushort)((int)DAT_003f9108 < 0 && (DAT_003f9108 & 0x7f) != 0);
  DAT_003f9124 = sVar4 + 0x1e;
  if (DAT_003f9124 < 0) {
    DAT_003f9124 = sVar4 + 0x66;
  }
  else if (0x48 < DAT_003f9124) {
    DAT_003f9124 = sVar4 + -0x2a;
  }
  if ((DAT_003f9124 == 0x23) || (DAT_003f9124 == 0x47)) {
    uVar5 = engine_speed_period / 9;
  }
  else {
    uVar5 = 0;
  }
  iVar1 = (int)DAT_003f9108 >> 0x1f;
  if ((DAT_003f9124 == 0x24) || (DAT_003f9124 == 0)) {
    uVar6 = (iVar1 * 0x80 | DAT_003f9108 * 0x2000000 + iVar1 >> 0x19) - iVar1;
    uVar3 = uVar6 * 2;
    uVar3 = ((int)uVar3 / 3 + ((int)(uVar3 | uVar6 >> 0x1f) >> 0x1f)) - ((int)uVar3 >> 0x1f);
  }
  else {
    uVar3 = (iVar1 * 0x80 | DAT_003f9108 * 0x2000000 + iVar1 >> 0x19) - iVar1;
  }
  if ((shutdown_flags & 1) == 0) {
    DAT_003f81b0 = ((uVar3 & 0xffff) * 0x100 + crank_tooth_pattern[DAT_003f9124]) * 0x10000;
  }
  else {
    DAT_003f81b0 = (uint)DAT_003f90e8 +
                   ((uVar3 & 0xffff) * 0x100 + crank_tooth_pattern[DAT_003f9124]) * 0x10000 + uVar5;
  }
  sVar4 = (short)((int)DAT_003f910c >> 7) +
          (ushort)((int)DAT_003f910c < 0 && (DAT_003f910c & 0x7f) != 0);
  DAT_003f9124 = sVar4 + 0xc;
  if (DAT_003f9124 < 0) {
    DAT_003f9124 = sVar4 + 0x54;
  }
  else if (0x48 < DAT_003f9124) {
    DAT_003f9124 = sVar4 + -0x3c;
  }
  if ((DAT_003f9124 == 0x23) || (DAT_003f9124 == 0x47)) {
    uVar5 = engine_speed_period / 9;
  }
  else {
    uVar5 = 0;
  }
  iVar1 = (int)DAT_003f910c >> 0x1f;
  if ((DAT_003f9124 == 0x24) || (DAT_003f9124 == 0)) {
    uVar6 = (iVar1 * 0x80 | DAT_003f910c * 0x2000000 + iVar1 >> 0x19) - iVar1;
    uVar3 = uVar6 * 2;
    uVar3 = ((int)uVar3 / 3 + ((int)(uVar3 | uVar6 >> 0x1f) >> 0x1f)) - ((int)uVar3 >> 0x1f);
  }
  else {
    uVar3 = (iVar1 * 0x80 | DAT_003f910c * 0x2000000 + iVar1 >> 0x19) - iVar1;
  }
  if ((shutdown_flags & 1) == 0) {
    DAT_003f81b4 = ((uVar3 & 0xffff) * 0x100 + crank_tooth_pattern[DAT_003f9124]) * 0x10000;
  }
  else {
    DAT_003f81b4 = (uint)DAT_003f90ea +
                   ((uVar3 & 0xffff) * 0x100 + crank_tooth_pattern[DAT_003f9124]) * 0x10000 + uVar5;
  }
  sVar4 = (short)((int)DAT_003f9110 >> 7) +
          (ushort)((int)DAT_003f9110 < 0 && (DAT_003f9110 & 0x7f) != 0);
  DAT_003f9124 = sVar4 + -0x18;
  if (DAT_003f9124 < 0) {
    DAT_003f9124 = sVar4 + 0x30;
  }
  else if (0x48 < DAT_003f9124) {
    DAT_003f9124 = sVar4 + -0x60;
  }
  if ((DAT_003f9124 == 0x23) || (DAT_003f9124 == 0x47)) {
    uVar5 = engine_speed_period / 9;
  }
  else {
    uVar5 = 0;
  }
  iVar1 = (int)DAT_003f9110 >> 0x1f;
  if ((DAT_003f9124 == 0x24) || (DAT_003f9124 == 0)) {
    uVar6 = (iVar1 * 0x80 | DAT_003f9110 * 0x2000000 + iVar1 >> 0x19) - iVar1;
    uVar3 = uVar6 * 2;
    uVar3 = ((int)uVar3 / 3 + ((int)(uVar3 | uVar6 >> 0x1f) >> 0x1f)) - ((int)uVar3 >> 0x1f);
  }
  else {
    uVar3 = (iVar1 * 0x80 | DAT_003f9110 * 0x2000000 + iVar1 >> 0x19) - iVar1;
  }
  if ((shutdown_flags & 1) == 0) {
    DAT_003f81b8 = ((uVar3 & 0xffff) * 0x100 + crank_tooth_pattern[DAT_003f9124]) * 0x10000;
  }
  else {
    DAT_003f81b8 = (uint)DAT_003f90ec +
                   ((uVar3 & 0xffff) * 0x100 + crank_tooth_pattern[DAT_003f9124]) * 0x10000 + uVar5;
  }
  sVar4 = (short)((int)DAT_003f9114 >> 7) +
          (ushort)((int)DAT_003f9114 < 0 && (DAT_003f9114 & 0x7f) != 0);
  DAT_003f9124 = sVar4 + -6;
  if (DAT_003f9124 < 0) {
    DAT_003f9124 = sVar4 + 0x42;
  }
  else if (0x48 < DAT_003f9124) {
    DAT_003f9124 = sVar4 + -0x4e;
  }
  DAT_003f9128 = crank_tooth_pattern[DAT_003f9124];
  if ((DAT_003f9124 == 0x23) || (DAT_003f9124 == 0x47)) {
    uVar5 = engine_speed_period / 9;
  }
  else {
    uVar5 = 0;
  }
  iVar1 = (int)DAT_003f9114 >> 0x1f;
  if ((DAT_003f9124 == 0x24) || (DAT_003f9124 == 0)) {
    uVar6 = (iVar1 * 0x80 | DAT_003f9114 * 0x2000000 + iVar1 >> 0x19) - iVar1;
    uVar3 = uVar6 * 2;
    uVar3 = ((int)uVar3 / 3 + ((int)(uVar3 | uVar6 >> 0x1f) >> 0x1f)) - ((int)uVar3 >> 0x1f);
  }
  else {
    uVar3 = (iVar1 * 0x80 | DAT_003f9114 * 0x2000000 + iVar1 >> 0x19) - iVar1;
  }
  if ((shutdown_flags & 1) == 0) {
    DAT_003f81bc = ((uVar3 & 0xffff) * 0x100 + DAT_003f9128) * 0x10000;
  }
  else {
    DAT_003f81bc = (uint)DAT_003f90ee + ((uVar3 & 0xffff) * 0x100 + DAT_003f9128) * 0x10000 + uVar5;
  }
  pop_26to31();
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
    diag_channel[0x1b].confirm_threshold = (uint16_t)DAT_003fc9ed;
    diag_channel[0x1b].clear_threshold = 5;
    diag_channel[0x1b].confirm_count = 0;
    diag_channel[0x1b].clear_count = 0;
    diag_channel[0x1c].result = 0;
    diag_channel[0x1c].state = 0;
    diag_channel[0x1c].confirm_threshold = (uint16_t)DAT_003fc9ee;
    diag_channel[0x1c].clear_threshold = 5;
    diag_channel[0x1c].confirm_count = 0;
    diag_channel[0x1c].clear_count = 0;
    diag_channel[0x1d].result = 0;
    diag_channel[0x1d].state = 0;
    diag_channel[0x1d].confirm_threshold = (uint16_t)DAT_003fc9ef;
    diag_channel[0x1d].clear_threshold = 5;
    diag_channel[0x1d].confirm_count = 0;
    diag_channel[0x1d].clear_count = 0;
    diag_channel[0x1e].result = 0;
    diag_channel[0x1e].state = 0;
    diag_channel[0x1e].confirm_threshold = (uint16_t)DAT_003fc9f0;
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
  inj_time_base = (ushort)bVar5 * 20;
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
    DAT_003fd74c = DAT_003fd74c | 1;
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
    DAT_003fd74c = DAT_003fd74c & 0xfe;
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
  DAT_003fd748 = (undefined2)uVar1;
  inj_fuel_load_needed =
       (ushort)((int)(load_1_smooth * 10000) / (int)((uint)afr_target - (uint)afr_adj));
  if (evap_fuel_load < inj_fuel_load_needed) {
    DAT_003fd75c = inj_fuel_load_needed - evap_fuel_load;
  }
  else {
    DAT_003fd75c = 0;
  }
  inj_time_afr = ((uint)DAT_003fd75c * 10000) / (uVar1 & 0xffff);
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
  DAT_003fd758 = injtip_in +
                 ((int)uVar1 >> 7) + (uint)((int)uVar1 < 0 && (uVar1 & 0x7f) != 0) + injtip_reactive
                 + injtip_out;
  iVar2 = (DAT_003fd758 * inj_time_adj_by_stft) / 2000 +
          (DAT_003fd758 * inj_time_adj_by_stft >> 0x1f);
  iVar4 = (DAT_003fd758 * inj_time_adj_by_ltft) / 1000 +
          (DAT_003fd758 * inj_time_adj_by_ltft >> 0x1f);
  DAT_003fd750 = DAT_003fd758 + (iVar2 - (iVar2 >> 0x1f)) + (iVar4 - (iVar4 >> 0x1f));
  if (DAT_003fd750 < 0) {
    inj_time_final_1 = (u32_time_us)inj_time_base;
  }
  else {
    inj_time_final_1 = DAT_003fd750 + (uint)inj_time_base + (int)LEA_ltft_zone1_adj;
  }
  if ((int)inj_time_final_1 < 0xa0) {
    inj_time_final_2 = 160;
    DAT_003fd762 = 0;
    inj_duty_cycle = 0;
  }
  else {
    if (0xffff < (int)inj_time_final_1) {
      inj_time_final_1 = 65535;
    }
    DAT_003f9134 = (uint)engine_speed_period * 8 + -500;
    if (DAT_003f9134 < (int)inj_time_final_1) {
      DAT_003fd73c = (uint)DAT_003f81d7 + (inj_time_final_1 - DAT_003f9134) * 4;
      if (DAT_003f9134 < DAT_003fd73c) {
        DAT_003fd762 = 100;
        DAT_003fd73c = DAT_003f9134;
      }
      else {
        DAT_003fd762 = (undefined1)((DAT_003fd73c * 100) / DAT_003f9134);
      }
      inj_duty_cycle = 100;
    }
    else {
      DAT_003fd73c = 0xa0;
      inj_duty_cycle = (undefined1)((int)(inj_time_final_1 * 100) / DAT_003f9134);
      DAT_003fd762 = 0;
    }
    inj_time_final_2 = (u16_time_us)inj_time_final_1;
    DAT_003f81d4 = (undefined2)DAT_003fd73c;
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
  inj_angle_2 = (u16_angle_1_10deg)(((uint)inj_angle_1 * 720) / 2560);
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
  
  push_20to31();
  bVar5 = lookup_2D_uint8_interpolated
                    (8,car_speed_smooth,CAL_idle_speed_adj,CAL_idle_speed_adj_X_car_speed);
  idle_speed_adj = (ushort)bVar5 << 2;
  if (DAT_003fd7b8 < idle_speed_adj) {
    DAT_003fd7b8 = idle_speed_adj;
  }
  bVar5 = lookup_2D_uint8_interpolated
                    (16,coolant_smooth,CAL_idle_speed_base,CAL_idle_speed_base_X_coolant);
  sVar7 = (ushort)bVar5 * 4 + 500;
  sVar1 = LEA_idle_flow_adj1;
  sVar2 = DAT_003fd7b8;
  if ((ac_fan_flags & 0x400) != 0) {
    sVar1 = LEA_idle_flow_adj1_ac_on;
    sVar2 = DAT_003fd7b8 + CAL_idle_speed_adj_ac_on;
  }
  idle_speed_target = sVar7 + sVar2 + DAT_003fd7c6;
  uVar8 = (uint)sVar1;
  if (0x5f0 < idle_speed_target) {
    idle_speed_target = 1520;
  }
  engine_speed_idle_error = (short)((int)(uint)engine_speed_1 >> 2) - idle_speed_target;
  DAT_003fd7ae = idle_speed_target + (ushort)CAL_idle_flow_adj7_enable * 8;
  DAT_003fd7b0 = idle_speed_target + (ushort)CAL_idle_flow_adj7_disable * 8;
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
  if ((uint)DAT_003fd7ae < (uint)((int)(uint)engine_speed_1 >> 2)) {
    DAT_003f9144 = idle_flow_target + idle_flow_adj7;
  }
  else if ((uint)((int)(uint)engine_speed_1 >> 2) < (uint)DAT_003fd7b0) {
    DAT_003f9144 = idle_flow_target;
  }
  else {
    DAT_003f9144 = idle_flow_target +
                   (char)(((uint)idle_flow_adj7 *
                          (((int)(uint)engine_speed_1 >> 2) - (uint)DAT_003fd7b0)) /
                         ((uint)DAT_003fd7ae - (uint)DAT_003fd7b0));
  }
  DAT_003fd7a9 = lookup_3D_uint8_interpolated
                           (8,8,(ushort)DAT_003fd7ab,vacuum_2 & 0xff,CAL_idle_tps,
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
  DAT_003fd7aa = lookup_3D_uint8_interpolated
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
  uVar4 = (ushort)DAT_003f9a6a * 10;
  sVar7 = sVar7 + DAT_003fd7b8 + (ushort)DAT_003f99a8;
  if (((((int)idle_speed_target + (int)(short)(ushort)DAT_003f99a8 < (int)(uint)engine_speed_2) &&
       (dt_engine_speed < (int)-(uint)DAT_003f99a9)) ||
      (uVar3 = DAT_003fd7c6, (idle_flags & 8) == 0)) &&
     ((DAT_003fd7ac = CAL_idle_flow_base, uVar3 = uVar4,
      (int)(uint)engine_speed_2 <= (int)(short)uVar4 + (int)sVar7 && (engine_is_running != false))))
  {
    if ((int)sVar7 < (int)(uint)engine_speed_2) {
      uVar3 = engine_speed_2 - sVar7;
    }
    else {
      uVar3 = DAT_003fd7c6;
      if ((idle_flags & 8) == 0) {
        uVar3 = (ushort)DAT_003f99a8;
      }
    }
  }
  DAT_003fd7c6 = uVar3;
  if ((ac_fan_flags & 0x400) == 0) {
    idle_flow_adj_ac = 0;
  }
  else {
    idle_flow_adj_ac =
         lookup_2D_uint8_interpolated
                   (8,DAT_003fd5ce,CAL_idle_flow_adj_ac,CAL_idle_flow_adj_ac_X_on_time);
  }
  if ((ac_fan_flags & 0x800) == 0) {
    idle_flow_adj_fan_low = 0;
  }
  else {
    idle_flow_adj_fan_low =
         lookup_2D_uint8_interpolated
                   (8,DAT_003fd5cf,CAL_idle_flow_adj_fan_low,CAL_idle_flow_adj_fan_low_X_on_time);
  }
  if ((ac_fan_flags & 0x1000) == 0) {
    idle_flow_adj_fan_high = 0;
  }
  else {
    idle_flow_adj_fan_high =
         lookup_2D_uint8_interpolated
                   (8,DAT_003fd5d0,CAL_idle_flow_adj_fan_high,CAL_idle_flow_adj_fan_high_X_on_time);
  }
  if ((((short)pps < (short)(ushort)CAL_idle_flow_pps_max) &&
      ((uint)((int)(uint)engine_speed_1 >> 2) < (uint)DAT_003fd7b0)) && (engine_is_running != false)
     ) {
    uVar4 = idle_flags & 0xfffd | 8;
    if ((car_speed_smooth < CAL_idle_flow_adj5_max) || (engine_speed_idle_error < 0)) {
      idle_flow_adj5_or_zero = (i16_flow_100mg_s)(char)idle_flow_adj5;
    }
    else {
      idle_flow_adj5_or_zero = 0;
    }
    if (DAT_003fd7b4 == 0) {
      DAT_003fd7b4 = (ushort)CAL_idle_flow_adj8_corr_time_between_step;
      if ((((DAT_003fd7b8 == 0) && (DAT_003fd7c6 == 0)) || (engine_speed_idle_error < 0)) &&
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
  else if ((((uint)((int)(uint)engine_speed_1 >> 2) < (uint)DAT_003fd7b0) &&
           (engine_is_running != false)) && (engine_speed_idle_error < 0)) {
    idle_flow_adj5_or_zero = (i16_flow_100mg_s)(char)idle_flow_adj5;
    idle_flow_adj8 = 0;
    DAT_003fd7b4 = (ushort)CAL_idle_flow_adj8_corr_time_between_step;
    uVar4 = idle_flags & 0xfff7;
  }
  else {
    idle_flow_adj5_or_zero = 0;
    idle_flow_adj8 = 0;
    DAT_003fd7b4 = (ushort)CAL_idle_flow_adj8_corr_time_between_step;
    if (((short)pps < (short)(ushort)CAL_idle_flow_pps_max) &&
       ((uint)DAT_003fd7b0 < (uint)((int)(uint)engine_speed_1 >> 2))) {
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
  else if (DAT_003f81d8 == 0) {
    idle_status = 4;
  }
  else {
    idle_status = 3;
  }
  iVar9 = (uint)DAT_003fd7ac +
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
    idle_tps_target = (u16_factor_1_1023)DAT_003fd7aa;
  }
  else if (DAT_003fd7a9 < CAL_idle_tps_limit_h) {
    idle_tps_target = (u16_factor_1_1023)DAT_003fd7a9;
  }
  else {
    idle_tps_target = CAL_idle_tps_limit_h;
  }
  pop_20to31();
  return;
}



// Idle control task (5ms)

void idle_5ms(void)

{
  if (DAT_003fd7ab < DAT_003f9144) {
    DAT_003fd7ab = DAT_003f9144;
  }
  else if (DAT_003f9140 == 0) {
    DAT_003f9140 = CAL_idle_flow_time_between_decrement;
    if ((DAT_003f9144 < DAT_003fd7ab) && (DAT_003fd7ab != 0)) {
      DAT_003fd7ab = DAT_003fd7ab - 1;
    }
  }
  else {
    DAT_003f9140 = DAT_003f9140 + 255;
  }
  if (DAT_003fd7b4 != 0) {
    DAT_003fd7b4 = DAT_003fd7b4 + -1;
  }
  if (idle_status == 3) {
    DAT_003f81d8 = DAT_003f81d8 + -1;
  }
  else if (idle_status == 4) {
    DAT_003f81d8 = 0;
  }
  else {
    DAT_003f81d8 = 6000;
  }
  if (DAT_003f9141 == '\0') {
    DAT_003f9141 = CAL_idle_speed_time_between_decrement;
    if ((idle_speed_adj < DAT_003fd7b8) && (10 < DAT_003fd7b8)) {
      DAT_003fd7b8 = DAT_003fd7b8 + -10;
    }
    else {
      DAT_003fd7b8 = idle_speed_adj;
    }
    if (DAT_003fd7c6 < 0xb) {
      DAT_003fd7c6 = 0;
    }
    else {
      DAT_003fd7c6 = DAT_003fd7c6 + -10;
    }
    if (DAT_003fd7ac != '\0') {
      DAT_003fd7ac = DAT_003fd7ac + -1;
    }
  }
  else {
    DAT_003f9141 = DAT_003f9141 + 255;
  }
  return;
}



// Computes averaged sensor values with filtering

void adc_avg(void)

{
  ushort uVar1;
  
  uVar1 = REG_TPU3A_CH0_PARAM2;
  if (2 < (uVar1 & 0xff)) {
    DAT_003f97ba = '\0';
    DAT_003f97bc = 0;
    DAT_003fd7cc = '\0';
    DAT_003f8010 = 1;
    DAT_003f97c1 = 0;
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
  if (((uVar1 & 0xff00) == 0) || (DAT_003f97ba != '\0')) {
    if ((DAT_003fd7fb == '\x01') &&
       ((uVar1 = REG_TPU3A_CH15_PARAM6, 0xd < uVar1 && (DAT_003fd7cc != '\0')))) {
      DAT_003fd7fb = '\0';
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
    DAT_003fdd4c = lookup_2D_uint8_interpolated_noaxis
                             (4,(ushort)coolant_stop,CAL_obd_P0128_wait_air_mass);
    DAT_003fd7f4 = 0;
    sensor_adc_maf1 = read_adc_maf();
    sensor_adc_maf2 = sensor_adc_maf1;
    sensor_adc_map = read_adc_map();
    reset_maf_avg(sensor_adc_maf1);
    if (DAT_003fd7fb == '\0') {
      DAT_003fd7fb = '\x01';
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
  if (((engine_speed_period < CAL_misc_engine_running_enable) && (DAT_003f8216 == 0)) &&
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
  
  if (DAT_003f9920 == '\0') {
    uVar2 = 100;
  }
  else {
    uVar2 = inj_time_cranking & 0xffff;
  }
  uVar3 = (ushort)uVar2;
  if (uVar2 < 0x8000) {
    DAT_003f9874 = 0;
    DAT_003f97b0 = 4;
  }
  else {
    DAT_003f9874 = uVar3 + 0x8001;
    uVar3 = 0x7fff;
    DAT_003f97b0 = 8;
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
  DAT_003f9858 = DAT_003f9874;
  DAT_003f9870 = DAT_003f9874;
  DAT_003f9872 = DAT_003f9874;
  return;
}



// Initializes engine speed buffers used by on_crank_tooth

void init_on_crank_tooth(uint16_t param_1)

{
  short sVar1;
  
  for (sVar1 = 7; 0 < sVar1; sVar1 = sVar1 + -1) {
    (&DAT_003f81e6)[sVar1] = param_1;
  }
  DAT_003f81e6 = param_1;
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
    if (DAT_003f8216 != 0) {
      DAT_003f8216 = DAT_003f8216 - 1;
    }
  }
  else {
    DAT_003f8216 = (ushort)CAL_misc_engine_running_crank_tooth_min;
  }
  DAT_003fe18c = DAT_003fc59c;
  if (injtip_reactive != 0) {
    uVar3 = injtip_reactive * CAL_injtip_catalyst_adj_fadeout;
    injtip_reactive = ((int)uVar3 >> 8) + (uint)((int)uVar3 < 0 && (uVar3 & 0xff) != 0);
  }
  if (((dfso_flags & 1) != 0) && (dfso_count < 0x7ff)) {
    dfso_count = dfso_count + 1;
  }
  uVar2 = REG_TPU3A_CH15_PARAM6;
  if ((uVar2 & 0xff00) == 0) {
    for (DAT_003f9148 = 7; 0 < (short)DAT_003f9148; DAT_003f9148 = DAT_003f9148 + -1) {
      (&DAT_003f81e6)[(short)DAT_003f9148] = (&DAT_003f81e6)[(short)DAT_003f9148 + -1];
    }
    DAT_003f81e6 = engine_speed_period;
    if (DAT_003f914a < 3) {
      DAT_003f914a = DAT_003f914a + 1;
    }
    else {
      DAT_003f914a = 0;
      for (DAT_003f9148 = 0xf; 0 < (short)DAT_003f9148; DAT_003f9148 = DAT_003f9148 + -1) {
        engine_speed_period_history[(short)DAT_003f9148] =
             engine_speed_period_history[(short)DAT_003f9148 + -1];
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
        for (DAT_003f9148 = (ushort)CAL_sensor_engine_speed_period_avg_size; 0 < (short)DAT_003f9148
            ; DAT_003f9148 = DAT_003f9148 - 1) {
          iVar1 = iVar1 + (uint)(&DAT_003f81e6)[(short)DAT_003f9148];
        }
        engine_speed_period_avg =
             (u16_time_4us)(iVar1 / (int)(uint)CAL_sensor_engine_speed_period_avg_size);
      }
    }
    else {
      CAL_sensor_engine_speed_period_avg_size = 7;
    }
    DAT_003f9148 = (ushort)CAL_sensor_dt_engine_speed_age;
    if (7 < DAT_003f9148) {
      DAT_003f9148 = 7;
    }
    iVar1 = (60000000 / DAT_003f81e6 - 60000000 / (&DAT_003f81e6)[(short)DAT_003f9148]) *
            (uint)DAT_003f81e6 * (int)(short)DAT_003f9148;
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
  DAT_003fd834 = dt_tps_injtip;
  if (dt_tps_injtip < 0) {
    uVar2 = -(int)dt_tps_injtip * (uint)injtip_out_speed;
    uVar2 = (uint)injtip_out_coolant *
            (((int)uVar2 >> 7) + (uint)((int)uVar2 < 0 && (uVar2 & 0x7f) != 0));
    DAT_003fd830 = (uint)CAL_injtip_time_base *
                   (((int)uVar2 >> 6) + (uint)((int)uVar2 < 0 && (uVar2 & 0x3f) != 0));
    DAT_003fd82c = 0;
  }
  else {
    uVar2 = (int)dt_tps_injtip * (uint)injtip_in_speed;
    uVar2 = (uint)injtip_in_coolant *
            (((int)uVar2 >> 7) + (uint)((int)uVar2 < 0 && (uVar2 & 0x7f) != 0));
    uVar2 = (uint)injtip_in_gear *
            (((int)uVar2 >> 6) + (uint)((int)uVar2 < 0 && (uVar2 & 0x3f) != 0));
    DAT_003fd82c = (uint)CAL_injtip_time_base *
                   (((int)uVar2 >> 7) + (uint)((int)uVar2 < 0 && (uVar2 & 0x7f) != 0));
    DAT_003fd830 = 0;
  }
  if (engine_is_running == false) {
    injtip_out = 0;
    injtip_in = 0;
  }
  else {
    injtip_in = DAT_003fd82c;
    injtip_out = DAT_003fd830;
  }
  dfso_delay = lookup_2D_uint8_interpolated
                         (4,(uint8_t)((short)pps >> 2),CAL_dfso_delay,CAL_dfso_delay_X_pps);
  if (((((uint)CAL_dfso_engine_speed_enable < (uint)((int)(uint)engine_speed_1 >> 2)) &&
       ((uint)CAL_dfso_runtime_min * 10 < engine_runtime)) &&
      (CAL_dfso_coolant_enable < coolant_smooth)) &&
     (((CAL_dfso_car_speed_enable < car_speed_smooth || (car_speed_smooth == 0)) &&
      ((short)pps < (short)(ushort)CAL_dfso_pps_enable)))) {
    if (((DAT_003fd5bc == 0) && (injtip_out == 0)) ||
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
      DAT_003fd5bc = (ushort)dfso_delay;
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
  if (obd_mode_0x2F_state == 0x9) {
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
  uint v;
  
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
  if (obd_mode_0x2F_state == 10) {
    v = (uint)CAL_vvl_period * (uint)obd_mode_0x2F_value >> 8;
  }
  else {
    v = (uint)CAL_vvl_period * (uint)vvl_duty_cycle >> 0xb;
  }
  set_vvl_pwm(v & 0xffff);
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
  else if ((((shutdown_flags & 8) != 0) && ((shutdown_flags & 0x20) == 0)) &&
          ((shutdown_flags & 0x40) != 0)) {
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
  if (((((shutdown_flags & 1) == 0) || (CAL_ecu_startrelay_runtime_max <= engine_runtime)) ||
      ((shutdown_flags & 0x20) != 0)) || ((shutdown_flags & 0x40) == 0)) {
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
    DAT_003fd5c8 = (ushort)CAL_ac_pps_disable_time_min * 0x14;
  }
  if (((CAL_ac_runtime_min < engine_runtime) && ((ac_fan_flags & 0x4300) == 0)) &&
     (((ac_fan_flags & 0x80) == 0 || (((ac_fan_flags & 0x80) != 0 && (DAT_003fd5c8 == 0)))))) {
    uVar1 = REG_MPIOSMDR;
    if ((short)uVar1 < 0) {
      DAT_003fd5ce = 0;
      ac_fan_flags = ac_fan_flags & 0xfffffbff;
      DAT_003fd5c4 = (ushort)CAL_ac_user_disable_time_min;
      if (DAT_003fd5c6 == 0) {
        L9822E_outputs = L9822E_outputs & 0xef;
      }
    }
    else {
      ac_fan_flags = ac_fan_flags | 0x400;
      DAT_003fd5c6 = (ushort)CAL_ac_user_enable_time_min;
      if (DAT_003fd5c4 == 0) {
        L9822E_outputs = L9822E_outputs | 0x10;
      }
    }
  }
  else {
    L9822E_outputs = L9822E_outputs & 0xef;
    DAT_003fd5c4 = (ushort)CAL_ac_user_disable_time_min;
    DAT_003fd5c6 = (ushort)CAL_ac_user_enable_time_min;
    ac_fan_flags = ac_fan_flags & 0xfffffbff;
    DAT_003fd5ce = 0;
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
                  uint16_t_003fd880 = uint16_t_003fd880 | 1;
                }
                car_gear_current = 0;
              }
              else {
                if (car_gear_current != 6) {
                  uint16_t_003fd880 = uint16_t_003fd880 | 1;
                }
                car_gear_current = 6;
              }
            }
            else {
              if (car_gear_current != 5) {
                uint16_t_003fd880 = uint16_t_003fd880 | 1;
              }
              car_gear_current = 5;
            }
          }
          else {
            if (car_gear_current != 4) {
              uint16_t_003fd880 = uint16_t_003fd880 | 1;
            }
            car_gear_current = 4;
          }
        }
        else {
          if (car_gear_current != 3) {
            uint16_t_003fd880 = uint16_t_003fd880 | 1;
          }
          car_gear_current = 3;
        }
      }
      else {
        if (car_gear_current != 2) {
          uint16_t_003fd880 = uint16_t_003fd880 | 1;
        }
        car_gear_current = 2;
      }
    }
    else {
      if (car_gear_current != 1) {
        uint16_t_003fd880 = uint16_t_003fd880 | 1;
      }
      car_gear_current = 1;
    }
  }
  return;
}



// Coolant recirculation pump control

void recirculation_pump(void)

{
  if (obd_mode_0x2F_state == 0x14) {
    if (obd_mode_0x2F_value == 0) {
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
    if (CAL_fan_low_stop_time_min <= DAT_003fd5c0) {
      L9822E_outputs = L9822E_outputs | 8;
    }
  }
  else {
    ac_fan_flags = ac_fan_flags & 0xfffff7ff;
    DAT_003fd5c0 = 0;
    L9822E_outputs = L9822E_outputs & 0xf7;
    DAT_003fd5cf = 0;
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
     (((DAT_003f917a != 0 || ((ac_fan_flags & 8) != 0)) ||
      ((((L9822E_outputs & 0x10) != 0 && ((ac_fan_flags & 0x10) != 0)) ||
       ((sensor_fault_flags & 3) != 0)))))) {
    ac_fan_flags = ac_fan_flags | 0x1000;
    if (CAL_fan_high_stop_time_min <= DAT_003fd5c2) {
      L9822E_outputs = L9822E_outputs | 4;
    }
  }
  else {
    ac_fan_flags = ac_fan_flags & 0xffffefff;
    DAT_003fd5c2 = 0;
    L9822E_outputs = L9822E_outputs & 0xfb;
    DAT_003fd5d0 = 0;
  }
  if (sensor_adc_ac_fan_request < 0x200) {
    DAT_003f917a = (ushort)CAL_fan_high_stop_user_delay * 200;
  }
  return;
}



// Updates variable pointer I/O for external tool communication

void dev_varptr_io_update(void)

{
  ushort uVar1;
  
  DAT_003fd887 = (L9822E_outputs & 8) != 0;
  DAT_003fd888 = (L9822E_outputs & 4) != 0;
  DAT_003fd889 = (L9822E_outputs & 0x10) != 0;
  DAT_003fd88a = (L9822E_outputs & 2) != 0;
  uVar1 = REG_MPWMSM16_SCR;
  REG_MPWMSM16_SCR = uVar1 & 0x7fff | 0x8000;
  DAT_003fd88b = 1;
  uVar1 = REG_MPIOSMDR;
  DAT_003fd88c = -1 < (short)uVar1;
  DAT_003fd88d = (uint)CAL_ecu_ign_min << 2 <= (uint)sensor_adc_ign;
  DAT_003fd88e = sensor_adc_ac_fan_request < 0x200;
  uVar1 = REG_MPIOSMDR;
  DAT_003fd895 = (uVar1 >> 2 & 1) == 1;
  uVar1 = REG_MPIOSMDR;
  DAT_003fd894 = (uVar1 & 1) == 1;
  return;
}



// Sends engine data to instrument cluster via CAN

void send_cluster_data(void)

{
  byte bVar1;
  byte bVar3;
  int iVar2;
  
  if ((((LEA_ecu_VIN[0xb] == 'A') || (LEA_ecu_VIN[0xb] == 'B')) || (LEA_ecu_VIN[0xb] == 'L')) ||
     (LEA_ecu_VIN[0xb] == 'M')) {
    lights_flags[1] = lights_flags[1] & 0xdf;
  }
  else {
    lights_flags[1] = lights_flags[1] | 0x20;
  }
  if ((LEA_ecu_VIN[0xb] == 'A') || (LEA_ecu_VIN[0xb] == 'L')) {
    lights_flags[0] = lights_flags[0] | 0x80;
  }
  else {
    lights_flags[0] = lights_flags[0] & 0x7f;
  }
  bVar1 = lookup_2D_uint8_fixed
                    (8,car_gear_current,CAL_misc_shift_lights_before_revlimit_X_car_gear_current);
  DAT_003f9178 = (ushort)bVar1 << 1;
  bVar3 = lights_flags[0];
  if (engine_speed_1 != 0) {
    if (shift_lights_state == 2) {
      bVar3 = lights_flags[0] & 0xfb | 3;
      if ((int)((uint)revlimit + (uint)bVar1 * -4) < (int)(uint)engine_speed_2) {
        shift_lights_state = 3;
        bVar3 = lights_flags[0] & 0xfb | 7;
      }
      else if ((int)(uint)engine_speed_2 <
               (int)(((uint)revlimit + (uint)bVar1 * -6) - (uint)CAL_misc_shift_lights_margin)) {
        shift_lights_state = 1;
        bVar3 = bVar3 & 0xfd;
      }
    }
    else {
      if (shift_lights_state < 2) {
        if (shift_lights_state == 0) {
          bVar3 = lights_flags[0] & 0xf8;
          if ((int)((uint)revlimit + (uint)bVar1 * -8) < (int)(uint)engine_speed_2) {
            shift_lights_state = 1;
            bVar3 = lights_flags[0] & 0xf8 | 1;
          }
          goto LAB_0003c600;
        }
        if (true) {
          if ((int)((uint)revlimit + (uint)bVar1 * -6) < (int)(uint)engine_speed_2) {
            shift_lights_state = shift_lights_state + 1;
            bVar3 = lights_flags[0] & 0xf9 | 3;
          }
          else {
            bVar3 = lights_flags[0] & 0xf9 | 1;
            if ((int)(uint)engine_speed_2 <
                (int)(((uint)revlimit + (uint)bVar1 * -8) - (uint)CAL_misc_shift_lights_margin)) {
              shift_lights_state = shift_lights_state - 1;
              bVar3 = lights_flags[0] & 0xf8;
            }
          }
          goto LAB_0003c600;
        }
      }
      else if (shift_lights_state < 4) {
        bVar3 = lights_flags[0] ^ 7;
        if ((int)(uint)engine_speed_2 <
            (int)(((uint)revlimit + (uint)bVar1 * -4) - (uint)CAL_misc_shift_lights_margin)) {
          shift_lights_state = shift_lights_state - 1;
          bVar3 = (lights_flags[0] ^ 7) & 0xfb | 3;
        }
        goto LAB_0003c600;
      }
      bVar3 = lights_flags[0] & 0xf8;
    }
  }
LAB_0003c600:
  lights_flags[0] = bVar3;
  if (fuel_level < 0xe) {
    DAT_003fd886 = 0;
  }
  else if (fuel_level < 0xab) {
    DAT_003fd886 = (u8_factor_1_255)(((fuel_level - 0xe & 0xffff) * 0xff) / 0x9c);
  }
  else {
    DAT_003fd886 = 255;
  }
  if ((((tc_flags & 0x20) == 0) && (engine_speed_1 != 0)) || (LEA_tc_button_fitted != true)) {
    lights_flags[0] = lights_flags[0] & 0xdf;
  }
  else {
    lights_flags[0] = lights_flags[0] | 0x20;
  }
  lights_flags[0] = lights_flags[0] & 0xbf;
  if ((((tpms_flags & 0x10) != 0) && ((tpms_flags & 1) == 0)) &&
     (lights_flags[0] = lights_flags[0] | 0x40, DAT_003f9184 == '\0')) {
    DAT_003fd898 = DAT_003fd898 | 0x10;
  }
  if ((((tpms_flags & 0x20) != 0) && ((tpms_flags & 2) == 0)) &&
     (lights_flags[0] = lights_flags[0] | 0x40, DAT_003f9184 == '\0')) {
    DAT_003fd898 = DAT_003fd898 | 0x40;
  }
  if ((((tpms_flags & 0x40) != 0) && ((tpms_flags & 4) == 0)) &&
     (lights_flags[0] = lights_flags[0] | 0x40, DAT_003f9184 == '\0')) {
    DAT_003fd898 = DAT_003fd898 | 0x100;
  }
  if ((((tpms_flags & 0x80) != 0) && ((tpms_flags & 8) == 0)) &&
     (lights_flags[0] = lights_flags[0] | 0x40, DAT_003f9184 == '\0')) {
    DAT_003fd898 = DAT_003fd898 | 0x400;
  }
  if (((tpms_flags & 0x100) != 0) || (DAT_003fd9b9 == '\x01')) {
    if (DAT_003f9182 < 0x28a) {
      DAT_003f9182 = DAT_003f9182 + 1;
      if (DAT_003f9180 == '\0') {
        DAT_003f917f = DAT_003f917f ^ 0x40;
        DAT_003f9180 = '\x05';
      }
      else {
        DAT_003f9180 = DAT_003f9180 + -1;
      }
      if (DAT_003f917f == 0) {
        lights_flags[0] = lights_flags[0] & 0xbf;
      }
      else {
        lights_flags[0] = lights_flags[0] | 0x40;
      }
    }
    else {
      lights_flags[0] = lights_flags[0] | 0x40;
    }
    if (DAT_003f9184 == '\0') {
      DAT_003fd898 = DAT_003fd898 | 0x1000;
    }
  }
  if (obd_mode_0x2F_state == '\x17') {
    if (obd_mode_0x2F_value != '\0') {
      lights_flags[0] = lights_flags[0] | 0x10;
    }
  }
  else if (sensor_adc_oil_pressure < 0x200) {
    lights_flags[0] = lights_flags[0] | 0x10;
  }
  else {
    lights_flags[0] = lights_flags[0] & 0xef;
  }
  if (obd_mode_0x2F_state == '\x11') {
    if (obd_mode_0x2F_value != '\0') {
      lights_flags[0] = lights_flags[0] | 8;
    }
  }
  else if ((obd_mil_flags & 8) == 0) {
    lights_flags[0] = lights_flags[0] & 0xf7;
  }
  else {
    lights_flags[0] = lights_flags[0] | 8;
  }
  if (obd_mode_0x2F_state == '\v') {
    data2cluster.speed_display = DAT_003fc5b1;
  }
  else if (car_speed_smooth < 0x82) {
    data2cluster.speed_display = (u8_speed_kph)(((uint)car_speed_smooth * 0x6b) / 100);
  }
  else if (car_speed_smooth < 0x9b) {
    iVar2 = ((0x9b - (uint)car_speed_smooth) * 2 + 0x14) * (uint)car_speed_smooth;
    iVar2 = iVar2 / 1000 + (iVar2 >> 0x1f);
    data2cluster.speed_display = car_speed_smooth + ((char)iVar2 - (char)(iVar2 >> 0x1f));
  }
  else {
    data2cluster.speed_display = (u8_speed_kph)(((uint)car_speed_smooth * 0x66) / 100);
  }
  data2cluster.speed_odo = car_speed_smooth;
  if (obd_mode_0x2F_state == '\f') {
    data2cluster.rpm = obd_mode_0x2F_RPM;
  }
  else if (DAT_003f8cba == 0) {
    data2cluster.rpm = LEA_tc_launchcontrol_revlimit;
  }
  else {
    data2cluster.rpm = engine_speed_2;
  }
  data2cluster.fuel_level = DAT_003fd886;
  data2cluster.temp_coolant = coolant_smooth;
  if (CAL_misc_coolant_warning_max < coolant_smooth) {
    lights_flags[1] = lights_flags[1] | 0x10;
  }
  else {
    lights_flags[1] = lights_flags[1] & 0xef;
  }
  data2cluster.lights_flags[0] = lights_flags[0];
  data2cluster.lights_flags[1] = lights_flags[1];
  can_a_send_cluster(&data2cluster);
  return;
}



// Sends text messages to cluster display

void send_cluster_text(void)

{
  byte bVar1;
  char local_38 [7];
  char local_31 [7];
  char local_2a [7];
  char local_23 [7];
  char local_1c [7];
  char local_15 [7];
  
  builtin_strncpy(local_15," LF LOW",7);
  builtin_strncpy(local_1c," RF LOW",7);
  builtin_strncpy(local_23," LR LOW",7);
  builtin_strncpy(local_2a," RR LOW",7);
  builtin_strncpy(local_31," TPMS  ",7);
  builtin_strncpy(local_38," FAULT ",7);
  DAT_003fd89c = 0;
  if (DAT_003f9184 == '\0') {
    DAT_003f9184 = '<';
  }
  else {
    DAT_003f9184 = DAT_003f9184 + -1;
  }
  if (((((DAT_003fd898 & 0x10) == 0) || ((DAT_003fd898 & 1) != 0)) && ((DAT_003fd898 & 8) == 0)) ||
     (DAT_003f8249 == 0)) {
    if ((DAT_003fd898 & 8) != 0) {
      DAT_003fd89c = 0;
      DAT_003fd898 = DAT_003fd898 & 0xfffffff6;
      DAT_003f8249 = DAT_003f8248;
    }
  }
  else {
    DAT_003fd89c = 1;
    for (bVar1 = 1; bVar1 < 8; bVar1 = bVar1 + 1) {
      (&DAT_003fd89c)[bVar1] = local_15[bVar1];
    }
    DAT_003fd898 = DAT_003fd898 & 0xffffffef | 9;
    DAT_003f8249 = DAT_003f8249 - 1;
  }
  if (((((DAT_003fd898 & 0x40) == 0) || ((DAT_003fd898 & 1) != 0)) && ((DAT_003fd898 & 0x20) == 0))
     || (DAT_003f8249 == 0)) {
    if ((DAT_003fd898 & 0x20) != 0) {
      DAT_003fd89c = 0;
      DAT_003fd898 = DAT_003fd898 & 0xffffffde;
      DAT_003f8249 = DAT_003f8248;
    }
  }
  else {
    DAT_003fd89c = 1;
    for (bVar1 = 1; bVar1 < 8; bVar1 = bVar1 + 1) {
      (&DAT_003fd89c)[bVar1] = local_1c[bVar1];
    }
    DAT_003fd898 = DAT_003fd898 & 0xffffffbf | 0x21;
    DAT_003f8249 = DAT_003f8249 - 1;
  }
  if (((((DAT_003fd898 & 0x100) == 0) || ((DAT_003fd898 & 1) != 0)) && ((DAT_003fd898 & 0x80) == 0))
     || (DAT_003f8249 == 0)) {
    if ((DAT_003fd898 & 0x80) != 0) {
      DAT_003fd89c = 0;
      DAT_003fd898 = DAT_003fd898 & 0xffffff7e;
      DAT_003f8249 = DAT_003f8248;
    }
  }
  else {
    DAT_003fd89c = 1;
    for (bVar1 = 1; bVar1 < 8; bVar1 = bVar1 + 1) {
      (&DAT_003fd89c)[bVar1] = local_23[bVar1];
    }
    DAT_003fd898 = DAT_003fd898 & 0xfffffeff | 0x81;
    DAT_003f8249 = DAT_003f8249 - 1;
  }
  if (((((DAT_003fd898 & 0x400) == 0) || ((DAT_003fd898 & 1) != 0)) && ((DAT_003fd898 & 0x200) == 0)
      ) || (DAT_003f8249 == 0)) {
    if ((DAT_003fd898 & 0x200) != 0) {
      DAT_003fd89c = 0;
      DAT_003fd898 = DAT_003fd898 & 0xfffffdfe;
      DAT_003f8249 = DAT_003f8248;
    }
  }
  else {
    DAT_003fd89c = 1;
    for (bVar1 = 1; bVar1 < 8; bVar1 = bVar1 + 1) {
      (&DAT_003fd89c)[bVar1] = local_2a[bVar1];
    }
    DAT_003fd898 = DAT_003fd898 & 0xfffffbff | 0x201;
    DAT_003f8249 = DAT_003f8249 - 1;
  }
  if (((((DAT_003fd898 & 0x1000) == 0) || ((DAT_003fd898 & 1) != 0)) &&
      ((DAT_003fd898 & 0x800) == 0)) || (DAT_003f8249 == 0)) {
    if ((DAT_003fd898 & 0x800) != 0) {
      DAT_003fd89c = 0;
      DAT_003fd898 = DAT_003fd898 & 0xfffff7fe;
      DAT_003f8249 = DAT_003f8248;
    }
  }
  else {
    DAT_003fd89c = 1;
    if (((DAT_003f8249 & 3) == 0) || ((DAT_003f8249 + 1 & 3) == 0)) {
      for (bVar1 = 1; bVar1 < 8; bVar1 = bVar1 + 1) {
        (&DAT_003fd89c)[bVar1] = local_31[bVar1];
      }
    }
    else {
      for (bVar1 = 1; bVar1 < 8; bVar1 = bVar1 + 1) {
        (&DAT_003fd89c)[bVar1] = local_38[bVar1];
      }
    }
    DAT_003fd898 = DAT_003fd898 & 0xffffefff | 0x801;
    DAT_003f8249 = DAT_003f8249 - 1;
  }
  if ((((DAT_003fd898 & 0x4000) != 0) && ((DAT_003fd898 & 0x2000) != 0)) && (DAT_003f8249 < 8)) {
    DAT_003f8249 = DAT_003f8248;
  }
  if (((((DAT_003fd898 & 0x4000) == 0) || ((DAT_003fd898 & 1) != 0)) &&
      ((DAT_003fd898 & 0x2000) == 0)) || (DAT_003f8249 == 0)) {
    if ((DAT_003fd898 & 0x2000) != 0) {
      DAT_003fd89c = 0;
      DAT_003fd898 = DAT_003fd898 & 0xffffdffe;
      DAT_003f8249 = DAT_003f8248;
    }
  }
  else {
    DAT_003fd89c = 1;
    if ((tc_flags & 0x80) == 0) {
      DAT_003fd89d = 'L';
      DAT_003fd89e = 'T';
      DAT_003fd89f = 'C';
      DAT_003fd8a0 = ' ';
      DAT_003fd8a1 = 'O';
      DAT_003fd8a2 = 'N';
      DAT_003fd8a3 = ' ';
    }
    else if (tc_state == '\x03') {
      DAT_003fd89d = 'L';
      DAT_003fd89e = 'T';
      DAT_003fd89f = 'C';
      DAT_003fd8a0 = ' ';
      DAT_003fd8a1 = 'O';
      DAT_003fd8a2 = 'F';
      DAT_003fd8a3 = 'F';
    }
    else if ((DAT_003f8249 < 9) || ((DAT_003fd898 & 0x8000) == 0)) {
      DAT_003fd898 = DAT_003fd898 & 0xffff7fff;
      DAT_003fd89d = (byte)(sensor_adc_tc_knob / 100) | 0x30;
      DAT_003fd89e = '%';
      DAT_003fd89f = ' ';
      DAT_003fd8a0 = 'S';
      DAT_003fd8a1 = 'l';
      DAT_003fd8a2 = 'i';
      DAT_003fd8a3 = 'p';
    }
    else {
      DAT_003fd89d = ' ';
      DAT_003fd89e = ' ';
      DAT_003fd89f = 'L';
      DAT_003fd8a0 = 'T';
      DAT_003fd8a1 = 'C';
      DAT_003fd8a2 = ' ';
      DAT_003fd8a3 = ' ';
    }
    DAT_003fd898 = DAT_003fd898 & 0xffffbfff | 0x2001;
    DAT_003f8249 = DAT_003f8249 - 1;
  }
  if (((DAT_003fd898 & 0x20000) != 0) && ((DAT_003fd898 & 0x10000) != 0)) {
    DAT_003f8249 = DAT_003f8248;
  }
  if (((((DAT_003fd898 & 0x20000) == 0) || ((DAT_003fd898 & 1) != 0)) &&
      ((DAT_003fd898 & 0x10000) == 0)) || (DAT_003f8249 == 0)) {
    if ((DAT_003fd898 & 0x10000) != 0) {
      DAT_003fd89c = 0;
      DAT_003fd898 = DAT_003fd898 & 0xfffefffe;
      DAT_003f8249 = DAT_003f8248;
    }
  }
  else {
    DAT_003fd89c = 1;
    DAT_003fd89d = 'L';
    DAT_003fd89e = 'a';
    DAT_003fd89f = 'u';
    DAT_003fd8a0 = 'n';
    DAT_003fd8a1 = 'c';
    DAT_003fd8a2 = 'h';
    DAT_003fd8a3 = ' ';
    DAT_003fd898 = DAT_003fd898 & 0xfffdffff | 0x10001;
    DAT_003f8249 = DAT_003f8249 - 1;
  }
  DAT_003fd898 = DAT_003fd898 | 0x40000;
  return;
}



// Airbox flap control for cold air intake

void airbox_flap(void)

{
  if (obd_mode_0x2F_state == 0x16) {
    if (obd_mode_0x2F_value == 0) {
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



// Cluster communication task (100ms)

void cluster_task_100ms(void)

{
  bool bVar1;
  byte bVar2;
  
  if (DAT_003f917a != 0) {
    DAT_003f917a = DAT_003f917a + -1;
  }
  DAT_003f824a = DAT_003f824a + -1;
  if (DAT_003f824a == '\0') {
    DAT_003f824a = '\x05';
    send_cluster_text();
  }
  send_cluster_data();
  if (CAL_tpms_use_tpms != false) {
    can_b_send_rpm_speed();
    tpms_process();
    bVar2 = DAT_003f9188 + 1;
    bVar1 = 8 < DAT_003f9188;
    DAT_003f9188 = bVar2;
    if (bVar1) {
      can_b_send_temp();
      DAT_003f9188 = 0;
    }
  }
  return;
}



// Computes CRC16 using lookup table for calibration and learned data integrity

uint16_t CRC16(char *data,ushort size)

{
  uint crc;
  
  crc = 0;
  for (; size != 0; size = size - 1) {
    watchdog_retrigger();
    crc = (int)crc >> 8 ^ (uint)CRC16_lookup[(crc ^ (byte)*data) & 0xff];
    data = (char *)((byte *)data + 1);
  }
  return (uint16_t)crc;
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
  if ((int)(uint)DAT_003fd8e2 < (int)atmo_pressure) {
    vacuum_1 = atmo_pressure - DAT_003fd8e2;
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
  DAT_003fd8ee = lookup_3D_uint8_get_address
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
  DAT_003fd904 = (ushort)bVar4 << 2;
  if (engine_is_running == false) {
    iVar5 = (uint)bVar3 * 4 * (int)atmo_pressure;
    iVar5 = iVar5 / 1013 + (iVar5 >> 0x1f);
    load_alphaN = ((iVar5 - (iVar5 >> 0x1f)) * 298) /
                  (((int)((uint)engine_air_smooth * 5) >> 3) + 233);
  }
  else {
    iVar5 = (uint)bVar4 * 4 * (int)(short)load_alphaN_adj;
    iVar5 = iVar5 / 100 + (iVar5 >> 0x1f);
    iVar5 = (int)atmo_pressure * (iVar5 - (iVar5 >> 0x1f));
    iVar5 = iVar5 / 1013 + (iVar5 >> 0x1f);
    load_alphaN = ((iVar5 - (iVar5 >> 0x1f)) * 298) /
                  (((int)((uint)engine_air_smooth * 5) >> 3) + 233);
  }
  iVar5 = (uint)engine_speed_period_avg * ((int)((uint)maf_flow_1 + (uint)maf_flow_2) >> 1);
  iVar5 = iVar5 / 10 + (iVar5 >> 0x1f);
  uVar6 = iVar5 - (iVar5 >> 0x1f);
  uVar2 = uVar6 * 2;
  iVar5 = (int)uVar2 / 10000 + ((int)(uVar2 | uVar6 >> 0x1f) >> 0x1f);
  load_maf = iVar5 - (iVar5 >> 0x1f);
  uVar2 = (((uint)evap_flow * (uint)engine_speed_period_avg) / 100 << 1) / 10000;
  DAT_003fd93a = (undefined2)uVar2;
  load_diff = (short)load_maf - (short)load_alphaN;
  if (load_maf != 0) {
    load_alphaN_maf_error = (u8_factor_1_100)((int)(load_alphaN * 100) / (int)load_maf);
  }
  DAT_003fd906 = (undefined2)((((load_diff * 10000) / (int)(uint)engine_speed_period_avg) * 10) / 2)
  ;
  if ((((int)dt_tps_target_1 < -(int)(short)CAL_load_use_alphaN_dt_tps_target_1_negative_min) ||
      ((short)CAL_load_use_alphaN_dt_tps_target_1_positive_min < dt_tps_target_1)) ||
     ((load_use_alphaN_tps_min < tps && ((idle_flags & 8) == 0)))) {
    DAT_003fd90a = CAL_load_use_alphaN_timer;
  }
  if (((engine_is_running == false) || ((sensor_fault_flags & 0x10) != 0)) ||
     ((DAT_003fd90a != 0 &&
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
  DAT_003f9192 = lookup_2D_uint8_interpolated
                           (16,engine_speed_3,CAL_load_possible_max,
                            CAL_load_possible_max_X_engine_speed);
  if ((int)load_1_smooth >> 2 < (int)(uint)DAT_003f9192) {
    load_3 = (u8_factor_1_255)
             (((int)(load_1_smooth * 1013) / (int)atmo_pressure << 6) / (int)(uint)DAT_003f9192);
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
  bVar3 = lookup_2D_uint8_interpolated(16,engine_speed_3,&DAT_003fa8d4,&DAT_003fa8c4);
  DAT_003fd8f2 = (ushort)bVar3 << 1;
  bVar3 = lookup_2D_uint8_interpolated(16,engine_speed_3,&DAT_003fa8f4,&DAT_003fa8e4);
  DAT_003fd8f4 = bVar3 + 153;
  uVar2 = 27300 / (((int)((uint)engine_air_smooth * 5) >> 3) + 233U);
  DAT_003fd910 = (char)uVar2;
  iVar5 = (atmo_pressure * 100) / 1013 + (atmo_pressure * 100 >> 0x1f);
  DAT_003fd911 = (char)iVar5 - (char)(iVar5 >> 0x1f);
  DAT_003fd8e2 = (short)(((uint)DAT_003fd8f2 * (uint)DAT_003fd911) / 100) +
                 (short)((int)(load_1_smooth * 37778) /
                        (int)((uint)(ushort)(bVar3 + 153) * (uVar2 & 0xff)));
  return;
}



// EVAP purge state machine - manages canister purge sequence

void evap_state_machine(void)

{
  if (((((((evap_flags & 0x100) == 0) || ((DAT_003fdc70 & 0x1000) != 0)) ||
        ((DAT_003fdc70 & 0x8000) != 0)) &&
       ((((DAT_003fdc70 & 4) == 0 || ((evap_flags & 1) == 0)) && ((DAT_003fdc70 & 1) == 0)))) ||
      (CAL_evap_purge_mode == 1)) &&
     (((CAL_evap_purge_mode != 2 && (DAT_003f91b6 == 0)) &&
      ((((misfire_flags & 0x20) == 0 &&
        ((((fuel_system_status & 2) != 0 && ((DAT_003fdc70 & 0x400) == 0)) &&
         ((LEA_obd_P0441_flags & 4) == 0)))) &&
       (((LEA_obd_P0444_flags & 4) == 0 && ((LEA_obd_P0445_flags & 4) == 0)))))))) {
    evap_flags = evap_flags | 2;
  }
  else if ((fuel_system_status & 2) == 0) {
    if (((fuel_system_status & 0x404) == 0) || (DAT_003f91ba == 0)) {
      evap_flags = evap_flags & 0xfffd;
    }
  }
  else {
    evap_flags = evap_flags & 0xfffd;
  }
  if (DAT_003f8254 == 0) {
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
  if (((DAT_003f91b6 == 0) && ((DAT_003fdc70 & 0x400) == 0)) &&
     (((evap_flags & 0x20) == 0 || ((evap_flags & 0x80) == 0)))) {
    evap_flags = evap_flags & 0xffbf;
  }
  else {
    evap_flags = evap_flags | 0x40;
  }
  if (!engine_is_running) {
    DAT_003f91b6 = (ushort)CAL_evap_engine_start_delay << 3;
    DAT_003f91be = (ushort)CAL_evap_restart_delay << 4;
  }
  if ((DAT_003fd74c & 1) == 0) {
    DAT_003f91ba = CAL_evap_closedloop_delay;
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
      fuel_learn_timer = (u16_time_100ms)((int)(uint)DAT_003f9ace >> 3);
      return;
    }
    evap_state = 0;
    inj_time_adj_by_stft = 0;
    fuel_learn_timer = DAT_003f9ace;
    return;
  }
  if (evap_state < 2) {
    if (evap_state == 0) {
      if (((evap_flags & 0x100) != 0) && (fuel_learn_timer == 0)) {
        if ((evap_flags & 0x800) == 0) {
          if ((evap_flags & 0x1000) == 0) {
            fuel_learn_timer = DAT_003f9ace;
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
        if ((DAT_003fdc70 & 4) == 0) {
          DAT_003f8254 = CAL_evap_initial_delay;
          evap_concentration_1 = 0;
          evap_pressure_drop_1 = 0;
          DAT_003f91c1 = CAL_evap_duty_cycle_initial_time;
          evap_pressure_drop_2 = 0;
          return;
        }
        if ((evap_flags & 1) == 0) {
          DAT_003f8254 = CAL_evap_initial_delay;
          evap_concentration_1 = 0;
          evap_pressure_drop_1 = 0;
          DAT_003f91c1 = CAL_evap_duty_cycle_initial_time;
          evap_pressure_drop_2 = 0;
          return;
        }
        DAT_003f8254 = CAL_evap_initial_delay;
        evap_concentration_1 = 0;
        evap_pressure_drop_1 = 0;
        DAT_003f91c1 = CAL_evap_duty_cycle_initial_time;
        evap_flags = evap_flags & 0xfbff;
        evap_pressure_drop_2 = 0;
        evap_state = 4;
        DAT_003fdc70 = DAT_003fdc70 | 8;
        return;
      }
      if ((evap_flags & 0x20) != 0) {
        DAT_003f8254 = CAL_evap_initial_delay;
        evap_concentration_1 = 0;
        evap_pressure_drop_1 = 0;
        DAT_003f91c1 = CAL_evap_duty_cycle_initial_time;
        evap_pressure_drop_2 = 0;
        return;
      }
      if ((evap_flags & 0x40) != 0) {
        DAT_003f8254 = CAL_evap_initial_delay;
        evap_concentration_1 = 0;
        evap_pressure_drop_1 = 0;
        DAT_003f91c1 = CAL_evap_duty_cycle_initial_time;
        evap_pressure_drop_2 = 0;
        return;
      }
      DAT_003f8254 = CAL_evap_initial_delay;
      evap_concentration_1 = 0;
      evap_pressure_drop_1 = 0;
      DAT_003f91c1 = CAL_evap_duty_cycle_initial_time;
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
        if (DAT_003f91be != 0) {
          evap_pressure_drop_1 = 0;
        }
        DAT_003f8255 = CAL_evap_dfso_recovery_delay;
        evap_pressure_drop_2 = 0;
        evap_state = 3;
        return;
      }
      if ((evap_flags & 2) == 0) {
        evap_state = evap_state + 1;
        return;
      }
      if (((DAT_003f9a76 < evap_purge_command) && (evap_concentration_2 < DAT_003f9a72)) &&
         ((closedloop_flags & 0x10) != 0)) {
        if (DAT_003f91bc == 0) {
          evap_flags = evap_flags | 0x900;
        }
      }
      else {
        DAT_003f91bc = CAL_evap_learn_delay;
      }
      if (evap_concentration_2 <= DAT_003f9a9a) {
        if (evap_purge_command <= DAT_003f9a76) {
          return;
        }
        evap_flags = evap_flags | 1;
        return;
      }
      if ((DAT_003fdc70 & 4) == 0) {
        return;
      }
      evap_flags = evap_flags & 0xfffe | 0x200;
      return;
    }
  }
  else {
    if (evap_state == 4) {
      if ((((DAT_003fdc70 & 4) == 0) || ((evap_flags & 2) != 0)) || ((evap_flags & 1) == 0)) {
        DAT_003fdc70 = DAT_003fdc70 & 0xfff7;
        evap_state = 0;
      }
      if (evap_leak_state < 3) {
        DAT_003f8254 = CAL_evap_initial_delay;
      }
      if (evap_concentration_2 <= DAT_003f9a74) {
        return;
      }
      evap_flags = evap_flags & 0xfffe | 0x600;
      return;
    }
    if (evap_state < 4) {
      if ((DAT_003f8255 != '\0') && ((evap_flags & 0x40) == 0)) {
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



// EVAP purge duty cycle calculation

void evap(void)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  ushort uVar4;
  
  push_26to31();
  if ((inj_time_stft_smooth < -199) || (199 < inj_time_stft_smooth)) {
    evap_flags = evap_flags & 0xffef;
  }
  else {
    evap_flags = evap_flags | 0x10;
  }
  if ((((inj_time_stft_smooth < -99) || (99 < inj_time_stft_smooth)) || ((evap_flags & 0x100) == 0))
     || (evap_pressure_drop_2 != 0)) {
    evap_flags = evap_flags & 0xefff;
    DAT_003f91c0 = CAL_evap_stft_stability_delay;
  }
  else if (DAT_003f91c0 == 0) {
    evap_flags = evap_flags | 0x1000;
  }
  if (DAT_003f8254 == '\0') {
    uVar2 = ((uint)maf_flow_1 * 225) / ((uint)evap_concentration_2 * 2 + 750);
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
     ((evap_state == '\x04' && ((DAT_003fdc70 & 0x20) == 0)))) {
    evap_flags = evap_flags & 0xfffb | 8;
  }
  else if ((((CAL_evap_idle_flow_enable < idle_flow_target) &&
            ((int)((uint)CAL_evap_inj_time_enable << 3) < (int)inj_time_final_1)) &&
           ((evap_flags & 0x10) != 0)) &&
          (((evap_state == '\x01' &&
            ((((DAT_003fdc70 & 0x8000) == 0 && ((DAT_003fdc70 & 0x1000) == 0)) ||
             ((short)evap_purge_command < DAT_003fc602)))) ||
           ((evap_state == '\x04' && ((DAT_003fdc70 & 0x20) != 0)))))) {
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
         (ushort)(((uint)DAT_003fd748 * ((uint)CAL_evap_inj_time_enable * 8 - (uint)inj_time_base))
                 / 10000);
    uVar2 = ((uVar2 * 290044) / (uint)((int)(uint)evap_concentration_2 >> 1)) /
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
  uVar2 = ((uint)evap_pressure_drop_2 * 10130000) / 1880424;
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
  if ((DAT_003fd74c & 1) == 0) {
    evap_stft_neg = -inj_time_stft_smooth;
  }
  else {
    evap_stft_neg = 0;
  }
  iVar3 = (int)((int)evap_stft_neg * (uint)inj_fuel_load_needed * 25) /
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
    if (DAT_003f91c1 != '\0') {
      uVar4 = (ushort)CAL_evap_duty_cycle_initial;
    }
  }
  evap_pwm_pulse = (undefined2)((int)(short)uVar4 * (uint)CAL_evap_period >> 8);
  set_evap_pwm(evap_pwm_pulse);
  pop_26to31();
  return;
}



// EVAP monitoring task (100ms)

void evap_100ms(void)

{
  uint uVar1;
  
  if ((DAT_003f8254 != '\0') && ((evap_flags & 0x10) != 0)) {
    DAT_003f8254 = DAT_003f8254 + -1;
  }
  if (DAT_003f8255 != '\0') {
    DAT_003f8255 = DAT_003f8255 + -1;
  }
  if ((DAT_003f91b6 != 0) && ((fuel_system_status & 2) != 0)) {
    DAT_003f91b6 = DAT_003f91b6 + -1;
  }
  if (DAT_003f91ba != '\0') {
    DAT_003f91ba = DAT_003f91ba + -1;
  }
  if (DAT_003f91c0 != '\0') {
    DAT_003f91c0 = DAT_003f91c0 + -1;
  }
  if (DAT_003f91be != 0) {
    DAT_003f91be = DAT_003f91be + -1;
  }
  if (DAT_003f91bc != '\0') {
    DAT_003f91bc = DAT_003f91bc + -1;
  }
  if (DAT_003f91c1 != '\0') {
    DAT_003f91c1 = DAT_003f91c1 + -1;
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
        ((inj_time_stft_smooth < DAT_003f9198 ||
         ((int)inj_time_stft_smooth <= -((short)CAL_stft_limit + -40))))) ||
       ((evap_concentration_adj < 0 &&
        ((DAT_003f9198 < inj_time_stft_smooth ||
         ((short)CAL_stft_limit + -40 <= (int)inj_time_stft_smooth)))))) {
      evap_concentration_1 = evap_concentration_1 + evap_concentration_adj * DAT_003f9a98;
      if (evap_concentration_1 < 0xffff01) {
        if (evap_concentration_1 < 0) {
          evap_concentration_1 = 0;
        }
      }
      else {
        evap_concentration_1 = 0xffff00;
      }
    }
    DAT_003f9198 = inj_time_stft_smooth;
  }
  if ((evap_flags & 0x20) == 0) {
    if ((uint)evap_pressure_drop_max << 8 < (uint)evap_pressure_drop_1) {
      if (DAT_003f91bb < 3) {
        DAT_003f91bb = DAT_003f91bb + 1;
      }
      else {
        evap_pressure_drop_1 = (ushort)evap_pressure_drop_max << 8;
      }
    }
    else {
      DAT_003f91bb = 0;
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
    DAT_003f91bb = 0;
  }
  DAT_003fd94c = DAT_003fd94c + (uint)evap_pressure_drop_2;
  DAT_003f91a8 = DAT_003f91a8 + (uint)evap_flow;
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
  
  memcpy(LEA_base,"CroftT4E090 14/07/2006 Lotus EngV0091",0x20);
  LEA_sensor_pps_1_offset = CAL_sensor_pps_1_offset;
  LEA_sensor_pps_2_offset = CAL_sensor_pps_2_offset;
  LEA_idle_flow_adj1 = 0;
  LEA_idle_flow_adj1_ac_on = 0;
  for (iVar2 = 0; iVar2 < 8; iVar2 = iVar2 + 1) {
    (&DAT_002f82df)[iVar2] = (&DAT_003fd426)[iVar2];
    (&DAT_002f82cf)[iVar2] = (&DAT_003fd426)[iVar2];
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
    *(undefined1 *)((int)&LEA_ecu_engine_speed_byte_coefficient + iVar2) =
         *(undefined1 *)(iVar2 + 0x3fd1ce);
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
    (&DAT_003fdcb6)[iVar2] = 0;
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
  DAT_002f8356 = 0;
  DAT_002f8354 = 0;
  DAT_002f835a = 0;
  DAT_002f8358 = 0;
  DAT_002f8366 = 0;
  for (iVar2 = 0; iVar2 < 4; iVar2 = iVar2 + 1) {
    LEA_misfire_count[iVar2] = 0;
  }
  DAT_002f8365 = 0;
  DAT_002f8364 = 0;
  DAT_002f8362 = 0;
  LEA_evap_leak_result = 0;
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
    (&DAT_002f8286)[iVar2] = 0;
    (&DAT_002f829a)[iVar2] = 0;
    (&DAT_002f82ae)[iVar2] = 0;
  }
  LEA_tc_button_fitted = false;
  DAT_002f822e = 0;
  DAT_002f8230 = 0;
  DAT_002f8232 = 0;
  DAT_002f8234 = 0;
  DAT_002f82c2 = DAT_003fc9e6;
  DAT_002f835c = 0;
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
  uint16_t crc;
  
  obd_pre_save();
  crc = CRC16(LEA_base,0x568);
  DAT_002f8568 = (uint)crc;
  DAT_003fd9b2 = 0;
  eeprom_write(LEA_base,0x56c);
  return;
}



// Loads learned parameters from EEPROM with CRC validation

void eeprom_load(void)

{
  uint uVar1;
  int iVar2;
  uint16_t uVar3;
  
  eeprom_read(LEA_base,0x56c);
  uVar1 = only_zeros(0x7c0,0x20);
  if ((uVar1 & 0xff) == 1) {
    eeprom_write_at(0x7c0,CAL_ecu_model_name,0x20);
  }
  eeprom_read_at(0x7c0,&DAT_003f96e1,0x20);
  iVar2 = strncmp((byte *)CAL_ecu_model_name,&DAT_003f96e1,0x1f);
  security_flag = iVar2 != 0;
  uVar3 = CRC16(LEA_base,0x568);
  if (DAT_002f8568 != uVar3) {
    DAT_003fdc90 = DAT_003fdc90 | 1;
  }
  iVar2 = memcmp("CroftT4E090 14/07/2006 Lotus EngV0091",LEA_base,0x20);
  if ((iVar2 == 0) && ((DAT_003fdc90 & 1) == 0)) {
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
      (&DAT_003fdcb6)[iVar2] = 0;
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
      *(undefined1 *)((int)&LEA_ecu_engine_speed_byte_coefficient + iVar2) =
           *(undefined1 *)(iVar2 + 0x3fd1ce);
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
      (&DAT_002f8286)[iVar2] = 0;
      (&DAT_002f829a)[iVar2] = 0;
      (&DAT_002f82ae)[iVar2] = 0;
    }
    DAT_002f822e = 0;
    DAT_002f8230 = 0;
    DAT_002f8232 = 0;
    DAT_002f8234 = 0;
    DAT_002f82c2 = DAT_003fc9e6;
    DAT_002f835c = 0;
    LEA_tc_launchcontrol_revlimit = 10000;
    dev_reset_lea_magic = 0x4b4f;
  }
  return;
}



// Checks if EEPROM region contains only zeros

int only_zeros(uint addr,uint size)

{
  char cVar1;
  uint uVar2;
  
  uVar2 = 0;
  while( true ) {
    if ((size & 0xff) <= (uVar2 & 0xffff)) {
      return 1;
    }
    cVar1 = eeprom_read_byte(addr + (uVar2 & 0xffff) & 0xffff);
    if (cVar1 != '\0') break;
    uVar2 = uVar2 + 1;
  }
  return 0;
}



// Closed-loop fuel control state machine - enables/disables based on conditions

void closedloop(void)

{
  byte bVar1;
  
  bVar1 = lookup_2D_uint8_interpolated_noaxis(4,(ushort)coolant_stop,CAL_stft_runtime_min);
  DAT_003fd988 = (ushort)bVar1 * 200;
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
    DAT_003f8258 = CAL_stft_time_between_step;
    bVar1 = lookup_2D_uint8_interpolated
                      (8,engine_speed_3,CAL_stft_time_use_adj,CAL_stft_time_use_adj_X_engine_speed);
    stft_time_use_adj = (ushort)bVar1 * 5;
  }
  else {
    stft_enrichment_step = CAL_stft_idle_enrichment_step;
    stft_enleanment_step = CAL_stft_idle_enleanment_step;
    stft_enrichment_initial = CAL_stft_idle_enrichment_initial;
    stft_enleanment_initial = CAL_stft_idle_enleanment_initial;
    DAT_003f8258 = (u8_time_5ms)
                   (((uint)CAL_stft_idle_time_between_step * 1200) / (uint)engine_speed_2);
    stft_time_use_adj = 1275;
  }
  stft_lean_threshold = CAL_stft_stoich_min;
  stft_rich_threshold = CAL_stft_stoich_max;
  if (engine_speed_period == 65535) {
    closedloop_flags = 0;
    DAT_003f91da = 0;
    inj_time_adj_by_stft = 0;
    DAT_003fd98a = 0;
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
  if ((((engine_runtime < DAT_003fd988) || (engine_air_smooth <= CAL_stft_engine_air_min)) ||
      (afr_target != CAL_stft_afr)) || ((misfire_flags & 0x20) != 0)) {
    fuel_system_status = 1;
    if (afr_target < CAL_stft_afr) {
      fuel_system_status = 1025;
    }
    DAT_003fd98c = 0;
    DAT_003f91da = 0;
    inj_time_adj_by_stft = 0;
    closedloop_flags = closedloop_flags & 0xff1f;
    stft_time_use_adj_timer = stft_time_use_adj;
  }
  else if ((((DAT_003fdd42 == '\0') || (DAT_003fdd43 == '\0')) ||
           ((DAT_003fdcee == '\0' || ((DAT_003fd9fb == '\0' || (DAT_003fd9f2 == '\0')))))) ||
          ((DAT_003fd9f3 == '\0' || ((DAT_003fd9f4 == '\0' || (DAT_003fd9f5 == '\0')))))) {
    fuel_system_status = 8;
    DAT_003f91da = 0;
    inj_time_adj_by_stft = 0;
    closedloop_flags = closedloop_flags & 0xff1f;
    stft_time_use_adj_timer = stft_time_use_adj;
  }
  else if ((((dfso_flags & 1) == 0) &&
           (((injtip_in == 0 && (injtip_out == 0)) && (injtip_reactive == 0)))) &&
          (((tc_flags & 2) == 0 && (DAT_003f91d6 == '\0')))) {
    if ((closedloop_flags & 1) != 0) {
      DAT_003fd98c = 1;
      if (((DAT_003fdcfa & 2) == 0) || ((closedloop_flags & 0x40) == 0)) {
        fuel_system_status = 2;
        if ((closedloop_flags & 0x20) != 0) {
          closedloop_flags = closedloop_flags & 0xff9f | 0x80;
        }
        stft();
      }
      else {
        inj_time_adj_by_stft = DAT_003f91da;
        closedloop_flags = closedloop_flags | 0x20;
      }
    }
  }
  else {
    fuel_system_status = 1028;
    DAT_003f91da = 0;
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
        DAT_003fd98a = -stft_enleanment_step;
      }
      else {
        uVar1 = (int)stft_enleanment_step * (uint)CAL_stft_enleanment_step_adj;
        DAT_003fd98a = -((short)((int)uVar1 >> 6) + (ushort)((int)uVar1 < 0 && (uVar1 & 0x3f) != 0))
        ;
      }
    }
    else {
      DAT_003f91c8 = (ushort)DAT_003f8258;
      stft_time_use_adj_timer = stft_time_use_adj;
      DAT_003fd98a = -stft_enleanment_step;
      closedloop_flags = closedloop_flags & 0xfe7f | 0x4040;
      DAT_003f91da = inj_time_adj_by_stft;
      inj_time_adj_by_stft = inj_time_adj_by_stft - stft_enleanment_initial;
    }
  }
  else if ((short)sensor_adc_pre_o2 < (short)stft_lean_threshold) {
    if (((closedloop_flags & 0x40) == 0) && ((closedloop_flags & 0x80) != 0)) {
      if ((closedloop_flags & 0x100) == 0) {
        DAT_003fd98a = stft_enrichment_step;
      }
      else {
        uVar1 = (int)stft_enrichment_step * (uint)CAL_stft_enrichment_step_adj;
        DAT_003fd98a = (short)((int)uVar1 >> 6) + (ushort)((int)uVar1 < 0 && (uVar1 & 0x3f) != 0);
      }
    }
    else {
      DAT_003f91c8 = (ushort)DAT_003f8258;
      stft_time_use_adj_timer = stft_time_use_adj;
      DAT_003fd98a = stft_enrichment_step;
      closedloop_flags = closedloop_flags & 0xfebf | 0x8080;
      inj_time_adj_by_stft = inj_time_adj_by_stft + stft_enrichment_initial;
    }
  }
  else if ((closedloop_flags & 0x40) == 0) {
    if ((closedloop_flags & 0x80) != 0) {
      DAT_003fd98a = stft_enrichment_step;
    }
  }
  else {
    DAT_003fd98a = -stft_enleanment_step;
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
    DAT_003f91c8 = DAT_003f91c8 - 1;
    if ((short)DAT_003f91c8 < 1) {
      DAT_003f91c8 = (ushort)DAT_003f8258;
      inj_time_adj_by_stft = inj_time_adj_by_stft + DAT_003fd98a;
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
    if (((fuel_system_status == 4 | 0x400) != 0) && (DAT_003f91d6 != '\0')) {
      DAT_003f91d6 = DAT_003f91d6 + -1;
    }
  }
  else {
    DAT_003f91d6 = DAT_003f9941;
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
    DAT_003f91d5 = 1;
    inj_time_adj_by_ltft = 0;
  }
  else if (maf_flow_1 < CAL_ltft_zone2_flow_max) {
    DAT_003f91d5 = 2;
    uVar3 = (char)(LEA_ltft_zone2_adj ^ 0x80) * 500;
    inj_time_adj_by_ltft =
         (short)((int)uVar3 >> 7) + (ushort)((int)uVar3 < 0 && (uVar3 & 0x7f) != 0);
  }
  else if ((CAL_ltft_zone2_flow_max < maf_flow_1) && (maf_flow_1 < CAL_ltft_zone3_flow_min)) {
    DAT_003f91d5 = 4;
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
    DAT_003f91d5 = 3;
    uVar3 = (char)(LEA_ltft_zone3_adj ^ 0x80) * 500;
    inj_time_adj_by_ltft =
         (short)((int)uVar3 >> 7) + (ushort)((int)uVar3 < 0 && (uVar3 & 0x7f) != 0);
  }
  else {
    inj_time_adj_by_ltft = 0;
    DAT_003f91d5 = 0;
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
      bVar1 = DAT_003f91d4 == 0;
      DAT_003f91d4 = DAT_003f91d4 + 255;
      uVar4 = closedloop_flags | 0x410;
      if (bVar1) {
        DAT_003f91d4 = CAL_ltft_time_between_step;
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
    if (((closedloop_flags & 0x3000) != 0) && (DAT_003fd97e != -1)) {
      DAT_003fd97e = DAT_003fd97e + 1;
    }
  }
  else if (DAT_003fd97c != -1) {
    DAT_003fd97c = DAT_003fd97c + 1;
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



// Calculates knock sensing window timing per cylinder

void knock_window(void)

{
  byte i;
  
  push_25to31();
  knock_window_start =
       lookup_3D_uint8_interpolated
                 (16,16,(ushort)engine_speed_3,(ushort)load_2,CAL_knock_window_start,
                  CAL_knock_window_start_X_engine_speed,CAL_knock_window_start_Y_engine_load);
  knock_window_width =
       lookup_3D_uint8_interpolated
                 (16,16,(ushort)engine_speed_3,(ushort)load_2,CAL_knock_window_width,
                  CAL_knock_window_width_X_engine_speed,CAL_knock_window_width_Y_engine_load);
  if (knock_window_width < 65) {
    knock_window_width = 64;
  }
  for (i = 0; i < 4; i = i + 1) {
    knock_window_params[i] =
         ((uint)knock_window_start + knock_window_width + 26 & 0x7f) * 0x100 +
         ((knock_window_start + 26 & 0x7f) * 0x100 +
         (((int)(knock_window_start + 26) >> 7) + (crank_tooth_pattern["9\x03\x15\'"[i]] & 0xff) + 1
         & 0xff)) * 0x10000 +
         ((crank_tooth_pattern["9\x03\x15\'"[i]] & 0xff) +
          ((int)((uint)knock_window_start + knock_window_width + 26) >> 7) + 1 & 0xff);
  }
  pop_25to31();
  return;
}



// Main knock detection - threshold lookup and retard calculation

void knock(void)

{
  byte bVar2;
  uint uVar1;
  byte bVar3;
  
  push_25to31();
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
    DAT_003f91e8 = CAL_knock_retard1_dt_tps_target_2_time;
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
    if ((((DAT_003f91e8 == 0) && ((knock_flags & 0x20) != 0)) &&
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
  pop_25to31();
  return;
}



// Reads knock sensor signal level for specified cylinder

void knock_read_signal(uint8_t cyl)

{
  ushort uVar1;
  byte i;
  
  if (DAT_003f91e2 < 2000) {
    DAT_003f91e2 = DAT_003f91e2 + 1;
  }
  else {
    DAT_003f91e2 = 0;
    DAT_003f91e4 = 0;
    for (i = 0; i < 4; i = i + 1) {
      uint8_t_ARRAY_003f82bc[i] = (uint8_t)((int)(uint)uint16_t_ARRAY_003f82b4[i] >> 1);
      DAT_003f91e4 = DAT_003f91e4 + (ushort)uint8_t_ARRAY_003f82bc[i];
      uint16_t_ARRAY_003f82b4[i] = 0;
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
    knock_detected = 1;
    uint16_t_ARRAY_003f82b4[cyl] = uint16_t_ARRAY_003f82b4[cyl] + 1;
    if ((ushort)(knock_peak[cyl] - (ushort)knock_peak_threshold) < 0xff) {
      knock_peak_over_threshold[cyl] = (uint8_t)(knock_peak[cyl] - (ushort)knock_peak_threshold);
    }
    else {
      knock_peak_over_threshold[cyl] = 255;
    }
    knock_retard1_timer[cyl] = 255;
  }
  else {
    knock_detected = 0;
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
  byte i;
  
  for (i = 0; i < 4; i = i + 1) {
    if (knock_retard1[i] == 0) {
      if ((ushort)CAL_knock_retard2_corr_dec_step < LEA_knock_retard2[i]) {
        LEA_knock_retard2[i] = LEA_knock_retard2[i] - (ushort)CAL_knock_retard2_corr_dec_step;
      }
      else {
        LEA_knock_retard2[i] = 0;
      }
    }
    else {
      uVar1 = (uint)LEA_knock_retard2[i] +
              (uint)knock_retard1[i] * (uint)CAL_knock_retard2_corr_inc_coef;
      if (uVar1 < 0x10000) {
        LEA_knock_retard2[i] = (u16_factor_1_65536)uVar1;
      }
      else {
        LEA_knock_retard2[i] = 65535;
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
    send_spi_pcs2(DAT_003f82a2 & 0x3f | 0x40);
  }
  else {
    send_spi_pcs2(DAT_003f82a2 & 0x3f);
    send_spi_pcs2(DAT_003f82a3 & 0x3f | 0x80);
  }
  uVar1 = REG_MPIOSMDR;
  REG_MPIOSMDR = uVar1 & 0xfbff | 0x400;
  (&DAT_003f827d)[param_1 & 0xff] =
       (&DAT_0007afbc)[knock_sensitivity_threshold[param_1 & 0xff]] & 0xf;
  send_spi_pcs2((&DAT_003f827d)[param_1 & 0xff]);
  uVar1 = REG_MPIOSMDR;
  REG_MPIOSMDR = uVar1 & 0xfbff;
  uVar1 = REG_MPIOSMDR;
  REG_MPIOSMDR = uVar1 & 0xf7ff | 0x800;
  (&DAT_003f8281)[param_1 & 0xff] =
       (byte)(&DAT_0007afbc)[knock_sensitivity_threshold[param_1 & 0xff]] >> 4;
  send_spi_pcs2((&DAT_003f8281)[param_1 & 0xff]);
  (&DAT_003f82c4)[param_1 & 0xff] = knock_sensitivity_threshold[param_1 & 0xff];
  uVar1 = REG_MPIOSMDR;
  REG_MPIOSMDR = uVar1 & 0xf7ff;
  return;
}



// Knock control task (5ms)

void knock_5ms(void)

{
  ushort uVar1;
  byte i;
  
  if (!engine_is_running) {
    uVar1 = REG_MPIOSMDR;
    REG_MPIOSMDR = uVar1 & 0xffdf | 0x20;
    for (i = 0; i < 4; i = i + 1) {
      knock_first_read[i] = 1;
    }
  }
  if (DAT_003f82cd < 10) {
    DAT_003f82cd = DAT_003f82cd + 1;
  }
  else {
    DAT_003f82cd = '\0';
    if (DAT_003f91e8 != '\0') {
      DAT_003f91e8 = DAT_003f91e8 + -1;
    }
    for (i = 0; i < 4; i = i + 1) {
      if ((knock_retard1_timer[i] != 0) && (knock_retard1_timer[i] != 255)) {
        knock_retard1_timer[i] = knock_retard1_timer[i] + 255;
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
  
  obd_mil_dtc_count_update();
  uVar1 = obd_mil_flags;
  if (engine_speed_1 == 0) {
    if ((((DAT_003f9952 == '\0') || (LEA_obd_monitors_completeness == 0)) || (ecu_runtime < 0x97))
       || (0xf9 < ecu_runtime)) {
      uVar1 = obd_mil_flags | 8;
    }
    else if ((obd_task_scheduler & 1) != 0) {
      obd_task_scheduler = obd_task_scheduler & 0xfffe;
      DAT_003f91f6 = DAT_003f91f6 + 1;
      if (4 < DAT_003f91f6) {
        DAT_003f91f6 = 0;
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
        DAT_003f91f6 = DAT_003f91f6 + 1;
        if (0x1c < DAT_003f91f6) {
          uVar1 = obd_mil_flags | 8;
          if (0x1d < DAT_003f91f6) {
            DAT_003f91f6 = 0;
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
    DAT_003f91f6 = DAT_003f91f6 + 1;
    if (4 < DAT_003f91f6) {
      DAT_003f91f6 = 0;
      uVar1 = obd_mil_flags ^ 8;
    }
  }
  obd_mil_flags = uVar1;
  iVar2 = obd_init_state_machine();
  if (iVar2 != 0) {
    if (DAT_003fd9b8 != '\0') {
      DAT_003fd9b8 = '\0';
      obd_clear_freeze();
    }
    if ((int)(uint)DAT_003fc4d0 <
        (int)(short)(ushort)coolant_smooth - (int)(short)(ushort)coolant_stop) {
      if (DAT_003fc4d1 < coolant_smooth) {
        DAT_003f91f0 = 1;
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
                    DAT_003fd9bc = 0;
                  }
                  DAT_003fd9bc = DAT_003fd9bc + wheel_speed_r_max / 0x168;
                  if (0x270fd8f0 < DAT_003fd9bc) {
                    DAT_003fd9bc = 0x3e7fc18;
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
      DAT_003f91f8 = DAT_003f91f8 + 1;
      if (9 < DAT_003f91f8) {
        DAT_003f91f8 = 0;
        DAT_003f91f9 = DAT_003f91f9 + 1;
        if (DAT_003f91f9 < 0x80) {
          if (obd_trouble_list[DAT_003f91f9] == 0) {
            DAT_003f91f9 = 0;
          }
        }
        else {
          DAT_003f91f9 = 0;
        }
        DAT_003fd9b4 = obd_trouble_list[DAT_003f91f9];
        DAT_003f91fa = DAT_003f91fa + 1;
        if (DAT_003f91fa < 0x80) {
          if (obd_pending_list[DAT_003f91fa] == 0) {
            DAT_003f91fa = 0;
          }
        }
        else {
          DAT_003f91fa = 0;
        }
        DAT_003fd9b6 = obd_pending_list[DAT_003f91fa];
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
  if (((int)uVar1 < (int)(uint)DAT_003fc4d6) && (DAT_003f91f0 == DAT_002f8316)) {
    if (DAT_003fd9ac == 0) {
      DAT_003fd998 = 1;
    }
  }
  else {
    DAT_003fd9ac = DAT_003fc4d8;
  }
  return;
}



// Sets OBD DTC with maturation counter

void obd_set_dtc(u8_obd_config *obd_config,uint8_t *obd_flags,uint8_t *engine_start_counter,
                uint8_t *warm_up_cycle_counter,uint obd_code)

{
  ushort uVar1;
  byte bVar3;
  ushort uVar2;
  byte *pbVar4;
  byte *pbVar5;
  undefined8 uVar6;
  
  uVar6 = push_27to31();
  pbVar4 = (byte *)((ulonglong)uVar6 >> 0x20);
  pbVar5 = (byte *)uVar6;
  if ((*pbVar4 & 0x10) != 0) {
    DAT_003f9200 = *pbVar4;
    DAT_003f91fc = obd_code;
    obd_freeze2(DAT_003f9200,obd_code);
  }
  bVar3 = *pbVar4 & 7;
  if (bVar3 == 2) {
    if (((*pbVar5 & 8) == 0) && ((*pbVar4 & 0x40) != 0)) {
      DAT_003f91f2 = DAT_003f91f2 + '\x01';
    }
    *pbVar5 = *pbVar5 | 0xc;
    *engine_start_counter = 0;
    *warm_up_cycle_counter = 0;
    if ((*pbVar5 & 0x10) == 0) {
      if ((*pbVar5 & 0x80) == 0) {
        *pbVar5 = *pbVar5 | 0x80;
        obd_add_pending(obd_code & 0xffff);
      }
    }
    else {
      *pbVar5 = *pbVar5 | 1;
      *pbVar5 = *pbVar5 & 0xef;
      if (DAT_002f830e == 0) {
        DAT_002f830e = (ushort)(obd_code << 3) | *pbVar4 & 7;
        DAT_002f8312 = load_3;
        DAT_002f8314 = maf_flow_1;
        DAT_002f8310 = engine_speed_1;
        DAT_002f8316 = DAT_003f91f0;
        DAT_002f8317 = DAT_002f82c3;
      }
      if ((((*pbVar4 & 0x10) != 0) &&
          (obd_mil_flags = obd_mil_flags | 1, (LEA_obd_freeze_dtc & 7) != 2)) &&
         ((LEA_obd_freeze_dtc & 7) != 4)) {
        LEA_obd_freeze_dtc = (ushort)(obd_code << 3) | *pbVar4 & 7;
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
      if ((*pbVar5 & 0x80) == 0) {
        *pbVar5 = *pbVar5 | 0x80;
        obd_add_trouble(obd_code & 0xffff);
      }
    }
  }
  else if (bVar3 < 2) {
    if (((*pbVar4 & 7) != 0) && (true)) {
      if (((*pbVar5 & 8) == 0) && ((*pbVar4 & 0x40) != 0)) {
        DAT_003f91f2 = DAT_003f91f2 + '\x01';
      }
      *pbVar5 = *pbVar5 | 0xd;
      *engine_start_counter = 0;
      *warm_up_cycle_counter = 0;
      if ((((*pbVar4 & 0x10) != 0) &&
          (uVar1 = obd_mil_flags | 1, uVar2 = obd_mil_flags & 2, obd_mil_flags = uVar1, uVar2 == 0))
         && (LEA_obd_freeze_dtc == 0)) {
        LEA_obd_freeze_dtc = (ushort)(obd_code << 3) | *pbVar4 & 7;
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
      if (((*pbVar5 & 0x80) == 0) && ((*pbVar5 & 4) != 0)) {
        *pbVar5 = *pbVar5 | 0x80;
        obd_add_trouble(obd_code & 0xffff);
      }
    }
  }
  else if (bVar3 == 4) {
    if (((*pbVar5 & 8) == 0) && ((*pbVar4 & 0x40) != 0)) {
      DAT_003f91f2 = DAT_003f91f2 + '\x01';
    }
    *pbVar5 = *pbVar5 | 0xd;
    *engine_start_counter = 0;
    *warm_up_cycle_counter = 0;
    if (DAT_002f830e == 0) {
      DAT_002f830e = (ushort)(obd_code << 3) | *pbVar4 & 7;
      DAT_002f8312 = load_3;
      DAT_002f8314 = maf_flow_1;
      DAT_002f8310 = engine_speed_1;
      DAT_002f8316 = DAT_003f91f0;
      DAT_002f8317 = DAT_002f82c3;
    }
    if ((((*pbVar4 & 0x10) != 0) &&
        (obd_mil_flags = obd_mil_flags | 2, (LEA_obd_freeze_dtc & 7) != 2)) &&
       ((LEA_obd_freeze_dtc & 7) != 4)) {
      LEA_obd_freeze_dtc = (ushort)(obd_code << 3) | *pbVar4 & 7;
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
    if (((*pbVar5 & 0x80) == 0) && ((*pbVar5 & 4) != 0)) {
      *pbVar5 = *pbVar5 | 0x80;
      obd_add_trouble(obd_code & 0xffff);
    }
  }
  else if (bVar3 < 4) {
    if (((*pbVar5 & 8) == 0) && ((*pbVar4 & 0x40) != 0)) {
      DAT_003f91f2 = DAT_003f91f2 + '\x01';
    }
    *pbVar5 = *pbVar5 | 0xc;
    *engine_start_counter = 0;
    *warm_up_cycle_counter = 0;
    if ((*pbVar5 & 0x10) == 0) {
      if ((*pbVar5 & 0x80) == 0) {
        *pbVar5 = *pbVar5 | 0x80;
        obd_add_pending(obd_code & 0xffff);
      }
    }
    else {
      *pbVar5 = *pbVar5 | 1;
      *pbVar5 = *pbVar5 & 0xef;
      if ((((*pbVar4 & 0x10) != 0) &&
          (uVar2 = obd_mil_flags | 1, uVar1 = obd_mil_flags & 2, obd_mil_flags = uVar2, uVar1 == 0))
         && (LEA_obd_freeze_dtc == 0)) {
        LEA_obd_freeze_dtc = (ushort)(obd_code << 3) | *pbVar4 & 7;
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
      if ((*pbVar5 & 0x80) == 0) {
        *pbVar5 = *pbVar5 | 0x80;
        obd_add_trouble(obd_code & 0xffff);
      }
    }
  }
  pop_27to31();
  return;
}



// Clears OBD DTC pending/confirmed status

void obd_clr_dtc(u8_obd_config *obd_config,uint8_t *obd_flags)

{
  byte bVar1;
  
  bVar1 = *obd_config & 7;
  if (bVar1 == 2) {
    if (((*obd_flags & 8) == 0) && ((*obd_config & 0x40) != 0)) {
      DAT_003f91f2 = DAT_003f91f2 + '\x01';
    }
    *obd_flags = *obd_flags | 8;
  }
  else if (bVar1 < 2) {
    if (((*obd_config & 7) != 0) && (true)) {
      if (((*obd_flags & 8) == 0) && ((*obd_config & 0x40) != 0)) {
        DAT_003f91f2 = DAT_003f91f2 + '\x01';
      }
      *obd_flags = *obd_flags | 8;
    }
  }
  else if (bVar1 == 4) {
    if (((*obd_flags & 8) == 0) && ((*obd_config & 0x40) != 0)) {
      DAT_003f91f2 = DAT_003f91f2 + '\x01';
    }
    *obd_flags = *obd_flags | 8;
    if (((*obd_flags & 1) != 0) && ((*obd_config & 0x10) != 0)) {
      obd_mil_flags = obd_mil_flags & 0xfffd | 1;
    }
  }
  else if (bVar1 < 4) {
    if (((*obd_flags & 8) == 0) && ((*obd_config & 0x40) != 0)) {
      DAT_003f91f2 = DAT_003f91f2 + '\x01';
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
  DAT_003f91f1 = engine_has_started;
  if (engine_has_started) {
    DAT_002f82c3 = DAT_002f82c3 + 1;
  }
  if ((uint)((int)(short)(ushort)DAT_002f8317 + (int)(short)(ushort)DAT_003fc4d3) <=
      (uint)(int)(short)(ushort)DAT_002f82c3) {
    DAT_002f830e = 0;
    DAT_002f8312 = 0;
    DAT_002f8314 = 0;
    DAT_002f8310 = 0;
    DAT_002f8316 = 0;
    DAT_002f8317 = 0;
  }
  if (DAT_003fc4d2 <= DAT_003f91f2) {
    DAT_002f8322 = DAT_002f8322 + '\x01';
    DAT_003f91f5 = 1;
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
  
  if (((((DAT_003f91f1 != '\0') && ((*obd_flags & 8) != 0)) && ((*obd_flags & 4) == 0)) &&
      (((int)(uint)DAT_002f830e >> 3 != obd_code ||
       ((DAT_003fd998 != '\0' && ((int)(uint)DAT_002f830e >> 3 == obd_code)))))) &&
     (uVar1 = *engine_start_counter, *engine_start_counter = uVar1 + 1, 2 < (byte)(uVar1 + 1))) {
    *obd_flags = *obd_flags & 0xfe;
  }
  if (((DAT_003f91f0 != '\0') && ((*obd_flags & 8) != 0)) &&
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
    DAT_003fd9bc = 0;
  }
  if (DAT_003f91f5 != '\0') {
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
  
  switch(DAT_003fd9b2) {
  case '\0':
    DAT_003fd9b2 = DAT_003fd9b2 + '\x01';
    uVar1 = 0;
    break;
  case '\x01':
    obd_init_nop();
    DAT_003fd9b2 = DAT_003fd9b2 + '\x01';
    uVar1 = 0;
    break;
  case '\x02':
    obd_init_sensors();
    DAT_003fd9b2 = DAT_003fd9b2 + '\x01';
    uVar1 = 0;
    break;
  case '\x03':
    obd_init_outputs();
    DAT_003fd9b2 = DAT_003fd9b2 + '\x01';
    uVar1 = 0;
    break;
  case '\x04':
    obd_init_catalyst();
    DAT_003fd9b2 = DAT_003fd9b2 + '\x01';
    uVar1 = 0;
    break;
  case '\x05':
    obd_init_fuel_trim();
    DAT_003fd9b2 = DAT_003fd9b2 + '\x01';
    uVar1 = 0;
    break;
  case '\x06':
    obd_init_o2_response();
    DAT_003fd9b2 = DAT_003fd9b2 + '\x01';
    uVar1 = 0;
    break;
  case '\a':
    obd_init_crank_cam_speed();
    DAT_003fd9b2 = DAT_003fd9b2 + '\x01';
    uVar1 = 0;
    break;
  case '\b':
    obd_init_fuel_evap_press();
    DAT_003fd9b2 = DAT_003fd9b2 + '\x01';
    uVar1 = 0;
    break;
  case '\t':
    obd_init_idle_speed();
    DAT_003fd9b2 = DAT_003fd9b2 + '\x01';
    uVar1 = 0;
    break;
  case '\n':
    obd_init_vvt_vvl();
    DAT_003fd9b2 = DAT_003fd9b2 + '\x01';
    uVar1 = 0;
    break;
  case '\v':
    obd_init_misfire();
    DAT_003fd9b2 = DAT_003fd9b2 + '\x01';
    uVar1 = 0;
    break;
  case '\f':
    obd_init_evap_leak();
    DAT_003fd9b2 = DAT_003fd9b2 + '\x01';
    uVar1 = 0;
    break;
  case '\r':
    obd_init_evap_flow();
    DAT_003fd9b2 = DAT_003fd9b2 + '\x01';
    uVar1 = 0;
    break;
  case '\x0e':
    obd_init_ecu_internal();
    DAT_003fd9b2 = DAT_003fd9b2 + '\x01';
    uVar1 = 0;
    break;
  case '\x0f':
    obd_init_thermostat();
    DAT_003fd9b2 = DAT_003fd9b2 + '\x01';
    uVar1 = 0;
    break;
  case '\x10':
    obd_mil_flags = obd_mil_flags | 0x10;
    DAT_003fd9b2 = DAT_003fd9b2 + '\x01';
    uVar1 = 0;
    break;
  case '\x11':
    obd_init_pps();
    DAT_003fd9b2 = DAT_003fd9b2 + '\x01';
    uVar1 = 0;
    break;
  case '\x12':
    obd_init_tps_throttle();
    DAT_003fd9b2 = DAT_003fd9b2 + '\x01';
    uVar1 = 0;
    break;
  case '\x13':
    obd_init_iumpr();
    DAT_003fd9b2 = DAT_003fd9b2 + '\x01';
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
  
  DAT_003f9209 = lookup_2D_uint8_interpolated(8,coolant_stop,&DAT_003fd41e,&DAT_003fd416);
  bVar4 = lookup_2D_uint8_fixed(8,(uint8_t)(maf_flow_1 / 100),&DAT_003fd426);
  cat_diag_pre_o2_max_sw = (uint16_t)bVar4;
  bVar4 = lookup_2D_uint8_fixed(8,(uint8_t)(maf_flow_1 / 100),&DAT_002f82cf);
  cat_diag_pre_o2_sw = (uint16_t)bVar4;
  bVar4 = lookup_2D_uint8_fixed(8,(uint8_t)(maf_flow_1 / 100),&DAT_002f82df);
  DAT_003fd9d0 = (ushort)bVar4;
  if (((((((uint)((int)(uint)maf_accumulated_2 >> 4) < (uint)DAT_003f9209) ||
         (coolant_smooth <= DAT_003fc500)) || (engine_air_smooth <= DAT_003fc501)) ||
       (((int)atmo_pressure <= (int)(uint)DAT_003fc4fe || ((fuel_system_status & 2) == 0)))) ||
      ((car_speed_smooth < DAT_003fc50b ||
       ((DAT_003fc50a <= car_speed_smooth || (maf_flow_1 <= DAT_003fc502)))))) ||
     ((DAT_003fc504 <= maf_flow_1 || ((DAT_003f9210 != 0 || (DAT_003f9212 != 0)))))) {
    DAT_003fd9ce = DAT_003fd9ce & 0xffbc;
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
      uVar1 = DAT_003fd9ce | 0x43;
      for (sVar5 = 0; ((uint)(byte)(&DAT_002f82cf)[sVar5] < maf_flow_1 / 100 && (sVar5 < 7));
          sVar5 = sVar5 + 1) {
      }
      if (DAT_003fc524 < (short)sensor_adc_pre_o2) {
        if (((DAT_003fd9ce & 4) != 0) || ((DAT_003fd9ce & 8) == 0)) {
          DAT_003fd9ce = uVar1;
          (&DAT_002f82d7)[sVar5] = (&DAT_002f82d7)[sVar5] + '\x01';
          uVar1 = DAT_003fd9ce & 0xfffb | 8;
        }
      }
      else if (((short)sensor_adc_pre_o2 < DAT_003fc522) &&
              (((DAT_003fd9ce & 8) != 0 || ((DAT_003fd9ce & 4) == 0)))) {
        DAT_003fd9ce = uVar1;
        (&DAT_002f82d7)[sVar5] = (&DAT_002f82d7)[sVar5] + '\x01';
        uVar1 = DAT_003fd9ce & 0xfff7 | 4;
      }
      DAT_003fd9ce = uVar1;
      iVar2 = DAT_003fd9d4 / 0xa00 + (DAT_003fd9d4 >> 0x1f);
      if ((iVar2 - (iVar2 >> 0x1f)) + (int)DAT_003fc528 < (int)(short)sensor_adc_post_o2) {
        if (((DAT_003fd9ce & 0x10) != 0) || ((DAT_003fd9ce & 0x20) == 0)) {
          (&DAT_002f82e7)[sVar5] = (&DAT_002f82e7)[sVar5] + '\x01';
          DAT_003fd9ce = DAT_003fd9ce & 0xffef | 0x20;
        }
      }
      else {
        iVar2 = DAT_003fd9d4 / 0xa00 + (DAT_003fd9d4 >> 0x1f);
        if (((int)(short)sensor_adc_post_o2 < (iVar2 - (iVar2 >> 0x1f)) - (int)DAT_003fc526) &&
           (((DAT_003fd9ce & 0x20) != 0 || ((DAT_003fd9ce & 0x10) == 0)))) {
          (&DAT_002f82e7)[sVar5] = (&DAT_002f82e7)[sVar5] + '\x01';
          DAT_003fd9ce = DAT_003fd9ce & 0xffdf | 0x10;
        }
      }
      iVar2 = DAT_003fd9d4 / 0xa00 + (DAT_003fd9d4 >> 0x1f);
      if (iVar2 - (iVar2 >> 0x1f) < (int)(short)sensor_adc_post_o2) {
        DAT_003fd9ce = DAT_003fd9ce & 0xffef;
      }
      else {
        DAT_003fd9ce = DAT_003fd9ce & 0xffdf;
      }
    }
    else {
      DAT_003fd9ce = DAT_003fd9ce & 0xffbf | 3;
      for (sVar5 = 0; ((uint)(byte)(&DAT_002f82cf)[sVar5] < maf_flow_1 / 100 && (sVar5 < 7));
          sVar5 = sVar5 + 1) {
      }
      DAT_002f82ff = DAT_002f82ff | (byte)(1 << ((int)sVar5 & 0x3fU));
    }
  }
  else {
    DAT_003fd9ce = DAT_003fd9ce & 0xffbd | 1;
  }
  if (DAT_002f82ff == 0xff) {
    for (iVar2 = 8; iVar2 < 0x10; iVar2 = iVar2 + 1) {
      DAT_003f920a = DAT_003f920a + (byte)(&DAT_002f82cf)[iVar2];
      DAT_003f920c = DAT_003f920c + (byte)(&DAT_002f82df)[iVar2];
    }
    uVar3 = ((uint)DAT_003f920c * 1000) / (uint)DAT_003f920a;
    DAT_002f8352 = (ushort)uVar3;
    if ((uint)DAT_002f8272 < (uVar3 & 0xffff)) {
      DAT_002f8272 = DAT_002f8352;
      sort10(&DAT_002f8272);
    }
    if (DAT_002f8352 < DAT_003fc52a) {
      obd_clr_dtc(&CAL_obd_P0420,&LEA_obd_P0420_flags);
      if (DAT_003f9208 < DAT_003fca0f) {
        DAT_003f9208 = DAT_003f9208 + 1;
      }
      DAT_002f82ff = 0;
    }
    else if (DAT_003f9208 == 0) {
      obd_set_dtc(&CAL_obd_P0420,&LEA_obd_P0420_flags,&LEA_obd_P0420_engine_start_count,
                  &LEA_obd_P0420_warm_up_cycle_count,0x1a4);
      DAT_002f82ff = 0;
    }
    else {
      DAT_003f9208 = DAT_003f9208 - 1;
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
  
  iVar1 = (0xa00 - (uint)DAT_003fc506) * DAT_003fd9d4;
  iVar1 = iVar1 / 0xa00 + (iVar1 >> 0x1f);
  DAT_003fd9d4 = (iVar1 - (iVar1 >> 0x1f)) + (uint)DAT_003fc506 * (uint)sensor_adc_post_o2;
  if (DAT_003f9210 < DAT_003fd5be) {
    DAT_003f9210 = DAT_003fd5be;
    iVar1 = DAT_003fd9d4 / 0xa00 + (DAT_003fd9d4 >> 0x1f);
    if ((int)(short)sensor_adc_post_o2 < iVar1 - (iVar1 >> 0x1f)) {
      DAT_003fd9ce = DAT_003fd9ce & 0xffdf | 0x10;
    }
  }
  else if ((DAT_003f9210 == 0) || (DAT_003f920e != '\0')) {
    if (DAT_003f920e != '\0') {
      DAT_003f920e = DAT_003f920e + -1;
    }
  }
  else {
    DAT_003f9210 = DAT_003f9210 + -1;
    DAT_003f920e = DAT_003fc507;
  }
  if (((short)(ushort)DAT_003f99aa < dt_tps_target_2) ||
     ((int)dt_tps_target_2 < -(int)(short)(ushort)DAT_003f99aa)) {
    DAT_003f9212 = DAT_003f99ac;
  }
  else if ((DAT_003f9212 != 0) && (DAT_003f9212 = DAT_003f9212 + -1, DAT_003f9212 == 0)) {
    DAT_003fd9d4 = (uint)sensor_adc_post_o2 * 0xa00;
  }
  return;
}



// Initializes catalyst monitor state

void obd_init_catalyst(void)

{
  DAT_003f9208 = DAT_003fca0f;
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
  if ((((vvt_runtime_min < engine_runtime) && (DAT_003f9704 != -0x80)) && (DAT_003fdd14 != '\0')) &&
     ((DAT_003fdd40 != '\0' && (DAT_003fdd41 != '\0')))) {
    if ((((CAL_obd_P0011 & 7) != 0) && (DAT_003fc554 < coolant_smooth)) &&
       (DAT_003fc556 < engine_runtime)) {
      if ((int)vvt_diff < -(int)DAT_003fc52c) {
        if (DAT_003f921a < DAT_003fc555) {
          DAT_003f921a = DAT_003f921a + 1;
        }
        else {
          DAT_003f921a = 0;
          if (DAT_003fd9d8 == 0) {
            obd_set_dtc(&CAL_obd_P0011,&LEA_obd_P0011_flags,&LEA_obd_P0011_engine_start_count,
                        &LEA_obd_P0011_warm_up_cycle_count,0xb);
          }
          else {
            DAT_003fd9d8 = DAT_003fd9d8 - 1;
          }
        }
      }
      else {
        obd_clr_dtc(&CAL_obd_P0011,&LEA_obd_P0011_flags);
        if (DAT_003fd9d8 < DAT_003fca18) {
          DAT_003fd9d8 = DAT_003fd9d8 + 1;
        }
        DAT_003f921a = 0;
      }
    }
    if ((((CAL_obd_P0012 & 7) != 0) && (DAT_003fc554 < coolant_smooth)) &&
       (DAT_003fc556 < engine_runtime)) {
      if (DAT_003fc52c < vvt_diff) {
        if (DAT_003f921b < DAT_003fc555) {
          DAT_003f921b = DAT_003f921b + 1;
        }
        else {
          DAT_003f921b = 0;
          if (DAT_003fd9dd == 0) {
            obd_set_dtc(&CAL_obd_P0012,&LEA_obd_P0012_flags,&LEA_obd_P0012_engine_start_count,
                        &LEA_obd_P0012_warm_up_cycle_count,0xc);
          }
          else {
            DAT_003fd9dd = DAT_003fd9dd - 1;
          }
        }
      }
      else {
        obd_clr_dtc(&CAL_obd_P0012,&LEA_obd_P0012_flags);
        if (DAT_003fd9dd < DAT_003fca19) {
          DAT_003fd9dd = DAT_003fd9dd + 1;
        }
        DAT_003f921b = 0;
      }
    }
    if (((CAL_obd_P0016 & 7) != 0) && (vvt_rest_pos_measured == true)) {
      if (vvt_rest_pos_fault == true) {
        if (DAT_003fd9de == 0) {
          obd_set_dtc(&CAL_obd_P0016,&LEA_obd_P0016_flags,&LEA_obd_P0016_engine_start_count,
                      &LEA_obd_P0016_warm_up_cycle_count,0x10);
        }
        else {
          DAT_003fd9de = DAT_003fd9de - 1;
        }
      }
      else {
        obd_clr_dtc(&CAL_obd_P0016,&LEA_obd_P0016_flags);
        if (DAT_003fd9de < DAT_003fca45) {
          DAT_003fd9de = DAT_003fd9de + 1;
        }
      }
    }
  }
  else {
    DAT_003f921b = 0;
    DAT_003f921a = 0;
  }
  if (((DAT_003fd9d8 == 0) || (DAT_003fd9dd == 0)) ||
     ((DAT_003fd9de == 0 ||
      (((DAT_003fd9e4 == '\0' || (DAT_003fd9f1 == '\0')) || (DAT_003fdc3b == '\0')))))) {
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
    DAT_003f9219 = DAT_003fc4ea;
  }
  else if (!vvl_is_high_cam) {
    DAT_003f9218 = DAT_003fc4ea;
    if (DAT_003f9219 == '\0') {
      if (sensor_adc_oil_vvtl < 0x201) {
        obd_clr_dtc(&CAL_obd_P2647,&LEA_obd_P2647_flags);
        if (DAT_003fd9e0 < DAT_003fca1d) {
          DAT_003fd9e0 = DAT_003fd9e0 + 1;
        }
      }
      else if (DAT_003fd9e0 == 0) {
        obd_set_dtc(&CAL_obd_P2647,&LEA_obd_P2647_flags,&LEA_obd_P2647_engine_start_count,
                    &LEA_obd_P2647_warm_up_cycle_count,0xa57);
      }
      else {
        DAT_003fd9e0 = DAT_003fd9e0 - 1;
      }
    }
    else {
      DAT_003f9219 = DAT_003f9219 + -1;
    }
  }
  if ((((CAL_obd_P2646 & 7) == 0) || (engine_is_running == false)) || ((shutdown_flags & 1) == 0)) {
    DAT_003f9218 = DAT_003fc4ea;
  }
  else if (vvl_is_high_cam == true) {
    DAT_003f9219 = DAT_003fc4ea;
    if (DAT_003f9218 == '\0') {
      if (sensor_adc_oil_vvtl < 0x200) {
        if (DAT_003fd9df == 0) {
          obd_set_dtc(&CAL_obd_P2646,&LEA_obd_P2646_flags,&LEA_obd_P2646_engine_start_count,
                      &LEA_obd_P2646_warm_up_cycle_count,0xa56);
        }
        else {
          DAT_003fd9df = DAT_003fd9df - 1;
        }
      }
      else {
        obd_clr_dtc(&CAL_obd_P2646,&LEA_obd_P2646_flags);
        if (DAT_003fd9df < DAT_003fca1c) {
          DAT_003fd9df = DAT_003fd9df + 1;
        }
      }
    }
    else {
      DAT_003f9218 = DAT_003f9218 + -1;
    }
  }
  return;
}



// Initializes VVT/VVL monitor state

void obd_init_vvt_vvl(void)

{
  DAT_003fd9d8 = DAT_003fca18;
  DAT_003fd9dd = DAT_003fca19;
  DAT_003fd9de = DAT_003fca45;
  DAT_003fd9df = DAT_003fca1c;
  DAT_003fd9e0 = DAT_003fca1d;
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
    if ((DAT_003fdc20 & 0x20) == 0) {
      DAT_003f9220 = 0;
      obd_clr_dtc(&CAL_obd_P0076,&LEA_obd_P0076_flags);
      if (DAT_003fd9e4 < DAT_003fc9e9) {
        DAT_003fd9e4 = DAT_003fd9e4 + 1;
      }
    }
    else {
      DAT_003fdc20 = DAT_003fdc20 & 0xffdf;
      DAT_003f9220 = DAT_003f9220 + 1;
      if (DAT_003fdd44 <= DAT_003f9220) {
        DAT_003f9220 = 0;
        if (DAT_003fd9e4 != 0) {
          DAT_003fd9e4 = DAT_003fd9e4 - 1;
        }
        if (DAT_003fd9e4 == 0) {
          obd_set_dtc(&CAL_obd_P0076,&LEA_obd_P0076_flags,&LEA_obd_P0076_engine_start_count,
                      &LEA_obd_P0076_warm_up_cycle_count,0x4c);
        }
      }
    }
  }
  if ((((CAL_obd_P0077 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if ((DAT_003fdc20 & 0x10) == 0) {
      DAT_003f9222 = 0;
      obd_clr_dtc(&CAL_obd_P0077,&LEA_obd_P0077_flags);
      if (DAT_003fd9f1 < DAT_003fc9ea) {
        DAT_003fd9f1 = DAT_003fd9f1 + 1;
      }
    }
    else {
      DAT_003fdc20 = DAT_003fdc20 & 0xffef;
      DAT_003f9222 = DAT_003f9222 + 1;
      if (DAT_003fdd44 <= DAT_003f9222) {
        DAT_003f9222 = 0;
        if (DAT_003fd9f1 != 0) {
          DAT_003fd9f1 = DAT_003fd9f1 - 1;
        }
        if (DAT_003fd9f1 == 0) {
          obd_set_dtc(&CAL_obd_P0077,&LEA_obd_P0077_flags,&LEA_obd_P0077_engine_start_count,
                      &LEA_obd_P0077_warm_up_cycle_count,0x4d);
        }
      }
    }
  }
  if ((((CAL_obd_P0646 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if ((DAT_003fdc10 & 0x200) == 0) {
      DAT_003f922a = 0;
      obd_clr_dtc(&CAL_obd_P0646,&LEA_obd_P0646_flags);
      if (DAT_003f9228 < DAT_003fc9f5) {
        DAT_003f9228 = DAT_003f9228 + 1;
      }
    }
    else {
      DAT_003f922a = DAT_003f922a + 1;
      if (DAT_003fdd44 <= DAT_003f922a) {
        DAT_003f922a = 0;
        if (DAT_003f9228 == 0) {
          obd_set_dtc(&CAL_obd_P0646,&LEA_obd_P0646_flags,&LEA_obd_P0646_engine_start_count,
                      &LEA_obd_P0646_warm_up_cycle_count,0x286);
        }
        else {
          DAT_003f9228 = DAT_003f9228 - 1;
        }
      }
    }
  }
  if ((((CAL_obd_P0647 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if ((DAT_003fdc10 & 0x100) == 0) {
      DAT_003f9226 = 0;
      obd_clr_dtc(&CAL_obd_P0647,&LEA_obd_P0647_flags);
      if (DAT_003f9224 < DAT_003fc9f6) {
        DAT_003f9224 = DAT_003f9224 + 1;
      }
    }
    else {
      DAT_003f9226 = DAT_003f9226 + 1;
      if (DAT_003fdd44 <= DAT_003f9226) {
        DAT_003f9226 = 0;
        if (DAT_003f9224 == 0) {
          obd_set_dtc(&CAL_obd_P0647,&LEA_obd_P0647_flags,&LEA_obd_P0647_engine_start_count,
                      &LEA_obd_P0647_warm_up_cycle_count,0x287);
        }
        else {
          DAT_003f9224 = DAT_003f9224 - 1;
        }
      }
    }
  }
  if ((((CAL_obd_P0444 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if ((DAT_003fdc22 & 0x80) == 0) {
      DAT_003f922e = 0;
      obd_clr_dtc(&CAL_obd_P0444,&LEA_obd_P0444_flags);
      if (DAT_003f922c < DAT_003fc9f7) {
        DAT_003f922c = DAT_003f922c + 1;
      }
    }
    else {
      DAT_003fdc22 = DAT_003fdc22 & 0xff7f;
      DAT_003f922e = DAT_003f922e + 1;
      if (DAT_003fdd44 <= DAT_003f922e) {
        DAT_003f922e = 0;
        if (DAT_003f922c == 0) {
          obd_set_dtc(&CAL_obd_P0444,&LEA_obd_P0444_flags,&LEA_obd_P0444_engine_start_count,
                      &LEA_obd_P0444_warm_up_cycle_count,0x1bc);
        }
        else {
          DAT_003f922c = DAT_003f922c - 1;
        }
      }
    }
  }
  if ((((CAL_obd_P0445 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if ((DAT_003fdc22 & 0x40) == 0) {
      DAT_003f9232 = 0;
      obd_clr_dtc(&CAL_obd_P0445,&LEA_obd_P0445_flags);
      if (DAT_003f9230 < DAT_003fc9f8) {
        DAT_003f9230 = DAT_003f9230 + 1;
      }
    }
    else {
      DAT_003fdc22 = DAT_003fdc22 & 0xffbf;
      DAT_003f9232 = DAT_003f9232 + 1;
      if (DAT_003fdd44 <= DAT_003f9232) {
        DAT_003f9232 = 0;
        if (DAT_003f9230 == 0) {
          obd_set_dtc(&CAL_obd_P0445,&LEA_obd_P0445_flags,&LEA_obd_P0445_engine_start_count,
                      &LEA_obd_P0445_warm_up_cycle_count,0x1bd);
        }
        else {
          DAT_003f9230 = DAT_003f9230 - 1;
        }
      }
    }
  }
  if ((((CAL_obd_P0447 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if ((DAT_003fdc22 & 0x20) == 0) {
      DAT_003f9258 = 0;
      obd_clr_dtc(&CAL_obd_P0447,&LEA_obd_P0447_flags);
      if (DAT_003f9256 < DAT_003fc9f9) {
        DAT_003f9256 = DAT_003f9256 + 1;
      }
    }
    else {
      DAT_003f9258 = DAT_003f9258 + 1;
      if (DAT_003fdd44 <= DAT_003f9258) {
        DAT_003f9258 = 0;
        if (DAT_003f9256 == 0) {
          obd_set_dtc(&CAL_obd_P0447,&LEA_obd_P0447_flags,&LEA_obd_P0447_engine_start_count,
                      &LEA_obd_P0447_warm_up_cycle_count,0x1bf);
        }
        else {
          DAT_003f9256 = DAT_003f9256 - 1;
        }
      }
    }
  }
  if ((((CAL_obd_P0448 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if ((DAT_003fdc22 & 0x10) == 0) {
      DAT_003f925c = 0;
      obd_clr_dtc(&CAL_obd_P0448,&LEA_obd_P0448_flags);
      if (DAT_003f925a < DAT_003fc9fa) {
        DAT_003f925a = DAT_003f925a + 1;
      }
    }
    else {
      DAT_003f925c = DAT_003f925c + 1;
      if (DAT_003fdd44 <= DAT_003f925c) {
        DAT_003f925c = 0;
        if (DAT_003f925a == 0) {
          obd_set_dtc(&CAL_obd_P0448,&LEA_obd_P0448_flags,&LEA_obd_P0448_engine_start_count,
                      &LEA_obd_P0448_warm_up_cycle_count,0x1c0);
        }
        else {
          DAT_003f925a = DAT_003f925a - 1;
        }
      }
    }
  }
  if ((((CAL_obd_P0201 & 7) != 0) && (engine_is_running != false)) &&
     (((shutdown_flags & 1) != 0 && ((hc08_obd_flags & 0x20) == 0)))) {
    if ((DAT_003fdc1c & 3) == 0) {
      obd_clr_dtc(&CAL_obd_P0201,&LEA_obd_P0201_flags);
      if (DAT_003fd9f2 < DAT_003fc9fd) {
        DAT_003fd9f2 = DAT_003fd9f2 + 1;
      }
    }
    else if (((DAT_003fdc1c & 2) == 0) && (((DAT_003fdc1c & 2) == 0 || ((DAT_003fdc1c & 1) == 0))))
    {
      if (((DAT_003fdc1c & 2) == 0) && ((DAT_003fdc1c & 1) != 0)) {
        DAT_003fdc1c = DAT_003fdc1c & 0xfffe;
        if (DAT_003fd9f2 == 0) {
          obd_set_dtc(&CAL_obd_P0201,&LEA_obd_P0201_flags,&LEA_obd_P0201_engine_start_count,
                      &LEA_obd_P0201_warm_up_cycle_count,0xc9);
        }
        else {
          DAT_003fd9f2 = DAT_003fd9f2 - 1;
        }
      }
    }
    else {
      DAT_003fdc1c = DAT_003fdc1c & 0xfffc;
      DAT_003f9234 = DAT_003f9234 + 1;
      if (DAT_003fdd44 <= DAT_003f9234) {
        DAT_003f9234 = 0;
        if (DAT_003fd9f2 == 0) {
          obd_set_dtc(&CAL_obd_P0201,&LEA_obd_P0201_flags,&LEA_obd_P0201_engine_start_count,
                      &LEA_obd_P0201_warm_up_cycle_count,0xc9);
        }
        else {
          DAT_003fd9f2 = DAT_003fd9f2 - 1;
        }
      }
    }
  }
  if (((((CAL_obd_P0202 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0))
     && ((hc08_obd_flags & 0x20) == 0)) {
    if ((DAT_003fdc1c & 0x30) == 0) {
      DAT_003f9236 = 0;
      obd_clr_dtc(&CAL_obd_P0202,&LEA_obd_P0202_flags);
      if (DAT_003fd9f3 < DAT_003fc9fe) {
        DAT_003fd9f3 = DAT_003fd9f3 + 1;
      }
    }
    else if (((DAT_003fdc1c & 0x20) == 0) &&
            (((DAT_003fdc1c & 0x20) == 0 || ((DAT_003fdc1c & 0x10) == 0)))) {
      if (((DAT_003fdc1c & 0x20) == 0) && ((DAT_003fdc1c & 0x10) != 0)) {
        DAT_003fdc1c = DAT_003fdc1c & 0xffef;
        if (DAT_003fd9f3 == 0) {
          obd_set_dtc(&CAL_obd_P0202,&LEA_obd_P0202_flags,&LEA_obd_P0202_engine_start_count,
                      &LEA_obd_P0202_warm_up_cycle_count,0xca);
        }
        else {
          DAT_003fd9f3 = DAT_003fd9f3 - 1;
        }
      }
    }
    else {
      DAT_003fdc1c = DAT_003fdc1c & 0xffcf;
      DAT_003f9236 = DAT_003f9236 + 1;
      if (DAT_003fdd44 <= DAT_003f9236) {
        DAT_003f9236 = 0;
        if (DAT_003fd9f3 == 0) {
          obd_set_dtc(&CAL_obd_P0202,&LEA_obd_P0202_flags,&LEA_obd_P0202_engine_start_count,
                      &LEA_obd_P0202_warm_up_cycle_count,0xca);
        }
        else {
          DAT_003fd9f3 = DAT_003fd9f3 - 1;
        }
      }
    }
  }
  if ((((CAL_obd_P0203 & 7) != 0) && (engine_is_running != false)) &&
     (((shutdown_flags & 1) != 0 && ((hc08_obd_flags & 0x20) == 0)))) {
    if ((DAT_003fdc1c & 0xc0) == 0) {
      DAT_003f9238 = 0;
      obd_clr_dtc(&CAL_obd_P0203,&LEA_obd_P0203_flags);
      if (DAT_003fd9f4 < DAT_003fc9ff) {
        DAT_003fd9f4 = DAT_003fd9f4 + 1;
      }
    }
    else if (((DAT_003fdc1c & 0x80) == 0) &&
            (((DAT_003fdc1c & 0x80) == 0 || ((DAT_003fdc1c & 0x40) == 0)))) {
      if (((DAT_003fdc1c & 0x80) == 0) && ((DAT_003fdc1c & 0x40) != 0)) {
        DAT_003fdc1c = DAT_003fdc1c & 0xffbf;
        if (DAT_003fd9f4 == 0) {
          obd_set_dtc(&CAL_obd_P0203,&LEA_obd_P0203_flags,&LEA_obd_P0203_engine_start_count,
                      &LEA_obd_P0203_warm_up_cycle_count,0xcb);
        }
        else {
          DAT_003fd9f4 = DAT_003fd9f4 - 1;
        }
      }
    }
    else {
      DAT_003fdc1c = DAT_003fdc1c & 0xff3f;
      DAT_003f9238 = DAT_003f9238 + 1;
      if (DAT_003fdd44 <= DAT_003f9238) {
        DAT_003f9238 = 0;
        if (DAT_003fd9f4 == 0) {
          obd_set_dtc(&CAL_obd_P0203,&LEA_obd_P0203_flags,&LEA_obd_P0203_engine_start_count,
                      &LEA_obd_P0203_warm_up_cycle_count,0xcb);
        }
        else {
          DAT_003fd9f4 = DAT_003fd9f4 - 1;
        }
      }
    }
  }
  if (((((CAL_obd_P0204 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0))
     && ((hc08_obd_flags & 0x20) == 0)) {
    if ((DAT_003fdc1c & 0xc) == 0) {
      DAT_003f923a = 0;
      obd_clr_dtc(&CAL_obd_P0204,&LEA_obd_P0204_flags);
      if (DAT_003fd9f5 < DAT_003fca00) {
        DAT_003fd9f5 = DAT_003fd9f5 + 1;
      }
    }
    else if (((DAT_003fdc1c & 8) == 0) && (((DAT_003fdc1c & 8) == 0 || ((DAT_003fdc1c & 4) == 0))))
    {
      if (((DAT_003fdc1c & 8) == 0) && ((DAT_003fdc1c & 4) != 0)) {
        DAT_003fdc1c = DAT_003fdc1c & 0xfffb;
        if (DAT_003fd9f5 == 0) {
          obd_set_dtc(&CAL_obd_P0204,&LEA_obd_P0204_flags,&LEA_obd_P0204_engine_start_count,
                      &LEA_obd_P0204_warm_up_cycle_count,0xcc);
        }
        else {
          DAT_003fd9f5 = DAT_003fd9f5 - 1;
        }
      }
    }
    else {
      DAT_003fdc1c = DAT_003fdc1c & 0xfff3;
      DAT_003f923a = DAT_003f923a + 1;
      if (DAT_003fdd44 <= DAT_003f923a) {
        DAT_003f923a = 0;
        if (DAT_003fd9f5 == 0) {
          obd_set_dtc(&CAL_obd_P0204,&LEA_obd_P0204_flags,&LEA_obd_P0204_engine_start_count,
                      &LEA_obd_P0204_warm_up_cycle_count,0xcc);
        }
        else {
          DAT_003fd9f5 = DAT_003fd9f5 - 1;
        }
      }
    }
  }
  if ((((CAL_obd_P0205 & 7) != 0) && (engine_is_running != false)) &&
     (((shutdown_flags & 1) != 0 && ((hc08_obd_flags & 0x20) == 0)))) {
    if ((DAT_003fdc1c & 3) == 0) {
      DAT_003f923c = 0;
      obd_clr_dtc(&CAL_obd_P0205,&LEA_obd_P0205_flags);
      if (DAT_003fd9f6 < DAT_003fca01) {
        DAT_003fd9f6 = DAT_003fd9f6 + 1;
      }
    }
    else if (((DAT_003fdc1c & 2) == 0) && (((DAT_003fdc1c & 2) == 0 || ((DAT_003fdc1c & 1) == 0))))
    {
      if (((DAT_003fdc1c & 2) == 0) && ((DAT_003fdc1c & 1) != 0)) {
        DAT_003fdc1c = DAT_003fdc1c & 0xfffe;
        if (DAT_003fd9f6 == 0) {
          obd_set_dtc(&CAL_obd_P0205,&LEA_obd_P0205_flags,&LEA_obd_P0205_engine_start_count,
                      &LEA_obd_P0205_warm_up_cycle_count,0xcd);
        }
        else {
          DAT_003fd9f6 = DAT_003fd9f6 - 1;
        }
      }
    }
    else {
      DAT_003fdc1c = DAT_003fdc1c & 0xfffc;
      DAT_003f923c = DAT_003f923c + 1;
      if (DAT_003fdd44 <= DAT_003f923c) {
        DAT_003f923c = 0;
        if (DAT_003fd9f6 == 0) {
          obd_set_dtc(&CAL_obd_P0205,&LEA_obd_P0205_flags,&LEA_obd_P0205_engine_start_count,
                      &LEA_obd_P0205_warm_up_cycle_count,0xcd);
        }
        else {
          DAT_003fd9f6 = DAT_003fd9f6 - 1;
        }
      }
    }
  }
  if ((((CAL_obd_P0351 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if (diag_channel[0x1b].state < 2) {
      DAT_003f923e = 0;
      obd_clr_dtc(&CAL_obd_P0351,&LEA_obd_P0351_flags);
      if (DAT_003fd9f7 < DAT_003fc9ed) {
        DAT_003fd9f7 = DAT_003fd9f7 + 1;
      }
    }
    else {
      DAT_003f923e = DAT_003f923e + 1;
      if (DAT_003fdd44 <= DAT_003f923e) {
        DAT_003f923e = 0;
        if (DAT_003fd9f7 == 0) {
          obd_set_dtc(&CAL_obd_P0351,&LEA_obd_P0351_flags,&LEA_obd_P0351_engine_start_count,
                      &LEA_obd_P0351_warm_up_cycle_count,0x15f);
        }
        else {
          DAT_003fd9f7 = DAT_003fd9f7 - 1;
        }
      }
    }
  }
  if ((((CAL_obd_P0352 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if (diag_channel[0x1c].state < 2) {
      DAT_003f9240 = 0;
      obd_clr_dtc(&CAL_obd_P0352,&LEA_obd_P0352_flags);
      if (DAT_003fd9f8 < DAT_003fc9ee) {
        DAT_003fd9f8 = DAT_003fd9f8 + 1;
      }
    }
    else {
      DAT_003f9240 = DAT_003f9240 + 1;
      if (DAT_003fdd44 <= DAT_003f9240) {
        DAT_003f9240 = 0;
        if (DAT_003fd9f8 == 0) {
          obd_set_dtc(&CAL_obd_P0352,&LEA_obd_P0352_flags,&LEA_obd_P0352_engine_start_count,
                      &LEA_obd_P0352_warm_up_cycle_count,0x160);
        }
        else {
          DAT_003fd9f8 = DAT_003fd9f8 - 1;
        }
      }
    }
  }
  if ((((CAL_obd_P0353 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if (diag_channel[0x1d].state < 2) {
      DAT_003f9242 = 0;
      obd_clr_dtc(&CAL_obd_P0353,&LEA_obd_P0353_flags);
      if (DAT_003fd9f9 < DAT_003fc9ef) {
        DAT_003fd9f9 = DAT_003fd9f9 + 1;
      }
    }
    else {
      DAT_003f9242 = DAT_003f9242 + 1;
      if (DAT_003fdd44 <= DAT_003f9242) {
        DAT_003f9242 = 0;
        if (DAT_003fd9f9 == 0) {
          obd_set_dtc(&CAL_obd_P0353,&LEA_obd_P0353_flags,&LEA_obd_P0353_engine_start_count,
                      &LEA_obd_P0353_warm_up_cycle_count,0x161);
        }
        else {
          DAT_003fd9f9 = DAT_003fd9f9 - 1;
        }
      }
    }
  }
  if ((((CAL_obd_P0354 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if (diag_channel[0x1e].state < 2) {
      DAT_003f9244 = 0;
      obd_clr_dtc(&CAL_obd_P0354,&LEA_obd_P0354_flags);
      if (DAT_003fd9fa < DAT_003fc9f0) {
        DAT_003fd9fa = DAT_003fd9fa + 1;
      }
    }
    else {
      DAT_003f9244 = DAT_003f9244 + 1;
      if (DAT_003fdd44 <= DAT_003f9244) {
        DAT_003f9244 = 0;
        if (DAT_003fd9fa == 0) {
          obd_set_dtc(&CAL_obd_P0354,&LEA_obd_P0354_flags,&LEA_obd_P0354_engine_start_count,
                      &LEA_obd_P0354_warm_up_cycle_count,0x162);
        }
        else {
          DAT_003fd9fa = DAT_003fd9fa - 1;
        }
      }
    }
  }
  if (((CAL_obd_P0627 & 7) != 0) && ((shutdown_flags & 1) != 0)) {
    if ((DAT_003fdc10 & 0x3000) == 0) {
      DAT_003f9248 = 0;
      obd_clr_dtc(&CAL_obd_P0627,&LEA_obd_P0627_flags);
      if (DAT_003f9246 < DAT_003fca07) {
        DAT_003f9246 = DAT_003f9246 + 1;
      }
    }
    else {
      DAT_003f9248 = DAT_003f9248 + 1;
      if ((DAT_003fdd44 <= DAT_003f9248) && ((shutdown_flags & 0x20) == 0)) {
        DAT_003f9248 = 0;
        if (DAT_003f9246 == 0) {
          obd_set_dtc(&CAL_obd_P0627,&LEA_obd_P0627_flags,&LEA_obd_P0627_engine_start_count,
                      &LEA_obd_P0627_warm_up_cycle_count,0x273);
        }
        else {
          DAT_003f9246 = DAT_003f9246 - 1;
        }
      }
    }
  }
  if (((((CAL_obd_P0480 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0))
     && (car_speed_smooth < CAL_fan_car_speed_disable)) {
    if ((DAT_003fdc10 & 0xc) == 0) {
      DAT_003f924c = 0;
      obd_clr_dtc(&CAL_obd_P0480,&LEA_obd_P0480_flags);
      if (DAT_003f924a < DAT_003fca09) {
        DAT_003f924a = DAT_003f924a + 1;
      }
    }
    else {
      DAT_003f924c = DAT_003f924c + 1;
      if (DAT_003fdd44 <= DAT_003f924c) {
        DAT_003f924c = 0;
        if (DAT_003f924a == 0) {
          obd_set_dtc(&CAL_obd_P0480,&LEA_obd_P0480_flags,&LEA_obd_P0480_engine_start_count,
                      &LEA_obd_P0480_warm_up_cycle_count,0x1e0);
        }
        else {
          DAT_003f924a = DAT_003f924a - 1;
        }
      }
    }
  }
  if ((((CAL_obd_P0481 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if ((DAT_003fdc10 & 0xc00) == 0) {
      DAT_003f9250 = 0;
      obd_clr_dtc(&CAL_obd_P0481,&LEA_obd_P0481_flags);
      if (DAT_003f924e < DAT_003fca0a) {
        DAT_003f924e = DAT_003f924e + 1;
      }
    }
    else {
      DAT_003f9250 = DAT_003f9250 + 1;
      if (DAT_003fdd44 <= DAT_003f9250) {
        DAT_003f9250 = 0;
        if (DAT_003f924e == 0) {
          obd_set_dtc(&CAL_obd_P0481,&LEA_obd_P0481_flags,&LEA_obd_P0481_engine_start_count,
                      &LEA_obd_P0481_warm_up_cycle_count,0x1e1);
        }
        else {
          DAT_003f924e = DAT_003f924e - 1;
        }
      }
    }
  }
  if ((((CAL_obd_P0135 & 7) != 0) && (&UNK_00002ee0 < engine_runtime)) &&
     ((shutdown_flags & 1) != 0)) {
    if (diag_channel[0x19].state < 2) {
      if (pre_o2_heater_current < CAL_obd_P0135_P0141_threshold) {
        DAT_003f9252 = DAT_003f9252 + 1;
        if (DAT_003fdd44 <= DAT_003f9252) {
          DAT_003fdc24 = DAT_003fdc24 & 0xffcf;
          DAT_003f9252 = 0;
          if (DAT_003fd9fb == 0) {
            obd_set_dtc(&CAL_obd_P0135,&LEA_obd_P0135_flags,&LEA_obd_P0135_engine_start_count,
                        &LEA_obd_P0135_warm_up_cycle_count,0x87);
          }
          else {
            DAT_003fd9fb = DAT_003fd9fb - 1;
          }
        }
      }
      else {
        DAT_003f9252 = 0;
        obd_clr_dtc(&CAL_obd_P0135,&LEA_obd_P0135_flags);
        if (DAT_003fd9fb < CAL_obd_P0135_confirm_threshold) {
          DAT_003fd9fb = DAT_003fd9fb + 1;
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
        DAT_003fdc24 = DAT_003fdc24 & 0xfffc;
        DAT_003f9254 = DAT_003f9254 + 1;
        if (DAT_003fdd44 <= DAT_003f9254) {
          DAT_003f9254 = 0;
          if (DAT_003fd9fc == 0) {
            obd_set_dtc(&CAL_obd_P0141,&LEA_obd_P0141_flags,&LEA_obd_P0141_engine_start_count,
                        &LEA_obd_P0141_warm_up_cycle_count,0x8d);
          }
          else {
            DAT_003fd9fc = DAT_003fd9fc - 1;
          }
        }
      }
      else {
        DAT_003f9254 = 0;
        obd_clr_dtc(&CAL_obd_P0141,&LEA_obd_P0141_flags);
        if (DAT_003fd9fc < CAL_obd_P0141_confirm_threshold) {
          DAT_003fd9fc = DAT_003fd9fc + 1;
        }
      }
    }
    else {
      obd_set_dtc(&CAL_obd_P0141,&LEA_obd_P0141_flags,&LEA_obd_P0141_engine_start_count,
                  &LEA_obd_P0141_warm_up_cycle_count,0x8d);
    }
  }
  if (((((LEA_obd_P0135_flags & 8) != 0) && ((LEA_obd_P0141_flags & 8) != 0)) &&
      (((LEA_obd_P0135_flags & 4) == 0 && ((LEA_obd_P0141_flags & 4) == 0)))) ||
     (((((LEA_obd_P0135_flags & 4) != 0 && ((LEA_obd_P0135_flags & 0x10) != 0)) &&
       ((LEA_obd_P0141_flags & 4) != 0)) && ((LEA_obd_P0141_flags & 0x10) != 0)))) {
    LEA_obd_monitors_completeness = LEA_obd_monitors_completeness & 0xbf;
  }
  if ((CAL_obd_P2602 & 7) != 0) {
    if ((DAT_003fdc24 & 0x4000) == 0) {
      DAT_003f9260 = 0;
      obd_clr_dtc(&CAL_obd_P2602,&LEA_obd_P2602_flags);
      if (DAT_003f925e < DAT_003fca16) {
        DAT_003f925e = DAT_003f925e + 1;
      }
    }
    else {
      DAT_003fdc24 = DAT_003fdc24 & 0xbfff;
      DAT_003f9260 = DAT_003f9260 + 1;
      if (DAT_003fdd44 <= DAT_003f9260) {
        DAT_003f9260 = 0;
        if (DAT_003f925e == 0) {
          obd_set_dtc(&CAL_obd_P2602,&LEA_obd_P2602_flags,&LEA_obd_P2602_engine_start_count,
                      &LEA_obd_P2602_warm_up_cycle_count,0xa2a);
        }
        else {
          DAT_003f925e = DAT_003f925e - 1;
        }
      }
    }
  }
  if ((((CAL_obd_P2603 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if ((DAT_003fdc24 & 0x8000) == 0) {
      DAT_003f9264 = 0;
      obd_clr_dtc(&CAL_obd_P2603,&LEA_obd_P2603_flags);
      if (DAT_003f9262 < DAT_003fca17) {
        DAT_003f9262 = DAT_003f9262 + 1;
      }
    }
    else {
      DAT_003fdc24 = DAT_003fdc24 & 0x7fff;
      DAT_003f9264 = DAT_003f9264 + 1;
      if (DAT_003fdd44 <= DAT_003f9264) {
        DAT_003f9264 = 0;
        if (DAT_003f9262 == 0) {
          obd_set_dtc(&CAL_obd_P2603,&LEA_obd_P2603_flags,&LEA_obd_P2603_engine_start_count,
                      &LEA_obd_P2603_warm_up_cycle_count,0xa2b);
        }
        else {
          DAT_003f9262 = DAT_003f9262 - 1;
        }
      }
    }
  }
  if ((((CAL_obd_P2648 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if ((DAT_003fdc22 & 2) == 0) {
      DAT_003f9268 = 0;
      obd_clr_dtc(&CAL_obd_P2648,&LEA_obd_P2648_flags);
      if (DAT_003f9266 < DAT_003fca24) {
        DAT_003f9266 = DAT_003f9266 + 1;
      }
    }
    else {
      DAT_003fdc22 = DAT_003fdc22 & 0xfffd;
      DAT_003f9268 = DAT_003f9268 + 1;
      if (DAT_003fdd44 <= DAT_003f9268) {
        DAT_003f9268 = 0;
        if (DAT_003f9266 == 0) {
          obd_set_dtc(&CAL_obd_P2648,&LEA_obd_P2648_flags,&LEA_obd_P2648_engine_start_count,
                      &LEA_obd_P2648_warm_up_cycle_count,0xa58);
        }
        else {
          DAT_003f9266 = DAT_003f9266 - 1;
        }
      }
    }
  }
  if ((((CAL_obd_P2649 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if ((DAT_003fdc22 & 1) == 0) {
      DAT_003f926c = 0;
      obd_clr_dtc(&CAL_obd_P2649,&LEA_obd_P2649_flags);
      if (DAT_003f926a < DAT_003fca25) {
        DAT_003f926a = DAT_003f926a + 1;
      }
    }
    else {
      DAT_003fdc22 = DAT_003fdc22 & 0xfffe;
      DAT_003f926c = DAT_003f926c + 1;
      if (DAT_003fdd44 <= DAT_003f926c) {
        DAT_003f926c = 0;
        if (DAT_003f926a == 0) {
          obd_set_dtc(&CAL_obd_P2649,&LEA_obd_P2649_flags,&LEA_obd_P2649_engine_start_count,
                      &LEA_obd_P2649_warm_up_cycle_count,0xa59);
        }
        else {
          DAT_003f926a = DAT_003f926a - 1;
        }
      }
    }
  }
  if ((((DAT_003fd9f2 == 0) || (DAT_003fd9f3 == 0)) || (DAT_003fd9f4 == 0)) || (DAT_003fd9f5 == 0))
  {
    sensor_fault_flags = sensor_fault_flags | 0x1000;
  }
  else {
    sensor_fault_flags = sensor_fault_flags & 0xefff;
  }
  if (((DAT_003fd9f7 == 0) || (DAT_003fd9f8 == 0)) || ((DAT_003fd9f9 == 0 || (DAT_003fd9fa == 0))))
  {
    sensor_fault_flags = sensor_fault_flags | 0x2000;
  }
  else {
    sensor_fault_flags = sensor_fault_flags & 0xdfff;
  }
  if (((DAT_003fd9e4 == 0) || (DAT_003fd9f1 == 0)) ||
     ((DAT_003fd9d8 == '\0' || (DAT_003fd9dd == '\0')))) {
    sensor_fault_flags = sensor_fault_flags | 0x40;
  }
  else {
    sensor_fault_flags = sensor_fault_flags & 0xffbf;
  }
  if ((((DAT_003f9266 == 0) || (DAT_003f926a == 0)) || (DAT_003fd9e0 == '\0')) ||
     (DAT_003fd9df == '\0')) {
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
  DAT_003fd9e4 = DAT_003fc9e9;
  DAT_003fd9f1 = DAT_003fc9ea;
  DAT_003f9224 = DAT_003fc9f6;
  DAT_003f9228 = DAT_003fc9f5;
  DAT_003f922c = DAT_003fc9f7;
  DAT_003f9230 = DAT_003fc9f8;
  DAT_003f9256 = DAT_003fc9f9;
  DAT_003f925a = DAT_003fc9fa;
  DAT_003fd9f2 = DAT_003fc9fd;
  DAT_003fd9f3 = DAT_003fc9fe;
  DAT_003fd9f4 = DAT_003fc9ff;
  DAT_003fd9f5 = DAT_003fca00;
  DAT_003fd9f6 = DAT_003fca01;
  DAT_003fd9fb = CAL_obd_P0135_confirm_threshold;
  DAT_003fd9fc = CAL_obd_P0141_confirm_threshold;
  DAT_003f9246 = DAT_003fca07;
  DAT_003f924a = DAT_003fca09;
  DAT_003f924e = DAT_003fca0a;
  DAT_003f925e = DAT_003fca16;
  DAT_003f9262 = DAT_003fca17;
  DAT_003f9266 = DAT_003fca24;
  DAT_003f926a = DAT_003fca25;
  DAT_003fd9f7 = DAT_003fc9ed;
  DAT_003fd9f8 = DAT_003fc9ee;
  DAT_003fd9f9 = DAT_003fc9ef;
  DAT_003fd9fa = DAT_003fc9f0;
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



// Sends OBD response frame

void send_obd_resp(void)

{
  uint uVar1;
  byte bVar3;
  uint uVar2;
  
  REG_CANA_MB7_CS = 0x80;
  REG_CANA_MB7_ID_HI = 0xfd00;
  if (DAT_003fdb08 == 0) {
    if (obd_resp_len < 8) {
      REG_CANA_MB7_DATA0 = (byte)obd_resp_len;
      for (uVar1 = 0; (uVar1 & 0xff) < (uint)obd_resp_len; uVar1 = uVar1 + 1) {
        (&REG_CANA_MB7_DATA1)[uVar1 & 0xff] = obd_resp[uVar1 & 0xff];
      }
      for (uVar1 = obd_resp_len & 0xff; (uVar1 & 0xff) < 7; uVar1 = uVar1 + 1) {
        (&REG_CANA_MB7_DATA1)[uVar1 & 0xff] = 0;
      }
      DAT_003fdb08 = '\0';
    }
    else {
      REG_CANA_MB7_DATA0 = (byte)(obd_resp_len >> 8) | 0x10;
      REG_CANA_MB7_DATA1 = (byte)obd_resp_len;
      for (bVar3 = 0; bVar3 < 6; bVar3 = bVar3 + 1) {
        (&REG_CANA_MB7_DATA2)[bVar3] = obd_resp[bVar3];
      }
      DAT_003fdb08 = '\x01';
    }
  }
  else {
    if (DAT_003fdb08 < 2) {
      uVar1 = 0;
    }
    else {
      uVar1 = (DAT_003fdb08 - 1) * 7 & 0xffff;
    }
    REG_CANA_MB7_DATA0 = DAT_003fdb08 & 0xf | 0x20;
    if ((uVar1 & 0xff) + 0xd < (uint)obd_resp_len) {
      for (bVar3 = 0; bVar3 < 7; bVar3 = bVar3 + 1) {
        (&REG_CANA_MB7_DATA1)[bVar3] = obd_resp[(uVar1 & 0xff) + (uint)bVar3 + 6];
      }
      if (DAT_003fdb08 < 0xff) {
        DAT_003fdb08 = DAT_003fdb08 + 1;
      }
      else {
        DAT_003fdb08 = '\0';
      }
    }
    else {
      for (uVar2 = 0; (int)(uVar2 & 0xff) < (int)((obd_resp_len - uVar1) + -6); uVar2 = uVar2 + 1) {
        (&REG_CANA_MB7_DATA1)[uVar2 & 0xff] = obd_resp[(uVar1 & 0xff) + (uVar2 & 0xff) + 6];
      }
      for (uVar1 = (obd_resp_len - uVar1) - 6 & 0xff; (uVar1 & 0xff) < 7; uVar1 = uVar1 + 1) {
        (&REG_CANA_MB7_DATA1)[uVar1 & 0xff] = 0;
      }
      DAT_003fdb0c = 0;
      DAT_003fdb0a = 0;
      DAT_003fdb08 = '\0';
    }
  }
  REG_CANA_MB7_CS = 200;
  return;
}



// OBD multi-frame response handler (5ms)

void send_obd_resp_5ms(void)

{
  if ((DAT_003fdb0a != '\0') && (DAT_003fdb08 != '\0')) {
    if (DAT_003fdb09 == '\0') {
      if (DAT_003f9270 == '\0') {
        if (DAT_003fdb0b == '\0') {
          DAT_003f9270 = -1;
        }
        else {
          DAT_003f9270 = DAT_003fdb0b;
          DAT_003fdb0b = '\0';
        }
      }
      if (DAT_003f9270 != '\0') {
        if (DAT_003f9271 == 0) {
          send_obd_resp();
          DAT_003f9270 = DAT_003f9270 + -1;
          if (DAT_003f9270 == '\0') {
            DAT_003fdb0a = '\0';
            DAT_003fdb0c = 0;
            DAT_003f9270 = '\0';
            DAT_003fdb0b = '\0';
            DAT_003fdb09 = '\0';
          }
          if ((DAT_003fdb0c & 0xf0) == 0xf0) {
            DAT_003f9271 = 0;
          }
          else {
            DAT_003f9271 = DAT_003fdb0c / 5;
          }
        }
        else {
          DAT_003f9271 = DAT_003f9271 - 1;
        }
      }
    }
    else if (DAT_003fdb09 == '\x01') {
      DAT_003fdb0a = '\0';
    }
    else if (DAT_003fdb09 == '\x02') {
      DAT_003fdb0a = '\0';
      DAT_003fdb0c = 0;
      DAT_003f9270 = '\0';
      DAT_003fdb0b = '\0';
      DAT_003fdb09 = '\0';
    }
  }
  return;
}



// ISR: SCI serial interrupt - HC08 communication

undefined8 isr_sci(undefined4 param_1,undefined4 param_2)

{
  uint uVar1;
  undefined4 in_MSR;
  undefined4 in_SRR1;
  
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
  if (((DAT_003f98b0 ^ DAT_003f98b7) & 1) == 0) {
    DAT_003fdc10 = DAT_003fdc10 & 0xcfff;
  }
  else if ((DAT_003f98b7 & 1) == 0) {
    DAT_003fdc10 = DAT_003fdc10 | 0x2000;
  }
  else {
    DAT_003fdc10 = DAT_003fdc10 | 0x1000;
  }
  if (((DAT_003f98b0 ^ DAT_003f98b7) & 2) == 0) {
    DAT_003fdc10 = DAT_003fdc10 & 0x3fff;
  }
  else if ((DAT_003f98b7 & 2) == 0) {
    DAT_003fdc10 = DAT_003fdc10 | 0x8000;
  }
  else {
    DAT_003fdc10 = DAT_003fdc10 | 0x4000;
  }
  if (((DAT_003f98b0 ^ DAT_003f98b7) & 4) == 0) {
    DAT_003fdc10 = DAT_003fdc10 & 0xf3ff;
  }
  else if ((DAT_003f98b7 & 4) == 0) {
    DAT_003fdc10 = DAT_003fdc10 | 0x800;
  }
  else {
    DAT_003fdc10 = DAT_003fdc10 | 0x400;
  }
  if (((DAT_003f98b0 ^ DAT_003f98b7) & 8) == 0) {
    DAT_003fdc10 = DAT_003fdc10 & 0xfff3;
  }
  else if ((DAT_003f98b7 & 8) == 0) {
    DAT_003fdc10 = DAT_003fdc10 | 8;
  }
  else {
    DAT_003fdc10 = DAT_003fdc10 | 4;
  }
  if (((DAT_003f98b0 ^ DAT_003f98b7) & 0x10) == 0) {
    DAT_003fdc10 = DAT_003fdc10 & 0xfcff;
  }
  else if ((DAT_003f98b7 & 0x10) == 0) {
    DAT_003fdc10 = DAT_003fdc10 | 0x200;
  }
  else {
    DAT_003fdc10 = DAT_003fdc10 | 0x100;
  }
  if (((DAT_003f98b0 ^ DAT_003f98b7) & 0x20) == 0) {
    DAT_003fdc10 = DAT_003fdc10 & 0xffcf;
  }
  else if ((DAT_003f98b7 & 0x20) == 0) {
    DAT_003fdc10 = DAT_003fdc10 | 0x20;
  }
  else {
    DAT_003fdc10 = DAT_003fdc10 | 0x10;
  }
  if (((DAT_003f98b0 ^ DAT_003f98b7) & 0x40) == 0) {
    DAT_003fdc10 = DAT_003fdc10 & 0xfffc;
  }
  else if ((DAT_003f98b7 & 0x40) == 0) {
    DAT_003fdc10 = DAT_003fdc10 | 2;
  }
  else {
    DAT_003fdc10 = DAT_003fdc10 | 1;
  }
  if (((DAT_003f98b0 ^ DAT_003f98b7) & 0x80) == 0) {
    DAT_003fdc10 = DAT_003fdc10 & 0xff3f;
  }
  else if ((DAT_003f98b7 & 0x80) == 0) {
    DAT_003fdc10 = DAT_003fdc10 | 0x80;
  }
  else {
    DAT_003fdc10 = DAT_003fdc10 | 0x40;
  }
  if (((DAT_003fdc10 & 0x80) == 0) || ((DAT_003fdc10 & 0x2000) == 0)) {
    shutdown_flags = shutdown_flags & 0xffdf;
  }
  else {
    shutdown_flags = shutdown_flags | 0x20;
  }
  shutdown_flags = shutdown_flags | 0x40;
  return;
}



// Checks TLE6220 high-side driver faults for injectors, VVT, VVL, and EVAP outputs

void TLE6220_fault_check(void)

{
  DAT_003fdc1c = DAT_003fdc1c | ~(ushort)DAT_003f8192 & 0xff;
  DAT_003fdc20 = DAT_003fdc20 | ~(ushort)DAT_003f8191 & 0xff;
  DAT_003fdc22 = DAT_003fdc22 | ~(ushort)DAT_003f8190 & 0xff;
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
    if ((engine_speed_2 < 501) || (1500 < engine_speed_2)) {
      if ((engine_speed_2 < 1501) || (2500 < engine_speed_2)) {
        if ((engine_speed_2 < 2501) || (3500 < engine_speed_2)) {
          if ((engine_speed_2 < 3501) || (4500 < engine_speed_2)) {
            if ((engine_speed_2 < 4501) || (5500 < engine_speed_2)) {
              if ((engine_speed_2 < 5501) || (6500 < engine_speed_2)) {
                if ((engine_speed_2 < 6501) || (7000 < engine_speed_2)) {
                  if ((7000 < engine_speed_2) && (engine_speed_2 < 7501)) {
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
    else if ((car_speed_smooth < 31) || (60 < car_speed_smooth)) {
      if ((car_speed_smooth < 61) || (90 < car_speed_smooth)) {
        if ((car_speed_smooth < 91) || (120 < car_speed_smooth)) {
          if ((car_speed_smooth < 121) || (150 < car_speed_smooth)) {
            if ((car_speed_smooth < 151) || (180 < car_speed_smooth)) {
              if ((car_speed_smooth < 181) || (210 < car_speed_smooth)) {
                if ((210 < car_speed_smooth) && (car_speed_smooth < 241)) {
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
  if ((DAT_003f8328 != '\0') && (DAT_003f8328 = DAT_003f8328 + -1, DAT_003fdc32 < engine_speed_2)) {
    DAT_003fdc32 = engine_speed_2;
  }
  if (DAT_003f8328 == '\0') {
    DAT_003f8328 = '2';
    if (LEA_perf_max_engine_speed[0] < DAT_003fdc32) {
      LEA_perf_max_engine_speed[4] = LEA_perf_max_engine_speed[3];
      LEA_perf_max_engine_speed[3] = LEA_perf_max_engine_speed[2];
      LEA_perf_max_engine_speed[2] = LEA_perf_max_engine_speed[1];
      LEA_perf_max_engine_speed[1] = LEA_perf_max_engine_speed[0];
      LEA_perf_max_engine_speed[0] = DAT_003fdc32;
      LEA_perf_max_engine_speed_5_coolant_temp = coolant_smooth;
      LEA_perf_max_engine_speed_5_run_timer = LEA_perf_engine_run_timer;
    }
    else if ((LEA_perf_max_engine_speed[1] < DAT_003fdc32) &&
            (DAT_003fdc32 < LEA_perf_max_engine_speed[0])) {
      LEA_perf_max_engine_speed[4] = LEA_perf_max_engine_speed[3];
      LEA_perf_max_engine_speed[3] = LEA_perf_max_engine_speed[2];
      LEA_perf_max_engine_speed[2] = LEA_perf_max_engine_speed[1];
      LEA_perf_max_engine_speed[1] = DAT_003fdc32;
      LEA_perf_max_engine_speed_4_coolant_temp = coolant_smooth;
      LEA_perf_max_engine_speed_4_run_timer = LEA_perf_engine_run_timer;
    }
    else if ((LEA_perf_max_engine_speed[2] < DAT_003fdc32) &&
            (DAT_003fdc32 < LEA_perf_max_engine_speed[1])) {
      LEA_perf_max_engine_speed[4] = LEA_perf_max_engine_speed[3];
      LEA_perf_max_engine_speed[3] = LEA_perf_max_engine_speed[2];
      LEA_perf_max_engine_speed[2] = DAT_003fdc32;
      LEA_perf_max_engine_speed_3_coolant_temp = coolant_smooth;
      LEA_perf_max_engine_speed_3_run_timer = LEA_perf_engine_run_timer;
    }
    else if ((LEA_perf_max_engine_speed[3] < DAT_003fdc32) &&
            (DAT_003fdc32 < LEA_perf_max_engine_speed[2])) {
      LEA_perf_max_engine_speed[4] = LEA_perf_max_engine_speed[3];
      LEA_perf_max_engine_speed[3] = DAT_003fdc32;
      LEA_perf_max_engine_speed_2_coolant_temp = coolant_smooth;
      LEA_perf_max_engine_speed_2_run_timer = LEA_perf_engine_run_timer;
    }
    else if ((LEA_perf_max_engine_speed[4] < DAT_003fdc32) &&
            (DAT_003fdc32 < LEA_perf_max_engine_speed[3])) {
      LEA_perf_max_engine_speed[4] = DAT_003fdc32;
      LEA_perf_max_engine_speed_1_coolant_temp = coolant_smooth;
      LEA_perf_max_engine_speed_1_run_timer = LEA_perf_engine_run_timer;
    }
    DAT_003fdc32 = 0;
  }
  if (car_speed_smooth != 255) {
    if (LEA_perf_max_vehicle_speed[0] < car_speed_smooth) {
      if (DAT_003fdc28 == '\x01') {
        DAT_003fdc30 = DAT_003fdc30 + 1;
      }
      else {
        DAT_003fdc30 = 0;
        DAT_003fdc28 = '\x01';
      }
      if (0x14 < DAT_003fdc30) {
        LEA_perf_max_vehicle_speed[4] = LEA_perf_max_vehicle_speed[3];
        LEA_perf_max_vehicle_speed[3] = LEA_perf_max_vehicle_speed[2];
        LEA_perf_max_vehicle_speed[2] = LEA_perf_max_vehicle_speed[1];
        LEA_perf_max_vehicle_speed[1] = LEA_perf_max_vehicle_speed[0];
        LEA_perf_max_vehicle_speed[0] = car_speed_smooth;
        DAT_003fdc30 = 0;
      }
    }
    else if ((LEA_perf_max_vehicle_speed[1] < car_speed_smooth) &&
            (car_speed_smooth < LEA_perf_max_vehicle_speed[0])) {
      if (DAT_003fdc28 == '\x02') {
        DAT_003fdc30 = DAT_003fdc30 + 1;
      }
      else {
        DAT_003fdc30 = 0;
        DAT_003fdc28 = '\x02';
      }
      if (0x14 < DAT_003fdc30) {
        LEA_perf_max_vehicle_speed[4] = LEA_perf_max_vehicle_speed[3];
        LEA_perf_max_vehicle_speed[3] = LEA_perf_max_vehicle_speed[2];
        LEA_perf_max_vehicle_speed[2] = LEA_perf_max_vehicle_speed[1];
        LEA_perf_max_vehicle_speed[1] = car_speed_smooth;
        DAT_003fdc30 = 0;
      }
    }
    else if ((LEA_perf_max_vehicle_speed[2] < car_speed_smooth) &&
            (car_speed_smooth < LEA_perf_max_vehicle_speed[1])) {
      if (DAT_003fdc28 == '\x03') {
        DAT_003fdc30 = DAT_003fdc30 + 1;
      }
      else {
        DAT_003fdc30 = 0;
        DAT_003fdc28 = '\x03';
      }
      if (0x14 < DAT_003fdc30) {
        LEA_perf_max_vehicle_speed[4] = LEA_perf_max_vehicle_speed[3];
        LEA_perf_max_vehicle_speed[3] = LEA_perf_max_vehicle_speed[2];
        LEA_perf_max_vehicle_speed[2] = car_speed_smooth;
        DAT_003fdc30 = 0;
      }
    }
    else if ((LEA_perf_max_vehicle_speed[3] < car_speed_smooth) &&
            (car_speed_smooth < LEA_perf_max_vehicle_speed[2])) {
      if (DAT_003fdc28 == '\x04') {
        DAT_003fdc30 = DAT_003fdc30 + 1;
      }
      else {
        DAT_003fdc30 = 0;
        DAT_003fdc28 = '\x04';
      }
      if (0x14 < DAT_003fdc30) {
        LEA_perf_max_vehicle_speed[4] = LEA_perf_max_vehicle_speed[3];
        LEA_perf_max_vehicle_speed[3] = car_speed_smooth;
        DAT_003fdc30 = 0;
      }
    }
    else if ((LEA_perf_max_vehicle_speed[4] < car_speed_smooth) &&
            (car_speed_smooth < LEA_perf_max_vehicle_speed[3])) {
      if (DAT_003fdc28 == '\x05') {
        DAT_003fdc30 = DAT_003fdc30 + 1;
      }
      else {
        DAT_003fdc30 = 0;
        DAT_003fdc28 = '\x05';
      }
      if (0x14 < DAT_003fdc30) {
        LEA_perf_max_vehicle_speed[4] = car_speed_smooth;
        DAT_003fdc30 = 0;
      }
    }
    else {
      DAT_003fdc28 = '\0';
    }
  }
  if (engine_speed_2 != 0) {
    if (LEA_perf_engine_run_timer == 4294967295) {
      LEA_perf_engine_run_timer = 0;
    }
    else {
      LEA_perf_engine_run_timer = LEA_perf_engine_run_timer + 1;
    }
  }
  if (car_speed_smooth == 0) {
    DAT_003fdc34 = 0;
    if (DAT_003f9a26 < engine_speed_2) {
      DAT_003fdc37 = DAT_003fdc37 | 7;
    }
    else {
      DAT_003fdc37 = DAT_003fdc37 & 0xf8;
    }
  }
  else if ((DAT_003fdc37 & 1) != 0) {
    DAT_003fdc34 = DAT_003fdc34 + 1;
    if (DAT_003fdc34 < 0xff) {
      if (((99 < car_speed_smooth) && (car_speed_smooth < 120)) && ((DAT_003fdc37 & 2) != 0)) {
        DAT_003fdc37 = DAT_003fdc37 & 0xfd;
        LEA_perf_number_of_standing_starts = LEA_perf_number_of_standing_starts + 1;
        DAT_003fdc35 = DAT_003fdc34;
      }
      if (((159 < car_speed_smooth) && (car_speed_smooth < 180)) && ((DAT_003fdc37 & 4) != 0)) {
        DAT_003fdc37 = DAT_003fdc37 & 0xfb;
        DAT_003fdc36 = DAT_003fdc34;
      }
    }
    else {
      DAT_003fdc37 = DAT_003fdc37 & 0xf8;
      DAT_003fdc34 = 0;
    }
  }
  if ((DAT_003fdc35 != 0) &&
     (LEA_perf_last_standing_start[0] = DAT_003fdc35,
     DAT_003fdc35 < LEA_perf_fastest_standing_start[0])) {
    LEA_perf_fastest_standing_start[0] = DAT_003fdc35;
  }
  if (((100 < DAT_003fdc36) && (DAT_003fdc35 < DAT_003fdc36)) &&
     (LEA_perf_last_standing_start[1] = DAT_003fdc36,
     DAT_003fdc36 < LEA_perf_fastest_standing_start[1])) {
    LEA_perf_fastest_standing_start[1] = DAT_003fdc36;
  }
  return;
}



// EVAP flow monitor (P0441)

void obd_check_evap_flow(void)

{
  ushort uVar1;
  ushort uVar2;
  
  if ((vacuum_smooth < DAT_003fc60c) || (evap_purge_command < DAT_003fc602)) {
    DAT_003f927c = DAT_003fc608;
    DAT_003f927e = '\0';
    DAT_003f927d = '\0';
  }
  else if ((int)evap_pressure_smooth < -(int)DAT_003fc604) {
    if (DAT_003f927d == '\x04') {
      if (DAT_003f927c == '\0') {
        DAT_003f927e = '\x04';
      }
    }
    else {
      DAT_003f927c = DAT_003fc608;
      DAT_003f927e = '\0';
      DAT_003f927d = '\x04';
    }
  }
  else if ((int)evap_pressure_smooth < -(int)DAT_003fc606) {
    if (DAT_003f927d == '\x03') {
      if (DAT_003f927c == '\0') {
        DAT_003f927e = '\x03';
      }
    }
    else {
      DAT_003f927c = DAT_003fc608;
      DAT_003f927e = '\0';
      DAT_003f927d = '\x03';
    }
  }
  else if (-(int)CAL_evap_leak_vacuum_min < (int)evap_pressure_smooth) {
    if (DAT_003f927d == '\x01') {
      if (DAT_003f927c == '\0') {
        DAT_003f927e = '\x01';
      }
    }
    else {
      DAT_003f927c = DAT_003fc608;
      DAT_003f927e = '\0';
      DAT_003f927d = '\x01';
    }
  }
  else if (DAT_003f927d == '\x02') {
    if (DAT_003f927c == '\0') {
      DAT_003f927e = '\x02';
    }
  }
  else {
    DAT_003f927c = DAT_003fc608;
    DAT_003f927e = '\0';
    DAT_003f927d = '\x02';
  }
  if (((((evap_flags & 0x200) == 0) || ((LEA_obd_P0455_flags & 8) != 0)) ||
      ((DAT_003fdc70 & 0x2000) != 0)) && ((DAT_003fdc70 & 0x40) == 0)) {
    uVar1 = DAT_003fdc70 & 0xefff;
  }
  else {
    uVar1 = DAT_003fdc70 | 0x1000;
    if (DAT_003f927e == '\x03') {
      if ((DAT_003fdc70 & 0x40) != 0) {
        if ((DAT_003fdc70 & 0x80) == 0) {
          uVar1 = DAT_003fdc70 | 0x5000;
        }
        DAT_003fdc70 = uVar1;
        uVar1 = DAT_003fdc70 & 0xffbf;
      }
      DAT_003fdc70 = uVar1;
      obd_clr_dtc(&CAL_obd_P0455,&LEA_obd_P0455_flags);
      obd_clr_dtc(&CAL_obd_P0441,&LEA_obd_P0441_flags);
      uVar1 = DAT_003fdc70;
    }
    else if ((DAT_003f927e == '\x02') || (DAT_003f927e == '\x01')) {
      if ((DAT_003fdc70 & 0x40) == 0) {
        uVar1 = DAT_003fdc70 | 0x3000;
      }
      else {
        if (((DAT_003fdc70 & 0x80) == 0) || (DAT_003f927e != '\x01')) {
          if ((DAT_003f927e == '\x02') || (DAT_003f927e == '\x01')) {
            uVar1 = DAT_003fdc70 | 0x3000;
          }
        }
        else {
          uVar1 = DAT_003fdc70 | 0x1100;
        }
        DAT_003fdc70 = uVar1;
        uVar1 = DAT_003fdc70 & 0xffbf;
      }
    }
  }
  DAT_003fdc70 = uVar1;
  if (((DAT_003fdc70 & 0x4000) == 0) && ((DAT_003fdc70 & 0x2000) == 0)) {
    if ((DAT_003fdc70 & 0x8000) != 0) {
      DAT_003f927a = DAT_003fc609;
    }
    DAT_003fdc70 = DAT_003fdc70 & 0x7fff;
    if (DAT_003f927a == '\0') {
      evap_flags = evap_flags & 0xdfff;
    }
    DAT_003f927b = DAT_003fc60a;
  }
  else {
    if ((DAT_003fdc70 & 0x8000) == 0) {
      DAT_003f927a = DAT_003fc609;
    }
    uVar1 = DAT_003fdc70 | 0x8000;
    evap_flags = evap_flags | 0x2000;
    if (((((car_speed_smooth == 0) || (load_2 <= DAT_003f927b)) || (DAT_003f927e == '\x04')) ||
        ((vacuum_smooth < DAT_003fc60c || (evap_purge_command < DAT_003fc602)))) ||
       ((DAT_003f927a == '\0' && (DAT_003f927e != '\0')))) {
      if (DAT_003f927e == '\x04') {
        uVar1 = DAT_003fdc70 & 0x9fff | 0x8000;
      }
      else if ((DAT_003f927e != '\0') && (DAT_003f927a == '\0')) {
        if ((DAT_003fdc70 & 0x4000) != 0) {
          uVar1 = DAT_003fdc70 & 0xbfff | 0x8200;
        }
        DAT_003fdc70 = uVar1;
        uVar1 = DAT_003fdc70;
        if ((DAT_003fdc70 & 0x2000) != 0) {
          DAT_002f835a = 1;
          if ((CAL_obd_P0455 & 7) != 0) {
            if (DAT_003fdc4c != '\0') {
              DAT_003fdc4c = DAT_003fdc4c + -1;
            }
            if (DAT_003fdc4c == '\0') {
              obd_set_dtc(&CAL_obd_P0455,&LEA_obd_P0455_flags,&LEA_obd_P0455_engine_start_count,
                          &LEA_obd_P0455_warm_up_cycle_count,0x1c7);
            }
          }
          uVar1 = DAT_003fdc70 & 0xdfff;
        }
      }
      DAT_003fdc70 = uVar1;
      uVar1 = REG_MPWMSM0_SCR;
      REG_MPWMSM0_SCR = uVar1 & 0xf7ff;
      DAT_003f927a = DAT_003fc609;
      DAT_003f927b = DAT_003fc60a;
    }
    else {
      uVar2 = REG_MPWMSM0_SCR;
      REG_MPWMSM0_SCR = uVar2 & 0xf7ff | 0x800;
      DAT_003f927b = DAT_003fc60b;
      DAT_003fdc70 = uVar1;
    }
  }
  if ((CAL_obd_P0441 & 7) != 0) {
    DAT_002f8358 = DAT_003fdc72;
    if (((int)DAT_003fdc72 < -(int)DAT_003fc606) || ((DAT_003fdc70 & 0x100) != 0)) {
      if (DAT_003f9278 != 0) {
        DAT_003f9278 = DAT_003f9278 - 1;
      }
      if (DAT_003f9278 == 0) {
        obd_set_dtc(&CAL_obd_P0441,&LEA_obd_P0441_flags,&LEA_obd_P0441_engine_start_count,
                    &LEA_obd_P0441_warm_up_cycle_count,0x1b9);
        DAT_003fdc70 = DAT_003fdc70 & 0xfeff;
        DAT_003fdc72 = 0;
      }
    }
    else {
      if (DAT_003f9278 < DAT_003fca30) {
        DAT_003f9278 = DAT_003f9278 + 1;
      }
      if (evap_leak_state == 5) {
        obd_clr_dtc(&CAL_obd_P0441,&LEA_obd_P0441_flags);
      }
    }
  }
  if ((CAL_obd_P0446 & 7) != 0) {
    if ((((int)evap_pressure_smooth < -(int)DAT_003fc604) && (evap_state == '\x01')) &&
       ((evap_flags & 0x2000) == 0)) {
      if (DAT_003f927f == '\0') {
        if (DAT_003f9279 != 0) {
          DAT_003f9279 = DAT_003f9279 - 1;
        }
        if (DAT_003f9279 == 0) {
          obd_set_dtc(&CAL_obd_P0446,&LEA_obd_P0446_flags,&LEA_obd_P0446_engine_start_count,
                      &LEA_obd_P0446_warm_up_cycle_count,0x1be);
          DAT_003fdc70 = DAT_003fdc70 | 0x400;
        }
      }
    }
    else {
      DAT_003f927f = DAT_003fc608;
      if ((DAT_003fdc70 & 0x200) == 0) {
        if (DAT_003f9279 < DAT_003fca40) {
          DAT_003f9279 = DAT_003f9279 + 1;
        }
        if (((((DAT_003fdc70 & 0x80) != 0) || (evap_leak_state == 5)) ||
            (DAT_003f9a76 >> 1 < evap_purge_command)) && ((LEA_obd_P0446_flags & 8) == 0)) {
          obd_clr_dtc(&CAL_obd_P0446,&LEA_obd_P0446_flags);
        }
      }
      else {
        if (DAT_003f9279 != 0) {
          DAT_003f9279 = DAT_003f9279 - 1;
        }
        if (DAT_003f9279 == 0) {
          obd_set_dtc(&CAL_obd_P0446,&LEA_obd_P0446_flags,&LEA_obd_P0446_engine_start_count,
                      &LEA_obd_P0446_warm_up_cycle_count,0x1be);
          DAT_003fdc70 = DAT_003fdc70 & 0xfdff;
        }
      }
    }
  }
  return;
}



// EVAP flow monitor task (100ms)

void obd_check_evap_flow_100ms(void)

{
  if (DAT_003f927a != '\0') {
    DAT_003f927a = DAT_003f927a + -1;
  }
  if (DAT_003f927c != '\0') {
    DAT_003f927c = DAT_003f927c + -1;
  }
  if (DAT_003f927f != '\0') {
    DAT_003f927f = DAT_003f927f + -1;
  }
  return;
}



// Initializes EVAP flow monitor state

void obd_init_evap_flow(void)

{
  DAT_003f9278 = DAT_003fca30;
  DAT_003f9279 = DAT_003fca40;
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
  if (DAT_003f9282 < car_speed_smooth) {
    DAT_003f9282 = car_speed_smooth;
  }
  if (((CAL_obd_P1280 & 7) != 0) && (engine_is_running)) {
    if (((dfso_flags & 1) == 0) ||
       (((engine_speed_3 < DAT_003fc54b || (DAT_003fc5a6 < engine_speed_3)) ||
        (atmo_pressure < DAT_003fc5d6)))) {
      DAT_003f9280 = DAT_003fc544;
    }
    else if (DAT_003f9280 != 0) {
      DAT_003f9280 = DAT_003f9280 + -1;
    }
    if (DAT_003f9280 == 0) {
      if (car_speed_smooth < DAT_003fc548) {
        if (DAT_003fdc3c == 0) {
          obd_set_dtc(&CAL_obd_P1280,&LEA_obd_P0500_flags,&LEA_obd_P0500_engine_start_count,
                      &LEA_obd_P0500_warm_up_cycle_count,500);
        }
        else {
          DAT_003fdc3c = DAT_003fdc3c - 1;
        }
      }
      else {
        obd_clr_dtc(&CAL_obd_P1280,&LEA_obd_P0500_flags);
        if (DAT_003fdc3c < DAT_003fca2d) {
          DAT_003fdc3c = DAT_003fdc3c + 1;
        }
      }
    }
  }
  if (((CAL_obd_P0335 & 7) != 0) && ((shutdown_flags & 1) != 0)) {
    if ((DAT_003fc549 < DAT_003f97c1) || (DAT_003fc549 < DAT_003f97c0)) {
      if (DAT_003fdc38 == 0) {
        obd_set_dtc(&CAL_obd_P0335,&LEA_obd_P0335_flags,&LEA_obd_P0335_engine_start_count,
                    &LEA_obd_P0335_warm_up_cycle_count,0x14f);
      }
      else {
        DAT_003fdc38 = DAT_003fdc38 - 1;
      }
    }
    else {
      obd_clr_dtc(&CAL_obd_P0335,&LEA_obd_P0335_flags);
      if (DAT_003fdc38 < DAT_003fca2b) {
        DAT_003fdc38 = DAT_003fdc38 + 1;
      }
    }
  }
  if ((engine_is_running == false) && (DAT_003f97c0 < DAT_003fc549)) {
    DAT_003fdc38 = DAT_003fca2b;
  }
  if ((((CAL_obd_P0340 & 7) != 0) && ((shutdown_flags & 1) != 0)) && (engine_is_running != false)) {
    if ((DAT_003f9704 == -0x80) || (DAT_003f9704 == -1)) {
      if (DAT_003fdc3b == 0) {
        obd_set_dtc(&CAL_obd_P0340,&LEA_obd_P0340_flags,&LEA_obd_P0340_engine_start_count,
                    &LEA_obd_P0340_warm_up_cycle_count,0x154);
      }
      else {
        DAT_003fdc3b = DAT_003fdc3b - 1;
      }
    }
    else {
      obd_clr_dtc(&CAL_obd_P0340,&LEA_obd_P0340_flags);
      if (DAT_003fdc3b < DAT_003fca2c) {
        DAT_003fdc3b = DAT_003fdc3b + 1;
      }
    }
  }
  return;
}



// Initializes crank/cam monitor state

void obd_init_crank_cam_speed(void)

{
  DAT_003fdc38 = DAT_003fca2b;
  DAT_003fdc3c = DAT_003fca2d;
  DAT_003fdc3b = DAT_003fca2c;
  DAT_003f9280 = DAT_003fc544;
  obd_init_dtc(&CAL_obd_P0335,&LEA_obd_P0335_flags,0x14f);
  obd_init_dtc(&CAL_obd_P1280,&LEA_obd_P0500_flags,500);
  obd_init_dtc(&CAL_obd_P0340,&LEA_obd_P0340_flags,0x154);
  return;
}



// Crank/cam monitor cycle counter

void obd_cyc_crank_cam_speed(void)

{
  obd_cyc_dtc(&CAL_obd_P0335,&LEA_obd_P0335_flags,&LEA_obd_P0335_engine_start_count,
              &LEA_obd_P0335_warm_up_cycle_count,0x14f);
  obd_cyc_dtc(&CAL_obd_P1280,&LEA_obd_P0500_flags,&LEA_obd_P0500_engine_start_count,
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
    iVar1 = (1000 - atmo_pressure) * (int)(short)(ushort)DAT_003fc535;
    iVar1 = iVar1 / 100 + (iVar1 >> 0x1f);
    DAT_003fdc46 = DAT_003fc52e + ((short)iVar1 - (short)(iVar1 >> 0x1f));
  }
  else {
    DAT_003fdc46 = DAT_003fc52e;
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
      if ((((DAT_003fdc46 < inj_time_adj_by_ltft) && (DAT_003fc5ce <= DAT_003fd97e)) &&
          (maf_flow_1 < CAL_ltft_zone2_flow_max)) ||
         (((short)(ushort)DAT_003fc562 * 10 < (int)LEA_ltft_zone1_adj &&
          (DAT_003fc5cc <= DAT_003fd97c)))) {
        if (DAT_003fdc40 == 0) {
          obd_set_dtc(&CAL_obd_P0171,&LEA_obd_P0171_flags,&LEA_obd_P0171_engine_start_count,
                      &LEA_obd_P0171_warm_up_cycle_count,0xab);
        }
        else {
          DAT_003fdc40 = DAT_003fdc40 - 1;
        }
      }
      else if ((DAT_003fc5cc <= DAT_003fd97c) &&
              ((DAT_003fc5ce < DAT_003fd97e &&
               (obd_clr_dtc(&CAL_obd_P0171,&LEA_obd_P0171_flags), DAT_003fdc40 < DAT_003fca1a)))) {
        DAT_003fdc40 = DAT_003fdc40 + 1;
      }
    }
    if ((CAL_obd_P0172 & 7) != 0) {
      if (((((int)inj_time_adj_by_ltft < -(int)DAT_003fc530) && (DAT_003fc5ce <= DAT_003fd97e)) &&
          (maf_flow_1 < CAL_ltft_zone2_flow_max)) ||
         (((int)LEA_ltft_zone1_adj < (short)(ushort)DAT_003fc563 * -10 &&
          (DAT_003fc5cc <= DAT_003fd97c)))) {
        if (DAT_003fdc44 == 0) {
          obd_set_dtc(&CAL_obd_P0172,&LEA_obd_P0172_flags,&LEA_obd_P0172_engine_start_count,
                      &LEA_obd_P0172_warm_up_cycle_count,0xac);
        }
        else {
          DAT_003fdc44 = DAT_003fdc44 - 1;
        }
      }
      else if ((DAT_003fc5cc <= DAT_003fd97c) &&
              ((DAT_003fc5ce < DAT_003fd97e &&
               (obd_clr_dtc(&CAL_obd_P0172,&LEA_obd_P0172_flags), DAT_003fdc44 < DAT_003fca1b)))) {
        DAT_003fdc44 = DAT_003fdc44 + 1;
      }
    }
  }
  return;
}



// Initializes fuel trim monitor state

void obd_init_fuel_trim(void)

{
  DAT_003fdc40 = DAT_003fca1a;
  DAT_003fdc44 = DAT_003fca1b;
  obd_init_dtc(&CAL_obd_P0171,&LEA_obd_P0171_flags,0xab);
  obd_init_dtc(&CAL_obd_P0172,&LEA_obd_P0172_flags,0xac);
  return;
}



// Fuel trim monitor cycle counter

void obd_cyc_fuel_trim(void)

{
  if (((LEA_obd_P0171_flags & 4) != 0) && ((short)((ushort)DAT_003fc562 * 5) < LEA_ltft_zone1_adj))
  {
    LEA_ltft_zone1_adj = (ushort)DAT_003fc562 * 5;
  }
  if (((LEA_obd_P0172_flags & 4) != 0) && (LEA_ltft_zone1_adj < (short)((ushort)DAT_003fc563 * -5)))
  {
    LEA_ltft_zone1_adj = (ushort)DAT_003fc563 * -5;
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
  
  if (((((idle_flags & 8) != 0) && (sensor_adc_ecu_voltage < DAT_003fc54e)) &&
      (DAT_003fc54c < sensor_adc_ecu_voltage)) && (engine_is_running)) {
    if ((CAL_obd_P0506 & 7) != 0) {
      if (((((ac_fan_flags & 0x400) == 0) ||
           (uVar1 = (uint)LEA_idle_flow_adj1_ac_on,
           (int)(((int)uVar1 >> 10) + (uint)((int)uVar1 < 0 && (uVar1 & 0x3ff) != 0)) <=
           (int)(uint)DAT_003fc551)) &&
          (((ac_fan_flags & 0x400) != 0 ||
           (uVar1 = (uint)LEA_idle_flow_adj1,
           (int)(((int)uVar1 >> 10) + (uint)((int)uVar1 < 0 && (uVar1 & 0x3ff) != 0)) <=
           (int)(uint)DAT_003fc551)))) ||
         ((int)((uint)DAT_003fc574 * -2) <= (int)engine_speed_idle_error)) {
        DAT_003f9288 = 0;
        obd_clr_dtc(&CAL_obd_P0506,&LEA_obd_P0506_flags);
        if (DAT_003fdc48 < DAT_003fca2e) {
          DAT_003fdc48 = DAT_003fdc48 + 1;
        }
      }
      else {
        DAT_003f9288 = DAT_003f9288 + 1;
        if (DAT_003fc552 <= DAT_003f9288) {
          DAT_003f9288 = 0;
          if (DAT_003fdc48 == 0) {
            obd_set_dtc(&CAL_obd_P0506,&LEA_obd_P0506_flags,&LEA_obd_P0506_engine_start_count,
                        &LEA_obd_P0506_warm_up_cycle_count,0x1fa);
          }
          else {
            DAT_003fdc48 = DAT_003fdc48 - 1;
          }
        }
      }
    }
    if ((CAL_obd_P0507 & 7) != 0) {
      if (((((ac_fan_flags & 0x400) == 0) ||
           (uVar1 = (uint)LEA_idle_flow_adj1_ac_on,
           (int)-(uint)DAT_003fc550 <=
           (int)(((int)uVar1 >> 10) + (uint)((int)uVar1 < 0 && (uVar1 & 0x3ff) != 0)))) &&
          (((ac_fan_flags & 0x400) != 0 ||
           (uVar1 = (uint)LEA_idle_flow_adj1,
           (int)-(uint)DAT_003fc550 <=
           (int)(((int)uVar1 >> 10) + (uint)((int)uVar1 < 0 && (uVar1 & 0x3ff) != 0)))))) ||
         ((int)engine_speed_idle_error <= (int)((uint)DAT_003fc573 << 1))) {
        DAT_003f9289 = 0;
        obd_clr_dtc(&CAL_obd_P0507,&LEA_obd_P0507_flags);
        if (DAT_003fdc4a < DAT_003fca2f) {
          DAT_003fdc4a = DAT_003fdc4a + 1;
        }
      }
      else {
        DAT_003f9289 = DAT_003f9289 + 1;
        if (DAT_003fc552 <= DAT_003f9289) {
          DAT_003f9289 = 0;
          if (DAT_003fdc4a == 0) {
            obd_set_dtc(&CAL_obd_P0507,&LEA_obd_P0507_flags,&LEA_obd_P0507_engine_start_count,
                        &LEA_obd_P0507_warm_up_cycle_count,0x1fb);
          }
          else {
            DAT_003fdc4a = DAT_003fdc4a - 1;
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
  DAT_003fdc48 = DAT_003fca2e;
  DAT_003fdc4a = DAT_003fca2f;
  obd_init_dtc(&CAL_obd_P0506,&LEA_obd_P0506_flags,0x1fa);
  obd_init_dtc(&CAL_obd_P0507,&LEA_obd_P0507_flags,0x1fb);
  return;
}



// Idle speed monitor cycle counter

void obd_cyc_idle_speed(void)

{
  if ((LEA_obd_P0506_flags & 4) != 0) {
    if ((short)(ushort)DAT_003fc551 < LEA_idle_flow_adj1_ac_on >> 10) {
      LEA_idle_flow_adj1_ac_on = (i16_flow_100_1024mg_s)((int)(short)(ushort)DAT_003fc551 << 9);
    }
    if ((short)(ushort)DAT_003fc551 < LEA_idle_flow_adj1 >> 10) {
      LEA_idle_flow_adj1 = (i16_flow_100_1024mg_s)((int)(short)(ushort)DAT_003fc551 << 9);
    }
  }
  if ((LEA_obd_P0507_flags & 4) != 0) {
    if ((int)LEA_idle_flow_adj1_ac_on >> 10 < -(int)(short)(ushort)DAT_003fc550) {
      LEA_idle_flow_adj1_ac_on = (ushort)DAT_003fc550 * -0x200;
    }
    if ((int)LEA_idle_flow_adj1 >> 10 < -(int)(short)(ushort)DAT_003fc550) {
      LEA_idle_flow_adj1 = (ushort)DAT_003fc550 * -0x200;
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
  uint uVar3;
  byte bVar4;
  int iVar5;
  
  if ((CAL_obd_P0442 & 7) == 0) {
    DAT_003fdc8c = DAT_003fdc8c | 1;
  }
  if ((((LEA_obd_P0455_flags & 4) != 0) || ((LEA_obd_P0442_flags & 4) != 0)) ||
     ((LEA_obd_P0456_flags & 8) != 0)) {
    DAT_003fdc8c = DAT_003fdc8c | 2;
  }
  if ((LEA_obd_P0441_flags & 4) != 0) {
    DAT_003fdc8c = DAT_003fdc8c | 4;
  }
  if ((LEA_obd_P0444_flags & 4) != 0) {
    DAT_003fdc8c = DAT_003fdc8c | 8;
  }
  if ((LEA_obd_P0445_flags & 4) != 0) {
    DAT_003fdc8c = DAT_003fdc8c | 0x10;
  }
  if ((LEA_obd_P0446_flags & 4) != 0) {
    DAT_003fdc8c = DAT_003fdc8c | 0x20;
  }
  if ((LEA_obd_P0447_flags & 4) != 0) {
    DAT_003fdc8c = DAT_003fdc8c | 0x40;
  }
  if ((LEA_obd_P0448_flags & 4) != 0) {
    DAT_003fdc8c = DAT_003fdc8c | 0x80;
  }
  if ((LEA_obd_P0451_flags & 4) != 0) {
    DAT_003fdc8c = DAT_003fdc8c | 0x100;
  }
  if ((LEA_obd_P0452_flags & 4) != 0) {
    DAT_003fdc8c = DAT_003fdc8c | 0x200;
  }
  if ((LEA_obd_P0453_flags & 4) != 0) {
    DAT_003fdc8c = DAT_003fdc8c | 0x400;
  }
  if ((LEA_obd_P0461_flags & 4) != 0) {
    DAT_003fdc8c = DAT_003fdc8c | 0x800;
  }
  if ((LEA_obd_P0462_flags & 4) != 0) {
    DAT_003fdc8c = DAT_003fdc8c | 0x1000;
  }
  if ((LEA_obd_P0463_flags & 4) != 0) {
    DAT_003fdc8c = DAT_003fdc8c | 0x2000;
  }
  if ((LEA_obd_P0500_flags & 4) != 0) {
    DAT_003fdc8c = DAT_003fdc8c | 0x4000;
  }
  if (DAT_003fdc40 == '\0') {
    DAT_003fdc8c = DAT_003fdc8c | 0x8000;
  }
  if (DAT_003fdc44 == '\0') {
    DAT_003fdc8c = DAT_003fdc8c | 0x10000;
  }
  if (engine_air_stop < CAL_evap_leak_engine_air_stop_max) {
    DAT_003fdc8c = DAT_003fdc8c | 0x40000;
  }
  if (DAT_003fdc8c != 0) {
    DAT_003fdc70 = DAT_003fdc70 | 2;
  }
  if ((((((DAT_003fdc70 & 2) == 0) && (CAL_evap_leak_atmo_pressure_min < atmo_pressure)) &&
       (((((LEA_obd_P0442_flags & 8) == 0 && ((evap_flags & 0x200) == 0)) || (DAT_003f9292 == 0)) &&
        (((fuel_level_smooth < CAL_evap_leak_fuel_level_max &&
          (CAL_evap_leak_fuel_level_min < fuel_level_smooth)) &&
         ((CAL_evap_leak_coolant_min < coolant_smooth &&
          ((engine_air_smooth < CAL_evap_leak_engine_air_max && ((DAT_003fdc70 & 0x6040) == 0)))))))
        ))) || ((DAT_003fdc70 & 1) != 0)) &&
     ((((car_speed_smooth == 0 && ((fuel_system_status & 2) != 0)) && ((idle_flags & 8) != 0)) &&
      ((shutdown_flags & 1) != 0)))) {
    DAT_003fdc70 = DAT_003fdc70 | 4;
  }
  else {
    DAT_003fdc70 = DAT_003fdc70 & 0xfffb;
  }
  if (((DAT_003fdc70 & 4) == 0) || ((DAT_003fdc70 & 8) == 0)) {
    if ((obd_mode_0x2F_state == '\x18') ||
       ((obd_mode_0x08_state == '\x18' || (DAT_003fc56a == '\x06')))) {
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
    DAT_003fdc70 = DAT_003fdc70 & 0xffcf;
    evap_leak_state = 0;
    DAT_003fdc84 = CAL_evap_leak_initial_delay;
    if ((((idle_flags & 8) == 0) || (car_speed_smooth != 0)) &&
       (((LEA_obd_P0442_flags & 8) != 0 || ((evap_flags & 0x200) != 0)))) {
      DAT_003f9292 = CAL_evap_leak_cooldown;
    }
    else if (DAT_003f9292 != 0) {
      DAT_003f9292 = DAT_003f9292 - 1;
    }
    if (CAL_evap_leak_force != 0) {
      DAT_003fdc70 = DAT_003fdc70 | 1;
    }
    evap_pressure_drop_max_leak_test = 255;
    uVar1 = DAT_003fdc70;
  }
  else {
    uVar1 = DAT_003fdc70 | 0x10;
    if (evap_leak_state == 3) {
      uVar1 = DAT_003fdc70 | 0x30;
      if (DAT_003fdc8a < evap_pressure) {
        if ((int)DAT_003fdc8a + (int)DAT_003f8330 < (int)evap_pressure) {
          DAT_003f9294 = evap_pressure_drop_2;
          evap_pressure_drop_max_leak_test = 255;
        }
        else {
          iVar5 = (int)((uint)DAT_003f9294 * ((int)evap_pressure - (int)DAT_003fdc8a)) /
                  (int)DAT_003f8330 + ((int)(uint)DAT_003f9298 >> 2);
          if (iVar5 < 2) {
            evap_pressure_drop_max_leak_test = 2;
          }
          else if (iVar5 < 0x100) {
            evap_pressure_drop_max_leak_test = (u8_pressure_4mbar)iVar5;
          }
          else {
            evap_pressure_drop_max_leak_test = 255;
          }
          if (DAT_003f9298 != 0xff) {
            DAT_003f9298 = DAT_003f9298 + 1;
          }
        }
        if (DAT_003f9296 == 0) {
          if ((((DAT_003fdc70 & 0x800) == 0) &&
              ((short)CAL_evap_leak_purge_min < evap_purge_command)) ||
             ((short)CAL_evap_leak_purge_retry_min < evap_purge_command)) {
            uVar1 = DAT_003fdc70 | 0x70;
          }
          DAT_003fdc70 = uVar1;
          uVar1 = DAT_003fdc70 & 0xfffe;
        }
        else {
          DAT_003f9296 = DAT_003f9296 - 1;
          if (CAL_evap_leak_gross_pressure < evap_pressure) {
            DAT_003fdc70 = uVar1;
            obd_clr_dtc(&CAL_obd_P0455,&LEA_obd_P0455_flags);
            uVar1 = DAT_003fdc70 | 0x80;
          }
          else if ((int)evap_pressure < -(int)CAL_evap_leak_vacuum_min) {
            uVar1 = DAT_003fdc70 | 0x830;
          }
        }
      }
      else {
        DAT_003fdc70 = uVar1 & 0xffdf;
        DAT_003fdc85 = CAL_evap_leak_settle_time;
        obd_clr_dtc(&CAL_obd_P0455,&LEA_obd_P0455_flags);
        DAT_002f835a = 0;
        evap_leak_state = evap_leak_state + 1;
        uVar1 = DAT_003fdc70;
      }
    }
    else {
      DAT_003fdc70 = uVar1;
      if (evap_leak_state < 3) {
        if (evap_leak_state == 1) {
          if (DAT_003fdc85 == 0) {
            uVar3 = (uint)sensor_adc_evap * (uint)CAL_sensor_evap_gain;
            DAT_003fd6a2 = ((short)((int)uVar3 >> 10) +
                           (ushort)((int)uVar3 < 0 && (uVar3 & 0x3ff) != 0)) -
                           CAL_sensor_evap_offset;
            DAT_003fdc80 = 0;
            DAT_003fdc72 = 0;
            DAT_003fdc86 = CAL_evap_leak_baseline_time;
            evap_leak_state = 2;
          }
          else {
            DAT_003fdc85 = DAT_003fdc85 + 255;
          }
        }
        else if (evap_leak_state == 0) {
          if (true) {
            if (DAT_003fdc84 == 0) {
              uVar2 = REG_MPWMSM0_SCR;
              REG_MPWMSM0_SCR = uVar2 & 0xf7ff | 0x800;
              DAT_003fdc85 = CAL_evap_leak_settle_time;
              evap_leak_state = 1;
            }
            else {
              DAT_003fdc84 = DAT_003fdc84 + 255;
            }
          }
        }
        else {
          if (DAT_003fdc86 == 0) {
            bVar4 = lookup_3D_uint8_interpolated
                              (8,16,DAT_003fdc7c & 0xff,(ushort)fuel_level_smooth,&DAT_003fd48e,
                               &DAT_003fd476,&DAT_003fd47e);
            DAT_003fdc8a = DAT_003fdc72 - (ushort)bVar4;
            DAT_003f9296 = (ushort)CAL_evap_leak_purge_time;
            DAT_003f9298 = 0;
            evap_leak_state = evap_leak_state + 1;
            DAT_003fdc70 = DAT_003fdc70 & 0xf7ff;
          }
          else {
            DAT_003fdc86 = DAT_003fdc86 + 255;
          }
          if (DAT_003fdc80 < evap_pressure) {
            DAT_003fdc80 = evap_pressure;
          }
          if (evap_pressure < DAT_003fdc72) {
            DAT_003fdc72 = evap_pressure;
          }
          uVar1 = DAT_003fdc70;
          if (DAT_003fdc80 < DAT_003fdc72) {
            DAT_003fdc7c = 0;
          }
          else {
            DAT_003fdc7c = DAT_003fdc80 - DAT_003fdc72;
          }
        }
      }
      else if (evap_leak_state == 5) {
        DAT_003fdc76 = (evap_pressure - evap_reference) -
                       (short)(((int)(short)DAT_003fdc7c *
                               (int)(short)(CAL_evap_leak_P0456_time - DAT_003fdc88)) /
                              (int)(short)(ushort)CAL_evap_leak_baseline_time);
        if (DAT_003fdc88 != 0) {
          DAT_003fdc88 = DAT_003fdc88 - 1;
        }
        if (DAT_003fdc87 == 0) {
          DAT_002f8364 = DAT_003fdc7b;
          LEA_evap_leak_result = evap_leak_result;
          obd_clr_dtc(&CAL_obd_P0442,&LEA_obd_P0442_flags);
          if (DAT_003f9291 < DAT_003fca31) {
            DAT_003f9291 = DAT_003f9291 + 1;
          }
          if (DAT_003fdc88 == 0) {
            DAT_002f8365 = DAT_003fdc7a;
            DAT_002f8362 = DAT_003fdc76;
            obd_clr_dtc(&CAL_obd_P0456,&LEA_obd_P0456_flags);
            if (DAT_003f9290 < DAT_003fca44) {
              DAT_003f9290 = DAT_003f9290 + 1;
            }
            if (((int)(uint)DAT_002f829a < (int)(short)DAT_003fdc76) && (0 < (short)DAT_003fdc76)) {
              DAT_002f829a = DAT_003fdc76;
              sort10(&DAT_002f829a);
            }
            uVar1 = DAT_003fdc70 & 0xfffe;
          }
          else {
            uVar1 = DAT_003fdc70;
            if ((short)(ushort)DAT_003fdc7a < (short)DAT_003fdc76) {
              DAT_002f8365 = DAT_003fdc7a;
              DAT_002f8362 = DAT_003fdc76;
              if (DAT_003f9290 != 0) {
                DAT_003f9290 = DAT_003f9290 - 1;
              }
              if (DAT_003f9290 == 0) {
                obd_set_dtc(&CAL_obd_P0456,&LEA_obd_P0456_flags,&LEA_obd_P0456_engine_start_count,
                            &LEA_obd_P0456_warm_up_cycle_count,0x1c8);
                uVar1 = DAT_003fdc70 & 0xfffe;
              }
            }
          }
        }
        else {
          DAT_003fdc87 = DAT_003fdc87 + 255;
          evap_leak_result = DAT_003fdc76;
          if ((short)(ushort)DAT_003fdc7b < (short)DAT_003fdc76) {
            DAT_002f8364 = DAT_003fdc7b;
            if (DAT_003f9291 != 0) {
              DAT_003f9291 = DAT_003f9291 - 1;
            }
            LEA_evap_leak_result = DAT_003fdc76;
            if (DAT_003f9291 == 0) {
              obd_set_dtc(&CAL_obd_P0442,&LEA_obd_P0442_flags,&LEA_obd_P0442_engine_start_count,
                          &LEA_obd_P0442_warm_up_cycle_count,0x1ba);
              uVar1 = DAT_003fdc70 & 0xfffe;
            }
          }
        }
      }
      else if ((evap_leak_state < 5) && (evap_pressure_drop_2 == 0)) {
        if (DAT_003fdc85 == 0) {
          inj_time_adj_by_stft = 0;
          evap_reference = evap_pressure;
          DAT_003fdc87 = CAL_evap_leak_P0442_time;
          DAT_003fdc88 = CAL_evap_leak_P0456_time;
          DAT_003fdc7a = lookup_2D_uint8_interpolated
                                   (16,fuel_level_smooth,CAL_evap_leak_P0456_threshold,
                                    CAL_evap_leak_P0456_threshold_X_fuel_level);
          DAT_003fdc7b = lookup_2D_uint8_interpolated
                                   (16,fuel_level_smooth,CAL_evap_leak_P0442_threshold,
                                    CAL_evap_leak_P0442_threshold_X_fuel_level);
          evap_leak_state = evap_leak_state + 1;
          uVar1 = DAT_003fdc70;
        }
        else {
          DAT_003fdc85 = DAT_003fdc85 + 255;
        }
      }
    }
  }
  DAT_003fdc70 = uVar1;
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
  DAT_003f9291 = DAT_003fca31;
  DAT_003fdc4c = DAT_003fca43;
  DAT_003f9290 = DAT_003fca44;
  obd_init_dtc(&CAL_obd_P0442,&LEA_obd_P0442_flags,0x1ba);
  obd_init_dtc(&CAL_obd_P0455,&LEA_obd_P0455_flags,0x1c7);
  obd_init_dtc(&CAL_obd_P0456,&LEA_obd_P0456_flags,0x1c8);
  DAT_003fdc84 = CAL_evap_leak_initial_delay;
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
    if ((DAT_003fdc90 & 1) == 0) {
      obd_clr_dtc(&CAL_obd_P0601,&LEA_obd_P0601_flags);
    }
    else {
      DAT_003fdc90 = DAT_003fdc90 & 0xfffe;
      obd_set_dtc(&CAL_obd_P0601,&LEA_obd_P0601_flags,&LEA_obd_P0601_engine_start_count,
                  &LEA_obd_P0601_warm_up_cycle_count,0x259);
    }
  }
  if ((CAL_obd_P0606 & 7) != 0) {
    if ((DAT_003fdc90 & 2) == 0) {
      obd_clr_dtc(&CAL_obd_P0606,&LEA_obd_P0606_flags);
    }
    else {
      DAT_003fdc90 = DAT_003fdc90 & 0xfffd;
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
  DAT_003fdc90 = DAT_003fdc90 | 4;
  for (bVar1 = 0; bVar1 < 0x11; bVar1 = bVar1 + 1) {
    if (LEA_ecu_VIN[bVar1] != CAL_ecu_generic_VIN[bVar1]) {
      DAT_003fdc90 = DAT_003fdc90 & 0xfffb;
      bVar1 = 0x11;
    }
  }
  if ((CAL_obd_P0630 & 7) != 0) {
    if ((DAT_003fdc90 & 4) == 0) {
      obd_clr_dtc(&CAL_obd_P0630,&LEA_obd_P0630_flags);
    }
    else {
      DAT_003fdc90 = DAT_003fdc90 & 0xfffb;
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
                    (16,16,engine_speed_2,(uint16_t)load_1_smooth,CAL_obd_misfire_threshold,
                     CAL_obd_misfire_threshold_X_engine_speed,
                     CAL_obd_misfire_threshold_Y_engine_load);
  misfire_threshold = uVar3 ^ 0x8000;
  DAT_003f92a7 = lookup_3D_uint8_interpolated_noaxis
                           (33,5,3,(ushort)engine_speed_3,(ushort)load_2,&DAT_003fcad0);
  bVar4 = lookup_2D_uint8_interpolated_noaxis(3,(ushort)engine_speed_3,(uint8_t *)&PTR_DAT_003fd530)
  ;
  DAT_003f92a9 = (char)((int)(((uint)*(byte *)((int)&PTR_DAT_003fd53b + iVar1) -
                              (uint)(byte)(&DAT_003fdcb6)[iVar1]) * (int)(short)(ushort)bVar4) /
                       (int)(uint)*(byte *)((int)&PTR_DAT_003fd53b + iVar1));
  uVar5 = lookup_2D_uint8_interpolated_noaxis(3,(ushort)engine_speed_3,&DAT_003fcf12);
  misfire_cat_threshold = DAT_003f92a9 + uVar5;
  DAT_003f92a8 = lookup_3D_uint8_interpolated
                           (8,8,(ushort)engine_speed_3,(ushort)load_2,&DAT_003fd196,&DAT_003fd186,
                            &DAT_003fd18e);
  DAT_003fdcae = DAT_003fc5e4;
  DAT_003f92b2 = lookup_2D_uint8_interpolated_noaxis(3,(ushort)engine_speed_3,&DAT_003fcf1c);
  if ((((LEA_obd_P0101_flags & 4) == 0) && ((LEA_obd_P0102_flags & 4) == 0)) &&
     ((LEA_obd_P0103_flags & 4) == 0)) {
    misfire_flags = misfire_flags & 0xfff7;
  }
  else {
    misfire_flags = misfire_flags | 8;
  }
  uVar2 = abs(DAT_003f9854);
  if (((int)DAT_003fc560 < (int)uVar2) ||
     (uVar2 = abs(dt_engine_speed), (int)DAT_003fc55e < (int)uVar2)) {
    misfire_flags = misfire_flags | 0x10;
    DAT_003f92b6 = DAT_003fc558;
  }
  else if (DAT_003f92b6 == 0) {
    misfire_flags = misfire_flags & 0xffef;
  }
  if ((((((misfire_flags & 0x20) != 0) || (coolant_smooth < DAT_003fc53c)) ||
       ((DAT_003fc53d < coolant_smooth ||
        ((((engine_speed_3 < DAT_003fc542 || (DAT_003fc543 < engine_speed_3)) ||
          (revlimit_misfire_eval < engine_speed_2)) ||
         ((fuel_level_smooth < DAT_003fc553 || ((tc_flags & 2) != 0)))))))) ||
      ((load_2 < DAT_003f92b2 && ((misfire_flags & 8) == 0)))) || ((dfso_flags & 1) != 0)) {
    DAT_003f92ac = DAT_003fc55a;
  }
  if ((DAT_003f92ac == 0) && (DAT_003f92b6 == 0)) {
    misfire_flags = misfire_flags | 2;
  }
  else {
    misfire_flags = misfire_flags & 0xfffd;
  }
  DAT_003f92b4 = 0;
  for (bVar4 = 0; bVar4 < 4; bVar4 = bVar4 + 1) {
    if (misfire_cat_timer[bVar4] == 0) {
      DAT_003f92b4 = DAT_003f92b4 + 0xfa;
    }
  }
  if (engine_is_running == false) {
    DAT_003f92a5 = '\x01';
    DAT_003f92a6 = '\x01';
    misfire_flags = misfire_flags & 0xcfff;
  }
  uVar3 = misfire_flags;
  if ((misfire_flags & 0x4000) != 0) {
    uVar3 = misfire_flags & 0xbfff;
    if (DAT_003f92b4 < misfire_cat_total_count) {
      misfire_cat_max_result = misfire_cat_total_count;
    }
    else {
      misfire_cat_max_result = DAT_003f92b4;
    }
    if ((CAL_obd_P1302 & 7) != 0) {
      if (((uint)DAT_003f92a8 << 1 < (uint)misfire_cat_max_result) &&
         (((misfire_flags & 2) != 0 || ((misfire_flags & 0x20) != 0)))) {
        if (DAT_003f92a6 == '\0') {
          misfire_flags = uVar3;
          obd_set_dtc(&CAL_obd_P1302,&LEA_obd_P1302_flags,&LEA_obd_P1302_engine_start_count,
                      &LEA_obd_P1302_warm_up_cycle_count,0x516);
          uVar3 = misfire_flags;
          if ((DAT_003f92aa == 0) && (DAT_003f9913 != '\0')) {
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
          DAT_003f92a6 = DAT_003f92a6 + -1;
          if (DAT_003f92a6 == '\0') {
            misfire_flags = uVar3;
            obd_set_dtc(&CAL_obd_P1302,&LEA_obd_P1302_flags,&LEA_obd_P1302_engine_start_count,
                        &LEA_obd_P1302_warm_up_cycle_count,0x516);
            uVar3 = misfire_flags;
          }
        }
      }
      else {
        DAT_003f92aa = DAT_003fc55c;
        misfire_flags = uVar3;
        obd_clr_dtc(&CAL_obd_P1302,&LEA_obd_P1302_flags);
        uVar3 = misfire_flags;
        if ((misfire_flags & 0x2000) == 0) {
          DAT_003f92a6 = DAT_003fca1f;
          uVar3 = misfire_flags | 0x2000;
        }
      }
    }
  }
  misfire_flags = uVar3;
  if ((misfire_flags & 0x8000) != 0) {
    uVar6 = misfire_flags & 0x7fff;
    DAT_002f8366 = 1;
    if ((misfire_flags & 0x20) == 0) {
      if (DAT_003f92b4 < misfire_total_count) {
        misfire_max_result = misfire_total_count;
      }
      else {
        misfire_max_result = DAT_003f92b4;
      }
    }
    else {
      misfire_max_result = misfire_cat_max_result;
    }
    misfire_flags = uVar6;
    if (DAT_002f8286 < misfire_max_result) {
      DAT_002f8286 = misfire_max_result;
      sort10(&DAT_002f8286);
    }
    if ((CAL_obd_P1301 & 7) != 0) {
      if (DAT_003fdcae < misfire_max_result) {
        if ((DAT_003f92a5 != '\0') && (DAT_003f92a5 = DAT_003f92a5 + -1, DAT_003f92a5 == '\0')) {
          obd_set_dtc(&CAL_obd_P1301,&LEA_obd_P1301_flags,&LEA_obd_P1301_engine_start_count,
                      &LEA_obd_P1301_warm_up_cycle_count,0x515);
        }
      }
      else {
        obd_clr_dtc(&CAL_obd_P1301,&LEA_obd_P1301_flags);
        if ((misfire_flags & 0x1000) == 0) {
          DAT_003f92a5 = DAT_003fca1e;
          misfire_flags = misfire_flags | 0x1000;
        }
      }
    }
  }
  DAT_003f92ae = 0;
  if (((CAL_obd_P0301 & 7) != 0) && ((LEA_obd_P0340_flags & 4) == 0)) {
    if (((misfire_count_prev[0] < 6) ||
        (((LEA_obd_P1301_flags & 1) == 0 || ((DAT_003f92b8 & 1) != 0)))) &&
       (((misfire_cat_count_prev[0] < 3 && (misfire_cat_timer[0] != 0)) ||
        (((LEA_obd_P1302_flags & 1) == 0 || ((DAT_003f92b9 & 1) != 0)))))) {
      obd_clr_dtc(&CAL_obd_P0301,&LEA_obd_P0301_flags);
    }
    else {
      obd_set_dtc(&CAL_obd_P0301,&LEA_obd_P0301_flags,&LEA_obd_P0301_engine_start_count,
                  &LEA_obd_P0301_warm_up_cycle_count,0x12d);
      DAT_003f92ae = DAT_003f92ae + 1;
    }
  }
  if (((CAL_obd_P0302 & 7) != 0) && ((LEA_obd_P0340_flags & 4) == 0)) {
    if (((misfire_count_prev[3] < 6) ||
        (((LEA_obd_P1301_flags & 1) == 0 || ((DAT_003f92b8 & 1) != 0)))) &&
       (((misfire_cat_count_prev[3] < 3 && (misfire_cat_timer[3] != 0)) ||
        (((LEA_obd_P1302_flags & 1) == 0 || ((DAT_003f92b9 & 1) != 0)))))) {
      obd_clr_dtc(&CAL_obd_P0302,&LEA_obd_P0302_flags);
    }
    else {
      obd_set_dtc(&CAL_obd_P0302,&LEA_obd_P0302_flags,&LEA_obd_P0302_engine_start_count,
                  &LEA_obd_P0302_warm_up_cycle_count,0x12e);
      DAT_003f92ae = DAT_003f92ae + 1;
    }
  }
  if (((CAL_obd_P0303 & 7) != 0) && ((LEA_obd_P0340_flags & 4) == 0)) {
    if (((misfire_count_prev[1] < 6) ||
        (((LEA_obd_P1301_flags & 1) == 0 || ((DAT_003f92b8 & 1) != 0)))) &&
       (((misfire_cat_count_prev[1] < 3 && (misfire_cat_timer[1] != 0)) ||
        (((LEA_obd_P1302_flags & 1) == 0 || ((DAT_003f92b9 & 1) != 0)))))) {
      obd_clr_dtc(&CAL_obd_P0303,&LEA_obd_P0303_flags);
    }
    else {
      obd_set_dtc(&CAL_obd_P0303,&LEA_obd_P0303_flags,&LEA_obd_P0303_engine_start_count,
                  &LEA_obd_P0303_warm_up_cycle_count,0x12f);
      DAT_003f92ae = DAT_003f92ae + 1;
    }
  }
  if (((CAL_obd_P0304 & 7) != 0) && ((LEA_obd_P0340_flags & 4) == 0)) {
    if (((misfire_count_prev[2] < 6) ||
        (((LEA_obd_P1301_flags & 1) == 0 || ((DAT_003f92b8 & 1) != 0)))) &&
       (((misfire_cat_count_prev[2] < 3 && (misfire_cat_timer[2] != 0)) ||
        (((LEA_obd_P1302_flags & 1) == 0 || ((DAT_003f92b9 & 1) != 0)))))) {
      obd_clr_dtc(&CAL_obd_P0304,&LEA_obd_P0304_flags);
    }
    else {
      obd_set_dtc(&CAL_obd_P0304,&LEA_obd_P0304_flags,&LEA_obd_P0304_engine_start_count,
                  &LEA_obd_P0304_warm_up_cycle_count,0x130);
      DAT_003f92ae = DAT_003f92ae + 1;
    }
  }
  if ((CAL_obd_P0768 & 7) != 0) {
    if ((DAT_003f92ae < 2) &&
       (((LEA_obd_P0340_flags & 4) == 0 ||
        (((LEA_obd_P1301_flags & 1) == 0 && ((LEA_obd_P1302_flags & 1) == 0)))))) {
      obd_clr_dtc(&CAL_obd_P0768,&LEA_obd_P0300_flags);
    }
    else {
      obd_set_dtc(&CAL_obd_P0768,&LEA_obd_P0300_flags,&LEA_obd_P0300_engine_start_count,
                  &LEA_obd_P0300_warm_up_cycle_count,300);
    }
  }
  DAT_003f92b8 = LEA_obd_P1301_flags;
  DAT_003f92b9 = LEA_obd_P1302_flags;
  return;
}



// Initializes misfire monitor state

void obd_init_misfire(void)

{
  DAT_003f92a0 = DAT_003fca3c;
  DAT_003f92a1 = DAT_003fca34;
  DAT_003f92a2 = DAT_003fca35;
  DAT_003f92a3 = DAT_003fca36;
  DAT_003f92a4 = DAT_003fca37;
  DAT_003f92a5 = 1;
  DAT_003f92a6 = 1;
  obd_init_dtc(&CAL_obd_P0768,&LEA_obd_P0300_flags,300);
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
  obd_cyc_dtc(&CAL_obd_P0768,&LEA_obd_P0300_flags,&LEA_obd_P0300_engine_start_count,
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
  
  if (DAT_003f92ac != 0) {
    DAT_003f92ac = DAT_003f92ac + -1;
  }
  if (DAT_003f92b6 != 0) {
    DAT_003f92b6 = DAT_003f92b6 + -1;
  }
  if (DAT_003f92aa != 0) {
    DAT_003f92aa = DAT_003f92aa + -1;
  }
  uVar1 = (0x100 - (uint)DAT_003f8338) * DAT_003f833c;
  DAT_003f833c = ((int)uVar1 >> 8) + (uint)((int)uVar1 < 0 && (uVar1 & 0xff) != 0) +
                 (uint)DAT_003f8338 * (uint)load_2;
  DAT_003f92b0 = (short)(DAT_003f833c >> 8) +
                 (ushort)((int)DAT_003f833c < 0 && (DAT_003f833c & 0xff) != 0);
  return;
}



// O2 sensor activity monitor (P0134/P0140)

void obd_check_o2_activity(void)

{
  if (engine_runtime < CAL_stft_o2_test_runtime_min) {
    o2_flags = o2_flags & 0xff3f;
    closedloop_flags = closedloop_flags & 0xfff5;
    DAT_003f92c2 = 0;
    DAT_003f92c4 = 0;
  }
  else {
    if (((idle_flags & 8) != 0) ||
       (((fuel_system_status & 2) == 0 && ((closedloop_flags & 1) != 0)))) {
      o2_flags = o2_flags & 0xff3f;
      DAT_003f92c2 = 0;
      DAT_003f92c4 = 0;
    }
    if (DAT_003f92c2 < DAT_003fc5d0) {
      if (DAT_003fc5dc < engine_runtime) {
        if (sensor_adc_pre_o2 < DAT_003fc5da) {
          o2_flags = o2_flags | 0x80;
        }
        if (DAT_003fc5d8 < sensor_adc_pre_o2) {
          o2_flags = o2_flags | 0x40;
        }
        if (((o2_flags & 0x80) != 0) && ((o2_flags & 0x40) != 0)) {
          closedloop_flags = closedloop_flags | 2;
        }
      }
    }
    else if ((CAL_obd_P0134 & 7) != 0) {
      if ((closedloop_flags & 2) == 0) {
        if (DAT_003fdcee != 0) {
          DAT_003fdcee = DAT_003fdcee - 1;
          DAT_003f92c2 = 0;
          o2_flags = o2_flags & 0xff3f;
        }
        if (DAT_003fdcee == 0) {
          obd_set_dtc(&CAL_obd_P0134,&LEA_obd_P0134_flags,&LEA_obd_P0134_engine_start_count,
                      &LEA_obd_P0134_warm_up_cycle_count,0x86);
        }
      }
      else {
        obd_clr_dtc(&CAL_obd_P0134,&LEA_obd_P0134_flags);
        if (DAT_003fdcee < DAT_003fca21) {
          DAT_003fdcee = DAT_003fdcee + 1;
        }
      }
    }
    if (DAT_003f92c4 < DAT_003fc5d2) {
      if ((closedloop_flags & 4) != 0) {
        closedloop_flags = closedloop_flags | 8;
      }
    }
    else if ((CAL_obd_P0140 & 7) != 0) {
      if ((closedloop_flags & 8) == 0) {
        if (DAT_003f92c0 != 0) {
          DAT_003f92c0 = DAT_003f92c0 - 1;
        }
        if (DAT_003f92c0 == 0) {
          obd_set_dtc(&CAL_obd_P0140,&LEA_obd_P0140_flags,&LEA_obd_P0140_engine_start_count,
                      &LEA_obd_P0140_warm_up_cycle_count,0x8c);
        }
      }
      else {
        obd_clr_dtc(&CAL_obd_P0140,&LEA_obd_P0140_flags);
        if (DAT_003f92c0 < DAT_003fca26) {
          DAT_003f92c0 = DAT_003f92c0 + 1;
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
  
  if (DAT_003fdd0e != -1) {
    DAT_003fdd0e = (short)(engine_runtime / 200);
  }
  if ((((((((car_speed_smooth < DAT_003fc532) || (DAT_003fc533 <= car_speed_smooth)) ||
          ((int)load_1_smooth <= (int)(uint)DAT_003fc57e)) ||
         (((int)(uint)DAT_003fc580 <= (int)load_1_smooth || (engine_speed_3 <= DAT_003fc582)))) ||
        ((DAT_003fc583 <= engine_speed_3 ||
         ((engine_runtime <= DAT_003fc5d4 || (coolant_smooth <= DAT_003fc575)))))) ||
       ((closedloop_flags & 1) == 0)) ||
      (((((LEA_obd_P0116_flags & 4) != 0 || ((LEA_obd_P0117_flags & 4) != 0)) ||
        ((LEA_obd_P0118_flags & 4) != 0)) ||
       ((((LEA_obd_P0131_flags & 4) != 0 || ((LEA_obd_P0132_flags & 4) != 0)) ||
        (((LEA_obd_P0134_flags & 4) != 0 ||
         (((LEA_obd_P0135_flags & 4) != 0 || ((LEA_obd_P0101_flags & 4) != 0)))))))))) ||
     ((((LEA_obd_P0102_flags & 4) != 0 ||
       ((((LEA_obd_P0103_flags & 4) != 0 || ((LEA_obd_P0335_flags & 4) != 0)) ||
        ((LEA_obd_P0500_flags & 4) != 0)))) ||
      ((((fuel_system_status & 2) == 0 || (DAT_003f92c6 != '\0')) ||
       (((int)(uint)DAT_003f9a46 <= DAT_003f92c8 ||
        (((closedloop_flags & 0x400) == 0 && (DAT_003fc53a == '\0')))))))))) {
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
      if ((DAT_003f92cc != 0) && (DAT_002f82ae < DAT_003f92cc)) {
        DAT_002f82ae = DAT_003f92cc;
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
          if (DAT_003fdcc8 != 0) {
            DAT_003fdcc8 = DAT_003fdcc8 - 1;
            cat_diag_pre_o2_timer = DAT_003fc596;
            o2_flags = o2_flags & 0xfeff;
            o2_lean2rich_total_time = 0;
            o2_rich2lean_total_time = 0;
            o2_lean2rich_switch_count = 0;
            o2_rich2lean_switch_count = 0;
          }
          uVar1 = o2_flags;
          if (DAT_003fdcc8 == 0) {
            obd_set_dtc(&CAL_obd_P0133,&LEA_obd_P0133_flags,&LEA_obd_P0133_engine_start_count,
                        &LEA_obd_P0133_warm_up_cycle_count,0x85);
            uVar1 = o2_flags;
          }
        }
        else {
          obd_clr_dtc(&CAL_obd_P0133,&LEA_obd_P0133_flags);
          uVar1 = o2_flags;
          if (DAT_003fdcc8 < CAL_obd_P0133_consecutive) {
            DAT_003fdcc8 = DAT_003fdcc8 + 1;
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
    cat_diag_pre_o2_timer = DAT_003fc596;
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
         ((LEA_obd_P0204_flags & 4) != 0)))))))) || (engine_runtime <= DAT_003fc5d4)) {
    DAT_003fdcfa = DAT_003fdcfa & 0xfffc;
    DAT_003fdd0c = DAT_003fc600;
    DAT_003fdd0a = DAT_003fc5e2;
    uVar1 = DAT_003fdcfa;
    if ((closedloop_flags & 4) != 0) {
      if (DAT_003fc5de < sensor_adc_post_o2) {
        DAT_003fdcfa = DAT_003fdcfa | 0x80;
      }
      uVar1 = DAT_003fdcfa;
      if (sensor_adc_post_o2 < DAT_003fc5e0) {
        uVar1 = DAT_003fdcfa | 0x40;
      }
    }
  }
  else {
    uVar1 = DAT_003fdcfa | 1;
    if ((DAT_003fdcfa & 0x3c) == 0) {
      if ((((DAT_003fdcfa & 0x100) != 0) && ((DAT_003fdcfa & 0x200) != 0)) &&
         (((DAT_003fdcfa & 0x40) != 0 && ((DAT_003fdcfa & 0x80) != 0)))) {
        DAT_003fdcfa = uVar1;
        obd_clr_dtc(&CAL_obd_P0139,&LEA_obd_P0139_flags);
        if (DAT_003fdcef < DAT_003fc9e6) {
          DAT_003fdcef = DAT_003fdcef + 1;
        }
        DAT_003fdd0c = DAT_003fc600;
        DAT_003fdd0a = DAT_003fc5e2;
        uVar1 = DAT_003fdcfa;
      }
    }
    else if (DAT_003fdcef != 0) {
      DAT_003fdcef = DAT_003fdcef - 1;
      if (DAT_003fdcef < DAT_002f82c2) {
        DAT_002f82c2 = DAT_003fdcef;
      }
      if (DAT_003fdcef == 0) {
        DAT_003fdcfa = uVar1;
        obd_set_dtc(&CAL_obd_P0139,&LEA_obd_P0139_flags,&LEA_obd_P0139_engine_start_count,
                    &LEA_obd_P0139_warm_up_cycle_count,0x8b);
        uVar1 = DAT_003fdcfa;
      }
    }
  }
  DAT_003fdcfa = uVar1;
  if (((LEA_obd_P0139_flags & 8) != 0) && ((CAL_obd_P0139 & 8) != 0)) {
    LEA_obd_P0139_flags = LEA_obd_P0139_flags & 0xf7;
    DAT_003fdcfa = DAT_003fdcfa & 0xfc3f;
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
      DAT_003fe648 = DAT_003fe648 | 0x10;
      if ((LEA_obd_P0133_flags & 8) == 0) {
        if ((o2_rich2lean_switch_count < DAT_003fc534) || (o2_lean2rich_switch_count < DAT_003fc534)
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
        if (DAT_003fc5d8 < sensor_adc_pre_o2) {
          o2_flags = o2_flags & 0xffcb | 8;
        }
        else if (sensor_adc_pre_o2 < DAT_003fc5da) {
          o2_flags = o2_flags & 0xffd3 | 0x10;
        }
        else if ((DAT_003fc5da < sensor_adc_pre_o2) && (sensor_adc_pre_o2 < DAT_003fc5d8)) {
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
        if ((DAT_003fc534 <= o2_rich2lean_switch_count) &&
           (DAT_003fc534 <= o2_lean2rich_switch_count)) {
          o2_flags = o2_flags & 0xffc3 | 2;
        }
      }
    }
  }
  if (load_use_alphaN == 0) {
    if (DAT_003f92c6 != '\0') {
      DAT_003f92c6 = DAT_003f92c6 + -1;
    }
  }
  else {
    DAT_003f92c6 = DAT_003f9a47;
  }
  if (unaff_r30 == '\0') {
    for (bVar1 = 9; bVar1 != 0; bVar1 = bVar1 - 1) {
      (&DAT_003f8340)[bVar1] = (&DAT_003f8340)[bVar1 - 1];
    }
    DAT_003f8340 = load_1_smooth;
  }
  if (DAT_003f8364 < (int)DAT_003f8340) {
    DAT_003f92c8 = DAT_003f8340 - DAT_003f8364;
  }
  else {
    DAT_003f92c8 = DAT_003f8364 - DAT_003f8340;
  }
  if (DAT_003fc5dc < engine_runtime) {
    if (DAT_003f92c2 < DAT_003fc5d0) {
      DAT_003f92c2 = DAT_003f92c2 + 1;
    }
    if (DAT_003f92c4 < DAT_003fc5d2) {
      DAT_003f92c4 = DAT_003f92c4 + 1;
    }
  }
  if ((DAT_003fdcfa & 1) == 0) {
    DAT_003fdcfa = DAT_003fdcfa & 0xfffd;
    return;
  }
  if ((DAT_003fdcfa & 0x80) == 0) {
    if (DAT_003fc5d8 < sensor_adc_pre_o2) {
      if (DAT_003fdd0c == 0) {
        DAT_003fdcfa = DAT_003fdcfa | 0x20;
        DAT_003fdd0c = DAT_003fc600;
      }
      else {
        DAT_003fdd0c = DAT_003fdd0c + -1;
        if (DAT_003fc5de < sensor_adc_post_o2) {
          DAT_003fdcfa = DAT_003fdcfa | 0x80;
        }
      }
    }
    else {
      DAT_003fdd0c = DAT_003fc600;
    }
  }
  if ((DAT_003fdcfa & 0x40) == 0) {
    if (sensor_adc_pre_o2 < DAT_003fc5da) {
      if (DAT_003fdd0a == 0) {
        DAT_003fdcfa = DAT_003fdcfa | 0x10;
        DAT_003fdd0a = DAT_003fc5e2;
      }
      else {
        DAT_003fdd0a = DAT_003fdd0a + -1;
        if (sensor_adc_post_o2 < DAT_003fc5e0) {
          DAT_003fdcfa = DAT_003fdcfa | 0x40;
        }
      }
    }
    else {
      DAT_003fdd0a = DAT_003fc5e2;
    }
  }
  if ((DAT_003fdcfa & 0x200) == 0) {
    if (post_o2_state == 2) {
      if ((sensor_adc_post_o2 < DAT_003fc5e0) && ((idle_flags & 8) != 0)) {
        DAT_003fdcfa = DAT_003fdcfa | 2;
        if ((closedloop_flags & 0x20) != 0) {
          post_o2_state = 3;
        }
      }
      else {
        DAT_003fdcfa = DAT_003fdcfa & 0xfffd;
        post_o2_state = 0;
        DAT_003fdcfc = 0;
      }
    }
    else {
      if (post_o2_state < 2) {
        if (post_o2_state == 0) {
          if ((((dfso_flags & 1) != 0) && (sensor_adc_post_o2 < DAT_003fc5e0)) &&
             (car_speed_smooth != 0)) {
            post_o2_state = 1;
          }
          goto LAB_000586a0;
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
          goto LAB_000586a0;
        }
      }
      else if (post_o2_state < 4) {
        if ((((closedloop_flags & 0x20) == 0) || ((idle_flags & 8) == 0)) ||
           (sensor_adc_pre_o2 <= DAT_003fc5d8)) {
          DAT_003fdcfa = DAT_003fdcfa & 0xfffd;
          post_o2_state = 0;
          DAT_003fdcfc = 0;
        }
        else {
          if ((DAT_003fc5e0 < sensor_adc_post_o2) && (sensor_adc_post_o2 < DAT_003fc5de)) {
            DAT_003fdcfc = DAT_003fdcfc + 1;
            if (DAT_003fc56e <= DAT_003fdcfc) {
              DAT_003fdd00 = DAT_003fdd00 + DAT_003fc56e;
              DAT_003fdcfa = DAT_003fdcfa & 0xfffd;
              DAT_003fdcfc = 0;
              post_o2_state = 0;
              DAT_003fdd04 = DAT_003fdd04 + 1;
            }
            if ((uint)DAT_003fc56e * (uint)DAT_003fc56b <= (uint)DAT_003fdd00) {
              DAT_003fdcfa = DAT_003fdcfa | 8;
              if (DAT_002f821a < DAT_003fdd00) {
                DAT_002f821a = DAT_003fdd00;
                sort10(&DAT_002f821a);
              }
              DAT_003fdcfa = DAT_003fdcfa & 0xfffd;
              post_o2_state = 0;
              DAT_003fdcfc = 0;
              DAT_003fdd04 = 0;
              DAT_003fdd00 = 0;
            }
          }
          else if (DAT_003fc5de < sensor_adc_post_o2) {
            DAT_003fdd00 = DAT_003fdd00 + DAT_003fdcfc;
            DAT_003fdd04 = DAT_003fdd04 + 1;
            DAT_003fdcfa = DAT_003fdcfa & 0xfffd;
            post_o2_state = 0;
            DAT_003fdcfc = 0;
          }
          else if (sensor_adc_post_o2 < DAT_003fc5e0) {
            DAT_003fdcfc = 0;
          }
          if (((DAT_003fdd00 < DAT_003fc56e) && (DAT_003fdd04 == 1)) ||
             ((DAT_003fc56b <= DAT_003fdd04 && ((DAT_003fdcfa & 8) == 0)))) {
            DAT_003fdcfa = DAT_003fdcfa | 0x200;
            if (DAT_002f821a < DAT_003fdd00) {
              DAT_002f821a = DAT_003fdd00;
              sort10(&DAT_002f821a);
            }
            post_o2_state = 0;
            DAT_003fdcfc = 0;
            DAT_003fdd04 = 0;
            DAT_003fdd00 = 0;
          }
        }
        goto LAB_000586a0;
      }
      DAT_003fdcfa = DAT_003fdcfa & 0xfffd;
      post_o2_state = 0;
      DAT_003fdcfc = 0;
    }
  }
LAB_000586a0:
  if ((DAT_003fdcfa & 0x100) == 0) {
    if (DAT_003fdd11 == '\x01') {
      if ((dfso_flags & 1) == 0) {
        DAT_003fdcfe = 0;
        DAT_003fdd11 = '\0';
      }
      else if ((DAT_003fc5e0 < sensor_adc_post_o2) && (sensor_adc_post_o2 < DAT_003fc5de)) {
        DAT_003fdcfe = DAT_003fdcfe + 1;
        if (DAT_003fc570 <= DAT_003fdcfe) {
          DAT_003fdd02 = DAT_003fdd02 + DAT_003fc570;
          DAT_003fdcfe = 0;
          DAT_003fdd11 = '\0';
          DAT_003fdd05 = DAT_003fdd05 + 1;
        }
        if ((uint)DAT_003fc570 * (uint)DAT_003fc56b <= (uint)DAT_003fdd02) {
          DAT_003fdcfa = DAT_003fdcfa | 4;
          if (DAT_002f8206 < DAT_003fdd02) {
            DAT_002f8206 = DAT_003fdd02;
            sort10(&DAT_002f8206);
          }
          DAT_003fdd11 = '\0';
          DAT_003fdcfe = 0;
          DAT_003fdd05 = 0;
          DAT_003fdd02 = 0;
        }
      }
      else if (DAT_003fc5de < sensor_adc_post_o2) {
        DAT_003fdcfe = 0;
      }
      else if (sensor_adc_post_o2 < DAT_003fc5e0) {
        DAT_003fdd02 = DAT_003fdd02 + DAT_003fdcfe;
        DAT_003fdd05 = DAT_003fdd05 + 1;
        DAT_003fdd11 = '\0';
        DAT_003fdcfe = 0;
      }
      if (((DAT_003fdd02 < DAT_003fc570) && (DAT_003fdd05 == 1)) ||
         ((DAT_003fc56b <= DAT_003fdd05 && ((DAT_003fdcfa & 4) == 0)))) {
        DAT_003fdcfa = DAT_003fdcfa | 0x100;
        if (DAT_002f8206 < DAT_003fdd02) {
          DAT_002f8206 = DAT_003fdd02;
          sort10(&DAT_002f8206);
        }
        DAT_003fdd11 = '\0';
        DAT_003fdcfe = 0;
        DAT_003fdd05 = 0;
        DAT_003fdd02 = 0;
      }
    }
    else if ((DAT_003fdd11 != '\0') || (false)) {
      DAT_003fdcfe = 0;
      DAT_003fdd11 = '\0';
    }
    else if ((DAT_003fc5de < sensor_adc_post_o2) && ((dfso_flags & 1) != 0)) {
      DAT_003fdd11 = '\x01';
    }
  }
  return;
}



// Initializes O2 response DTCs (P0133/P0134/P0139/P0140)

void obd_init_o2_response(void)

{
  cat_diag_pre_o2_timer = DAT_003fc596;
  DAT_003fdcc8 = CAL_obd_P0133_consecutive;
  DAT_003fdcee = DAT_003fca21;
  DAT_003fdcef = DAT_003fc9e6;
  DAT_003f92c0 = DAT_003fca26;
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
  
  DAT_003fdd44 = (ushort)DAT_003fc4e5;
  if (((((((CAL_obd_P0101 & 7) != 0) && (engine_is_running)) && (DAT_003fe4cc != '\0')) &&
       ((DAT_003fe4dc != '\0' && (DAT_003fe4dd != '\0')))) && (DAT_003fe4de != '\0')) &&
     (DAT_003fc57b <= engine_speed_3)) {
    if (((DAT_003fc4eb < tps) && ((int)load_1_smooth < (int)(uint)DAT_003fc4ee)) ||
       ((tps < DAT_003fc4ec && ((int)(uint)DAT_003fc4f0 < (int)load_1_smooth)))) {
      DAT_003f92d2 = DAT_003f92d2 + 1;
      if ((short)DAT_003fdd44 <= DAT_003f92d2) {
        if (DAT_003f92d0 != 0) {
          DAT_003f92d0 = DAT_003f92d0 - 1;
        }
        if (DAT_003f92d0 == 0) {
          obd_set_dtc(&CAL_obd_P0101,&LEA_obd_P0101_flags,&LEA_obd_P0101_engine_start_count,
                      &LEA_obd_P0101_warm_up_cycle_count,0x65);
        }
        else {
          DAT_003f92d2 = 0;
        }
      }
    }
    else {
      DAT_003f92d2 = 0;
      obd_clr_dtc(&CAL_obd_P0101,&LEA_obd_P0101_flags);
      if (DAT_003f92d0 < DAT_003fc9e7) {
        DAT_003f92d0 = DAT_003f92d0 + 1;
      }
    }
  }
  if (((CAL_obd_P0102 & 7) != 0) && (engine_is_running != false)) {
    if (sensor_adc_maf1 < CAL_obd_P0102_threshold) {
      DAT_003f92d6 = DAT_003f92d6 + 1;
      if ((short)DAT_003fdd44 <= DAT_003f92d6) {
        DAT_003f92d6 = 0;
        if (DAT_003f92d4 == 0) {
          obd_set_dtc(&CAL_obd_P0102,&LEA_obd_P0102_flags,&LEA_obd_P0102_engine_start_count,
                      &LEA_obd_P0102_warm_up_cycle_count,0x66);
        }
        else {
          DAT_003f92d4 = DAT_003f92d4 - 1;
        }
      }
    }
    else {
      DAT_003f92d6 = 0;
      obd_clr_dtc(&CAL_obd_P0102,&LEA_obd_P0102_flags);
      if (DAT_003f92d4 < DAT_003fc9e4) {
        DAT_003f92d4 = DAT_003f92d4 + 1;
      }
    }
  }
  if (((CAL_obd_P0103 & 7) != 0) && (engine_is_running != false)) {
    if (CAL_obd_P0103_threshold < sensor_adc_maf1) {
      DAT_003f92da = DAT_003f92da + 1;
      if ((short)DAT_003fdd44 <= DAT_003f92da) {
        DAT_003f92da = 0;
        if (DAT_003f92d8 == 0) {
          obd_set_dtc(&CAL_obd_P0103,&LEA_obd_P0103_flags,&LEA_obd_P0103_engine_start_count,
                      &LEA_obd_P0103_warm_up_cycle_count,0x67);
        }
        else {
          DAT_003f92d8 = DAT_003f92d8 - 1;
        }
      }
    }
    else {
      DAT_003f92da = 0;
      obd_clr_dtc(&CAL_obd_P0103,&LEA_obd_P0103_flags);
      if (DAT_003f92d8 < DAT_003fc9e5) {
        DAT_003f92d8 = DAT_003f92d8 + 1;
      }
    }
  }
  if (((((((CAL_obd_P0106 & 7) != 0) && (DAT_003fc5e5 < engine_speed_3)) &&
        (engine_speed_3 < DAT_003fc5e6)) &&
       (((DAT_003fc5e7 < tps && (DAT_003f92d0 != 0)) &&
        ((DAT_003f92d4 != 0 && ((DAT_003f92d8 != 0 && (DAT_003fe4cc != '\0')))))))) &&
      (DAT_003fe4dc != '\0')) &&
     (((DAT_003fe4dd != '\0' && (DAT_003fe4de != '\0')) && (DAT_003fe4e1 != '\0')))) {
    iVar2 = (int)(load_1_smooth * DAT_003fc5e8) / 0x21c +
            ((int)(load_1_smooth * DAT_003fc5e8) >> 0x1f);
    DAT_003fdd48 = (short)iVar2 - (short)(iVar2 >> 0x1f);
    DAT_003f932e = atmo_pressure - DAT_003fdd48;
    if ((DAT_003fc5c8 < DAT_003f932e) || ((int)DAT_003f932e < -(int)DAT_003fc5ca)) {
      DAT_003f92de = DAT_003f92de + 1;
      if ((short)DAT_003fdd44 <= DAT_003f92de) {
        if (DAT_003f92dc != 0) {
          DAT_003f92dc = DAT_003f92dc - 1;
        }
        if (DAT_003f92dc == 0) {
          obd_set_dtc(&CAL_obd_P0106,&LEA_obd_P0106_flags,&LEA_obd_P0106_engine_start_count,
                      &LEA_obd_P0106_warm_up_cycle_count,0x6a);
        }
        else {
          DAT_003f92de = 0;
        }
      }
    }
    else {
      DAT_003f92de = 0;
      obd_clr_dtc(&CAL_obd_P0106,&LEA_obd_P0106_flags);
      if (DAT_003f92dc < DAT_003fc9d1) {
        DAT_003f92dc = DAT_003f92dc + 1;
      }
    }
  }
  if (((CAL_obd_P0107 & 7) != 0) && (engine_is_running != false)) {
    if (sensor_adc_baro < CAL_obd_P0107_threshold) {
      DAT_003f92e2 = DAT_003f92e2 + 1;
      if ((short)DAT_003fdd44 <= DAT_003f92e2) {
        DAT_003f92e2 = 0;
        if (DAT_003f92e0 == 0) {
          obd_set_dtc(&CAL_obd_P0107,&LEA_obd_P0107_flags,&LEA_obd_P0107_engine_start_count,
                      &LEA_obd_P0107_warm_up_cycle_count,0x6b);
        }
        else {
          DAT_003f92e0 = DAT_003f92e0 - 1;
        }
      }
    }
    else {
      DAT_003f92e2 = 0;
      obd_clr_dtc(&CAL_obd_P0107,&LEA_obd_P0107_flags);
      if (DAT_003f92e0 < DAT_003fc9d2) {
        DAT_003f92e0 = DAT_003f92e0 + 1;
      }
    }
  }
  if (((CAL_obd_P0108 & 7) != 0) && (engine_is_running != false)) {
    if (CAL_obd_P0108_threshold < sensor_adc_baro) {
      DAT_003f92e6 = DAT_003f92e6 + 1;
      if ((short)DAT_003fdd44 <= DAT_003f92e6) {
        DAT_003f92e6 = 0;
        if (DAT_003f92e4 == 0) {
          obd_set_dtc(&CAL_obd_P0108,&LEA_obd_P0108_flags,&LEA_obd_P0108_engine_start_count,
                      &LEA_obd_P0108_warm_up_cycle_count,0x6c);
        }
        else {
          DAT_003f92e4 = DAT_003f92e4 - 1;
        }
      }
    }
    else {
      DAT_003f92e6 = 0;
      obd_clr_dtc(&CAL_obd_P0108,&LEA_obd_P0108_flags);
      if (DAT_003f92e4 < DAT_003fc9d3) {
        DAT_003f92e4 = DAT_003f92e4 + 1;
      }
    }
  }
  if (((CAL_obd_P0131 & 7) != 0) && (engine_is_running != false)) {
    if ((sensor_adc_pre_o2 < CAL_obd_P0131_threshold) && ((dfso_flags & 2) == 0)) {
      DAT_003f92fa = DAT_003f92fa + 1;
      if ((short)DAT_003fdd44 <= DAT_003f92fa) {
        DAT_003f92fa = 0;
        if (DAT_003fdd42 == 0) {
          obd_set_dtc(&CAL_obd_P0131,&LEA_obd_P0131_flags,&LEA_obd_P0131_engine_start_count,
                      &LEA_obd_P0131_warm_up_cycle_count,0x83);
        }
        else {
          DAT_003fdd42 = DAT_003fdd42 - 1;
        }
      }
    }
    else {
      DAT_003f92fa = 0;
      obd_clr_dtc(&CAL_obd_P0131,&LEA_obd_P0131_flags);
      if (DAT_003fdd42 < DAT_003fc9e0) {
        DAT_003fdd42 = DAT_003fdd42 + 1;
      }
    }
  }
  if (((CAL_obd_P0132 & 7) != 0) && (engine_is_running != false)) {
    if (CAL_obd_P0132_threshold < sensor_adc_pre_o2) {
      DAT_003f92fc = DAT_003f92fc + 1;
      if ((short)DAT_003fdd44 <= DAT_003f92fc) {
        DAT_003f92fc = 0;
        if (DAT_003fdd43 == 0) {
          obd_set_dtc(&CAL_obd_P0132,&LEA_obd_P0132_flags,&LEA_obd_P0132_engine_start_count,
                      &LEA_obd_P0132_warm_up_cycle_count,0x84);
        }
        else {
          DAT_003fdd43 = DAT_003fdd43 - 1;
        }
      }
    }
    else {
      DAT_003f92fc = 0;
      obd_clr_dtc(&CAL_obd_P0132,&LEA_obd_P0132_flags);
      if (DAT_003fdd43 < DAT_003fc9e1) {
        DAT_003fdd43 = DAT_003fdd43 + 1;
      }
    }
  }
  if (((CAL_obd_P0137 & 7) != 0) && (engine_is_running != false)) {
    if ((sensor_adc_post_o2 < CAL_obd_P0137_threshold) && ((dfso_flags & 2) == 0)) {
      DAT_003f9300 = DAT_003f9300 + 1;
      if ((short)DAT_003fdd44 <= DAT_003f9300) {
        DAT_003f9300 = 0;
        if (DAT_003f92fe == 0) {
          obd_set_dtc(&CAL_obd_P0137,&LEA_obd_P0137_flags,&LEA_obd_P0137_engine_start_count,
                      &LEA_obd_P0137_warm_up_cycle_count,0x89);
        }
        else {
          DAT_003f92fe = DAT_003f92fe - 1;
        }
      }
    }
    else {
      DAT_003f9300 = 0;
      obd_clr_dtc(&CAL_obd_P0137,&LEA_obd_P0137_flags);
      if (DAT_003f92fe < DAT_003fc9e2) {
        DAT_003f92fe = DAT_003f92fe + 1;
      }
    }
  }
  if (((CAL_obd_P0138 & 7) != 0) && (engine_is_running != false)) {
    if (CAL_obd_P0138_threshold < sensor_adc_post_o2) {
      DAT_003f930c = DAT_003f930c + 1;
      if ((short)DAT_003fdd44 <= DAT_003f930c) {
        DAT_003f930c = 0;
        if (DAT_003f930a == 0) {
          obd_set_dtc(&CAL_obd_P0138,&LEA_obd_P0138_flags,&LEA_obd_P0138_engine_start_count,
                      &LEA_obd_P0138_warm_up_cycle_count,0x8a);
        }
        else {
          DAT_003f930a = DAT_003f930a - 1;
        }
      }
    }
    else {
      DAT_003f930c = 0;
      obd_clr_dtc(&CAL_obd_P0138,&LEA_obd_P0138_flags);
      if (DAT_003f930a < DAT_003fc9e3) {
        DAT_003f930a = DAT_003f930a + 1;
      }
    }
  }
  if (((CAL_obd_P0111 & 7) != 0) && (engine_is_running != false)) {
    if (((engine_runtime < DAT_003fc5ec) &&
        ((coolant_smooth < DAT_003fc5ee && (DAT_003fc5ef < engine_air_smooth)))) ||
       (uVar1 = abs((uint)engine_air - (uint)engine_air_smooth),
       (int)(uint)DAT_003fc5ea < (int)uVar1)) {
      DAT_003f92ea = DAT_003f92ea + 1;
      if ((short)DAT_003fdd44 <= DAT_003f92ea) {
        DAT_003f92ea = 0;
        if (DAT_003f92e8 == 0) {
          obd_set_dtc(&CAL_obd_P0111,&LEA_obd_P0111_flags,&LEA_obd_P0111_engine_start_count,
                      &LEA_obd_P0111_warm_up_cycle_count,0x6f);
        }
        else {
          DAT_003f92e8 = DAT_003f92e8 - 1;
        }
      }
    }
    else {
      DAT_003f92ea = 0;
      obd_clr_dtc(&CAL_obd_P0111,&LEA_obd_P0111_flags);
      if (DAT_003f92e8 < DAT_003fc9d5) {
        DAT_003f92e8 = DAT_003f92e8 + 1;
      }
    }
  }
  if (((CAL_obd_P0112 & 7) != 0) && (engine_is_running != false)) {
    if (sensor_adc_engine_air < CAL_obd_P0112_threshold) {
      DAT_003f92ee = DAT_003f92ee + 1;
      if ((short)DAT_003fdd44 <= DAT_003f92ee) {
        DAT_003f92ee = 0;
        if (DAT_003f92ec == 0) {
          obd_set_dtc(&CAL_obd_P0112,&LEA_obd_P0112_flags,&LEA_obd_P0112_engine_start_count,
                      &LEA_obd_P0112_warm_up_cycle_count,0x70);
        }
        else {
          DAT_003f92ec = DAT_003f92ec - 1;
        }
      }
    }
    else {
      DAT_003f92ee = 0;
      obd_clr_dtc(&CAL_obd_P0112,&LEA_obd_P0112_flags);
      if (DAT_003f92ec < DAT_003fc9d6) {
        DAT_003f92ec = DAT_003f92ec + 1;
      }
    }
  }
  if (((CAL_obd_P0113 & 7) != 0) && (engine_is_running != false)) {
    if (CAL_obd_P0113_threshold < sensor_adc_engine_air) {
      DAT_003f92f2 = DAT_003f92f2 + 1;
      if ((short)DAT_003fdd44 <= DAT_003f92f2) {
        DAT_003f92f2 = 0;
        if (DAT_003f92f0 == 0) {
          obd_set_dtc(&CAL_obd_P0113,&LEA_obd_P0113_flags,&LEA_obd_P0113_engine_start_count,
                      &LEA_obd_P0113_warm_up_cycle_count,0x71);
        }
        else {
          DAT_003f92f0 = DAT_003f92f0 - 1;
        }
      }
    }
    else {
      DAT_003f92f2 = 0;
      obd_clr_dtc(&CAL_obd_P0113,&LEA_obd_P0113_flags);
      if (DAT_003f92f0 < DAT_003fc9d7) {
        DAT_003f92f0 = DAT_003f92f0 + 1;
      }
    }
  }
  if (((CAL_obd_P0116 & 7) != 0) && (engine_is_running != false)) {
    if ((((uint)CAL_obd_P0116_engine_runtime_min * 200 < engine_runtime) &&
        (coolant_smooth < CAL_obd_P0116_threshold)) ||
       (uVar1 = abs((uint)coolant - (uint)coolant_smooth), (int)(uint)DAT_003fc5eb < (int)uVar1)) {
      DAT_003f92f4 = DAT_003f92f4 + 1;
      if ((short)DAT_003fdd44 <= DAT_003f92f4) {
        DAT_003f92f4 = 0;
        if (DAT_003fdd14 == 0) {
          obd_set_dtc(&CAL_obd_P0116,&LEA_obd_P0116_flags,&LEA_obd_P0116_engine_start_count,
                      &LEA_obd_P0116_warm_up_cycle_count,0x74);
        }
        else {
          DAT_003fdd14 = DAT_003fdd14 - 1;
        }
      }
    }
    else {
      DAT_003f92f4 = 0;
      obd_clr_dtc(&CAL_obd_P0116,&LEA_obd_P0116_flags);
      if (DAT_003fdd14 < DAT_003fc9d9) {
        DAT_003fdd14 = DAT_003fdd14 + 1;
      }
    }
  }
  if (((CAL_obd_P0117 & 7) != 0) && (engine_is_running != false)) {
    if (sensor_adc_coolant < CAL_obd_P0117_threshold) {
      DAT_003f92f6 = DAT_003f92f6 + 1;
      if ((short)DAT_003fdd44 <= DAT_003f92f6) {
        DAT_003f92f6 = 0;
        if (DAT_003fdd40 == 0) {
          obd_set_dtc(&CAL_obd_P0117,&LEA_obd_P0117_flags,&LEA_obd_P0117_engine_start_count,
                      &LEA_obd_P0117_warm_up_cycle_count,0x75);
        }
        else {
          DAT_003fdd40 = DAT_003fdd40 - 1;
        }
      }
    }
    else {
      DAT_003f92f6 = 0;
      obd_clr_dtc(&CAL_obd_P0117,&LEA_obd_P0117_flags);
      if (DAT_003fdd40 < DAT_003fc9da) {
        DAT_003fdd40 = DAT_003fdd40 + 1;
      }
    }
  }
  if (((CAL_obd_P0118 & 7) != 0) && (engine_is_running != false)) {
    if (CAL_obd_P0118_threshold < sensor_adc_coolant) {
      DAT_003f92f8 = DAT_003f92f8 + 1;
      if ((short)DAT_003fdd44 <= DAT_003f92f8) {
        DAT_003f92f8 = 0;
        if (DAT_003fdd41 == 0) {
          obd_set_dtc(&CAL_obd_P0118,&LEA_obd_P0118_flags,&LEA_obd_P0118_engine_start_count,
                      &LEA_obd_P0118_warm_up_cycle_count,0x76);
        }
        else {
          DAT_003fdd41 = DAT_003fdd41 - 1;
        }
      }
    }
    else {
      DAT_003f92f8 = 0;
      obd_clr_dtc(&CAL_obd_P0118,&LEA_obd_P0118_flags);
      if (DAT_003fdd41 < DAT_003fc9db) {
        DAT_003fdd41 = DAT_003fdd41 + 1;
      }
    }
  }
  if (((CAL_obd_P0237 & 7) != 0) && (engine_is_running != false)) {
    if (sensor_adc_map < CAL_obd_P0237_threshold) {
      DAT_003f9310 = DAT_003f9310 + 1;
      if ((short)DAT_003fdd44 <= DAT_003f9310) {
        DAT_003f9310 = 0;
        if (DAT_003f930e == 0) {
          obd_set_dtc(&CAL_obd_P0237,&LEA_obd_P0237_flags,&LEA_obd_P0237_engine_start_count,
                      &LEA_obd_P0237_warm_up_cycle_count,0xed);
        }
        else {
          DAT_003f930e = DAT_003f930e - 1;
        }
      }
    }
    else {
      DAT_003f9310 = 0;
      obd_clr_dtc(&CAL_obd_P0237,&LEA_obd_P0237_flags);
      if (DAT_003f930e < DAT_003fca02) {
        DAT_003f930e = DAT_003f930e + 1;
      }
    }
  }
  if (((CAL_obd_P0238 & 7) != 0) && (engine_is_running != false)) {
    if (CAL_obd_P0238_threshold < sensor_adc_map) {
      DAT_003f9314 = DAT_003f9314 + 1;
      if ((short)DAT_003fdd44 <= DAT_003f9314) {
        DAT_003f9314 = 0;
        if (DAT_003f9312 == 0) {
          obd_set_dtc(&CAL_obd_P0238,&LEA_obd_P0238_flags,&LEA_obd_P0238_engine_start_count,
                      &LEA_obd_P0238_warm_up_cycle_count,0xee);
        }
        else {
          DAT_003f9312 = DAT_003f9312 - 1;
        }
      }
    }
    else {
      DAT_003f9314 = 0;
      obd_clr_dtc(&CAL_obd_P0238,&LEA_obd_P0238_flags);
      if (DAT_003f9312 < DAT_003fca03) {
        DAT_003f9312 = DAT_003f9312 + 1;
      }
    }
  }
  if (((CAL_obd_P0452 & 7) != 0) && (engine_is_running != false)) {
    if (sensor_adc_evap < CAL_obd_P0452_threshold) {
      DAT_003f9318 = DAT_003f9318 + 1;
      if ((short)DAT_003fdd44 <= DAT_003f9318) {
        DAT_003f9318 = 0;
        if (DAT_003f9316 == 0) {
          obd_set_dtc(&CAL_obd_P0452,&LEA_obd_P0452_flags,&LEA_obd_P0452_engine_start_count,
                      &LEA_obd_P0452_warm_up_cycle_count,0x1c4);
        }
        else {
          DAT_003f9316 = DAT_003f9316 - 1;
        }
      }
    }
    else {
      DAT_003f9318 = 0;
      obd_clr_dtc(&CAL_obd_P0452,&LEA_obd_P0452_flags);
      if (DAT_003f9316 < DAT_003fc9eb) {
        DAT_003f9316 = DAT_003f9316 + 1;
      }
    }
  }
  if (((CAL_obd_P0453 & 7) != 0) && (engine_is_running != false)) {
    if (CAL_obd_P0453_threshold < sensor_adc_evap) {
      DAT_003f931c = DAT_003f931c + 1;
      if ((short)DAT_003fdd44 <= DAT_003f931c) {
        DAT_003f931c = 0;
        if (DAT_003f931a == 0) {
          obd_set_dtc(&CAL_obd_P0453,&LEA_obd_P0453_flags,&LEA_obd_P0453_engine_start_count,
                      &LEA_obd_P0453_warm_up_cycle_count,0x1c5);
        }
        else {
          DAT_003f931a = DAT_003f931a - 1;
        }
      }
    }
    else {
      DAT_003f931c = 0;
      obd_clr_dtc(&CAL_obd_P0453,&LEA_obd_P0453_flags);
      if (DAT_003f931a < DAT_003fc9ec) {
        DAT_003f931a = DAT_003f931a + 1;
      }
    }
  }
  if (((CAL_obd_P0327 & 7) != 0) && (engine_is_running != false)) {
    if (sensor_adc_knock < DAT_003fc632) {
      DAT_003f9304 = DAT_003f9304 + 1;
      if ((short)DAT_003fdd44 <= DAT_003f9304) {
        DAT_003f9304 = 0;
        if (DAT_003f9302 == 0) {
          obd_set_dtc(&CAL_obd_P0327,&LEA_obd_P0327_flags,&LEA_obd_P0327_engine_start_count,
                      &LEA_obd_P0327_warm_up_cycle_count,0x147);
        }
        else {
          DAT_003f9302 = DAT_003f9302 - 1;
        }
      }
    }
    else {
      DAT_003f9304 = 0;
      obd_clr_dtc(&CAL_obd_P0327,&LEA_obd_P0327_flags);
      if (DAT_003f9302 < DAT_003fc9f1) {
        DAT_003f9302 = DAT_003f9302 + 1;
      }
    }
  }
  if (((CAL_obd_P0328 & 7) != 0) && (engine_is_running != false)) {
    if (DAT_003fc630 < sensor_adc_knock) {
      DAT_003f9308 = DAT_003f9308 + 1;
      if ((short)DAT_003fdd44 <= DAT_003f9308) {
        DAT_003f9308 = 0;
        if (DAT_003f9306 == 0) {
          obd_set_dtc(&CAL_obd_P0328,&LEA_obd_P0328_flags,&LEA_obd_P0328_engine_start_count,
                      &LEA_obd_P0328_warm_up_cycle_count,0x148);
        }
        else {
          DAT_003f9306 = DAT_003f9306 - 1;
        }
      }
    }
    else {
      DAT_003f9308 = 0;
      obd_clr_dtc(&CAL_obd_P0328,&LEA_obd_P0328_flags);
      if (DAT_003f9306 < DAT_003fc9f2) {
        DAT_003f9306 = DAT_003f9306 + 1;
      }
    }
  }
  if (((CAL_obd_P0462 & 7) != 0) && (engine_is_running != false)) {
    if (sensor_adc_fuel_level < CAL_obd_P0462_threshold) {
      DAT_003f9320 = DAT_003f9320 + 1;
      if ((short)DAT_003fdd44 <= DAT_003f9320) {
        DAT_003f9320 = 0;
        if (DAT_003f931e == 0) {
          obd_set_dtc(&CAL_obd_P0462,&LEA_obd_P0462_flags,&LEA_obd_P0462_engine_start_count,
                      &LEA_obd_P0462_warm_up_cycle_count,0x1ce);
        }
        else {
          DAT_003f931e = DAT_003f931e - 1;
        }
      }
    }
    else {
      DAT_003f9320 = 0;
      obd_clr_dtc(&CAL_obd_P0462,&LEA_obd_P0462_flags);
      if (DAT_003f931e < DAT_003fca3e) {
        DAT_003f931e = DAT_003f931e + 1;
      }
    }
  }
  if (((CAL_obd_P0463 & 7) != 0) && (engine_is_running != false)) {
    if (CAL_obd_P0463_threshold < sensor_adc_fuel_level) {
      DAT_003f9324 = DAT_003f9324 + 1;
      if ((short)DAT_003fdd44 <= DAT_003f9324) {
        DAT_003f9324 = 0;
        if (DAT_003f9322 == 0) {
          obd_set_dtc(&CAL_obd_P0463,&LEA_obd_P0463_flags,&LEA_obd_P0463_engine_start_count,
                      &LEA_obd_P0463_warm_up_cycle_count,0x1cf);
        }
        else {
          DAT_003f9322 = DAT_003f9322 - 1;
        }
      }
    }
    else {
      DAT_003f9324 = 0;
      obd_clr_dtc(&CAL_obd_P0463,&LEA_obd_P0463_flags);
      if (DAT_003f9322 < DAT_003fca3f) {
        DAT_003f9322 = DAT_003f9322 + 1;
      }
    }
  }
  if ((((CAL_obd_P0562 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if ((sensor_adc_ecu_voltage < CAL_obd_P0562_threshold) && ((shutdown_flags & 1) != 0)) {
      DAT_003f932c = DAT_003f932c + 1;
      if ((short)(ushort)DAT_003fc51c <= DAT_003f932c) {
        DAT_003f932c = 0;
        if (DAT_003f932a == 0) {
          obd_set_dtc(&CAL_obd_P0562,&LEA_obd_P0562_flags,&LEA_obd_P0562_engine_start_count,
                      &LEA_obd_P0562_warm_up_cycle_count,0x232);
        }
        else {
          DAT_003f932a = DAT_003f932a - 1;
        }
      }
    }
    else {
      DAT_003f932c = 0;
      obd_clr_dtc(&CAL_obd_P0562,&LEA_obd_P0562_flags);
      if (DAT_003f932a < DAT_003fc9f4) {
        DAT_003f932a = DAT_003f932a + 1;
      }
    }
  }
  if ((((CAL_obd_P0563 & 7) != 0) && (engine_is_running != false)) && ((shutdown_flags & 1) != 0)) {
    if (CAL_obd_P0563_threshold < sensor_adc_ecu_voltage) {
      DAT_003f9328 = DAT_003f9328 + 1;
      if ((short)(ushort)DAT_003fc51d <= DAT_003f9328) {
        DAT_003f9328 = 0;
        if (DAT_003f9326 == 0) {
          obd_set_dtc(&CAL_obd_P0563,&LEA_obd_P0563_flags,&LEA_obd_P0563_engine_start_count,
                      &LEA_obd_P0563_warm_up_cycle_count,0x233);
        }
        else {
          DAT_003f9326 = DAT_003f9326 - 1;
        }
      }
    }
    else {
      DAT_003f9328 = 0;
      obd_clr_dtc(&CAL_obd_P0563,&LEA_obd_P0563_flags);
      if (DAT_003f9326 < DAT_003fc9f3) {
        DAT_003f9326 = DAT_003f9326 + 1;
      }
    }
  }
  if (((DAT_003f92d0 == 0) || (DAT_003f92d4 == 0)) || (DAT_003f92d8 == 0)) {
    sensor_fault_flags = sensor_fault_flags | 0x10;
    flags_to_hc08 = flags_to_hc08 | 0x20;
  }
  else {
    sensor_fault_flags = sensor_fault_flags & 0xffef;
  }
  if (((DAT_003f92ec == 0) || (DAT_003f92f0 == 0)) || (DAT_003f92e8 == 0)) {
    sensor_fault_flags = sensor_fault_flags | 1;
  }
  else {
    sensor_fault_flags = sensor_fault_flags & 0xfffe;
  }
  if (((DAT_003fdd40 == 0) || (DAT_003fdd41 == 0)) || (DAT_003fdd14 == 0)) {
    sensor_fault_flags = sensor_fault_flags | 2;
  }
  else {
    sensor_fault_flags = sensor_fault_flags & 0xfffd;
  }
  if (((DAT_003f92dc == 0) || (DAT_003f92e0 == 0)) || (DAT_003f92e4 == 0)) {
    sensor_fault_flags = sensor_fault_flags | 8;
  }
  else {
    sensor_fault_flags = sensor_fault_flags & 0xfff7;
  }
  if (((DAT_003fdd42 == 0) || (DAT_003fdd43 == 0)) || (DAT_003fdcc8 == '\0')) {
    sensor_fault_flags = sensor_fault_flags | 0x800;
  }
  else {
    sensor_fault_flags = sensor_fault_flags & 0xf7ff;
  }
  if (DAT_003fdc3c == '\0') {
    sensor_fault_flags = sensor_fault_flags | 0x200;
  }
  else {
    sensor_fault_flags = sensor_fault_flags & 0xfdff;
  }
  if ((DAT_003fdc48 == '\0') || (DAT_003fdc4a == '\0')) {
    sensor_fault_flags = sensor_fault_flags | 0x400;
  }
  else {
    sensor_fault_flags = sensor_fault_flags & 0xfbff;
  }
  if ((DAT_003f9302 == 0) || (DAT_003f9306 == 0)) {
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
  DAT_003f92d0 = DAT_003fc9e7;
  DAT_003f92d4 = DAT_003fc9e4;
  DAT_003f92d8 = DAT_003fc9e5;
  DAT_003f92dc = DAT_003fc9d1;
  DAT_003f92e0 = DAT_003fc9d2;
  DAT_003f92e4 = DAT_003fc9d3;
  DAT_003f92e8 = DAT_003fc9d5;
  DAT_003f92ec = DAT_003fc9d6;
  DAT_003f92f0 = DAT_003fc9d7;
  DAT_003fdd14 = DAT_003fc9d9;
  DAT_003fdd40 = DAT_003fc9da;
  DAT_003fdd41 = DAT_003fc9db;
  DAT_003fdd42 = DAT_003fc9e0;
  DAT_003fdd43 = DAT_003fc9e1;
  DAT_003f92fe = DAT_003fc9e2;
  DAT_003f930a = DAT_003fc9e3;
  DAT_003f930e = DAT_003fca02;
  DAT_003f9312 = DAT_003fca03;
  DAT_003f9302 = DAT_003fc9f1;
  DAT_003f9306 = DAT_003fc9f2;
  DAT_003f9326 = DAT_003fc9f3;
  DAT_003f932a = DAT_003fc9f4;
  DAT_003f931a = DAT_003fc9ec;
  DAT_003f9316 = DAT_003fc9eb;
  DAT_003f9322 = DAT_003fca3f;
  DAT_003f931e = DAT_003fca3e;
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
    DAT_003fdd5c = lookup_2D_uint8_interpolated
                             (8,load_2,CAL_obd_P0128_air_mass_factor,
                              CAL_obd_P0128_air_mass_factor_X_engine_load);
  }
  else {
    DAT_003fdd5c = 255;
  }
  if ((((((CAL_obd_P0128 & 7) != 0) && (DAT_003fdd40 != '\0')) && (DAT_003fdd41 != '\0')) &&
      ((DAT_003fdd14 != '\0' && (DAT_003fc62f < coolant_stop)))) &&
     ((coolant_stop < CAL_obd_P0128_threshold && ((LEA_obd_P0128_flags & 8) == 0)))) {
    if (((uint)DAT_003fdd4c < DAT_003fdd58 >> 0x10) && (coolant_smooth < CAL_obd_P0128_threshold)) {
      if (DAT_003f9330 == 0) {
        obd_set_dtc(&CAL_obd_P0128,&LEA_obd_P0128_flags,&LEA_obd_P0128_engine_start_count,
                    &LEA_obd_P0128_warm_up_cycle_count,0x80);
      }
      else {
        DAT_003f9330 = DAT_003f9330 - 1;
      }
    }
    else if ((CAL_obd_P0128_threshold < coolant_smooth) &&
            (obd_clr_dtc(&CAL_obd_P0128,&LEA_obd_P0128_flags), DAT_003f9330 < DAT_003fc9e8)) {
      DAT_003f9330 = DAT_003f9330 + 1;
    }
  }
  return;
}



// Initializes thermostat monitor state

void obd_init_thermostat(void)

{
  DAT_003f9330 = DAT_003fc9e8;
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
  DAT_003f934c = (byte)uVar2;
  evap_pressure_smooth = smooth_evap_pressure((int)evap_pressure);
  uVar2 = abs((int)evap_pressure - (int)evap_pressure_smooth);
  DAT_003f934e = (short)uVar2;
  if ((((car_speed_smooth == 0) && ((idle_flags & 8) != 0)) && ((DAT_003fdc70 & 0x10) != 0)) &&
     ((DAT_003fdd66 & 2) == 0)) {
    if (DAT_003fdd67 == '\0') {
      if ((DAT_003fdd66 & 0x20) == 0) {
        DAT_003fdd66 = DAT_003fdd66 | 0x20;
        DAT_003f933a = fuel_level_smooth;
        DAT_003f933e = 0;
      }
      else if (DAT_003f933e < DAT_003fc648) {
        DAT_003f933e = DAT_003f933e + 1;
        if (DAT_003fc64d < DAT_003f934c) {
          DAT_003fdd68 = DAT_003fdd68 + 1;
        }
        if (DAT_003fc64e < DAT_003f934e) {
          DAT_003fdd69 = DAT_003fdd69 + 1;
        }
      }
      else {
        if (DAT_003f933a <= fuel_level_smooth) {
          DAT_003f933c = (ushort)fuel_level_smooth - (ushort)DAT_003f933a;
        }
        if (DAT_003f933c < (short)(ushort)DAT_003fc64a) {
          DAT_003fdd66 = DAT_003fdd66 | 2;
        }
        else {
          DAT_003fdd66 = DAT_003fdd66 & 0xdf;
          DAT_003fdd69 = 0;
          DAT_003f933c = 0;
          DAT_003fdd68 = 0;
        }
      }
    }
    else {
      DAT_003fdd67 = DAT_003fdd67 + -1;
    }
  }
  else {
    DAT_003fdd67 = DAT_003fc649;
  }
  if ((car_speed_smooth == 0) || ((DAT_003fdd66 & 1) != 0)) {
    if (car_speed_smooth == 0) {
      if (DAT_003f8369 == '\0') {
        DAT_003f9340 = DAT_003fc652;
        DAT_003f9342 = DAT_003fc654;
      }
      else {
        DAT_003f8369 = DAT_003f8369 + -1;
      }
    }
  }
  else {
    DAT_003f8369 = -6;
    if (fuel_level < DAT_003fc650) {
      if (DAT_003fc651 < fuel_level) {
        DAT_003f9340 = DAT_003fc652;
        DAT_003f9342 = DAT_003fc654;
        if (DAT_003f9344 == 0) {
          DAT_003f9346 = fuel_level;
          DAT_003f9345 = fuel_level;
          DAT_003f934a = evap_pressure;
          DAT_003f9348 = evap_pressure;
        }
        if (DAT_003f8368 != '\0') {
          DAT_003f8368 = DAT_003f8368 + -1;
        }
        if (((uint16_t_003fd880 & 1) != 0) && (DAT_003f8368 == '\0')) {
          DAT_003f9344 = DAT_003f9344 + 1;
          uint16_t_003fd880 = uint16_t_003fd880 & 0xfffe;
          DAT_003f8368 = '2';
        }
        if (fuel_level < DAT_003f9345) {
          DAT_003f9345 = fuel_level;
        }
        if (DAT_003f9346 < fuel_level) {
          DAT_003f9346 = fuel_level;
        }
        if (evap_pressure < DAT_003f9348) {
          DAT_003f9348 = evap_pressure;
        }
        if (DAT_003f934a < evap_pressure) {
          DAT_003f934a = evap_pressure;
        }
        if (DAT_003fc658 <= DAT_003f9344) {
          bVar1 = DAT_003fdd66 | 1;
          if ((int)((uint)DAT_003f9346 - (uint)DAT_003f9345) < (int)(uint)DAT_003fc659) {
            bVar1 = DAT_003fdd66 | 0x11;
          }
          DAT_003fdd66 = bVar1;
          if (((int)DAT_003f934a - (int)DAT_003f9348 < (int)DAT_003fc65a) && (DAT_003fdc4c != '\0'))
          {
            DAT_003fdd66 = DAT_003fdd66 | 0x40;
          }
        }
      }
      else {
        DAT_003f9342 = DAT_003fc654;
        if ((DAT_003fc656 < engine_speed_3) && (DAT_003fc657 < load_2)) {
          if (DAT_003f9340 == 0) {
            DAT_003fdd66 = DAT_003fdd66 | 9;
          }
          else {
            DAT_003f9340 = DAT_003f9340 + -1;
          }
        }
      }
    }
    else {
      DAT_003f9340 = DAT_003fc652;
      if ((DAT_003fc656 < engine_speed_3) && (DAT_003fc657 < load_2)) {
        if (DAT_003f9342 == 0) {
          DAT_003fdd66 = DAT_003fdd66 | 5;
        }
        else {
          DAT_003f9342 = DAT_003f9342 + -1;
        }
      }
    }
  }
  if ((((DAT_003fdd66 & 2) != 0) && ((DAT_003fdd66 & 1) != 0)) && (DAT_003fdc3c != '\0')) {
    if ((CAL_obd_P0461 & 7) != 0) {
      if ((DAT_003fc64b < DAT_003fdd68) || ((DAT_003fdd66 & 0x1c) != 0)) {
        if (DAT_003f9338 == 0) {
          obd_set_dtc(&CAL_obd_P0461,&LEA_obd_P0461_flags,&LEA_obd_P0461_engine_start_count,
                      &LEA_obd_P0461_warm_up_cycle_count,0x1cd);
        }
        else {
          DAT_003f9338 = DAT_003f9338 - 1;
        }
      }
      else {
        obd_clr_dtc(&CAL_obd_P0461,&LEA_obd_P0461_flags);
        if (DAT_003f9338 < DAT_003fca3d) {
          DAT_003f9338 = DAT_003f9338 + 1;
        }
      }
    }
    if ((CAL_obd_P0451 & 7) != 0) {
      if ((DAT_003fc64c < DAT_003fdd69) || ((DAT_003fdd66 & 0x40) != 0)) {
        if (DAT_003f9339 == 0) {
          obd_set_dtc(&CAL_obd_P0451,&LEA_obd_P0451_flags,&LEA_obd_P0451_engine_start_count,
                      &LEA_obd_P0451_warm_up_cycle_count,0x1c3);
        }
        else {
          DAT_003f9339 = DAT_003f9339 - 1;
        }
      }
      else {
        obd_clr_dtc(&CAL_obd_P0451,&LEA_obd_P0451_flags);
        if (DAT_003f9339 < DAT_003fc9fb) {
          DAT_003f9339 = DAT_003f9339 + 1;
        }
      }
    }
    DAT_003fdd66 = DAT_003fdd66 & 0x80;
    DAT_003f9344 = 0;
    DAT_003fdd69 = 0;
    DAT_003fdd68 = 0;
    DAT_003f933e = 0;
    DAT_003f9340 = DAT_003fc652;
    DAT_003f9342 = DAT_003fc654;
  }
  return;
}



// Initializes fuel/EVAP pressure monitor state

void obd_init_fuel_evap_press(void)

{
  fuel_level_smooth_x = (uint)fuel_level << 8;
  evap_pressure_smooth_x = (int)evap_pressure << 8;
  DAT_003f9338 = DAT_003fca3d;
  DAT_003f9339 = DAT_003fc9fb;
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



// OBD Mode 01: Returns current live data PIDs

void obd_mode_0x01_live_data(void)

{
  uint8_t extraout_var;
  uint8_t uVar2;
  int iVar1;
  uint uVar3;
  byte bVar4;
  byte bVar5;
  
  bVar5 = 1;
  obd_resp[0] = 65;
  for (uVar3 = 2; (uVar3 & 0xff) < obd_req[0] + 1; uVar3 = uVar3 + 1) {
    if (true) {
      switch(obd_req[uVar3 & 0xff]) {
      case '\0':
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        obd_resp[(byte)(bVar5 + 1)] = DAT_003f8370;
        obd_resp[(byte)(bVar5 + 2)] = DAT_003f8371;
        bVar4 = bVar5 + 4;
        obd_resp[(byte)(bVar5 + 3)] = DAT_003f8372;
        bVar5 = bVar5 + 5;
        obd_resp[bVar4] = DAT_003f8373;
        break;
      case '\x01':
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        obd_resp[(byte)(bVar5 + 1)] = obd_mil_dtc_count;
        obd_resp[(byte)(bVar5 + 2)] = CAL_obd_monitors[0];
        bVar4 = bVar5 + 4;
        obd_resp[(byte)(bVar5 + 3)] = CAL_obd_monitors[1];
        bVar5 = bVar5 + 5;
        obd_resp[bVar4] = LEA_obd_monitors_completeness;
        break;
      case '\x02':
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        bcd_encode((int)(uint)LEA_obd_freeze_dtc >> 3);
        bVar4 = bVar5 + 2;
        obd_resp[(byte)(bVar5 + 1)] = extraout_var;
        uVar2 = bcd_encode((int)(uint)LEA_obd_freeze_dtc >> 3);
        bVar5 = bVar5 + 3;
        obd_resp[bVar4] = uVar2;
        break;
      case '\x03':
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        bVar4 = bVar5 + 2;
        obd_resp[(byte)(bVar5 + 1)] = (uint8_t)fuel_system_status;
        bVar5 = bVar5 + 3;
        obd_resp[bVar4] = 0;
        break;
      case '\x04':
        bVar4 = bVar5 + 1;
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        if (engine_speed_1 == 0) {
          bVar5 = bVar5 + 2;
          obd_resp[bVar4] = 0;
        }
        else {
          bVar5 = bVar5 + 2;
          obd_resp[bVar4] = load_3;
        }
        break;
      case '\x05':
        bVar4 = bVar5 + 1;
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        bVar5 = bVar5 + 2;
        obd_resp[bVar4] = (uint8_t)((uint)coolant * 0xa0 >> 8);
        break;
      case '\x06':
        bVar4 = bVar5 + 1;
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        bVar5 = bVar5 + 2;
        obd_resp[bVar4] = obd_stft;
        break;
      case '\a':
        bVar4 = bVar5 + 1;
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        bVar5 = bVar5 + 2;
        obd_resp[bVar4] = obd_ltft;
        break;
      case '\f':
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        bVar4 = bVar5 + 2;
        obd_resp[(byte)(bVar5 + 1)] = (uint8_t)(engine_speed_1 >> 8);
        bVar5 = bVar5 + 3;
        obd_resp[bVar4] = (uint8_t)engine_speed_1;
        break;
      case '\r':
        bVar4 = bVar5 + 1;
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        bVar5 = bVar5 + 2;
        obd_resp[bVar4] = car_speed_smooth;
        break;
      case '\x0e':
        bVar4 = bVar5 + 1;
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        bVar5 = bVar5 + 2;
        obd_resp[bVar4] = (char)((int)ign_adv_final / 2) + 128;
        break;
      case '\x0f':
        bVar4 = bVar5 + 1;
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        bVar5 = bVar5 + 2;
        obd_resp[bVar4] = (uint8_t)((uint)engine_air * 0xa0 >> 8);
        break;
      case '\x10':
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        bVar4 = bVar5 + 2;
        obd_resp[(byte)(bVar5 + 1)] = (uint8_t)(maf_flow_1 >> 8);
        bVar5 = bVar5 + 3;
        obd_resp[bVar4] = (uint8_t)maf_flow_1;
        break;
      case '\x11':
        bVar4 = bVar5 + 1;
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        bVar5 = bVar5 + 2;
        obd_resp[bVar4] = (uint8_t)((int)(uint)sensor_adc_tps_1 >> 2);
        break;
      case '\x13':
        bVar4 = bVar5 + 1;
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        bVar5 = bVar5 + 2;
        obd_resp[bVar4] = DAT_003fc569;
        break;
      case '\x14':
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        if (sensor_adc_pre_o2 < 0x105) {
          DAT_003f9352 = (uint8_t)(((uint)sensor_adc_pre_o2 * 0xff) / 0x105);
        }
        else {
          DAT_003f9352 = 255;
        }
        bVar4 = bVar5 + 2;
        obd_resp[(byte)(bVar5 + 1)] = DAT_003f9352;
        bVar5 = bVar5 + 3;
        obd_resp[bVar4] = obd_stft;
        break;
      case '\x15':
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        if (sensor_adc_post_o2 < 0x105) {
          DAT_003f9352 = (uint8_t)(((uint)sensor_adc_post_o2 * 0xff) / 0x105);
        }
        else {
          DAT_003f9352 = 255;
        }
        bVar4 = bVar5 + 2;
        obd_resp[(byte)(bVar5 + 1)] = DAT_003f9352;
        bVar5 = bVar5 + 3;
        obd_resp[bVar4] = 255;
        break;
      case '\x1c':
        bVar4 = bVar5 + 1;
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        bVar5 = bVar5 + 2;
        obd_resp[bVar4] = DAT_003fc56a;
        break;
      case '\x1f':
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        bVar4 = bVar5 + 2;
        obd_resp[(byte)(bVar5 + 1)] = (uint8_t)(engine_runtime / 200 >> 8);
        bVar5 = bVar5 + 3;
        obd_resp[bVar4] = (uint8_t)(engine_runtime / 200);
        break;
      case ' ':
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        obd_resp[(byte)(bVar5 + 1)] = DAT_003f8374;
        obd_resp[(byte)(bVar5 + 2)] = DAT_003f8375;
        bVar4 = bVar5 + 4;
        obd_resp[(byte)(bVar5 + 3)] = DAT_003f8376;
        bVar5 = bVar5 + 5;
        obd_resp[bVar4] = DAT_003f8377;
        break;
      case '!':
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        bVar4 = bVar5 + 2;
        obd_resp[(byte)(bVar5 + 1)] = (uint8_t)(DAT_003fd9bc / 10000 >> 8);
        bVar5 = bVar5 + 3;
        obd_resp[bVar4] = (uint8_t)(DAT_003fd9bc / 10000);
        break;
      case '.':
        bVar4 = bVar5 + 1;
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        bVar5 = bVar5 + 2;
        obd_resp[bVar4] = (uint8_t)evap_purge_command;
        break;
      case '/':
        bVar4 = bVar5 + 1;
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        bVar5 = bVar5 + 2;
        obd_resp[bVar4] = DAT_003fd886;
        break;
      case '3':
        bVar4 = bVar5 + 1;
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        iVar1 = (int)atmo_pressure / 10 + ((int)atmo_pressure >> 0x1f);
        bVar5 = bVar5 + 2;
        obd_resp[bVar4] = (char)iVar1 - (char)(iVar1 >> 0x1f);
        break;
      case '@':
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        obd_resp[(byte)(bVar5 + 1)] = DAT_003f8378;
        obd_resp[(byte)(bVar5 + 2)] = DAT_003f8379;
        bVar4 = bVar5 + 4;
        obd_resp[(byte)(bVar5 + 3)] = DAT_003f9350;
        bVar5 = bVar5 + 5;
        obd_resp[bVar4] = DAT_003f9351;
        break;
      case 'B':
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        bVar4 = bVar5 + 2;
        obd_resp[(byte)(bVar5 + 1)] = (uint8_t)((uint)sensor_adc_ecu_voltage * 0x12 >> 8);
        bVar5 = bVar5 + 3;
        obd_resp[bVar4] = (char)sensor_adc_ecu_voltage * '\x12';
        break;
      case 'C':
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        if (engine_speed_1 == 0) {
          bVar4 = bVar5 + 2;
          obd_resp[(byte)(bVar5 + 1)] = 0;
          bVar5 = bVar5 + 3;
          obd_resp[bVar4] = 0;
        }
        else {
          bVar4 = bVar5 + 2;
          obd_resp[(byte)(bVar5 + 1)] = 0;
          bVar5 = bVar5 + 3;
          obd_resp[bVar4] = load_4;
        }
        break;
      case 'E':
        bVar4 = bVar5 + 1;
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        bVar5 = bVar5 + 2;
        obd_resp[bVar4] =
             (uint8_t)((int)((uint)sensor_adc_tps_1 - (uint)tps_1_range_corrected_low) >> 2);
        break;
      case 'G':
        bVar4 = bVar5 + 1;
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        bVar5 = bVar5 + 2;
        obd_resp[bVar4] = (uint8_t)((int)(uint)sensor_adc_tps_2 >> 2);
        break;
      case 'I':
        bVar4 = bVar5 + 1;
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        bVar5 = bVar5 + 2;
        obd_resp[bVar4] = (uint8_t)((int)(uint)sensor_adc_pps_1 >> 2);
        break;
      case 'J':
        bVar4 = bVar5 + 1;
        obd_resp[bVar5] = obd_req[uVar3 & 0xff];
        bVar5 = bVar5 + 2;
        obd_resp[bVar4] = (uint8_t)((int)(uint)sensor_adc_pps_2 >> 2);
      }
    }
  }
  if (bVar5 < 2) {
    DAT_003fda00 = 1;
  }
  else {
    obd_resp_len = (uint16_t)bVar5;
    send_obd_resp();
  }
  return;
}



// OBD Mode 02: Returns freeze frame data

void obd_mode_0x02_freeze_frame(void)

{
  uint8_t extraout_var;
  uint8_t uVar1;
  uint uVar2;
  byte bVar3;
  byte bVar4;
  
  bVar4 = 1;
  obd_resp[0] = 66;
  for (uVar2 = 2; (uVar2 & 0xff) < obd_req[0] + 1; uVar2 = uVar2 + 2) {
    if (true) {
      switch(obd_req[uVar2 & 0xff]) {
      case '\0':
        obd_resp[bVar4] = obd_req[uVar2 & 0xff];
        obd_resp[(byte)(bVar4 + 1)] = obd_req[(uVar2 & 0xff) + 1];
        obd_resp[(byte)(bVar4 + 2)] = DAT_003f84a8;
        obd_resp[(byte)(bVar4 + 3)] = DAT_003f84a9;
        bVar3 = bVar4 + 5;
        obd_resp[(byte)(bVar4 + 4)] = DAT_003f84aa;
        bVar4 = bVar4 + 6;
        obd_resp[bVar3] = DAT_003f9358;
        break;
      case '\x02':
        obd_resp[bVar4] = obd_req[uVar2 & 0xff];
        obd_resp[(byte)(bVar4 + 1)] = obd_req[(uVar2 & 0xff) + 1];
        bcd_encode((int)(uint)LEA_obd_freeze_dtc >> 3);
        bVar3 = bVar4 + 3;
        obd_resp[(byte)(bVar4 + 2)] = extraout_var;
        uVar1 = bcd_encode((int)(uint)LEA_obd_freeze_dtc >> 3);
        bVar4 = bVar4 + 4;
        obd_resp[bVar3] = uVar1;
        break;
      case '\x03':
        obd_resp[bVar4] = obd_req[uVar2 & 0xff];
        obd_resp[(byte)(bVar4 + 1)] = obd_req[(uVar2 & 0xff) + 1];
        bVar3 = bVar4 + 3;
        obd_resp[(byte)(bVar4 + 2)] = LEA_obd_freeze_fuel_system_status;
        bVar4 = bVar4 + 4;
        obd_resp[bVar3] = 0;
        break;
      case '\x04':
        obd_resp[bVar4] = obd_req[uVar2 & 0xff];
        bVar3 = bVar4 + 2;
        obd_resp[(byte)(bVar4 + 1)] = obd_req[(uVar2 & 0xff) + 1];
        bVar4 = bVar4 + 3;
        obd_resp[bVar3] = LEA_obd_freeze_load;
        break;
      case '\x05':
        obd_resp[bVar4] = obd_req[uVar2 & 0xff];
        bVar3 = bVar4 + 2;
        obd_resp[(byte)(bVar4 + 1)] = obd_req[(uVar2 & 0xff) + 1];
        bVar4 = bVar4 + 3;
        obd_resp[bVar3] = LEA_obd_freeze_coolant;
        break;
      case '\x06':
        obd_resp[bVar4] = obd_req[uVar2 & 0xff];
        bVar3 = bVar4 + 2;
        obd_resp[(byte)(bVar4 + 1)] = obd_req[(uVar2 & 0xff) + 1];
        bVar4 = bVar4 + 3;
        obd_resp[bVar3] = LEA_obd_freeze_stft;
        break;
      case '\a':
        obd_resp[bVar4] = obd_req[uVar2 & 0xff];
        bVar3 = bVar4 + 2;
        obd_resp[(byte)(bVar4 + 1)] = obd_req[(uVar2 & 0xff) + 1];
        bVar4 = bVar4 + 3;
        obd_resp[bVar3] = LEA_obd_freeze_ltft;
        break;
      case '\f':
        obd_resp[bVar4] = obd_req[uVar2 & 0xff];
        obd_resp[(byte)(bVar4 + 1)] = obd_req[(uVar2 & 0xff) + 1];
        bVar3 = bVar4 + 3;
        obd_resp[(byte)(bVar4 + 2)] = (uint8_t)(LEA_obd_freeze_engine_speed >> 8);
        bVar4 = bVar4 + 4;
        obd_resp[bVar3] = (uint8_t)LEA_obd_freeze_engine_speed;
        break;
      case '\r':
        obd_resp[bVar4] = obd_req[uVar2 & 0xff];
        bVar3 = bVar4 + 2;
        obd_resp[(byte)(bVar4 + 1)] = obd_req[(uVar2 & 0xff) + 1];
        bVar4 = bVar4 + 3;
        obd_resp[bVar3] = LEA_obd_freeze_car_speed;
        break;
      case '\x10':
        obd_resp[bVar4] = obd_req[uVar2 & 0xff];
        obd_resp[(byte)(bVar4 + 1)] = obd_req[(uVar2 & 0xff) + 1];
        bVar3 = bVar4 + 3;
        obd_resp[(byte)(bVar4 + 2)] = (uint8_t)(LEA_obd_freeze_maf_flow >> 8);
        bVar4 = bVar4 + 4;
        obd_resp[bVar3] = (uint8_t)LEA_obd_freeze_maf_flow;
        break;
      case '\x11':
        obd_resp[bVar4] = obd_req[uVar2 & 0xff];
        bVar3 = bVar4 + 2;
        obd_resp[(byte)(bVar4 + 1)] = obd_req[(uVar2 & 0xff) + 1];
        bVar4 = bVar4 + 3;
        obd_resp[bVar3] = LEA_obd_freeze_tps;
      }
    }
  }
  if (bVar4 < 2) {
    DAT_003fda00 = 1;
  }
  else {
    obd_resp_len = (uint16_t)bVar4;
    send_obd_resp();
  }
  return;
}



// OBD Mode 03: Returns confirmed DTCs

void obd_mode_0x03_trouble_code(void)

{
  uint uVar1;
  byte bVar2;
  uint uVar3;
  uint uVar4;
  
  obd_resp[0] = 67;
  obd_resp[1] = obd_trouble_list_count;
  uVar3 = 2;
  for (bVar2 = 0; bVar2 < obd_trouble_list_count; bVar2 = bVar2 + 1) {
    uVar1 = bcd_encode(obd_trouble_list[bVar2]);
    uVar4 = uVar3 + 1;
    obd_resp[uVar3 & 0xff] = (uint8_t)((uVar1 & 0xffff) >> 8);
    uVar3 = uVar3 + 2;
    obd_resp[uVar4 & 0xff] = (uint8_t)(uVar1 & 0xffff);
  }
  obd_resp_len = (ushort)uVar3 & 0xff;
  send_obd_resp();
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
  obd_resp[0] = 68;
  obd_resp_len = 1;
  obd_clear_freeze();
  send_obd_resp();
  return;
}



// Clears all freeze frame data

void obd_clear_freeze(void)

{
  byte bVar1;
  
  LEA_ltft_zone2_adj = 128;
  DAT_002f835a = 0;
  DAT_002f8358 = 0;
  DAT_002f8365 = 0;
  DAT_002f8364 = 0;
  DAT_002f8362 = 0;
  LEA_evap_leak_result = 0;
  DAT_002f8366 = 0;
  for (bVar1 = 0; bVar1 < 4; bVar1 = bVar1 + 1) {
    LEA_misfire_count[bVar1] = 0;
  }
  for (bVar1 = 8; bVar1 < 0x10; bVar1 = bVar1 + 1) {
    (&DAT_002f82df)[bVar1] = 0;
    (&DAT_002f82cf)[bVar1] = 0;
  }
  DAT_002f8352 = 0;
  DAT_002f82ff = 0;
  cat_diag_pre_o2_timer = DAT_003fc596;
  DAT_002f834e = 0;
  DAT_002f8350 = 0x3ff;
  o2_flags = o2_flags & 0xfeff;
  o2_lean2rich_total_time = 0;
  o2_rich2lean_total_time = 0;
  o2_lean2rich_switch_count = 0;
  o2_rich2lean_switch_count = 0;
  LEA_o2_rich2lean_avg_time = 0;
  LEA_o2_lean2rich_avg_time = 0;
  DAT_003fdd0c = DAT_003fc600;
  DAT_003fdd0a = DAT_003fc5e2;
  DAT_003fdcfa = 0;
  DAT_003fdd11 = 0;
  DAT_003fdcfe = 0;
  DAT_003fdd05 = 0;
  DAT_002f8356 = 0;
  post_o2_state = 0;
  DAT_003fdcfc = 0;
  DAT_003fdd04 = 0;
  DAT_002f8354 = 0;
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
  DAT_003fd998 = 0;
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
  LEA_obd_P0222_engine_start_count = 3;
  LEA_obd_P0222_warm_up_cycle_count = 40;
  LEA_obd_P0123_flags = 0;
  LEA_obd_P0223_engine_start_count = 3;
  LEA_obd_P0223_warm_up_cycle_count = 40;
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
  DAT_002f83d1 = 3;
  DAT_002f83d2 = 0x28;
  LEA_obd_P0223_flags = 0;
  DAT_002f83d4 = 3;
  DAT_002f83d5 = 0x28;
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
  DAT_003fd9b2 = 1;
  obd_init_state_machine();
  DAT_003fd9bc = 0;
  return;
}



// OBD Mode 09: Returns vehicle information (VIN, calibration ID)

void obd_mode_0x09_informations(void)

{
  byte bVar1;
  uint uVar2;
  byte bVar3;
  
  bVar3 = 1;
  obd_resp[0] = 73;
  obd_resp_len = obd_resp_len + 1;
  for (uVar2 = 2; (uVar2 & 0xff) < obd_req[0] + 1; uVar2 = uVar2 + 1) {
    switch(obd_req[uVar2 & 0xff]) {
    case '\0':
      obd_resp[bVar3] = obd_req[uVar2 & 0xff];
      obd_resp[(byte)(bVar3 + 1)] = DAT_003f84f8;
      obd_resp[(byte)(bVar3 + 2)] = DAT_003fdf74;
      bVar1 = bVar3 + 4;
      obd_resp[(byte)(bVar3 + 3)] = DAT_003fdf75;
      bVar3 = bVar3 + 5;
      obd_resp[bVar1] = DAT_003fdf76;
      break;
    case '\x01':
      bVar1 = bVar3 + 1;
      obd_resp[bVar3] = obd_req[uVar2 & 0xff];
      bVar3 = bVar3 + 2;
      obd_resp[bVar1] = 1;
      break;
    case '\x02':
      obd_resp[bVar3] = obd_req[uVar2 & 0xff];
      obd_resp[(byte)(bVar3 + 1)] = 1;
      bVar3 = bVar3 + 2;
      for (bVar1 = 0; bVar1 < 0x11; bVar1 = bVar1 + 1) {
        obd_resp[bVar3] = LEA_ecu_VIN[bVar1];
        bVar3 = bVar3 + 1;
      }
      break;
    case '\x03':
      bVar1 = bVar3 + 1;
      obd_resp[bVar3] = obd_req[uVar2 & 0xff];
      bVar3 = bVar3 + 2;
      obd_resp[bVar1] = 1;
      break;
    case '\x04':
      obd_resp[bVar3] = obd_req[uVar2 & 0xff];
      obd_resp[(byte)(bVar3 + 1)] = 1;
      bVar3 = bVar3 + 2;
      for (bVar1 = 0; bVar1 < 0x10; bVar1 = bVar1 + 1) {
        obd_resp[bVar3] = s_A129E0002_Sport_GT_240_EU_003fcf26[bVar1];
        bVar3 = bVar3 + 1;
      }
      break;
    case '\x05':
      bVar1 = bVar3 + 1;
      obd_resp[bVar3] = obd_req[uVar2 & 0xff];
      bVar3 = bVar3 + 2;
      obd_resp[bVar1] = 1;
      break;
    case '\x06':
      obd_resp[bVar3] = obd_req[uVar2 & 0xff];
      obd_resp[(byte)(bVar3 + 1)] = 1;
      obd_resp[(byte)(bVar3 + 2)] = 0;
      obd_resp[(byte)(bVar3 + 3)] = 0;
      bVar1 = bVar3 + 5;
      obd_resp[(byte)(bVar3 + 4)] = (uint8_t)(ecu_CRC_computed >> 8);
      bVar3 = bVar3 + 6;
      obd_resp[bVar1] = (uint8_t)ecu_CRC_computed;
      break;
    case '\a':
      bVar1 = bVar3 + 1;
      obd_resp[bVar3] = obd_req[uVar2 & 0xff];
      bVar3 = bVar3 + 2;
      obd_resp[bVar1] = 1;
      break;
    case '\b':
      obd_resp[bVar3] = obd_req[uVar2 & 0xff];
      obd_resp[(byte)(bVar3 + 1)] = 16;
      obd_resp[(byte)(bVar3 + 2)] = (uint8_t)(LEA_obd_iumpr_obdcond_count >> 8);
      obd_resp[(byte)(bVar3 + 3)] = (uint8_t)LEA_obd_iumpr_obdcond_count;
      obd_resp[(byte)(bVar3 + 4)] = (uint8_t)(LEA_obd_iumpr_ignition_count >> 8);
      obd_resp[(byte)(bVar3 + 5)] = (uint8_t)LEA_obd_iumpr_ignition_count;
      obd_resp[(byte)(bVar3 + 6)] = (uint8_t)((ushort)DAT_003fe736 >> 8);
      obd_resp[(byte)(bVar3 + 7)] = (uint8_t)DAT_003fe736;
      obd_resp[(byte)(bVar3 + 8)] = (uint8_t)((ushort)DAT_003fe734 >> 8);
      obd_resp[(byte)(bVar3 + 9)] = (uint8_t)DAT_003fe734;
      obd_resp[(byte)(bVar3 + 10)] = 0;
      obd_resp[(byte)(bVar3 + 0xb)] = 0;
      obd_resp[(byte)(bVar3 + 0xc)] = 0;
      obd_resp[(byte)(bVar3 + 0xd)] = 0;
      obd_resp[(byte)(bVar3 + 0xe)] = (uint8_t)((ushort)DAT_003fe72e >> 8);
      obd_resp[(byte)(bVar3 + 0xf)] = (uint8_t)DAT_003fe72e;
      obd_resp[(byte)(bVar3 + 0x10)] = (uint8_t)((ushort)DAT_003fe72c >> 8);
      obd_resp[(byte)(bVar3 + 0x11)] = (uint8_t)DAT_003fe72c;
      obd_resp[(byte)(bVar3 + 0x12)] = 0;
      obd_resp[(byte)(bVar3 + 0x13)] = 0;
      obd_resp[(byte)(bVar3 + 0x14)] = 0;
      obd_resp[(byte)(bVar3 + 0x15)] = 0;
      obd_resp[(byte)(bVar3 + 0x16)] = (uint8_t)((ushort)DAT_003fe73e >> 8);
      obd_resp[(byte)(bVar3 + 0x17)] = (uint8_t)DAT_003fe73e;
      obd_resp[(byte)(bVar3 + 0x18)] = (uint8_t)((ushort)DAT_003fe73c >> 8);
      obd_resp[(byte)(bVar3 + 0x19)] = (uint8_t)DAT_003fe73c;
      obd_resp[(byte)(bVar3 + 0x1a)] = 0;
      obd_resp[(byte)(bVar3 + 0x1b)] = 0;
      obd_resp[(byte)(bVar3 + 0x1c)] = 0;
      obd_resp[(byte)(bVar3 + 0x1d)] = 0;
      obd_resp[(byte)(bVar3 + 0x1e)] = (uint8_t)((ushort)DAT_003fe746 >> 8);
      obd_resp[(byte)(bVar3 + 0x1f)] = (uint8_t)DAT_003fe746;
      bVar1 = bVar3 + 0x21;
      obd_resp[(byte)(bVar3 + 0x20)] = (uint8_t)((ushort)DAT_003fe744 >> 8);
      bVar3 = bVar3 + 0x22;
      obd_resp[bVar1] = (uint8_t)DAT_003fe744;
    }
  }
  if (bVar3 < 2) {
    DAT_003fda00 = 1;
  }
  else {
    obd_resp_len = (uint16_t)bVar3;
    send_obd_resp();
  }
  return;
}



// OBD Mode 06: Returns test results for specific monitor

void obd_mode_0x06_test_results(void)

{
  bool bVar1;
  uint8_t uVar2;
  uint uVar3;
  short sVar4;
  short sVar5;
  short sVar6;
  short sVar7;
  ushort uVar8;
  uint uVar9;
  short sVar10;
  undefined2 uVar11;
  undefined2 uVar12;
  short sVar13;
  uint8_t uVar16;
  ushort uVar14;
  uint16_t uVar15;
  byte bVar17;
  byte bVar18;
  
  push_24to31();
  bVar18 = 1;
  obd_resp[0] = 70;
  for (uVar9 = 2; (uVar9 & 0xff) < obd_req[0] + 1; uVar9 = uVar9 + 1) {
    bVar17 = obd_req[uVar9 & 0xff];
    if (bVar17 == 0x40) {
      obd_resp[bVar18] = obd_req[uVar9 & 0xff];
      obd_resp[(byte)(bVar18 + 1)] = DAT_003f9364;
      obd_resp[(byte)(bVar18 + 2)] = DAT_003f9365;
      bVar17 = bVar18 + 4;
      obd_resp[(byte)(bVar18 + 3)] = DAT_003f9366;
      bVar18 = bVar18 + 5;
      obd_resp[bVar17] = DAT_003f8524;
    }
    else if (bVar17 < 0x40) {
      if (bVar17 == 0x21) {
        sVar6 = DAT_002f8352;
        uVar11 = DAT_003fc52a;
        if (DAT_002f8352 == 0) {
          sVar6 = 0;
          uVar11 = 0;
        }
        obd_resp[bVar18] = obd_req[uVar9 & 0xff];
        obd_resp[(byte)(bVar18 + 1)] = 128;
        obd_resp[(byte)(bVar18 + 2)] = 4;
        obd_resp[(byte)(bVar18 + 3)] = (uint8_t)((ushort)sVar6 >> 8);
        obd_resp[(byte)(bVar18 + 4)] = (uint8_t)sVar6;
        obd_resp[(byte)(bVar18 + 5)] = 0;
        obd_resp[(byte)(bVar18 + 6)] = 0;
        bVar17 = bVar18 + 8;
        obd_resp[(byte)(bVar18 + 7)] = (uint8_t)((ushort)uVar11 >> 8);
        bVar18 = bVar18 + 9;
        obd_resp[bVar17] = (uint8_t)uVar11;
      }
      else if (bVar17 < 0x21) {
        if (bVar17 == 2) {
          if ((DAT_002f8354 == 0) || (DAT_002f8356 == 0)) {
            sVar13 = 0;
            sVar7 = 0;
            sVar5 = 0;
            sVar4 = 0;
            sVar6 = 0;
            sVar10 = 0;
          }
          else {
            sVar4 = DAT_003fc5e0 * 0x28;
            sVar5 = DAT_003fc5de * 0x28;
            sVar7 = DAT_003fc570 * 5;
            sVar13 = DAT_003fc56e * 5;
            sVar6 = DAT_002f8356;
            sVar10 = DAT_002f8354;
          }
          obd_resp[bVar18] = obd_req[uVar9 & 0xff];
          obd_resp[(byte)(bVar18 + 1)] = 3;
          obd_resp[(byte)(bVar18 + 2)] = 10;
          uVar2 = (uint8_t)((ushort)sVar4 >> 8);
          obd_resp[(byte)(bVar18 + 3)] = uVar2;
          uVar16 = (uint8_t)sVar4;
          obd_resp[(byte)(bVar18 + 4)] = uVar16;
          obd_resp[(byte)(bVar18 + 5)] = uVar2;
          obd_resp[(byte)(bVar18 + 6)] = uVar16;
          obd_resp[(byte)(bVar18 + 7)] = uVar2;
          obd_resp[(byte)(bVar18 + 8)] = uVar16;
          obd_resp[(byte)(bVar18 + 9)] = obd_req[uVar9 & 0xff];
          obd_resp[(byte)(bVar18 + 10)] = 4;
          obd_resp[(byte)(bVar18 + 0xb)] = 10;
          uVar2 = (uint8_t)((ushort)sVar5 >> 8);
          obd_resp[(byte)(bVar18 + 0xc)] = uVar2;
          uVar16 = (uint8_t)sVar5;
          obd_resp[(byte)(bVar18 + 0xd)] = uVar16;
          obd_resp[(byte)(bVar18 + 0xe)] = uVar2;
          obd_resp[(byte)(bVar18 + 0xf)] = uVar16;
          obd_resp[(byte)(bVar18 + 0x10)] = uVar2;
          obd_resp[(byte)(bVar18 + 0x11)] = uVar16;
          obd_resp[(byte)(bVar18 + 0x12)] = obd_req[uVar9 & 0xff];
          obd_resp[(byte)(bVar18 + 0x13)] = 5;
          obd_resp[(byte)(bVar18 + 0x14)] = 16;
          obd_resp[(byte)(bVar18 + 0x15)] = (uint8_t)((ushort)sVar6 >> 8);
          obd_resp[(byte)(bVar18 + 0x16)] = (uint8_t)sVar6;
          obd_resp[(byte)(bVar18 + 0x17)] = 0;
          obd_resp[(byte)(bVar18 + 0x18)] = 0;
          obd_resp[(byte)(bVar18 + 0x19)] = (uint8_t)((ushort)sVar7 >> 8);
          obd_resp[(byte)(bVar18 + 0x1a)] = (uint8_t)sVar7;
          obd_resp[(byte)(bVar18 + 0x1b)] = obd_req[uVar9 & 0xff];
          obd_resp[(byte)(bVar18 + 0x1c)] = 6;
          obd_resp[(byte)(bVar18 + 0x1d)] = 16;
          obd_resp[(byte)(bVar18 + 0x1e)] = (uint8_t)((ushort)sVar10 >> 8);
          obd_resp[(byte)(bVar18 + 0x1f)] = (uint8_t)sVar10;
          obd_resp[(byte)(bVar18 + 0x20)] = 0;
          obd_resp[(byte)(bVar18 + 0x21)] = 0;
          bVar17 = bVar18 + 0x23;
          obd_resp[(byte)(bVar18 + 0x22)] = (uint8_t)((ushort)sVar13 >> 8);
          bVar18 = bVar18 + 0x24;
          obd_resp[bVar17] = (uint8_t)sVar13;
        }
        else if (bVar17 < 2) {
          if (bVar17 == 0) {
            obd_resp[bVar18] = obd_req[uVar9 & 0xff];
            obd_resp[(byte)(bVar18 + 1)] = DAT_003f8520;
            obd_resp[(byte)(bVar18 + 2)] = DAT_003f9360;
            bVar17 = bVar18 + 4;
            obd_resp[(byte)(bVar18 + 3)] = DAT_003f9361;
            bVar18 = bVar18 + 5;
            obd_resp[bVar17] = DAT_003f8521;
          }
          else if (true) {
            if ((LEA_o2_rich2lean_avg_time == 0) || (LEA_o2_lean2rich_avg_time == 0)) {
              sVar4 = 0;
              sVar5 = 0;
              sVar6 = 0;
              sVar7 = 0;
              sVar10 = 0;
              sVar13 = 0;
            }
            else {
              sVar13 = DAT_003fc5da * 0x28;
              sVar10 = DAT_003fc5d8 * 0x28;
              sVar7 = LEA_o2_lean2rich_avg_time * 5;
              sVar6 = CAL_obd_P0133_threshold1_lean2rich * 5;
              sVar5 = LEA_o2_rich2lean_avg_time * 5;
              sVar4 = CAL_obd_P0133_threshold1_rich2lean * 5;
            }
            obd_resp[bVar18] = obd_req[uVar9 & 0xff];
            obd_resp[(byte)(bVar18 + 1)] = 3;
            obd_resp[(byte)(bVar18 + 2)] = 10;
            uVar2 = (uint8_t)((ushort)sVar13 >> 8);
            obd_resp[(byte)(bVar18 + 3)] = uVar2;
            uVar16 = (uint8_t)sVar13;
            obd_resp[(byte)(bVar18 + 4)] = uVar16;
            obd_resp[(byte)(bVar18 + 5)] = uVar2;
            obd_resp[(byte)(bVar18 + 6)] = uVar16;
            obd_resp[(byte)(bVar18 + 7)] = uVar2;
            obd_resp[(byte)(bVar18 + 8)] = uVar16;
            obd_resp[(byte)(bVar18 + 9)] = obd_req[uVar9 & 0xff];
            obd_resp[(byte)(bVar18 + 10)] = 4;
            obd_resp[(byte)(bVar18 + 0xb)] = 10;
            uVar2 = (uint8_t)((ushort)sVar10 >> 8);
            obd_resp[(byte)(bVar18 + 0xc)] = uVar2;
            uVar16 = (uint8_t)sVar10;
            obd_resp[(byte)(bVar18 + 0xd)] = uVar16;
            obd_resp[(byte)(bVar18 + 0xe)] = uVar2;
            obd_resp[(byte)(bVar18 + 0xf)] = uVar16;
            obd_resp[(byte)(bVar18 + 0x10)] = uVar2;
            obd_resp[(byte)(bVar18 + 0x11)] = uVar16;
            obd_resp[(byte)(bVar18 + 0x12)] = obd_req[uVar9 & 0xff];
            obd_resp[(byte)(bVar18 + 0x13)] = 5;
            obd_resp[(byte)(bVar18 + 0x14)] = 16;
            obd_resp[(byte)(bVar18 + 0x15)] = (uint8_t)((ushort)sVar7 >> 8);
            obd_resp[(byte)(bVar18 + 0x16)] = (uint8_t)sVar7;
            obd_resp[(byte)(bVar18 + 0x17)] = 0;
            obd_resp[(byte)(bVar18 + 0x18)] = 0;
            obd_resp[(byte)(bVar18 + 0x19)] = (uint8_t)((ushort)sVar6 >> 8);
            obd_resp[(byte)(bVar18 + 0x1a)] = (uint8_t)sVar6;
            obd_resp[(byte)(bVar18 + 0x1b)] = obd_req[uVar9 & 0xff];
            obd_resp[(byte)(bVar18 + 0x1c)] = 6;
            obd_resp[(byte)(bVar18 + 0x1d)] = 16;
            obd_resp[(byte)(bVar18 + 0x1e)] = (uint8_t)((ushort)sVar5 >> 8);
            obd_resp[(byte)(bVar18 + 0x1f)] = (uint8_t)sVar5;
            obd_resp[(byte)(bVar18 + 0x20)] = 0;
            obd_resp[(byte)(bVar18 + 0x21)] = 0;
            bVar17 = bVar18 + 0x23;
            obd_resp[(byte)(bVar18 + 0x22)] = (uint8_t)((ushort)sVar4 >> 8);
            bVar18 = bVar18 + 0x24;
            obd_resp[bVar17] = (uint8_t)sVar4;
          }
        }
        else if (0x1f < bVar17) {
          obd_resp[bVar18] = obd_req[uVar9 & 0xff];
          obd_resp[(byte)(bVar18 + 1)] = DAT_003f8522;
          obd_resp[(byte)(bVar18 + 2)] = DAT_003f9362;
          bVar17 = bVar18 + 4;
          obd_resp[(byte)(bVar18 + 3)] = DAT_003f9363;
          bVar18 = bVar18 + 5;
          obd_resp[bVar17] = DAT_003f8523;
        }
      }
      else if (bVar17 == 0x3b) {
        obd_resp[bVar18] = obd_req[uVar9 & 0xff];
        obd_resp[(byte)(bVar18 + 1)] = 130;
        obd_resp[(byte)(bVar18 + 2)] = 254;
        if (LEA_evap_leak_result == 0) {
          uVar12 = 0;
          uVar11 = 0;
        }
        else {
          uVar11 = (undefined2)((LEA_evap_leak_result * 5) / 2);
          uVar12 = (undefined2)((int)((uint)DAT_002f8364 * 5) >> 1);
        }
        obd_resp[(byte)(bVar18 + 3)] = (uint8_t)((ushort)uVar11 >> 8);
        obd_resp[(byte)(bVar18 + 4)] = (uint8_t)uVar11;
        obd_resp[(byte)(bVar18 + 5)] = 0;
        obd_resp[(byte)(bVar18 + 6)] = 0;
        bVar17 = bVar18 + 8;
        obd_resp[(byte)(bVar18 + 7)] = (uint8_t)((ushort)uVar12 >> 8);
        bVar18 = bVar18 + 9;
        obd_resp[bVar17] = (uint8_t)uVar12;
      }
      else if (bVar17 < 0x3b) {
        if (bVar17 == 0x39) {
          bVar1 = DAT_002f835a != 0;
          uVar16 = DAT_002f835a;
          if (!bVar1) {
            uVar16 = 0;
          }
          obd_resp[bVar18] = obd_req[uVar9 & 0xff];
          obd_resp[(byte)(bVar18 + 1)] = 129;
          obd_resp[(byte)(bVar18 + 2)] = 46;
          obd_resp[(byte)(bVar18 + 3)] = 0;
          obd_resp[(byte)(bVar18 + 4)] = uVar16;
          obd_resp[(byte)(bVar18 + 5)] = 0;
          obd_resp[(byte)(bVar18 + 6)] = 0;
          bVar17 = bVar18 + 8;
          obd_resp[(byte)(bVar18 + 7)] = 0;
          bVar18 = bVar18 + 9;
          obd_resp[bVar17] = bVar1;
        }
      }
      else if (bVar17 == 0x3d) {
        if (DAT_002f8358 == 0) {
          uVar8 = 0;
          uVar11 = 0;
          uVar14 = 0;
        }
        else {
          uVar14 = DAT_002f8358 / 100;
          uVar11 = 0x7fff;
          uVar8 = DAT_003fc606 / 100;
        }
        obd_resp[bVar18] = obd_req[uVar9 & 0xff];
        obd_resp[(byte)(bVar18 + 1)] = 131;
        obd_resp[(byte)(bVar18 + 2)] = 253;
        obd_resp[(byte)(bVar18 + 3)] = (uint8_t)(uVar14 >> 8);
        obd_resp[(byte)(bVar18 + 4)] = (uint8_t)uVar14;
        obd_resp[(byte)(bVar18 + 5)] = (uint8_t)((ushort)uVar11 >> 8);
        obd_resp[(byte)(bVar18 + 6)] = (uint8_t)uVar11;
        bVar17 = bVar18 + 8;
        obd_resp[(byte)(bVar18 + 7)] = -(char)(uVar8 >> 8);
        bVar18 = bVar18 + 9;
        obd_resp[bVar17] = (uint8_t)uVar8;
      }
      else if (bVar17 < 0x3d) {
        obd_resp[bVar18] = obd_req[uVar9 & 0xff];
        obd_resp[(byte)(bVar18 + 1)] = 130;
        obd_resp[(byte)(bVar18 + 2)] = 254;
        if (DAT_002f8362 == 0) {
          uVar12 = 0;
          uVar11 = 0;
        }
        else {
          uVar11 = (undefined2)((DAT_002f8362 * 5) / 2);
          uVar12 = (undefined2)((int)((uint)DAT_002f8365 * 5) >> 1);
        }
        obd_resp[(byte)(bVar18 + 3)] = (uint8_t)((ushort)uVar11 >> 8);
        obd_resp[(byte)(bVar18 + 4)] = (uint8_t)uVar11;
        obd_resp[(byte)(bVar18 + 5)] = 0;
        obd_resp[(byte)(bVar18 + 6)] = 0;
        bVar17 = bVar18 + 8;
        obd_resp[(byte)(bVar18 + 7)] = (uint8_t)((ushort)uVar12 >> 8);
        bVar18 = bVar18 + 9;
        obd_resp[bVar17] = (uint8_t)uVar12;
      }
    }
    else if (bVar17 == 0xa0) {
      obd_resp[bVar18] = obd_req[uVar9 & 0xff];
      obd_resp[(byte)(bVar18 + 1)] = DAT_003f8528;
      obd_resp[(byte)(bVar18 + 2)] = DAT_003f936c;
      bVar17 = bVar18 + 4;
      obd_resp[(byte)(bVar18 + 3)] = DAT_003f936d;
      bVar18 = bVar18 + 5;
      obd_resp[bVar17] = DAT_003f936e;
    }
    else if (bVar17 < 0xa0) {
      if (bVar17 == 0x80) {
        obd_resp[bVar18] = obd_req[uVar9 & 0xff];
        obd_resp[(byte)(bVar18 + 1)] = DAT_003f8526;
        obd_resp[(byte)(bVar18 + 2)] = DAT_003f936a;
        bVar17 = bVar18 + 4;
        obd_resp[(byte)(bVar18 + 3)] = DAT_003f936b;
        bVar18 = bVar18 + 5;
        obd_resp[bVar17] = DAT_003f8527;
      }
      else if (bVar17 < 0x80) {
        if (bVar17 == 0x60) {
          obd_resp[bVar18] = obd_req[uVar9 & 0xff];
          obd_resp[(byte)(bVar18 + 1)] = DAT_003f9367;
          obd_resp[(byte)(bVar18 + 2)] = DAT_003f9368;
          bVar17 = bVar18 + 4;
          obd_resp[(byte)(bVar18 + 3)] = DAT_003f9369;
          bVar18 = bVar18 + 5;
          obd_resp[bVar17] = DAT_003f8525;
        }
      }
      else if (bVar17 < 0x82) {
        if (LEA_ltft_zone2_adj == 0) {
          sVar5 = 0;
          sVar10 = 0;
          sVar6 = 0;
        }
        else {
          uVar3 = (char)(LEA_ltft_zone2_adj ^ 0x80) * 500;
          uVar3 = abs(((int)uVar3 >> 7) + (uint)((int)uVar3 < 0 && (uVar3 & 0x7f) != 0));
          sVar6 = (short)uVar3 * 10;
          sVar10 = DAT_003fc530 * 10;
          sVar5 = DAT_003fc52e * 10;
        }
        obd_resp[bVar18] = obd_req[uVar9 & 0xff];
        obd_resp[(byte)(bVar18 + 1)] = 132;
        obd_resp[(byte)(bVar18 + 2)] = 175;
        obd_resp[(byte)(bVar18 + 3)] = (uint8_t)((ushort)sVar6 >> 8);
        obd_resp[(byte)(bVar18 + 4)] = (uint8_t)sVar6;
        obd_resp[(byte)(bVar18 + 5)] = (uint8_t)((ushort)sVar10 >> 8);
        obd_resp[(byte)(bVar18 + 6)] = (uint8_t)sVar10;
        bVar17 = bVar18 + 8;
        obd_resp[(byte)(bVar18 + 7)] = (uint8_t)((ushort)sVar5 >> 8);
        bVar18 = bVar18 + 9;
        obd_resp[bVar17] = (uint8_t)sVar5;
      }
    }
    else if (bVar17 == 0xa4) {
      if (DAT_002f8366 == '\0') {
        sVar10 = 0;
        sVar6 = 0;
      }
      else {
        sVar6 = LEA_misfire_count[1] * 10;
        sVar10 = (ushort)DAT_003fdcae * 10;
      }
      obd_resp[bVar18] = obd_req[uVar9 & 0xff];
      obd_resp[(byte)(bVar18 + 1)] = 11;
      obd_resp[(byte)(bVar18 + 2)] = 36;
      uVar16 = (uint8_t)((ushort)sVar6 >> 8);
      obd_resp[(byte)(bVar18 + 3)] = uVar16;
      obd_resp[(byte)(bVar18 + 4)] = (uint8_t)sVar6;
      obd_resp[(byte)(bVar18 + 5)] = 0;
      obd_resp[(byte)(bVar18 + 6)] = 0;
      uVar2 = (uint8_t)((ushort)sVar10 >> 8);
      obd_resp[(byte)(bVar18 + 7)] = uVar2;
      obd_resp[(byte)(bVar18 + 8)] = (uint8_t)sVar10;
      obd_resp[(byte)(bVar18 + 9)] = obd_req[uVar9 & 0xff];
      obd_resp[(byte)(bVar18 + 10)] = 12;
      obd_resp[(byte)(bVar18 + 0xb)] = 47;
      obd_resp[(byte)(bVar18 + 0xc)] = uVar16;
      obd_resp[(byte)(bVar18 + 0xd)] = (uint8_t)sVar6;
      obd_resp[(byte)(bVar18 + 0xe)] = 0;
      obd_resp[(byte)(bVar18 + 0xf)] = 0;
      bVar17 = bVar18 + 0x11;
      obd_resp[(byte)(bVar18 + 0x10)] = uVar2;
      bVar18 = bVar18 + 0x12;
      obd_resp[bVar17] = (uint8_t)sVar10;
    }
    else if (bVar17 < 0xa4) {
      if (bVar17 == 0xa2) {
        if (DAT_002f8366 == '\0') {
          sVar10 = 0;
          sVar6 = 0;
        }
        else {
          sVar6 = LEA_misfire_count[0] * 10;
          sVar10 = (ushort)DAT_003fdcae * 10;
        }
        obd_resp[bVar18] = obd_req[uVar9 & 0xff];
        obd_resp[(byte)(bVar18 + 1)] = 11;
        obd_resp[(byte)(bVar18 + 2)] = 36;
        uVar16 = (uint8_t)((ushort)sVar6 >> 8);
        obd_resp[(byte)(bVar18 + 3)] = uVar16;
        obd_resp[(byte)(bVar18 + 4)] = (uint8_t)sVar6;
        obd_resp[(byte)(bVar18 + 5)] = 0;
        obd_resp[(byte)(bVar18 + 6)] = 0;
        uVar2 = (uint8_t)((ushort)sVar10 >> 8);
        obd_resp[(byte)(bVar18 + 7)] = uVar2;
        obd_resp[(byte)(bVar18 + 8)] = (uint8_t)sVar10;
        obd_resp[(byte)(bVar18 + 9)] = obd_req[uVar9 & 0xff];
        obd_resp[(byte)(bVar18 + 10)] = 12;
        obd_resp[(byte)(bVar18 + 0xb)] = 47;
        obd_resp[(byte)(bVar18 + 0xc)] = uVar16;
        obd_resp[(byte)(bVar18 + 0xd)] = (uint8_t)sVar6;
        obd_resp[(byte)(bVar18 + 0xe)] = 0;
        obd_resp[(byte)(bVar18 + 0xf)] = 0;
        bVar17 = bVar18 + 0x11;
        obd_resp[(byte)(bVar18 + 0x10)] = uVar2;
        bVar18 = bVar18 + 0x12;
        obd_resp[bVar17] = (uint8_t)sVar10;
      }
      else if (bVar17 < 0xa2) {
        if (DAT_002f8366 == '\0') {
          sVar6 = 0;
          sVar10 = 0;
        }
        else {
          sVar10 = misfire_max_result * 10;
          sVar6 = (ushort)DAT_003fdcae * 10;
        }
        obd_resp[bVar18] = obd_req[uVar9 & 0xff];
        obd_resp[(byte)(bVar18 + 1)] = 133;
        obd_resp[(byte)(bVar18 + 2)] = 47;
        obd_resp[(byte)(bVar18 + 3)] = (uint8_t)((ushort)sVar10 >> 8);
        obd_resp[(byte)(bVar18 + 4)] = (uint8_t)sVar10;
        obd_resp[(byte)(bVar18 + 5)] = 0;
        obd_resp[(byte)(bVar18 + 6)] = 0;
        bVar17 = bVar18 + 8;
        obd_resp[(byte)(bVar18 + 7)] = (uint8_t)((ushort)sVar6 >> 8);
        bVar18 = bVar18 + 9;
        obd_resp[bVar17] = (uint8_t)sVar6;
      }
      else {
        if (DAT_002f8366 == '\0') {
          sVar10 = 0;
          sVar6 = 0;
        }
        else {
          sVar6 = LEA_misfire_count[3] * 10;
          sVar10 = (ushort)DAT_003fdcae * 10;
        }
        obd_resp[bVar18] = obd_req[uVar9 & 0xff];
        obd_resp[(byte)(bVar18 + 1)] = 11;
        obd_resp[(byte)(bVar18 + 2)] = 36;
        uVar16 = (uint8_t)((ushort)sVar6 >> 8);
        obd_resp[(byte)(bVar18 + 3)] = uVar16;
        obd_resp[(byte)(bVar18 + 4)] = (uint8_t)sVar6;
        obd_resp[(byte)(bVar18 + 5)] = 0;
        obd_resp[(byte)(bVar18 + 6)] = 0;
        uVar2 = (uint8_t)((ushort)sVar10 >> 8);
        obd_resp[(byte)(bVar18 + 7)] = uVar2;
        obd_resp[(byte)(bVar18 + 8)] = (uint8_t)sVar10;
        obd_resp[(byte)(bVar18 + 9)] = obd_req[uVar9 & 0xff];
        obd_resp[(byte)(bVar18 + 10)] = 12;
        obd_resp[(byte)(bVar18 + 0xb)] = 47;
        obd_resp[(byte)(bVar18 + 0xc)] = uVar16;
        obd_resp[(byte)(bVar18 + 0xd)] = (uint8_t)sVar6;
        obd_resp[(byte)(bVar18 + 0xe)] = 0;
        obd_resp[(byte)(bVar18 + 0xf)] = 0;
        bVar17 = bVar18 + 0x11;
        obd_resp[(byte)(bVar18 + 0x10)] = uVar2;
        bVar18 = bVar18 + 0x12;
        obd_resp[bVar17] = (uint8_t)sVar10;
      }
    }
    else if (bVar17 < 0xa6) {
      if (DAT_002f8366 == '\0') {
        sVar6 = 0;
        uVar15 = 0;
      }
      else {
        sVar6 = (ushort)DAT_003fdcae * 10;
        uVar15 = LEA_misfire_count[2];
      }
      obd_resp[bVar18] = obd_req[uVar9 & 0xff];
      obd_resp[(byte)(bVar18 + 1)] = 11;
      obd_resp[(byte)(bVar18 + 2)] = 36;
      uVar16 = (uint8_t)(uVar15 >> 8);
      obd_resp[(byte)(bVar18 + 3)] = uVar16;
      obd_resp[(byte)(bVar18 + 4)] = (uint8_t)uVar15;
      obd_resp[(byte)(bVar18 + 5)] = 0;
      obd_resp[(byte)(bVar18 + 6)] = 0;
      uVar2 = (uint8_t)((ushort)sVar6 >> 8);
      obd_resp[(byte)(bVar18 + 7)] = uVar2;
      obd_resp[(byte)(bVar18 + 8)] = (uint8_t)sVar6;
      obd_resp[(byte)(bVar18 + 9)] = obd_req[uVar9 & 0xff];
      obd_resp[(byte)(bVar18 + 10)] = 12;
      obd_resp[(byte)(bVar18 + 0xb)] = 47;
      obd_resp[(byte)(bVar18 + 0xc)] = uVar16;
      obd_resp[(byte)(bVar18 + 0xd)] = (uint8_t)uVar15;
      obd_resp[(byte)(bVar18 + 0xe)] = 0;
      obd_resp[(byte)(bVar18 + 0xf)] = 0;
      bVar17 = bVar18 + 0x11;
      obd_resp[(byte)(bVar18 + 0x10)] = uVar2;
      bVar18 = bVar18 + 0x12;
      obd_resp[bVar17] = (uint8_t)sVar6;
    }
  }
  if (bVar18 < 2) {
    DAT_003fda00 = 1;
  }
  else {
    obd_resp_len = (uint16_t)bVar18;
    send_obd_resp();
  }
  pop_24to31();
  return;
}



// OBD Mode 07: Returns pending DTCs

void obd_mode_0x07_pending_code(void)

{
  uint uVar1;
  byte bVar2;
  uint uVar3;
  uint uVar4;
  
  obd_resp[0] = 71;
  obd_resp[1] = obd_pending_list_count;
  uVar3 = 2;
  for (bVar2 = 0; bVar2 < obd_pending_list_count; bVar2 = bVar2 + 1) {
    uVar1 = bcd_encode(obd_pending_list[bVar2]);
    uVar4 = uVar3 + 1;
    obd_resp[uVar3 & 0xff] = (uint8_t)((uVar1 & 0xffff) >> 8);
    uVar3 = uVar3 + 2;
    obd_resp[uVar4 & 0xff] = (uint8_t)(uVar1 & 0xffff);
  }
  obd_resp_len = (ushort)uVar3 & 0xff;
  send_obd_resp();
  return;
}



// Adds DTC to pending trouble code list

void obd_add_pending(uint16_t param_1)

{
  if (obd_pending_list_count < 127) {
    obd_pending_list[obd_pending_list_count] = param_1;
    obd_pending_list_count = obd_pending_list_count + 1;
  }
  return;
}



// OBD Mode 08: Controls EVAP system test

void obd_mode_0x08_evap_control(void)

{
  uint uVar1;
  byte bVar2;
  byte bVar3;
  
  bVar3 = 1;
  obd_resp[0] = 72;
  obd_resp_len = obd_resp_len + 1;
  for (uVar1 = 2; (uVar1 & 0xff) < obd_req[0] + 1; uVar1 = uVar1 + 1) {
    if (obd_req[uVar1 & 0xff] == 1) {
      if ((engine_speed_1 == 0) && (DAT_003fc5a4 != 0)) {
        obd_resp[bVar3] = obd_req[uVar1 & 0xff];
        obd_resp[(byte)(bVar3 + 1)] = 0;
        obd_resp[(byte)(bVar3 + 2)] = 0;
        obd_resp[(byte)(bVar3 + 3)] = 0;
        bVar2 = bVar3 + 5;
        obd_resp[(byte)(bVar3 + 4)] = 0;
        bVar3 = bVar3 + 6;
        obd_resp[bVar2] = 0;
        obd_mode_0x08_state = 0x18;
        obd_mode_0x08_timer = DAT_003fc5a4;
        obd_mode_0x2F_value = 0xff;
      }
      else {
        obd_resp[0] = 127;
        obd_resp[1] = obd_req[1];
        obd_resp[2] = 34;
        obd_resp_len = 3;
        send_obd_resp();
        obd_mode_0x2F_value = 0;
        obd_mode_0x08_state = 0;
      }
    }
    else if ((obd_req[uVar1 & 0xff] == 0) && (true)) {
      obd_resp[bVar3] = obd_req[uVar1 & 0xff];
      obd_resp[(byte)(bVar3 + 1)] = DAT_003f8530;
      obd_resp[(byte)(bVar3 + 2)] = DAT_003f9370;
      bVar2 = bVar3 + 4;
      obd_resp[(byte)(bVar3 + 3)] = DAT_003f9371;
      bVar3 = bVar3 + 5;
      obd_resp[bVar2] = DAT_003f9372;
    }
  }
  if (bVar3 < 2) {
    DAT_003fda00 = 1;
  }
  else {
    obd_resp_len = (uint16_t)bVar3;
    send_obd_resp();
  }
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



// OBD Mode 13: Returns DTC list

void obd_mode_0x13_dtc_list(void)

{
  bool bVar1;
  byte bVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  ushort uVar6;
  
  if (obd_mode_0x13_state == 1) {
    bVar1 = DAT_003f8538 == '\0';
    DAT_003f8538 = DAT_003f8538 + -1;
    if (bVar1) {
      DAT_003f8538 = '\b';
      obd_mode_0x13_state = 2;
      DAT_003fd9b9 = '\x01';
    }
  }
  else if (obd_mode_0x13_state == 0) {
    if (true) {
      if (CAL_tpms_use_tpms) {
        tpms_session_start();
        obd_mode_0x13_state = obd_mode_0x13_state + 1;
      }
      else {
        obd_mode_0x13_state = 2;
      }
    }
  }
  else if (obd_mode_0x13_state < 3) {
    if ((obd_req[0] == 1) || (((obd_req[0] == 3 && (obd_req[2] == 255)) && (obd_req[3] == 0)))) {
      uVar3 = 1;
      obd_resp[0] = 83;
      for (bVar2 = 0; bVar2 < obd_trouble_list_count; bVar2 = bVar2 + 1) {
        uVar5 = bcd_encode(obd_trouble_list[bVar2]);
        uVar4 = uVar3 + 1;
        obd_resp[uVar3 & 0xff] = (uint8_t)((uVar5 & 0xffff) >> 8);
        uVar3 = uVar3 + 2;
        obd_resp[uVar4 & 0xff] = (uint8_t)(uVar5 & 0xffff);
      }
      if (CAL_tpms_use_tpms != false) {
        for (bVar2 = 0; bVar2 < DAT_003fe2cb; bVar2 = bVar2 + 1) {
          uVar5 = uVar3 + 1;
          obd_resp[uVar3 & 0xff] = (uint8_t)((ushort)(&DAT_003fe3ce)[bVar2] >> 8);
          uVar3 = uVar3 + 2;
          obd_resp[uVar5 & 0xff] = (uint8_t)(&DAT_003fe3ce)[bVar2];
        }
      }
      uVar6 = (ushort)uVar3;
      if (DAT_003fd9b9 == '\x01') {
        obd_resp[uVar3 & 0xff] = 193;
        uVar6 = uVar6 + 2;
        obd_resp[uVar3 + 1 & 0xff] = 39;
      }
      obd_resp_len = uVar6 & 0xff;
      send_obd_resp();
    }
    obd_mode_0x13_state = 0;
    DAT_003f8538 = '\b';
  }
  return;
}



// OBD Mode 14: Clears DTCs

void obd_mode_0x14_clear(void)

{
  if ((obd_req[0] == 1) || (obd_req[2] == 255)) {
    if (CAL_tpms_use_tpms) {
      tpms_session_stop();
      DAT_003fd9b9 = 0;
    }
    obd_clear_freeze();
    obd_resp[0] = 84;
    obd_resp_len = 1;
    send_obd_resp();
  }
  return;
}



// OBD Mode 22: Returns extended performance data (Lotus-specific)

void obd_mode_0x22_performance_data(void)

{
  uint8_t uVar1;
  int iVar2;
  ushort uVar3;
  
  obd_resp[0] = 98;
  obd_resp[1] = obd_req[2];
  uVar3 = 3;
  obd_resp[2] = obd_req[3];
  if (true) {
    uVar1 = (uint8_t)((ushort)LEA_ltft_zone1_adj >> 8);
    switch((ushort)obd_req[2] * 0x100 + (ushort)obd_req[3]) {
    case 0x200:
      obd_resp[3] = DAT_003f8540;
      obd_resp[4] = DAT_003f8541;
      uVar3 = 7;
      obd_resp._5_2_ = CONCAT11(DAT_003f8542,DAT_003f8543);
      break;
    case 0x201:
      uVar3 = 4;
      obd_resp[3] = evap_leak_state;
      break;
    case 0x203:
      obd_resp[3] = (uint8_t)(LEA_idle_flow_adj1 >> 0xf);
      uVar3 = 7;
      obd_resp[4] = obd_resp[3];
      obd_resp._5_2_ = LEA_idle_flow_adj1;
      break;
    case 0x204:
      uVar3 = 4;
      obd_resp[3] = idle_flow_target;
      break;
    case 0x205:
      obd_resp[3] = (uint8_t)(inj_time_final_1 >> 0x18);
      obd_resp[4] = (uint8_t)(inj_time_final_1 >> 0x10);
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)inj_time_final_1;
      break;
    case 0x206:
      uVar3 = 4;
      obd_resp[3] = idle_status;
      break;
    case 0x207:
      obd_resp[3] = (uint8_t)((ushort)vvt_target_smooth >> 8);
      obd_resp[4] = (uint8_t)vvt_target_smooth;
      uVar3 = 5;
      break;
    case 0x208:
      obd_resp[3] = (uint8_t)((ushort)vvt_pos >> 8);
      obd_resp[4] = (uint8_t)vvt_pos;
      uVar3 = 5;
      break;
    case 0x209:
      uVar3 = 4;
      obd_resp[3] = vvl_is_high_cam;
      break;
    case 0x20a:
      obd_resp[3] = (uint8_t)(cat_diag_pre_o2_sw >> 8);
      obd_resp[4] = (uint8_t)cat_diag_pre_o2_sw;
      uVar3 = 5;
      break;
    case 0x20b:
      obd_resp[3] = (uint8_t)(cat_diag_pre_o2_max_sw >> 8);
      obd_resp[4] = (uint8_t)cat_diag_pre_o2_max_sw;
      uVar3 = 5;
      break;
    case 0x20c:
      uVar3 = 4;
      obd_resp[3] = car_gear_current;
      break;
    case 0x20d:
      iVar2 = (idle_speed_target + -600) / 5 + (idle_speed_target + -600 >> 0x1f);
      obd_resp[3] = (char)iVar2 - (char)(iVar2 >> 0x1f);
      uVar3 = 4;
      break;
    case 0x20e:
      obd_resp[3] = 0;
      obd_resp[4] = 0;
      uVar3 = 7;
      obd_resp._5_2_ = 0x2be8;
      break;
    case 0x20f:
      obd_resp[3] = 255;
      obd_resp[4] = 255;
      uVar3 = 7;
      obd_resp._5_2_ = 4;
      break;
    case 0x210:
      obd_resp[3] = 0;
      obd_resp[4] = 0;
      uVar3 = 7;
      obd_resp._5_2_ = 1;
      break;
    case 0x211:
      obd_resp[3] = 'T';
      obd_resp[4] = '4';
      uVar3 = 7;
      obd_resp._5_2_ = 0x4520;
      break;
    case 0x212:
      obd_resp[3] = (uint8_t)((ushort)evap_pressure >> 8);
      obd_resp[4] = (uint8_t)evap_pressure;
      uVar3 = 5;
      break;
    case 0x213:
      obd_resp[3] = (uint8_t)(afr_target >> 8);
      obd_resp[4] = (uint8_t)afr_target;
      uVar3 = 5;
      break;
    case 0x214:
      uVar3 = 4;
      obd_resp[3] = L9822E_outputs;
      break;
    case 0x215:
      obd_resp[3] = tpms_pressure_fl;
      obd_resp[4] = tpms_pressure_fr;
      uVar3 = 7;
      obd_resp._5_2_ = CONCAT11(tpms_pressure_rl,tpms_pressure_rr);
      break;
    case 0x216:
      obd_resp[3] = (uint8_t)(tpms_flags >> 8);
      obd_resp[4] = (uint8_t)tpms_flags;
      uVar3 = 5;
      break;
    case 0x218:
      obd_resp[3] = (uint8_t)(LEA_knock_retard2[0] >> 8);
      obd_resp[4] = (uint8_t)LEA_knock_retard2[0];
      uVar3 = 5;
      break;
    case 0x219:
      obd_resp[3] = (uint8_t)(LEA_knock_retard2[1] >> 8);
      obd_resp[4] = (uint8_t)LEA_knock_retard2[1];
      uVar3 = 5;
      break;
    case 0x21a:
      obd_resp[3] = (uint8_t)(LEA_knock_retard2[2] >> 8);
      uVar3 = 5;
      obd_resp[4] = (uint8_t)LEA_knock_retard2[2];
      break;
    case 0x21b:
      obd_resp[3] = (uint8_t)(LEA_knock_retard2[3] >> 8);
      obd_resp[4] = (uint8_t)LEA_knock_retard2[3];
      uVar3 = 5;
      break;
    case 0x21c:
      obd_resp[3] = CAL_ecu_model_name[0];
      obd_resp[4] = CAL_ecu_model_name[1];
      uVar3 = 7;
      obd_resp._5_2_ = CONCAT11(CAL_ecu_model_name[2],CAL_ecu_model_name[3]);
      break;
    case 0x21d:
      obd_resp[3] = CAL_ecu_model_name[4];
      obd_resp[4] = CAL_ecu_model_name[5];
      uVar3 = 7;
      obd_resp._5_2_ = CONCAT11(CAL_ecu_model_name[6],CAL_ecu_model_name[7]);
      break;
    case 0x21e:
      obd_resp[3] = CAL_ecu_model_name[8];
      obd_resp[4] = CAL_ecu_model_name[9];
      uVar3 = 7;
      obd_resp._5_2_ = CONCAT11(CAL_ecu_model_name[10],CAL_ecu_model_name[0xb]);
      break;
    case 0x21f:
      obd_resp[3] = CAL_ecu_model_name[0xc];
      obd_resp[4] = CAL_ecu_model_name[0xd];
      uVar3 = 7;
      obd_resp._5_2_ = CONCAT11(CAL_ecu_model_name[0xe],CAL_ecu_model_name[0xf]);
      break;
    case 0x220:
      obd_resp[3] = DAT_003f8544;
      obd_resp[4] = DAT_003f8545;
      uVar3 = 7;
      obd_resp._5_2_ = CONCAT11(DAT_003f8546,DAT_003f8547);
      break;
    case 0x221:
      obd_resp[3] = CAL_ecu_model_name[0x10];
      obd_resp[4] = CAL_ecu_model_name[0x11];
      uVar3 = 7;
      obd_resp._5_2_ = CONCAT11(CAL_ecu_model_name[0x12],CAL_ecu_model_name[0x13]);
      break;
    case 0x222:
      obd_resp[3] = CAL_ecu_model_name[0x14];
      obd_resp[4] = CAL_ecu_model_name[0x15];
      uVar3 = 7;
      obd_resp._5_2_ = CONCAT11(CAL_ecu_model_name[0x16],CAL_ecu_model_name[0x17]);
      break;
    case 0x223:
      obd_resp[3] = CAL_ecu_model_name[0x18];
      obd_resp[4] = CAL_ecu_model_name[0x19];
      uVar3 = 7;
      obd_resp._5_2_ = CONCAT11(CAL_ecu_model_name[0x1a],CAL_ecu_model_name[0x1b]);
      break;
    case 0x224:
      obd_resp[3] = CAL_ecu_model_name[0x1c];
      obd_resp[4] = CAL_ecu_model_name[0x1d];
      uVar3 = 7;
      obd_resp._5_2_ = CONCAT11(CAL_ecu_model_name[0x1e],CAL_ecu_model_name[0x1f]);
      break;
    case 0x225:
      uVar3 = 4;
      obd_resp[3] = intake_air_smooth;
      break;
    case 0x226:
      uVar3 = 4;
      obd_resp[3] = load_2;
      break;
    case 0x227:
      uVar3 = 4;
      obd_resp[3] = coolant_stop;
      break;
    case 0x228:
      obd_resp[3] = (uint8_t)(maf_accumulated_1 >> 0x18);
      obd_resp[4] = (uint8_t)(maf_accumulated_1 >> 0x10);
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)maf_accumulated_1;
      break;
    case 0x229:
      obd_resp[3] = (uint8_t)(shutdown_delay_2 >> 0x18);
      obd_resp[4] = (uint8_t)(shutdown_delay_2 >> 0x10);
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)shutdown_delay_2;
      break;
    case 0x22a:
      uVar3 = 4;
      obd_resp[3] = load_5;
      break;
    case 0x22b:
      obd_resp[3] = (uint8_t)((ushort)vvt_diff >> 8);
      obd_resp[4] = (uint8_t)vvt_diff;
      uVar3 = 5;
      break;
    case 0x22c:
      obd_resp[3] = (uint8_t)((ushort)engine_speed_idle_error >> 8);
      obd_resp[4] = (uint8_t)engine_speed_idle_error;
      uVar3 = 5;
      break;
    case 0x22d:
      obd_resp[3] = (uint8_t)(ecu_runtime >> 8);
      obd_resp[4] = (uint8_t)ecu_runtime;
      uVar3 = 5;
      break;
    case 0x22e:
      uVar3 = 5;
      obd_resp[3] = uVar1;
      obd_resp[4] = (uint8_t)LEA_ltft_zone1_adj;
      break;
    case 0x22f:
      uVar3 = 5;
      obd_resp[3] = (uint8_t)(evap_concentration_2 >> 8);
      obd_resp[4] = (uint8_t)evap_concentration_2;
      break;
    case 0x231:
      obd_resp[3] = knock_retard1[0];
      obd_resp[4] = knock_retard1[1];
      uVar3 = 7;
      obd_resp._5_2_ = CONCAT11(knock_retard1[2],knock_retard1[3]);
      break;
    case 0x232:
      uVar3 = 5;
      obd_resp[3] = (uint8_t)((ushort)idle_flow_adj5_or_zero >> 8);
      obd_resp[4] = (uint8_t)idle_flow_adj5_or_zero;
      break;
    case 0x233:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)idle_flow_adj8;
      obd_resp[3] = (uint8_t)((uint)idle_flow_adj8 >> 0x18);
      obd_resp[4] = (uint8_t)((uint)idle_flow_adj8 >> 0x10);
      break;
    case 0x234:
      uVar3 = 5;
      obd_resp[3] = (uint8_t)(misfire_count[0] >> 8);
      obd_resp[4] = (uint8_t)misfire_count[0];
      break;
    case 0x235:
      uVar3 = 5;
      obd_resp[3] = (uint8_t)(misfire_count[1] >> 8);
      obd_resp[4] = (uint8_t)misfire_count[1];
      break;
    case 0x236:
      uVar3 = 5;
      obd_resp[3] = (uint8_t)(misfire_count[2] >> 8);
      obd_resp[4] = (uint8_t)misfire_count[2];
      break;
    case 0x237:
      uVar3 = 5;
      obd_resp[3] = (uint8_t)(misfire_count[3] >> 8);
      obd_resp[4] = (uint8_t)misfire_count[3];
      break;
    case 0x238:
      uVar3 = 5;
      obd_resp[3] = (uint8_t)(misfire_max_result >> 8);
      obd_resp[4] = (uint8_t)misfire_max_result;
      break;
    case 0x239:
      uVar3 = 5;
      obd_resp[3] = (uint8_t)(misfire_cat_max_result >> 8);
      obd_resp[4] = (uint8_t)misfire_cat_max_result;
      break;
    case 0x23a:
      uVar3 = 5;
      obd_resp[3] = (uint8_t)(fuel_learn_timer >> 8);
      obd_resp[4] = (uint8_t)fuel_learn_timer;
      break;
    case 0x23b:
      uVar3 = 5;
      obd_resp[3] = (uint8_t)(tps_target_smooth >> 8);
      obd_resp[4] = (uint8_t)tps_target_smooth;
      break;
    case 0x23c:
      uVar3 = 5;
      obd_resp[3] = (uint8_t)((ushort)LEA_idle_flow_adj1_ac_on >> 8);
      obd_resp[4] = (uint8_t)LEA_idle_flow_adj1_ac_on;
      break;
    case 0x23d:
      uVar3 = 5;
      obd_resp[3] = (uint8_t)(wheel_speed_rl >> 8);
      obd_resp[4] = (uint8_t)wheel_speed_rl;
      break;
    case 0x23e:
      uVar3 = 5;
      obd_resp[3] = (uint8_t)(wheel_speed_rr >> 8);
      obd_resp[4] = (uint8_t)wheel_speed_rr;
      break;
    case 0x23f:
      uVar3 = 5;
      obd_resp[3] = (uint8_t)(wheel_speed_fl >> 8);
      obd_resp[4] = (uint8_t)wheel_speed_fl;
      break;
    case 0x240:
      obd_resp[3] = DAT_003f8548;
      obd_resp[4] = DAT_003f8549;
      uVar3 = 7;
      obd_resp._5_2_ = CONCAT11(DAT_003f9378,DAT_003f9379);
      break;
    case 0x241:
      uVar3 = 5;
      obd_resp[3] = (uint8_t)(wheel_speed_fr >> 8);
      obd_resp[4] = (uint8_t)wheel_speed_fr;
      break;
    case 0x242:
      uVar3 = 4;
      obd_resp[3] = tc_slip;
      break;
    case 0x243:
      uVar3 = 4;
      obd_resp[3] = tc_slip_target;
      break;
    case 0x244:
      uVar3 = 5;
      obd_resp[3] = (uint8_t)(cat_diag_pre_o2_timer >> 8);
      obd_resp[4] = (uint8_t)cat_diag_pre_o2_timer;
      break;
    case 0x245:
      uVar3 = 5;
      obd_resp[3] = (uint8_t)(tps_max >> 8);
      obd_resp[4] = (uint8_t)tps_max;
      break;
    case 0x246:
      uVar3 = 5;
      obd_resp[3] = (uint8_t)((ushort)pps_min >> 8);
      obd_resp[4] = (uint8_t)pps_min;
      break;
    case 0x247:
      uVar3 = 5;
      obd_resp[3] = (uint8_t)((ushort)evap_leak_result >> 8);
      obd_resp[4] = (uint8_t)evap_leak_result;
      break;
    case 0x248:
      uVar3 = 4;
      obd_resp[3] = LEA_ltft_zone2_adj;
      break;
    case 0x249:
      uVar3 = 4;
      obd_resp[3] = LEA_ltft_zone3_adj;
      break;
    case 0x24a:
      uVar3 = 5;
      obd_resp[3] = uVar1;
      obd_resp[4] = (uint8_t)LEA_ltft_zone1_adj;
      break;
    case 0x300:
      obd_resp[3] = DAT_003f854a;
      obd_resp[4] = DAT_003f854b;
      uVar3 = 7;
      obd_resp._5_2_ = CONCAT11(DAT_003f854c,DAT_003f854d);
      break;
    case 0x301:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_time_at_TPS[0];
      obd_resp[3] = (uint8_t)(LEA_perf_time_at_TPS[0] >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_time_at_TPS[0] >> 0x10);
      break;
    case 0x302:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_time_at_TPS[1];
      obd_resp[3] = (uint8_t)(LEA_perf_time_at_TPS[1] >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_time_at_TPS[1] >> 0x10);
      break;
    case 0x303:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_time_at_TPS[2];
      obd_resp[3] = (uint8_t)(LEA_perf_time_at_TPS[2] >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_time_at_TPS[2] >> 0x10);
      break;
    case 0x304:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_time_at_TPS[3];
      obd_resp[3] = (uint8_t)(LEA_perf_time_at_TPS[3] >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_time_at_TPS[3] >> 0x10);
      break;
    case 0x305:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_time_at_TPS[4];
      obd_resp[3] = (uint8_t)(LEA_perf_time_at_TPS[4] >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_time_at_TPS[4] >> 0x10);
      break;
    case 0x306:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_time_at_TPS[5];
      obd_resp[3] = (uint8_t)(LEA_perf_time_at_TPS[5] >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_time_at_TPS[5] >> 0x10);
      break;
    case 0x307:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_time_at_TPS[6];
      obd_resp[3] = (uint8_t)(LEA_perf_time_at_TPS[6] >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_time_at_TPS[6] >> 0x10);
      break;
    case 0x308:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_time_at_TPS[7];
      obd_resp[3] = (uint8_t)(LEA_perf_time_at_TPS[7] >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_time_at_TPS[7] >> 0x10);
      break;
    case 0x309:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_time_at_RPM[0];
      obd_resp[3] = (uint8_t)(LEA_perf_time_at_RPM[0] >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_time_at_RPM[0] >> 0x10);
      break;
    case 0x30a:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_time_at_RPM[1];
      obd_resp[3] = (uint8_t)(LEA_perf_time_at_RPM[1] >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_time_at_RPM[1] >> 0x10);
      break;
    case 0x30b:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_time_at_RPM[2];
      obd_resp[3] = (uint8_t)(LEA_perf_time_at_RPM[2] >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_time_at_RPM[2] >> 0x10);
      break;
    case 0x30c:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_time_at_RPM[3];
      obd_resp[3] = (uint8_t)(LEA_perf_time_at_RPM[3] >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_time_at_RPM[3] >> 0x10);
      break;
    case 0x30d:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_time_at_RPM[4];
      obd_resp[3] = (uint8_t)(LEA_perf_time_at_RPM[4] >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_time_at_RPM[4] >> 0x10);
      break;
    case 0x30e:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_time_at_RPM[5];
      obd_resp[3] = (uint8_t)(LEA_perf_time_at_RPM[5] >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_time_at_RPM[5] >> 0x10);
      break;
    case 0x30f:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_time_at_RPM[6];
      obd_resp[3] = (uint8_t)(LEA_perf_time_at_RPM[6] >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_time_at_RPM[6] >> 0x10);
      break;
    case 0x310:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_time_at_RPM[7];
      obd_resp[3] = (uint8_t)(LEA_perf_time_at_RPM[7] >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_time_at_RPM[7] >> 0x10);
      break;
    case 0x311:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_time_at_KMH[0];
      obd_resp[3] = (uint8_t)(LEA_perf_time_at_KMH[0] >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_time_at_KMH[0] >> 0x10);
      break;
    case 0x312:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_time_at_KMH[1];
      obd_resp[3] = (uint8_t)(LEA_perf_time_at_KMH[1] >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_time_at_KMH[1] >> 0x10);
      break;
    case 0x313:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_time_at_KMH[2];
      obd_resp[3] = (uint8_t)(LEA_perf_time_at_KMH[2] >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_time_at_KMH[2] >> 0x10);
      break;
    case 0x314:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_time_at_KMH[3];
      obd_resp[3] = (uint8_t)(LEA_perf_time_at_KMH[3] >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_time_at_KMH[3] >> 0x10);
      break;
    case 0x315:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_time_at_KMH[4];
      obd_resp[3] = (uint8_t)(LEA_perf_time_at_KMH[4] >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_time_at_KMH[4] >> 0x10);
      break;
    case 0x316:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_time_at_KMH[5];
      obd_resp[3] = (uint8_t)(LEA_perf_time_at_KMH[5] >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_time_at_KMH[5] >> 0x10);
      break;
    case 0x317:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_time_at_KMH[6];
      obd_resp[3] = (uint8_t)(LEA_perf_time_at_KMH[6] >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_time_at_KMH[6] >> 0x10);
      break;
    case 0x318:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_time_at_KMH[7];
      obd_resp[3] = (uint8_t)(LEA_perf_time_at_KMH[7] >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_time_at_KMH[7] >> 0x10);
      break;
    case 0x319:
      obd_resp[3] = DAT_003f8548;
      obd_resp[4] = DAT_003f8549;
      uVar3 = 7;
      obd_resp._5_2_ = CONCAT11(DAT_003f9378,DAT_003f9379);
      break;
    case 0x31a:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_time_at_coolant_temp[0];
      obd_resp[3] = (uint8_t)(LEA_perf_time_at_coolant_temp[0] >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_time_at_coolant_temp[0] >> 0x10);
      break;
    case 0x31b:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_time_at_coolant_temp[1];
      obd_resp[3] = (uint8_t)(LEA_perf_time_at_coolant_temp[1] >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_time_at_coolant_temp[1] >> 0x10);
      break;
    case 0x31c:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_time_at_coolant_temp[2];
      obd_resp[3] = (uint8_t)(LEA_perf_time_at_coolant_temp[2] >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_time_at_coolant_temp[2] >> 0x10);
      break;
    case 0x31d:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_time_at_coolant_temp[3];
      obd_resp[3] = (uint8_t)(LEA_perf_time_at_coolant_temp[3] >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_time_at_coolant_temp[3] >> 0x10);
      break;
    case 0x31e:
      obd_resp[3] = 0;
      obd_resp[4] = 0;
      uVar3 = 7;
      obd_resp._5_2_ = LEA_perf_max_engine_speed[0];
      break;
    case 799:
      obd_resp[3] = 0;
      obd_resp[4] = 0;
      uVar3 = 7;
      obd_resp._5_2_ = LEA_perf_max_engine_speed[1];
      break;
    case 800:
      obd_resp[3] = DAT_003f854e;
      obd_resp[4] = DAT_003f854f;
      uVar3 = 7;
      obd_resp._5_2_ = CONCAT11(DAT_003f8550,DAT_003f8551);
      break;
    case 0x321:
      obd_resp[3] = 0;
      obd_resp[4] = 0;
      uVar3 = 7;
      obd_resp._5_2_ = LEA_perf_max_engine_speed[2];
      break;
    case 0x322:
      obd_resp[3] = 0;
      obd_resp[4] = 0;
      uVar3 = 7;
      obd_resp._5_2_ = LEA_perf_max_engine_speed[3];
      break;
    case 0x323:
      obd_resp[3] = 0;
      obd_resp[4] = 0;
      uVar3 = 7;
      obd_resp._5_2_ = LEA_perf_max_engine_speed[4];
      break;
    case 0x324:
      obd_resp[3] = 0;
      obd_resp[4] = 0;
      uVar3 = 7;
      obd_resp._5_2_ = ZEXT12(LEA_perf_max_engine_speed_5_coolant_temp);
      break;
    case 0x325:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_max_engine_speed_5_run_timer;
      obd_resp[3] = (uint8_t)(LEA_perf_max_engine_speed_5_run_timer >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_max_engine_speed_5_run_timer >> 0x10);
      break;
    case 0x326:
      obd_resp[3] = 0;
      obd_resp[4] = 0;
      uVar3 = 7;
      obd_resp._5_2_ = ZEXT12(LEA_perf_max_engine_speed_4_coolant_temp);
      break;
    case 0x327:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_max_engine_speed_4_run_timer;
      obd_resp[3] = (uint8_t)(LEA_perf_max_engine_speed_4_run_timer >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_max_engine_speed_4_run_timer >> 0x10);
      break;
    case 0x328:
      obd_resp[3] = 0;
      obd_resp[4] = 0;
      uVar3 = 7;
      obd_resp._5_2_ = ZEXT12(LEA_perf_max_engine_speed_3_coolant_temp);
      break;
    case 0x329:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_max_engine_speed_3_run_timer;
      obd_resp[3] = (uint8_t)(LEA_perf_max_engine_speed_3_run_timer >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_max_engine_speed_3_run_timer >> 0x10);
      break;
    case 0x32a:
      obd_resp[3] = 0;
      obd_resp[4] = 0;
      uVar3 = 7;
      obd_resp._5_2_ = ZEXT12(LEA_perf_max_engine_speed_2_coolant_temp);
      break;
    case 0x32b:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_max_engine_speed_2_run_timer;
      obd_resp[3] = (uint8_t)(LEA_perf_max_engine_speed_2_run_timer >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_max_engine_speed_2_run_timer >> 0x10);
      break;
    case 0x32c:
      obd_resp[3] = 0;
      obd_resp[4] = 0;
      uVar3 = 7;
      obd_resp._5_2_ = ZEXT12(LEA_perf_max_engine_speed_1_coolant_temp);
      break;
    case 0x32d:
      obd_resp[3] = DAT_003f8551;
      obd_resp[4] = DAT_003f937a;
      uVar3 = 7;
      obd_resp._5_2_ = CONCAT11(DAT_003f937b,DAT_003f937c);
      break;
    case 0x32e:
      uVar3 = 7;
      obd_resp._5_2_ = (undefined2)LEA_perf_max_engine_speed_1_run_timer;
      obd_resp[3] = (uint8_t)(LEA_perf_max_engine_speed_1_run_timer >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_max_engine_speed_1_run_timer >> 0x10);
      break;
    case 0x32f:
      uVar3 = 4;
      obd_resp[3] = LEA_perf_max_vehicle_speed[0];
      break;
    case 0x330:
      uVar3 = 4;
      obd_resp[3] = LEA_perf_max_vehicle_speed[1];
      break;
    case 0x331:
      uVar3 = 4;
      obd_resp[3] = LEA_perf_max_vehicle_speed[2];
      break;
    case 0x332:
      uVar3 = 4;
      obd_resp[3] = LEA_perf_max_vehicle_speed[3];
      break;
    case 0x333:
      uVar3 = 4;
      obd_resp[3] = LEA_perf_max_vehicle_speed[4];
      break;
    case 0x334:
      uVar3 = 4;
      obd_resp[3] = LEA_perf_fastest_standing_start[0];
      break;
    case 0x335:
      uVar3 = 4;
      obd_resp[3] = LEA_perf_fastest_standing_start[1];
      break;
    case 0x336:
      uVar3 = 4;
      obd_resp[3] = LEA_perf_last_standing_start[0];
      break;
    case 0x337:
      uVar3 = 4;
      obd_resp[3] = LEA_perf_last_standing_start[1];
      break;
    case 0x338:
      obd_resp._5_2_ = (undefined2)LEA_perf_engine_run_timer;
      uVar3 = 7;
      obd_resp[3] = (uint8_t)(LEA_perf_engine_run_timer >> 0x18);
      obd_resp[4] = (uint8_t)(LEA_perf_engine_run_timer >> 0x10);
      break;
    case 0x339:
      uVar3 = 5;
      obd_resp[3] = (uint8_t)(LEA_perf_number_of_standing_starts >> 8);
      obd_resp[4] = (uint8_t)LEA_perf_number_of_standing_starts;
    }
  }
  if (uVar3 < 4) {
    DAT_003fda00 = 1;
    uVar3 = obd_resp._5_2_;
  }
  else {
    obd_resp_len = uVar3;
    send_obd_resp();
    uVar3 = obd_resp._5_2_;
  }
  obd_resp[5] = (uint8_t)(uVar3 >> 8);
  obd_resp[6] = (uint8_t)uVar3;
  return;
}



// OBD Mode 2F: Output test/control (Lotus-specific)

void obd_mode_0x2F_test(void)

{
  ushort uVar1;
  
  push_22to31();
  uVar1 = 1;
  obd_resp[0] = 111;
  if (true) {
    switch(CONCAT11(obd_req[2],obd_req[3])) {
    case 0x100:
      obd_resp[1] = obd_req[2];
      obd_resp[2] = obd_req[3];
      obd_resp[3] = DAT_003f8a40;
      obd_resp[4] = DAT_003f9380;
      obd_resp[5] = DAT_003f9381;
      uVar1 = 7;
      obd_resp[6] = DAT_003f8a41;
      break;
    case 0x101:
      if (((DAT_003fe18c == 0) && (engine_speed_1 == 0)) && (DAT_003fc5a2 != 0)) {
        obd_mode_0x2F_value = obd_req[4];
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
        obd_mode_0x2F_timer = DAT_003fc5a2;
        obd_mode_0x2F_state = 1;
        obd_resp[1] = obd_req[2];
        obd_resp[2] = obd_req[3];
        uVar1 = 4;
        obd_resp[3] = obd_req[4];
      }
      else {
        obd_negative_response();
      }
      break;
    case 0x102:
      if (((DAT_003fe18c == 0) && (engine_speed_1 == 0)) && (DAT_003fc5a2 != 0)) {
        obd_mode_0x2F_value = obd_req[4];
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
        obd_mode_0x2F_timer = DAT_003fc5a2;
        obd_resp[1] = obd_req[2];
        obd_resp[2] = obd_req[3];
        uVar1 = 4;
        obd_resp[3] = obd_req[4];
      }
      else {
        obd_negative_response();
      }
      break;
    case 0x103:
      if (((DAT_003fe18c == 0) && (engine_speed_1 == 0)) && (DAT_003fc5a2 != 0)) {
        obd_mode_0x2F_value = obd_req[4];
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
        obd_mode_0x2F_timer = DAT_003fc5a2;
        obd_resp[1] = obd_req[2];
        obd_resp[2] = obd_req[3];
        uVar1 = 4;
        obd_resp[3] = obd_req[4];
      }
      else {
        obd_negative_response();
      }
      break;
    case 0x104:
      if (((DAT_003fe18c == 0) && (engine_speed_1 == 0)) && (DAT_003fc5a2 != 0)) {
        obd_mode_0x2F_value = obd_req[4];
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
        obd_mode_0x2F_timer = DAT_003fc5a2;
        obd_resp[1] = obd_req[2];
        obd_resp[2] = obd_req[3];
        uVar1 = 4;
        obd_resp[3] = obd_req[4];
      }
      else {
        obd_negative_response();
      }
      break;
    case 0x120:
      obd_resp[1] = obd_req[2];
      obd_resp[2] = obd_req[3];
      obd_resp[3] = DAT_003f8a42;
      obd_resp[4] = DAT_003f9382;
      obd_resp[5] = DAT_003f9383;
      uVar1 = 7;
      obd_resp[6] = DAT_003f8a43;
      break;
    case 0x121:
      if ((DAT_003fe18c == 0) && (engine_speed_1 == 0)) {
        obd_mode_0x2F_value = obd_req[4];
        if (obd_req[4] < 4) {
          obd_mode_0x2F_value = 4;
        }
        obd_mode_0x2F_state = 9;
        obd_mode_0x2F_timer = DAT_003fc598;
        obd_resp[1] = obd_req[2];
        obd_resp[2] = obd_req[3];
        uVar1 = 4;
        obd_resp[3] = obd_req[4];
      }
      else {
        obd_negative_response();
      }
      break;
    case 0x122:
      if ((DAT_003fe18c == 0) && (engine_speed_1 == 0)) {
        obd_mode_0x2F_value = obd_req[4];
        if (obd_req[4] < 4) {
          obd_mode_0x2F_value = 4;
        }
        obd_mode_0x2F_state = 10;
        obd_mode_0x2F_timer = DAT_003fc59a;
        obd_resp[1] = obd_req[2];
        obd_resp[2] = obd_req[3];
        uVar1 = 4;
        obd_resp[3] = obd_req[4];
      }
      else {
        obd_negative_response();
      }
      break;
    case 0x125:
      if (((DAT_003fe18c == 0) && (engine_speed_1 == 0)) && (DAT_003fc5b2 != 0)) {
        obd_mode_0x2F_value = obd_req[4];
        if (obd_req[4] < 4) {
          obd_mode_0x2F_value = 4;
        }
        obd_mode_0x2F_state = 0xc;
        obd_mode_0x2F_timer = DAT_003fc5b2;
        obd_resp[1] = obd_req[2];
        obd_resp[2] = obd_req[3];
        uVar1 = 4;
        obd_resp[3] = obd_req[4];
      }
      else {
        obd_negative_response();
      }
      break;
    case 0x126:
      if (((DAT_003fe18c == 0) && (engine_speed_1 == 0)) && (DAT_003fc5b4 != 0)) {
        obd_mode_0x2F_value = obd_req[4];
        if (obd_req[4] < 4) {
          obd_mode_0x2F_value = 4;
        }
        obd_mode_0x2F_timer = DAT_003fc5b4;
        obd_mode_0x2F_state = 0xb;
        obd_resp[1] = obd_req[2];
        obd_resp[2] = obd_req[3];
        uVar1 = 4;
        obd_resp[3] = obd_req[4];
      }
      else {
        obd_negative_response();
      }
      break;
    case 0x127:
      obd_mode_0x2F_value = obd_req[4];
      if (obd_req[4] < 4) {
        obd_mode_0x2F_value = 4;
      }
      obd_mode_0x2F_state = 0xd;
      obd_mode_0x2F_timer = DAT_003fc5a4;
      obd_resp[1] = obd_req[2];
      obd_resp[2] = obd_req[3];
      uVar1 = 4;
      obd_resp[3] = obd_req[4];
      break;
    case 0x12a:
      obd_mode_0x2F_value = obd_req[4];
      if (obd_req[4] < 4) {
        obd_mode_0x2F_value = 4;
      }
      obd_mode_0x2F_state = 0xe;
      obd_mode_0x2F_timer = DAT_003fc5ac;
      obd_resp[1] = obd_req[2];
      obd_resp[2] = obd_req[3];
      uVar1 = 4;
      obd_resp[3] = obd_req[4];
      break;
    case 0x140:
      obd_resp[1] = obd_req[2];
      obd_resp[2] = obd_req[3];
      obd_resp[3] = DAT_003f8a44;
      obd_resp[4] = DAT_003f8a45;
      obd_resp[5] = DAT_003f9384;
      uVar1 = 7;
      obd_resp[6] = DAT_003f8a46;
      break;
    case 0x141:
      if (((DAT_003fe18c == 0) && (engine_speed_1 == 0)) && (DAT_003fc5bc != 0)) {
        DAT_003fe18e = obd_mode_0x2F_value == obd_req[4];
        DAT_003fe18f = 1;
        obd_mode_0x2F_state = 0xf;
        obd_mode_0x2F_timer = DAT_003fc5bc;
        obd_resp[1] = obd_req[2];
        obd_resp[2] = obd_req[3];
        uVar1 = 4;
        obd_resp[3] = obd_req[4];
      }
      else {
        obd_negative_response();
      }
      break;
    case 0x142:
      if (DAT_003fc516 == 0) {
        obd_negative_response();
      }
      else {
        obd_mode_0x2F_value = obd_req[4];
        obd_mode_0x2F_state = 0x16;
        obd_mode_0x2F_timer = DAT_003fc516;
        obd_resp[1] = obd_req[2];
        obd_resp[2] = obd_req[3];
        uVar1 = 4;
        obd_resp[3] = obd_req[4];
      }
      break;
    case 0x143:
      if (((DAT_003fe18c == 0) && (engine_speed_1 == 0)) && (DAT_003fc5be != 0)) {
        obd_mode_0x2F_value = obd_req[4];
        obd_mode_0x2F_state = 0x15;
        obd_mode_0x2F_timer = DAT_003fc5be;
        obd_resp[1] = obd_req[2];
        obd_resp[2] = obd_req[3];
        uVar1 = 4;
        obd_resp[3] = obd_req[4];
      }
      else {
        obd_negative_response();
      }
      break;
    case 0x144:
      if (((DAT_003fe18c == 0) && (engine_speed_1 == 0)) && (DAT_003fc5c0 != 0)) {
        obd_mode_0x2F_value = obd_req[4];
        obd_mode_0x2F_state = 0x14;
        obd_mode_0x2F_timer = DAT_003fc5c0;
        obd_resp[1] = obd_req[2];
        obd_resp[2] = obd_req[3];
        uVar1 = 4;
        obd_resp[3] = obd_req[4];
      }
      else {
        obd_negative_response();
      }
      break;
    case 0x146:
      if (((DAT_003fe18c == 0) && (engine_speed_1 == 0)) && (DAT_003fc5c2 != 0)) {
        if (obd_mode_0x2F_value == obd_req[4]) {
          DAT_003fe18e = 0x10;
        }
        else {
          DAT_003fe18e = 0;
        }
        DAT_003fe18f = 0x10;
        obd_mode_0x2F_state = 0x10;
        obd_mode_0x2F_timer = DAT_003fc5c2;
        obd_resp[1] = obd_req[2];
        obd_resp[2] = obd_req[3];
        uVar1 = 4;
        obd_resp[3] = obd_req[4];
      }
      else {
        obd_negative_response();
      }
      break;
    case 0x147:
      if (((DAT_003fe18c == 0) && (engine_speed_1 == 0)) && (DAT_003fc5c4 != 0)) {
        obd_mode_0x2F_value = obd_req[4];
        obd_mode_0x2F_state = 0x11;
        obd_mode_0x2F_timer = DAT_003fc5c4;
        obd_resp[1] = obd_req[2];
        obd_resp[2] = obd_req[3];
        uVar1 = 4;
        obd_resp[3] = obd_req[4];
      }
      else {
        obd_negative_response();
      }
      break;
    case 0x148:
      if (((DAT_003fe18c == 0) && (engine_speed_1 == 0)) && (DAT_003fc5c4 != 0)) {
        obd_mode_0x2F_value = obd_req[4];
        obd_mode_0x2F_state = 0x17;
        obd_mode_0x2F_timer = DAT_003fc5c4;
        obd_resp[1] = obd_req[2];
        obd_resp[2] = obd_req[3];
        uVar1 = 4;
        obd_resp[3] = obd_req[4];
      }
      else {
        obd_negative_response();
      }
      break;
    case 0x149:
      if (((DAT_003fe18c == 0) && (engine_speed_1 == 0)) && (DAT_003fc5a4 != 0)) {
        obd_mode_0x2F_value = obd_req[4];
        obd_mode_0x2F_state = 0x18;
        obd_mode_0x2F_timer = DAT_003fc5a4;
        obd_resp[1] = obd_req[2];
        obd_resp[2] = obd_req[3];
        uVar1 = 4;
        obd_resp[3] = obd_req[4];
      }
      else {
        obd_negative_response();
      }
      break;
    case 0x14a:
      if (((DAT_003fe18c == 0) && (engine_speed_1 == 0)) && (DAT_003fc5c6 != 0)) {
        if (obd_mode_0x2F_value == obd_req[4]) {
          DAT_003fe18e = 8;
        }
        else {
          DAT_003fe18e = 0;
        }
        DAT_003fe18f = 8;
        obd_mode_0x2F_state = 0x12;
        obd_mode_0x2F_timer = DAT_003fc5c6;
        obd_resp[1] = obd_req[2];
        obd_resp[2] = obd_req[3];
        uVar1 = 4;
        obd_resp[3] = obd_req[4];
      }
      else {
        obd_negative_response();
      }
      break;
    case 0x14b:
      if (((DAT_003fe18c == 0) && (engine_speed_1 == 0)) && (DAT_003fc5c6 != 0)) {
        if (obd_mode_0x2F_value == obd_req[4]) {
          DAT_003fe18e = 4;
        }
        else {
          DAT_003fe18e = 0;
        }
        DAT_003fe18f = 4;
        obd_mode_0x2F_state = 0x13;
        obd_mode_0x2F_timer = DAT_003fc5c6;
        obd_resp[1] = obd_req[2];
        obd_resp[2] = obd_req[3];
        uVar1 = 4;
        obd_resp[3] = obd_req[4];
      }
      else {
        obd_negative_response();
      }
      break;
    case 0x160:
      obd_resp[1] = obd_req[2];
      obd_resp[2] = obd_req[3];
      obd_resp[3] = DAT_003f9385;
      obd_resp[4] = DAT_003f9386;
      obd_resp[5] = DAT_003f9387;
      uVar1 = 7;
      obd_resp[6] = DAT_003f9388;
      break;
    case 0x161:
      if (((DAT_003fe18c == 0) && (engine_speed_1 == 0)) && (DAT_003fc5ba != 0)) {
        obd_mode_0x2F_value = obd_req[4];
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
        obd_mode_0x2F_timer = DAT_003fc5ba;
        obd_resp[1] = obd_req[2];
        obd_resp[2] = obd_req[3];
        uVar1 = 4;
        obd_resp[3] = obd_req[4];
      }
      else {
        obd_negative_response();
      }
      break;
    case 0x162:
      if (((DAT_003fe18c == 0) && (engine_speed_1 == 0)) && (DAT_003fc5ba != 0)) {
        obd_mode_0x2F_value = obd_req[4];
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
        obd_mode_0x2F_timer = DAT_003fc5ba;
        obd_resp[1] = obd_req[2];
        obd_resp[2] = obd_req[3];
        uVar1 = 4;
        obd_resp[3] = obd_req[4];
      }
      else {
        obd_negative_response();
      }
      break;
    case 0x163:
      if (((DAT_003fe18c == 0) && (engine_speed_1 == 0)) && (DAT_003fc5ba != 0)) {
        obd_mode_0x2F_value = obd_req[4];
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
        obd_mode_0x2F_timer = DAT_003fc5ba;
        obd_resp[1] = obd_req[2];
        obd_resp[2] = obd_req[3];
        uVar1 = 4;
        obd_resp[3] = obd_req[4];
      }
      else {
        obd_negative_response();
      }
      break;
    case 0x164:
      if (((DAT_003fe18c == 0) && (engine_speed_1 == 0)) && (DAT_003fc5ba != 0)) {
        obd_mode_0x2F_value = obd_req[4];
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
        obd_mode_0x2F_timer = DAT_003fc5ba;
        obd_resp[1] = obd_req[2];
        obd_resp[2] = obd_req[3];
        uVar1 = 4;
        obd_resp[3] = obd_req[4];
      }
      else {
        obd_negative_response();
      }
    }
  }
  if (uVar1 < 2) {
    DAT_003fda00 = 1;
  }
  else {
    obd_resp_len = uVar1;
    send_obd_resp();
  }
  pop_22to31();
  return;
}



// Sends OBD negative response (error)

void obd_negative_response(void)

{
  obd_resp[0] = 127;
  obd_resp[1] = obd_req[1];
  obd_resp[2] = 34;
  obd_resp_len = 3;
  send_obd_resp();
  return;
}



// OBD Mode 2F test handler (5ms)

void obd_mode_0x2F_test_5ms(void)

{
  ushort uVar1;
  
  push_24to31();
  if (engine_speed_1 == 0) {
    if (DAT_003fe18c != 0) {
      DAT_003fe18c = DAT_003fe18c + -1;
    }
  }
  else {
    DAT_003fe18c = DAT_003fc59c;
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
        obd_mode_0x2F_pulse_interval = DAT_003fc59e;
        uVar1 = REG_CFSR3_B;
        if ((uVar1 >> 4 & 0xf) == 0xe) {
          REG_TPU3B_CH1_PARAM1 = DAT_003fc5a0;
          uVar1 = REG_HSRR1_B;
          REG_HSRR1_B = uVar1 & 0xfff3 | 4;
          do {
            uVar1 = REG_HSRR1_B;
          } while (uVar1 != 0);
        }
        DAT_003f96b8 = 1;
        spi_pcs1();
        DAT_003f96b8 = 0;
        TLE6220_fault_check();
        if ((DAT_003fdc1c & 1) != 0) {
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
        obd_mode_0x2F_pulse_interval = DAT_003fc59e;
        uVar1 = REG_CFSR3_B;
        if ((uVar1 >> 8 & 0xf) == 0xe) {
          REG_TPU3B_CH2_PARAM1 = DAT_003fc5a0;
          uVar1 = REG_HSRR1_B;
          REG_HSRR1_B = uVar1 & 0xffcf | 0x10;
          do {
            uVar1 = REG_HSRR1_B;
          } while (uVar1 != 0);
        }
        DAT_003f96b8 = 1;
        spi_pcs1();
        DAT_003f96b8 = 0;
        TLE6220_fault_check();
        if ((DAT_003fdc1c & 0x10) != 0) {
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
        obd_mode_0x2F_pulse_interval = DAT_003fc59e;
        uVar1 = REG_CFSR3_B;
        if (uVar1 >> 0xc == 0xe) {
          REG_TPU3B_CH3_PARAM1 = DAT_003fc5a0;
          uVar1 = REG_HSRR1_B;
          REG_HSRR1_B = uVar1 & 0xff3f | 0x40;
          do {
            uVar1 = REG_HSRR1_B;
          } while (uVar1 != 0);
        }
        DAT_003f96b8 = 1;
        spi_pcs1();
        DAT_003f96b8 = 0;
        TLE6220_fault_check();
        if ((DAT_003fdc1c & 0x40) != 0) {
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
        obd_mode_0x2F_pulse_interval = DAT_003fc59e;
        uVar1 = REG_CFSR2_B;
        if ((uVar1 & 0xf) == 0xe) {
          REG_TPU3B_CH4_PARAM1 = DAT_003fc5a0;
          uVar1 = REG_HSRR1_B;
          REG_HSRR1_B = uVar1 & 0xfcff | 0x100;
          do {
            uVar1 = REG_HSRR1_B;
          } while (uVar1 != 0);
        }
        DAT_003f96b8 = 1;
        spi_pcs1();
        DAT_003f96b8 = 0;
        TLE6220_fault_check();
        if ((DAT_003fdc1c & 4) != 0) {
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
        obd_mode_0x2F_pulse_interval = DAT_003fc5b9;
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
        obd_mode_0x2F_pulse_interval = DAT_003fc5b9;
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
        obd_mode_0x2F_pulse_interval = DAT_003fc5b9;
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
        obd_mode_0x2F_pulse_interval = DAT_003fc5b9;
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
      DAT_003f96bf = 0;
      obd_mode_0x2F_state = 0;
    }
    else {
      DAT_003f96bf = obd_mode_0x2F_value;
    }
    break;
  case 0xf:
    if (obd_mode_0x2F_timer == 0) {
      DAT_003fe18f = 0;
      DAT_003fe18e = 0;
      obd_mode_0x2F_state = 0;
    }
    break;
  case 0x10:
    if (obd_mode_0x2F_timer == 0) {
      DAT_003fe18f = 0;
      DAT_003fe18e = 0;
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
      DAT_003fe18f = 0;
      DAT_003fe18e = 0;
      obd_mode_0x2F_state = 0;
    }
    break;
  case 0x13:
    if (obd_mode_0x2F_timer == 0) {
      DAT_003fe18f = 0;
      DAT_003fe18e = 0;
      obd_mode_0x2F_state = 0;
    }
    break;
  case 0x14:
    if (obd_mode_0x2F_timer == 0) {
      DAT_003fe18f = 0;
      DAT_003fe18e = 0;
      obd_mode_0x2F_state = 0;
    }
    break;
  case 0x15:
    if (obd_mode_0x2F_timer == 0) {
      DAT_003fe18f = 0;
      DAT_003fe18e = 0;
      obd_mode_0x2F_state = 0;
    }
    break;
  case 0x16:
    if (obd_mode_0x2F_timer == 0) {
      DAT_003fe18f = 0;
      DAT_003fe18e = 0;
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
  pop_24to31();
  return;
}



// OBD Mode 3B: Writes VIN to EEPROM

void obd_mode_0x3B_VIN(void)

{
  byte bVar1;
  
  obd_resp[0] = 123;
  if (obd_req[2] == 3) {
    LEA_ecu_VIN[0xb] = obd_req[3];
    LEA_ecu_VIN[0xc] = obd_req[4];
    LEA_ecu_VIN[0xd] = obd_req[5];
    LEA_ecu_VIN[0xe] = obd_req[6];
    obd_resp[1] = obd_req[2];
    obd_resp_len = 2;
    send_obd_resp();
  }
  else if (obd_req[2] < 3) {
    if (obd_req[2] == 1) {
      LEA_ecu_VIN[3] = obd_req[3];
      LEA_ecu_VIN[4] = obd_req[4];
      LEA_ecu_VIN[5] = obd_req[5];
      LEA_ecu_VIN[6] = obd_req[6];
      obd_resp[1] = obd_req[2];
      obd_resp_len = 2;
      send_obd_resp();
    }
    else if (obd_req[2] != 0) {
      LEA_ecu_VIN[7] = obd_req[3];
      LEA_ecu_VIN[8] = obd_req[4];
      LEA_ecu_VIN[9] = obd_req[5];
      LEA_ecu_VIN[10] = obd_req[6];
      obd_resp[1] = obd_req[2];
      obd_resp_len = 2;
      send_obd_resp();
    }
  }
  else if (obd_req[2] == 5) {
    tpms_session_handler_state = obd_req[3];
    tpms_session_handler_100ms();
    obd_resp[1] = obd_req[2];
    obd_resp_len = 2;
    send_obd_resp();
  }
  else if (obd_req[2] < 5) {
    LEA_ecu_VIN[0xf] = obd_req[3];
    LEA_ecu_VIN[0x10] = obd_req[4];
    obd_resp[1] = obd_req[2];
    obd_resp_len = 2;
    send_obd_resp();
    if ((((LEA_ecu_VIN[0xd] == '9') && (LEA_ecu_VIN[0xe] == '9')) && (LEA_ecu_VIN[0xf] == '9')) &&
       (LEA_ecu_VIN[0x10] == '9')) {
      for (bVar1 = 0; bVar1 < 0x1e; bVar1 = bVar1 + 1) {
        LEA_base[bVar1] = '1';
      }
    }
  }
  return;
}



// Initializes TPMS communication state machine

void can_b_tpms_init(void)

{
  REG_CANB_MB3_CS = 0x80;
  REG_CANB_MB3_ID_HI = 0x4400;
  REG_CANB_MB3_DATA0 = 0x19;
  REG_CANB_MB3_DATA1 = 0x81;
  REG_CANB_MB3_DATA2 = 0;
  REG_CANB_MB3_DATA3 = 0x20;
  REG_CANB_MB3_DATA4 = 2;
  REG_CANB_MB3_DATA5 = 0x40;
  REG_CANB_MB3_DATA6 = 0;
  REG_CANB_MB3_DATA7 = 0;
  REG_CANB_MB3_CS = 200;
  return;
}



// Sends TPMS request/command messages

void can_b_tpms_send(void)

{
  byte bVar3;
  byte bVar4;
  uint uVar1;
  uint uVar2;
  
  REG_CANB_MB6_CS = 0x80;
  REG_CANB_MB6_ID_HI = DAT_003fe190 << 5;
  if (DAT_003fe2c9 == 0) {
    if (DAT_003fe2c8 < 5) {
      REG_CANB_MB6_DATA0 = 0x40;
      REG_CANB_MB6_DATA1 = 0x97;
      REG_CANB_MB6_DATA2 = DAT_003fe2c8;
      for (bVar3 = 0; bVar4 = DAT_003fe2c8, bVar3 < DAT_003fe2c8; bVar3 = bVar3 + 1) {
        (&REG_CANB_MB6_DATA3)[bVar3] = (&DAT_003fe2cd)[bVar3];
      }
      for (; bVar4 < 5; bVar4 = bVar4 + 1) {
        (&REG_CANB_MB6_DATA3)[bVar4] = 0;
      }
    }
    else {
      if ((int)(DAT_003fe2c8 - 4) % 6 == 0) {
        DAT_003f9391 = (byte)((int)(DAT_003fe2c8 - 4) / 6);
      }
      else {
        DAT_003f9391 = (char)((int)(DAT_003fe2c8 - 4) / 6) + 1;
      }
      REG_CANB_MB6_DATA0 = DAT_003f9391 | 0xc0;
      REG_CANB_MB6_DATA1 = 0x97;
      REG_CANB_MB6_DATA2 = DAT_003fe2c8;
      for (bVar3 = 0; bVar3 < 5; bVar3 = bVar3 + 1) {
        (&REG_CANB_MB6_DATA3)[bVar3] = (&DAT_003fe2cd)[bVar3];
      }
      DAT_003fe2c9 = 1;
      DAT_003f9392 = 1;
    }
  }
  else {
    if (DAT_003fe2c9 < 2) {
      uVar2 = 0;
    }
    else {
      uVar2 = (DAT_003fe2c9 - 1) * 6 & 0xffff;
    }
    REG_CANB_MB6_DATA0 = DAT_003f9391 - DAT_003fe2c9 | 0x80;
    REG_CANB_MB6_DATA1 = 0x97;
    if ((uVar2 & 0xff) + 10 < (uint)DAT_003fe2c8) {
      for (bVar3 = 0; bVar3 < 6; bVar3 = bVar3 + 1) {
        (&REG_CANB_MB6_DATA2)[bVar3] = (&DAT_003fe2d2)[(uVar2 & 0xff) + (uint)bVar3];
      }
      if (DAT_003fe2c9 < 0xff) {
        DAT_003fe2c9 = DAT_003fe2c9 + 1;
      }
      else {
        DAT_003fe2c9 = 0;
      }
    }
    else {
      for (uVar1 = 0; (int)(uVar1 & 0xff) < (int)((DAT_003fe2c8 - uVar2) + -5); uVar1 = uVar1 + 1) {
        (&REG_CANB_MB6_DATA2)[uVar1 & 0xff] = (&DAT_003fe2d2)[(uVar2 & 0xff) + (uVar1 & 0xff)];
      }
      for (uVar2 = (DAT_003fe2c8 - uVar2) - 5 & 0xff; (uVar2 & 0xff) < 6; uVar2 = uVar2 + 1) {
        (&REG_CANB_MB6_DATA2)[uVar2 & 0xff] = 0;
      }
      DAT_003fe2c9 = 0;
      DAT_003f9391 = 0;
      DAT_003f9392 = 0;
    }
  }
  REG_CANB_MB6_CS = 200;
  return;
}



// Processes received TPMS sensor data

void tpms_process(void)

{
  if (DAT_003f9392 != '\0') {
    can_b_tpms_send();
  }
  if (DAT_003f9390 != -1) {
    if (0x32 < ecu_runtime) {
      DAT_003f9390 = -1;
      DAT_003fd9b9 = 1;
    }
    switch(DAT_003f9390) {
    case '\0':
      can_b_tpms_init();
      DAT_003f9390 = DAT_003f9390 + '\x01';
      break;
    case '\x01':
      DAT_003fe190 = 0x240;
      DAT_003fe2c8 = 2;
      DAT_003fe2cd = 0x21;
      DAT_003fe2ce = 0x2f;
      can_b_tpms_send();
      DAT_003f9390 = DAT_003f9390 + '\x01';
      break;
    case '\x02':
      if ((DAT_003f9880 == '\0') || (DAT_003fe34f != '/')) {
        DAT_003f8c46 = DAT_003f8c46 + -1;
        if (DAT_003f8c46 == '\0') {
          if (DAT_003f8c47 == '\0') {
            DAT_003f9390 = -1;
            DAT_003fd9b9 = 1;
          }
          else {
            DAT_003f8c47 = DAT_003f8c47 + -1;
            DAT_003f8c46 = '\x03';
            DAT_003f9390 = '\0';
          }
        }
      }
      else {
        if ((((uint)DAT_003fe350 == (int)CAL_ecu_generic_VIN[5]) &&
            ((uint)DAT_003fe351 == (int)CAL_ecu_generic_VIN[6])) &&
           ((uint)DAT_003fe352 == (int)CAL_ecu_generic_VIN[7])) {
          DAT_003f9390 = -1;
        }
        else {
          DAT_003f9390 = DAT_003f9390 + '\x01';
        }
        DAT_003f8c46 = '\x03';
      }
      break;
    case '\x03':
      DAT_003fe190 = 0x240;
      DAT_003fe2c8 = 0xb;
      DAT_003fe2cd = 0x3b;
      DAT_003fe2ce = 0x2f;
      DAT_003fe2cf = CAL_ecu_generic_VIN[5];
      DAT_003fe2d0 = CAL_ecu_generic_VIN[6];
      DAT_003fe2d1 = CAL_ecu_generic_VIN[7];
      DAT_003fe2d2 = 52;
      DAT_003fe2d3 = 0x35;
      DAT_003fe2d4 = CAL_tpms_pressure_front;
      DAT_003fe2d5 = CAL_tpms_pressure_rear;
      DAT_003fe2d6 = 0x18;
      DAT_003fe2d7 = 0x5a;
      can_b_tpms_send();
      DAT_003f9390 = DAT_003f9390 + '\x01';
      break;
    case '\x04':
      if ((DAT_003fe34e == '{') && (DAT_003fe34f == '/')) {
        DAT_003f9390 = DAT_003f9390 + '\x01';
        DAT_003f8c46 = '\x03';
      }
      else {
        DAT_003f8c46 = DAT_003f8c46 + -1;
        if (DAT_003f8c46 == '\0') {
          if (DAT_003f8c47 == '\0') {
            DAT_003f9390 = -1;
            DAT_003fd9b9 = 1;
          }
          else {
            DAT_003f8c47 = DAT_003f8c47 + -1;
            DAT_003f8c46 = '\x03';
            DAT_003f9390 = '\0';
          }
        }
      }
      break;
    case '\x05':
      DAT_003fe190 = 0x240;
      DAT_003fe2c8 = 0xe;
      DAT_003fe2cd = 0x3b;
      DAT_003fe2ce = 0x40;
      DAT_003fe2cf = CAL_tpms_threshold_front;
      DAT_003fe2d0 = CAL_tpms_threshold_front;
      DAT_003fe2d1 = CAL_tpms_threshold_rear;
      DAT_003fe2d2 = CAL_tpms_threshold_rear;
      DAT_003fe2d3 = 0x3c;
      DAT_003fe2d4 = 7;
      DAT_003fe2d5 = 7;
      DAT_003fe2d6 = 0x23;
      DAT_003fe2d7 = 0x23;
      DAT_003fe2d8 = 0x23;
      DAT_003fe2d9 = 3;
      DAT_003fe2da = 0xff;
      can_b_tpms_send();
      DAT_003f9390 = DAT_003f9390 + '\x01';
      break;
    case '\x06':
      if ((DAT_003fe34e == '{') && (DAT_003fe34f == '@')) {
        DAT_003f9390 = DAT_003f9390 + '\x01';
        DAT_003f8c46 = '\x03';
      }
      else {
        DAT_003f8c46 = DAT_003f8c46 + -1;
        if (DAT_003f8c46 == '\0') {
          if (DAT_003f8c47 == '\0') {
            DAT_003f9390 = -1;
            DAT_003fd9b9 = 1;
          }
          else {
            DAT_003f8c47 = DAT_003f8c47 + -1;
            DAT_003f8c46 = '\x03';
            DAT_003f9390 = '\0';
          }
        }
      }
      break;
    case '\a':
      DAT_003fe190 = 0x240;
      DAT_003fe2c8 = 4;
      DAT_003fe2cd = 0x3b;
      DAT_003fe2ce = 0x47;
      DAT_003fe2cf = 0;
      DAT_003fe2d0 = 1;
      can_b_tpms_send();
      DAT_003f9390 = DAT_003f9390 + '\x01';
      break;
    case '\b':
      if ((DAT_003fe34e == '{') && (DAT_003fe34f == 'G')) {
        DAT_003f9390 = -1;
        DAT_003f8c46 = '\x03';
      }
      else {
        DAT_003f8c46 = DAT_003f8c46 + -1;
        if (DAT_003f8c46 == '\0') {
          if (DAT_003f8c47 == '\0') {
            DAT_003f9390 = -1;
            DAT_003fd9b9 = 1;
          }
          else {
            DAT_003f8c47 = DAT_003f8c47 + -1;
            DAT_003f8c46 = '\x03';
            DAT_003f9390 = '\0';
          }
        }
      }
    }
  }
  return;
}



// TPMS session state machine (100ms task)

void tpms_session_handler_100ms(void)

{
  bool bVar1;
  ushort uVar2;
  char cVar4;
  uint16_t uVar3;
  
  if (tpms_session_handler_state == 3) {
    DAT_003fe190 = 0x240;
    DAT_003fe2c8 = 2;
    DAT_003fe2cd = 0x21;
    DAT_003fe2ce = 0x15;
    can_b_tpms_send();
    tpms_session_handler_state = tpms_session_handler_state + 1;
    uVar3 = tpms_flags;
  }
  else {
    uVar3 = tpms_flags;
    if (tpms_session_handler_state < 3) {
      if (tpms_session_handler_state == 1) {
        DAT_003fe190 = 0x240;
        DAT_003fe2c8 = 8;
        DAT_003fe2cd = 0x3b;
        DAT_003fe2ce = 0x48;
        DAT_003fe2cf = 0x1e;
        DAT_003fe2d0 = 5;
        DAT_003fe2d1 = 4;
        DAT_003fe2d2 = 4;
        DAT_003fe2d3 = 1;
        DAT_003fe2d4 = 0x90;
        can_b_tpms_send();
        tpms_session_handler_state = tpms_session_handler_state + 1;
        uVar3 = tpms_flags;
      }
      else if (tpms_session_handler_state == 0) {
        if (true) {
          if (DAT_003fe2cc == '\0') {
            tpms_session_stop();
            tpms_session_handler_state = tpms_session_handler_state + 1;
            DAT_003fe2cc = '\x01';
            uVar3 = tpms_flags;
          }
          else {
            cVar4 = DAT_003f9393 + -1;
            bVar1 = DAT_003f9393 == '\0';
            DAT_003f9393 = cVar4;
            if (bVar1) {
              DAT_003fe190 = 0x240;
              DAT_003fe2c8 = 1;
              DAT_003fe2cd = 0x3e;
              can_b_tpms_send();
              DAT_003f9393 = DAT_003f8c48;
              uVar3 = tpms_flags;
            }
          }
        }
      }
      else if ((DAT_003fe34e == '{') && (DAT_003fe34f == 'H')) {
        tpms_session_handler_state = tpms_session_handler_state + 1;
      }
    }
    else if (tpms_session_handler_state == 5) {
      uVar3 = tpms_flags & 0xfdff;
      DAT_003f8c49 = DAT_003f8c49 + -1;
      if (DAT_003f8c49 == '\0') {
        uVar2 = tpms_flags & 0x100;
        tpms_flags = uVar3;
        if (uVar2 == 0) {
          tpms_session_stop();
        }
        tpms_session_handler_state = 0;
        DAT_003fe2cc = '\0';
        uVar3 = tpms_flags;
      }
    }
    else if (((tpms_session_handler_state < 5) && (DAT_003fe34f == '\x15')) &&
            (DAT_003fe350 == '\x01')) {
      tpms_session_handler_state = 0;
      uVar3 = tpms_flags | 0x200;
    }
  }
  tpms_flags = uVar3;
  return;
}



// Starts TPMS communication session

void tpms_session_start(void)

{
  can_b_tpms_init();
  DAT_003fe190 = 0x240;
  DAT_003fe2c8 = 4;
  DAT_003fe2cd = 0x18;
  DAT_003fe2ce = 0;
  DAT_003fe2cf = 0xff;
  DAT_003fe2d0 = 0;
  can_b_tpms_send();
  return;
}



// Stops TPMS communication session

void tpms_session_stop(void)

{
  can_b_tpms_init();
  DAT_003fe190 = 0x240;
  DAT_003fe2c8 = 3;
  DAT_003fe2cd = 0x14;
  DAT_003fe2ce = 0xff;
  DAT_003fe2cf = 0;
  can_b_tpms_send();
  return;
}



// Updates TPMS status flags

void can_b_tpms_status(void)

{
  byte bVar1;
  
  REG_CANB_MB6_CS = 0x80;
  REG_CANB_MB6_ID_HI = 0x4cc0;
  REG_CANB_MB6_DATA0 = 0x40;
  REG_CANB_MB6_DATA1 = 0x97;
  REG_CANB_MB6_DATA2 = 0x19;
  bVar1 = REG_CANB_MB7_DATA0;
  REG_CANB_MB6_DATA3 = (bVar1 & 0xf) + 0x80;
  for (bVar1 = 4; bVar1 < 8; bVar1 = bVar1 + 1) {
    (&REG_CANB_MB6_DATA0)[bVar1] = 0;
  }
  REG_CANB_MB6_CS = 200;
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
    if ((DAT_003fe9a8 & 4) == 0) {
      DAT_003f939a = 0;
      obd_clr_dtc(&CAL_obd_P2138,&LEA_obd_P2138_flags);
      if (DAT_003f9398 < DAT_003fca15) {
        DAT_003f9398 = DAT_003f9398 + 1;
      }
    }
    else {
      obd_set_dtc(&CAL_obd_P2138,&LEA_obd_P2138_flags,&LEA_obd_P2138_engine_start_count,
                  &LEA_obd_P2138_warm_up_cycle_count,0x85a);
      DAT_003f9398 = 0;
    }
  }
  if ((CAL_obd_P2122 & 7) != 0) {
    if (((DAT_003fe9a8 & 1) == 0) || (diag_channel[1].result != 1)) {
      DAT_003f939e = 0;
      obd_clr_dtc(&CAL_obd_P2122,&LEA_obd_P2122_flags);
      if (DAT_003f939c < DAT_003fca0b) {
        DAT_003f939c = DAT_003f939c + 1;
      }
    }
    else {
      obd_set_dtc(&CAL_obd_P2122,&LEA_obd_P2122_flags,&LEA_obd_P2122_engine_start_count,
                  &LEA_obd_P2122_warm_up_cycle_count,0x84a);
      DAT_003f939c = 0;
    }
  }
  if ((CAL_obd_P2123 & 7) != 0) {
    if (((DAT_003fe9a8 & 1) == 0) || (diag_channel[1].result != 2)) {
      DAT_003f93a2 = 0;
      obd_clr_dtc(&CAL_obd_P2123,&LEA_obd_P2123_flags);
      if (DAT_003f93a0 < DAT_003fca0c) {
        DAT_003f93a0 = DAT_003f93a0 + 1;
      }
    }
    else {
      obd_set_dtc(&CAL_obd_P2123,&LEA_obd_P2123_flags,&LEA_obd_P2123_engine_start_count,
                  &LEA_obd_P2123_warm_up_cycle_count,0x84b);
      DAT_003f93a0 = 0;
    }
  }
  if ((CAL_obd_P2127 & 7) != 0) {
    if (((DAT_003fe9a8 & 2) == 0) || (diag_channel[2].result != 3)) {
      DAT_003f93a6 = 0;
      obd_clr_dtc(&CAL_obd_P2127,&LEA_obd_P2127_flags);
      if (DAT_003f93a4 < DAT_003fca0d) {
        DAT_003f93a4 = DAT_003f93a4 + 1;
      }
    }
    else {
      obd_set_dtc(&CAL_obd_P2127,&LEA_obd_P2127_flags,&LEA_obd_P2127_engine_start_count,
                  &LEA_obd_P2127_warm_up_cycle_count,0x84f);
      DAT_003f93a4 = 0;
    }
  }
  if ((CAL_obd_P2128 & 7) != 0) {
    if (((DAT_003fe9a8 & 2) == 0) || (diag_channel[2].result != 4)) {
      DAT_003f93aa = 0;
      obd_clr_dtc(&CAL_obd_P2128,&LEA_obd_P2128_flags);
      if (DAT_003f93a8 < DAT_003fca0e) {
        DAT_003f93a8 = DAT_003f93a8 + 1;
      }
    }
    else {
      obd_set_dtc(&CAL_obd_P2128,&LEA_obd_P2128_flags,&LEA_obd_P2128_engine_start_count,
                  &LEA_obd_P2128_warm_up_cycle_count,0x850);
      DAT_003f93a8 = 0;
    }
  }
  if ((((DAT_003f9398 == 0) || (DAT_003f939c == 0)) || (DAT_003f93a0 == 0)) ||
     ((DAT_003f93a4 == 0 || (DAT_003f93a8 == 0)))) {
    sensor_fault_flags = sensor_fault_flags | 0x4000;
  }
  return;
}



// Initializes PPS monitor state

void obd_init_pps(void)

{
  DAT_003f9398 = DAT_003fca15;
  DAT_003f939c = DAT_003fca0b;
  DAT_003f93a0 = DAT_003fca0c;
  DAT_003f93a4 = DAT_003fca0d;
  DAT_003f93a8 = DAT_003fca0e;
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
  DAT_003fe4b0 = 1;
  DAT_003fe4b1 = 1;
  DAT_003fe4b2 = 0xf;
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
  if (DAT_003fe4b2 == '\0') {
    tps_dt = adc_filter_update(&filter_tps_diff,tps_1_smooth - uVar2);
  }
  else {
    tps_dt = 0;
    DAT_003fe4b2 = DAT_003fe4b2 + -1;
  }
  iVar3 = (int)((uint)CAL_tps_ctrl_p_gain * (int)(short)tps_diff) / 100 +
          ((int)((uint)CAL_tps_ctrl_p_gain * (int)(short)tps_diff) >> 0x1f);
  tps_ctrl_p = iVar3 - (iVar3 >> 0x1f);
  tps_ctrl_i_sum = tps_ctrl_i_sum + (short)tps_diff;
  iVar3 = (int)(short)(tps_dt * CAL_tps_ctrl_d_gain) / 10 +
          ((int)(short)(tps_dt * CAL_tps_ctrl_d_gain) >> 0x1f);
  tps_ctrl_d = (short)iVar3 - (short)(iVar3 >> 0x1f);
  DAT_003fe496 = CAL_tps_ctrl_i_gain;
  DAT_003fe498 = (uint)CAL_tps_ctrl_i_limit;
  iVar3 = (int)((uint)CAL_tps_ctrl_i_gain * tps_ctrl_i_sum) / 10000 +
          ((int)((uint)CAL_tps_ctrl_i_gain * tps_ctrl_i_sum) >> 0x1f);
  tps_ctrl_i = iVar3 - (iVar3 >> 0x1f);
  uVar4 = abs(tps_ctrl_i);
  if ((int)DAT_003fe498 < (int)uVar4) {
    if (tps_ctrl_i < 1) {
      tps_ctrl_i = -DAT_003fe498;
      tps_ctrl_i_sum = (int)(DAT_003fe498 * -10000) / (int)(uint)DAT_003fe496;
    }
    else {
      tps_ctrl_i = DAT_003fe498;
      tps_ctrl_i_sum = (int)(DAT_003fe498 * 10000) / (int)(uint)DAT_003fe496;
    }
  }
  uVar5 = lookup_2D_uint16_interpolated
                    (16,tps_1_smooth,CAL_tps_motor_duty_cycle,CAL_tps_motor_duty_cycle_X_tps);
  DAT_003fe4b8 = uVar5 - 1024;
  tps_output = DAT_003fe4b8 + (((short)tps_ctrl_p + (short)tps_ctrl_i) - tps_ctrl_d);
  uVar1 = REG_QADCB_RJURR10;
  DAT_003fe4bc = (tps_output * 0x3ff) / (int)(uint)uVar1;
  if (DAT_003fe4bc < 0) {
    iVar3 = (int)(DAT_003fe4bc * (uint)CAL_tps_period) / 0x3ff +
            ((int)(DAT_003fe4bc * (uint)CAL_tps_period) >> 0x1f);
    DAT_003fe480 = -((short)iVar3 - (short)(iVar3 >> 0x1f));
    uVar1 = REG_MPWMSM19_SCR;
    REG_MPWMSM19_SCR = uVar1 & 0xf7ff | 0x800;
  }
  else {
    iVar3 = (int)(DAT_003fe4bc * (uint)CAL_tps_period) / 0x3ff +
            ((int)(DAT_003fe4bc * (uint)CAL_tps_period) >> 0x1f);
    DAT_003fe480 = (short)iVar3 - (short)(iVar3 >> 0x1f);
    uVar1 = REG_MPWMSM19_SCR;
    REG_MPWMSM19_SCR = uVar1 & 0xf7ff;
  }
  DAT_003fe484 = (undefined1)(((uint)DAT_003fe480 * 100) / (uint)CAL_tps_period);
  if (((uint)CAL_tps_period * 0x32) / 100 < (uint)DAT_003fe480) {
    if (DAT_003fe486 != 0) {
      DAT_003fe486 = DAT_003fe486 + -1;
    }
  }
  else {
    DAT_003fe486 = 100;
  }
  if (DAT_003fe486 == 0) {
    DAT_003fe480 = (ushort)(((uint)CAL_tps_period * 0x32) / 100);
  }
  REG_MPWMSM18_PULR = DAT_003fe480;
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
  
  if (((int)(CAL_sensor_tps_1_offset - 20) < (int)(uint)tps_state_test_sample_tps_1) &&
     ((uint)tps_state_test_sample_tps_1 < CAL_sensor_tps_1_offset + 20)) {
    iVar1 = ((int)(short)LEA_sensor_tps_1_offset - (int)(short)tps_state_test_sample_tps_1) * 50;
    iVar1 = iVar1 / 100 + (iVar1 >> 0x1f);
    LEA_sensor_tps_1_offset = LEA_sensor_tps_1_offset - ((short)iVar1 - (short)(iVar1 >> 0x1f));
  }
  else {
    LEA_sensor_tps_1_offset = CAL_sensor_tps_1_offset;
  }
  if (((int)(CAL_sensor_tps_2_offset - 20) < (int)(uint)tps_state_test_sample_tps_2) &&
     ((uint)tps_state_test_sample_tps_2 < CAL_sensor_tps_2_offset + 20)) {
    iVar1 = ((int)(short)LEA_sensor_tps_2_offset - (int)(short)tps_state_test_sample_tps_2) * 50;
    iVar1 = iVar1 / 100 + (iVar1 >> 0x1f);
    LEA_sensor_tps_2_offset = LEA_sensor_tps_2_offset - ((short)iVar1 - (short)(iVar1 >> 0x1f));
  }
  else {
    LEA_sensor_tps_2_offset = CAL_sensor_tps_2_offset;
  }
  iVar1 = (uint)LEA_sensor_tps_1_offset * 0x3ff +
          (uint)DAT_003f99ce * ((uint)DAT_003f99ba - (uint)LEA_sensor_tps_1_offset);
  iVar1 = iVar1 / 0x3ff + (iVar1 >> 0x1f);
  tps_1_range_corrected_low = (short)iVar1 - (short)(iVar1 >> 0x1f);
  iVar1 = (uint)LEA_sensor_tps_1_offset * 0x3ff +
          (uint)DAT_003f99d0 * ((uint)DAT_003f99ba - (uint)LEA_sensor_tps_1_offset);
  iVar1 = iVar1 / 0x3ff + (iVar1 >> 0x1f);
  tps_1_range_corrected_high = (short)iVar1 - (short)(iVar1 >> 0x1f);
  iVar1 = (uint)LEA_sensor_tps_2_offset * 0x3ff +
          (uint)DAT_003f99d2 * ((uint)DAT_003f99be - (uint)LEA_sensor_tps_2_offset);
  iVar1 = iVar1 / 0x3ff + (iVar1 >> 0x1f);
  tps_2_range_corrected_low = (short)iVar1 - (short)(iVar1 >> 0x1f);
  iVar1 = (uint)LEA_sensor_tps_2_offset * 0x3ff +
          (uint)DAT_003f99d4 * ((uint)DAT_003f99be - (uint)LEA_sensor_tps_2_offset);
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
    DAT_003fe4c4 = (int)(short)pps_tps_target + (uint)idle_tps_target;
    if ((short)CAL_tps_limit_h < DAT_003fe4c4) {
      tps_target = CAL_tps_limit_h;
    }
    else if (DAT_003fe4c4 < (short)CAL_tps_limit_l) {
      tps_target = CAL_tps_limit_l;
    }
    else {
      tps_target = (u16_factor_1_1023)DAT_003fe4c4;
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
        DAT_003fe4c2 = 1;
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
        DAT_003fe4c2 = 0;
        flags_to_hc08 = flags_to_hc08 & 0xfb;
      }
    }
    else if ((short)tps_target < (short)tps_target_smooth) {
      uVar3 = abs((int)(short)tps_target - (int)(short)tps_target_smooth);
      if ((int)(uint)tps_target_smooth_dec < (int)uVar3) {
        DAT_003fe4c2 = 1;
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
        DAT_003fe4c2 = 0;
        flags_to_hc08 = flags_to_hc08 & 0xfb;
      }
    }
    else {
      tps_target_smooth = tps_target;
      DAT_003fe4c2 = 0;
      flags_to_hc08 = flags_to_hc08 & 0xfb;
    }
  }
  tps_check(tps_1_smooth,sensor_adc_tps_2);
  uVar2 = tps_1_smooth_history[1];
  if ((int)(uint)DAT_003fe9b6 < (int)(short)tps_target_smooth) {
    tps_target_smooth = DAT_003fe9b6;
  }
  if (DAT_003fe9b6 == DAT_003fc590) {
    DAT_003fe4c0 = tps_max;
  }
  else {
    DAT_003fe4c0 = tps_1_smooth;
  }
  if (((DAT_003fe9bb != '\0') || (DAT_003fe9ca != '\0')) &&
     ((int)(uint)DAT_003f9ad2 < (int)(short)tps_target_smooth)) {
    tps_target_smooth = DAT_003f9ad2;
  }
  tps_diff = tps_target_smooth - tps_max;
  tps_1_smooth_history[0] = tps_1_smooth_history[1];
  tps_1_smooth_history[1] = tps_1_smooth_history[2];
  tps_1_smooth_history[2] = tps_1_smooth_history[3];
  tps_1_smooth_history[3] = DAT_003fe4c0;
  if (DAT_003fe4b2 == '\0') {
    tps_dt = adc_filter_update(&filter_tps_diff,DAT_003fe4c0 - uVar2);
  }
  else {
    tps_dt = 0;
    DAT_003fe4b2 = DAT_003fe4b2 + -1;
  }
  iVar4 = (int)((uint)CAL_tps_ctrl_p_gain * (int)(short)tps_diff) / 100 +
          ((int)((uint)CAL_tps_ctrl_p_gain * (int)(short)tps_diff) >> 0x1f);
  tps_ctrl_p = iVar4 - (iVar4 >> 0x1f);
  tps_ctrl_i_sum = tps_ctrl_i_sum + (short)tps_diff;
  iVar4 = (int)(short)(tps_dt * CAL_tps_ctrl_d_gain) / 10 +
          ((int)(short)(tps_dt * CAL_tps_ctrl_d_gain) >> 0x1f);
  tps_ctrl_d = (short)iVar4 - (short)(iVar4 >> 0x1f);
  DAT_003fe496 = CAL_tps_ctrl_i_gain;
  DAT_003fe498 = (uint)CAL_tps_ctrl_i_limit;
  iVar4 = (int)((uint)CAL_tps_ctrl_i_gain * tps_ctrl_i_sum) / 10000 +
          ((int)((uint)CAL_tps_ctrl_i_gain * tps_ctrl_i_sum) >> 0x1f);
  tps_ctrl_i = iVar4 - (iVar4 >> 0x1f);
  uVar3 = abs(tps_ctrl_i);
  if ((int)DAT_003fe498 < (int)uVar3) {
    if (tps_ctrl_i < 1) {
      tps_ctrl_i = -DAT_003fe498;
      tps_ctrl_i_sum = (int)(DAT_003fe498 * -10000) / (int)(uint)DAT_003fe496;
    }
    else {
      tps_ctrl_i = DAT_003fe498;
      tps_ctrl_i_sum = (int)(DAT_003fe498 * 10000) / (int)(uint)DAT_003fe496;
    }
  }
  uVar5 = lookup_2D_uint16_interpolated
                    (16,tps_1_smooth,CAL_tps_motor_duty_cycle,CAL_tps_motor_duty_cycle_X_tps);
  DAT_003fe4b8 = uVar5 - 1024;
  tps_output = (uVar5 - 1024) + (((short)tps_ctrl_p + (short)tps_ctrl_i) - tps_ctrl_d);
  DAT_003fe4bc = (tps_output * 0x3ff) / (int)(uint)sensor_adc_ecu_voltage;
  if (DAT_003fe4bc < 0) {
    iVar4 = (int)(DAT_003fe4bc * (uint)CAL_tps_period) / 0x3ff +
            ((int)(DAT_003fe4bc * (uint)CAL_tps_period) >> 0x1f);
    DAT_003fe480 = -((short)iVar4 - (short)(iVar4 >> 0x1f));
    uVar1 = REG_MPWMSM19_SCR;
    REG_MPWMSM19_SCR = uVar1 & 0xf7ff | 0x800;
  }
  else {
    iVar4 = (int)(DAT_003fe4bc * (uint)CAL_tps_period) / 0x3ff +
            ((int)(DAT_003fe4bc * (uint)CAL_tps_period) >> 0x1f);
    DAT_003fe480 = (short)iVar4 - (short)(iVar4 >> 0x1f);
    uVar1 = REG_MPWMSM19_SCR;
    REG_MPWMSM19_SCR = uVar1 & 0xf7ff;
  }
  DAT_003fe484 = (char)(((uint)DAT_003fe480 * 100) / (uint)CAL_tps_period);
  if (((uint)CAL_tps_period * 0x32) / 100 < (uint)DAT_003fe480) {
    if (DAT_003fe486 != 0) {
      DAT_003fe486 = DAT_003fe486 + -1;
    }
  }
  else {
    DAT_003fe486 = 100;
  }
  if (DAT_003fe486 == 0) {
    DAT_003fe480 = (ushort)(((uint)CAL_tps_period * 0x32) / 100);
  }
  if ((((sensor_fault_flags & 0x8000) == 0) && (DAT_003fe9ce == '\0')) &&
     ((tps_both_fault == false && ((DAT_003fe4ea == '\0' && (tps_state_test_failed == 0)))))) {
    if (((shutdown_flags & 1) == 0) && (engine_speed_1 == 0)) {
      REG_MPWMSM18_PULR = 0;
    }
    else {
      REG_MPWMSM18_PULR = DAT_003fe480;
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
    if ((DAT_003fe954 & 0x40) == 0) {
      DAT_003f93c8 = 0;
      obd_clr_dtc(&CAL_obd_P2135,&LEA_obd_P2135_flags);
      if (DAT_003fe4e1 < DAT_003fca12) {
        DAT_003fe4e1 = DAT_003fe4e1 + 1;
      }
    }
    else {
      obd_set_dtc(&CAL_obd_P2135,&LEA_obd_P2135_flags,&LEA_obd_P2135_engine_start_count,
                  &LEA_obd_P2135_warm_up_cycle_count,0x857);
      DAT_003fe4e1 = 0;
    }
  }
  if ((CAL_obd_P0122 & 7) != 0) {
    if (((DAT_003fe954 & 1) == 0) || (diag_channel[4].result != 6)) {
      DAT_003f93c0 = 0;
      obd_clr_dtc(&CAL_obd_P0122,&LEA_obd_P0122_flags);
      if (DAT_003fe4cc < DAT_003fc9de) {
        DAT_003fe4cc = DAT_003fe4cc + 1;
      }
    }
    else {
      obd_set_dtc(&CAL_obd_P0122,&LEA_obd_P0122_flags,&LEA_obd_P0222_engine_start_count,
                  &LEA_obd_P0222_warm_up_cycle_count,0x7a);
      DAT_003fe4cc = 0;
    }
  }
  if ((CAL_obd_P0123 & 7) != 0) {
    if (((DAT_003fe954 & 1) == 0) || (diag_channel[4].result != 7)) {
      DAT_003f93c2 = 0;
      obd_clr_dtc(&CAL_obd_P0123,&LEA_obd_P0123_flags);
      if (DAT_003fe4dc < DAT_003fc9df) {
        DAT_003fe4dc = DAT_003fe4dc + 1;
      }
    }
    else {
      obd_set_dtc(&CAL_obd_P0123,&LEA_obd_P0123_flags,&LEA_obd_P0223_engine_start_count,
                  &LEA_obd_P0223_warm_up_cycle_count,0x7b);
      DAT_003fe4dc = 0;
    }
  }
  if ((CAL_obd_P0222 & 7) != 0) {
    if (((DAT_003fe954 & 2) == 0) || (diag_channel[5].result != 8)) {
      DAT_003f93c4 = 0;
      obd_clr_dtc(&CAL_obd_P0222,&LEA_obd_P0222_flags);
      if (DAT_003fe4dd < DAT_003fca10) {
        DAT_003fe4dd = DAT_003fe4dd + 1;
      }
    }
    else {
      obd_set_dtc(&CAL_obd_P0222,&LEA_obd_P0222_flags,&DAT_002f83d1,&DAT_002f83d2,0xde);
      DAT_003fe4dd = 0;
    }
  }
  if ((CAL_obd_P0223 & 7) != 0) {
    if (((DAT_003fe954 & 2) == 0) || (diag_channel[5].result != 9)) {
      DAT_003f93c6 = 0;
      obd_clr_dtc(&CAL_obd_P0223,&LEA_obd_P0223_flags);
      if (DAT_003fe4de < DAT_003fca11) {
        DAT_003fe4de = DAT_003fe4de + 1;
      }
    }
    else {
      obd_set_dtc(&CAL_obd_P0223,&LEA_obd_P0223_flags,&DAT_002f83d4,&DAT_002f83d5,0xdf);
      DAT_003fe4de = 0;
    }
  }
  if ((((((CAL_obd_P0638 & 7) != 0) && (engine_is_running != false)) &&
       ((sensor_fault_flags & 4) == 0)) && ((sensor_fault_flags & 0x4000) == 0)) ||
     (tps_state_test_failed != 0)) {
    if ((((-(int)(short)CAL_load_use_alphaN_dt_tps_target_1_negative_min < (int)dt_tps_target_1) &&
         (dt_tps_target_1 < (short)CAL_load_use_alphaN_dt_tps_target_1_positive_min)) &&
        (uVar1 = abs((int)(short)tps_diff), (int)(uint)CAL_obd_P0638_threshold < (int)uVar1)) ||
       (tps_state_test_failed != 0)) {
      DAT_003f93ca = DAT_003f93ca + 1;
      if (DAT_003fdd44 <= DAT_003f93ca) {
        if (DAT_003fe4df != 0) {
          DAT_003fe4df = DAT_003fe4df - 1;
        }
        if (DAT_003fe4df == 0) {
          obd_set_dtc(&CAL_obd_P0638,&LEA_obd_P0638_flags,&LEA_obd_P0638_engine_start_count,
                      &LEA_obd_P0638_warm_up_cycle_count,0x27e);
        }
        else {
          DAT_003f93ca = 0;
        }
      }
    }
    else {
      DAT_003f93ca = 0;
      obd_clr_dtc(&CAL_obd_P0638,&LEA_obd_P0638_flags);
      if (DAT_003fe4df < DAT_003fca13) {
        DAT_003fe4df = DAT_003fe4df + 1;
      }
    }
  }
  if (((CAL_obd_P2173 & 7) != 0) && (engine_is_running != false)) {
    if (((sensor_fault_flags & 0x10) == 0) &&
       (((load_use_alphaN == 0 && ((int)(uint)DAT_003fc594 < (int)load_diff)) &&
        ((short)(ushort)CAL_load_alphaN_adj_corr_limit_h <= (short)load_alphaN_adj)))) {
      DAT_003f93cc = DAT_003f93cc + 1;
      if (DAT_003fdd44 <= DAT_003f93cc) {
        if (DAT_003fe4e0 != 0) {
          DAT_003fe4e0 = DAT_003fe4e0 - 1;
        }
        if (DAT_003fe4e0 == 0) {
          obd_set_dtc(&CAL_obd_P2173,&LEA_obd_P2173_flags,&LEA_obd_P2173_engine_start_count,
                      &LEA_obd_P2173_warm_up_cycle_count,0x87d);
        }
        else {
          DAT_003f93cc = 0;
        }
      }
    }
    else {
      DAT_003f93cc = 0;
      obd_clr_dtc(&CAL_obd_P2173,&LEA_obd_P2173_flags);
      if (DAT_003fe4e0 < DAT_003fca46) {
        DAT_003fe4e0 = DAT_003fe4e0 + 1;
      }
    }
  }
  if ((((CAL_obd_P2104 & 7) != 0) && (engine_is_running != false)) &&
     (((sensor_fault_flags & 4) == 0 &&
      (((sensor_fault_flags & 0x4000) == 0 && ((sensor_fault_flags & 0x8000) == 0)))))) {
    if ((hc08_obd_flags & 0x10) == 0) {
      DAT_003f93ce = 0;
      obd_clr_dtc(&CAL_obd_P2104,&LEA_obd_P2104_flags);
      if (DAT_003fe4e2 < DAT_003fca47) {
        DAT_003fe4e2 = DAT_003fe4e2 + 1;
      }
    }
    else {
      DAT_003f93ce = DAT_003f93ce + 1;
      if (DAT_003fdd44 <= DAT_003f93ce) {
        if (DAT_003fe4e2 != 0) {
          DAT_003fe4e2 = DAT_003fe4e2 - 1;
        }
        if (DAT_003fe4e2 == 0) {
          obd_set_dtc(&CAL_obd_P2104,&LEA_obd_P2104_flags,&LEA_obd_P2104_engine_start_count,
                      &LEA_obd_P2104_warm_up_cycle_count,0x838);
        }
        else {
          DAT_003f93ce = 0;
        }
      }
    }
  }
  if (((((CAL_obd_P2105 & 7) != 0) && ((sensor_fault_flags & 4) == 0)) &&
      ((sensor_fault_flags & 0x4000) == 0)) && ((sensor_fault_flags & 0x8000) == 0)) {
    if ((hc08_obd_flags & 0x20) == 0) {
      DAT_003f93d0 = 0;
      obd_clr_dtc(&CAL_obd_P2105,&LEA_obd_P2105_flags);
      if (DAT_003fe4e3 < DAT_003fca48) {
        DAT_003fe4e3 = DAT_003fe4e3 + 1;
      }
    }
    else {
      DAT_003f93d0 = DAT_003f93d0 + 1;
      if (DAT_003fdd44 <= DAT_003f93d0) {
        if (DAT_003fe4e3 != 0) {
          DAT_003fe4e3 = DAT_003fe4e3 - 1;
        }
        if (DAT_003fe4e3 == 0) {
          obd_set_dtc(&CAL_obd_P2105,&LEA_obd_P2105_flags,&LEA_obd_P2105_engine_start_count,
                      &LEA_obd_P2105_warm_up_cycle_count,0x839);
        }
        else {
          DAT_003f93d0 = 0;
        }
      }
    }
  }
  if ((CAL_obd_P2107 & 7) != 0) {
    if (((hc08_obd_flags & 0x40) == 0) && ((hc08_obd_flags & 0x80) == 0)) {
      DAT_003f93d4 = 0;
      obd_clr_dtc(&CAL_obd_P2107,&LEA_obd_P2107_flags);
      if (DAT_003fe4e5 < DAT_003fca4a) {
        DAT_003fe4e5 = DAT_003fe4e5 + 1;
      }
    }
    else {
      DAT_003f93d4 = DAT_003f93d4 + 1;
      if (DAT_003fdd44 <= DAT_003f93d4) {
        if (DAT_003fe4e5 != 0) {
          DAT_003fe4e5 = DAT_003fe4e5 - 1;
        }
        if (DAT_003fe4e5 == 0) {
          obd_set_dtc(&CAL_obd_P2107,&LEA_obd_P2107_flags,&LEA_obd_P2107_engine_start_count,
                      &LEA_obd_P2107_warm_up_cycle_count,0x83b);
          DAT_003fe4ea = 1;
        }
        else {
          DAT_003f93d4 = 0;
        }
      }
    }
  }
  if (((CAL_obd_P2106 & 7) != 0) && (engine_is_running != false)) {
    if ((DAT_003fe9bb == '\0') && (DAT_003fe9ca == '\0')) {
      DAT_003f93d2 = 0;
      obd_clr_dtc(&CAL_obd_P2106,&LEA_obd_P2106_flags);
      if (DAT_003fe4e4 < DAT_003fca49) {
        DAT_003fe4e4 = DAT_003fe4e4 + 1;
      }
    }
    else {
      DAT_003f93d2 = DAT_003f93d2 + 1;
      if (DAT_003fdd44 <= DAT_003f93d2) {
        if (DAT_003fe4e4 != 0) {
          DAT_003fe4e4 = DAT_003fe4e4 - 1;
        }
        if (DAT_003fe4e4 == 0) {
          obd_set_dtc(&CAL_obd_P2106,&LEA_obd_P2106_flags,&LEA_obd_P2106_engine_start_count,
                      &LEA_obd_P2106_warm_up_cycle_count,0x83a);
        }
        else {
          DAT_003f93d2 = 0;
        }
      }
    }
  }
  if (((CAL_obd_P2100 & 7) != 0) && ((hc08_obd_flags & 0x10) == 0)) {
    if ((DAT_003f98b8 & 0x10) == 0) {
      obd_clr_dtc(&CAL_obd_P2100,&LEA_obd_P2100_flags);
      if (DAT_003fe4e6 < DAT_003fca4b) {
        DAT_003fe4e6 = DAT_003fe4e6 + 1;
      }
    }
    else if (DAT_003fe4e6 == 0) {
      obd_set_dtc(&CAL_obd_P2100,&LEA_obd_P2100_flags,&LEA_obd_P2100_engine_start_count,
                  &LEA_obd_P2100_warm_up_cycle_count,0x834);
    }
    else {
      DAT_003fe4e6 = DAT_003fe4e6 - 1;
    }
    DAT_003f98b8 = DAT_003f98b8 & 0xef;
  }
  if ((CAL_obd_P2102 & 7) != 0) {
    if ((DAT_003f98b8 & 8) == 0) {
      obd_clr_dtc(&CAL_obd_P2102,&LEA_obd_P2102_flags);
      if (DAT_003fe4e7 < DAT_003fca4c) {
        DAT_003fe4e7 = DAT_003fe4e7 + 1;
      }
    }
    else if (DAT_003fe4e7 == 0) {
      obd_set_dtc(&CAL_obd_P2102,&LEA_obd_P2102_flags,&LEA_obd_P2102_engine_start_count,
                  &LEA_obd_P2102_warm_up_cycle_count,0x836);
    }
    else {
      DAT_003fe4e7 = DAT_003fe4e7 - 1;
    }
    DAT_003f98b8 = DAT_003f98b8 & 0xf7;
  }
  if ((CAL_obd_P2103 & 7) != 0) {
    if ((DAT_003f98b8 & 4) == 0) {
      obd_clr_dtc(&CAL_obd_P2103,&LEA_obd_P2103_flags);
      if (DAT_003fe4e8 < DAT_003fca4d) {
        DAT_003fe4e8 = DAT_003fe4e8 + 1;
      }
    }
    else if (DAT_003fe4e8 == 0) {
      obd_set_dtc(&CAL_obd_P2103,&LEA_obd_P2103_flags,&LEA_obd_P2103_engine_start_count,
                  &LEA_obd_P2103_warm_up_cycle_count,0x837);
    }
    else {
      DAT_003fe4e8 = DAT_003fe4e8 - 1;
    }
    DAT_003f98b8 = DAT_003f98b8 & 0xfb;
  }
  if ((CAL_obd_P2108 & 7) != 0) {
    if ((DAT_003f98b8 & 1) == 0) {
      obd_clr_dtc(&CAL_obd_P2108,&LEA_obd_P2108_flags);
      if (DAT_003fe4e9 < DAT_003fca4e) {
        DAT_003fe4e9 = DAT_003fe4e9 + 1;
      }
    }
    else if (DAT_003fe4e9 == 0) {
      obd_set_dtc(&CAL_obd_P2108,&LEA_obd_P2108_flags,&LEA_obd_P2108_engine_start_count,
                  &LEA_obd_P2108_warm_up_cycle_count,0x83c);
    }
    else {
      DAT_003fe4e9 = DAT_003fe4e9 - 1;
    }
    DAT_003f98b8 = DAT_003f98b8 & 0xfe;
  }
  if ((((DAT_003fe4e1 == 0) || (DAT_003fe4cc == 0)) || (DAT_003fe4dc == 0)) ||
     ((DAT_003fe4dd == 0 || (DAT_003fe4de == 0)))) {
    sensor_fault_flags = sensor_fault_flags | 4;
  }
  if ((DAT_003fe4df == 0) || (DAT_003fe4e0 == 0)) {
    sensor_fault_flags = sensor_fault_flags | 0x8000;
  }
  if (DAT_003fe4e0 == 0) {
    flags_to_hc08 = flags_to_hc08 | 0x20;
  }
  if (DAT_003fe4e4 == 0) {
    flags_to_hc08 = flags_to_hc08 | 8;
  }
  return;
}



// Initializes TPS/throttle monitor state

void obd_init_tps_throttle(void)

{
  DAT_003fe4cc = DAT_003fc9de;
  DAT_003fe4dc = DAT_003fc9df;
  DAT_003fe4dd = DAT_003fca10;
  DAT_003fe4de = DAT_003fca11;
  DAT_003fe4df = DAT_003fca13;
  DAT_003fe4e0 = DAT_003fca46;
  DAT_003fe4e1 = DAT_003fca12;
  DAT_003fe4e2 = DAT_003fca47;
  DAT_003fe4e3 = DAT_003fca48;
  DAT_003fe4e4 = DAT_003fca49;
  DAT_003fe4e5 = DAT_003fca4a;
  DAT_003fe4e6 = DAT_003fca4b;
  DAT_003fe4e7 = DAT_003fca4c;
  DAT_003fe4e8 = DAT_003fca4d;
  DAT_003fe4e9 = DAT_003fca4e;
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
  obd_cyc_dtc(&CAL_obd_P0123,&LEA_obd_P0123_flags,&LEA_obd_P0223_engine_start_count,
              &LEA_obd_P0223_warm_up_cycle_count,0x7b);
  obd_cyc_dtc(&CAL_obd_P0122,&LEA_obd_P0122_flags,&LEA_obd_P0222_engine_start_count,
              &LEA_obd_P0222_warm_up_cycle_count,0x7a);
  obd_cyc_dtc(&CAL_obd_P0223,&LEA_obd_P0223_flags,&DAT_002f83d4,&DAT_002f83d5,0xdf);
  obd_cyc_dtc(&CAL_obd_P0222,&LEA_obd_P0222_flags,&DAT_002f83d1,&DAT_002f83d2,0xde);
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
  
  if (((DAT_003fc63b <= coolant_smooth) && (coolant_smooth <= DAT_003fc63c)) &&
     ((uint)coolant_smooth <= (uint)engine_air_smooth + (uint)DAT_003fc63f)) {
    DAT_003fe648 = DAT_003fe648 | 8;
  }
  DAT_003f93d8 = DAT_003fc646;
  DAT_003f93da = DAT_003fc640;
  DAT_003f93dc = DAT_003fc642;
  DAT_003f93de = DAT_003fc644;
  for (bVar2 = 0; bVar2 < 6; bVar2 = bVar2 + 1) {
    iumpr_monitor[bVar2].pass_count = LEA_obd_iumpr_pass_count[bVar2];
    iumpr_monitor[bVar2].passed = 0;
    iumpr_monitor[bVar2].fail_count = LEA_obd_iumpr_fail_count[bVar2];
    iumpr_monitor[bVar2].failed = 0;
    iumpr_monitor[bVar2].sensor_error = 0;
    iumpr_monitor[bVar2].ready = 0;
    iumpr_monitor[bVar2].test_id = (&DAT_003f8c94)[bVar2];
    if (bVar2 < DAT_003f8c90) {
      iumpr_monitor[bVar2].state = 0;
    }
    else if ((bVar2 < DAT_003f8c90) || ((uint)DAT_003f8c90 + (uint)DAT_003f8c91 <= (uint)bVar2)) {
      if (((uint)bVar2 < (uint)DAT_003f8c90 + (uint)DAT_003f8c91) ||
         ((uint)DAT_003f8c90 + (uint)DAT_003f8c91 + (uint)DAT_003f8c92 <= (uint)bVar2)) {
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
  
  if (((((DAT_003fe648 & 1) == 0) && (DAT_003fdc38 != '\0')) && (DAT_003fdc3b != '\0')) &&
     (DAT_003fc636 <= engine_runtime)) {
    if (LEA_obd_iumpr_ignition_count < 0xffff) {
      LEA_obd_iumpr_ignition_count = LEA_obd_iumpr_ignition_count + 1;
    }
    else {
      LEA_obd_iumpr_ignition_count = 0;
    }
    DAT_003fe648 = DAT_003fe648 | 1;
  }
  if (((engine_is_running) && ((int)(uint)DAT_003fc638 < (int)atmo_pressure)) &&
     (DAT_003fc63a < engine_air_smooth)) {
    if (DAT_003f93da != 0) {
      DAT_003f93da = DAT_003f93da + -1;
    }
    if ((DAT_003f93de != 0) && (DAT_003fc63d <= car_speed_smooth)) {
      DAT_003f93de = DAT_003f93de + -1;
    }
    if (((DAT_003f93d8 == 0) || ((short)(ushort)CAL_idle_flow_pps_max <= (short)pps)) ||
       (DAT_003fc63e < car_speed_smooth)) {
      if (DAT_003f93d8 != 0) {
        DAT_003f93d8 = DAT_003fc646;
      }
    }
    else {
      DAT_003f93d8 = DAT_003f93d8 + -1;
    }
  }
  else if (DAT_003f93d8 != 0) {
    DAT_003f93d8 = DAT_003fc646;
  }
  if (((engine_is_running) && (DAT_003f93dc != 0)) &&
     (((int)(uint)DAT_003fc638 < (int)atmo_pressure &&
      ((DAT_003fc634 < engine_air_smooth && (engine_air_smooth < DAT_003fc635)))))) {
    DAT_003f93dc = DAT_003f93dc + -1;
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
    DAT_003fe648 = DAT_003fe648 | 4;
  }
  if ((((DAT_003fe648 & 2) == 0) && ((DAT_003fe648 & 4) == 0)) &&
     ((DAT_003f93da == 0 && ((DAT_003f93de == 0 && (DAT_003f93d8 == 0)))))) {
    if (LEA_obd_iumpr_obdcond_count < 0xffff) {
      LEA_obd_iumpr_obdcond_count = LEA_obd_iumpr_obdcond_count + 1;
    }
    else {
      LEA_obd_iumpr_obdcond_count = 0;
    }
    DAT_003fe648 = DAT_003fe648 | 2;
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
          (((DAT_003fe648 & 4) == 0 && ((DAT_003fe648 & 0x10) != 0)))))) {
        iumpr_fail(uVar2);
      }
    }
    else if ((((iumpr_monitor[uVar2 & 0xff].ready != 0) && (iumpr_monitor[uVar2 & 0xff].failed == 0)
              ) && (iumpr_monitor[uVar2 & 0xff].sensor_error == 0)) && ((DAT_003fe648 & 4) == 0)) {
      iumpr_fail(uVar2);
    }
    if (iumpr_monitor[uVar2 & 0xff].state == 3) {
      if ((((DAT_003fe648 & 2) != 0) && (iumpr_monitor[uVar2 & 0xff].passed == 0)) &&
         (((iumpr_monitor[uVar2 & 0xff].sensor_error == 0 &&
           ((DAT_003f93dc == 0 && ((DAT_003fe648 & 8) != 0)))) && ((DAT_003fe648 & 4) == 0)))) {
        iumpr_pass(uVar2);
      }
    }
    else if (((((DAT_003fe648 & 2) != 0) && (iumpr_monitor[uVar2 & 0xff].passed == 0)) &&
             (iumpr_monitor[uVar2 & 0xff].sensor_error == 0)) && ((DAT_003fe648 & 4) == 0)) {
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



// Finds best IUMPR ratio among monitors with same state

void iumpr_best(void)

{
  byte bVar1;
  uint uVar2;
  uint16_t uVar3;
  uint16_t uVar4;
  uint16_t uVar5;
  uint16_t uVar6;
  byte bVar7;
  
  uVar2 = push_26to31();
  uVar6 = iumpr_monitor[uVar2 & 0xff].ratio;
  uVar4 = iumpr_monitor[uVar2 & 0xff].fail_count;
  uVar5 = iumpr_monitor[uVar2 & 0xff].pass_count;
  uVar3 = iumpr_monitor[uVar2 & 0xff].test_id;
  bVar1 = iumpr_monitor[uVar2 & 0xff].state;
  for (bVar7 = 0; bVar7 < 6; bVar7 = bVar7 + 1) {
    if ((bVar1 == iumpr_monitor[bVar7].state) &&
       ((iumpr_monitor[bVar7].ratio < uVar6 ||
        ((uVar6 == iumpr_monitor[bVar7].ratio && (uVar5 < iumpr_monitor[bVar7].pass_count)))))) {
      uVar6 = iumpr_monitor[bVar7].ratio;
      uVar3 = iumpr_monitor[bVar7].test_id;
      uVar5 = iumpr_monitor[bVar7].pass_count;
      uVar4 = iumpr_monitor[bVar7].fail_count;
    }
  }
  *(uint16_t *)(&DAT_003fe72a + (uint)bVar1 * 8) = uVar3;
  (&DAT_003fe72e)[(uint)bVar1 * 4] = uVar4;
  (&DAT_003fe72c)[(uint)bVar1 * 4] = uVar5;
  *(uint16_t *)(&DAT_003fe730 + (uint)bVar1 * 8) = uVar6;
  pop_26to31();
  return;
}



// Main traction control logic - wheel slip detection and intervention

void traction_control(void)

{
  ushort uVar1;
  uint uVar2;
  byte bVar4;
  uint uVar3;
  int iVar5;
  uint unaff_r31;
  
  push_27to31();
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
    uVar1 = wheel_period_rl;
  }
  else {
    wheel_speed_r_max = wheel_speed_rr;
    uVar1 = wheel_period_rr;
  }
  uVar2 = abs((int)(short)wheel_speed_rl - (int)(short)wheel_speed_rr);
  wheel_speed_rear_diff = (u16_speed_1_100kph)uVar2;
  uVar2 = abs((int)(short)wheel_speed_fl - (int)(short)wheel_speed_fr);
  wheel_speed_front_diff = (u16_speed_1_100kph)uVar2;
  wheel_speed_diff = wheel_speed_front_diff;
  if (wheel_speed_rear_diff <= wheel_speed_front_diff) {
    wheel_speed_diff = wheel_speed_rear_diff;
  }
  if ((uVar1 == 0xffff) || ((sensor_fault_flags & 0x200) != 0)) {
    car_speed_smooth = 0;
  }
  else {
    if (CAL_tc_abs_ring_teeth_count == 0) {
      uVar2 = (0x100 - (uint)CAL_tc_car_speed_reactivity) * car_speed_smooth_x;
      car_speed_smooth_x =
           ((int)uVar2 >> 8) + (uint)((int)uVar2 < 0 && (uVar2 & 0xff) != 0) +
           (uint)CAL_tc_car_speed_reactivity *
           (((uint)CAL_tc_rear_tyre_circumference * 36000) / (uint)uVar1);
    }
    else {
      uVar2 = (0x100 - (uint)CAL_tc_car_speed_reactivity) * car_speed_smooth_x;
      car_speed_smooth_x =
           ((int)uVar2 >> 8) + (uint)((int)uVar2 < 0 && (uVar2 & 0xff) != 0) +
           (uint)CAL_tc_car_speed_reactivity *
           (((uint)CAL_tc_rear_tyre_circumference * 36000) /
           ((uint)uVar1 * (uint)CAL_tc_abs_ring_teeth_count));
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
  if ((tc_flags & 0x80) == 0) {
    tc_min_speed = CAL_tc_front_speed_min;
    bVar4 = lookup_3D_uint8_interpolated
                      (4,4,(ushort)wheel_speed_f_max_2,(short)pps >> 2 & 0xff,
                       CAL_tc_slip_target_base,CAL_tc_slip_target_base_X_speed_front,
                       CAL_tc_slip_target_base_Y_pps);
    unaff_r31 = (uint)bVar4;
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
    uVar2 = abs((uint)sensor_adc_tc_knob - (uint)DAT_003f93f6);
    if (4 < (int)uVar2) {
      DAT_003f93f6 = sensor_adc_tc_knob;
      DAT_003fd898 = DAT_003fd898 | 0x4000;
    }
    if (sensor_adc_tc_knob < 0x30) {
      tc_state = 0;
      bVar4 = lookup_3D_uint8_interpolated
                        (4,4,(ushort)wheel_speed_f_max_2,(short)pps >> 2 & 0xff,
                         CAL_tc_slip_target_base,CAL_tc_slip_target_base_X_speed_front,
                         CAL_tc_slip_target_base_Y_pps);
      unaff_r31 = (uint)bVar4;
      tc_flags = tc_flags | 8;
    }
    else if (sensor_adc_tc_knob < 0x3b1) {
      tc_state = 1;
      bVar4 = lookup_3D_uint8_interpolated
                        (4,4,(ushort)wheel_speed_f_max_2,(short)pps >> 2 & 0xff,
                         CAL_tc_slip_target_base,CAL_tc_slip_target_base_X_speed_front,
                         CAL_tc_slip_target_base_Y_pps);
      unaff_r31 = (int)(uint)sensor_adc_tc_knob >> (bVar4 + 5 & 0x3f) & 0xffff;
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
    uVar2 = (uint)tc_slip - (uint)tc_slip_target & 0xff;
  }
  else {
    uVar2 = 0;
  }
  if (uVar2 < tc_slip_diff_smooth) {
    uVar3 = (0x100 - (uint)CAL_tc_slip_reactivity) * tc_slip_diff_smooth_x;
    tc_slip_diff_smooth_x =
         ((int)uVar3 >> 8) + (uint)((int)uVar3 < 0 && (uVar3 & 0xff) != 0) +
         CAL_tc_slip_reactivity * uVar2;
    tc_slip_diff_smooth =
         (char)(tc_slip_diff_smooth_x >> 8) +
         ((int)tc_slip_diff_smooth_x < 0 && (tc_slip_diff_smooth_x & 0xff) != 0);
  }
  else {
    tc_slip_diff_smooth = (u8_factor_1_100)uVar2;
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
      uVar2 = (int)((uint)tc_slip_diff_smooth * (uint)CAL_tc_slip_to_retard_ratio) >> 6;
      if (uVar2 < 0x100) {
        tc_retard_adj2 = (u8_factor_1_255)uVar2;
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
  pop_27to31();
  return;
}



// Traction control task (5ms)

void traction_control_5ms(void)

{
  byte bVar1;
  
  if (((LEA_obd_iumpr_ignition_count < 6) && ((DAT_003fdc10 & 0x20) == 0)) && (10 < ecu_runtime)) {
    LEA_tc_button_fitted = true;
  }
  bVar1 = tc_flags;
  if (((sensor_adc_tc_button < 400) && ((tc_flags & 0x10) == 0)) && (LEA_tc_button_fitted == true))
  {
    if (CAL_tc_mode == 2) {
      if ((tc_flags & 0x80) == 0) {
        DAT_003f8cbc = DAT_003f8cbc + -1;
        if (DAT_003f8cbc == 0) {
          DAT_003fd898 = DAT_003fd898 | 0xc000;
          bVar1 = tc_flags | 0x90;
        }
      }
      else {
        tc_state = '\0';
        DAT_003f8cbc = 400;
        DAT_003fd898 = DAT_003fd898 | 0x4000;
        bVar1 = tc_flags & 0x7f | 0x18;
      }
    }
    else if (CAL_tc_mode == 1) {
      if (tc_state == '\x03') {
        tc_state = '\0';
        DAT_003f8cbc = 400;
        bVar1 = tc_flags & 0x7f | 0x18;
      }
      else {
        DAT_003f8cbc = DAT_003f8cbc + -1;
        bVar1 = tc_flags & 0x7f;
        if (DAT_003f8cbc == 0) {
          tc_state = '\x03';
          bVar1 = tc_flags & 0x77 | 0x10;
        }
      }
    }
  }
  else if (600 < sensor_adc_tc_button) {
    DAT_003f8cbc = 400;
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
      DAT_003f93f4 = DAT_003f93f4 + 1;
      if (0x31 < DAT_003f93f4) {
        tc_flags = tc_flags & 0xdf;
        DAT_003f93f4 = 0;
      }
    }
    else if ((tc_flags & 0x40) == 0) {
      tc_flags = tc_flags ^ 0x60;
      DAT_003f93f4 = 0;
    }
    else {
      DAT_003f93f4 = DAT_003f93f4 + 1;
      if (0x31 < DAT_003f93f4) {
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
    if (DAT_003f8cba == 0) {
      DAT_003fd898 = DAT_003fd898 | 0x20000;
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
      DAT_003f8cba = DAT_003f8cba + -1;
    }
  }
  else {
    DAT_003f8cba = 1000;
  }
  return;
}



// Initializes HC08 safety processor communication

void hc08_init(void)

{
  ushort uVar1;
  
  DAT_003f93f8 = 0;
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
  return DAT_003f9419 != '\0';
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
  DAT_003f941b = 0;
  DAT_003f941a = 0;
  DAT_003f9419 = 0;
  uVar1 = REG_SCC2R1;
  REG_SCC2R1 = uVar1 & 0xffdf | 0x20;
  hc08_parse_len = 0;
  DAT_003f9416 = 0;
  return;
}



// Reads character from SCI2

char sci2_getchar(void)

{
  uint uVar1;
  
  do {
  } while (DAT_003f9419 == '\0');
  uVar1 = (uint)DAT_003f941a;
  DAT_003f9419 = DAT_003f9419 + -1;
  if (DAT_003f941a < 0x1f) {
    DAT_003f941a = DAT_003f941a + 1;
  }
  else {
    DAT_003f941a = '\0';
  }
  return sci2_rx_buffer[uVar1];
}



// SCI receive interrupt handler

void sci_rx_handler(void)

{
  ushort uVar1;
  
  uVar1 = REG_SC2SR;
  if (((uVar1 >> 6 & 1) != 0) && (uVar1 = REG_SC2DR, DAT_003f9419 < 0x20)) {
    sci2_rx_buffer[DAT_003f941b] = (char)uVar1;
    if (DAT_003f941b < 0x1f) {
      DAT_003f941b = DAT_003f941b + 1;
    }
    else {
      DAT_003f941b = 0;
    }
    DAT_003f9419 = DAT_003f9419 + 1;
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
  DAT_003f9417 = param_2;
  DAT_003f9418 = 0;
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
    bVar2 = DAT_003f9418 + 1;
    REG_SC2DR = (ushort)(byte)sci2_tx_buffer[DAT_003f9418];
    DAT_003f9418 = bVar2;
    if (bVar2 == DAT_003f9417) {
      uVar1 = REG_SCC2R1;
      REG_SCC2R1 = uVar1 & 0xff7f;
    }
  }
  return;
}



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
      if ((param_1 == (byte)~hc08_parse_sum) && ((&hc08_parse_sum)[uVar1] == DAT_003f9416)) {
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



// Sends message to HC08 processor

void hc08_send(void)

{
  char cVar1;
  char *pcVar2;
  uint uVar3;
  char *pcVar4;
  int iVar5;
  byte *pbVar6;
  undefined8 uVar7;
  
  uVar7 = push_27to31();
  pcVar2 = (char *)((ulonglong)uVar7 >> 0x20);
  uVar3 = (uint)uVar7;
  *pcVar2 = (char)uVar7;
  DAT_003f9416 = DAT_003f9416 + '\x01';
  pcVar2[(uVar3 & 0xff) + 1] = DAT_003f9416;
  pbVar6 = (byte *)(pcVar2 + (uVar3 & 0xff) + 2);
  *pbVar6 = 0;
  pcVar4 = pcVar2;
  for (iVar5 = 0; iVar5 <= (int)((uVar3 & 0xff) + 1); iVar5 = iVar5 + 1) {
    cVar1 = *pcVar4;
    pcVar4 = pcVar4 + 1;
    *pbVar6 = *pbVar6 + cVar1;
  }
  *pbVar6 = ~*pbVar6;
  sci2_send(pcVar2,uVar3 + 3 & 0xff);
  pop_27to31();
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
        DAT_003fe78f = hc08_parse_buf[3];
        DAT_003fe790 = hc08_parse_buf[4];
        DAT_003fe791 = hc08_parse_buf[5];
        DAT_003fe792 = hc08_parse_buf[6];
        hc08_tps_1 = hc08_parse_buf[7];
        hc08_tps_2 = hc08_parse_buf[8];
        hc08_pps_1 = hc08_parse_buf[9];
        hc08_pps_2 = hc08_parse_buf[10];
        DAT_003fe797 = hc08_parse_buf[0xb];
        DAT_003fe798 = hc08_parse_buf[0xc];
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
      DAT_003fe933 = 1;
      (&DAT_003fe934)[param_2] = 1;
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
        (&DAT_003fe934)[diag_channel[param_1 & 0xff].result] = 0;
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
  
  DAT_003fe933 = 0;
  for (iVar1 = 0; iVar1 < 0x1e; iVar1 = iVar1 + 1) {
    (&DAT_003fe934)[iVar1] = 0;
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
  diag_channel[0x19].confirm_threshold = (ushort)CAL_obd_P0135_confirm_threshold;
  diag_channel[0x19].clear_threshold = 10000;
  diag_channel[0x1a].confirm_threshold = (ushort)CAL_obd_P0141_confirm_threshold;
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
  
  DAT_003fe9b9 = out_range(param_1,pps_1_range_high,pps_1_range_low);
  DAT_003fe9ba = out_range(param_2,pps_2_range_high,pps_2_range_low);
  if (DAT_003fe9b9 == 0) {
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
    DAT_003fe9ae = pps_1_history[2];
  }
  else {
    if (DAT_003fe9b9 == 2) {
      diag_set(1,2);
    }
    else {
      diag_set(1,1);
    }
    pps_1 = DAT_003fe9ae;
  }
  if (DAT_003fe9ba == 0) {
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
    DAT_003fe9b0 = pps_2_history[2];
  }
  else {
    if (DAT_003fe9ba == 2) {
      diag_set(2,4);
    }
    else {
      diag_set(2,3);
    }
    pps_2 = DAT_003fe9b0;
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
       pps_sensor_correlation_check(DAT_003fe9b9,DAT_003fe9ba,iVar4,iVar3,CAL_sensor_pps_match_max);
  if ((1 < diag_channel[1].state) || (1 < diag_channel[2].state)) {
    DAT_003fe9bb = 1;
  }
  if ((diag_channel[1].state < 2) || (diag_channel[2].state < 2)) {
    DAT_003fe9ce = 0;
  }
  else {
    DAT_003fe9ce = 1;
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
      if (DAT_003fe9b9 == 0) {
        if (diag_channel[1].state < 2) {
          pps_min = pps_1;
          flags_to_hc08 = flags_to_hc08 | 1;
        }
        else if (diag_channel[1].state == 3) {
          pps_min = DAT_003fe9b0;
          flags_to_hc08 = flags_to_hc08 & 0xfe;
        }
      }
      if (DAT_003fe9ba == 0) {
        if (diag_channel[2].state < 2) {
          pps_min = pps_2;
          flags_to_hc08 = flags_to_hc08 & 0xfe;
        }
        else if (diag_channel[2].state == 3) {
          pps_min = DAT_003fe9ae;
          flags_to_hc08 = flags_to_hc08 | 1;
        }
      }
    }
  }
  else if ((pps_correlation_state < 4) &&
          ((diag_channel[1].state < 2 || (diag_channel[2].state < 2)))) {
    if ((diag_channel[1].state < 2) && (diag_channel[2].state < 2)) {
      if (DAT_003fe9ae < DAT_003fe9b0) {
        pps_min = DAT_003fe9ae;
        flags_to_hc08 = flags_to_hc08 | 1;
      }
      else {
        pps_min = DAT_003fe9b0;
        flags_to_hc08 = flags_to_hc08 & 0xfe;
      }
    }
    else if ((diag_channel[1].state < 2) && (1 < diag_channel[2].state)) {
      pps_min = DAT_003fe9ae;
      flags_to_hc08 = flags_to_hc08 | 1;
    }
    else if ((1 < diag_channel[1].state) && (diag_channel[2].state < 2)) {
      pps_min = DAT_003fe9b0;
      flags_to_hc08 = flags_to_hc08 & 0xfe;
    }
  }
  if ((1 < diag_channel[1].state) || (1 < diag_channel[2].state)) {
    DAT_003fe9bb = 1;
  }
  if ((diag_channel[1].state < 2) || (diag_channel[2].state < 2)) {
    DAT_003fe9ce = 0;
  }
  else {
    DAT_003fe9ce = 1;
  }
  if (diag_channel[1].state < 2) {
    DAT_003fe9a8 = DAT_003fe9a8 & 0xfe;
    flags_to_hc08 = flags_to_hc08 & 0xbf;
  }
  else {
    DAT_003fe9a8 = DAT_003fe9a8 | 1;
    flags_to_hc08 = flags_to_hc08 | 0x40;
  }
  if (diag_channel[2].state < 2) {
    DAT_003fe9a8 = DAT_003fe9a8 & 0xfd;
    flags_to_hc08 = flags_to_hc08 & 0xbf;
  }
  else {
    DAT_003fe9a8 = DAT_003fe9a8 | 2;
    flags_to_hc08 = flags_to_hc08 | 0x40;
  }
  if (diag_channel[3].state < 2) {
    DAT_003fe9a8 = DAT_003fe9a8 & 0xfb;
  }
  else {
    DAT_003fe9a8 = DAT_003fe9a8 | 4;
    DAT_003fe9bb = 1;
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
        if (((int)(uint)param_5 < (int)uVar2) && ((int)param_4 < (int)(uint)DAT_003fc590)) {
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
  DAT_003fe954 = 0;
  DAT_003fe9a8 = 0;
  DAT_003fe9b4 = 0;
  DAT_003fe9b2 = 0;
  DAT_003fe9b0 = 0;
  DAT_003fe9ae = 0;
  pps_2 = 0;
  pps_1 = 0;
  DAT_003fe9b6 = 0x3ff;
  pps_correlation_state = 0;
  DAT_003fe9ba = 0;
  DAT_003fe9b9 = 0;
  DAT_003fe9bb = 0;
  tps_max = 0;
  DAT_003fe9c8 = 0;
  DAT_003fe9c6 = 0;
  DAT_003fe9c4 = 0;
  DAT_003fe9c2 = 0;
  tps_2 = 0;
  tps_1 = 0;
  DAT_003fe9ca = 0;
  tps_correlation_state = 0;
  DAT_003fe9cd = 0;
  DAT_003fe9cc = 0;
  DAT_003fe9ce = 0;
  DAT_003fe9cf = 0;
  tps_both_fault = false;
  DAT_003fe9d1 = 0;
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
  
  DAT_003fe9cc = out_range(param_1,tps_1_range_high,tps_1_range_low);
  DAT_003fe9cd = out_range(param_2,tps_2_range_high,tps_2_range_low);
  if (DAT_003fe9cc == 0) {
    if (LEA_sensor_tps_1_offset < param_1) {
      uVar1 = (uint)tps_1_gain_corrected * ((uint)param_1 - (uint)tps_1_range_corrected_low);
      tps_1 = (short)((int)uVar1 >> 6) + (ushort)((int)uVar1 < 0 && (uVar1 & 0x3f) != 0);
      tps_1_history[2] = tps_1_history[1];
      tps_1_history[1] = tps_1_history[0];
      tps_1_history[0] = tps_1;
    }
    diag_set(4,0);
    DAT_003fe9c2 = tps_1_history[2];
  }
  else {
    if (DAT_003fe9cc == 2) {
      diag_set(4,7);
    }
    else {
      diag_set(4,6);
    }
    tps_1 = DAT_003fe9c2;
  }
  if (DAT_003fe9cd == 0) {
    if (LEA_sensor_tps_2_offset < param_2) {
      uVar1 = abs((uint)param_2 - (uint)tps_2_range_corrected_low);
      uVar1 = tps_2_gain_computed * uVar1;
      tps_2 = (short)((int)uVar1 >> 6) + (ushort)((int)uVar1 < 0 && (uVar1 & 0x3f) != 0);
      tps_2_history[2] = tps_2_history[1];
      tps_2_history[1] = tps_2_history[0];
      tps_2_history[0] = tps_2;
    }
    diag_set(5,0);
    DAT_003fe9c4 = tps_2_history[2];
  }
  else {
    if (DAT_003fe9cd == 2) {
      diag_set(5,9);
    }
    else {
      diag_set(5,8);
    }
    tps_2 = DAT_003fe9c4;
  }
  tps_correlation_state =
       tps_sensor_correlation_check
                 (DAT_003fe9cc,DAT_003fe9cd,(int)(short)tps_1,(int)(short)tps_2,
                  CAL_sensor_tps_match_max);
  if (tps_correlation_state == 2) {
    diag_set(8,10);
    if ((short)tps_2 < (short)tps_1) {
      tps_max = tps_1;
      flags_to_hc08 = flags_to_hc08 | 2;
      DAT_003fe9b6 = 0x3ff;
    }
    else {
      tps_max = tps_2;
      flags_to_hc08 = flags_to_hc08 & 0xfd;
      DAT_003fe9b6 = DAT_003fc590;
    }
  }
  else if (tps_correlation_state < 2) {
    if (tps_correlation_state == 0) {
      diag_set(8,0);
      if (((diag_channel[4].state < 2) && (diag_channel[5].state < 2)) &&
         (diag_channel[8].state < 2)) {
        tps_max = tps_1;
        flags_to_hc08 = flags_to_hc08 | 2;
        DAT_003fe9b6 = 0x3ff;
      }
      else if (diag_channel[4].state == 3) {
        if (diag_channel[5].state != 3) {
          tps_max = tps_2;
          flags_to_hc08 = flags_to_hc08 & 0xfd;
          DAT_003fe9b6 = DAT_003fc590;
        }
      }
      else {
        tps_max = tps_1;
        flags_to_hc08 = flags_to_hc08 | 2;
        DAT_003fe9b6 = 0x3ff;
      }
    }
    else if (true) {
      if ((1 < diag_channel[4].state) && (1 < diag_channel[5].state)) {
        DAT_003fe9b6 = DAT_003fc590;
      }
      if (DAT_003fe9cc == 0) {
        if (diag_channel[4].state < 2) {
          tps_max = tps_1;
          flags_to_hc08 = flags_to_hc08 | 2;
          DAT_003fe9b6 = 0x3ff;
        }
        else if (diag_channel[4].state == 3) {
          tps_max = DAT_003fe9c4;
          flags_to_hc08 = flags_to_hc08 & 0xfd;
          DAT_003fe9b6 = DAT_003fc590;
        }
      }
      if (DAT_003fe9cd == 0) {
        if (diag_channel[5].state < 2) {
          tps_max = tps_2;
          flags_to_hc08 = flags_to_hc08 & 0xfd;
          DAT_003fe9b6 = DAT_003fc590;
        }
        else if (diag_channel[5].state == 3) {
          tps_max = DAT_003fe9c2;
          flags_to_hc08 = flags_to_hc08 | 2;
          DAT_003fe9b6 = 0x3ff;
        }
      }
    }
  }
  else if ((tps_correlation_state < 4) &&
          ((diag_channel[4].state < 2 || (diag_channel[5].state < 2)))) {
    if ((diag_channel[4].state < 2) && (diag_channel[5].state < 2)) {
      if ((short)DAT_003fe9c4 < (short)DAT_003fe9c2) {
        tps_max = DAT_003fe9c2;
        flags_to_hc08 = flags_to_hc08 | 2;
        DAT_003fe9b6 = 0x3ff;
      }
      else {
        tps_max = DAT_003fe9c4;
        flags_to_hc08 = flags_to_hc08 & 0xfd;
        DAT_003fe9b6 = DAT_003fc590;
      }
    }
    else if ((diag_channel[4].state < 2) && (1 < diag_channel[5].state)) {
      tps_max = DAT_003fe9c2;
      flags_to_hc08 = flags_to_hc08 | 2;
      DAT_003fe9b6 = 0x3ff;
    }
    else if ((1 < diag_channel[4].state) && (diag_channel[5].state < 2)) {
      tps_max = DAT_003fe9c4;
      flags_to_hc08 = flags_to_hc08 & 0xfd;
      DAT_003fe9b6 = DAT_003fc590;
    }
  }
  if ((1 < diag_channel[4].state) || (1 < diag_channel[5].state)) {
    DAT_003fe9ca = 1;
  }
  if ((diag_channel[4].state < 2) || (diag_channel[5].state < 2)) {
    tps_both_fault = false;
  }
  else {
    tps_both_fault = true;
  }
  if (diag_channel[4].state < 2) {
    DAT_003fe954 = DAT_003fe954 & 0xfe;
    flags_to_hc08 = flags_to_hc08 & 0x7f;
  }
  else {
    DAT_003fe954 = DAT_003fe954 | 1;
    flags_to_hc08 = flags_to_hc08 | 0x80;
  }
  if (diag_channel[5].state < 2) {
    DAT_003fe954 = DAT_003fe954 & 0xfd;
    flags_to_hc08 = flags_to_hc08 & 0x7f;
  }
  else {
    DAT_003fe954 = DAT_003fe954 | 2;
    flags_to_hc08 = flags_to_hc08 | 0x80;
  }
  if (diag_channel[8].state < 2) {
    DAT_003fe954 = DAT_003fe954 & 0xbf;
  }
  else {
    DAT_003fe954 = DAT_003fe954 | 0x40;
    DAT_003fe9ca = 1;
  }
  return;
}



// OBD Mode 11: Resets ECU learned tables

void obd_mode_0x11_reset_learn_table(void)

{
  obd_resp[0] = 81;
  obd_resp_len = 1;
  reset_learn_tables();
  send_obd_resp();
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
    (&DAT_003fdcb6)[iVar2] = 0;
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
    *(undefined1 *)((int)&LEA_ecu_engine_speed_byte_coefficient + iVar2) =
         *(undefined1 *)(iVar2 + 0x3fd1ce);
  }
  for (iVar2 = 0x28; iVar2 < 0x128; iVar2 = iVar2 + 1) {
    *(undefined1 *)((int)&LEA_ecu_engine_speed_byte_coefficient + iVar2) = 100;
  }
  LEA_ltft_zone1_adj = 0;
  LEA_ltft_zone3_adj = 128;
  LEA_ltft_zone2_adj = 128;
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
  uint i;
  ushort r;
  
  r = REG_PORTQS;
  REG_PORTQS = r & 0xfffb;
  for (i = 0; (i & 0xffff) < (uint)size; i = i + 1) {
    eeprom_write_byte(buffer[i & 0xffff],i);
    REG_SWSR = 0x556c;
    REG_SWSR = 0xaa39;
  }
  r = REG_PORTQS;
  REG_PORTQS = r & 0xfffb | 4;
  return;
}



// Reads buffer from EEPROM

void eeprom_read(char *buffer,ushort size)

{
  char c;
  uint i;
  ushort r;
  
  r = REG_PORTQS;
  REG_PORTQS = r & 0xfffb;
  for (i = 0; (i & 0xffff) < (uint)size; i = i + 1) {
    c = eeprom_read_byte(i);
    buffer[i & 0xffff] = c;
    REG_SWSR = 0x556c;
    REG_SWSR = 0xaa39;
  }
  r = REG_PORTQS;
  REG_PORTQS = r & 0xfffb | 4;
  return;
}



// Reads buffer from EEPROM at specified address

void eeprom_read_at(uint addr,char *buffer,ushort size)

{
  ushort uVar1;
  char cVar2;
  uint addr_00;
  
  uVar1 = REG_PORTQS;
  REG_PORTQS = uVar1 & 0xfffb;
  for (addr_00 = addr; (addr_00 & 0xffff) < (addr & 0xffff) + (uint)size; addr_00 = addr_00 + 1) {
    cVar2 = eeprom_read_byte(addr_00);
    buffer[(addr_00 & 0xffff) - (addr & 0xffff)] = cVar2;
    REG_SWSR = 0x556c;
    REG_SWSR = 0xaa39;
  }
  uVar1 = REG_PORTQS;
  REG_PORTQS = uVar1 & 0xfffb | 4;
  return;
}



// Writes byte to EEPROM with verification

bool eeprom_write_byte_checked(char c,uint addr)

{
  byte bVar1;
  char cVar2;
  char acStack_18 [4];
  char local_14;
  undefined1 local_13;
  undefined1 local_12;
  char local_11;
  
  do {
    bVar1 = eeprom_status();
  } while ((bVar1 & 1) != 0);
  eeprom_write_enable();
  local_14 = '\x02';
  local_13 = (undefined1)(addr >> 8);
  local_12 = (undefined1)addr;
  local_11 = c;
  eeprom_command(&local_14,acStack_18,4);
  cVar2 = eeprom_read_byte(addr);
  return c == cVar2;
}



// Writes buffer to EEPROM at specified address

int eeprom_write_at(uint addr,char *buffer,ushort size)

{
  ushort uVar1;
  bool bVar2;
  uint addr_00;
  
  uVar1 = REG_PORTQS;
  REG_PORTQS = uVar1 & 0xfffb;
  addr_00 = addr;
  while( true ) {
    if ((addr & 0xffff) + (uint)size <= (addr_00 & 0xffff)) {
      uVar1 = REG_PORTQS;
      REG_PORTQS = uVar1 & 0xfffb | 4;
      return 1;
    }
    bVar2 = eeprom_write_byte_checked(buffer[(addr_00 & 0xffff) - (addr & 0xffff)],addr_00);
    if (!bVar2) break;
    REG_SWSR = 0x556c;
    REG_SWSR = 0xaa39;
    addr_00 = addr_00 + 1;
  }
  return 0;
}



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
  
  push_26to31();
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
    puVar7 = (undefined1 *)dev_varptr_list[uint16_t_ARRAY_003f9ba8[iVar6] & 0x3ff].ptr;
    if (*(char *)&dev_varptr_list[uint16_t_ARRAY_003f9ba8[iVar6] & 0x3ff].size_le == '\x01') {
      (&DAT_003f8fc0)[iVar6 * 2] = 0;
      (&DAT_003f8fc1)[iVar6 * 2] = *puVar7;
    }
    else if (*(char *)&dev_varptr_list[uint16_t_ARRAY_003f9ba8[iVar6] & 0x3ff].size_le == '\x02') {
      (&DAT_003f8fc0)[iVar6 * 2] = *puVar7;
      (&DAT_003f8fc1)[iVar6 * 2] = puVar7[1];
    }
    else if (*(char *)&dev_varptr_list[uint16_t_ARRAY_003f9ba8[iVar6] & 0x3ff].size_le == '\x04') {
      (&DAT_003f8fc0)[iVar6 * 2] = puVar7[2];
      (&DAT_003f8fc1)[iVar6 * 2] = puVar7[3];
    }
  }
  pop_26to31();
  return;
}



// Walks CRT cleanup linked list of destructor callbacks

void cleanup_callbacks(void)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  
  while (DAT_003f8fd8 != (int *)0x0) {
    puVar1 = DAT_003f8fd8 + 1;
    puVar2 = DAT_003f8fd8 + 2;
    DAT_003f8fd8 = (int *)*DAT_003f8fd8;
    (*(code *)*puVar1)(*puVar2,0xffffffff);
  }
  return;
}



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



// Restores registers r20-r31 from stack

void pop_20to31(void)

{
  return;
}



// Restores registers r22-r31 from stack

void pop_22to31(void)

{
  return;
}



// Restores registers r23-r31 from stack

void pop_23to31(void)

{
  return;
}



// Restores registers r24-r31 from stack

void pop_24to31(void)

{
  return;
}



// Restores registers r25-r31 from stack

void pop_25to31(void)

{
  return;
}



// Restores registers r26-r31 from stack

void pop_26to31(void)

{
  return;
}



// Restores registers r27-r31 from stack

void pop_27to31(void)

{
  return;
}



// CRT exit() implementation: runs atexit callbacks, cleanup list, then calls atexit_handlers

void exit(int __status)

{
  undefined **ppuVar1;
  
  if (DAT_003f8fe0 == 0) {
    while (0 < DAT_003f8ff0) {
      DAT_003f8ff0 = DAT_003f8ff0 + -1;
      (**(code **)(&DAT_003f9468 + DAT_003f8ff0 * 4))();
    }
    cleanup_callbacks();
    for (ppuVar1 = &PTR_cleanup_callbacks_0007d970; (code *)*ppuVar1 != (code *)0x0;
        ppuVar1 = ppuVar1 + 1) {
      (*(code *)*ppuVar1)();
    }
    if (DAT_003f8fe4 != (code *)0x0) {
      (*DAT_003f8fe4)();
      DAT_003f8fe4 = (code *)0x0;
    }
  }
  atexit_handlers(__status);
  return;
}



// Runs registered atexit() functions, then dead_end()

void atexit_handlers(void)

{
  while (0 < DAT_003f8ff4) {
    DAT_003f8ff4 = DAT_003f8ff4 + -1;
    (**(code **)(&DAT_003f9568 + DAT_003f8ff4 * 4))();
  }
  if (DAT_003f8fe8 != (code *)0x0) {
    (*DAT_003f8fe8)();
    DAT_003f8fe8 = (code *)0x0;
  }
  dead_end();
  return;
}



// Returns absolute value of integer

uint abs(int v)

{
  return (v >> 31 ^ v) - (v >> 31);
}



// Compares two memory blocks, returns -1/0/1 at first mismatch

int memcmp(char *a,char *b,uint size)

{
  int i;
  byte *pa;
  byte *pb;
  
  pa = (byte *)(a + -1);
  pb = (byte *)(b + -1);
  i = size + 1;
  do {
    i = i + -1;
    if (i == 0) {
      return 0;
    }
    pa = pa + 1;
    pb = pb + 1;
  } while (*pa == *pb);
  if (*pb <= *pa) {
    return 1;
  }
  return -1;
}



// Compares two null-terminated strings up to N bytes, returns byte difference at first mismatch

int strncmp(byte *ptr1,byte *ptr2,uint num)

{
  uint uVar1;
  byte *pbVar2;
  byte *pbVar3;
  int iVar4;
  
  pbVar2 = ptr1 + -1;
  pbVar3 = ptr2 + -1;
  iVar4 = num + 1;
  while( true ) {
    iVar4 = iVar4 + -1;
    if (iVar4 == 0) {
      return 0;
    }
    pbVar2 = pbVar2 + 1;
    uVar1 = (uint)*pbVar2;
    pbVar3 = pbVar3 + 1;
    if (uVar1 != *pbVar3) break;
    if (uVar1 == 0) {
      return 0;
    }
  }
  return uVar1 - *pbVar3;
}


