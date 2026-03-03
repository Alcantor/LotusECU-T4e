#define 1 0x1
#define 0 0x0
#define 0x90 0x90

typedef unsigned char   undefined;

typedef unsigned char    byte;
typedef unsigned char    uchar;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned short    ushort;
typedef ushort uint16_t;

typedef uchar uint8_t;



byte REG_INTSCR;
byte REG_CONFIG1;
undefined2 DAT_015e;
byte REG_PTD;
byte REG_ADSCR;
byte REG_ADR;
byte REG_PTB;
byte REG_DDRD;
byte DAT_0063;
char DAT_0062;
char DAT_0061;
char DAT_0060;
undefined1 adc_PTB1;
undefined1 adc_PTB2_tps_1;
undefined1 adc_PTB3_tps_2;
undefined1 adc_PTB7;
undefined1 adc_PTB4_pps_1;
undefined1 adc_PTB5_pps_2;
undefined1 adc_PTB6;
byte DAT_0064;
undefined DAT_eb82;
undefined1 crc16_high;
undefined1 crc16_low;
undefined1 state;
undefined1 flags_to_mpc;
undefined1 flags_from_mpc;
undefined1 timer_1;
uint8_t[16] CAL_tps_target_X_pps;
undefined1 timer_2;
uint8_t[16] CAL_tps_target;
undefined1 timer_3_low;
undefined1 timer_3_high;
undefined1 timer_3_alive;
char DAT_0064;
undefined1 tps_max;
undefined1 pps_min;
undefined1 pps_to_mpc;
undefined1 tps_to_mpc;
undefined1 tps_target_to_mpc;
undefined1 timer_countdown_1;
undefined1 timer_countdown_2;
undefined1 DAT_00b8;
undefined1 DAT_00b7;
undefined1 DAT_00b6;
undefined1 DAT_00b3;
byte REG_SCC1;
byte REG_SCC2;
undefined1 parse_len;
byte REG_SCBR;
char DAT_00b6;
byte DAT_00b7;
undefined1 DAT_00b4;
undefined1 DAT_00b5;
byte DAT_00b6;
byte DAT_00b8;
byte REG_SCS1;
byte REG_SCDR;
byte DAT_00b5;
byte DAT_00b4;
undefined1 DAT_0064;
undefined1 timer_countdown3;
undefined1 parse_sum;
char[20] parse_buffer;
undefined1 UNK_00ba;
undefined1 UNK_00bb;
undefined1 UNK_00bc;
undefined1 UNK_00bd;
undefined1 UNK_00be;
undefined1 UNK_00bf;
undefined1 UNK_00c0;
undefined1 UNK_00c1;
undefined1 UNK_00c2;
undefined1 UNK_00c3;
undefined1 UNK_00c4;
undefined1 UNK_00c5;
undefined1 UNK_00c6;
undefined1 UNK_00c7;
byte REG_T1SC;
byte REG_T1MODH;
byte REG_T1MODL;
byte DAT_0062;
byte DAT_0061;
undefined1 DAT_0060;
undefined1 DAT_0061;
undefined1 DAT_0062;
undefined1 DAT_0063;
byte DAT_0060;
char DAT_0063;

// System initialization: disable COP watchdog, enable IRQ, init GPIO/SCI/Timer, init state machine

void init_system(void)

{
  byte bVar1;
  
  bVar1 = REG_CONFIG1;
  REG_CONFIG1 = bVar1 | 1;
  REG_INTSCR = 2;
  init_gpio();
  init_sci();
  init_timer1();
  init_state();
  return;
}



// WARNING: This function may have set the stack pointer
// Reset vector handler: set stack pointer, call init, enter main loop

void isr_reset(void)

{
  DAT_015e = 0xdc18;
  init_system();
  entry_point();
  return;
}



// Diagnostic test mode: infinite loop reading ADC and mirroring value to PTD and PTB
// (nibble-swapped)

void adc_test_loop(void)

{
  byte bVar1;
  
  do {
    do {
      bVar1 = REG_ADSCR;
    } while ((bVar1 & 0x80) == 0);
    bVar1 = REG_ADR;
    REG_PTD = bVar1;
    REG_PTB = bVar1 >> 4 | bVar1 << 4;
  } while( true );
}



// Initialize GPIO: PTD3 high (engine OK), PTD4 low (no forced idle), PTD2 output

byte init_gpio(void)

{
  byte bVar1;
  
  bVar1 = REG_PTD;
  REG_PTD = bVar1 | 8;
  bVar1 = REG_DDRD;
  REG_DDRD = bVar1 | 8;
  bVar1 = REG_PTD;
  REG_PTD = bVar1 & 0xef;
  bVar1 = REG_DDRD;
  REG_DDRD = bVar1 | 0x10;
  bVar1 = REG_DDRD;
  REG_DDRD = bVar1 | 4;
  return bVar1 | 4;
}



// Entry point: calls main loop

void entry_point(void)

{
  main();
  return;
}



// 2D table lookup with interpolation (y params are high bytes of 16-bit pointers)

uint8_t lookup_2D_uint8_interpolated(uint16_t size_x,uint16_t input_x,uint8_t *lut,uint8_t *x_axis)

{
  byte bVar1;
  byte bVar2;
  undefined1 auStack_1d [4];
  undefined1 auStack_19 [4];
  undefined1 auStack_15 [3];
  char local_12;
  undefined1 local_11;
  undefined1 local_10;
  char local_f;
  byte local_e;
  undefined1 auStack_d [2];
  char local_b;
  byte local_a;
  undefined1 auStack_9 [4];
  undefined1 local_5;
  undefined1 local_4;
  undefined1 local_3;
  undefined1 local_2;
  undefined1 uStack_1;
  
  uStack_1 = (undefined1)(size_x >> 8);
  local_2 = (undefined1)size_x;
  local_3 = 0;
  local_4 = 0;
  local_5 = 0;
  acc32_load(&local_5);
  acc32_sub();
  acc32_store(auStack_d);
  local_e = 0;
  local_f = '\0';
  local_10 = 0;
  local_11 = 0;
  if (*x_axis < (byte)input_x) {
    if ((byte)input_x <
        *(byte *)CONCAT11(local_b + x_axis._0_1_ + CARRY1(local_a,(byte)x_axis),
                          local_a + (byte)x_axis)) {
      while( true ) {
        bVar1 = *(byte *)CONCAT11(local_f + x_axis._0_1_ + CARRY1(local_e,(byte)x_axis),
                                  local_e + (byte)x_axis);
        bVar2 = bVar1 - (byte)input_x;
        bVar2 = ((char)bVar2 < '\0') << 2 |
                (((bVar1 & ~(byte)input_x & ~bVar2 | ~bVar1 & (byte)input_x & bVar2) & 0x80) != 0)
                << 7;
        if ((byte)input_x <= bVar1) break;
        acc32_load(&local_11);
        acc32_cmp(auStack_d);
        if ((byte)(bVar2 >> 2 & 1 ^ bVar2 >> 7) != 1) break;
        DAT_0063 = 1;
        DAT_0062 = 0;
        DAT_0061 = 0;
        DAT_0060 = 0;
        mem32_add(&local_11);
      }
      if (*(byte *)CONCAT11(local_f + x_axis._0_1_ + CARRY1(local_e,(byte)x_axis),
                            local_e + (byte)x_axis) == (byte)input_x) {
        return *(uint8_t *)
                CONCAT11(local_f + lut._0_1_ + CARRY1(local_e,(byte)lut),local_e + (byte)lut);
      }
      if (*(char *)CONCAT11(local_f + x_axis._0_1_ + CARRY1(local_e,(byte)x_axis),
                            local_e + (byte)x_axis) ==
          *(char *)CONCAT11((local_f - (local_e == 0)) + x_axis._0_1_ +
                            CARRY1(local_e - 1,(byte)x_axis),(local_e - 1) + (byte)x_axis)) {
        input_x._1_1_ =
             *(byte *)CONCAT11(local_f + lut._0_1_ + CARRY1(local_e,(byte)lut),local_e + (byte)lut);
      }
      else {
        local_12 = *(char *)CONCAT11((local_f - (local_e == 0)) + lut._0_1_ +
                                     CARRY1(local_e - 1,(byte)lut),(local_e - 1) + (byte)lut);
        acc32_extend16(*(char *)CONCAT11(local_f + lut._0_1_ + CARRY1(local_e,(byte)lut),
                                         local_e + (byte)lut) - local_12);
        acc32_store(auStack_9);
        DAT_0063 = *(char *)CONCAT11((local_f - (local_e == 0)) + lut._0_1_ +
                                     CARRY1(local_e - 1,(byte)lut),(local_e - 1) + (byte)lut);
        DAT_0060 = (char)DAT_0063 >> 7;
        DAT_0061 = DAT_0060;
        DAT_0062 = DAT_0060;
        acc32_store(auStack_15);
        DAT_0063 = *(undefined1 *)
                    CONCAT11((local_f - (local_e == 0)) + x_axis._0_1_ +
                             CARRY1(local_e - 1,(byte)x_axis),(local_e - 1) + (byte)x_axis);
        DAT_0062 = 0;
        DAT_0061 = 0;
        DAT_0060 = 0;
        acc32_store(auStack_19);
        DAT_0063 = *(undefined1 *)
                    CONCAT11(local_f + x_axis._0_1_ + CARRY1(local_e,(byte)x_axis),
                             local_e + (byte)x_axis);
        DAT_0062 = 0;
        DAT_0061 = 0;
        DAT_0060 = 0;
        acc32_sub(auStack_19);
        acc32_store(auStack_19);
        DAT_0063 = *(undefined1 *)
                    CONCAT11((local_f - (local_e == 0)) + x_axis._0_1_ +
                             CARRY1(local_e - 1,(byte)x_axis),(local_e - 1) + (byte)x_axis);
        DAT_0062 = 0;
        DAT_0061 = 0;
        DAT_0060 = 0;
        acc32_store(auStack_1d);
        DAT_0063 = (byte)input_x;
        DAT_0062 = 0;
        DAT_0061 = 0;
        DAT_0060 = 0;
        acc32_sub(auStack_1d);
        acc32_mul(auStack_9);
        acc32_div_signed(auStack_19);
        acc32_add(auStack_15);
        input_x._1_1_ = DAT_0063;
      }
    }
    else {
      input_x._1_1_ =
           *(byte *)CONCAT11(local_b + lut._0_1_ + CARRY1(local_a,(byte)lut),local_a + (byte)lut);
    }
  }
  else {
    input_x._1_1_ = *lut;
  }
  return (byte)input_x;
}



// Read single ADC channel: start conversion, wait for completion, return result

byte adc_read(byte param_1)

{
  byte bVar1;
  
  REG_ADSCR = param_1;
  do {
    bVar1 = REG_ADSCR;
  } while ((bVar1 & 0x80) == 0);
  bVar1 = REG_ADR;
  return bVar1;
}



// Sample all 7 ADC channels (PTB1-PTB7) into RAM variables

void adc_sample(void)

{
  adc_PTB1 = adc_read(1);
  adc_PTB2_tps_1 = adc_read(2);
  adc_PTB3_tps_2 = adc_read(3);
  adc_PTB4_pps_1 = adc_read(4);
  adc_PTB5_pps_2 = adc_read(5);
  adc_PTB6 = adc_read(6);
  adc_PTB7 = adc_read(7);
  return;
}



// CRC-16 update step using lookup table

undefined2 crc16_update(byte param_1,byte param_2,byte param_3)

{
  DAT_0064 = param_3 ^ (&DAT_eb82)[CONCAT11(param_2 >> 7,param_2 << 1)] ^ 0x55 < param_1;
  return CONCAT11(param_2 >> 7,DAT_0064);
}



// Compute CRC-16 over ROM regions for integrity check

void crc16_compute(void)

{
  byte bVar1;
  undefined1 extraout_X;
  undefined1 extraout_X_00;
  char cVar2;
  undefined1 local_3;
  undefined1 local_2;
  undefined1 local_1;
  
  crc16_high = 1;
  crc16_low = 0x23;
  local_1 = 0xdc;
  cVar2 = '\0';
  local_3 = 0;
  local_2 = '\0';
  do {
    bVar1 = local_1;
    cVar2 = cVar2 + '\x01';
    if (cVar2 == '\0') {
      local_1 = local_1 + 1;
    }
    crc16_low = crc16_update((ushort)bVar1 << 8,crc16_high,crc16_low);
    local_2 = local_2 + '\x01';
    if (local_2 == '\0') {
      local_3 = local_3 + 1;
    }
    crc16_high = extraout_X;
  } while (local_3 < 0x20);
  local_1 = 0xff;
  cVar2 = -0x24;
  local_3 = 0;
  local_2 = 0;
  do {
    bVar1 = local_1;
    cVar2 = cVar2 + '\x01';
    if (cVar2 == '\0') {
      local_1 = local_1 + 1;
    }
    crc16_low = crc16_update((ushort)bVar1 << 8,crc16_high,crc16_low);
    crc16_high = extraout_X_00;
    local_2 = local_2 + 1;
    if (local_2 == 0) {
      local_3 = local_3 + 1;
    }
  } while (local_3 < (local_2 < 0x24));
  return;
}



// Release forced idle: clear PTD4 output and flag bit 4 (only if state < 4)

void release_forced_idle(void)

{
  byte bVar1;
  
  if (state < 4) {
    bVar1 = REG_PTD;
    REG_PTD = bVar1 & 0xef;
    flags_to_mpc = flags_to_mpc & 0xef;
  }
  return;
}



// Force idle (P2014): set state >= 4, assert PTD4, set flag bit 4

void force_idle(void)

{
  byte bVar1;
  
  if (state < 4) {
    state = 4;
  }
  bVar1 = REG_PTD;
  REG_PTD = bVar1 | 0x10;
  flags_to_mpc = flags_to_mpc | 0x10;
  return;
}



// Release engine shutdown: set PTD3 high (active-low logic), clear flag bit 5 (only if state < 5)

void release_engine_shutdown(void)

{
  byte bVar1;
  
  if (state < 5) {
    bVar1 = REG_PTD;
    REG_PTD = bVar1 | 8;
    flags_to_mpc = flags_to_mpc & 0xdf;
  }
  return;
}



// Force engine shutdown (P2105): set state >= 5, clear PTD3, set flag bit 5

void force_engine_shutdown(void)

{
  byte bVar1;
  
  if (state < 5) {
    state = 5;
  }
  bVar1 = REG_PTD;
  REG_PTD = bVar1 & 0xf7;
  flags_to_mpc = flags_to_mpc | 0x20;
  return;
}



// Initialize state machine: compute CRC, load PPS-to-TPS lookup table, reset timers and state

void init_state(void)

{
  crc16_compute();
  flags_from_mpc = 0;
  flags_to_mpc = 0;
  CAL_tps_target_X_pps[0] = 0;
  CAL_tps_target[0] = 26;
  CAL_tps_target_X_pps[1] = 5;
  CAL_tps_target[1] = 26;
  CAL_tps_target_X_pps[2] = 10;
  CAL_tps_target[2] = 28;
  CAL_tps_target_X_pps[3] = 15;
  CAL_tps_target[3] = 30;
  CAL_tps_target_X_pps[4] = 20;
  CAL_tps_target[4] = 32;
  CAL_tps_target_X_pps[5] = 26;
  CAL_tps_target[5] = 35;
  CAL_tps_target_X_pps[6] = 31;
  CAL_tps_target[6] = 38;
  CAL_tps_target_X_pps[7] = 41;
  CAL_tps_target[7] = 44;
  CAL_tps_target_X_pps[8] = 51;
  CAL_tps_target[8] = 51;
  CAL_tps_target_X_pps[9] = 77;
  CAL_tps_target[9] = 68;
  CAL_tps_target_X_pps[10] = 102;
  CAL_tps_target[10] = 89;
  CAL_tps_target_X_pps[0xb] = 128;
  CAL_tps_target[0xb] = 117;
  CAL_tps_target_X_pps[0xc] = 153;
  CAL_tps_target[0xc] = 148;
  CAL_tps_target_X_pps[0xd] = 178;
  CAL_tps_target[0xd] = 181;
  CAL_tps_target_X_pps[0xe] = 204;
  CAL_tps_target[0xe] = 220;
  CAL_tps_target_X_pps[0xf] = 246;
  CAL_tps_target[0xf] = 255;
  timer_1 = 0;
  timer_2 = 0;
  timer_3_high = 0;
  timer_3_low = 0;
  timer_3_alive = 1;
  state = 0;
  release_engine_shutdown();
  release_forced_idle();
  return;
}



// Compute PPS-to-TPS target using lookup table (returns 0x33 if state >= 3)

uint8_t pps_tps_target(byte param_1)

{
  uint8_t uVar1;
  
  if (state < 3) {
    uVar1 = lookup_2D_uint8_interpolated(0x10,(ushort)param_1,CAL_tps_target,CAL_tps_target_X_pps);
  }
  else {
    uVar1 = 51;
  }
  return uVar1;
}



// Scale ADC value from raw range to normalized [0..255] with clipping

byte range_scale(byte param_1,byte param_2,byte param_3,byte param_4,byte param_5)

{
  undefined1 uVar1;
  byte in_X;
  undefined1 local_2;
  
  if (in_X < param_4 || (byte)(in_X - param_4) < (param_1 < param_5)) {
    if (param_2 < in_X || (byte)(param_2 - in_X) < (param_3 < param_1)) {
      DAT_0064 = (in_X - param_2) - (param_1 < param_3);
      uVar1 = mul16(param_1 - param_3);
      local_2 = div16(uVar1);
      if (DAT_0064 != '\0') {
        local_2 = 0xff;
      }
    }
    else {
      local_2 = 0;
    }
  }
  else {
    local_2 = 0xff;
  }
  return local_2;
}



// Normalize PPS and TPS from raw ADC to 0-255 range, selecting primary/secondary sensor via MPC
// flags

void normalize_sensors(void)

{
  if ((flags_from_mpc & 1) == 0) {
    pps_min = range_scale(adc_PTB5_pps_2,0,0x18,0,0x60);
    flags_to_mpc = flags_to_mpc & 0xfe;
  }
  else {
    pps_min = range_scale(adc_PTB4_pps_1,0,0x30,0,0xc1);
    flags_to_mpc = flags_to_mpc | 1;
  }
  if ((flags_from_mpc & 2) == 0) {
    tps_max = range_scale(adc_PTB3_tps_2,0,0x74,1,0x3e);
    if (tps_max == 0xff) {
      tps_max = 0xfe;
    }
    flags_to_mpc = flags_to_mpc & 0xfd;
  }
  else {
    tps_max = range_scale(adc_PTB2_tps_1,0,0x24,0,0xc5);
    flags_to_mpc = flags_to_mpc | 2;
  }
  return;
}



// Compare PPS-derived TPS target vs actual TPS, assert forced idle (P2014) if mismatch persists
// 100ms

void check_pps_tps(void)

{
  byte bVar1;
  byte extraout_HI;
  
  normalize_sensors();
  bVar1 = pps_tps_target((ushort)extraout_HI << 8);
  if ((pps_min < 0xcc) || (2 < state)) {
    pps_to_mpc = pps_min;
    tps_to_mpc = tps_max;
    tps_target_to_mpc = bVar1;
    if (bVar1 < tps_max) {
      if (timer_1 < 100) {
        timer_1 = timer_1 + 1;
      }
      else {
        timer_1 = 100;
        force_idle();
      }
    }
    else if ((timer_1 == 0) || (99 < timer_1)) {
      if (timer_1 == 0) {
        release_forced_idle();
      }
    }
    else {
      timer_1 = timer_1 - 1;
    }
  }
  else if (timer_1 == 0) {
    release_forced_idle();
  }
  return;
}



// Monitor PTB1 analog input, escalate to engine shutdown (P2105) if threshold exceeded for 100ms

void monitor_ptb1(void)

{
  if (adc_PTB1 < 0x71) {
    if ((timer_2 == 0) || (99 < timer_2)) {
      if (timer_2 == 0) {
        release_engine_shutdown();
      }
    }
    else {
      timer_2 = timer_2 - 1;
    }
  }
  else if (timer_2 < 100) {
    timer_2 = timer_2 + 1;
  }
  else {
    timer_2 = 100;
    force_engine_shutdown();
  }
  return;
}



// 1ms state machine: sample ADC, handle states 0-5
// (init/MPC-alive/monitor/degraded/forced-idle/shutdown)

void state_machine_1ms(void)

{
  adc_sample();
  if (state == 0) {
    state = 2;
  }
  else if (state == 1) {
    timer_1 = 0;
    timer_2 = 0;
    timer_3_low = timer_3_low + 1;
    if (timer_3_low == 0) {
      timer_3_high = timer_3_high + 1;
    }
                    // Maximum 400ms (0x190)
    if (timer_3_high == 0 || (byte)(timer_3_high - 1U) < (timer_3_low < 0x90)) {
      if ((flags_from_mpc & 4) == 0) {
        state = 2;
      }
    }
    else {
      timer_3_alive = '\0';
      state = 2;
    }
  }
  else if (state == 2) {
    if (((flags_from_mpc & 4) == 0) || (timer_3_alive == '\0')) {
      check_pps_tps();
    }
    else {
      state = 1;
    }
  }
  else if (state == 3) {
    check_pps_tps();
  }
  else if (state == 4) {
    force_idle();
    monitor_ptb1();
    if ((flags_from_mpc & 0x20) != 0) {
      force_engine_shutdown();
    }
  }
  else if (state == 5) {
    force_idle();
    force_engine_shutdown();
  }
  if (state == 1) {
    flags_to_mpc = flags_to_mpc | 4;
  }
  else {
    flags_to_mpc = flags_to_mpc & 0xfb;
  }
  if (state < 5) {
    if (timer_1 == '\0') {
      flags_to_mpc = flags_to_mpc & 0xf7;
    }
    else {
      flags_to_mpc = flags_to_mpc | 8;
    }
  }
  else if (timer_2 == '\0') {
    flags_to_mpc = flags_to_mpc & 0xf7;
  }
  else {
    flags_to_mpc = flags_to_mpc | 8;
  }
  return;
}



// Main loop: process serial commands from MPC, run 1ms state machine, force idle on communication
// timeout

void main(void)

{
  char cVar1;
  char extraout_X;
  
  do {
    cVar1 = process_serial();
    if (cVar1 != '\0' || extraout_X != '\0') {
      timer_countdown_1 = 'd';
      if ((flags_from_mpc & 4) == 0) {
        timer_3_high = 0;
        timer_3_low = 0;
        timer_3_alive = 1;
      }
      if ((state < 3) && ((flags_from_mpc & 8) != 0)) {
        state = 3;
      }
      if ((state < 4) && ((flags_from_mpc & 0x10) != 0)) {
        force_idle();
      }
    }
    if (timer_countdown_1 == '\0') {
      force_idle();
    }
    if (timer_countdown_2 == '\0') {
      timer_countdown_2 = '\x01';
      state_machine_1ms();
    }
  } while( true );
}



// Initialize SCI serial: baud rate divisor 2, enable TX/RX, enable receiver interrupt

void init_sci(void)

{
  byte bVar1;
  
  REG_SCBR = 2;
  REG_SCC1 = 0x40;
  REG_SCC2 = 0xc;
  bVar1 = REG_SCC2;
  REG_SCC2 = bVar1 & 0x7f;
  bVar1 = REG_SCC2;
  REG_SCC2 = bVar1 | 0x20;
  DAT_00b8 = 0;
  DAT_00b7 = 0;
  DAT_00b6 = 0;
  parse_len = 0;
  DAT_00b3 = 0;
  return;
}



// Check if serial receive ring buffer has data available

undefined1 serial_hasmore(void)

{
  if (DAT_00b6 != '\0') {
    return 1;
  }
  return 0;
}



// Read one byte from serial receive ring buffer (blocking)

char serial_getchar(void)

{
  ushort uVar1;
  
  do {
  } while (DAT_00b6 == '\0');
  uVar1 = (ushort)DAT_00b7;
  DAT_00b6 = DAT_00b6 + -1;
  if (DAT_00b7 < 0x1f) {
    DAT_00b7 = DAT_00b7 + 1;
  }
  else {
    DAT_00b7 = '\0';
  }
  return *(char *)(uVar1 + 0xd9);
}



// Start serial transmission: load byte count and enable TX interrupt

byte serial_send(undefined1 param_1)

{
  byte bVar1;
  
  bVar1 = REG_SCC2;
  REG_SCC2 = bVar1 & 0x7f;
  DAT_00b4 = param_1;
  DAT_00b5 = 0;
  bVar1 = REG_SCC2;
  REG_SCC2 = bVar1 | 0x80;
  return bVar1 | 0x80;
}



// SCI receive ISR: read SCDR into 32-byte ring buffer at 0xD9

undefined1 isr_sci_rx(undefined1 param_1)

{
  byte bVar1;
  
  bVar1 = REG_SCS1;
  if ((bVar1 & 0x20) != 0) {
    bVar1 = REG_SCDR;
    if (DAT_00b6 < 0x20) {
      *(byte *)(DAT_00b8 + 0xd9) = bVar1;
      if (DAT_00b8 < 0x1f) {
        DAT_00b8 = DAT_00b8 + 1;
      }
      else {
        DAT_00b8 = 0;
      }
      DAT_00b6 = DAT_00b6 + 1;
    }
  }
  return param_1;
}



// SCI transmit ISR: send next byte from TX buffer at 0xB9, disable TX when done

undefined1 isr_sci_tx(undefined1 param_1)

{
  byte bVar1;
  
  bVar1 = REG_SCC2;
  if (((bVar1 & 0x80) != 0) && (bVar1 = REG_SCS1, (bVar1 & 0x80) != 0)) {
    bVar1 = DAT_00b5 + 1;
    REG_SCDR = *(byte *)(DAT_00b5 + 0xb9);
    DAT_00b5 = bVar1;
    if (bVar1 == DAT_00b4) {
      bVar1 = REG_SCC2;
      REG_SCC2 = bVar1 & 0x7f;
    }
  }
  return param_1;
}



// WARNING: Unknown calling convention: __fastcall -- yet parameter storage is locked
// Parse incoming serial frame: length byte + payload + checksum, store in parse_buffer

undefined2 __fastcall parse_frame(char c)

{
  ushort uVar1;
  
  if (0x13 < parse_len) {
    parse_len = 0;
  }
  if (timer_countdown3 == '\0') {
    parse_len = 0;
  }
  timer_countdown3 = 6;
  if (parse_len == 0) {
    parse_len = '\x01';
    parse_sum = c;
    parse_buffer[0] = c;
  }
  else if (parse_len == 1) {
    parse_len = '\x02';
    parse_sum = c + parse_sum;
    parse_buffer[1] = c;
  }
  else if ((parse_len < 2) ||
          (DAT_0064 = parse_buffer[0] == -1,
          (byte)DAT_0064 < ((byte)(parse_buffer[0] + 1U) < parse_len))) {
    DAT_0064 = 0xfd < (byte)parse_buffer[0];
    if (parse_len != (byte)(parse_buffer[0] + 2U) || (bool)DAT_0064) {
      parse_len = '\0';
    }
    else {
      DAT_00b3 = *(undefined1 *)(parse_len + 0x9d);
      *(char *)(parse_len + 0x9e) = c;
      parse_len = '\0';
    }
  }
  else {
    uVar1 = (ushort)parse_len;
    parse_len = parse_len + 1;
    *(char *)(uVar1 + 0x9e) = c;
    parse_sum = c + parse_sum;
  }
  return 0;
}



// Build and send serial frame to MPC: length + command + payload + checksum

void send_frame(byte param_1,byte param_2)

{
  bool bVar1;
  char cVar2;
  char cVar3;
  char cVar4;
  char in_X;
  char *pcVar5;
  char local_7;
  byte local_6;
  char local_3;
  byte local_2;
  
  *(byte *)CONCAT11(in_X,param_1) = param_2;
  *(undefined1 *)(CONCAT11(in_X + CARRY1(param_2,param_1),param_2 + param_1) + 1) = DAT_00b3;
  cVar4 = in_X + CARRY1(param_2,param_1);
  cVar3 = param_2 + param_1 + 2;
  if (0xfd < (byte)(param_2 + param_1)) {
    cVar4 = cVar4 + '\x01';
  }
  *(undefined1 *)CONCAT11(cVar4,cVar3) = 0;
  local_7 = '\0';
  local_6 = 0;
  local_3 = in_X;
  local_2 = param_1;
  while (bVar1 = (byte)(param_2 + 1) < local_6, cVar2 = (param_2 == 0xff) - local_7,
        (char)(cVar2 - bVar1) < '\0' != (SBORROW1(param_2 == 0xff,local_7) != SBORROW1(cVar2,bVar1))
        ) {
    pcVar5 = (char *)CONCAT11(local_3,local_2);
    local_2 = local_2 + 1;
    if (local_2 == 0) {
      local_3 = local_3 + '\x01';
    }
    *(char *)CONCAT11(cVar4,cVar3) = *pcVar5 + *(char *)CONCAT11(cVar4,cVar3);
    local_6 = local_6 + 1;
    if (local_6 == 0) {
      local_7 = local_7 + '\x01';
    }
  }
  *(byte *)CONCAT11(cVar4,cVar3) = ~*(byte *)CONCAT11(cVar4,cVar3);
  serial_send(param_2 + 3,CONCAT11(cVar4,0xfc < param_2));
  return;
}



// Send heartbeat response (cmd 0x80) with CRC-16 to MPC

void send_heartbeat(void)

{
  uRAM00ba = 0x80;
  uRAM00bb = crc16_high;
  uRAM00bc = crc16_low;
  send_frame(0xb9,0,0,3);
  return;
}



// Send status response (cmd 0x81) with flags, PPS/TPS values, all ADC readings, and CRC-16 to MPC

void send_status(void)

{
  uRAM00ba = 0x81;
  uRAM00bb = flags_to_mpc;
  uRAM00bc = pps_to_mpc;
  uRAM00bd = tps_to_mpc;
  uRAM00be = tps_target_to_mpc;
  uRAM00bf = adc_PTB1;
  uRAM00c0 = adc_PTB2_tps_1;
  uRAM00c1 = adc_PTB3_tps_2;
  uRAM00c2 = adc_PTB4_pps_1;
  uRAM00c3 = adc_PTB5_pps_2;
  uRAM00c4 = adc_PTB6;
  uRAM00c5 = adc_PTB7;
  uRAM00c6 = crc16_high;
  uRAM00c7 = crc16_low;
  send_frame(0xb9,0,0,0xe);
  return;
}



// Process serial commands from MPC: dispatch heartbeat (0x80) and status request (0x81) commands

undefined1 process_serial(void)

{
  char cVar1;
  char extraout_X;
  char extraout_X_00;
  
  while( true ) {
    do {
      cVar1 = serial_hasmore();
      if (cVar1 == '\0' && extraout_X == '\0') {
        return 0;
      }
      cVar1 = serial_getchar();
      cVar1 = parse_frame(cVar1);
    } while (cVar1 == '\0' && extraout_X_00 == '\0');
    if (parse_buffer[1] == -0x80) break;
    if (parse_buffer[1] == -0x7f) {
      flags_from_mpc = parse_buffer[2];
      send_status();
      return 1;
    }
  }
  send_heartbeat();
  return 1;
}



// Initialize Timer1: prescaler /8, modulo 0x0C26 (1ms overflow), enable overflow interrupt

void init_timer1(void)

{
  byte bVar1;
  
  REG_T1SC = 0x33;
  REG_T1MODH = 0xc;
  REG_T1MODL = 0x26;
  bVar1 = REG_T1SC;
  REG_T1SC = bVar1 | 0x10;
  bVar1 = REG_T1SC;
  REG_T1SC = bVar1 | 0x40;
  bVar1 = REG_T1SC;
  REG_T1SC = bVar1 & 0xdf;
  timer_countdown_1 = 100;
  timer_countdown_2 = 0;
  timer_countdown3 = 0;
  return;
}



// Timer1 overflow ISR (1ms): decrement countdown timers for communication timeout, state machine
// tick, and parse timeout

undefined1 isr_timer1_1ms(undefined1 param_1)

{
  byte bVar1;
  
  bVar1 = REG_T1SC;
  REG_T1SC = bVar1 & 0x7f;
  if (timer_countdown_1 != '\0') {
    timer_countdown_1 = timer_countdown_1 + -1;
  }
  if (timer_countdown_2 != '\0') {
    timer_countdown_2 = timer_countdown_2 + -1;
  }
  if (timer_countdown3 != '\0') {
    timer_countdown3 = timer_countdown3 + -1;
  }
  return param_1;
}



// 16x16 multiply: (DAT_0064:A) * (H:X) -> (DAT_0064:A)

undefined1 mul16(byte param_1)

{
  char in_HI;
  byte in_X;
  
  DAT_0064 = (char)((ushort)param_1 * (ushort)in_X >> 8) + param_1 * in_HI + DAT_0064 * in_X;
  return (char)((ushort)param_1 * (ushort)in_X);
}



// 32-bit add: accumulator (DAT_0060:0063) += memory[param]

undefined1 acc32_add(undefined1 param_1,char *param_2)

{
  byte bVar1;
  bool bVar2;
  bool bVar3;
  
  bVar1 = param_2[3];
  bVar2 = CARRY1(DAT_0063,bVar1);
  DAT_0063 = DAT_0063 + bVar1;
  bVar1 = DAT_0062 + param_2[2];
  bVar3 = CARRY1(DAT_0062,param_2[2]) || CARRY1(bVar1,bVar2);
  DAT_0062 = bVar1 + bVar2;
  bVar2 = CARRY1(DAT_0061,param_2[1]);
  bVar1 = DAT_0061 + param_2[1];
  DAT_0061 = bVar1 + bVar3;
  DAT_0060 = DAT_0060 + *param_2 + (bVar2 || CARRY1(bVar1,bVar3));
  return param_1;
}



// 32-bit compare: set CCR flags for accumulator (DAT_0060:0063) vs memory[param], fixup N/V for
// signed branches

undefined1 acc32_cmp(undefined1 param_1)

{
  return param_1;
}



// Signed 32-bit division: accumulator /= memory[param], handles sign via negate

undefined1 acc32_div_signed(undefined1 param_1)

{
  undefined1 uStack_1;
  
  acc32_div_unsigned();
  if ((uStack_1 != '\0') && (uStack_1 != '\x03')) {
    acc32_negate();
  }
  return param_1;
}



// Unsigned 32-bit division: shift-subtract algorithm, 32 iterations

undefined1 acc32_div_unsigned(char *param_1)

{
  byte bVar1;
  byte bVar2;
  bool bVar3;
  bool bVar4;
  byte bVar5;
  byte bVar6;
  short sVar7;
  undefined1 *puVar8;
  char cVar9;
  byte bStack0003;
  byte bStack0004;
  byte bStack0005;
  byte bStack0006;
  char cStack0007;
  char cStack0008;
  char cStack0009;
  char cStack000a;
  undefined1 uStack000b;
  
  cStack000a = param_1[3];
  cStack0009 = param_1[2];
  cStack0008 = param_1[1];
  puVar8 = &stack0x0001;
  uStack000b = 0;
  cStack0007 = *param_1;
  if (*param_1 < '\0') {
    sVar7 = mem32_negate(&stack0x0007);
    puVar8 = (undefined1 *)(sVar7 + -6);
    *(char *)(sVar7 + 4) = *(char *)(sVar7 + 4) + '\x01';
  }
  if ((char)DAT_0060 < '\0') {
    puVar8 = (undefined1 *)acc32_negate();
    puVar8[10] = puVar8[10] + '\x01';
    puVar8[10] = puVar8[10] + '\x01';
  }
  bStack0003 = 0;
  bStack0004 = 0;
  bStack0005 = 0;
  bStack0006 = 0;
  cVar9 = ' ';
  do {
    bVar5 = DAT_0063 >> 7;
    DAT_0063 = DAT_0063 * '\x02';
    bVar6 = DAT_0062 >> 7;
    DAT_0062 = DAT_0062 << 1 | bVar5;
    bVar5 = DAT_0061 >> 7;
    DAT_0061 = DAT_0061 << 1 | bVar6;
    bVar6 = DAT_0060 >> 7;
    DAT_0060 = DAT_0060 << 1 | bVar5;
    bVar5 = bStack0006 >> 7;
    bStack0006 = bStack0006 << 1 | bVar6;
    bVar6 = bStack0005 >> 7;
    bStack0005 = bStack0005 << 1 | bVar5;
    bVar5 = bStack0004 >> 7;
    bStack0004 = bStack0004 << 1 | bVar6;
    bStack0003 = bStack0003 << 1 | bVar5;
    bVar5 = puVar8[9];
    bVar6 = bStack0005 - puVar8[8];
    bVar3 = bStack0005 < (byte)puVar8[8] || bVar6 < (bStack0006 < bVar5);
    bVar1 = bStack0004 - puVar8[7];
    bVar4 = bStack0004 < (byte)puVar8[7] || bVar1 < bVar3;
    bVar2 = bStack0003 - puVar8[6];
    if ((byte)puVar8[6] <= bStack0003 && bVar4 <= bVar2) {
      DAT_0063 = DAT_0063 + 1;
      bStack0003 = bVar2 - bVar4;
      bStack0004 = bVar1 - bVar3;
      bStack0005 = bVar6 - (bStack0006 < bVar5);
      bStack0006 = bStack0006 - bVar5;
    }
    cVar9 = cVar9 + -1;
  } while (cVar9 != '\0');
  return 0;
}



// 32-bit add: memory[param] += accumulator (DAT_0060:0063)

undefined1 mem32_add(undefined1 param_1,char *param_2)

{
  byte bVar1;
  bool bVar2;
  bool bVar3;
  
  bVar1 = param_2[3];
  bVar2 = CARRY1(bVar1,DAT_0063);
  param_2[3] = bVar1 + DAT_0063;
  bVar1 = param_2[2] + DAT_0062;
  bVar3 = CARRY1(param_2[2],DAT_0062) || CARRY1(bVar1,bVar2);
  param_2[2] = bVar1 + bVar2;
  bVar2 = CARRY1(param_2[1],DAT_0061);
  bVar1 = param_2[1] + DAT_0061;
  param_2[1] = bVar1 + bVar3;
  *param_2 = *param_2 + DAT_0060 + (bVar2 || CARRY1(bVar1,bVar3));
  return param_1;
}



// Negate 32-bit value in memory (two's complement)

void mem32_negate(byte *param_1)

{
  byte bVar1;
  
  *param_1 = ~*param_1;
  param_1[1] = ~param_1[1];
  param_1[2] = ~param_1[2];
  bVar1 = -param_1[3];
  param_1[3] = bVar1;
  if (((bVar1 == 0) && (bVar1 = param_1[2] + 1, param_1[2] = bVar1, bVar1 == 0)) &&
     (bVar1 = param_1[1] + 1, param_1[1] = bVar1, bVar1 == 0)) {
    *param_1 = *param_1 + 1;
  }
  return;
}



// 32-bit multiply: accumulator *= memory[param], partial products

undefined1 acc32_mul(undefined1 param_1,char *param_2)

{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  byte bVar4;
  short sVar5;
  byte bVar6;
  byte bVar7;
  byte bVar8;
  
  bVar1 = param_2[3];
  bVar2 = param_2[2];
  bVar6 = (byte)((ushort)DAT_0061 * (ushort)bVar1);
  bVar7 = (byte)((ushort)DAT_0062 * (ushort)bVar2);
  bVar3 = bVar7 + bVar6;
  sVar5 = (ushort)DAT_0063 * (ushort)(byte)param_2[1];
  bVar8 = (byte)sVar5;
  bVar4 = bVar8 + bVar3;
  DAT_0060 = (char)((ushort)sVar5 >> 8) +
             (char)((ushort)DAT_0062 * (ushort)bVar2 >> 8) +
             (char)((ushort)DAT_0061 * (ushort)bVar1 >> 8) +
             DAT_0063 * *param_2 + DAT_0062 * param_2[1] + DAT_0061 * bVar2 + DAT_0060 * bVar1 +
             CARRY1(bVar7,bVar6) + CARRY1(bVar8,bVar3);
  bVar7 = (byte)((ushort)DAT_0062 * (ushort)bVar1);
  bVar6 = (byte)((ushort)DAT_0062 * (ushort)bVar1 >> 8);
  bVar3 = bVar6 + bVar4;
  if (CARRY1(bVar6,bVar4)) {
    DAT_0060 = DAT_0060 + '\x01';
  }
  bVar6 = (byte)((ushort)DAT_0063 * (ushort)bVar2);
  bVar4 = (byte)((ushort)DAT_0063 * (ushort)bVar2 >> 8);
  bVar2 = bVar4 + bVar3;
  DAT_0061 = bVar2 + CARRY1(bVar6,bVar7);
  if (CARRY1(bVar4,bVar3) || CARRY1(bVar2,CARRY1(bVar6,bVar7))) {
    DAT_0060 = DAT_0060 + '\x01';
  }
  bVar2 = (byte)((ushort)DAT_0063 * (ushort)bVar1 >> 8);
  DAT_0063 = (char)((ushort)DAT_0063 * (ushort)bVar1);
  DAT_0062 = bVar2 + bVar6 + bVar7;
  if ((CARRY1(bVar2,bVar6 + bVar7)) && (DAT_0061 = DAT_0061 + '\x01', DAT_0061 == '\0')) {
    DAT_0060 = DAT_0060 + '\x01';
  }
  return param_1;
}



// Negate 32-bit accumulator (DAT_0060:0063) in place (two's complement)

void acc32_negate(void)

{
  DAT_0060 = ~DAT_0060;
  DAT_0061 = ~DAT_0061;
  DAT_0062 = ~DAT_0062;
  DAT_0063 = -DAT_0063;
  if (((DAT_0063 == '\0') && (DAT_0062 = DAT_0062 + 1, DAT_0062 == 0)) &&
     (DAT_0061 = DAT_0061 + 1, DAT_0061 == 0)) {
    DAT_0060 = DAT_0060 + 1;
  }
  return;
}



// 32-bit subtract: accumulator -= memory[param]

undefined1 acc32_sub(undefined1 param_1,char *param_2)

{
  byte bVar1;
  bool bVar2;
  bool bVar3;
  
  bVar1 = param_2[3];
  bVar2 = DAT_0063 < bVar1;
  DAT_0063 = DAT_0063 - bVar1;
  bVar1 = DAT_0062 - param_2[2];
  bVar3 = DAT_0062 < (byte)param_2[2] || bVar1 < bVar2;
  DAT_0062 = bVar1 - bVar2;
  bVar2 = DAT_0061 < (byte)param_2[1];
  bVar1 = DAT_0061 - param_2[1];
  DAT_0061 = bVar1 - bVar3;
  DAT_0060 = (DAT_0060 - *param_2) - (bVar2 || bVar1 < bVar3);
  return param_1;
}



// Load 32-bit accumulator (DAT_0060:0063) from memory

undefined1 * acc32_load(undefined1 *param_1)

{
  DAT_0060 = *param_1;
  DAT_0061 = param_1[1];
  DAT_0062 = param_1[2];
  DAT_0063 = param_1[3];
  return param_1;
}



// Store 32-bit accumulator (DAT_0060:0063) to memory

undefined1 * acc32_store(undefined1 *param_1)

{
  *param_1 = DAT_0060;
  param_1[1] = DAT_0061;
  param_1[2] = DAT_0062;
  param_1[3] = DAT_0063;
  return param_1;
}



// 16-bit unsigned division: (DAT_0064:A) / (H:X)

ushort div16(byte param_1,ushort param_2)

{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  byte bVar4;
  byte bVar6;
  ushort uVar5;
  bool bVar7;
  undefined1 in_stack_00000000;
  char cStack_3;
  byte local_1;
  
  bVar4 = (byte)(param_2 >> 8);
  bVar6 = (byte)param_2;
  if (bVar4 != 0) {
    bVar3 = 0;
    cStack_3 = '\b';
    do {
      bVar1 = param_1 >> 7;
      param_1 = param_1 * '\x02';
      bVar2 = DAT_0064 >> 7;
      DAT_0064 = DAT_0064 << 1 | bVar1;
      bVar3 = bVar3 << 1 | bVar2;
      if ((bVar4 <= bVar3) && ((bVar3 != bVar4 || (bVar6 <= DAT_0064)))) {
        bVar7 = DAT_0064 < bVar6;
        DAT_0064 = DAT_0064 - bVar6;
        bVar3 = (bVar3 - bVar4) - bVar7;
        param_1 = param_1 + 1;
      }
      cStack_3 = cStack_3 + -1;
    } while (cStack_3 != '\0');
    uVar5 = CONCAT11(bVar3,DAT_0064);
    DAT_0064 = 0;
    return uVar5;
  }
  if (DAT_0064 < bVar6) {
    uVar5 = CONCAT11(DAT_0064,in_stack_00000000);
    bVar4 = (byte)(uVar5 % (param_2 & 0xff));
    DAT_0064 = 0;
  }
  else {
    uVar5 = (ushort)DAT_0064;
    DAT_0064 = DAT_0064 / bVar6;
    bVar4 = (byte)((uVar5 % (param_2 & 0xff) << 8 | (ushort)param_1) % (param_2 & 0xff));
  }
  return (ushort)bVar4;
}



// Sign-extend 16-bit value (X:A) to 32-bit accumulator (DAT_0060:0063)

void acc32_extend16(undefined1 param_1)

{
  char in_X;
  
  DAT_0063 = param_1;
  DAT_0061 = 0;
  DAT_0062 = in_X;
  if (in_X < '\0') {
    DAT_0061 = 0xff;
  }
  DAT_0060 = DAT_0061;
  return;
}


