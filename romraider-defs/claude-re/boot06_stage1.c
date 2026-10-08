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

typedef ushort uint16_t;

typedef uint uint32_t;



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
short DAT_003ff000;
undefined DAT_0000fffe;
undefined DAT_0000bffe;
undefined UNK_0001869f;
ushort REG_SWSR;
undefined DAT_0007a120;
ushort DAT_003ff000;
ushort REG_MPWMSM3_SCR;
uint REG_UC3FMCR;
uint REG_UC3FMCRE;
uint REG_UC3FCTL;
undefined4 UNK_00000000;
undefined1 DAT_003f8000;
undefined init_system_registers;
ushort REG_TBSCR;
undefined DAT_003ff008;
ushort REG_SCC1R0;
ushort REG_SCC1R1;
ushort REG_SC1SR;
ushort REG_SC1DR;
uint16_t[256] crc_table;

// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Initializes MPC563 system registers: SIUMCR chip selects BR0-3/OR0-3 clock (SCCR/PLPRCR) and port
// presets

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



// Single blr instruction - unused return stub

void stub_return(void)

{
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Checks the stage 2 CRC16 over flash 0x4000-0xFFFD (seed 0x123, update
// (byte+0xAA)^crc<<8^table[crc>>8]) against the u16 at 0xFFFE; match -> jump to stage 2. Mismatch
// -> recovery: wait 100 ms for 'S', ack 0xA6, wait 'N', ack ~'N', erase the stage 2 sector (block
// 0x80); timeout -> jump to stage 2 anyway

void stage2_crc_gate(void)

{
  int iVar1;
  char cVar3;
  undefined *puVar2;
  
  DAT_003ff000 = crc16_range(0x4000,&DAT_0000bffe);
  if (_DAT_0000fffe == DAT_003ff000) {
    func_0x00004000();
    return;
  }
  timer_save(0);
  while ((iVar1 = kline_rx_ready(), iVar1 == 0 || (cVar3 = kline_recv_byte(), cVar3 != 'S'))) {
    puVar2 = (undefined *)timer_elapsed(0);
    if (&UNK_0001869f < puVar2) {
      REG_SWSR = 0x556c;
      REG_SWSR = 0xaa39;
      func_0x00004000();
      return;
    }
  }
  kline_rx_drain();
  kline_send_byte(0xffffffac);
  timer_save(0);
  while ((iVar1 = kline_rx_ready(), iVar1 == 0 || (cVar3 = kline_recv_byte(), cVar3 != 'Y'))) {
    puVar2 = (undefined *)timer_elapsed(0);
    if (&UNK_0001869f < puVar2) {
      REG_SWSR = 0x556c;
      REG_SWSR = 0xaa39;
      func_0x00004000();
      return;
    }
  }
  kline_rx_drain();
  kline_send_byte(0xffffffa6);
  timer_save(0);
  while ((iVar1 = kline_rx_ready(), iVar1 == 0 || (cVar3 = kline_recv_byte(), cVar3 != 'N'))) {
    puVar2 = (undefined *)timer_elapsed(0);
    if (&UNK_0001869f < puVar2) {
      REG_SWSR = 0x556c;
      REG_SWSR = 0xaa39;
      func_0x00004000();
      return;
    }
  }
  flash_erase(0x80,0);
  kline_rx_drain();
  kline_send_byte(0xffffffb1);
  return;
}



// Receives one big-endian 16-bit word from the K-Line for the stage 2 recovery upload

undefined4 kline_recv_word(undefined2 *param_1)

{
  int iVar1;
  undefined1 uVar3;
  undefined1 uVar4;
  undefined *puVar2;
  
  timer_save(0);
  do {
    iVar1 = kline_rx_ready();
    if (iVar1 != 0) {
      uVar3 = kline_recv_byte();
      timer_save(0);
      do {
        iVar1 = kline_rx_ready();
        if (iVar1 != 0) {
          uVar4 = kline_recv_byte();
          *param_1 = CONCAT11(uVar3,uVar4);
          return 1;
        }
        puVar2 = (undefined *)timer_elapsed(0);
      } while (puVar2 < &DAT_0007a120);
      return 0;
    }
    puVar2 = (undefined *)timer_elapsed(0);
  } while (puVar2 < &DAT_0007a120);
  return 0;
}



// Stage 2 recovery uploader (run from RAM after stage1_to_ram): stage2_crc_gate, then receives
// 0x5FFF data halfwords covering 0x4000-0xFFFD (each programmed via UC3F and acked with its
// inverted word, running CRC16 seed 0x123), the 0x6000th word is the CRC (verified and programmed
// at 0xFFFE); then jumps to stage 2

void stage2_recovery_upload(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  ushort local_18 [8];
  
  crc16_table_init();
  init_sci1();
  timer_enable_timebase();
  stage2_crc_gate();
  DAT_003ff000 = 0x123;
  iVar4 = 0;
  iVar3 = 0x4000;
  while( true ) {
    if (0x5fff < iVar4) {
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    iVar1 = kline_recv_word(local_18);
    if (iVar1 == 0) break;
    if (iVar4 == 0x5fff) {
      iVar1 = iVar3;
      if (DAT_003ff000 == local_18[0]) {
        iVar1 = iVar3 + 2;
        iVar3 = flash_program_halfwords(iVar3,local_18,1);
        if (iVar3 != 0) {
          local_18[0] = ~local_18[0];
          kline_send_bytes(local_18,2);
        }
      }
    }
    else {
      DAT_003ff000 = crc16_update_byte((int)(uint)local_18[0] >> 8,DAT_003ff000);
      DAT_003ff000 = crc16_update_byte(local_18[0] & 0xff,DAT_003ff000);
      iVar2 = flash_program_halfwords(iVar3,local_18,1);
      iVar1 = iVar3 + 2;
      if (iVar2 != 0) {
        local_18[0] = ~local_18[0];
        kline_send_bytes(local_18,2);
      }
    }
    iVar4 = iVar4 + 1;
    iVar3 = iVar1;
  }
  func_0x00004000();
  return;
}



// Stage 1 boot: L-Line low (MPWMSM3 SCR bit 15) -> stage1_to_ram + run stage2_recovery_upload from
// RAM; then watchdog and jump to stage 2 at 0x4000

void main(void)

{
  ushort uVar1;
  
  uVar1 = REG_MPWMSM3_SCR;
  if (-1 < (short)uVar1) {
    stage1_to_ram();
    stage2_recovery_upload_ram();
  }
  REG_SWSR = 0x556c;
  REG_SWSR = 0xaa39;
  func_0x00004000();
  return;
}



// Programs N halfwords (16-bit) to flash via UC3F controller

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



// Copies flash 0x2000-0x8FFF (0x7000 bytes: stage 1 code + stage 2 code) to RAM 0x3F8000 so the
// recovery uploader runs from RAM while reprogramming flash

void stage1_to_ram(void)

{
  bool bVar1;
  code cVar2;
  int iVar3;
  code *pcVar4;
  code *pcVar5;
  
  pcVar5 = (code *)&DAT_003f8000;
  pcVar4 = init_system_registers;
  iVar3 = 0x7000;
  while (bVar1 = iVar3 != 0, iVar3 = iVar3 + -1, bVar1) {
    REG_SWSR = 0x556c;
    REG_SWSR = 0xaa39;
    cVar2 = *pcVar4;
    pcVar4 = pcVar4 + 1;
    *pcVar5 = cVar2;
    pcVar5 = pcVar5 + 1;
  }
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
  *(undefined4 *)(&DAT_003ff008 + (uint)param_1 * 4) = uVar1;
  return;
}



// Returns elapsed ticks since timer_save for indexed timer slot

int timer_elapsed(ushort param_1)

{
  int iVar1;
  
  iVar1 = timer_read_tbl();
  return iVar1 - *(int *)(&DAT_003ff008 + (uint)param_1 * 4);
}



// Reads PowerPC Time Base Lower register (TBL)

undefined4 timer_read_tbl(void)

{
  undefined4 uVar1;
  
  uVar1 = TBLr;
  return uVar1;
}



// Initializes QSCI1 (K-Line UART): baud 0x2B (29069) 8N1 sends sync bytes and drains RX

void init_sci1(void)

{
  ushort uVar1;
  
  REG_SCC1R1 = 0;
  REG_SCC1R0 = 0x2b;
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



// Transmits a byte buffer over SCI1 (K-Line): waits TDRE per byte waits TC at the end

void kline_send_bytes(byte *param_1,int param_2)

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



// Returns true when SCI1 receive data register is full (SC1SR RDRF) with watchdog retrigger

bool kline_rx_ready(void)

{
  ushort uVar1;
  
  REG_SWSR = 0x556c;
  REG_SWSR = 0xaa39;
  uVar1 = REG_SC1SR;
  return (uVar1 >> 6 & 1) != 0;
}



// Blocking receive of one byte from SCI1 (K-Line)

ushort kline_recv_byte(void)

{
  ushort uVar1;
  int iVar2;
  
  do {
    iVar2 = kline_rx_ready();
  } while (iVar2 == 0);
  uVar1 = REG_SC1DR;
  return uVar1 & 0xff;
}



// Discards all pending bytes from SCI1 (K-Line)

void kline_rx_drain(void)

{
  int iVar1;
  
  while (iVar1 = kline_rx_ready(), iVar1 != 0) {
    kline_recv_byte();
  }
  return;
}



// Sends one byte over SCI1 (K-Line)

void kline_send_byte(undefined1 param_1)

{
  undefined1 local_8 [8];
  
  local_8[0] = param_1;
  kline_send_bytes(local_8,1);
  return;
}



// Computes the stage 2 CRC16 over a byte range (seed 0x123): crc = (byte+0xAA) ^ crc<<8 ^
// table[crc>>8]

uint crc16_range(byte *param_1,int param_2)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  
  uVar3 = 0x123;
  for (iVar2 = 0; iVar2 < param_2; iVar2 = iVar2 + 1) {
    bVar1 = *param_1;
    param_1 = param_1 + 1;
    uVar3 = (bVar1 + 0xaa ^ uVar3 << 8 ^ (uint)crc_table[uVar3 >> 8]) & 0xffff;
  }
  return uVar3;
}



// CRC16 single-byte update: (byte+0xAA) ^ crc<<8 ^ table[crc>>8]

uint crc16_update_byte(uint param_1,uint param_2)

{
  return ((param_1 & 0xff) + 0xaa ^
         (param_2 & 0xffff) << 8 ^ (uint)crc_table[(param_2 & 0xffff) >> 8]) & 0xffff;
}



// Builds the 256-entry CRC16 table in RAM 0x3FF018 (generator 0xC0C1 step (g<<1)^0x4003 - standard
// CRC-16/IBM table)

void crc16_table_init(void)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  
  for (iVar3 = 0; iVar3 < 0x100; iVar3 = iVar3 + 1) {
    crc_table[iVar3] = 0;
  }
  for (uVar4 = 0; (int)uVar4 < 0x100; uVar4 = uVar4 + 1) {
    uVar1 = 0xc0c1;
    for (uVar2 = 1; (int)uVar2 < 0x100; uVar2 = uVar2 << 1) {
      if ((uVar4 & uVar2) != 0) {
        crc_table[uVar4] = crc_table[uVar4] ^ (ushort)uVar1;
      }
      uVar1 = (uVar1 << 1 ^ 0x4003) & 0xffff;
    }
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void stage2_crc_gate_ram(void)

{
  DAT_003ff000 = crc16_range_ram(0x4000,&DAT_0000bffe);
  if (_DAT_0000fffe == DAT_003ff000) {
    func_0x00004000();
    return;
  }
  timer_save_ram(0);
                    // WARNING: Subroutine does not return
  kline_rx_ready_ram();
}



void kline_recv_word_ram(void)

{
  timer_save_ram(0);
                    // WARNING: Subroutine does not return
  kline_rx_ready_ram();
}



void stage2_recovery_upload_ram(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  ushort auStack_18 [8];
  
  crc16_table_init_ram();
  init_sci1_ram();
  timer_enable_timebase_ram();
  stage2_crc_gate_ram();
  DAT_003ff000 = 0x123;
  iVar4 = 0;
  iVar3 = 0x4000;
  while( true ) {
    if (0x5fff < iVar4) {
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
    iVar1 = kline_recv_word_ram(auStack_18);
    if (iVar1 == 0) break;
    if (iVar4 == 0x5fff) {
      iVar1 = iVar3;
      if (DAT_003ff000 == auStack_18[0]) {
        iVar1 = iVar3 + 2;
        iVar3 = flash_program_halfwords_ram(iVar3,auStack_18,1);
        if (iVar3 != 0) {
          auStack_18[0] = ~auStack_18[0];
          kline_send_bytes_ram(auStack_18,2);
        }
      }
    }
    else {
      DAT_003ff000 = crc16_update_byte_ram((int)(uint)auStack_18[0] >> 8,DAT_003ff000);
      DAT_003ff000 = crc16_update_byte_ram(auStack_18[0] & 0xff,DAT_003ff000);
      iVar2 = flash_program_halfwords_ram(iVar3,auStack_18,1);
      iVar1 = iVar3 + 2;
      if (iVar2 != 0) {
        auStack_18[0] = ~auStack_18[0];
        kline_send_bytes_ram(auStack_18,2);
      }
    }
    iVar4 = iVar4 + 1;
    iVar3 = iVar1;
  }
  func_0x00004000();
  return;
}



// Stage2 boot: L-Line low -> run the CRP01 flasher from RAM; H308CODE magic -> HC08 programming +
// update marker; then boot the application (prog_entry_point) (RAM copy)

void main_ram(void)

{
  ushort uVar1;
  
  uVar1 = REG_MPWMSM3_SCR;
  if (-1 < (short)uVar1) {
    stage1_to_ram_ram();
    func_0x007ee454();
  }
  REG_SWSR = 0x556c;
  REG_SWSR = 0xaa39;
  func_0x00004000();
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



// Copies flash 0x2000-0x8FFF (0x7000 bytes: stage 1 code + stage 2 code) to RAM 0x3F8000 so the
// recovery uploader runs from RAM while reprogramming flash (RAM copy)

void stage1_to_ram_ram(void)

{
  bool bVar1;
  code cVar2;
  int iVar3;
  code *pcVar4;
  code *pcVar5;
  
  pcVar5 = (code *)&DAT_003f8000;
  pcVar4 = init_system_registers;
  iVar3 = 0x7000;
  while (bVar1 = iVar3 != 0, iVar3 = iVar3 + -1, bVar1) {
    REG_SWSR = 0x556c;
    REG_SWSR = 0xaa39;
    cVar2 = *pcVar4;
    pcVar4 = pcVar4 + 1;
    *pcVar5 = cVar2;
    pcVar5 = pcVar5 + 1;
  }
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
  *(undefined4 *)(&DAT_003ff008 + (uint)param_1 * 4) = uVar1;
  return;
}



// Returns elapsed time since timer_save for indexed timer slot (RAM copy)

int timer_elapsed_ram(ushort param_1)

{
  int iVar1;
  
  iVar1 = timer_read_tbl_ram();
  return iVar1 - *(int *)(&DAT_003ff008 + (uint)param_1 * 4);
}



// Reads PowerPC Time Base Lower register (TBL) (RAM copy)

undefined4 timer_read_tbl_ram(void)

{
  undefined4 uVar1;
  
  uVar1 = TBLr;
  return uVar1;
}



// Initializes QSCI1 (K-Line UART): baud 0x2A, 8N1, sends three sync bytes and drains RX (RAM copy)

void init_sci1_ram(void)

{
  ushort uVar1;
  
  REG_SCC1R1 = 0;
  REG_SCC1R0 = 0x2b;
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



void kline_send_bytes_ram(byte *param_1,int param_2)

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



bool kline_rx_ready_ram(void)

{
  ushort uVar1;
  
  REG_SWSR = 0x556c;
  REG_SWSR = 0xaa39;
  uVar1 = REG_SC1SR;
  return (uVar1 >> 6 & 1) != 0;
}



void kline_recv_byte_ram(void)

{
                    // WARNING: Subroutine does not return
  kline_rx_ready_ram();
}



void kline_rx_drain_ram(void)

{
                    // WARNING: Subroutine does not return
  kline_rx_ready_ram();
}



void kline_send_byte_ram(undefined1 param_1)

{
  undefined1 local_8 [8];
  
  local_8[0] = param_1;
  kline_send_bytes_ram(local_8,1);
  return;
}



uint crc16_range_ram(byte *param_1,int param_2)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  
  uVar3 = 0x123;
  for (iVar2 = 0; iVar2 < param_2; iVar2 = iVar2 + 1) {
    bVar1 = *param_1;
    param_1 = param_1 + 1;
    uVar3 = (bVar1 + 0xaa ^ uVar3 << 8 ^ (uint)crc_table[uVar3 >> 8]) & 0xffff;
  }
  return uVar3;
}



uint crc16_update_byte_ram(uint param_1,uint param_2)

{
  return ((param_1 & 0xff) + 0xaa ^
         (param_2 & 0xffff) << 8 ^ (uint)crc_table[(param_2 & 0xffff) >> 8]) & 0xffff;
}



void crc16_table_init_ram(void)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  
  for (iVar3 = 0; iVar3 < 0x100; iVar3 = iVar3 + 1) {
    crc_table[iVar3] = 0;
  }
  for (uVar4 = 0; (int)uVar4 < 0x100; uVar4 = uVar4 + 1) {
    uVar1 = 0xc0c1;
    for (uVar2 = 1; (int)uVar2 < 0x100; uVar2 = uVar2 << 1) {
      if ((uVar4 & uVar2) != 0) {
        crc_table[uVar4] = crc_table[uVar4] ^ (ushort)uVar1;
      }
      uVar1 = (uVar1 << 1 ^ 0x4003) & 0xffff;
    }
  }
  return;
}


