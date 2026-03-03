#define 0x7A1 0x7a1

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

typedef struct struct_segment_bss struct_segment_bss, *Pstruct_segment_bss;

struct struct_segment_bss {
    pointer dest;
    uint size;
};

typedef struct struct_segment_data struct_segment_data, *Pstruct_segment_data;

struct struct_segment_data {
    pointer src;
    pointer dest;
    uint size;
};

typedef uchar uint8_t;

typedef ulonglong uint64_t;

typedef uint uint32_t;

typedef ushort uint16_t;



struct_segment_data[8] segment_data;
struct_segment_bss[3] segment_bss;
uint REG_SGPIODT1;
uint REG_SCCRK;
uint REG_SGPIODT2;
uint REG_SCCR;
uint REG_PLPRCRK;
uint REG_SGPIOCR;
uint REG_PLPRCR;
uint REG_UMCR;
uint REG_PDMCR;
uint REG_SIUMCR;
ushort REG_SWSR;
byte DAT_003f9113;
int DAT_00021fe0;
int DAT_00021fe4;
int DAT_00021fe8;
undefined4 crp_dest;
undefined1 DAT_003fa428;
undefined4 flash_dest;
uint32_t crp_size;
uint16_t flash_data_read_i;
uint16_t flash_data_write_i;
uint8_t[1024] flash_data;
undefined4 DAT_00021fe8;
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
ushort REG_CANA_MB14_ID_LO;
ushort REG_CANA_MB3_CS;
ushort REG_CANA_MB3_ID_HI;
ushort REG_CANA_MB3_ID_LO;
ushort REG_CANA_MB15_CS;
ushort REG_CANA_MB15_ID_HI;
ushort REG_CANA_MB15_ID_LO;
ushort REG_CANA_MB4_CS;
ushort REG_CANA_MB4_ID_HI;
byte REG_CANA_MB0_DATA0;
uint8_t[16] tx_buffer;
uint16_t tx_buffer_len;
undefined2 tx_buffer_i;
ushort REG_IFLAG_A;
uint16_t tx_can_id;
byte DAT_003f910a;
uint8_t[256] CRC8_lookup_ram;
undefined DAT_003f938f;
uint8_t efip_crc;
uint16_t rx_buffer_write_i;
uint8_t efip_state;
undefined1 DAT_003f911d;
undefined1 DAT_003f911c;
uint32_t crp_frame_i;
char DAT_003f911d;
undefined1 DAT_003f9108;
undefined1 DAT_003f9110;
uint8_t DAT_003f9111;
byte DAT_003f9114;
byte DAT_003f9110;
uint8_t[1024] rx_buffer;
uint16_t rx_efi_id;
undefined1 DAT_003f9796;
undefined2 rx_buffer_i;
undefined1 DAT_003fa022;
undefined2 DAT_00000a06;
undefined DAT_000249f0;
undefined DAT_00027100;
byte DAT_003f911c;
short DAT_003f9136;
short DAT_003f9134;
ushort DAT_003f9122;
byte DAT_003f9120;
int DAT_00000a08;
int DAT_00000a00;
ushort DAT_003fa82a;
uint8_t[1024] plain_buffer;
uint16_t flash_data_len;
uint32_t plain_buffer_len;
undefined can_a_mb15_recv_ram;
undefined can_a_mb15_recv;
ushort REG_TBSCR;
uint DAT_003f913c;
uint DAT_003f9138;
int DAT_003f9138;
ushort REG_MPWMSM16_SCR;
ushort REG_MDASM27_SCR;
ushort REG_MDASM28_SCR;
ushort REG_MPWMSM17_SCR;
ushort REG_MPWMSM18_PERR;
ushort REG_MPWMSM18_PULR;
ushort REG_MDASM29_SCR;
ushort REG_MPWMSM18_SCR;
ushort REG_MDASM30_SCR;
ushort REG_MPWMSM19_SCR;
ushort REG_MDASM31_SCR;
ushort REG_MPIOSMDR;
ushort REG_MPIOSMDDR;
ushort REG_MPWMSM0_SCR;
ushort REG_MIOS14TPCR;
ushort REG_MDASM11_SCR;
ushort REG_MPWMSM1_SCR;
ushort REG_MDASM12_SCR;
ushort REG_MCPSMSCR;
ushort REG_MDASM13_SCR;
ushort REG_MPWMSM2_SCR;
ushort REG_MDASM14_SCR;
ushort REG_MPWMSM3_SCR;
ushort REG_MDASM15_SCR;
uint32_t[4] XTEA_KEY;
uint DAT_003f9144;
undefined4 DAT_003f9154;
uint DAT_003f9140;
undefined4 DAT_003f9150;
uint DAT_003f914c;
uint DAT_003f9148;
undefined4 DAT_003f9148;
undefined4 DAT_003f914c;
undefined4 DAT_003f9140;
undefined4 DAT_003f9144;
ushort REG_SCC1R1;
ushort REG_PORTQS;
byte REG_PQSPAR;
byte REG_DDRQST;
ushort REG_SPCR0;
ushort REG_SPCR1;
ushort REG_SPCR2;
byte REG_SPCR3;
ushort REG_QSMCMMCR;
ushort REG_QDSCI_IL;
ushort REG_QSPI_IL;
ushort REG_SCC1R0;
ushort REG_RECRAM0;
ushort REG_TRANRAM0;
byte REG_COMDRAM0;
byte REG_SPSR;
ushort REG_TPUMCR3_B;
ushort REG_TICR_B;
ushort REG_CFSR0_B;
ushort REG_CFSR1_B;
ushort REG_CFSR2_B;
ushort REG_TPU3B_CH14_PARAM0;
ushort REG_CFSR3_B;
ushort REG_HSQR0_B;
ushort REG_TPU3B_CH14_PARAM2;
ushort REG_HSRR0_B;
ushort REG_CPR0_B;
ushort REG_CPR1_B;
ushort REG_CISR_B;
ushort REG_TPUMCR2_B;
undefined4 DAT_003f915c;
int DAT_003f915c;
ushort REG_MDASM28_AR;
ushort REG_MDASM28_BR;
undefined *PTR_DAT_00021fec;
undefined *DAT_003f9158;
byte REG_PORTQA_A;
byte REG_PORTQB_A;
byte REG_DDRQA_A;
byte DAT_000088a0;
byte DAT_000088a1;
byte DAT_000088a2;
byte DAT_000088a3;
byte DAT_000088a4;
byte DAT_000088a5;
byte DAT_000088a6;
byte DAT_000088a7;
undefined DAT_0000fff6;
undefined DAT_0000c350;
int DAT_003f9158;
undefined DAT_0000dc00;
undefined DAT_0000ffdc;
undefined DAT_003f9180;
int *DAT_003f9160;
int DAT_003f9168;
int DAT_003f9178;
undefined *DAT_003f916c;
pointer PTR_cleanup_callbacks_000088a8;
undefined DAT_003f9190;
int DAT_003f917c;
undefined *DAT_003f9170;
undefined DAT_003f9290;
ushort REG_TIMER_A;
byte REG_CANA_MB15_DATA0;
byte DAT_003f9108;
uint REG_UC3FMCR;
uint REG_UC3FMCRE;
uint REG_UC3FCTL;
undefined4 UNK_00000000;
int DAT_003f913c;

void entry_point(undefined4 param_1,undefined4 param_2,uint param_3)

{
  char *destination;
  undefined8 uVar1;
  
  init_stack();
  enable_external_interrupts();
  init_segment();
  nop_stub2();
  main();
  uVar1 = exit();
  destination = (char *)((ulonglong)uVar1 >> 0x20);
  if ((param_3 != 0) && (destination != (char *)uVar1)) {
    memcpy(destination,(char *)uVar1,param_3);
    nop_stub(destination,param_3);
  }
  return;
}



void memcpy_checked(char *destination,char *source,uint size)

{
  if ((size != 0) && (destination != source)) {
    memcpy(destination,source,size);
    nop_stub(destination,size);
  }
  return;
}



void memzero(char *destination,uint size)

{
  if (size != 0) {
    memset_thunk(destination,0,size);
  }
  return;
}



void init_stack(void)

{
  return;
}



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



void enable_external_interrupts(void)

{
  uint in_MSR;
  
  init_system_registers(in_MSR | 0x2000);
  return;
}



void nop_stub(void)

{
  return;
}



// Initializes MPC561 system registers (PLL SIUMCR SCCR PDMCR SGPIOCR UMCR)

void init_system_registers(void)

{
  REG_PLPRCRK = 0x55ccaa33;
  REG_PLPRCR = 0x900000;
  REG_SIUMCR = 0;
  REG_SCCRK = 0x55ccaa33;
  REG_SCCR = 0x4024100;
  REG_PDMCR = 0x42100000;
  REG_SGPIOCR = 0xfcff;
  REG_SGPIODT1 = 0;
  REG_SGPIODT2 = 0;
  REG_UMCR = 0;
  return;
}



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



void memset_thunk(char *destination,int value,uint size)

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



void memset_thunk(char *destination,int value,uint size)

{
  memset_thunk(destination,value,size);
  return;
}



void main(void)

{
  int iVar1;
  
  DAT_003f9113 = DAT_003f9113 | 0x10;
  init_tpu();
  init_qsm();
  iVar1 = efip_is_active();
  if (iVar1 == 1) {
    copy_to_ram();
    efip_main_loop();
  }
  if (((DAT_00021fe0 == 0x48433038) && (DAT_00021fe4 == 0x434f4445)) &&
     ((DAT_00021fe8 == -0x55555556 ||
      ((DAT_00021fe8 == -0x5555ddde || (DAT_00021fe8 == -0x44444445)))))) {
    REG_SWSR = 0x556c;
    REG_SWSR = 0xaa39;
    timer_enable_timebase_2();
    REG_SWSR = 0x556c;
    REG_SWSR = 0xaa39;
    hc08_program_sequence();
  }
  return;
}



// Empty stub function

void nop_stub3(void)

{
  return;
}



void nop_stub2(void)

{
  return;
}



// Erases flash block at destination address (0x20000=prog, 0x10000=calrom)

undefined1 flash_erase_block(void)

{
  undefined1 uVar1;
  uint uVar2;
  
  uVar1 = 1;
  if (crp_dest == 0x20000) {
    uVar1 = flash_erase_ram(0x3f,0);
    REG_SWSR = 0x556c;
    REG_SWSR = 0xaa39;
  }
  else if (crp_dest == 0x10000) {
    uVar1 = flash_erase_ram(0x40,0);
    REG_SWSR = 0x556c;
    REG_SWSR = 0xaa39;
  }
  for (uVar2 = 0; uVar2 < 10000; uVar2 = uVar2 + 1) {
  }
  return uVar1;
}



// Resets CRP rx/tx buffer pointers and destination address/size tracking

void efip_reset_buffers(void)

{
  flash_data_write_i = 0;
  flash_data_read_i = 0;
  DAT_003fa428 = 0;
  crp_dest = 0;
  crp_size = 0;
  flash_dest = 0;
  return;
}



// Writes buffered data to flash (word or dword) or SPI EEPROM, depending on destination address

uint efip_write_data(void)

{
  uint uVar1;
  uint uVar2;
  
  if ((((crp_dest == 0x20000) || (crp_dest == 0x10000)) || (crp_dest == 0xa00)) ||
     (((crp_dest == 0xa2c || (crp_dest == 0xa4c)) || (crp_dest == 0xa08)))) {
    uVar2 = (int)(short)flash_data_write_i - (int)(short)flash_data_read_i;
    if ((int)uVar2 < 9) {
      if ((int)uVar2 < 1) {
        return 0;
      }
    }
    else {
      uVar2 = 8;
    }
    uVar1 = (int)uVar2 >> 0x1f;
    if (((uVar1 * 4 | uVar2 * 0x40000000 + uVar1 >> 0x1e) == uVar1) && ((flash_dest & 3) == 0)) {
      uVar1 = flash_program_words_ram
                        (flash_dest,flash_data + (short)flash_data_read_i,(int)uVar2 >> 2);
      uVar1 = uVar1 & 0xff;
      flash_dest = flash_dest + uVar2;
      crp_size = crp_size - uVar2;
      flash_data_read_i = flash_data_read_i + (short)uVar2;
    }
    else if ((uVar2 & 1 ^ uVar2 >> 0x1f) == uVar2 >> 0x1f) {
      uVar1 = flash_program_halfwords_ram(flash_dest,flash_data + (short)flash_data_read_i,1);
      uVar1 = uVar1 & 0xff;
      flash_dest = flash_dest + 2;
      crp_size = crp_size - 2;
      flash_data_read_i = flash_data_read_i + 2;
    }
    else {
      uVar1 = 0;
    }
  }
  else if (((crp_dest == 0x7c0) || (crp_dest == 0x17c0)) || (crp_dest == 0x7e0)) {
    if (crp_dest == 0x17c0) {
      flash_dest = flash_dest - 0x1000;
    }
    uVar2 = (int)(short)flash_data_write_i - (int)(short)flash_data_read_i;
    if ((int)uVar2 < 9) {
      if ((int)uVar2 < 1) {
        return 0;
      }
    }
    else {
      uVar2 = 8;
    }
    uVar1 = eeprom_write(flash_dest & 0xffff,flash_data + (short)flash_data_read_i,uVar2 & 0xffff);
    flash_dest = flash_dest + uVar2;
    crp_size = crp_size - uVar2;
    flash_data_read_i = flash_data_read_i + (short)uVar2;
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}



// Empty stub function

void nop_stub4(void)

{
  return;
}



// Writes 0x2222 marker to flash addresses 0x21FE8 and 0x21FEA to signal successful update

void flash_write_update_marker(void)

{
  undefined2 local_8 [4];
  
  local_8[0] = 0x2222;
  flash_program_halfwords_ram(&DAT_00021fe8,local_8,1);
  flash_program_halfwords_ram(0x21fea,local_8,1);
  return;
}



// Writes 0x2222 marker to flash address 0x21FEA only

void flash_write_update_marker_2(void)

{
  undefined2 local_8 [4];
  
  local_8[0] = 0x2222;
  flash_program_halfwords_ram(0x21fea,local_8,1);
  return;
}



// Initializes CAN-A module: soft reset, configures all 16 message buffers, sets MB15 for RX (ID
// 0x51/0x50), sets masks

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
  REG_PRESDIV_A = 3;
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
  REG_CANA_MB3_CS = 0;
  REG_CANA_MB3_ID_HI = 0;
  REG_CANA_MB3_ID_LO = 0;
  REG_CANA_MB4_CS = 0;
  REG_CANA_MB4_ID_HI = 0;
  REG_CANA_MB4_ID_LO = 0;
  REG_CANA_MB5_CS = 0;
  REG_CANA_MB5_ID_HI = 0;
  REG_CANA_MB5_ID_LO = 0;
  REG_CANA_MB6_CS = 0;
  REG_CANA_MB6_ID_HI = 0;
  REG_CANA_MB6_ID_LO = 0;
  REG_CANA_MB7_CS = 0;
  REG_CANA_MB7_ID_HI = 0;
  REG_CANA_MB7_ID_LO = 0;
  REG_CANA_MB8_CS = 0;
  REG_CANA_MB8_ID_HI = 0;
  REG_CANA_MB8_ID_LO = 0;
  REG_CANA_MB9_CS = 0;
  REG_CANA_MB9_ID_HI = 0;
  REG_CANA_MB9_ID_LO = 0;
  REG_CANA_MB10_CS = 0;
  REG_CANA_MB10_ID_HI = 0;
  REG_CANA_MB10_ID_LO = 0;
  REG_CANA_MB11_CS = 0;
  REG_CANA_MB11_ID_HI = 0;
  REG_CANA_MB11_ID_LO = 0;
  REG_CANA_MB12_CS = 0;
  REG_CANA_MB12_ID_HI = 0;
  REG_CANA_MB12_ID_LO = 0;
  REG_CANA_MB13_CS = 0;
  REG_CANA_MB13_ID_HI = 0;
  REG_CANA_MB13_ID_LO = 0;
  REG_CANA_MB14_CS = 0;
  REG_CANA_MB15_ID_HI = 0;
  REG_CANA_MB14_ID_LO = 0;
  REG_CANA_MB15_CS = 0;
  REG_CANA_MB15_ID_HI = 0xa20;
  REG_CANA_MB15_ID_LO = 0;
  uVar1 = REG_CANA_MB15_CS;
  REG_CANA_MB15_CS = uVar1 | 0x40;
  REG_RXGMSKHI_A = 0xffef;
  REG_RXGMSKLO_A = 0xfffe;
  REG_RX14MSKHI_A = 0xffef;
  REG_RX14MSKLO_A = 0xfffe;
  REG_RX15MSKHI_A = 0xff0f;
  REG_RX15MSKLO_A = 0xfffe;
  REG_ESTAT_A = 0;
  REG_CANICR_A = 0;
  REG_IMASK_A = 0;
  uVar1 = REG_CANMCR_A;
  REG_CANMCR_A = uVar1 & 0xefff;
  return;
}



// Sends CAN-A MB0 frame from tx buffer (up to 8 bytes per CAN frame)

void can_a_mb0_send(void)

{
  ushort uVar1;
  byte *pbVar2;
  uint uVar3;
  int iVar4;
  
  uVar1 = REG_CANA_MB0_CS;
  if ((uVar1 & 0xf0) == 0x80) {
    uVar1 = REG_IFLAG_A;
    REG_IFLAG_A = uVar1 & 0xfffe;
    pbVar2 = &REG_CANA_MB0_DATA0;
    REG_CANA_MB0_CS = 0x88;
    REG_CANA_MB0_ID_HI = tx_can_id << 5;
    iVar4 = (int)(short)tx_buffer_len - (int)tx_buffer_i;
    if (8 < iVar4) {
      iVar4 = 8;
    }
    if (0 < iVar4) {
      for (uVar3 = 0; (int)(uVar3 & 0xff) < iVar4; uVar3 = uVar3 + 1) {
        *pbVar2 = tx_buffer[uVar3 & 0xff];
        pbVar2 = pbVar2 + 1;
      }
      REG_CANA_MB0_CS = (short)iVar4 + 0xc0;
      tx_buffer_i = tx_buffer_i + (short)iVar4;
    }
  }
  return;
}



// Computes CRC8 using lookup table (polynomial 0x31)

byte CRC8(byte *param_1,int param_2)

{
  byte bVar1;
  int iVar2;
  
  DAT_003f910a = 0;
  for (iVar2 = 0; iVar2 < param_2; iVar2 = iVar2 + 1) {
    bVar1 = *param_1;
    param_1 = param_1 + 1;
    DAT_003f910a = CRC8_lookup_ram[bVar1 ^ DAT_003f910a];
  }
  return DAT_003f910a;
}



// Validates received CRP message CRC by comparing computed CRC with last byte

undefined4 efip_check_crc(void)

{
  undefined4 uVar1;
  
  if (((short)rx_buffer_write_i < 6) || (efip_crc != (&DAT_003f938f)[(short)rx_buffer_write_i])) {
    uVar1 = 0;
  }
  else {
    uVar1 = 1;
  }
  return uVar1;
}



// Main bootloader CRP protocol loop: polls CAN rx/tx, dispatches state machine, retriggers watchdog

void efip_main_loop(void)

{
  int iVar1;
  
  while (iVar1 = efip_is_active(), iVar1 == 1) {
    REG_SWSR = 0x556c;
    REG_SWSR = 0xaa39;
    efip_nop_timer();
    efip_poll_can_rx();
    efip_state_dispatch();
    efip_poll_can_tx();
  }
  return;
}



// Polls CAN-A MB15 for incoming frames

void efip_poll_can_rx(void)

{
  can_a_mb15_recv();
  return;
}



// Polls CAN-A MB0 to send pending tx data

void efip_poll_can_tx(void)

{
  can_a_mb0_send();
  return;
}



// CRP protocol state machine dispatcher (0=idle, 1=wait_cmd, 2=transfer, 3=end, 4=error)

void efip_state_dispatch(void)

{
  if (efip_state == 2) {
    efip_state_transfer();
    return;
  }
  if (efip_state < 2) {
    if (efip_state == 0) {
      efip_state_idle();
      return;
    }
    if (true) {
      efip_state_wait_cmd();
      return;
    }
  }
  else {
    if (efip_state == 4) {
      efip_state_error_clear();
      return;
    }
    if (efip_state < 4) {
      efip_state_end();
      return;
    }
  }
  efip_state = 0;
  return;
}



// State 0: Resets protocol state, initializes CAN, clears buffers, sends hello to flasher

void efip_state_idle(void)

{
  efip_init();
  efip_reset_buffers();
  efip_enable_timer();
  nop_stub4();
  xtea_reset_state();
  DAT_003f9113 = DAT_003f9113 & 0x10;
  crp_frame_i = 0;
  DAT_003f911d = 0;
  DAT_003f911c = 0;
  efip_set_rx_timeout(0);
  efip_state = 1;
  return;
}



// State 1: Waits for start command (cmd=7), validates CRC, checks message type, transitions to
// transfer state

void efip_state_wait_cmd(void)

{
  char cVar2;
  int iVar1;
  
  cVar2 = efip_check_enquiry_timeout();
  if ((cVar2 == '\x01') && ((DAT_003f9113 & 8) == 0)) {
    if (DAT_003f911d == '\0') {
      DAT_003f911d = DAT_003f911d + '\x01';
      efip_send_hello();
    }
    else {
      DAT_003f9113 = DAT_003f9113 & 0xef;
      DAT_003f911d = DAT_003f911d + '\x01';
    }
  }
  else {
    cVar2 = efip_rx_ready();
    if ((cVar2 == '\x01') && (iVar1 = efip_rx_count(), iVar1 == 8)) {
      cVar2 = efip_check_crc();
      if (cVar2 == '\x01') {
        efip_crc = 0;
        DAT_003f9108 = 0;
        cVar2 = efip_check_start_cmd();
        if (cVar2 == '\x01') {
          efip_send_frame_request();
          DAT_003f9110 = 0;
          efip_state = 2;
        }
        else {
          cVar2 = efip_check_pause_cmd();
          if (cVar2 == '\x01') {
            DAT_003f9113 = DAT_003f9113 & 0xef | 8;
          }
          else {
            cVar2 = efip_check_resume_cmd();
            if (cVar2 == '\x01') {
              DAT_003f9113 = DAT_003f9113 & 0xf7;
            }
            else {
              efip_send_error(0x81);
            }
          }
        }
      }
      else {
        efip_crc = 0;
        DAT_003f9108 = 0;
        efip_send_retry(0x97);
      }
    }
  }
  return;
}



// State 2: Active data transfer - processes data frames (cmd=6), handles erase/program, sends frame
// requests

void efip_state_transfer(void)

{
  ushort uVar1;
  ushort uVar2;
  char cVar5;
  int iVar3;
  char cVar6;
  uint uVar4;
  
  uVar2 = (ushort)rx_buffer[3];
  uVar1 = (ushort)rx_buffer[4];
  cVar5 = efip_check_crc();
  efip_erase_handler();
  efip_program_handler();
  if (((DAT_003f9113 & 2) != 0) || ((DAT_003f9113 & 1) != 0)) {
    if ((DAT_003f9113 & 1) != 1) {
      return;
    }
    if ((DAT_003f9113 & 4) != 0) {
      return;
    }
    iVar3 = efip_rx_count();
    if (iVar3 == 0) {
      return;
    }
  }
  if (((((short)rx_buffer_write_i < 6) ||
       ((int)(short)(uVar2 * 0x100 + uVar1) != (short)rx_buffer_write_i + -6)) || (cVar5 != '\x01'))
     && (cVar6 = efip_check_rx_timeout(), cVar6 != '\x01')) {
    return;
  }
  DAT_003f9111 = efip_crc;
  efip_crc = 0;
  DAT_003f9108 = 0;
  if ((DAT_003f9114 & 2) == 2) {
    efip_send_error(0x85);
  }
  else if ((DAT_003f9114 & 1) == 1) {
    efip_send_error(0x88);
  }
  else {
    iVar3 = efip_rx_count();
    if (iVar3 < 0x401) {
      iVar3 = efip_rx_count();
      if (iVar3 == 0) {
        if (((int)crp_size < 1) && (crp_dest != 0)) {
          efip_send_complete();
          efip_state = 3;
        }
        else if ((DAT_003f9113 & 4) == 4) {
          DAT_003f9110 = DAT_003f9110 + 1;
          if (DAT_003f9110 < 100) {
            efip_send_frame_request();
          }
          else {
            efip_send_error(0x8e);
            DAT_003f9110 = 0;
          }
        }
        else {
          efip_send_error(0x83);
        }
      }
      else if (cVar5 == '\0') {
        efip_send_retry(0x97);
      }
      else {
        cVar5 = efip_check_ack();
        if (cVar5 == '\0') {
          uVar4 = efip_process_frame();
          if (((uVar4 & 0xff) < 0x80) || (0x95 < (uVar4 & 0xff))) {
            if (((uVar4 & 0xff) < 0x96) || (0x9f < (uVar4 & 0xff))) {
              if ((uVar4 & 0xff) == 2) {
                crp_frame_i = crp_frame_i + 1;
                DAT_003f9113 = DAT_003f9113 | 2;
                if ((int)(short)flash_data_write_i < (int)crp_size) {
                  efip_send_frame_request();
                  DAT_003f9110 = 0;
                }
              }
              else if ((uVar4 & 0xff) == 3) {
                crp_frame_i = crp_frame_i + 1;
                DAT_003f9113 = DAT_003f9113 | 3;
                efip_send_erasing();
              }
            }
            else {
              efip_send_retry(uVar4);
            }
          }
          else {
            efip_send_error(uVar4);
          }
        }
      }
    }
    else {
      efip_send_retry(0x96);
    }
  }
  return;
}



// State 3: End procedure - handles next chunk start (cmd=7) or acknowledge (cmd=4), resets for next
// transfer

void efip_state_end(void)

{
  char cVar2;
  int iVar1;
  
  cVar2 = efip_check_rx_timeout();
  if (cVar2 == '\x01') {
    iVar1 = efip_rx_count();
    if (iVar1 == 0) {
      DAT_003f9113 = DAT_003f9113 & 0xef;
    }
    else {
      cVar2 = efip_check_crc();
      if (cVar2 == '\x01') {
        cVar2 = efip_check_ack();
        if (cVar2 == '\x01') {
          efip_retransmit();
        }
        else {
          cVar2 = efip_check_start_cmd();
          if (cVar2 == '\x01') {
            crp_frame_i = 0;
            efip_send_frame_request();
            efip_crc = 0;
            DAT_003f9108 = 0;
            efip_reset_buffers();
            DAT_003f911d = 0;
            DAT_003f911c = 0;
            DAT_003f9113 = DAT_003f9113 & 0xfb;
            efip_state = 2;
          }
          else {
            cVar2 = efip_check_resume_cmd();
            if (cVar2 == '\x01') {
              DAT_003f9113 = DAT_003f9113 & 0xf7;
            }
            else {
              efip_send_error(0x87);
            }
          }
        }
      }
      else {
        efip_send_retry(0x97);
      }
      efip_crc = 0;
      DAT_003f9108 = 0;
    }
  }
  return;
}



// State 4: Clears error flags

void efip_state_error_clear(void)

{
  DAT_003f9113 = DAT_003f9113 & 0xe7;
  return;
}



// Initiates flash erase when programming flag is set and no pending rx data

void efip_erase_handler(void)

{
  int iVar1;
  char cVar2;
  
  if ((((DAT_003f9113 & 1) == 1) && (iVar1 = efip_rx_count(), iVar1 == 0)) &&
     (cVar2 = efip_check_rx_timeout(), cVar2 == '\x01')) {
    iVar1 = flash_erase_block();
    if (iVar1 == 0) {
      DAT_003f9114 = DAT_003f9114 | 1;
    }
    DAT_003f9113 = DAT_003f9113 & 0xfe | 4;
  }
  return;
}



// Programs flash from rx buffer when erase is complete

void efip_program_handler(void)

{
  char cVar1;
  
  if (((DAT_003f9113 & 2) == 2) && ((DAT_003f9113 & 4) == 4)) {
    cVar1 = efip_write_data();
    if (cVar1 == '\0') {
      DAT_003f9114 = DAT_003f9114 | 2;
      DAT_003f9113 = DAT_003f9113 & 0xfd;
    }
    else {
      cVar1 = efip_write_complete();
      if (cVar1 == '\x01') {
        DAT_003f9113 = DAT_003f9113 & 0xfd;
      }
    }
  }
  return;
}



// Returns true when all buffered data has been written to flash/EEPROM

bool efip_write_complete(void)

{
  return (short)flash_data_write_i <= (short)flash_data_read_i;
}



// Enables timebase timer for protocol timeouts

void efip_enable_timer(void)

{
  timer_enable_timebase();
  return;
}



// Empty timer function (placeholder)

void efip_nop_timer(void)

{
  timer_nop();
  return;
}



// Checks if enquiry/hello timeout has expired

void efip_check_enquiry_timeout(void)

{
  timer_enquiry_expired();
  return;
}



// Sets rx timeout value for CAN message reception

void efip_set_rx_timeout(undefined4 param_1)

{
  timer_set_rx_timeout(param_1);
  return;
}



// Initializes CRP protocol: sets CAN local ID to 0x7A1, resets buffers, initializes CAN-A module

void efip_init(void)

{
  rx_efi_id = 1;
  rx_buffer_write_i = 0;
  rx_buffer_i = 0;
  DAT_003f9796 = 0;
  tx_can_id = 0x7a1;
  tx_buffer_len = 0;
  tx_buffer_i = 0;
  DAT_003fa022 = 0;
  init_can_a();
  return;
}



// Checks if CAN rx timeout has expired

void efip_check_rx_timeout(void)

{
  timer_rx_expired();
  return;
}



// Returns true if rx buffer has 8+ bytes or rx timeout expired

undefined4 efip_rx_ready(void)

{
  undefined4 uVar1;
  
  if (rx_buffer_write_i == 8) {
    uVar1 = 1;
  }
  else {
    uVar1 = timer_rx_expired();
  }
  return uVar1;
}



// Returns current rx buffer byte count

int efip_rx_count(void)

{
  return (int)(short)rx_buffer_write_i;
}



// Sends hello/enquiry message (cmd=0x0A) to flasher tool with EFI local ID, resets rx state

void efip_send_hello(void)

{
  tx_buffer[0] = 10;
  tx_buffer[1] = 1;
  tx_buffer[2] = 0;
  tx_buffer[3] = 0;
  tx_buffer[4] = 0;
  tx_buffer[5] = (uint8_t)((ushort)DAT_00000a06 >> 8);
  tx_buffer[6] = (uint8_t)DAT_00000a06;
  tx_buffer[7] = CRC8(tx_buffer,7);
  tx_buffer_len = 8;
  tx_buffer_i = 0;
  efip_poll_can_tx();
  efip_set_can_rx_timeout(&DAT_00027100);
  efip_set_rx_timeout(&DAT_000249f0);
  rx_buffer_write_i = 0;
  rx_buffer_i = 0;
  return;
}



// Sends retry response (cmd=0x04) with error code, increments retry counter (max 3 then fatal error
// 0x82)

void efip_send_retry(uint8_t param_1)

{
  if (DAT_003f911c < 3) {
    tx_buffer[0] = 4;
    tx_buffer[1] = 1;
    tx_buffer[2] = 0;
    tx_buffer[3] = 0;
    tx_buffer[4] = 0;
    tx_buffer[6] = 0;
    DAT_003f911c = DAT_003f911c + 1;
    tx_buffer[5] = param_1;
    tx_buffer[7] = CRC8(tx_buffer,7);
    tx_buffer_len = 8;
    tx_buffer_i = 0;
    efip_poll_can_tx();
    efip_set_can_rx_timeout(&DAT_00027100);
    rx_buffer_write_i = 0;
    rx_buffer_i = 0;
  }
  else {
    DAT_003f911c = DAT_003f911c + 1;
    efip_send_error(0x82);
  }
  return;
}



// Sends frame request (cmd=0x01) with frame size and current frame index to flasher

void efip_send_frame_request(void)

{
  tx_buffer[0] = 1;
  tx_buffer[1] = 1;
  tx_buffer[2] = 0;
  tx_buffer[3] = 4;
  tx_buffer[4] = 0;
  tx_buffer[5] = (uint8_t)(crp_frame_i >> 8);
  tx_buffer[6] = (uint8_t)crp_frame_i;
  tx_buffer[7] = CRC8(tx_buffer,7);
  tx_buffer_len = 8;
  tx_buffer_i = 0;
  efip_poll_can_tx();
  efip_set_can_rx_timeout(&DAT_00027100);
  rx_buffer_write_i = 0;
  rx_buffer_i = 0;
  return;
}



// Sends fatal error (cmd=0x05) with error code, transitions to error state

void efip_send_error(uint8_t param_1)

{
  tx_buffer[0] = 5;
  tx_buffer[1] = 1;
  tx_buffer[2] = 0;
  tx_buffer[3] = 0;
  tx_buffer[4] = 0;
  tx_buffer[6] = 0;
  tx_buffer[5] = param_1;
  tx_buffer[7] = CRC8(tx_buffer,7);
  tx_buffer_len = 8;
  tx_buffer_i = 0;
  efip_poll_can_tx();
  efip_set_can_rx_timeout(&DAT_00027100);
  rx_buffer_write_i = 0;
  rx_buffer_i = 0;
  efip_state = 4;
  return;
}



// Sends error response (cmd=0x05) with error code without changing protocol state

void efip_send_error_hc08(uint8_t param_1)

{
  tx_buffer[0] = 5;
  tx_buffer[1] = 1;
  tx_buffer[2] = 0;
  tx_buffer[3] = 0;
  tx_buffer[4] = 0;
  tx_buffer[6] = 0;
  tx_buffer[5] = param_1;
  tx_buffer[7] = CRC8(tx_buffer,7);
  tx_buffer_len = 8;
  tx_buffer_i = 0;
  efip_poll_can_tx();
  return;
}



// Resets tx buffer offset and retransmits pending CAN frame

void efip_retransmit(void)

{
  tx_buffer_i = 0;
  efip_poll_can_tx();
  efip_set_can_rx_timeout(&DAT_00027100);
  rx_buffer_write_i = 0;
  rx_buffer_i = 0;
  return;
}



// Checks if received message is start command (cmd=7) with matching EFI ID, extracts frame size
// limits

undefined4 efip_check_start_cmd(void)

{
  undefined4 uVar1;
  
  if ((rx_buffer[0] == 7) && ((ushort)rx_buffer[1] == (rx_efi_id & 0xff))) {
    DAT_003f9136 = (ushort)rx_buffer[3] * 0x100 + (ushort)rx_buffer[4];
    DAT_003f9134 = (ushort)rx_buffer[5] * 0x100 + (ushort)rx_buffer[6];
    uVar1 = 1;
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}



// Checks if received message is pause command (cmd=8, sub=0), resets rx state

undefined4 efip_check_pause_cmd(void)

{
  undefined4 uVar1;
  
  if ((rx_buffer[0] == 8) && (rx_buffer[1] == 0)) {
    rx_buffer_write_i = 0;
    rx_buffer_i = 0;
    uVar1 = 1;
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}



// Checks if received message is resume command (cmd=9, sub=0), resets rx state

undefined4 efip_check_resume_cmd(void)

{
  undefined4 uVar1;
  
  if ((rx_buffer[0] == 9) && (rx_buffer[1] == 0)) {
    rx_buffer_write_i = 0;
    rx_buffer_i = 0;
    uVar1 = 1;
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}



// Sends programming complete message (cmd=0x02) to flasher

void efip_send_complete(void)

{
  tx_buffer[0] = 2;
  tx_buffer[1] = 1;
  tx_buffer[2] = 0;
  tx_buffer[3] = 0;
  tx_buffer[4] = 0;
  tx_buffer[5] = 0;
  tx_buffer[6] = 0;
  tx_buffer[7] = CRC8(tx_buffer,7);
  tx_buffer_len = 8;
  tx_buffer_i = 0;
  efip_poll_can_tx();
  efip_set_can_rx_timeout(&DAT_00027100);
  rx_buffer_write_i = 0;
  rx_buffer_i = 0;
  return;
}



// Sends HC08 programming result message (cmd=0x0C) with 16-bit status parameter

void efip_send_hc08_result(undefined4 param_1)

{
  tx_buffer[0] = 12;
  tx_buffer[1] = 1;
  tx_buffer[2] = (uint8_t)((uint)param_1 >> 8);
  tx_buffer[3] = (uint8_t)param_1;
  tx_buffer[4] = 0;
  tx_buffer[5] = 0;
  tx_buffer[6] = 0;
  tx_buffer[7] = CRC8(tx_buffer,7);
  tx_buffer_len = 8;
  tx_buffer_i = 0;
  efip_poll_can_tx();
  return;
}



// Sends HC08 programming start message (cmd=0x0B) with 16-bit parameter

void efip_send_hc08_start(undefined4 param_1)

{
  tx_buffer[0] = 11;
  tx_buffer[1] = 1;
  tx_buffer[2] = (uint8_t)((uint)param_1 >> 8);
  tx_buffer[3] = (uint8_t)param_1;
  tx_buffer[4] = 0;
  tx_buffer[5] = 0;
  tx_buffer[6] = 0;
  tx_buffer[7] = CRC8(tx_buffer,7);
  tx_buffer_len = 8;
  tx_buffer_i = 0;
  efip_poll_can_tx();
  return;
}



// Sends HC08 erase/program info message (cmd=0x0D) with 16-bit timing parameter

void efip_send_hc08_erase_info(undefined4 param_1)

{
  tx_buffer[0] = 13;
  tx_buffer[1] = 1;
  tx_buffer[2] = (uint8_t)((uint)param_1 >> 8);
  tx_buffer[3] = (uint8_t)param_1;
  tx_buffer[4] = 0;
  tx_buffer[5] = 0;
  tx_buffer[6] = 0;
  tx_buffer[7] = CRC8(tx_buffer,7);
  tx_buffer_len = 8;
  tx_buffer_i = 0;
  efip_poll_can_tx();
  return;
}



// Checks if received message is acknowledge (cmd=4) with matching EFI ID, retransmits pending data

undefined4 efip_check_ack(void)

{
  undefined4 uVar1;
  
  if ((rx_buffer[0] == 4) && ((ushort)rx_buffer[1] == (rx_efi_id & 0xff))) {
    efip_retransmit();
    uVar1 = 1;
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}



// Validates incoming data frame (cmd=6): checks frame index, length, dispatches to encrypted or
// plain parser

undefined4 efip_process_frame(void)

{
  undefined4 uVar1;
  
  if (rx_buffer[0] == 6) {
    if (((uint)rx_buffer[1] * 0x100 + (uint)rx_buffer[2] & 0xffff) == crp_frame_i) {
      if (((uint)rx_buffer[3] * 0x100 + (uint)rx_buffer[4] & 0xffff) ==
          (int)(short)rx_buffer_write_i - 6U) {
        if ((crp_frame_i != 0) &&
           ((int)(crp_size - DAT_003f9122) <
            (int)(((short)rx_buffer_write_i + -6) - (uint)DAT_003f9120))) {
          return 0x99;
        }
        if (DAT_00000a08 == -1) {
          uVar1 = efip_parse_frame_plain();
        }
        else {
          uVar1 = efip_parse_frame_encrypted();
        }
      }
      else {
        uVar1 = 0x99;
      }
    }
    else {
      uVar1 = 0x98;
    }
  }
  else {
    uVar1 = 0x89;
  }
  return uVar1;
}



// Parses data frames (unencrypted): first frame extracts ECU header and validates, subsequent
// frames copy payload to write buffer

undefined4 efip_parse_frame_plain(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  char cVar5;
  
  if (crp_frame_i == 0) {
    iVar1 = read_be32(rx_buffer + 0x2d);
    iVar2 = read_be32(rx_buffer + 0x31);
    crp_dest = read_be32(rx_buffer + 0x25);
    crp_size = read_be32(rx_buffer + 0x29);
    iVar3 = strncmp(rx_buffer + 5,0xa0c,0x1f);
    if (iVar3 == 0) {
      if (DAT_00000a00 < 1) {
        if ((((crp_dest == 0xa00) && (iVar1 == iVar2)) && (0 < iVar1)) && (rx_buffer_write_i == 70))
        {
          flash_dest = crp_dest;
          memcpy((char *)flash_data,(char *)(rx_buffer + 0x2d),4);
          flash_data_write_i = 4;
          flash_data_read_i = 0;
          rx_buffer_i = 0;
          rx_buffer_write_i = 0;
          uVar4 = 3;
        }
        else {
          uVar4 = 0x8a;
        }
      }
      else if (((iVar1 < 1) && (iVar2 < 1)) || ((iVar1 <= DAT_00000a00 && (DAT_00000a00 <= iVar2))))
      {
        if (((((crp_dest == 0x20000) && ((int)crp_size < 0x60000)) ||
             ((crp_dest == 0x10000 && ((int)crp_size < 0x10001)))) ||
            ((((crp_dest == 0xa2c && (crp_size == 32)) &&
              (cVar5 = flash_is_blank(0xa2c,0x20), cVar5 == '\x01')) ||
             (((crp_dest == 0xa4c && (crp_size == 32)) &&
              (cVar5 = flash_is_blank(0xa4c,0x20), cVar5 == '\x01')))))) ||
           ((((crp_dest == 0xa08 && (crp_size == 4)) &&
             (cVar5 = flash_is_blank(0xa08,4), cVar5 == '\x01')) ||
            (((((crp_dest == 0x7c0 && (crp_size == 32)) &&
               (cVar5 = eeprom_is_blank(0x7c0,0x20), cVar5 == '\x01')) ||
              (((crp_dest == 0x17c0 && (crp_size == 32)) &&
               ((iVar1 == iVar2 && (iVar1 == DAT_00000a00)))))) ||
             ((((crp_dest == 0x7e0 && (crp_size == 32)) && (iVar1 == iVar2)) &&
              (iVar1 == DAT_00000a00)))))))) {
          flash_dest = crp_dest;
          if ((short)rx_buffer_write_i < 0x47) {
            uVar4 = 1;
          }
          else {
            memcpy((char *)flash_data,(char *)(rx_buffer + 0x45),
                   (int)(short)rx_buffer_write_i - 0x46);
            flash_data_write_i = rx_buffer_write_i - 70;
            if ((crp_size == (int)(short)rx_buffer_write_i - 70U) &&
               ((crp_size & 1 ^ crp_size >> 0x1f) != crp_size >> 0x1f)) {
              flash_data[(short)flash_data_write_i] = 255;
              flash_data_write_i = flash_data_write_i + 1;
            }
            flash_data_read_i = 0;
            rx_buffer_i = 0;
            rx_buffer_write_i = 0;
            uVar4 = 3;
          }
        }
        else if ((((((crp_dest == 0xa00) && (iVar1 == iVar2)) && (0 < iVar1)) &&
                  ((rx_buffer_write_i == 70 && (0 < DAT_00000a00)))) ||
                 (((crp_dest == 0xa2c &&
                   ((crp_size == 32 && (cVar5 = flash_is_blank(0xa2c,0x20), cVar5 == '\0')))) ||
                  ((crp_dest == 0xa4c &&
                   ((crp_size == 32 && (cVar5 = flash_is_blank(0xa4c,0x20), cVar5 == '\0')))))))) ||
                (((crp_dest == 0xa08 &&
                  ((crp_size == 4 && (cVar5 = flash_is_blank(0xa08,4), cVar5 == '\0')))) ||
                 ((crp_dest == 0x7c0 &&
                  ((crp_size == 32 && (cVar5 = eeprom_is_blank(0x7c0,0x20), cVar5 == '\0')))))))) {
          uVar4 = 0x8f;
        }
        else {
          uVar4 = 0x8d;
        }
      }
      else {
        uVar4 = 0x8c;
      }
    }
    else {
      uVar4 = 0x8b;
    }
  }
  else {
    memcpy((char *)flash_data,(char *)(rx_buffer + 5),(int)(short)rx_buffer_write_i - 6);
    flash_data_write_i = rx_buffer_write_i - 6;
    if ((crp_size == (int)(short)rx_buffer_write_i - 6U) &&
       ((crp_size & 1 ^ crp_size >> 0x1f) != crp_size >> 0x1f)) {
      flash_data[(short)flash_data_write_i] = 255;
      flash_data_write_i = flash_data_write_i + 1;
    }
    flash_data_read_i = 0;
    rx_buffer_i = 0;
    rx_buffer_write_i = 0;
    uVar4 = 2;
  }
  return uVar4;
}



// Parses data frames (XTEA encrypted): first frame decrypts and extracts ECU header, subsequent
// frames decrypt and buffer data

undefined4 efip_parse_frame_encrypted(void)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  char cVar6;
  ushort uVar7;
  
  if (crp_frame_i == 0) {
    xtea_decrypt_cbc(plain_buffer,rx_buffer + 5,rx_buffer_write_i - 6);
    iVar2 = read_be32(plain_buffer + 0x34);
    iVar3 = read_be32(plain_buffer + 0x38);
    crp_dest = read_be32(plain_buffer + 0x2c);
    crp_size = read_be32(plain_buffer + 0x30);
    plain_buffer_len = read_be32(plain_buffer + 8);
    uVar1 = (int)(plain_buffer_len + 12) >> 0x1f;
    if ((uVar1 * 8 | (plain_buffer_len + 12) * 0x20000000 + uVar1 >> 0x1d) == uVar1) {
      DAT_003f9120 = 0;
    }
    else {
      iVar4 = plain_buffer_len + 12;
      cVar6 = (char)(iVar4 >> 0x1f);
      DAT_003f9120 = 8 - ((cVar6 * '\b' |
                          (byte)((uint)(iVar4 * 0x20000000 + (iVar4 >> 0x1f)) >> 0x1d)) - cVar6);
    }
    iVar4 = strncmp(plain_buffer + 0xc,0xa0c,0x1f);
    if (iVar4 == 0) {
      if (DAT_00000a00 < 1) {
        if ((((crp_dest == 0xa00) && (iVar2 == iVar3)) && (0 < iVar2)) &&
           ((int)(short)rx_buffer_write_i == DAT_003f9120 + 0x52)) {
          flash_dest = crp_dest;
          memcpy((char *)flash_data,(char *)(plain_buffer + 0x38),4);
          flash_data_write_i = 4;
          flash_data_read_i = 0;
          rx_buffer_i = 0;
          rx_buffer_write_i = 0;
          uVar5 = 3;
        }
        else {
          uVar5 = 0x8a;
        }
      }
      else if (((iVar2 < 1) && (iVar3 < 1)) || ((iVar2 <= DAT_00000a00 && (DAT_00000a00 <= iVar3))))
      {
        if ((((((crp_dest == 0x20000) && ((int)crp_size < 0x60000)) ||
              (((crp_dest == 0x10000 && ((int)crp_size < 0x10001)) ||
               ((((crp_dest == 0xa2c && (plain_buffer_len == 96)) &&
                 (cVar6 = flash_is_blank(0xa2c,0x20), cVar6 == '\x01')) ||
                (((crp_dest == 0xa4c && (plain_buffer_len == 96)) &&
                 (cVar6 = flash_is_blank(0xa4c,0x20), cVar6 == '\x01')))))))) ||
             (((crp_dest == 0x7c0 && (plain_buffer_len == 96)) &&
              (cVar6 = eeprom_is_blank(0x7c0,0x20), cVar6 == '\x01')))) ||
            ((((crp_dest == 0x17c0 && (plain_buffer_len == 96)) && (iVar2 == iVar3)) &&
             (iVar2 == DAT_00000a00)))) ||
           (((crp_dest == 0x7e0 && (plain_buffer_len == 96)) &&
            ((iVar2 == iVar3 && (iVar2 == DAT_00000a00)))))) {
          flash_dest = crp_dest;
          if ((int)plain_buffer_len < 0x41) {
            uVar5 = 1;
          }
          else {
            uVar7 = (ushort)rx_buffer[3] * 0x100 + (ushort)rx_buffer[4];
            if ((int)((uVar7 - 0xc) - (uint)DAT_003f9120) < (int)plain_buffer_len) {
              flash_data_len = (uVar7 - 0x4c) - DAT_003f9122;
            }
            else {
              uVar1 = plain_buffer_len - 64 >> 0x1f;
              if ((plain_buffer_len - 64 & 1 ^ uVar1) == uVar1) {
                flash_data_len = (short)plain_buffer_len - 64;
              }
              else {
                plain_buffer[plain_buffer_len + 12] = 255;
                flash_data_len = (short)plain_buffer_len - 63;
              }
            }
            memcpy((char *)flash_data,(char *)(plain_buffer + 0x4c),(uint)flash_data_len);
            flash_data_write_i = flash_data_len;
            flash_data_read_i = 0;
            memcpy((char *)plain_buffer,
                   &DAT_003f938f + ((int)(short)rx_buffer_write_i - (uint)DAT_003f9122),
                   (uint)DAT_003f9122);
            DAT_003fa82a = DAT_003f9122;
            rx_buffer_i = 0;
            rx_buffer_write_i = 0;
            uVar5 = 3;
          }
        }
        else if ((((((crp_dest == 0xa00) && (iVar2 == iVar3)) && (0 < iVar2)) &&
                  (((int)(short)rx_buffer_write_i == DAT_003f9120 + 0x52 && (0 < DAT_00000a00)))) ||
                 (((crp_dest == 0xa2c &&
                   ((plain_buffer_len == 96 && (cVar6 = flash_is_blank(0xa2c,0x20), cVar6 == '\0')))
                   ) || ((crp_dest == 0xa4c &&
                         ((plain_buffer_len == 96 &&
                          (cVar6 = flash_is_blank(0xa4c,0x20), cVar6 == '\0')))))))) ||
                ((crp_dest == 0x7c0 &&
                 ((plain_buffer_len == 96 && (cVar6 = eeprom_is_blank(0x7c0,0x20), cVar6 == '\0'))))
                )) {
          uVar5 = 0x8f;
        }
        else {
          uVar5 = 0x8d;
        }
      }
      else {
        uVar5 = 0x8c;
      }
    }
    else {
      uVar5 = 0x8b;
    }
  }
  else {
    memcpy((char *)(plain_buffer + (short)DAT_003fa82a),(char *)(rx_buffer + 5),
           (int)(short)rx_buffer_write_i - 6);
    DAT_003fa82a = rx_buffer_write_i + DAT_003fa82a + -6;
    xtea_decrypt_cbc(flash_data,plain_buffer,DAT_003fa82a);
    DAT_003fa82a = DAT_003f9122;
    memcpy((char *)plain_buffer,&DAT_003f938f + ((int)(short)rx_buffer_write_i - (uint)DAT_003f9122)
           ,(uint)DAT_003f9122);
    if ((int)(uint)flash_data_len < (int)crp_size) {
      flash_data_write_i = flash_data_len;
    }
    else if ((crp_size & 1 ^ crp_size >> 0x1f) == crp_size >> 0x1f) {
      flash_data_write_i = (uint16_t)crp_size;
    }
    else {
      flash_data[crp_size] = 255;
      flash_data_write_i = (short)crp_size + 1;
    }
    flash_data_read_i = 0;
    rx_buffer_i = 0;
    rx_buffer_write_i = 0;
    uVar5 = 2;
  }
  return uVar5;
}



// Sends erasing notification (cmd=0x03) to flasher with erase parameters

void efip_send_erasing(void)

{
  tx_buffer[0] = 3;
  tx_buffer[1] = 1;
  tx_buffer[2] = 0;
  tx_buffer[3] = 78;
  tx_buffer[4] = 32;
  tx_buffer[5] = 0;
  tx_buffer[6] = 0;
  tx_buffer[7] = CRC8(tx_buffer,7);
  tx_buffer_len = 8;
  tx_buffer_i = 0;
  efip_poll_can_tx();
  efip_set_can_rx_timeout(&DAT_00027100);
  rx_buffer_write_i = 0;
  rx_buffer_i = 0;
  return;
}



// Reads 4-byte big-endian integer from byte buffer

int read_be32(byte *param_1)

{
  return (uint)*param_1 * 0x1000000 + (uint)param_1[1] * 0x10000 + (uint)param_1[2] * 0x100 +
         (uint)param_1[3];
}



// Checks if flash region is blank (all 0xFF bytes)

undefined4 flash_is_blank(char *param_1,byte param_2)

{
  char cVar1;
  byte bVar2;
  
  bVar2 = 0;
  while( true ) {
    if (param_2 <= bVar2) {
      return 1;
    }
    cVar1 = *param_1;
    param_1 = param_1 + 1;
    if (cVar1 != -1) break;
    bVar2 = bVar2 + 1;
  }
  return 0;
}



// Checks if SPI EEPROM region is blank by reading byte-by-byte

undefined4 eeprom_is_blank(short param_1,byte param_2)

{
  char cVar1;
  ushort uVar2;
  
  uVar2 = 0;
  while( true ) {
    if (param_2 <= uVar2) {
      return 1;
    }
    cVar1 = eeprom_read_byte(param_1 + uVar2);
    if (cVar1 != '\0') break;
    uVar2 = uVar2 + 1;
  }
  return 0;
}



// Decrypts data using XTEA CBC mode, handles 8-byte block alignment, stores remainder count

void xtea_decrypt_cbc(undefined4 param_1,undefined4 param_2,ushort param_3)

{
  DAT_003f9122 = param_3 & 7;
  flash_data_len = param_3 - DAT_003f9122;
  xtea_decrypt_cbc_blocks(param_1,param_2,flash_data_len);
  return;
}



// Copies flash programming routines (0x88C bytes from 0x8000) to RAM (0x3F8000) for execution
// during flash writes

void copy_to_ram(void)

{
  bool bVar1;
  code cVar2;
  int iVar3;
  code *pcVar4;
  code *pcVar5;
  
  pcVar5 = can_a_mb15_recv_ram;
  pcVar4 = can_a_mb15_recv;
  iVar3 = 0x88c;
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



// Returns true if bootloader CRP protocol is active (flags & 0x18 != 0)

bool efip_is_active(void)

{
  return (DAT_003f9113 & 0x18) != 0;
}



// Enables timebase timer by setting TBSCR enable bit

void timer_enable_timebase(void)

{
  ushort uVar1;
  
  uVar1 = REG_TBSCR;
  REG_TBSCR = uVar1 | 1;
  return;
}



// Returns true if CAN rx timeout has expired (current time >= deadline)

bool timer_rx_expired(void)

{
  uint uVar1;
  
  uVar1 = timer_read_tbl_2();
  return DAT_003f913c <= uVar1;
}



// Empty timer stub function

void timer_nop(void)

{
  return;
}



// Returns true if enquiry/hello timeout has expired

bool timer_enquiry_expired(void)

{
  uint uVar1;
  
  uVar1 = timer_read_tbl_2();
  return DAT_003f9138 <= uVar1;
}



// Sets CAN rx timeout deadline from current time plus offset

void timer_set_rx_timeout(int param_1)

{
  int iVar1;
  
  iVar1 = timer_read_tbl_2();
  DAT_003f9138 = param_1 + iVar1;
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



void xtea_decrypt(uint *param_1,uint *param_2)

{
  bool bVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  
  uVar3 = 0xc6ef3720;
  iVar2 = 0x20;
  uVar5 = *param_1;
  uVar4 = *param_2;
  while (bVar1 = iVar2 != 0, iVar2 = iVar2 + -1, bVar1) {
    uVar4 = uVar4 - (uVar5 + (uVar5 << 4 ^ uVar5 >> 5) ^ uVar3 + XTEA_KEY[uVar3 >> 0xb & 3]);
    uVar3 = uVar3 + 0x61c88647;
    uVar5 = uVar5 - (uVar4 + (uVar4 * 0x10 ^ uVar4 >> 5) ^ uVar3 + XTEA_KEY[uVar3 & 3]);
  }
  *param_1 = uVar5;
  *param_2 = uVar4;
  return;
}



// XTEA CBC decryption inner loop: processes 8-byte blocks with IV chaining

ushort xtea_decrypt_cbc_blocks(uint *param_1,uint *param_2,ushort param_3)

{
  for (; 7 < param_3; param_3 = param_3 - 8) {
    DAT_003f9144 = *param_2;
    DAT_003f9140 = param_2[1];
    param_2 = param_2 + 2;
    DAT_003f9150 = DAT_003f9140;
    DAT_003f9154 = DAT_003f9144;
    xtea_decrypt(&DAT_003f9154,&DAT_003f9150);
    DAT_003f9154 = DAT_003f9154 ^ DAT_003f914c;
    DAT_003f9150 = DAT_003f9150 ^ DAT_003f9148;
    DAT_003f914c = DAT_003f9144;
    DAT_003f9148 = DAT_003f9140;
    *param_1 = DAT_003f9154;
    param_1[1] = DAT_003f9150;
    param_1 = param_1 + 2;
  }
  return param_3 & 0xff;
}



// Resets XTEA CBC state: clears IV and temporary buffers

void xtea_reset_state(void)

{
  DAT_003f9148 = 0;
  DAT_003f914c = 0;
  DAT_003f9150 = 0;
  DAT_003f9154 = 0;
  DAT_003f9140 = 0;
  DAT_003f9144 = 0;
  return;
}



// Initializes QSM: configures QSPI (SPI pins, clock), SCI1 (9600 baud for HC08 communication)

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



// Executes EEPROM read/write command via SPI

void eeprom_command(int param_1,int param_2,byte param_3)

{
  uint uVar1;
  ushort uVar2;
  uint uVar3;
  byte bVar4;
  
  uVar1 = (uint)(byte)(param_3 - 1);
  eeprom_cs_assert();
  REG_SPCR0 = 0xa005;
  REG_SPCR1 = 0x1a03;
  REG_SPCR2 = 0;
  REG_SPCR3 = 0;
  for (uVar3 = 0; (uVar3 & 0xff) < uVar1; uVar3 = uVar3 + 1) {
    (&REG_TRANRAM0)[uVar3 & 0xff] = (ushort)*(byte *)(param_1 + (uVar3 & 0xff));
    (&REG_COMDRAM0)[uVar3 & 0xff] = 0xbe;
  }
  (&REG_TRANRAM0)[uVar1] = (ushort)*(byte *)(param_1 + uVar1);
  (&REG_COMDRAM0)[uVar1] = 0x3e;
  uVar2 = REG_SPCR2;
  REG_SPCR2 = uVar2 & 0xffe0;
  uVar2 = REG_SPCR2;
  REG_SPCR2 = ((byte)(param_3 - 1) & 0x1f) << 8 | uVar2 & 0xe0ff;
  uVar2 = REG_SPCR1;
  REG_SPCR1 = uVar2 & 0x7fff | 0x8000;
  do {
    bVar4 = REG_SPSR;
  } while (-1 < (char)bVar4);
  bVar4 = REG_SPSR;
  REG_SPSR = bVar4 & 0x7f;
  for (bVar4 = 0; bVar4 < param_3; bVar4 = bVar4 + 1) {
    *(char *)(param_2 + (uint)bVar4) = (char)(&REG_RECRAM0)[bVar4];
  }
  eeprom_cs_deassert();
  return;
}



// Initializes TPU (calls init_tpu_b)

void init_tpu(void)

{
  init_tpu_b();
  return;
}



// Initializes TPU-B channel 14 for SPI chip select signal generation

void init_tpu_b(void)

{
  ushort uVar1;
  
  REG_TPUMCR2_B = 0;
  REG_TPUMCR3_B = 0x53;
  REG_CPR1_B = 0;
  REG_CPR0_B = 0;
  REG_CFSR3_B = 0;
  REG_CFSR2_B = 0;
  REG_CFSR1_B = 0;
  REG_CFSR0_B = 0;
  uVar1 = REG_CFSR0_B;
  REG_CFSR0_B = uVar1 & 0xf0ff | 0x200;
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
  uVar1 = REG_TICR_B;
  REG_TICR_B = uVar1 & 0xf8ff | 0x400;
  uVar1 = REG_TICR_B;
  REG_TICR_B = uVar1 & 0xff3f;
  uVar1 = REG_CISR_B;
  if (uVar1 != 0) {
    REG_CISR_B = 0;
  }
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



// Reads SPI EEPROM status register (command 0x05)

undefined1 eeprom_status(void)

{
  undefined1 uStack_8;
  undefined1 local_7;
  undefined1 local_6;
  undefined1 local_5;
  
  local_6 = 5;
  local_5 = 0;
  eeprom_command(&local_6,&uStack_8,2);
  return local_7;
}



// Sends SPI WREN command (0x06) to enable EEPROM write latch

void eeprom_write_enable(void)

{
  uint uVar1;
  undefined1 uStack_18;
  undefined1 local_17 [19];
  
  do {
    uVar1 = eeprom_status();
  } while ((uVar1 & 1) != 0);
  local_17[0] = 6;
  eeprom_command(local_17,&uStack_18,1);
  return;
}



// Reads single byte from SPI EEPROM at address (command 0x03)

undefined1 eeprom_read_byte(undefined4 param_1)

{
  uint uVar1;
  undefined1 auStack_18 [3];
  undefined1 local_15;
  undefined1 local_14;
  undefined1 local_13;
  undefined1 local_12;
  undefined1 local_11;
  
  do {
    uVar1 = eeprom_status();
  } while ((uVar1 & 1) != 0);
  local_14 = 3;
  local_13 = (undefined1)((uint)param_1 >> 8);
  local_12 = (undefined1)param_1;
  local_11 = 0;
  eeprom_command(&local_14,auStack_18,4);
  return local_15;
}



// Writes single byte to SPI EEPROM with write-enable and read-back verify (command 0x02)

bool eeprom_write_byte_checked(char param_1,undefined4 param_2)

{
  uint uVar1;
  char cVar2;
  undefined1 auStack_18 [4];
  undefined1 local_14;
  undefined1 local_13;
  undefined1 local_12;
  char local_11;
  
  do {
    uVar1 = eeprom_status();
  } while ((uVar1 & 1) != 0);
  eeprom_write_enable();
  local_14 = 2;
  local_13 = (undefined1)((uint)param_2 >> 8);
  local_12 = (undefined1)param_2;
  local_11 = param_1;
  eeprom_command(&local_14,auStack_18,4);
  cVar2 = eeprom_read_byte(param_2);
  return param_1 == cVar2;
}



// Writes buffer to SPI EEPROM byte-by-byte with watchdog retrigger and verify

undefined4 eeprom_write(uint param_1,int param_2,ushort param_3)

{
  ushort uVar1;
  char cVar2;
  uint uVar3;
  
  uVar1 = REG_PORTQS;
  REG_PORTQS = uVar1 & 0xfffb;
  uVar3 = param_1;
  while( true ) {
    if ((param_1 & 0xffff) + (uint)param_3 <= (uVar3 & 0xffff)) {
      uVar1 = REG_PORTQS;
      REG_PORTQS = uVar1 & 0xfffb | 4;
      return 1;
    }
    cVar2 = eeprom_write_byte_checked
                      (*(undefined1 *)(param_2 + ((uVar3 & 0xffff) - (param_1 & 0xffff))),uVar3);
    if (cVar2 == '\0') break;
    REG_SWSR = 0x556c;
    REG_SWSR = 0xaa39;
    uVar3 = uVar3 + 1;
  }
  return 0;
}



// Retriggers hardware watchdog timer (SWSR sequence 0x556C/0xAA39)

void watchdog_retrigger(void)

{
  REG_SWSR = 0x556c;
  REG_SWSR = 0xaa39;
  return;
}



// Saves current timebase counter value for delay measurement

void delay_start(void)

{
  DAT_003f915c = timer_read_tbl();
  return;
}



// Waits until specified number of timebase ticks have elapsed since delay_start

void delay_wait(uint param_1)

{
  int iVar1;
  
  do {
    iVar1 = timer_read_tbl();
  } while ((uint)(iVar1 - DAT_003f915c) <= param_1);
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
  
  uVar1 = REG_MPWMSM2_SCR;
  REG_MPWMSM2_SCR = uVar1 & 0xf7ff | 0x800;
  return;
}



// Sets MPIO bit 14 high: disables EEPROM write protection

void eeprom_wp_pin_disable(void)

{
  ushort uVar1;
  
  uVar1 = REG_MPIOSMDR;
  REG_MPIOSMDR = uVar1 & 0xbfff | 0x4000;
  return;
}



// Clears MPIO bit 14 low: enables EEPROM write protection

void eeprom_wp_pin_enable(void)

{
  ushort uVar1;
  
  uVar1 = REG_MPIOSMDR;
  REG_MPIOSMDR = uVar1 & 0xbfff;
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
  
  DAT_003f9158 = PTR_DAT_00021fec;
  init_mios();
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
  eeprom_wp_pin_enable();
  uVar2 = REG_MPIOSMDDR;
  REG_MPIOSMDDR = uVar2 | 0x4000;
  uVar2 = REG_MPWMSM2_SCR;
  REG_MPWMSM2_SCR = uVar2 & 0xff00 | 0xec;
  uVar2 = REG_MPWMSM2_SCR;
  REG_MPWMSM2_SCR = uVar2 & 0xefff;
  uVar2 = REG_MPWMSM2_SCR;
  REG_MPWMSM2_SCR = uVar2 & 0xbfff | 0x4000;
  hc08_mpwm_start();
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
  if (iVar1 == 0) {
    uVar2 = 0xffffffff;
  }
  else {
    timer_save(0);
    while (iVar1 = hc08_mdasm_read(), iVar1 != 0) {
      uVar2 = timer_elapsed(0);
      if (1000000 < uVar2) {
        return 0xffffffff;
      }
      REG_SWSR = 0x556c;
      REG_SWSR = 0xaa39;
    }
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
  }
  return uVar2;
}



// HC08 passphrase authentication: sends "EFI Srl " (0x45 0x46 0x49 0x20 0x53 0x72 0x6C 0x20) and
// verifies echo

undefined4 hc08_authenticate(void)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  int iVar15;
  int iVar16;
  int iVar17;
  
  if ((DAT_00021fe8 == -0x55555556) || (DAT_00021fe8 == -0x44444445)) {
    hc08_send_byte(DAT_000088a0);
    uVar1 = hc08_recv_byte();
    hc08_send_byte(DAT_000088a1);
    uVar2 = hc08_recv_byte();
    hc08_send_byte(DAT_000088a2);
    uVar3 = hc08_recv_byte();
    hc08_send_byte(DAT_000088a3);
    uVar4 = hc08_recv_byte();
    hc08_send_byte(DAT_000088a4);
    uVar5 = hc08_recv_byte();
    hc08_send_byte(DAT_000088a5);
    uVar6 = hc08_recv_byte();
    hc08_send_byte(DAT_000088a6);
    uVar7 = hc08_recv_byte();
    hc08_send_byte(DAT_000088a7);
    uVar8 = hc08_recv_byte();
    iVar9 = hc08_recv_byte();
    if ((((uVar1 == DAT_000088a0) &&
         ((((uVar2 == DAT_000088a1 && (uVar3 == DAT_000088a2)) && (uVar4 == DAT_000088a3)) &&
          ((uVar5 == DAT_000088a4 && (uVar6 == DAT_000088a5)))))) && (uVar7 == DAT_000088a6)) &&
       ((uVar8 == DAT_000088a7 && (iVar9 == 0x8000)))) {
      return 1;
    }
  }
  else if (DAT_00021fe8 == -0x5555ddde) {
    hc08_send_byte(0xff);
    iVar9 = hc08_recv_byte();
    hc08_send_byte(0xff);
    iVar10 = hc08_recv_byte();
    hc08_send_byte(0xff);
    iVar11 = hc08_recv_byte();
    hc08_send_byte(0xff);
    iVar12 = hc08_recv_byte();
    hc08_send_byte(0xff);
    iVar13 = hc08_recv_byte();
    hc08_send_byte(0xff);
    iVar14 = hc08_recv_byte();
    hc08_send_byte(0xff);
    iVar15 = hc08_recv_byte();
    hc08_send_byte(0xff);
    iVar16 = hc08_recv_byte();
    iVar17 = hc08_recv_byte();
    if (((((iVar9 == 0xff) && (iVar10 == 0xff)) && (iVar11 == 0xff)) &&
        (((iVar12 == 0xff && (iVar13 == 0xff)) &&
         ((iVar14 == 0xff && ((iVar15 == 0xff && (iVar16 == 0xff)))))))) && (iVar17 == 0x8000)) {
      return 1;
    }
  }
  return 0;
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



// Verifies HC08 flash contents at addresses 0xFFF6-0xFFFD match expected values

undefined4 hc08_verify_flash(void)

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
    if (DAT_00021fe8 == -0x55555556) {
      if (local_18[0] != *(char *)(((uint)puVar2 & 0xffff) - 0x7756)) {
        return 0;
      }
    }
    else if ((DAT_00021fe8 == -0x5555ddde) && (local_18[0] != -1)) {
      return 0;
    }
    puVar2 = puVar2 + 1;
  }
  return 0;
}



// Verifies HC08 flash write by reading back first byte and comparing remaining words

undefined4 hc08_verify_write(undefined2 param_1,undefined4 param_2,byte param_3)

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
      iVar2 = memcmp(auStack_4e,param_2,param_3);
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



// Full HC08 programming sequence: init hardware, authenticate, verify/erase, program flash blocks,
// write markers

undefined4 hc08_program_sequence(void)

{
  int iVar1;
  undefined *puVar2;
  
  watchdog_retrigger();
  hc08_init();
  watchdog_retrigger();
  efip_send_hc08_start(5000);
  delay_blocking(600000);
  eeprom_wp_pin_disable();
  delay_blocking(600000);
  iVar1 = hc08_authenticate_retry();
  if (iVar1 == 0) {
    for (iVar1 = 0; iVar1 < 10000; iVar1 = iVar1 + 1) {
      REG_SWSR = 0x556c;
      REG_SWSR = 0xaa39;
    }
    efip_send_error_hc08(0x90);
    do {
      watchdog_retrigger();
    } while( true );
  }
  if (DAT_00021fe8 == -0x44444445) {
    iVar1 = hc08_mass_erase_retry();
    if (iVar1 != 0) {
      efip_send_hc08_erase_info(0);
      for (iVar1 = 0; iVar1 < 10000; iVar1 = iVar1 + 1) {
        REG_SWSR = 0x556c;
        REG_SWSR = 0xaa39;
      }
      efip_send_hc08_result(0);
      do {
        watchdog_retrigger();
      } while( true );
    }
    efip_send_error_hc08(0x91);
    do {
      watchdog_retrigger();
    } while( true );
  }
  iVar1 = hc08_verify_flash();
  if (iVar1 == 0) {
    iVar1 = hc08_mass_erase_retry();
    if (iVar1 != 0) {
      efip_send_hc08_erase_info(30000);
      flash_write_update_marker_2();
      for (iVar1 = 0; iVar1 < 10000; iVar1 = iVar1 + 1) {
        REG_SWSR = 0x556c;
        REG_SWSR = 0xaa39;
      }
      efip_send_hc08_result(3000);
      do {
        watchdog_retrigger();
      } while( true );
    }
    efip_send_error_hc08(0x91);
    do {
      watchdog_retrigger();
    } while( true );
  }
  iVar1 = hc08_mass_erase_retry();
  if (iVar1 == 0) {
    efip_send_error_hc08(0x91);
    do {
      watchdog_retrigger();
    } while( true );
  }
  efip_send_hc08_erase_info(30000);
  for (puVar2 = &DAT_0000dc00; (int)puVar2 < 0xfc00; puVar2 = puVar2 + 0x40) {
    watchdog_retrigger();
    iVar1 = hc08_program_flash_retry((uint)puVar2 & 0xffff,puVar2 + DAT_003f9158 + -0xdc00,0x40);
    if (iVar1 == 0) {
      watchdog_retrigger();
      efip_send_error_hc08(0x92);
      do {
        watchdog_retrigger();
      } while( true );
    }
  }
  watchdog_retrigger();
  iVar1 = hc08_program_flash_retry(&DAT_0000ffdc,DAT_003f9158 + 0x23dc,0x24);
  if (iVar1 == 0) {
    watchdog_retrigger();
    efip_send_error_hc08(0x92);
    do {
      watchdog_retrigger();
    } while( true );
  }
  flash_write_update_marker();
  efip_send_hc08_result(0);
  return 1;
}



// Enables timebase timer (duplicate of timer_enable_timebase)

void timer_enable_timebase_2(void)

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
  *(undefined4 *)(&DAT_003f9180 + (uint)param_1 * 4) = uVar1;
  return;
}



// Returns elapsed time since timer_save for indexed timer slot

int timer_elapsed(ushort param_1)

{
  int iVar1;
  
  iVar1 = timer_read_tbl();
  return iVar1 - *(int *)(&DAT_003f9180 + (uint)param_1 * 4);
}



// Reads PowerPC Time Base Lower register (TBL)

undefined4 timer_read_tbl(void)

{
  undefined4 uVar1;
  
  uVar1 = TBLr;
  return uVar1;
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



// Walks CRT cleanup linked list of destructor callbacks

void cleanup_callbacks(void)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  
  while (DAT_003f9160 != (int *)0x0) {
    puVar1 = DAT_003f9160 + 1;
    puVar2 = DAT_003f9160 + 2;
    DAT_003f9160 = (int *)*DAT_003f9160;
    (*(code *)*puVar1)(*puVar2,0xffffffff);
  }
  return;
}



// CRT exit() implementation: runs atexit callbacks, cleanup list, then calls atexit_handlers

void exit(undefined4 param_1)

{
  undefined **ppuVar1;
  
  if (DAT_003f9168 == 0) {
    while (0 < DAT_003f9178) {
      DAT_003f9178 = DAT_003f9178 + -1;
      (**(code **)(&DAT_003f9190 + DAT_003f9178 * 4))();
    }
    cleanup_callbacks();
    for (ppuVar1 = &PTR_cleanup_callbacks_000088a8; (code *)*ppuVar1 != (code *)0x0;
        ppuVar1 = ppuVar1 + 1) {
      (*(code *)*ppuVar1)();
    }
    if (DAT_003f916c != (code *)0x0) {
      (*DAT_003f916c)();
      DAT_003f916c = (code *)0x0;
    }
  }
  atexit_handlers(param_1);
  return;
}



// Executes registered atexit handler functions

void atexit_handlers(void)

{
  while (0 < DAT_003f917c) {
    DAT_003f917c = DAT_003f917c + -1;
    (**(code **)(&DAT_003f9290 + DAT_003f917c * 4))();
  }
  if (DAT_003f9170 != (code *)0x0) {
    (*DAT_003f9170)();
    DAT_003f9170 = (code *)0x0;
  }
  dead_end();
  return;
}



// Compares two memory blocks, returns -1/0/1 at first mismatch

undefined4 memcmp(int param_1,int param_2,int param_3)

{
  byte *pbVar1;
  byte *pbVar2;
  
  pbVar1 = (byte *)(param_1 + -1);
  pbVar2 = (byte *)(param_2 + -1);
  param_3 = param_3 + 1;
  do {
    param_3 = param_3 + -1;
    if (param_3 == 0) {
      return 0;
    }
    pbVar1 = pbVar1 + 1;
    pbVar2 = pbVar2 + 1;
  } while (*pbVar1 == *pbVar2);
  if (*pbVar2 <= *pbVar1) {
    return 1;
  }
  return 0xffffffff;
}



// Compares two strings up to N bytes, returns byte difference at first mismatch or 0 at null
// terminator

int strncmp(int param_1,int param_2,int param_3)

{
  uint uVar1;
  byte *pbVar2;
  byte *pbVar3;
  
  pbVar2 = (byte *)(param_1 + -1);
  pbVar3 = (byte *)(param_2 + -1);
  param_3 = param_3 + 1;
  while( true ) {
    param_3 = param_3 + -1;
    if (param_3 == 0) {
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



// CAN-A MB15 receive handler: reads frames from ID 0x50/0x51, copies data to rx buffer, updates
// running CRC8

void can_a_mb15_recv(void)

{
  byte bVar1;
  ushort uVar2;
  int iVar3;
  int iVar4;
  uint8_t *puVar5;
  byte *pbVar6;
  ushort uVar7;
  
  uVar2 = REG_IFLAG_A;
  if ((uVar2 & 0x8000) != 0) {
    uVar2 = REG_IFLAG_A;
    REG_IFLAG_A = uVar2 & 0x7fff;
    uVar2 = REG_CANA_MB15_CS;
    while ((uVar2 & 0x10) != 0) {
      uVar2 = REG_CANA_MB15_CS;
    }
    uVar2 = REG_CANA_MB15_CS;
    if ((uVar2 & 0x60) == 0x60) {
      REG_CANA_MB15_CS = 0x40;
      uVar2 = REG_TIMER_A;
    }
    else {
      uVar2 = REG_CANA_MB15_CS;
      if ((uVar2 & 0x20) != 0) {
        pbVar6 = &REG_CANA_MB15_DATA0;
        uVar2 = REG_CANA_MB15_ID_HI;
        if (((int)(uint)uVar2 >> 5 == 0x51) || ((int)(uint)uVar2 >> 5 == 0x50)) {
          uVar2 = REG_CANA_MB15_CS;
          iVar3 = (int)(short)rx_buffer_write_i;
          for (uVar7 = 0; (uVar7 & 0xff) < (uVar2 & 0xf); uVar7 = uVar7 + 1) {
            if ((short)rx_buffer_write_i < 0x400) {
              bVar1 = *pbVar6;
              pbVar6 = pbVar6 + 1;
              iVar4 = (int)(short)rx_buffer_write_i;
              rx_buffer_write_i = rx_buffer_write_i + 1;
              rx_buffer[iVar4] = bVar1;
            }
            else {
              rx_buffer_write_i = 1025;
            }
          }
          REG_CANA_MB15_CS = 0x40;
          puVar5 = rx_buffer + iVar3;
          for (uVar7 = 0; (uVar7 & 0xff) < (uVar2 & 0xf); uVar7 = uVar7 + 1) {
            crc8_update(puVar5);
            puVar5 = puVar5 + 1;
          }
          efip_set_can_rx_timeout(&DAT_000249f0);
        }
        else {
          REG_CANA_MB15_CS = 0x40;
          uVar2 = REG_TIMER_A;
        }
      }
    }
  }
  return;
}



// Updates running CRC8 with one byte, stores previous CRC for validatio

void crc8_update(byte *param_1)

{
  efip_crc = DAT_003f9108;
  DAT_003f9108 = CRC8_lookup_ram[*param_1 ^ DAT_003f9108];
  return;
}



// Sets CAN rx timeout deadline for frame reception

void efip_set_can_rx_timeout(undefined4 param_1)

{
  timer_set_can_rx_timeout(param_1);
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
      while (uVar4 = REG_UC3FCTL, (int)uVar4 < 0) {
        can_a_mb15_recv();
      }
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



// Programs N words (32-bit) to flash via UC3F controller, verifies after write

undefined4 flash_program_words(int *param_1,int *param_2,int param_3)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  int *piVar5;
  int iVar6;
  
  uVar2 = REG_UC3FCTL;
  if (((uVar2 >> 0x1c & 1) == 1) && (uVar2 = REG_UC3FCTL, (uVar2 >> 0x1b & 1) == 1)) {
    uVar2 = REG_UC3FMCR;
    REG_UC3FMCR = uVar2 & 0xffffff00;
    uVar2 = REG_UC3FMCRE;
    REG_UC3FMCRE = uVar2 & 0xfcffffff;
    uVar2 = REG_UC3FMCRE;
    REG_UC3FMCRE = uVar2 & 0x3fffffff | 0xc0000000;
    uVar2 = REG_UC3FCTL;
    REG_UC3FCTL = uVar2 & 0xfffcffff | 0x30000;
    uVar2 = REG_UC3FCTL;
    REG_UC3FCTL = uVar2 & 0xffff00ff | 0xff00;
    uVar2 = REG_UC3FCTL;
    REG_UC3FCTL = uVar2 & 0xfffffffd;
    uVar2 = REG_UC3FCTL;
    REG_UC3FCTL = uVar2 & 0xfffffffb;
    uVar2 = REG_UC3FCTL;
    REG_UC3FCTL = uVar2 & 0xfffffffd | 2;
    piVar4 = param_2;
    piVar5 = param_1;
    iVar6 = param_3;
    while (bVar1 = iVar6 != 0, iVar6 = iVar6 + -1, bVar1) {
      iVar3 = *piVar4;
      piVar4 = piVar4 + 1;
      *piVar5 = iVar3;
      piVar5 = piVar5 + 1;
      uVar2 = REG_UC3FCTL;
      REG_UC3FCTL = uVar2 & 0xfffffffe | 1;
      while (uVar2 = REG_UC3FCTL, (int)uVar2 < 0) {
        can_a_mb15_recv();
      }
      do {
        uVar2 = REG_UC3FCTL;
      } while ((uVar2 >> 0x1e & 1) == 0);
      uVar2 = REG_UC3FCTL;
      REG_UC3FCTL = uVar2 & 0xfffffffe;
    }
    uVar2 = REG_UC3FCTL;
    REG_UC3FCTL = uVar2 & 0xfffffffd;
    uVar2 = REG_UC3FCTL;
    REG_UC3FCTL = uVar2 & 0xffff00ff;
    uVar2 = REG_UC3FCTL;
    REG_UC3FCTL = uVar2 & 0xfffcffff;
    do {
      bVar1 = param_3 == 0;
      param_3 = param_3 + -1;
      if (bVar1) {
        return 1;
      }
      iVar3 = *param_1;
      param_1 = param_1 + 1;
      iVar6 = *param_2;
      param_2 = param_2 + 1;
    } while (iVar3 == iVar6);
  }
  return 0;
}



// Reads PowerPC Time Base Lower register (duplicate of timer_read_tbl)

undefined4 timer_read_tbl_2(void)

{
  undefined4 uVar1;
  
  uVar1 = TBLr;
  return uVar1;
}



// Sets CAN rx timeout deadline from current time plus offset

void timer_set_can_rx_timeout(int param_1)

{
  int iVar1;
  
  iVar1 = timer_read_tbl_2();
  DAT_003f913c = param_1 + iVar1;
  return;
}



// CAN-A MB15 receive handler: reads frames from ID 0x50/0x51, copies data to rx buffer, updates
// running CRC8 (RAM copy)

void can_a_mb15_recv_ram(void)

{
  byte bVar1;
  ushort uVar2;
  int iVar3;
  int iVar4;
  uint8_t *puVar5;
  byte *pbVar6;
  ushort uVar7;
  
  uVar2 = REG_IFLAG_A;
  if ((uVar2 & 0x8000) != 0) {
    uVar2 = REG_IFLAG_A;
    REG_IFLAG_A = uVar2 & 0x7fff;
    uVar2 = REG_CANA_MB15_CS;
    while ((uVar2 & 0x10) != 0) {
      uVar2 = REG_CANA_MB15_CS;
    }
    uVar2 = REG_CANA_MB15_CS;
    if ((uVar2 & 0x60) == 0x60) {
      REG_CANA_MB15_CS = 0x40;
      uVar2 = REG_TIMER_A;
    }
    else {
      uVar2 = REG_CANA_MB15_CS;
      if ((uVar2 & 0x20) != 0) {
        pbVar6 = &REG_CANA_MB15_DATA0;
        uVar2 = REG_CANA_MB15_ID_HI;
        if (((int)(uint)uVar2 >> 5 == 0x51) || ((int)(uint)uVar2 >> 5 == 0x50)) {
          uVar2 = REG_CANA_MB15_CS;
          iVar3 = (int)(short)rx_buffer_write_i;
          for (uVar7 = 0; (uVar7 & 0xff) < (uVar2 & 0xf); uVar7 = uVar7 + 1) {
            if ((short)rx_buffer_write_i < 0x400) {
              bVar1 = *pbVar6;
              pbVar6 = pbVar6 + 1;
              iVar4 = (int)(short)rx_buffer_write_i;
              rx_buffer_write_i = rx_buffer_write_i + 1;
              rx_buffer[iVar4] = bVar1;
            }
            else {
              rx_buffer_write_i = 1025;
            }
          }
          REG_CANA_MB15_CS = 0x40;
          puVar5 = rx_buffer + iVar3;
          for (uVar7 = 0; (uVar7 & 0xff) < (uVar2 & 0xf); uVar7 = uVar7 + 1) {
            crc8_update_ram(puVar5);
            puVar5 = puVar5 + 1;
          }
          efip_set_can_rx_timeout_ram(&DAT_000249f0);
        }
        else {
          REG_CANA_MB15_CS = 0x40;
          uVar2 = REG_TIMER_A;
        }
      }
    }
  }
  return;
}



// Updates running CRC8 with one byte, stores previous CRC for validation (RAM copy)

void crc8_update_ram(byte *param_1)

{
  efip_crc = DAT_003f9108;
  DAT_003f9108 = CRC8_lookup_ram[*param_1 ^ DAT_003f9108];
  return;
}



// Sets CAN rx timeout deadline for frame reception (RAM copy)

void efip_set_can_rx_timeout_ram(undefined4 param_1)

{
  timer_set_can_rx_timeout_ram(param_1);
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
      while (uVar4 = REG_UC3FCTL, (int)uVar4 < 0) {
        can_a_mb15_recv_ram();
      }
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



// Programs N words (32-bit) to flash via UC3F controller, verifies after write (RAM copy)

undefined4 flash_program_words_ram(int *param_1,int *param_2,int param_3)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  int *piVar5;
  int iVar6;
  
  uVar2 = REG_UC3FCTL;
  if (((uVar2 >> 0x1c & 1) == 1) && (uVar2 = REG_UC3FCTL, (uVar2 >> 0x1b & 1) == 1)) {
    uVar2 = REG_UC3FMCR;
    REG_UC3FMCR = uVar2 & 0xffffff00;
    uVar2 = REG_UC3FMCRE;
    REG_UC3FMCRE = uVar2 & 0xfcffffff;
    uVar2 = REG_UC3FMCRE;
    REG_UC3FMCRE = uVar2 & 0x3fffffff | 0xc0000000;
    uVar2 = REG_UC3FCTL;
    REG_UC3FCTL = uVar2 & 0xfffcffff | 0x30000;
    uVar2 = REG_UC3FCTL;
    REG_UC3FCTL = uVar2 & 0xffff00ff | 0xff00;
    uVar2 = REG_UC3FCTL;
    REG_UC3FCTL = uVar2 & 0xfffffffd;
    uVar2 = REG_UC3FCTL;
    REG_UC3FCTL = uVar2 & 0xfffffffb;
    uVar2 = REG_UC3FCTL;
    REG_UC3FCTL = uVar2 & 0xfffffffd | 2;
    piVar4 = param_2;
    piVar5 = param_1;
    iVar6 = param_3;
    while (bVar1 = iVar6 != 0, iVar6 = iVar6 + -1, bVar1) {
      iVar3 = *piVar4;
      piVar4 = piVar4 + 1;
      *piVar5 = iVar3;
      piVar5 = piVar5 + 1;
      uVar2 = REG_UC3FCTL;
      REG_UC3FCTL = uVar2 & 0xfffffffe | 1;
      while (uVar2 = REG_UC3FCTL, (int)uVar2 < 0) {
        can_a_mb15_recv_ram();
      }
      do {
        uVar2 = REG_UC3FCTL;
      } while ((uVar2 >> 0x1e & 1) == 0);
      uVar2 = REG_UC3FCTL;
      REG_UC3FCTL = uVar2 & 0xfffffffe;
    }
    uVar2 = REG_UC3FCTL;
    REG_UC3FCTL = uVar2 & 0xfffffffd;
    uVar2 = REG_UC3FCTL;
    REG_UC3FCTL = uVar2 & 0xffff00ff;
    uVar2 = REG_UC3FCTL;
    REG_UC3FCTL = uVar2 & 0xfffcffff;
    do {
      bVar1 = param_3 == 0;
      param_3 = param_3 + -1;
      if (bVar1) {
        return 1;
      }
      iVar3 = *param_1;
      param_1 = param_1 + 1;
      iVar6 = *param_2;
      param_2 = param_2 + 1;
    } while (iVar3 == iVar6);
  }
  return 0;
}



// Reads PowerPC Time Base Lower register (duplicate of timer_read_tbl, RAM copy)

undefined4 timer_read_tbl_2_ram(void)

{
  undefined4 uVar1;
  
  uVar1 = TBLr;
  return uVar1;
}



// Sets CAN rx timeout deadline from current time plus offset (RAM copy)

void timer_set_can_rx_timeout_ram(int param_1)

{
  int iVar1;
  
  iVar1 = timer_read_tbl_2_ram();
  DAT_003f913c = param_1 + iVar1;
  return;
}


