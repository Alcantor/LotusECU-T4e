AS=powerpc-linux-gnu-as
LD=powerpc-linux-gnu-ld
OC=powerpc-linux-gnu-objcopy
OD=powerpc-linux-gnu-objdump

NAME=patch
SRCS=hook.S cal.S
ASFLAGS=-a32 -be
DEFS=defs.inc
ifeq ($(OBD_KLINE), y)
  SRCS+=obd_kline.S
else
  SRCS+=obd_can.S
endif
ifeq ($(ACCUSUMP), y)
	SRCS+=../accusump/accusump.S
	ASFLAGS+=--defsym ACCUSUMP=1
	DEFS+=../accusump/defs.inc
endif
ifeq ($(FLEXFUEL), y)
	SRCS+=../flexfuel/hook.S ../flexfuel/flexfuel.S
	ASFLAGS+=--defsym FLEXFUEL=1
	DEFS+=../flexfuel/defs.inc
endif
ifeq ($(OBDOIL), y)
	SRCS+=../obdoil/obdoil.S
	ASFLAGS+=--defsym OBDOIL=1
	DEFS+=../obdoil/defs.inc
endif
ifeq ($(WIDEBAND), y)
	SRCS+=../wideband/wideband.S
	ASFLAGS+=--defsym WIDEBAND=1
endif
OBJS=$(SRCS:.S=.o)

all: $(NAME).text.bin $(NAME).data.bin $(NAME).txt $(NAME)_defs.xml

%.o: %.S
	$(AS) ${ASFLAGS} -o $@ $<

%.elf: $(OBJS)
	$(LD) -e 0 -Tdata $(CAL) -Ttext $(ROM) -Tbss $(RAM) -T $(SYM) -o $@ $^

%.text.bin: %.elf
	$(OC) -O binary --only-section .text $< $@

%.data.bin: %.elf
	$(OC) -O binary --only-section .data $< $@

%.txt: %.elf
	$(OD) -x $< > $@

%_defs.xml: %.txt $(DEFS)
	gawk -v base=0x10000 -f gen_defs.awk $< $(DEFS) > $@

clean:
	rm -f $(NAME).text.bin $(NAME).data.bin $(NAME).txt $(NAME)_defs.xml

