AS=powerpc-linux-gnu-as
LD=powerpc-linux-gnu-ld
OC=powerpc-linux-gnu-objcopy

NAME=patch
SRCS=hook.S cal.S
ASFLAGS=-a32 -be
ifeq ($(OBD_KLINE), y)
  SRCS+=obd_kline.S
else
  SRCS+=obd_can.S
endif
ifeq ($(ACCUSUMP), y)
	SRCS+=../accusump/accusump.S
	ASFLAGS+=--defsym ACCUSUMP=1
endif
ifeq ($(FLEXFUEL), y)
	SRCS+=../flexfuel/hook.S ../flexfuel/flexfuel.S
	ASFLAGS+=--defsym FLEXFUEL=1
endif
ifeq ($(OBDOIL), y)
	SRCS+=../obdoil/obdoil.S
	ASFLAGS+=--defsym OBDOIL=1
endif
ifeq ($(WIDEBAND), y)
	SRCS+=../wideband/wideband.S
	ASFLAGS+=--defsym WIDEBAND=1
endif
OBJS=$(SRCS:.S=.o)

all: $(NAME).text.bin $(NAME).data.bin

%.o: %.S
	$(AS) ${ASFLAGS} -o $@ $<

%.elf: $(OBJS)
	$(LD) -e 0 -Map map.txt -Tdata $(CAL) -Ttext $(ROM) -Tbss $(RAM) --just-symbols=$(SYM) -o $@ $^

%.text.bin: %.elf
	$(OC) -O binary --only-section .text $< $@

%.data.bin: %.elf
	$(OC) -O binary --only-section .data $< $@

clean:
	rm -f map.txt $(NAME).text.bin $(NAME).data.bin

