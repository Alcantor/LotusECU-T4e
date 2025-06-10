AS=powerpc-linux-gnu-as
LD=powerpc-linux-gnu-ld
OC=powerpc-linux-gnu-objcopy
OD=powerpc-linux-gnu-objdump

NAME=patch
SRCS=hook.S cal.S obd_can.S
ASFLAGS=-a32 -be
ifeq ($(FLEXFUEL), y)
	SRCS+=../flexfuel/flexfuel.S
	ASFLAGS+=--defsym FLEXFUEL=1
endif
ifeq ($(WIDEBAND), y)
	SRCS+=../wideband/wideband.S
	ASFLAGS+=--defsym WIDEBAND=1
endif
OBJS=$(SRCS:.S=.o)

all: $(NAME).text.bin $(NAME).data.bin $(NAME).txt

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

clean:
	rm -f $(NAME).text.bin $(NAME).data.bin $(NAME).txt

