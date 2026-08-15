AS=powerpc-linux-gnu-as
LD=powerpc-linux-gnu-ld
OC=powerpc-linux-gnu-objcopy
OD=powerpc-linux-gnu-objdump

all: flexfuel.text.bin flexfuel.data.bin flexfuel.txt

%.o: %.S
	$(AS) -a32 -be -o $@ $<

%.elf: %.o
	$(LD) -e 0 -Tdata $(CAL) -Ttext $(ROM) -Tbss $(RAM) -T $(SYM) -o $@ $^

%.text.bin: %.elf
	$(OC) -O binary --only-section .text $< $@

%.data.bin: %.elf
	$(OC) -O binary --only-section .data $< $@

%.txt: %.elf
	$(OD) -x $< > $@

clean:
	rm -f flexfuel.text.bin flexfuel.data.bin flexfuel.txt

