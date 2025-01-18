AS=powerpc-linux-gnu-as
LD=powerpc-linux-gnu-ld
OC=powerpc-linux-gnu-objcopy

all: obdoil.text.bin obdoil.data.bin

%.o: %.S
	$(AS) -a32 -be -o $@ $^

%.elf: %.o
	$(LD) -Map map.txt -Tdata $(CAL) -Ttext $(ROM) -Tbss $(RAM) --just-symbols=$(SYM) -o $@ $^

%.text.bin: %.elf
	$(OC) -O binary --only-section .text $^ $@

%.data.bin: %.elf
	$(OC) -O binary --only-section .data $^ $@

clean:
	rm -f map.txt obdoil.elf obdoil.text.bin obdoil.data.bin
