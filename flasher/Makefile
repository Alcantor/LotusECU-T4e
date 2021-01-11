AS=powerpc-linux-gnu-as
LD=powerpc-linux-gnu-ld

all: canstrap.bin plugin_flash.bin plugin_eeprom.bin func_eeprom_init.bin func_test.bin

%.o: %.S
	$(AS) -a32 -be -o $@ $^

%.bin: %.o
	$(LD) -Ttext 0 --oformat binary -o $@ $^

clean:
	rm -f *.o *.bin

