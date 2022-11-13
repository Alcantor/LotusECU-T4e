AS=powerpc-linux-gnu-as
LD=powerpc-linux-gnu-ld

all: canstrap-white.bin canstrap-black.bin plugin_flash.bin plugin_eeprom.bin func_eeprom_init.bin plugin_crc.bin func_test.bin

%.o: %.S
	$(AS) -a32 -be -o $@ $^

%.bin: %.o
	$(LD) -Ttext 0 --oformat binary -o $@ $^

%-black.S: %-white.S
	sed 's/^\(.*White Version\)/#\1/g;s/^#\(.*Black Version\)/\1/g' $^ > $@

clean:
	rm -f *.o *.bin

