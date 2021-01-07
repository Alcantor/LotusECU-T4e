AS=powerpc-linux-gnu-as
LD=powerpc-linux-gnu-ld

%.o: %.S
	$(AS) -a32 -be -o $@ $^

all: flasher.bin deadloop.bin

flasher.bin: flasher.o
	$(LD) -Ttext 0 --oformat binary -o $@ $^
     
deadloop.bin: deadloop.o
	$(LD) -Ttext 0 --oformat binary -o $@ $^

