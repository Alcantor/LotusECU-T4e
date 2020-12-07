AS=powerpc-linux-gnu-as
LD=powerpc-linux-gnu-ld

%.o: %.S
	$(AS) -a32 -be -o $@ $^
     
deadloop.bin: deadloop.o
	$(LD) -Ttext 0 --oformat binary -o $@ $^
