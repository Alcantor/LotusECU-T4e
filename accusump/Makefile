AS=powerpc-linux-gnu-as
LD=powerpc-linux-gnu-ld

all: accusump.bin

%.o: %.S
	$(AS) -a32 -be -o $@ $^

%.bin: %.o
	$(LD) -Ttext 0 --oformat binary -o $@ $^

clean:
	rm -f accusump.bin

