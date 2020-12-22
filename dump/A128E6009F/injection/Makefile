AS=powerpc-linux-gnu-as
LD=powerpc-linux-gnu-ld

%.o: %.S
	$(AS) -a32 -be -o $@ $^

all: fakerpm.bin

fakerpm.bin: fakerpm.o
	$(LD) -Ttext 0 --oformat binary -o $@ $^

