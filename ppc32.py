#!/usr/bin/python3

class PPC32:
	def __buildb(opcode, li, aa, lk):
		r  = opcode << 26
		r |= li     << 2
		r |= aa     << 1
		r |= lk
		return r.to_bytes(4, "big")
		
	def __build2i(opcode, op1, op2, imm):
		r  = opcode << 26
		r |= op1    << 21
		r |= op2    << 16
		r |= imm
		return r.to_bytes(4, "big")
		
	def __build3(opcode, op1, op2, op3, const):
		r  = opcode << 26
		r |= op1    << 21
		r |= op2    << 16
		r |= op3    << 11
		r |= const  <<  1
		return r.to_bytes(4, "big")

	def ppc_cmpli(rA, imm):
		return PPC32.__build2i(10, 0, rA, imm)

	def ppc_ba(addr):
		return PPC32.__buildb(18, addr >> 2, 1, 0)

	def ppc_rfi():
		return PPC32.__build3(19, 0, 0, 0, 50)

	def ppc_and(rD, rA, rB):
		return PPC32.__build3(31, rD, rA, rB, 28)

	def ppc_mfspr(rD, spr):
		return PPC32.__build3(31, rD, spr & 0x1F, spr >> 5, 339)

	def ppc_mtspr(rS, spr):
		return PPC32.__build3(31, rS, spr & 0x1F, spr >> 5, 467)

	def ppc_lwz(rD, rA, delta):
		return PPC32.__build2i(32, rD, rA, delta)

	def ppc_stw(rS, rA, delta):
		return PPC32.__build2i(36, rS, rA, delta)

def print_hex(array):
	return ' '.join('{:02x}'.format(x) for x in array)

if __name__ == "__main__":
	print("Small PPC32 library... Make some tests:\n")

	print("cmplwi %r2,30       "+print_hex(PPC32.ppc_cmpli(2, 0x30)))
	print("ba     0x3DC400     "+print_hex(PPC32.ppc_ba(0x3DC400)))
	print("mfspr  %r30,630     "+print_hex(PPC32.ppc_mfspr(30, 630)))
	print("mtspr  27,%r31      "+print_hex(PPC32.ppc_mtspr(31, 27)))
	print("lwz    %r31,0(%r30) "+print_hex(PPC32.ppc_lwz(31, 30, 0)))
	print("stw    %r31,0(%r30) "+print_hex(PPC32.ppc_stw(31, 30, 0)))
	print("and    %r0,%r0,%r0  "+print_hex(PPC32.ppc_and(0, 0, 0)))
	print("rfi                 "+print_hex(PPC32.ppc_rfi()))

