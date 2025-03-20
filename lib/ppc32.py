# Some constants
BO_BE = 'big'

class PPC32:
	def __verify_addr(addr):
		if(addr % 4 != 0):
			raise Exception("Jump address is not 4-byte aligned!")

	def __build1(opcd, li, aa, lk):
		li &= 0xFFFFFF
		return (opcd<<26|li<<2|aa<<1|lk).to_bytes(4,BO_BE)

	def __build2(opcd, bo, bi, bd, aa, lk):
		bd &= 0x3FFF
		return (opcd<<26|bo<<21|bi<<16|bd<<2|aa<<1|lk).to_bytes(4,BO_BE)

	def __build3(opcd, rSD, rA, imm):
		imm &= 0xFFFF
		return (opcd<<26|rSD<<21|rA<<16|imm).to_bytes(4,BO_BE)

	def __build4(opcd, rSD, rA, rB, xo):
		return (opcd<<26|rSD<<21|rA<<16|rB<<11|xo<<1).to_bytes(4,BO_BE)

	def __build5(opcd, rSD, rA, SH, MB, ME):
		return (opcd<<26|rSD<<21|rA<<16|SH<<11|MB<<6|ME<<1).to_bytes(4,BO_BE)

	def ppc_cmpli(rA, uimm):
		return PPC32.__build3(10, 0, rA, uimm)

	def ppc_addi(rD, rA, simm):
		return PPC32.__build3(14, rD, rA, simm)

	def ppc_li(rD, simm):
		return PPC32.ppc_addi(rD, 0, simm)

	def ppc_addis(rD, rA, simm):
		return PPC32.__build3(15, rD, rA, simm)

	def ppc_lis(rD, simm):
		return PPC32.ppc_addis(rD, 0, simm)

	def ppc_ble(addr):
		PPC32.__verify_addr(addr)
		return PPC32.__build2(16, 4, 1, addr >> 2, 0, 0)

	def ppc_b(addr):
		PPC32.__verify_addr(addr)
		return PPC32.__build1(18, addr >> 2, 0, 0)

	def ppc_bl(addr):
		PPC32.__verify_addr(addr)
		return PPC32.__build1(18, addr >> 2, 0, 1)

	def ppc_ba(addr):
		PPC32.__verify_addr(addr)
		return PPC32.__build1(18, addr >> 2, 1, 0)

	def ppc_bla(addr):
		PPC32.__verify_addr(addr)
		return PPC32.__build1(18, addr >> 2, 1, 1)

	def ppc_blr():
		return PPC32.__build4(19, 20, 0, 0, 16)

	def ppc_rfi():
		return PPC32.__build4(19, 0, 0, 0, 50)

	def ppc_rlwinm(rA, rS, SH, MB, ME):
		return PPC32.__build5(21, rS, rA, SH, MB, ME)

	def ppc_ori(rA, rS, uimm):
		return PPC32.__build3(24, rS, rA, uimm)

	def ppc_and(rA, rS, rB):
		return PPC32.__build4(31, rS, rA, rB, 28)

	def ppc_add(rD, rA, rB):
		return PPC32.__build4(31, rD, rA, rB, 266)

	def ppc_or(rA, rS, rB):
		return PPC32.__build4(31, rS, rA, rB, 444)

	def ppc_mfspr(rD, spr):
		return PPC32.__build4(31, rD, spr & 0x1F, spr >> 5, 339)

	def ppc_mtspr(rS, spr):
		return PPC32.__build4(31, rS, spr & 0x1F, spr >> 5, 467)

	def ppc_lwz(rD, rA, delta):
		return PPC32.__build3(32, rD, rA, delta)

	def ppc_lbz(rD, rA, delta):
		return PPC32.__build3(34, rD, rA, delta)

	def ppc_stw(rS, rA, delta):
		return PPC32.__build3(36, rS, rA, delta)

	def ppc_stb(rS, rA, delta):
		return PPC32.__build3(38, rS, rA, delta)

	def ppc_lhz(rD, rA, delta):
		return PPC32.__build3(40, rD, rA, delta)

	def ppc_sth(rS, rA, delta):
		return PPC32.__build3(44, rS, rA, delta)

def print_hex(array):
	return ' '.join('{:02x}'.format(x) for x in array)

if __name__ == "__main__":
	print("Small PPC32 library... Make some tests:\n")

	print("cmplwi %r2,30         " + print_hex(PPC32.ppc_cmpli(2, 30)))
	print("addi   %r3,%r2,10     " + print_hex(PPC32.ppc_addi(3, 2, 10)))
	print("li     %r3,1          " + print_hex(PPC32.ppc_li(3, 1)))
	print("addis  %r3,%r2,10     " + print_hex(PPC32.ppc_addis(3, 2, 10)))
	print("lis    %r3,1          " + print_hex(PPC32.ppc_lis(3, 1)))
	print("ble    -0x50          " + print_hex(PPC32.ppc_ble(-0x50)))
	print("b      -0x128         " + print_hex(PPC32.ppc_b(-0x128)))
	print("bl     0x100          " + print_hex(PPC32.ppc_bl(0x100)))
	print("ba     0x3DC400       " + print_hex(PPC32.ppc_ba(0x3DC400)))
	print("bla    0x200          " + print_hex(PPC32.ppc_bla(0x200)))
	print("blr                   " + print_hex(PPC32.ppc_blr()))
	print("rfi                   " + print_hex(PPC32.ppc_rfi()))
	print("rlwinm %r4,%r5,2,5,10 " + print_hex(PPC32.ppc_rlwinm(4, 5, 2, 5, 10)))
	print("ori    %r4,%r5,0xFF   " + print_hex(PPC32.ppc_ori(4, 5, 0xFF)))
	print("and    %r0,%r0,%r0    " + print_hex(PPC32.ppc_and(0, 0, 0)))
	print("add    %r9,%r10,%r11  " + print_hex(PPC32.ppc_add(9, 10, 11)))
	print("or     %r6,%r7,%r8    " + print_hex(PPC32.ppc_or(6, 7, 8)))
	print("mfspr  %r30,630       " + print_hex(PPC32.ppc_mfspr(30, 630)))
	print("mtspr  27,%r31        " + print_hex(PPC32.ppc_mtspr(31, 27)))
	print("lwz    %r31,0(%r30)   " + print_hex(PPC32.ppc_lwz(31, 30, 0)))
	print("lbz    %r28,4(%r29)   " + print_hex(PPC32.ppc_lbz(28, 29, 4)))
	print("stw    %r31,0(%r30)   " + print_hex(PPC32.ppc_stw(31, 30, 0)))
	print("stb    %r25,12(%r24)  " + print_hex(PPC32.ppc_stb(25, 24, 12)))
	print("lhz    %r27,8(%r26)   " + print_hex(PPC32.ppc_lhz(27, 26, 8)))
	print("sth    %r23,16(%r22)  " + print_hex(PPC32.ppc_sth(23, 22, 16)))

