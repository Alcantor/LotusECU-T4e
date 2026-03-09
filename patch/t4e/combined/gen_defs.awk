# Generate patch_defs.xml from patch.txt and defs.inc template files.
#
# Usage: awk -v base=0x10000 -f gen_defs.awk patch.txt romid.inc [defs.inc ...]
#
# .inc files use {SYMBOL} placeholders resolved from the patch.txt symbol table.
# base is subtracted from each symbol address to obtain the file offset expected
# by RomRaider.

FNR == NR {
	if      (/^SYMBOL TABLE:/)  in_sym = 1;
	else if (in_sym && /^$/)    in_sym = 0;
	else if (in_sym && NF >= 4) syms[$NF] = strtonum("0x" $1);
	next
}

BEGIN {
	base = strtonum(base)
	print "<roms>"
	print " <rom>"
}

{
	line = $0
	while (match(line, /\{CAL_[A-Za-z0-9_]*\}/)) {
		sym = substr(line, RSTART + 1, RLENGTH - 2)
		if (!(sym in syms)) {
			print "Symbol \"" sym "\" not found in patch.txt" > "/dev/stderr"
			exit 1
		}
		line = substr(line, 1, RSTART - 1) \
		       sprintf("0x%X", syms[sym] - base) \
		       substr(line, RSTART + RLENGTH)
	}
	print line
}

END {
	print " </rom>"
	print "</roms>"
}
