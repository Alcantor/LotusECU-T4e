# Restores the Ghidra project from ../Ghidra-Disassembly.gar into a
# scratch working directory and re-exports the tracked artifacts in place:
# hc08.c, boot08.c, black91.c, ../../patch/t4e/black91.sym and
# ../T4E090_defs.xml. These are git-tracked; `git diff` after a run shows
# exactly what changed, `git checkout --` reverts.
#
# Override on the command line, e.g.:
#   make GHIDRA_PATH=/opt/ghidra_11.4_PUBLIC WORKDIR=/tmp/disassembly

# Without this, the %.c rule below collides with make's built-in C-compile
# rules and its "remake the makefile" logic: it will try (for real, even
# under -n) to treat this Makefile itself as a stale .c/.o product.
MAKEFLAGS += --no-builtin-rules

GHIDRA_PATH ?= /opt/ghidra_11.4_PUBLIC
WORKDIR     ?= /tmp/disassembly
PROJECT     := Lotus-RE
GAR         := $(abspath ../Ghidra-Disassembly.gar)
PROJECT_GPR := $(WORKDIR)/$(PROJECT).gpr
PROJECT_REP := $(WORKDIR)/$(PROJECT).rep

HEADLESS = $(GHIDRA_PATH)/support/analyzeHeadless $(abspath $(WORKDIR)) $(PROJECT) -noanalysis -readOnly -scriptPath $(abspath ../ghidra_scripts)

.PHONY: all unpack pack guide clean help

all: black91.c boot08.c hc08.c ../../patch/t4e/black91.sym ../T4E090_defs.xml

help:
	@echo "Targets:"
	@echo "  all     rebuild black91.c, boot08.c, hc08.c, ../../patch/t4e/black91.sym"
	@echo "          and ../T4E090_defs.xml from the .gar, in place (default goal)"
	@echo "  guide   rebuild ../T4E090_guide.pdf via guide/Makefile"
	@echo "  unpack  extract the .gar into WORKDIR for inspection"
	@echo "  pack    re-zip WORKDIR back into the .gar (see caveats in the"
	@echo "          comment above the pack recipe: not byte-identical, and"
	@echo "          it overwrites the real, committed .gar directly)"
	@echo "  clean   remove WORKDIR"
	@echo ""
	@echo "Variables (override on the command line):"
	@echo "  GHIDRA_PATH   Ghidra install to use    (default: $(GHIDRA_PATH))"
	@echo "  WORKDIR       scratch project location (default: $(WORKDIR))"
	@echo ""
	@echo "Example: make GHIDRA_PATH=/opt/ghidra_12.0.2_PUBLIC WORKDIR=/tmp/disassembly all"

# Builds ../T4E090_guide.pdf via guide/Makefile (pdflatex/dot/libreoffice).
guide:
	$(MAKE) -C guide

unpack: $(PROJECT_GPR)

# Reproduces the .gar restore recipe: unzip everything except the project
# pointer file and the archive marker, recreate the (empty) pointer file and
# marker, and write a minimal project.prp (Ghidra only reads the OWNER field
# from it; it is not part of the archive, see the pack recipe below).
$(PROJECT_GPR): $(GAR)
	rm -rf $(PROJECT_REP)
	mkdir -p $(PROJECT_REP)
	unzip -o $(GAR) -d $(PROJECT_REP) -x $(PROJECT).gpr JAR_FORMAT
	printf '<?xml version="1.0" encoding="UTF-8"?>\n<FILE_INFO>\n <BASIC_INFO>\n  <STATE NAME="OWNER" TYPE="string" VALUE="%s" />\n </BASIC_INFO>\n</FILE_INFO>\n' "$$(whoami)" > $(PROJECT_REP)/project.prp
	touch $@ $(WORKDIR)/JAR_FORMAT

# Re-zips the working directory back into a .gar. NOT byte-identical to a
# Ghidra-produced .gar: Ghidra's own archiver (Java's zip writer) always
# deflates, even 0-byte entries, while Info-ZIP's `zip` stores those instead,
# and entry order/timestamps differ too. Verified equal where it matters
# though: same 22 entries, same name, size and CRC32 for every one, when
# packed from a project that was only unpacked, never opened by Ghidra
# (opening it, even -readOnly, rewrites idata/~index.dat/~index.bak and can
# drop idata/~journal.dat, so pack before running any export if you want a
# content-clean comparison). project.prp is excluded: it is a local
# reconstruction aid, not an original archive member.
pack: $(PROJECT_GPR)
	rm -f $(GAR)
	cd $(PROJECT_REP) && zip -q -X -D -r $(GAR) . -x project.prp
	cd $(WORKDIR) && zip -q -X -D $(GAR) $(PROJECT).gpr JAR_FORMAT
	@echo "Packed to $(GAR)"

%.c: $(PROJECT_GPR)
	$(HEADLESS) -process $(notdir $*).bin -postScript ExportCCode.java $@

%.sym: $(PROJECT_GPR)
	$(HEADLESS) -process $(notdir $*).bin -postScript ExportGNUSym.java $@

# ExportRomRaiderDefs.java takes no arguments: it writes "<xmlid>_defs.xml"
# (xmlid "T4E090" comes from the CAL_base EOL comment) in the current
# directory, and merges in "<xmlid>_defs.inc" from the current directory if
# present. The "cd .." puts it in romraider-defs/, where both live.
../T4E090_defs.xml: $(PROJECT_GPR) ../T4E090_defs.inc
	cd .. && $(HEADLESS) -process black91.bin -postScript ExportRomRaiderDefs.java

clean:
	rm -rf $(WORKDIR)
