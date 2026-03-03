DOT := $(wildcard dot/*.dot)
DOT_PDF := $(DOT:.dot=.pdf)
TEX := $(wildcard *.tex)
OUT_PDF := ../..
PDF := $(addprefix $(OUT_PDF)/, $(TEX:.tex=.pdf))

all: ${PDF}

dot/%.pdf: dot/%.dot
	dot -Tpdf $< -o $@
	pdfcrop $@ $@

pinout.pdf: ../../../documentation/Hardware/T4e/Board/pinout.ods
	libreoffice --headless --convert-to pdf --outdir . $<
	pdfcrop $@ $@

ltft_cup260.pdf: ltft_cup260.ods
	libreoffice --headless --convert-to pdf --outdir . $<
	pdfcrop $@ $@

$(OUT_PDF)/%.pdf: %.tex $(DOT_PDF) pinout.pdf ltft_cup260.pdf *.png
	pdflatex -interaction=nonstopmode -halt-on-error $<
	pdflatex -interaction=nonstopmode -halt-on-error $<
	mv $(<:.tex=.pdf) $@

clean:
	rm -f $(DOT_PDF) $(PDF) *.aux *.log *.toc *.out *.lof

.PHONY: all clean
.SECONDARY: $(DOT_PDF)
