# Makefile for WasmSentinel paper

MAIN = main
LATEX = pdflatex
BIBTEX = bibtex
LATEXFLAGS = -interaction=nonstopmode -halt-on-error

.PHONY: all clean view

all: $(MAIN).pdf

$(MAIN).pdf: $(MAIN).tex sections/*.tex bib/*.bib
	$(LATEX) $(LATEXFLAGS) $(MAIN)
	$(BIBTEX) $(MAIN)
	$(LATEX) $(LATEXFLAGS) $(MAIN)
	$(LATEX) $(LATEXFLAGS) $(MAIN)

quick:
	$(LATEX) $(LATEXFLAGS) $(MAIN)

clean:
	rm -f $(MAIN).{aux,bbl,blg,log,out,pdf,toc,lof,lot}
	rm -f sections/*.aux
	rm -f *.synctex.gz

view: $(MAIN).pdf
	xdg-open $(MAIN).pdf 2>/dev/null || open $(MAIN).pdf

watch:
	while true; do \
		inotifywait -e modify $(MAIN).tex sections/*.tex bib/*.bib 2>/dev/null; \
		make quick; \
	done

# Word count (approximate)
wordcount:
	@texcount -inc -total $(MAIN).tex 2>/dev/null || \
		echo "Install texcount for word counting"

# Check for common issues
lint:
	@echo "Checking for common issues..."
	@grep -n "TODO" sections/*.tex || true
	@grep -n "FIXME" sections/*.tex || true
	@grep -n "XXX" sections/*.tex || true
