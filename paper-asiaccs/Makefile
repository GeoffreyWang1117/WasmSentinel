# WasmSentinel AsiaCCS 2027 paper
MAIN = main
.PHONY: all quick clean lint numbers figures
all: $(MAIN).pdf
$(MAIN).pdf: $(MAIN).tex sections/*.tex bib/*.bib
	latexmk -pdf -interaction=nonstopmode -halt-on-error $(MAIN)
quick:
	pdflatex -interaction=nonstopmode -halt-on-error $(MAIN)
numbers:
	cd .. && conda run -n wasmsentinel python3 evaluation/scripts/paper_numbers.py --out paper-asiaccs/tables/numbers.tex
figures:
	mkdir -p figures
	cp ../evaluation/results/2026-11/e1/e1_pr_curves.pdf figures/
	cp ../evaluation/results/2026-11/e3/e3_latency_throughput.pdf figures/

lint:
	@grep -nE "TODO|FIXME|XXX|first system|zero-copy|zero copy|5x|485" sections/*.tex $(MAIN).tex || true
clean:
	latexmk -C $(MAIN); rm -f sections/*.aux
