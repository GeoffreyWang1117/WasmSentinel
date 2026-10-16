# WasmSentinel Paper

**Target Conference:** ACM CCS 2026 Cycle 2
**Deadline:** April 29, 2026
**Status:** Draft in progress

## Paper Structure

```
paper/
├── main.tex                    # Main LaTeX file
├── Makefile                    # Build configuration
├── sections/
│   ├── introduction.tex        # Introduction (1 page)
│   ├── background.tex          # Background (1 page)
│   ├── threat-model.tex        # Threat Model (0.5 page)
│   ├── design.tex              # System Design (3 pages)
│   ├── implementation.tex      # Implementation (1 page)
│   ├── evaluation.tex          # Evaluation (3 pages)
│   ├── discussion.tex          # Discussion (0.5 page)
│   ├── related-work.tex        # Related Work (1 page)
│   ├── conclusion.tex          # Conclusion (0.5 page)
│   └── appendix.tex            # Appendix
├── figures/                    # Figures directory
├── tables/                     # Tables directory
└── bib/
    └── references.bib          # Bibliography
```

## Building

```bash
# Full build (with bibliography)
make

# Quick build (single pass)
make quick

# Clean build artifacts
make clean

# View PDF
make view

# Word count
make wordcount
```

## Key Contributions

1. **WasmML**: First ML inference in Wasm sandbox for threat detection
2. **Hybrid Architecture**: STIDE + MLP for efficiency and accuracy
3. **Zero-Copy Channel**: Efficient eBPF-Wasm data transfer
4. **Comprehensive Evaluation**: 121-485x faster than baselines

## Experimental Results Summary

| Metric | Value |
|--------|-------|
| F1 Score | 0.72 |
| Inference Latency | 16.5 μs |
| Throughput | 60,612 events/s |
| Memory | 19 MB |
| Wasm Module Size | 180 KB |

## Dependencies

- LaTeX distribution (texlive-full recommended)
- ACM article class (acmart)
- Standard packages: booktabs, algorithm, listings, tikz

## TODO

- [ ] Add architecture diagram (TikZ)
- [ ] Add latency comparison bar chart
- [ ] Add ROC curve plot
- [ ] Review and polish text
- [ ] Internal review
- [ ] Camera-ready formatting
