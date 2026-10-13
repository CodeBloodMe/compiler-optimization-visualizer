# Compiler Optimization Visualizer

[![Compiler](https://img.shields.io/badge/LLVM%2FClang-14%2B-blue.svg)](https://llvm.org/)
[![Language](https://img.shields.io/badge/Python-3.9%2B-green.svg)](https://www.python.org/)
[![C/C++](https://img.shields.io/badge/C%2FC%2B%2B-ISO%20Standard-orange.svg)](https://isocpp.org/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

An interactive framework and visualization platform for studying, exploring, and automatically discovering optimal **compiler optimization-pass sequences** beyond traditional fixed compiler pipelines.

---

## 📌 Overview

Modern compilers (such as Clang/LLVM and GCC) utilize fixed, predefined optimization pipelines (`-O1`, `-O2`, `-O3`) to transform source code into efficient machine code. However, the order in which optimization passes are executed significantly impacts performance:

* **Pass Interdependence:** One pass can create or destroy opportunities for subsequent passes (e.g., *Constant Folding* can simplify conditional branches, enabling *Dead Code Elimination* to purge unreachable blocks).
* **Program Variance:** Different programs have unique characteristics (compute-bound, loop-intensive, branch-heavy), making a one-size-fits-all ordering sub-optimal for specific workloads.

**Compiler Optimization Visualizer** combines an automated pass-ordering exploration engine with an intuitive visualization interface, allowing developers and researchers to analyze step-by-step Intermediate Representation (IR) transformations, evaluate pass interactions, and benchmark alternative pass sequences.

---

## 🚀 Key Features

* **🔍 Automatic Pass Ordering:** Explores permutations of LLVM optimization passes to find sequences tailored to individual programs.
* **📊 Multi-Metric Evaluation:**
  * **Execution Time:** Runtime performance of the generated binary.
  * **Code Size:** Byte size of the compiled output.
  * **Instruction Count:** Number of generated and dynamic assembly/IR instructions.
  * **Compilation Overhead:** Time required to explore and compile candidate sequences.
* **📈 Interactive Visualizer:** Inspect IR modifications across consecutive passes, observe pass dependency chains, and compare custom pass sequences against standard `-O2` / `-O3` baselines.
* **🧪 Benchmark Suite:** Includes standardized C/C++ benchmark kernels exhibiting varied optimization challenges (loop nests, algebraic redundancy, dead control paths).

---

## 🛠️ System Architecture

```text
  +------------------+
  |  C/C++ Source    |
  +--------+---------+
           |
           v
  +------------------+
  | Clang / LLVM IR  | <---- Intermediate Representation (IR)
  +--------+---------+
           |
           +---------------------------------------+
           |                                       |
           v                                       v
+------------------------+             +------------------------+
|  Fixed Pipeline (-O2)  |             | Pass Ordering Engine   |
|  (Baseline Benchmark)  |             | (Explore Permutations) |
+-----------+------------+             +-----------+------------+
            |                                      |
            +------------------+-------------------+
                               |
                               v
                     +-------------------+
                     | Evaluation Engine |
                     | (Metrics Profile) |
                     +---------+---------+
                               |
                               v
                     +-------------------+
                     | Visualizer & UI   |
                     | (Diffs & Graphs)  |
                     +-------------------+
```

---

## 📁 Repository Structure

```text
compiler-optimization-visualizer/
├── docs/                     # Presentations, documentation, and review slides
│   └── review 1.pdf          # Review 1 presentation slides
├── src/                      # Core engine source code
│   ├── passes/               # Pass selection and pipeline runner scripts
│   ├── metrics/              # Profiling and evaluation measurement modules
│   └── explorer/             # Search heuristics and permutation generators
├── visualizer/               # UI and visualization dashboard
├── benchmarks/               # C/C++ sample programs and test kernels
├── .gitignore                # Git ignore configuration
└── README.md                 # Project documentation
```

---

## ⚙️ Prerequisites & Setup

### Requirements
* **LLVM & Clang** (Version 14 or later)
* **Python** 3.9+
* **GCC / G++** or Clang toolchain
* **Linux / WSL** (recommended for compiler benchmarking)

### Quick Start
1. Clone the repository:
   ```bash
   git clone https://github.com/ColdBloodMe/compiler-optimization-visualizer.git
   cd compiler-optimization-visualizer
   ```

2. Set up a Python virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. Verify your LLVM toolchain:
   ```bash
   clang --version
   opt --version
   ```

---

## 📅 Roadmap & Milestones

- [x] **Review 1:** Problem definition, motivation, pass interaction analysis, and methodology design.
- [ ] **Review 2:** Automated pass sequencing prototype, initial LLVM IR pipeline integration, and baseline benchmarking.
- [ ] **Review 3:** Visualizer UI development, comparative analytics dashboard, and optimization performance verification against `-O2`/`-O3`.
- [ ] **Final Review:** Comprehensive evaluation, documentation, and research article / patent study.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
