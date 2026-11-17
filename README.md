# IEC 62443 and CVSS Parameterization

This repository contains the executable Python implementation of the joint IEC 62443 and CVSS parameterization framework presented in the paper. It includes the data models, the alternating fixed-point algorithm, and a reproducible run of the hydrogen-production blueprint case study.

## How to run

To execute the case study, first install the Python requirements:

```bash
pip install -r requirements.txt
```

### Basic case study (CNS 2026 conference paper)

Then, run the following command from the root of the repository:

```bash
python case_study.py
```

### Detailed case studies (journal extension)

```bash
python -m extension.hydrogen # Hydrogen-production case study
python -m extension.energy   # Energy case study
```

## Repository structure

### `model.py`

This file defines the model, including IEC 62443 foundational requirements (`FR`), CVSS vectors (`MAV`, `MPR`, `Requirement`), and the `Vulnerability` evidence.

### `alg.py`

This module contains the fixed-point loop (`alg`) and the mapping functions `F` and `G`.

* IEC to CVSS (`G` function): Computes CVSS environmental vectors from the achieved IEC 62443 evidence, as described in the paper's definition of $G$.

* CVSS to IEC (`F` function): Computes new achieved IEC levels based on CVSS evidence, as described in the paper's definition of $F$.

### `case_study.py`

This script initializes the specific topology described in the case study:

* **Zones**: Instantiates `Boundary`, `TerminalBus`, `PlantBus`, and `PackageUnit`.
* **Target/Capability Evidence**: Sets up the baseline IEC levels inferred from the Siemens blueprint.
* **Vulnerabilities**: Defines V1 (a boundary firewall vulnerability affecting RDF and RA), V2 (a terminal bus HMI weakness), and V3 (a package unit PLC weakness).
* **Execution**: Runs the `alg` function to match Table 5 in the conference paper.

### `extension/`

Contains two detailed case studies that are explored in the paper's journal extension. The case studies are `extension/hydrogen.py` (hydrogen-production case study) and `extension/energy.py` (energy case study).

The `extension/model.py` contains a standalone implementation of the framework, with the following characteristics:
 
* **CVSS 3.1 scoring** (`env`, `base_score`): base and environmental scores computed directly from the specification formulas, so no external CVSS library is needed.
* **`Model`**: holds the target levels, the capability levels, the vulnerabilities, and the penalty thresholds (`theta`, default `(4, 8)`) and penalty classes (`pens`, default `(0, 1, 2)`). It provides `G` (IEC to CVSS), `F` (CVSS to IEC), `run()` (the alternating fixed-point loop, returning the final levels, the final vectors, and the per-round trace), and `lfp()` (the same loop started from the all-zero state).
* **`gaps`**: lists the (zone, FR) pairs where the achieved level is below the target.