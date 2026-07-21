# IEC 62443 and CVSS Parameterization

This repository contains the executable Python implementation of the joint IEC 62443 and CVSS parameterization framework presented in the paper. It includes the data models, the alternating fixed-point algorithm, and a reproducible run of the hydrogen-production blueprint case study.

## How to run

To execute the case study, first install the Python requirements:

```bash
pip install -r requirements.txt
```

Then, run the following command from the root of the repository:

```bash
python case_study.py
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
* **Execution**: Runs the `alg` function to match Table 5 in the paper.