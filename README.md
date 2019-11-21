# WBC DFA IMPLEMENTATION

This repository contains a WBC DFA attack implementation.

## What is DFA?

*Differential fault analysis (DFA) is a type of side channel attack in the field of cryptography, specifically cryptanalysis. The principle is to induce faults—unexpected environmental conditions—into cryptographic implementations, to reveal their internal states.*

## Requirements

### Python Dependencies

```shell
pip3 install -r requirements.txt
```

### Traces

In order to perform a DFA attack, it's needed to provide some traces.

* The first trace will be the correct output of the WBC (without a fault).
* All the other traces will be the outputs of the WBC with faults (the more, the better).

Example of the traces:

```
17,35,D1,09,C2,36,C4,CF,B4,E7,48,7C,80,27,8C,71
17,35,D1,36,C2,36,BB,CF,B4,44,48,7C,51,27,8C,71
17,7B,D1,09,49,36,C4,CF,B4,E7,48,AC,80,27,45,71
17,35,D1,AA,C2,36,1B,CF,B4,10,48,7C,DC,27,8C,71
```

* Every 4 bytes represents one column of the output.

## Usage

Execute the dfa script with Python3 and specify the output file.

```shell
python3 dfa.py outputs_DFA.dat [limit] [-log]
```

* [limit]: Specifies how many candidates are needed for the DFA (0 by default).
* [-log]: Specifies if you want to write all the candidates inside a file.

## Example

This example is performed using the outputs_DFA_AES128.dat file.

```shell
python3 dfa.py outputs_DFA.dat 100000 -log
```

The tool will do the next output:

```
[DFA] Trace file selected: outputs_DFA_AES128.dat.
[DFA] Candidates needed: 0.
[DFA] Logging enabled.
[DFA] Starting thread for target [(0, 0), (1, 3), (2, 2), (3, 1)].
[DFA] Starting thread for target [(0, 1), (1, 0), (2, 3), (3, 2)].
[DFA] Starting thread for target [(0, 2), (1, 1), (2, 0), (3, 3)].
[DFA] Starting thread for target [(0, 3), (1, 2), (2, 1), (3, 0)].
[DFA] SubKey10.
[['0x22' '0xf4' '0x32' '0xfa']
['0xf1' '0x79' '0x12' '0x8e']
['0xc' '0x86' '0x14' '0xe1']
['0x20' '0x12' '0x4' '0x20']]
[DFA] MasterKey.
[['0xca' '0xfe' '0xba' '0xbe']
['0xde' '0xad' '0xbe' '0xef']
['0xca' '0xfe' '0xba' '0xbe']
['0xde' '0xad' '0xbe' '0xef']]
```

The SubKey10 and MasterKey will be printed.

## Inspiration

A project inspired by:

* Differential Fault Analysis on A.E.S.
* People breaking WBC implementations.

<img src="https://img.shields.io/badge/kikones34-approved-blue" alt="approved">

## TODO

Finish CCA implementation.