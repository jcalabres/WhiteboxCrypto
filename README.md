# WBC DFA IMPLEMENTATION

This repository contains a WBC DFA attack implementation.

## What is DFA?

*Differential fault analysis (DFA) is a type of side channel attack in the field of cryptography, specifically cryptanalysis. The principle is to induce faults—unexpected environmental conditions—into cryptographic implementations, to reveal their internal states.*

## Requirements

In order to perform a DFA attack, it's needed to provide some traces.

* The first trace will be the correct output of the WBC (without a fault).
* All the other traces will be the outputs of the WBC with faults (the more, the better).

Example of the traces:

```
17,35,D1,09,C2,36,C4,CF,B4,E7,48,7C,80,27,8C,71
17,35,D1,36,C2,36,BB,CF,B4,44,48,7C,51,27,8C,71
17,7B,D1,09,49,36,C4,CF,B4,E7,48,AC,80,27,45,71
17,35,D1,AA,C2,36,1B,CF,B4,10,48,7C,DC,27,8C,71
17,8E,D1,09,16,36,C4,CF,B4,E7,48,23,80,27,65,71
```

* Every 4 bytes represents one column of the output.

## Usage

Execute the dfa script with Python3 and specify the output file.

```shel
python3 dfa.py outputs_DFA.dat
```

## Inspiration

A project inspired by:

* Differential Fault Analysis on A.E.S.
* People breaking WBC implementations.

## Authors

Implemented by Joan Calabrés.
