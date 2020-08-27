# Qiling Debugger

## Introduction

A multi-architecture and cross-platform debugger baked by [Qiling Framework](https://github.com/qilingframework/qiling)

## Installation

`pip3 install qiling`

`git clone git@github.com:ucgJhe/Qdb.git`

## How to run example.py

make sure you install `mipsel-linux-gnu-gcc` or `arm-linux-gnueabihf`

and make binary in src directory `cd src; make`

just uncomment the one you want to test in example.py and run it with `python3 example.py`

## Usage

```python
# simple setup
from qdb import Qdb

Qdb(["src/mips32el_hello"], "/usr/mipsel-linux-gnu", rr=True).interactive()
```

### 1. commandline-based user interface

- use command `start` and paused at the entry point

![](pics/cmd_start.png?raw=true)

### 2. step-by-step execution

- use command `step` or `s` to execute one instruction at a time

![](pics/step.png?raw=true)

### 3. breakpoints

- use command `breakpoint` or `b` to setup a breakpoint, and continue process with `continue` or `c`

![](pics/breakpoint.png?raw=true)

### 4. dynamic memory examination

- use command `examine` or `x` to read data from memory

![](pics/mem_examination.png?raw=true)

### 5. record and replay

- use command `backward` or `p` to step backward from current location
- Note:
    - 1. the address you want to step backward on it must be step-over before
    - 2. make sure run Qdb with option `rr=True` like the example above

![](pics/qdb_step_backward)

## Supported architecture for now

- [x] MIPS32
- [ ] MIPS64
- [x] ARM/THUMB
- [ ] ARM64
- [ ] x86/x86-64

### P.S. tested on Ubuntu 18.04 only
