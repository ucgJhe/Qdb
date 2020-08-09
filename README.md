# Qiling Debugger

## Introduction

A multi-architecture and cross-platform debugger baked by [Qiling Framework](https://github.com/qilingframework/qiling)

## Installation

`pip3 install qiling`

`git clone git@github.com:ucgJhe/Qdb.git`

## How to run example.py

make sure you install `mipsel-linux-gnu-gcc`

and make binary in src directory `cd src; make`

`python3 example.py`

## Usage


```python
# simple setup
from qdb import Qdb

Qdb(["src/mips32el_hello"], "/usr/mipsel-linux-gnu").interactive()
```

### 1. commandline-based user interface

- use command `start` and paused at the entry point

![](pics/cmd_start.png?raw=true)

### 2. step-by-step execution

### 3. breakpoints everywhere

#### set breakpoint before run



#### set breakpoint on-the-fly

### 4. dynamic memory examination



## Supported architecture for now

- [x] MIPS 
- [ ] ARM
- [ ] x86/x86-64

### P.S. tested on Ubuntu 18.04 only
