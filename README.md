# uECC-micropython

## Table of Contents
+ [About](#about)
+ [Getting Started](#getting_started)
+ [Usage](#usage)
+ [module documentation](#doc)

## About <a name = "about"></a>
This is a wrapper for [kmackay/micro-ecc](https://github.com/kmackay/micro-ecc) for
[micropython](https://github.com/micropython/micropython)

This C-Module is intended to lift the C functionality in micro-ecc to be usable
from micropython.

## Getting Started <a name = "getting_started"></a>

### Prerequisites
This is designed for micropython.

```
git clone --recurse-submodules https://github.com/micropython/micropython.git
```

to compile the project, [make](https://www.gnu.org/software/make/),
[gcc](https://gcc.gnu.org/) and [arm-none-eabi-gcc](https://gcc.gnu.org/) is required,
install them from your package manager

### Installing
[micro-ecc-micropython](https://github.com/peterzuger/micro-ecc-micropython) will work on
any port.

First create a modules folder next to your copy of [micropython](https://github.com/micropython/micropython).

```
project/
├── modules/
│   └──micro-ecc-micropython/
│       ├──...
│       └──micropython.mk
└── micropython/
    ├──ports/
   ... ├──stm32/
      ...
```

And now put this project in the modules folder.

```
cd modules
git clone https://gitlab.com/peterzuger/micro-ecc-micropython.git
```

Now that all required changes are made, it is time to build [micropython](https://github.com/micropython/micropython),
for this cd to the top level directory of [micropython](https://github.com/micropython/micropython).
From here, first the mpy-cross compiler has to be built:
```
make -C mpy-cross
```

once this is built, compile your port with:
```
make -C ports/your port name here/ USER_C_MODULES=../modules CFLAGS_EXTRA=-DMODULE_MICRO_ECC_ENABLED=1
```

and you are ready to use micro-ecc.

## Usage <a name = "usage"></a>
The module is available by just importing uECC:
```
import uECC
```

For an example of every function and object check out the [test script](tests/test_uECC.py).

## Documentation <a name = "doc"></a>
Every function and its python signature is documented in the C code: [here](micro_ecc.c).
