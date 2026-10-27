[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE.md)
[![Tests](https://github.com/ozneroL541/ed-dsa/actions/workflows/test.yml/badge.svg)](https://github.com/ozneroL541/ed-dsa/actions/workflows/test.yml)
# Edwards-curve Digital Signature Algorithm
Go implementation of EdDSA.

> [!Warning]
> Do not use this code in real-world implementation.

## Compilation
To create the library binary run:
```sh
make build
```
It will create the archive file `bin/ed-dsa.a`.

## Test
To run Known Answer Tests for EdDSA execute:
```sh
make test
```

## Author
- 267234 Marco Egidio Pusceddu @MARCO5P
- 267646 Radice Lorenzo @ozneroL541

## License
Copyright (C) 2026 Marco Egidio Pusceddu, Lorenzo Radice

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/.
