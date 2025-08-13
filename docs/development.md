# development guide

this guide covers setting up the development environment, building the project, and development workflow.

## prerequisites

- [nix](https://nixos.org/) with flakes enabled
- git

## development environment setup

### using nix (recommended)

the project uses nix flakes for a reproducible development environment:

1. **install nix:**
   follow the instructions at [nixos.org](https://nixos.org/download.html)

2. **enable flakes:**
   if you haven't already, [enable nix flakes](https://nixos.wiki/wiki/flakes#enabling-flakes)

3. **enter development shell:**
   ```bash
   cd betanet-c
   nix develop
   ```

4. **(optional) use direnv:**
   install [direnv](https://direnv.net/) and run `direnv allow` in the project root. this will automatically load the development environment when you `cd` into the directory.

### manual setup

if you prefer not to use nix, you'll need to install these dependencies:

- cmake (>= 3.10)
- pkg-config
- openssl development headers
- libsodium development headers
- cmocka (for testing)
- gcc or clang

## building the project

### basic build

```bash
mkdir build
cd build
cmake ..
make
```

### build targets

- `make betanet` - build the main library
- `make test_core` - build core functionality tests
- `make test_crypto` - build cryptographic function tests
- `make test_l2_secure_channel` - build l2 secure channel integration tests
- `make test_server` - build server-side functionality tests
- `make test_htx` - build htx access-ticket tests
- `make test_noise` - build noise xk handshake tests
- `make test_htx_frames` - build htx frame format tests
- `make test_api` - build api function tests
- `make all_tests` - build all test executables
- `make examples` - build all example applications
- `make example_client` - build example client application
- `make example_server` - build example server application
- `make api_demo` - build api demonstration program

### cmake configuration options

the project uses standard cmake configuration. key variables:

- `CMAKE_BUILD_TYPE` - `Debug` (default), `Release`, `RelWithDebInfo`
- `CMAKE_C_COMPILER` - specify c compiler
- `CMAKE_INSTALL_PREFIX` - installation directory

example:
```bash
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local ..
```

## development workflow

### code organization

```
betanet-c/
├── include/           # public headers
│   └── betanet.h     # main public api
├── src/              # implementation
│   ├── betanet.c     # main library code
│   ├── crypto.c      # cryptographic functions
│   ├── htx.c         # l2 cover transport
│   ├── noise.c       # noise xk handshake
│   └── ...           # other modules
├── tests/            # test suite
│   ├── betanet_internal.h  # internal testing interface
│   ├── test_*.c      # test files
│   └── ...
├── examples/         # example applications
└── docs/            # documentation
```

### coding standards

- **c standard:** c11
- **naming:** snake_case for functions and variables
- **indentation:** 4 spaces, no tabs
- **line length:** prefer 80-100 characters
- **comments:** use `//` for single line, `/* */` for multi-line
- **memory safety:** always check for null pointers, clear sensitive data
- **error handling:** return error codes, don't assume success

### key principles from user preferences

- avoid deep nesting; refactor code to improve readability
- do not use optional chaining (?.); always check values explicitly
- avoid implicit type coercion; always ensure explicit type conversions
- follow clear, consistent naming conventions
- write modular and reusable code; avoid large functions
- ensure error handling is implemented; do not assume success by default
- always assume everything could be null
- prioritize performance optimizations without sacrificing readability
- adhere to security best practices

### adding new functionality

1. **design first:** understand the betanet specification requirements
2. **implement:** add code to appropriate module in `src/`
3. **expose api:** add public functions to `include/betanet.h` if needed
4. **test:** create comprehensive tests (see [testing guide](testing.md))
5. **document:** update relevant documentation

### debugging

the project includes debug builds with full symbol information:

```bash
cmake -DCMAKE_BUILD_TYPE=Debug ..
make
gdb ./test_program
```

for memory debugging:
```bash
valgrind --leak-check=full ./test_program
```

## editor setup

### vscode (recommended)

the project is pre-configured for vscode:

1. **install extensions:** open command palette (`cmd+shift+p`) and run `extensions: show recommended extensions`. install the "c/c++" and "cmake tools" extensions.

2. **select cmake kit:** after reloading, open command palette and run `cmake: select a kit`. choose "nix clang" from the list.

this configures intellisense and the linter correctly.

### other editors

- ensure your editor uses the `build/compile_commands.json` file for intellisense
- the nix environment provides clang-based tools for most editors

## troubleshooting

### common issues

**"sodium.h not found"**
- ensure you're in the nix development shell: `nix develop`
- if not using nix, install libsodium development headers

**"cmocka not found"**  
- ensure cmocka is installed in your environment
- in nix shell, this should be automatic

**tests fail with "function not found"**
- ensure you've built the library: `make betanet`
- check that function signatures match between implementation and test headers

**cmake configuration fails**
- clean build directory: `rm -rf build && mkdir build`
- ensure all dependencies are installed
- check cmake version: `cmake --version` (need >= 3.10)

### getting help

- check the [testing guide](testing.md) for test-specific issues
- review cmake output for specific error messages
- ensure you're using the nix development environment for consistent results
