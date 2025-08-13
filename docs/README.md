# betanet c library documentation

this directory contains comprehensive documentation for the betanet c library project.

## documentation index

- [**development guide**](development.md) - setting up the development environment, building, and workflow
- [**testing guide**](testing.md) - running tests, writing new tests, and test architecture
- [**api reference**](api.md) - public api documentation and usage examples
- [**architecture overview**](architecture.md) - internal architecture and design decisions
- [**contributing**](contributing.md) - guidelines for contributing to the project

## quick start

1. **setup development environment:**
   ```bash
   nix develop
   ```

2. **build the project:**
   ```bash
   mkdir build && cd build
   cmake .. && make
   ```

3. **run tests:**
   ```bash
   ctest --verbose
   ```

4. **view api documentation:**
   see [api reference](api.md) for detailed usage examples.

## project status

this library implements the betanet protocol version 1.1 as specified in the [official specification](../spec/betanet.md).

### implemented features

- ✅ **cryptographic primitives** - sha-256, chacha20-poly1305, hkdf, ed25519, x25519
- ✅ **l2 cover transport (htx)** - access-ticket bootstrap, noise xk handshake (client & server), frame format with encryption
- ✅ **socket api** - berkeley-style socket interface for both client and server (`connect`, `bind`, `listen`, `accept`)
- 🚧 **l1 path layer** - scion packet handling (placeholder)
- 🚧 **l3 overlay mesh** - libp2p-v2 object relay (placeholder)
- 🚧 **l4 privacy layer** - nym mixnet integration (placeholder)
- 🚧 **l5 naming & trust** - self-certifying ids and alias ledger (placeholder)
- 🚧 **l6 payments** - federated cashu and lightning (placeholder)

### test coverage

- **50 total tests** across 8 test suites
- **100% pass rate** with comprehensive coverage
- tests for all implemented functionality including edge cases and error conditions
- includes unit, integration, and client-server tests

## getting help

- check the [development guide](development.md) for common setup issues
- review the [testing guide](testing.md) for test-related questions  
- see [contributing guide](contributing.md) for development workflow
- open an issue on the project repository for bugs or feature requests
