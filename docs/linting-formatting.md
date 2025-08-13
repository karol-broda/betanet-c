# linting and formatting

this document describes the linting and formatting setup for the betanet-c project.

## tools

- **clang-format**: code formatting
- **clang-tidy**: static analysis and linting
- **clangd**: language server for ide integration

## usage

### command line

after setting up the build directory with cmake, you can use these targets:

```bash
# format all source files
cmake --build build --target format

# check if files are properly formatted (without modifying)
cmake --build build --target check-format

# run static analysis
cmake --build build --target lint
```

### vs code integration

the project includes vs code configuration for automatic formatting and linting:

1. **automatic formatting**: files are formatted on save
2. **clangd integration**: provides real-time linting and code completion
3. **tasks**: use ctrl+shift+p → "tasks: run task" to access:
   - "format code"
   - "check format"
   - "lint code"
   - "build and lint"

### configuration files

- `.clang-format`: formatting rules (based on llvm style with customizations)
- `.clang-tidy`: static analysis rules
- `.vscode/settings.json`: vs code integration
- `.vscode/tasks.json`: vs code tasks for formatting and linting

## development workflow

1. write code
2. save files (automatic formatting)
3. run `cmake --build build --target lint` to check for issues
4. fix any reported problems
5. commit changes

## customization

### formatting

edit `.clang-format` to modify formatting rules. key settings:
- `IndentWidth: 4` - use 4 spaces for indentation
- `ColumnLimit: 100` - line length limit
- `PointerAlignment: Right` - int *ptr style

### linting

edit `.clang-tidy` to enable/disable specific checks:
- add checks: `bugprone-*,readability-*`
- disable checks: `-readability-magic-numbers`
- configure options in `CheckOptions` section

## nix integration

the development shell includes all necessary tools:

```bash
# enter development environment
nix develop

# tools are available
clang-format --version
clang-tidy --version
clangd --version
```
