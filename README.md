# betanet c library

this is a c library for the betanet protocol. it is currently under development.

the api is strongly inspired/basically the same as the berkeley sockets for familarily, but i also plan to write a futureproof async/event driven high level api with callbacks

## development environment

this project uses [nix](https://nixos.org/) with flakes for a reproducible development environment.

1.  **install nix:** follow the instructions at [nixos.org](https://nixos.org/download.html).
2.  **enable flakes:** if you haven't already, [enable nix flakes](https://nixos.wiki/wiki/flakes#enabling-flakes).
3.  **(optional) use direnv:** install [direnv](https://direnv.net/) and run `direnv allow` in the project root. this will automatically load the development environment when you `cd` into the directory.

alternatively, you can manually enter the development shell by running `nix develop` in the project root.

## building

once you are in the development environment, you can build the project using cmake and make:

```bash
mkdir build
cd build
cmake ..
make
```

## editor setup (vscode)

this project is pre-configured for use with vs code and the recommended extensions.

1.  **install recommended extensions:** open the command palette (`cmd+shift+p`) and run `extensions: show recommended extensions`. install the "c/c++" and "cmake tools" extensions.
2.  **select the nix clang kit:** after reloading the window, open the command palette again and run `cmake: select a kit`. choose "nix clang" from the list.

this will configure intellisense and the linter correctly.

## current status

this project is in its very early stages. while the basic structure and development environment are set up, there is currently no functional code. the api in `include/betanet.h` is a preliminary design and is subject to change.

## usage

the public api is defined in `include/betanet.h`. you can see example usage in the `examples` directory.