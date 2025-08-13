{
  description = "a development flake for the betanet c library";

  inputs = {
    nixpkgs.url = "github:Nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell {
          name = "betanet-dev";
          buildInputs = with pkgs; [
            # build tools
            cmake
            pkg-config

            # debugging
            # valgrind
            gdb

            # linting and formatting
            clang-tools
            clang

            # required dependencies
            openssl
            libsodium
            cmocka

            # future dependencies
            liboqs
            libuv
            libcbor
          ];
        };
      });
}
