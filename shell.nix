# shell for compiling latex spec

let
  pkgs = import <nixpkgs> {};
  isDarwin = pkgs.hostPlatform.isDarwin;

  # Latex
  tex = (pkgs.texlive.combine {
    inherit (pkgs.texlive) scheme-small
      collection-mathscience preprint amsmath enumitem placeins;
  });

in pkgs.stdenv.mkDerivation {
  name = "signers-env";
  nativeBuildInputs = [
    tex
  ];
  buildInputs = pkgs.lib.optionals isDarwin [pkgs.darwin.apple_sdk.frameworks.Security];
}
