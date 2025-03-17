# shell for compiling latex spec

let
  pkgs = import <nixpkgs> {};

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
}
