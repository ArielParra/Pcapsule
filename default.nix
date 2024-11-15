# default.nix
{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.gcc          
    pkgs.libpcap
    pkgs.raylib
    pkgs.cmake         
    pkgs.pkg-config     
  ];
}

