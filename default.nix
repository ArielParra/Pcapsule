# default.nix
{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.gcc          
    pkgs.libpcap
    pkgs.cmake         
    pkgs.pkg-config     
  ];
}

