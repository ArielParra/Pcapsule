# default.nix
{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.gcc          
    pkgs.libpcap
    pkgs.raylib
    pkgs.ncurses
    pkgs.cmake         
    pkgs.pkg-config     
  ];
}

