with import <nixpkgs> { };

mkShell {
  nativeBuildInputs = [
    cmake
    pkgconf
    fuse3
    json_c
    libsodium
  ];

  shellHook = ''
  '';
}
