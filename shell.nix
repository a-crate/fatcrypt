with import <nixpkgs> { };

mkShell {
  nativeBuildInputs = [
    cmake
    pkgconf
    fuse3
    libsodium
    json_c
  ];

  shellHook = ''
  '';
}
