{ pkgs, ... }:
pkgs.buildGoModule {
  pname = "age-plugin-op";
  version = "0.2.1";
  src = ../.;
  vendorHash = "sha256-dhJdLYy/CDqZuF5/1v05/ZEp+cWJ6V4GnVCf+mUr1MU=";
  CGO_ENABLED = 0;
}
