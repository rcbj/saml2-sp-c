# ConanCenter recipe

The recipe for `iya-saml2-sp` in [conan-center-index](https://github.com/conan-io/conan-center-index)'s
layout: copy this directory to `recipes/iya-saml2-sp/` there.

- `config.yml` maps each version to the `all/` recipe.
- `all/conanfile.py` builds the library alone (tests and programs off), static or shared, from the
  `v<version>` source archive that `release.yml` publishes. Windows is not supported yet.
- `all/conandata.yml` names that archive and its SHA-256. A new release adds its version here and in
  `config.yml`, with the hash of `https://github.com/rcbj/saml2-sp-c/archive/refs/tags/v<version>.tar.gz`.
- `all/test_package/` links the installed library from C and runs one call.

To check it locally (Conan 2, a C++17 profile):

```sh
conan create conan/all --version 0.1.0 --build=missing
conan create conan/all --version 0.1.0 --build=missing -o "&:shared=True"
```
