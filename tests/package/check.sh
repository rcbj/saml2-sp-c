#!/bin/sh
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# The installed package, as a Conan recipe or any CMake user would get it.
# Run by the Docker test stage from the repository root, after the suite, with
# the suite's static build in ./build (or the directory named last):
#
#   sh tests/package/check.sh <package> <library file stem> <option prefix> [suite build dir]
#
# It installs that static build, builds and installs the library alone as a
# shared library (tests and programs off), checks what each install holds, and
# builds and runs tests/package (the C++ smoke test, linked through
# find_package(<package>)) against each.
set -eu
pkg=$1 stem=$2 opt=$3 suite=${4:-build}
version=$(tr -d '[:space:]' < VERSION)

cmake --install "$suite" --prefix /tmp/pkg-static >/dev/null
cmake -S . -B /tmp/build-shared -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON \
  -D"${opt}_BUILD_TESTS=OFF" -D"${opt}_BUILD_PROGRAMS=OFF" >/dev/null
cmake --build /tmp/build-shared >/dev/null
cmake --install /tmp/build-shared --prefix /tmp/pkg-shared >/dev/null

fail() { echo "package check: $*" >&2; exit 1; }
for kind in static shared; do
  p=/tmp/pkg-$kind
  find "$p" -name "${pkg}Config.cmake" | grep -q . || fail "$kind: no ${pkg}Config.cmake"
  find "$p" -name "${pkg}ConfigVersion.cmake" | grep -q . || fail "$kind: no ${pkg}ConfigVersion.cmake"
  [ -z "$(find "$p/include" -name '*.h' -o -name '*.hpp' | grep -v "^$p/include/iya" )" ] || fail "$kind: unexpected headers"
done
find /tmp/pkg-static -name "lib${stem}.a" | grep -q . || fail "static: no lib${stem}.a"
find /tmp/pkg-shared -name "lib${stem}.so.*" | grep -q . || fail "shared: no lib${stem}.so.*"
[ -z "$(find /tmp/pkg-shared -name '*.a')" ] || fail "shared: a static archive was installed"
[ ! -d /tmp/pkg-shared/bin ] || fail "shared: programs were installed with the library alone"

for kind in static shared; do
  cmake -S tests/package -B "/tmp/consumer-$kind" -DCMAKE_PREFIX_PATH="/tmp/pkg-$kind" \
    -D"${pkg}_EXPECTED_VERSION=$version" >/dev/null
  cmake --build "/tmp/consumer-$kind" >/dev/null
done
ldd /tmp/consumer-shared/consumer | grep -q "lib${stem}\.so" || fail "the shared consumer does not load lib${stem}.so"
! ldd /tmp/consumer-static/consumer | grep -q "lib${stem}\.so" || fail "the static consumer loads lib${stem}.so"
/tmp/consumer-static/consumer >/dev/null || fail "the static consumer failed"
/tmp/consumer-shared/consumer >/dev/null || fail "the shared consumer failed"
echo "package check: ${pkg} ${version}: static and shared installs, find_package(${pkg} ${version} EXACT), consumers ran"
