# Toolchains, language standard, and build options

What compiles Glove, which C++ standard each compiler gets, and every switch
that changes the build. Prerequisites and the build commands are in
[build.md](build.md).

## Toolchains

| Toolchain | Standard | Checked by |
|---|---|---|
| Clang 18 + libc++ 18, Ubuntu 24.04 | C++23 | CI on every PR, full gate |
| Apple Clang (Xcode on the `macos-15` runner) | C++23 | CI on every PR, full gate |
| Clang 23 + libstdc++ 16, Linux | C++23 | by hand |
| GCC 16 + libstdc++ 16, Linux | C++26 | by hand, no `-Werror` (see below) |

Only the first two rows are a continuing guarantee. Nothing in CI builds with
GCC or as C++26.

clang-tidy and the libFuzzer targets need LLVM Clang; Apple Clang ships
neither. On macOS the gate takes them from Homebrew `llvm` and `llvm@18`, or
from `GLOVE_CLANG_TIDY`.

GCC is not a gated compiler:

- `scripts/preflight.sh` selects `clang`/`clang++` unless `CC` and `CXX` are
  both set, and a GCC-configured tree emits flags clang-tidy rejects.
- GCC 16 reports about 130 warnings on this tree (`-Wuseless-cast`,
  `-Wmissing-declarations`, `-Wshadow`, `-Wlogical-op`), so
  `GLOVE_WARNINGS_AS_ERRORS=ON` fails. Every preset except `dev` sets it.
- `GLOVE_BUILD_FUZZERS=ON` is refused for any compiler but Clang.

## Language standard

C++23 is the baseline: `CMAKE_CXX_STANDARD 23`, required, no GNU extensions
(`-std=c++23`, never `-std=gnu++23`).

The build becomes C++26 only when reflection is enabled. Nothing else selects
C++26, and there is no option to ask for C++26 without reflection.

| `GLOVE_REFLECTION` | Behavior |
|---|---|
| `AUTO` (default) | probe the compiler; C++26 with reflection if the probe passes, otherwise C++23 |
| `ON` | as `AUTO`, but configuration fails if the probe fails |
| `OFF` | C++23 always |

The probe tries `-freflection` (GCC 16+), then `-freflection-latest`
(clang-p2996). For each flag the compiler accepts, it compiles a program that
uses `<meta>`, `nonstatic_data_members_of`, `annotations_of`, `extract`, and
`define_static_array`. A compiler that accepts the flag but fails the program
(Clang 23 does) stays on C++23.

When the probe passes, every target gets `-std=c++26`, the reflection flag,
and `GLOVE_HAS_REFLECTION=1`. So **the default build on a GCC 16 host is
C++26, and on a Clang host C++23**, from the same command. To get the same
standard everywhere, pass `-DGLOVE_REFLECTION=OFF`.

Code must compile as both. Guard reflection code with
`#if defined(GLOVE_HAS_REFLECTION)`; see
[cpp26-reflection.md](cpp26-reflection.md). One C++26 difference has already
bitten: `std::ranges::find(strings, "literal")` does not compile as C++26
(the value type is deduced as a `char` array); write
`std::string_view{"literal"}`.

`configure` prints the result:

```text
--   C++ standard         : 23
--   GLOVE_REFLECTION     : AUTO
```

### Standard library

`std::expected` and `std::stop_token` are required.

- `setup.sh` and `scripts/configure.sh` compile a `std::expected` probe and
  add `-stdlib=libc++` on Linux when the default library fails it.
- CMake probes `std::stop_token` and adds `-fexperimental-library` when the
  library needs it (libc++ 18). Configuration fails if neither works.
- CI sets `CXXFLAGS=-stdlib=libc++` on Ubuntu.

## Presets

`CMakePresets.json`; each configures into `build/<preset>` with Ninja.

| Preset | Build type | Flags beyond warnings | `-Werror` | Use |
|---|---|---|---|---|
| `dev` | Debug | `-g` | no | iteration; clang-tidy database |
| `asan` | RelWithDebInfo | `-O2 -g -DNDEBUG -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer` | yes | gate |
| `tsan` | RelWithDebInfo | `-O2 -g -DNDEBUG -fsanitize=thread -fno-omit-frame-pointer` | yes | gate |
| `fuzz` | RelWithDebInfo | as `asan`, plus libFuzzer; tests and benchmarks off | yes | gate; no test preset |
| `relwithdebinfo` | RelWithDebInfo | `-O2 -g -DNDEBUG` | yes | profiling |
| `release` | Release | `-O3 -DNDEBUG`, LTO (`-flto=thin` on Clang) | yes | `setup.sh`, packages |

`setup.sh` uses `release`; `setup.sh Debug` uses `dev`.

No preset adds hardening flags. The release build has no
`_FORTIFY_SOURCE`, stack protector, libc++ hardening mode, or RELRO/PIE
options beyond the compiler's and platform's defaults.

## CMake options

Pass with `-D<name>=<value>` at configure time.

| Option | Default | Effect |
|---|---|---|
| `GLOVE_REFLECTION` | `AUTO` | see [Language standard](#language-standard) |
| `GLOVE_SANITIZER` | `none` | `none`, `address`, `address+undefined`, `thread`, `memory`. Adds `-fno-omit-frame-pointer -g`. `memory` is refused on macOS and is in no preset or gate. |
| `GLOVE_WARNINGS_AS_ERRORS` | `OFF` | adds `-Werror` |
| `GLOVE_BUILD_FUZZERS` | `OFF` | builds `fuzz/`; Clang only |
| `GLOVE_BUILD_BENCHMARKS` | `OFF` | builds `benchmarks/` |
| `GLOVE_WITH_GHOSTTY` | `OFF` | builds the libghostty terminal frontend; needs `-DGHOSTTY_ROOT=<prefix>` |
| `GLOVE_ENABLE_SAGE_INTEROP_TEST` | `OFF` | adds the Sage Rust consumer test; needs Cargo and `GLOVE_SAGE_MANIFEST` |
| `GLOVE_SAGE_MANIFEST` | `../sage/Cargo.toml` | absolute path to the Sage manifest for that test |
| `BUILD_TESTING` | `ON` | builds `tests/` |
| `FETCHCONTENT_SOURCE_DIR_GLAZE` | unset | use a local Glaze source instead of fetching |

`ccache` is used as the compiler launcher whenever it is on `PATH`. This
replaces a `CMAKE_CXX_COMPILER_LAUNCHER` given on the command line.

## Warnings

`cmake/CompilerWarnings.cmake`, applied to every Glove target through
`glove_options`. Glaze is a `SYSTEM` dependency and is exempt.

Clang and GCC: `-Wall -Wextra -Wpedantic -Wshadow -Wnon-virtual-dtor
-Wold-style-cast -Wcast-align -Wunused -Woverloaded-virtual -Wconversion
-Wsign-conversion -Wnull-dereference -Wdouble-promotion -Wformat=2
-Wimplicit-fallthrough -Wmissing-declarations
-Wzero-as-null-pointer-constant`.

Clang adds `-Wmissing-designated-field-initializers`, or
`-Wmissing-field-initializers` where that flag is unknown.

GCC adds `-Wmisleading-indentation -Wduplicated-cond -Wduplicated-branches
-Wlogical-op -Wuseless-cast`.

Other compilers get no warning flags.

## Environment variables

Build and install:

| Variable | Read by | Effect |
|---|---|---|
| `CC`, `CXX` | all | compiler. `setup.sh` defaults to `clang`/`clang++`. The gate requires both or neither. |
| `CXXFLAGS`, `LDFLAGS` | all | extra flags; the scripts append `-stdlib=libc++` when needed |
| `GLOVE_CLANG_C`, `GLOVE_CLANG_CXX` | `scripts/configure.sh` | compiler to use when `CC` and `CXX` are unset |
| `GLOVE_INSTALL_PREFIX` | `setup.sh` | absolute install prefix; default `$HOME/.local` |

Gate (`scripts/preflight.sh`):

| Variable | Effect |
|---|---|
| `GLOVE_PREFLIGHT_BUILD_ROOT` | absolute build root; default `build/`. Needs CTest 3.30+. |
| `GLOVE_ACTIONLINT`, `GLOVE_CLANG_FORMAT`, `GLOVE_CLANG_TIDY` | use this binary |
| `GLOVE_ALLOW_NEWER_CLANG_FORMAT=1` | run a newer clang-format; the format result is then not authoritative |
| `GLOVE_ALLOW_NO_LSAN=1` | run ASan without leak detection where ptrace is blocked; not evidence of leak-freedom |
| `GLOVE_PREPARE_LINUX_USERNS=1` | Linux: use `sudo sysctl` to lift AppArmor's restriction on unprivileged user namespaces before the tests. CI sets it; it changes host state. |

`--skip-tidy` skips clang-tidy. The final banner names every skipped or
non-authoritative stage.

## Seeing the real flags

```sh
cmake --preset release
grep -m1 -o '"command": "[^"]*runner.cpp' build/release/compile_commands.json
```

`compile_commands.json` is written for every configuration and is what
clang-tidy reads.
