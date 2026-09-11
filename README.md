# dash

[![Test](https://github.com/itchio/dash/actions/workflows/test.yml/badge.svg)](https://github.com/itchio/dash/actions/workflows/test.yml)
[![GoDoc](https://godoc.org/github.com/itchio/dash?status.svg)](https://godoc.org/github.com/itchio/dash)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/itchio/dash/blob/master/LICENSE)

dash "configures" a folder, which means it looks at its contents
and determines interesting launch targets such as:

  * Native Windows, Linux & macOS executables
  * HTML index files
  * .jar files, .love files, etc.
  * Engine payloads: Godot packs, GameMaker data files, PICO-8 carts,
    Ren'Py and RPG Maker folders, AGS games, WADs, SWFs, DOS folders,
    console ROMs and more (see the `Flavor` constants)

Each candidate may carry an `Engine` (what made it, and which version), set
on native executables when a known engine left its footprint next to them,
and on every payload flavor.

`Verdict.Filter` picks what a host can run. Hosts that ship runtimes for
payload flavors list them in `FilterParams.Runtimes` (`"godot-pck"`,
`"rom:snes"`, ...) so those candidates survive next to natives.

`ConfigureParams.DeepProbe` additionally records native dependencies
(imported libraries, glibc version) for server-side use.

## License

Licensed under MIT License, see `LICENSE` for details.
