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
    Playdate bundles, console ROMs and more (see the `Flavor` constants)

dash is used by the itch app to determine what launch targets to show to the
end-user when launching something they've downloaded. It is also used to
statically analyze a game's files for platform classification.

## Usage

```go
verdict, err := dash.Configure("path/to/game", dash.ConfigureParams{
	Consumer: consumer,
})

// narrow down to what can run on this machine
filtered := verdict.Filter(consumer, dash.FilterParams{
	OS:   "linux",
	Arch: "amd64",
	// payload formats you have a runtime for
	Runtimes: []dash.Flavor{"godot-pck", "rom:snes"},
})
```

Candidates also get tagged with the engine that made them when it can be
detected, and helper executables (crash handlers, bundled runtimes) are marked
so `Filter` skips them.

Set `DeepProbe` to also record library dependencies of native executables.

`ScanLaunchTargets` does a full scan with file hashes, for storing a report
about an upload. It's slow, so don't use it at launch time.

## License

Licensed under MIT License, see `LICENSE` for details.
