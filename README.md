# MapleStory Launcher

`MapleStory Launcher` is a native Windows launcher for MapleStory v48 that:

- launches `MapleStory.exe`
- unpacks the client in memory
- applies compiled-in client patches directly from the launcher

The project is designed to run as a single launcher executable beside the game files with no extra helper binaries required at runtime.

## Huge Thanks

Huge shoutout and thank you to **Hendi** for **ASpirin**:

- https://github.com/Hendi48/ASpirin

This launcher's unpacking work was heavily inspired by ASpirin, and that project was extremely valuable as a reference while building the native unpack flow.

Huge thanks as well to **Riremito** for **KaedeEditor**:

- https://github.com/Riremito/KaedeEditor

KaedeEditor was extremely helpful for finding addresses and validating patch locations used by this project.

## How To Use

1. Put `maple_launcher.exe` in the same folder as `MapleStory.exe`.
2. Run `maple_launcher.exe` as administrator.
3. Press `Play`.

The launcher will automatically prefer `MapleStory.exe` in its own folder.

If the client is already a prepatched executable such as `CleanLocalhostV48.exe`, the launcher will launch it directly without the unpack path.

## Build-Time Config

Edit `maple_config.cmake` before building.

It controls:

- default client name
- working directory
- whether unpack mode is forced
- embedded patch list

Patch format:

```cmake
"address|type|value|optional_size"
```

Examples:

```cmake
"0x007FE904|ascii|127.0.0.1|16"
"0x00736FF0|hex|31 C0 C3"
"0x00123456|u32|0"
```

Supported patch types:

- `ascii`
- `hex`
- `u32`

## Building

This project uses CMake.

Basic build:

```powershell
cmake -S . -B build
cmake --build build --config Release
```

If you are building with MinGW/LLVM-MinGW, configure the compiler paths explicitly as needed for your machine.

Example:

```powershell
cmake -S . -B build -G "MinGW Makefiles" `
  -DCMAKE_CXX_COMPILER="C:/path/to/i686-w64-mingw32-g++.exe" `
  -DCMAKE_MAKE_PROGRAM="C:/path/to/mingw32-make.exe" `
  -DCMAKE_RC_COMPILER="C:/path/to/i686-w64-mingw32-windres.exe"

cmake --build build
```

Build outputs:

- `build/maple_launcher.exe`

## Runtime Notes

- The launcher expects to run on Windows.
- The unpack/injection flow requires administrator rights.
- The launcher defaults to `MapleStory.exe` in its current directory.
- This project targets MapleStory **v48** specifically. Many patch offsets and runtime assumptions are version-sensitive.

## GUI Behavior

The launcher UI is intentionally simple:

- `Play` starts the game
- `Find Game Files` lets you point at a MapleStory executable if needed
- normal UI hides raw filesystem paths and internal implementation details

## Project Layout

- `src/launcher/` - Win32 launcher UI and app entry point
- `src/shared/` - shared config, patching helpers, and native unpacker code
- `maple_config.cmake` - patch/config source used at build time

## Current Defaults

- default target: `MapleStory.exe`
- pass-through client: `CleanLocalhostV48.exe`
- default server target in the current config: `127.0.0.1`

## Contributing

Contributions are welcome, but please keep changes version-aware and test carefully.

Recommended guidelines:

- keep launcher behavior stable
- avoid broad refactors unless they clearly improve maintainability
- document any new patch offsets and why they are needed
- mention the client version a change was tested against
- prefer small, reviewable pull requests

If you change runtime patching behavior, unpack flow, or stat/damage handling, please include enough detail for others to reproduce and validate the change.

## License

This project is released under the MIT License.

See `LICENSE` for the full text.
