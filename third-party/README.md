# Third-Party Dependencies

## JavaFX (Linux ARM64 & Windows ARM64)

JavaFX jars for `linux-aarch64` and `win-aarch64` are extracted from JDK 21 full distributions,
since org.openjfx does not publish these platforms to Maven Central.

**Included modules only** (WebView + JFXPanel): base, controls, graphics, media, swing, web.
Omitted: fxml (unused – reduces extension size). Media is required by javafx.web for HTML5 video.

**Windows ARM64:** The `jfxwebkit.dll` native library is not distributed by OpenJFX for Windows ARM64.
To enable WebView on Windows ARM64, place `jfxwebkit.dll` in `os/win_arm_64/` in the extension.
The DLL can be built from [OpenJFX source](https://github.com/openjdk/jfx) (JavaFX 22+ adds Windows ARM64 support).

### Native layout (os/)

**Linux ARM64:** No manual bundling. `libjfxwebkit.so` is inside the javafx-web JAR; JavaFX's
`NativeLibLoader` extracts it to `~/.openjfx/cache/` and loads it at runtime. This avoids
versioning/linking issues from shipping a standalone shared object.

**Windows ARM64:** Place `jfxwebkit.dll` in `os/win_arm_64/` when available (not distributed by OpenJFX).

### Extracting the jars

1. Download JDK 21 full (with JavaFX) for Linux ARM64 and Windows ARM64
2. Unzip to `~/Downloads/jdk-21.0.10-full_linux_arm64` and `~/Downloads/jdk-21.0.10-full_windows_arm64`
3. Run the extraction script:

```bash
./scripts/extract-javafx-from-jdk.sh
```

This creates:
- `javafx/linux-aarch64/` - JavaFX jars with Linux ARM64 native libs
- `javafx/win-aarch64/` - JavaFX jars with Windows ARM64 native libs

### Source JDKs

- [Bellsoft JDKs](https://bell-sw.com/pages/downloads/#jdk-21-lts)
