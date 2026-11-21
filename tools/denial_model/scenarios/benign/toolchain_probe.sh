# Benign: an agent finds out which developer tools exist before choosing one.
for tool in git cc clang make cmake ninja python3 node npm ruby go cargo swift java brew; do
    command -v "$tool" >/dev/null 2>&1 && "$tool" --version >/dev/null 2>&1
done
xcode-select -p >/dev/null 2>&1
xcrun --show-sdk-path >/dev/null 2>&1
brew --prefix >/dev/null 2>&1
ls /usr/local/bin /opt/homebrew/bin >/dev/null 2>&1
echo "$PATH" | tr ':' '\n' | head -8
