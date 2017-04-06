# whack

Win32 hooking/etc.

## Disclaimer

Not complete. Not guaranteed to work. Windows only. Has unimplemented/-tested edge cases.
32-bit functionality has been used somewhat, and seems to work fine in the usual situations.
Sorry for the messy, macro-heavy code structure.

## What whack does

Whack lets you easily hook functions of other libraries/executable of the current process, both
import calls to other .dlls, and internal functions of the binary. It also makes calling these
internal functions easier, and supports specifying calling conventions which pass variables in
registers.
