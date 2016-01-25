# KDNET - Windows Kernel Debugger over Network

Work in progress on the Windows Kernel Debugger protocol (over UDP, not to be
confused with the unencrypted serial protocol). Still learning, expect
incomplete analysis.

## kdnet.lua
A KDNET Wireshark dissector (tested with Wireshark 2.0.1). Decryption is
currently supported through the [lua-lockbox][2] library which is *slow* but
easy to install (pure LUA code, no native code). To make use of it, clone
https://github.com/somesocks/lua-lockbox into this repository.

A single encryption key must be configured first or else the decrypted contents
are not available.

Example invocation that focuses on the UDP and KDNET protocols:

    tshark -Xlua_script:kdnet.lua -okdnet.key:8.8.8.8 -O udp,kdnet \
        -r pcaps/windbg-uncut.pcapng

## Links
 - [Setting Up Kernel-Mode Debugging over a Network Cable Manually][1]

 [1]: https://msdn.microsoft.com/library/windows/hardware/hh439346%28v=vs.85%29.aspx
 [2]: https://github.com/somesocks/lua-lockbox
