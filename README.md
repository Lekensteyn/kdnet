# KDNET - Windows Kernel Debugger over Network

Work in progress on reverse-engineering the Windows Kernel Debugger protocol
(over UDP, not to be confused with the unencrypted serial protocol). Still
learning, expect incomplete analysis.

## kdnet.lua
A KDNET Wireshark dissector (tested with Wireshark 2.0.1). Decryption is
currently supported through the [lua-lockbox][2] library which is *slow* but
easy to install (pure LUA code, no native code). To make use of it, clone
https://github.com/somesocks/lua-lockbox into this repository.

A single encryption key must be configured first or else the decrypted contents
are not available.

Example invocation that focuses on the UDP and KDNET protocols:

    tshark -Xlua_script:kdnet.lua -okdnet.key:8.8.8.8 -O udp,kdnet \
        -r pcaps/windbg-uncut.pcapng.gz

Similarly, for Wireshark GUI:

    wireshark -Xlua_script:kdnet.lua -okdnet.key:8.8.8.8 \
        -r pcaps/windbg-uncut.pcapng.gz

## Configuring for debugging
In WinDbg terminology, the *target* is the machine that is being debugged, the
*host* is the machine that runs the debugger. The host listens on a UDP port.
The target uses the same source and destination port numbers for sending and
receiving data.

Assume:

    Host IP:        192.168.2.1
    Port number:    51111
    Key:            8.8.8.8

The 256-bit key uses base-36 encoding for each 64-bit part, see [MSDN][1].

Example *target* configuration:

    bcdedit /debug on
    bcdedit /dbgsettings net hostip:192.168.2.1 port:51111 key:8.8.8.8

On the *host*, you can wait for the target:

    windbg -k net:port=51111,key=8.8.8.8

The [pcaps/windbg-uncut.pcapng.gz](pcaps/windbg-uncut.pcapng.gz) file was
generated using these settings.

## Links
 - [Setting Up Kernel-Mode Debugging over a Network Cable Manually][1]
 - https://github.com/JumpCallPop/libKDNET

 [1]: https://msdn.microsoft.com/library/windows/hardware/hh439346%28v=vs.85%29.aspx
 [2]: https://github.com/somesocks/lua-lockbox
