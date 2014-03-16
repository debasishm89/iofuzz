iofuzz
======

A mutation based user mode (ring3) dumb in-memory IOCTL Fuzzer/Logger. This script attach it self to any given process and hooks DeviceIoControl!Kernel32 API and try to log or fuzz all I/O Control code I/O Buffer pointer, I/O buffer length that process sends to any Kernel driver.
