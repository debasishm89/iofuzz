iofuzz
======

A mutation based user mode (ring3) dumb in-memory Kernel Driver (IOCTL) Fuzzer/Logger. This script attach it self to any given user mode process and hooks DeviceIoControl!Kernel32 API call and try to log or fuzz all I/O Control code I/O buffer length that user process sends to any Kernel driver.
