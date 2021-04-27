![build-test](https://github.com/Chukak/netsniffer/actions/workflows/cmake.yml/badge.svg)

# Netsniffer

Sniffing network traffic on the interface. Filtering network packets. 
Displays IP and Protocol headers and any packet data. 


## Installation and Running

### Debian/Ubuntu

To install the `netsniffer` from the `.deb` package, download the release you need from [Releases](https://github.com/Chukak/netsniffer/releases).
Any `.deb` package has the format `netsniffer_<VERSION>_<OS-VERSIONS>_<ARCHITECRUTE>.deb`. After downloading run the following command:
```bash
dpkg -i ./<pkgname>.deb
```

To run the `netsniffer`:
```bash
sudo netsniffer # show help
```

### Windows 10

Download the `netsniffer_0.1.0_windows-10.exe` from [Releases](https://github.com/Chukak/netsniffer/releases). 
This is a self-extracting archive, created by `7-Zip`. Run this downloaded file in the folder you need.

To run the `netsniffer` open `cmd.exe` (or you can to use `powershell`) as root:
```bash
cd /d /path/to/netsniffer.exe # for cmd.exe
netsniffer.exe # show help
```

Alternatively, you can add `/path/to/netsniffer.exe` in the global `PATH` variable.

If you don\`t see incoming packets from Ethernet, you need to change firewall settings. Allow ports for the `netsniffer` app in additional firewall settings:

![win10_1](https://github.com/Chukak/netsniffer/blob/main/docs/win10/win10_1.png)

And now:

![win10_1](https://github.com/Chukak/netsniffer/blob/main/docs/win10/win10_2.png)

Now, try to run the `netsniffer` as root.


## Building from sources

### Linux

```bash
cmake . # for testing, -DTESTS_EANBLED=1 flags
make
sudo make install
```

### Windows

First, you need the `mingw` compiler. Other compilers are not supported at the moment.

```bash
cmake .
make
```
