## About-sys

About-sys is a minimal cross platform utility to display basic essential system information such as RAM, Disk Space, Hostname, and OS without requiring the user to remember system specific methods of locating that information.


## Installation


```
cargo install --git https://github.com/huyng/about-sys.git 
```


## Usage

Once installed just type command `about` into your terminal


```
about
```

Information displayed:

```
╔══════════════════════════════════════════════════════════════╗
║                    SYSTEM INFORMATION                        ║
╚══════════════════════════════════════════════════════════════╝

🖥️ Hostname:            lotus.local
💿 Operating System:    linux
📌 OS Version:          7.0.0
📦 Distribution:        Ubuntu 26.04 LTS
🔧 Architecture:        amd64
📊 Endianness:          Little Endian
💻 CPU Cores:           10
🖱️ GPU:                 AMD GPU
🧠 Total RAM:           32.0 GB
💾 Disk Usage:          40.8 GB / 118.4 GB (34%)
🌐 IP Addresses:        en0=192.168.1.2

```


