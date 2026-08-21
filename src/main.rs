use std::collections::HashMap;
use std::ffi::CStr;
use std::fs;

// libc is a Unix-only dep (see Cargo.toml); only referenced inside #[cfg(unix)] blocks.
#[cfg(unix)]
use libc;

struct SystemInfo {
    os_name:       String,
    os_version:    String,
    distribution:  String,
    arch:          String,
    endianness:    &'static str,
    cpu_cores:     usize,
    cpu_speed_mhz: f64,
    ram:           u64,
    hostname:      String,
    is_termux:     bool,
    is_jailbroken: bool,
    ip_addresses:  Vec<String>,
    disk_total:    u64,
    disk_used:     u64,
    gpu_names:     Vec<String>,
}

fn main() {
    let info = get_system_info();
    print_system_info(&info);
}

fn get_system_info() -> SystemInfo {
    let mut info = SystemInfo {
        os_name:       std::env::consts::OS.to_string(),
        arch:          normalize_arch(std::env::consts::ARCH),
        cpu_cores:     std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
        endianness:    get_endianness(),
        hostname:      get_hostname(),
        os_version:    String::new(),
        distribution:  String::new(),
        cpu_speed_mhz: 0.0,
        ram:           0,
        is_termux:     false,
        is_jailbroken: false,
        ip_addresses:  Vec::new(),
        disk_total:    0,
        disk_used:     0,
        gpu_names:     Vec::new(),
    };

    // Runtime OS dispatch — every branch is compiled on every platform.
    // #[cfg] only appears deeper, at actual syscall boundaries.
    match info.os_name.as_str() {
        "linux"   => detect_linux_info(&mut info),
        "macos"   => detect_macos_info(&mut info),
        "windows" => detect_windows_info(&mut info),
        "android" => detect_android_info(&mut info),
        "ios"     => detect_ios_info(&mut info),
        _         => {}
    }

    info.ip_addresses  = get_ip_addresses();
    info.gpu_names     = detect_gpu_names();
    info.cpu_speed_mhz = detect_cpu_speed();
    info.ram           = detect_ram();
    let (disk_total, disk_used) = detect_disk_usage();
    info.disk_total = disk_total;
    info.disk_used  = disk_used;
    info
}

fn normalize_arch(arch: &str) -> String {
    match arch {
        "x86_64"  => "amd64",
        "aarch64" => "arm64",
        "x86"     => "i386",
        "arm"     => "arm",
        other     => other,
    }
    .to_string()
}

// Runtime byte-order check — no compile-time flags needed.
fn get_endianness() -> &'static str {
    let x: u32 = 0x01020304;
    if x.to_ne_bytes()[0] == 0x04 { "Little Endian" } else { "Big Endian" }
}

// #[cfg] is confined to the syscall sites inside this function; the function itself
// always exists and always returns a String on every platform.
fn get_hostname() -> String {
    #[cfg(unix)]
    unsafe {
        let mut buf = [0i8; 256];
        if libc::gethostname(buf.as_mut_ptr(), buf.len()) == 0 {
            return CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned();
        }
    }
    #[cfg(target_os = "windows")]
    unsafe {
        extern "system" {
            fn GetComputerNameA(buf: *mut i8, size: *mut u32) -> i32;
        }
        let mut buf  = [0i8; 256];
        let mut size = 256u32;
        if GetComputerNameA(buf.as_mut_ptr(), &mut size) != 0 {
            return CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned();
        }
    }
    String::from("unknown")
}

// --- IP Addresses ---

// Returns addresses formatted as "interface=ip", IPv4 first then IPv6.
// Skips loopback, link-local, and APIPA (169.254.x.x) addresses.
fn get_ip_addresses() -> Vec<String> {
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    match std::env::consts::OS {
        "linux" | "macos" | "android" | "ios" => get_ip_addresses_posix(&mut ipv4, &mut ipv6),
        "windows"                              => get_ip_addresses_windows(&mut ipv4, &mut ipv6),
        _                                      => {}
    }
    ipv4.extend(ipv6);
    ipv4
}

fn get_ip_addresses_posix(ipv4: &mut Vec<String>, ipv6: &mut Vec<String>) {
    // getifaddrs/inet_ntop are POSIX — confined to a #[cfg(unix)] block so
    // this function still compiles (and returns nothing) on Windows.
    #[cfg(unix)]
    unsafe {
        use std::net::{Ipv4Addr, Ipv6Addr};

        let mut addr_list: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut addr_list) != 0 {
            return;
        }
        let mut entry = addr_list;
        while !entry.is_null() {
            let e = &*entry;
            if !e.ifa_addr.is_null() {
                let sock_addr = &*e.ifa_addr;
                let iface     = CStr::from_ptr(e.ifa_name).to_string_lossy();

                // libc::sockaddr.sa_family is u8 on macOS and u16 on Linux;
                // libc abstracts this — comparing to AF_* works on both.
                let family = sock_addr.sa_family as i32;
                if family == libc::AF_INET {
                    let sin = &*(e.ifa_addr as *const libc::sockaddr_in);
                    // s_addr is network byte order; from_be → host order for Ipv4Addr.
                    let ip     = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                    let ip_str = ip.to_string();
                    // skip loopback and APIPA (169.254.x.x, assigned when DHCP fails)
                    if !ip_str.starts_with("127.") && !ip_str.starts_with("169.254.") {
                        ipv4.push(format!("{}={}", iface, ip_str));
                    }
                } else if family == libc::AF_INET6 {
                    let sin6   = &*(e.ifa_addr as *const libc::sockaddr_in6);
                    // s6_addr is [u8; 16] in network order — Ipv6Addr::from takes it directly.
                    let ip     = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                    let ip_str = ip.to_string();
                    // skip loopback (::1) and link-local (fe80::)
                    if ip_str != "::1" && !ip_str.starts_with("fe80:") {
                        ipv6.push(format!("{}={}", iface, ip_str));
                    }
                }
            }
            entry = (*entry).ifa_next;
        }
        libc::freeifaddrs(addr_list);
    }
}

fn get_ip_addresses_windows(_ipv4: &mut Vec<String>, _ipv6: &mut Vec<String>) {
    // GetAdaptersAddresses is Windows-only — confined inside #[cfg(windows)].
    #[cfg(target_os = "windows")]
    unsafe {
        // Minimal repr(C) structs matching the first fields of the Windows IP helper structs.
        // The union at the start of each adapter struct is 8 bytes (ULONGLONG Alignment).
        // Rename shadowed params inside cfg block to use the real names.
        let (ipv4, ipv6) = (_ipv4, _ipv6);
        #[repr(C)]
        struct SocketAddress { lp_sockaddr: *mut u8, sockaddr_length: i32 }
        #[repr(C)]
        struct IpAdapterUnicastAddress {
            _alignment: u64,
            next:       *mut IpAdapterUnicastAddress,
            address:    SocketAddress,
        }
        #[repr(C)]
        struct IpAdapterAddresses {
            _alignment:            u64,
            next:                  *mut IpAdapterAddresses,
            adapter_name:          *mut i8,
            first_unicast_address: *mut IpAdapterUnicastAddress,
        }
        extern "system" {
            fn GetAdaptersAddresses(family: u32, flags: u32, reserved: *mut core::ffi::c_void,
                adapter_addresses: *mut IpAdapterAddresses, size_pointer: *mut u32) -> u32;
            fn inet_ntop(af: i32, src: *const core::ffi::c_void, dst: *mut i8, size: u32) -> *const i8;
        }
        const AF_INET:  i32 = 2;
        const AF_INET6: i32 = 23;

        let mut buf_size: u32 = 15000;
        let mut raw_buf = vec![0u8; buf_size as usize];
        let status = GetAdaptersAddresses(0, 0, std::ptr::null_mut(),
            raw_buf.as_mut_ptr() as *mut IpAdapterAddresses, &mut buf_size);
        if status != 0 { return; }

        let mut adapter = raw_buf.as_ptr() as *const IpAdapterAddresses;
        while !adapter.is_null() {
            let iface   = CStr::from_ptr((*adapter).adapter_name).to_string_lossy();
            let mut uni = (*adapter).first_unicast_address;
            while !uni.is_null() {
                let sa_ptr = (*uni).address.lp_sockaddr;
                let family = *(sa_ptr as *const i16) as i32;
                let mut buf = [0i8; 46];
                if family == AF_INET {
                    let src = sa_ptr.add(4) as *const core::ffi::c_void; // sin_addr at offset 4
                    if !inet_ntop(AF_INET, src, buf.as_mut_ptr(), 46).is_null() {
                        let ip = CStr::from_ptr(buf.as_ptr()).to_string_lossy();
                        if !ip.starts_with("127.") && !ip.starts_with("169.254.") {
                            ipv4.push(format!("{}={}", iface, ip));
                        }
                    }
                } else if family == AF_INET6 {
                    let src = sa_ptr.add(8) as *const core::ffi::c_void; // sin6_addr at offset 8
                    if !inet_ntop(AF_INET6, src, buf.as_mut_ptr(), 46).is_null() {
                        let ip = CStr::from_ptr(buf.as_ptr()).to_string_lossy();
                        if ip != "::1" && !ip.starts_with("fe80:") {
                            ipv6.push(format!("{}={}", iface, ip));
                        }
                    }
                }
                uni = (*uni).next;
            }
            adapter = (*adapter).next;
        }
    }
}

// --- Linux ---

fn detect_linux_info(info: &mut SystemInfo) {
    // Kernel version lives in /proc/version — a plain file read, no libc needed.
    if let Ok(content) = fs::read_to_string("/proc/version") {
        if let Some(rest) = content.strip_prefix("Linux version ") {
            info.os_version = rest.split_whitespace().next().unwrap_or("").to_string();
        }
    }
    info.distribution = detect_linux_distribution();
}

fn detect_linux_distribution() -> String {
    if let Some(d) = parse_os_release()  { return d; }
    if let Some(d) = parse_lsb_release() { return d; }

    let distro_files = [
        ("/etc/redhat-release", "Red Hat Enterprise Linux"),
        ("/etc/centos-release",  "CentOS"),
        ("/etc/fedora-release",  "Fedora"),
        ("/etc/debian_version",  "Debian"),
        ("/etc/arch-release",    "Arch Linux"),
        ("/etc/gentoo-release",  "Gentoo"),
        ("/etc/SuSE-release",    "openSUSE"),
        ("/etc/alpine-release",  "Alpine Linux"),
    ];
    for (path, name) in &distro_files {
        if let Ok(content) = fs::read_to_string(path) {
            if *name == "Arch Linux" { return "Arch Linux (Rolling Release)".to_string(); }
            if *name == "Debian" {
                let ver = content.lines().next().unwrap_or("").trim();
                return if ver.is_empty() { "Debian".to_string() } else { format!("Debian {}", ver) };
            }
            let version = parse_simple_release(&content);
            return if version.is_empty() { name.to_string() } else { format!("{} {}", name, version) };
        }
    }
    "Linux".to_string()
}

fn parse_os_release() -> Option<String> {
    let content     = fs::read_to_string("/etc/os-release").ok()?;
    let mut pretty  = String::new();
    let mut name    = String::new();
    let mut version = String::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        if let Some(idx) = line.find('=') {
            let key   = &line[..idx];
            let value = line[idx + 1..].trim_matches(|c| c == '"' || c == '\'');
            match key {
                "PRETTY_NAME" => pretty  = value.to_string(),
                "NAME"        => name    = value.to_string(),
                "VERSION_ID"  => if version.is_empty() { version = value.to_string() },
                "VERSION"     => if version.is_empty() { version = value.to_string() },
                _             => {}
            }
        }
    }
    if !pretty.is_empty()                          { return Some(pretty); }
    if !name.is_empty() && !version.is_empty()     { return Some(format!("{} {}", name, version)); }
    if !name.is_empty()                            { return Some(name); }
    None
}

fn parse_lsb_release() -> Option<String> {
    let content     = fs::read_to_string("/etc/lsb-release").ok()?;
    let mut distro  = String::new();
    let mut release = String::new();
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("DISTRIB_ID=") {
            distro = v.trim_matches(|c| c == '"' || c == '\'').to_string();
        } else if let Some(v) = line.strip_prefix("DISTRIB_RELEASE=") {
            release = v.trim_matches(|c| c == '"' || c == '\'').to_string();
        }
    }
    if !distro.is_empty() && !release.is_empty() { return Some(format!("{} {}", distro, release)); }
    if !distro.is_empty()                         { return Some(distro); }
    None
}

fn parse_simple_release(content: &str) -> String {
    let line = content.lines().next().unwrap_or("").trim();
    // Extract version number after 'release '
    if let Some(idx) = line.find("release ") {
        let rest = &line[idx + 8..];
        if let Some(end) = rest.find(|c| c == ' ' || c == '(' || c == '\t') {
            return rest[..end].to_string();
        }
        return rest.to_string();
    }
    line.to_string()
}

// --- macOS ---

fn detect_macos_info(info: &mut SystemInfo) {
    if let Ok(content) =
        fs::read_to_string("/System/Library/CoreServices/SystemVersion.plist")
    {
        info.os_version   = extract_plist_value(&content, "ProductVersion");
        info.distribution = extract_plist_value(&content, "ProductName");
    }
    if info.distribution.is_empty() {
        info.distribution = "macOS".to_string();
    }
}

// Extracts the <string> value following <key>key_name</key> in a plist file.
fn extract_plist_value(content: &str, key: &str) -> String {
    fn inner(content: &str, key: &str) -> Option<String> {
        let marker    = format!("<key>{}</key>", key);
        let after_key = content.split_once(&marker)?.1;
        let after_tag = after_key.split_once("<string>")?.1;
        Some(after_tag.split_once("</string>")?.0.to_string())
    }
    inner(content, key).unwrap_or_default()
}

// --- Windows ---

fn detect_windows_info(info: &mut SystemInfo) {
    info.distribution = "Windows".to_string();
    info.os_version   = "windows".to_string();
}

// --- Android ---

fn detect_android_info(info: &mut SystemInfo) {
    if std::path::Path::new("/data/data/com.termux").exists() {
        info.is_termux = true;
    }
    if let Some(props) = read_build_properties() {
        let release      = props.get("ro.build.version.release").map(String::as_str).unwrap_or("");
        let sdk          = props.get("ro.build.version.sdk").map(String::as_str).unwrap_or("");
        let manufacturer = props.get("ro.product.manufacturer").map(String::as_str).unwrap_or("");
        let model        = props.get("ro.product.model").map(String::as_str).unwrap_or("");
        info.os_version = match (!release.is_empty(), !sdk.is_empty()) {
            (true,  true)  => format!("Android {} (API {})", release, sdk),
            (true,  false) => format!("Android {}", release),
            (false, true)  => format!("Android API {}", sdk),
            _              => String::new(),
        };
        info.distribution = match (!manufacturer.is_empty(), !model.is_empty()) {
            (true, true)  => format!("{} {}", manufacturer, model),
            (true, false) => manufacturer.to_string(),
            _             => "Android Device".to_string(),
        };
    }
    if info.distribution.is_empty() {
        info.distribution = "Android Device".to_string();
    }
}

fn read_build_properties() -> Option<HashMap<String, String>> {
    for path in &["/system/build.prop", "/default.prop", "/prop.default"] {
        if let Ok(content) = fs::read_to_string(path) {
            let mut props = HashMap::new();
            for line in content.lines() {
                if line.starts_with('#') || !line.contains('=') { continue; }
                // split_once splits on the first '=' only
                if let Some((k, v)) = line.split_once('=') {
                    props.insert(k.trim().to_string(), v.trim().to_string());
                }
            }
            return Some(props);
        }
    }
    None
}

// --- iOS ---

fn detect_ios_info(info: &mut SystemInfo) {
    info.is_jailbroken = check_jailbreak();
    for path in &[
        "/System/Library/CoreServices/SystemVersion.plist",
        "/AppleInternal/Library/SystemVersion.plist",
    ] {
        if let Ok(content) = fs::read_to_string(path) {
            let v = extract_plist_value(&content, "ProductVersion");
            if !v.is_empty() { info.os_version = v; break; }
        }
    }
    if info.os_version.is_empty()   { info.os_version   = "Unknown iOS version".to_string(); }
    if info.distribution.is_empty() { info.distribution = "iOS Device".to_string(); }
}

fn check_jailbreak() -> bool {
    [
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/usr/bin/ssh",
        "/etc/apt",
        "/var/lib/apt",
        "/private/var/lib/apt",
        "/private/var/stash",
    ]
    .iter()
    .any(|p| std::path::Path::new(p).exists())
}

// --- CPU Speed ---

fn detect_cpu_speed() -> f64 {
    match std::env::consts::OS {
        "linux" | "android" => detect_cpu_speed_linux(),
        "macos" | "ios"     => detect_cpu_speed_macos(),
        _                   => 0.0,
    }
}

// Prefers the cpufreq max-frequency sysfs file (kHz).
// Falls back to the current speed reported in /proc/cpuinfo.
fn detect_cpu_speed_linux() -> f64 {
    if let Ok(content) =
        fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq")
    {
        let khz: u64 = content.trim().parse().unwrap_or(0);
        if khz > 0 { return khz as f64 / 1000.0; }
    }
    if let Ok(content) = fs::read_to_string("/proc/cpuinfo") {
        for line in content.lines() {
            if line.starts_with("cpu MHz") {
                if let Some((_, val)) = line.split_once(':') {
                    return val.trim().parse().unwrap_or(0.0);
                }
            }
        }
    }
    0.0
}

// Tries the Intel sysctl key first, then the Apple Silicon performance-core key.
// Neither key exists on Apple Silicon — correctly returns 0 there.
// sysctlbyname does not exist on non-Apple platforms, so it stays inside #[cfg].
fn detect_cpu_speed_macos() -> f64 {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        fn sysctl_u64(name: &[u8]) -> Option<u64> {
            let mut freq: u64 = 0;
            let mut size      = std::mem::size_of::<u64>();
            let ret = unsafe {
                libc::sysctlbyname(
                    name.as_ptr() as *const libc::c_char,
                    &mut freq as *mut u64 as *mut libc::c_void,
                    &mut size,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if ret == 0 && freq > 0 { Some(freq) } else { None }
        }
        if let Some(f) = sysctl_u64(b"hw.cpufrequency_max\0")           { return f as f64 / 1_000_000.0; }
        if let Some(f) = sysctl_u64(b"hw.perflevel0.cpufrequency_max\0") { return f as f64 / 1_000_000.0; }
    }
    #[allow(unreachable_code)]
    0.0
}

fn format_cpu_speed(mhz: f64) -> String {
    if mhz >= 1000.0 { format!("{:.2} GHz", mhz / 1000.0) }
    else             { format!("{:.0} MHz", mhz) }
}

// --- RAM ---

fn detect_ram() -> u64 {
    match std::env::consts::OS {
        "linux" | "android" => detect_ram_linux(),
        "macos" | "ios"     => detect_ram_macos(),
        _                   => 0,
    }
}

fn detect_ram_linux() -> u64 {
    let content = match fs::read_to_string("/proc/meminfo") {
        Ok(c)  => c,
        Err(_) => return 0,
    };
    for line in content.lines() {
        if line.starts_with("MemTotal:") {
            let kb: u64 = line.split_whitespace().nth(1)
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            return kb * 1024;
        }
    }
    0
}

// sysctlbyname("hw.memsize") returns total physical RAM as a u64.
fn detect_ram_macos() -> u64 {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    unsafe {
        let mut mem: u64 = 0;
        let mut size     = std::mem::size_of::<u64>();
        libc::sysctlbyname(
            b"hw.memsize\0".as_ptr() as *const libc::c_char,
            &mut mem as *mut u64 as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        );
        return mem;
    }
    #[allow(unreachable_code)]
    0
}

// --- GPU ---

fn detect_gpu_names() -> Vec<String> {
    match std::env::consts::OS {
        "linux"   => detect_gpu_names_linux(),
        "macos"   => detect_gpu_names_macos(),
        "windows" => detect_gpu_names_windows(),
        _         => Vec::new(),
    }
}

// Reads GPU info from sysfs and /proc without spawning any processes.
// NVIDIA GPUs also expose a model name via /proc/driver/nvidia/gpus/*/information.
fn detect_gpu_names_linux() -> Vec<String> {
    let mut gpus: Vec<String> = Vec::new();

    // NVIDIA: /proc/driver/nvidia/gpus/<pci-addr>/information has "Model: <name>"
    if let Ok(entries) = fs::read_dir("/proc/driver/nvidia/gpus") {
        for entry in entries.flatten() {
            if let Ok(content) = fs::read_to_string(entry.path().join("information")) {
                for line in content.lines() {
                    if let Some(model) = line.strip_prefix("Model:") {
                        let name = model.trim().to_string();
                        if !gpus.contains(&name) { gpus.push(name); }
                    }
                }
            }
        }
    }

    // DRM sysfs: each cardN entry (without dashes) is a display adapter.
    if let Ok(entries) = fs::read_dir("/sys/class/drm") {
        let mut cards: Vec<_> = entries.flatten().collect();
        cards.sort_by_key(|e| e.file_name());
        for entry in cards {
            let fname = entry.file_name();
            let fname = fname.to_string_lossy();
            // Skip connector entries like "card0-HDMI-A-1" — only want bare "cardN"
            if !fname.starts_with("card") || fname.contains('-') { continue; }

            let dev = entry.path().join("device");

            // Some drivers (e.g. virtio-gpu, vmwgfx) expose product_name directly.
            if let Ok(product) = fs::read_to_string(dev.join("product_name")) {
                let product = product.trim().to_string();
                if !product.is_empty() && !gpus.contains(&product) {
                    gpus.push(product);
                    continue;
                }
            }

            // Fallback: map PCI vendor ID to a label. Skip if we already have
            // a specific model name from this vendor (e.g. NVIDIA via procfs above).
            if let Ok(vendor) = fs::read_to_string(dev.join("vendor")) {
                let label = match vendor.trim() {
                    "0x10de" if gpus.iter().any(|g| g.contains("NVIDIA")) => continue,
                    "0x10de" => "NVIDIA GPU",
                    "0x1002" => "AMD GPU",
                    "0x8086" => "Intel GPU",
                    "0x1414" => "Microsoft Virtual GPU",
                    _        => continue,
                };
                if !gpus.contains(&label.to_string()) { gpus.push(label.to_string()); }
            }
        }
    }
    gpus
}

// system_profiler is a standard macOS utility — std::process::Command needs no #[cfg].
// The command simply won't exist if somehow called on another OS, producing an empty result.
fn detect_gpu_names_macos() -> Vec<String> {
    let Ok(output) = std::process::Command::new("system_profiler")
        .arg("SPDisplaysDataType")
        .output()
    else {
        return Vec::new();
    };
    let mut gpus = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if let Some(name) = line.trim().strip_prefix("Chipset Model: ") {
            let name = name.trim().to_string();
            if !gpus.contains(&name) { gpus.push(name); }
        }
    }
    gpus
}

// PowerShell's Get-CimInstance works on Windows 7+; wmic is deprecated on newer Windows.
fn detect_gpu_names_windows() -> Vec<String> {
    let Ok(output) = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", "(Get-CimInstance Win32_VideoController).Name"])
        .output()
    else {
        return Vec::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

// --- Disk ---

// Returns (total_bytes, used_bytes) for the root filesystem (or C:\ on Windows).
fn detect_disk_usage() -> (u64, u64) {
    // statvfs is POSIX — confined inside #[cfg] so this function compiles everywhere.
    #[cfg(unix)]
    unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(b"/\0".as_ptr() as *const libc::c_char, &mut stat) == 0 {
            let total = stat.f_frsize as u64 * stat.f_blocks as u64;
            let free  = stat.f_frsize as u64 * stat.f_bfree  as u64;
            return (total, total - free);
        }
    }
    #[cfg(target_os = "windows")]
    unsafe {
        extern "system" {
            fn GetDiskFreeSpaceExA(path: *const i8, free_available: *mut u64,
                total: *mut u64, total_free: *mut u64) -> i32;
        }
        let mut free_available: u64 = 0;
        let mut total:          u64 = 0;
        let mut total_free:     u64 = 0;
        if GetDiskFreeSpaceExA(b"C:\\\0".as_ptr() as *const i8,
            &mut free_available, &mut total, &mut total_free) != 0
        {
            return (total, total - total_free);
        }
    }
    #[allow(unreachable_code)]
    (0, 0)
}

fn format_bytes(bytes: u64) -> String {
    if bytes == 0 { return "Unknown".to_string(); }
    let units = ["B", "KB", "MB", "GB", "TB", "PB", "EB"];
    let mut val = bytes as f64;
    let mut idx = 0;
    while val >= 1024.0 && idx < units.len() - 1 {
        val /= 1024.0;
        idx += 1;
    }
    if idx == 0 { format!("{} B", bytes) } else { format!("{:.1} {}", val, units[idx]) }
}

fn print_system_info(info: &SystemInfo) {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                    SYSTEM INFORMATION                        ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // Labels are padded to 21 chars so values start at the same column.
    // 🖥️ and ⚠️ get an extra space — their variation selector may render
    // 1-column wide instead of 2 in some terminals.
    println!("🖥️ Hostname:            {}", info.hostname);
    println!("💿 Operating System:    {}", info.os_name);
    if !info.os_version.is_empty() {
        println!("📌 OS Version:          {}", info.os_version);
    }
    if !info.distribution.is_empty() && info.distribution != info.os_name {
        println!("📦 Distribution:        {}", info.distribution);
    }
    if info.is_termux    { println!("📱 Termux Environment:  Yes"); }
    if info.is_jailbroken { println!("⚠️  Jailbroken:          Yes"); }
    println!("🔧 Architecture:        {}", info.arch);
    println!("📊 Endianness:          {}", info.endianness);
    println!("💻 CPU Cores:           {}", info.cpu_cores);
    if info.cpu_speed_mhz > 0.0 {
        println!("⚡ CPU Speed:           {}", format_cpu_speed(info.cpu_speed_mhz));
    }
    if !info.gpu_names.is_empty() {
        println!("🖱️ GPU:                 {}", info.gpu_names[0]);
        for gpu in &info.gpu_names[1..] {
            println!("                        {}", gpu);
        }
    }
    println!("🧠 Total RAM:           {}", format_bytes(info.ram));
    if info.disk_total > 0 {
        let pct = 100 * info.disk_used / info.disk_total;
        println!("💾 Disk Usage:          {} / {} ({}%)",
            format_bytes(info.disk_used), format_bytes(info.disk_total), pct);
    }
    if !info.ip_addresses.is_empty() {
        println!("🌐 IP Addresses:        {}", info.ip_addresses[0]);
        for addr in &info.ip_addresses[1..] {
            println!("                        {}", addr);
        }
    }
}
