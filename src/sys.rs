//! Everything that talks to Windows: bcdedit, the registry, CPU / firmware
//! checks, shutdown.exe and title-bar styling.

use std::ffi::c_void;
use std::os::windows::process::CommandExt;
use std::process::{Command, Output};

use windows_sys::Win32::Graphics::Dwm::DwmSetWindowAttribute;
use windows_sys::Win32::System::Threading::IsProcessorFeaturePresent;
use windows_sys::Win32::UI::WindowsAndMessaging::FindWindowW;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// A three-way reading: the thing is on, off, or we couldn't tell.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tri {
    On,
    Off,
    Unknown,
}

fn run_hidden(program: &str, args: &[&str]) -> std::io::Result<Output> {
    Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
}

// ───────────────────────────── bcdedit ─────────────────────────────

fn bcdedit(args: &[&str]) -> (i32, String) {
    let windir = std::env::var("windir").unwrap_or_else(|_| r"C:\Windows".to_string());
    let exe = format!(r"{windir}\System32\bcdedit.exe");
    match run_hidden(&exe, args) {
        Ok(out) => {
            let text = format!(
                "{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            (out.status.code().unwrap_or(-1), text.trim().to_string())
        }
        Err(e) => (-1, e.to_string()),
    }
}

/// Reads the hypervisor launch type from BCD, or checks CPUID hypervisor bit.
pub fn read_hypervisor() -> Tri {
    let (code, out) = bcdedit(&["/enum", "{current}"]);
    if code == 0 {
        for line in out.lines() {
            let line = line.trim();
            if line.to_ascii_lowercase().starts_with("hypervisorlaunchtype") {
                let value = line
                    .split_whitespace()
                    .last()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                return match value.as_str() {
                    "auto" | "on" => Tri::On,
                    "off" => Tri::Off,
                    _ => Tri::Unknown,
                };
            }
        }
    }
    if hypervisor_present() {
        Tri::On
    } else {
        Tri::Off
    }
}

/// Reads the *configured* test-signing value from the boot configuration.
/// (A change only becomes active after a restart.)
pub fn read_testsigning() -> Tri {
    let (code, out) = bcdedit(&["/enum", "{current}"]);
    if code != 0 {
        return Tri::Unknown;
    }
    for line in out.lines() {
        let line = line.trim();
        if line.to_ascii_lowercase().starts_with("testsigning") {
            let value = line
                .split_whitespace()
                .last()
                .unwrap_or("")
                .to_ascii_lowercase();
            return match value.as_str() {
                "yes" | "on" | "true" => Tri::On,
                "no" | "off" | "false" => Tri::Off,
                _ => Tri::Unknown,
            };
        }
    }
    // bcdedit omits the line entirely when test signing was never set.
    Tri::Off
}

/// Turns test signing on or off. On failure returns bcdedit's first message line.
pub fn set_testsigning(on: bool) -> Result<(), String> {
    let (code, out) = bcdedit(&["/set", "testsigning", if on { "on" } else { "off" }]);
    if code == 0 {
        return Ok(());
    }
    let first = out
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("")
        .chars()
        .take(110)
        .collect::<String>();
    Err(first)
}

// ───────────────────────────── core isolation ─────────────────────────────

/// Core isolation's "Memory integrity" switch (HVCI) lives in this key.
const CORE_ISOLATION_KEY: &str =
    r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity";

/// Reads the *configured* core isolation (memory integrity) value.
/// (A change only becomes active after a restart.)
pub fn read_core_isolation() -> Tri {
    use std::io::ErrorKind;
    use winreg::{enums::HKEY_LOCAL_MACHINE, RegKey};

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = match hklm.open_subkey(CORE_ISOLATION_KEY) {
        Ok(key) => key,
        // No key means it was never switched on.
        Err(e) if e.kind() == ErrorKind::NotFound => return Tri::Off,
        Err(_) => return Tri::Unknown,
    };
    match key.get_value::<u32, _>("Enabled") {
        Ok(1) => Tri::On,
        Ok(_) => Tri::Off,
        Err(e) if e.kind() == ErrorKind::NotFound => Tri::Off,
        Err(_) => Tri::Unknown,
    }
}

/// Reads the *configured* Virtualization-Based Security (VBS) state.
pub fn read_vbs() -> Tri {
    use std::io::ErrorKind;
    use winreg::{enums::HKEY_LOCAL_MACHINE, RegKey};

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = match hklm.open_subkey(r"SYSTEM\CurrentControlSet\Control\DeviceGuard") {
        Ok(key) => key,
        Err(e) if e.kind() == ErrorKind::NotFound => return Tri::Off,
        Err(_) => return Tri::Unknown,
    };
    match key.get_value::<u32, _>("EnableVirtualizationBasedSecurity") {
        Ok(1) => Tri::On,
        Ok(_) => Tri::Off,
        Err(e) if e.kind() == ErrorKind::NotFound => Tri::Off,
        Err(_) => Tri::Unknown,
    }
}

/// Turns core isolation (memory integrity) on or off. On failure returns the
/// Windows error text.
pub fn set_core_isolation(on: bool) -> Result<(), String> {
    use winreg::{enums::HKEY_LOCAL_MACHINE, RegKey};

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let (key, _) = hklm
        .create_subkey(CORE_ISOLATION_KEY)
        .map_err(|e| e.to_string())?;
    key.set_value("Enabled", &u32::from(on))
        .map_err(|e| e.to_string())
}

// ───────────────────── virtualization / Secure Boot ─────────────────────

#[cfg(target_arch = "x86_64")]
fn hypervisor_present() -> bool {
    // CPUID leaf 1, ECX bit 31: set when a hypervisor is running
    // (Hyper-V, VBS, a VM...). Same idea as WMI's HypervisorPresent.
    #[allow(unused_unsafe)]
    let r = unsafe { std::arch::x86_64::__cpuid(1) };
    (r.ecx >> 31) & 1 == 1
}

#[cfg(not(target_arch = "x86_64"))]
fn hypervisor_present() -> bool {
    false
}

pub fn virtualization() -> Tri {
    if hypervisor_present() {
        return Tri::On;
    }
    // 21 = PF_VIRT_FIRMWARE_ENABLED (SVM / VT-x switched on in firmware)
    if unsafe { IsProcessorFeaturePresent(21) } != 0 {
        Tri::On
    } else {
        Tri::Off
    }
}

/// Returns (state, is_legacy_bios).
pub fn secure_boot() -> (Tri, bool) {
    use winreg::{enums::HKEY_LOCAL_MACHINE, RegKey};

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    match hklm.open_subkey(r"SYSTEM\CurrentControlSet\Control\SecureBoot\State") {
        // No SecureBoot\State key at all means a legacy BIOS machine.
        Err(_) => (Tri::Off, true),
        Ok(key) => match key.get_value::<u32, _>("UEFISecureBootEnabled") {
            Ok(1) => (Tri::On, false),
            Ok(_) => (Tri::Off, false),
            Err(_) => (Tri::Unknown, false),
        },
    }
}

// ───────────────────────────── power ─────────────────────────────

/// Runs shutdown.exe; true when it accepted the request.
pub fn shutdown(args: &[&str]) -> bool {
    run_hidden("shutdown.exe", args)
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ───────────────────────────── title bar ─────────────────────────────

const fn rgb(r: u32, g: u32, b: u32) -> u32 {
    r | (g << 8) | (b << 16)
}

/// Copy text to the Windows clipboard.
pub fn copy_to_clipboard(text: &str) -> bool {
    use std::io::Write;
    let mut child = match Command::new("clip.exe")
        .stdin(std::process::Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    if let Some(ref mut stdin) = child.stdin {
        let _ = stdin.write_all(text.as_bytes());
    }
    child.wait().map(|s| s.success()).unwrap_or(false)
}

/// Dark, theme-coloured title bar (Windows 11; harmlessly ignored on 10).
/// Finds the window by its title, so call it once the window exists.
pub fn style_window(title: &str) -> bool {
    let wide: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let hwnd = FindWindowW(std::ptr::null(), wide.as_ptr());
        if hwnd as usize == 0 {
            return false;
        }
        let set = |attr, value: u32| unsafe {
            DwmSetWindowAttribute(hwnd, attr, &value as *const u32 as *const c_void, 4)
        };
        // 20 = immersive dark mode (19 on early Windows 10 builds)
        if set(20, 1) != 0 {
            set(19, 1);
        }
        set(35, rgb(8, 8, 12)); // caption colour
        set(34, rgb(42, 36, 56)); // border colour
        set(36, rgb(245, 245, 250)); // caption text colour
        true
    }
}
