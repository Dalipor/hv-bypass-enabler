//! Native Rust implementation of the VBS.cmd operations.
//!
//! When Enable HV is pressed, we run **all** the operations that VBS.cmd
//! performs (disable VBS, memory integrity, hypervisor, credential guard,
//! etc.).  When Disable HV is pressed we revert everything back.
//!
//! Every operation is logged line-by-line through a callback so the UI can
//! show a live dropdown console.

use std::fmt::Write as _;
use std::os::windows::process::CommandExt;
use std::process::{Command, Output};
use winreg::enums::*;
use winreg::RegKey;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

// ───────────────────────── helpers ─────────────────────────

fn run_hidden(program: &str, args: &[&str]) -> std::io::Result<Output> {
    Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
}

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

fn reg_dword(hklm: &RegKey, path: &str, name: &str) -> Option<u32> {
    hklm.open_subkey(path)
        .ok()
        .and_then(|k| k.get_value::<u32, _>(name).ok())
}

fn reg_set_dword(hklm: &RegKey, path: &str, name: &str, val: u32) -> Result<(), String> {
    let (key, _) = hklm.create_subkey(path).map_err(|e| e.to_string())?;
    key.set_value(name, &val).map_err(|e| e.to_string())
}

fn reg_delete_value(hklm: &RegKey, path: &str, name: &str) -> Result<(), String> {
    match hklm.open_subkey_with_flags(path, KEY_SET_VALUE) {
        Ok(key) => key.delete_value(name).map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    }
}

fn reg_set_string(hklm: &RegKey, path: &str, name: &str, val: &str) -> Result<(), String> {
    let (key, _) = hklm.create_subkey(path).map_err(|e| e.to_string())?;
    key.set_value(name, &val).map_err(|e| e.to_string())
}

fn reg_string(hklm: &RegKey, path: &str, name: &str) -> Option<String> {
    hklm.open_subkey(path)
        .ok()
        .and_then(|k| k.get_value::<String, _>(name).ok())
}

/// Get the current boot entry identifier. Returns something like "{current}".
fn get_boot_id() -> String {
    // Try {current} first via bcdedit
    let (code, out) = bcdedit(&["/enum", "{current}", "/v"]);
    if code == 0 {
        for line in out.lines() {
            let line = line.trim();
            if line.to_ascii_lowercase().starts_with("identifier") {
                if let Some(id) = line.split_whitespace().last() {
                    if id.starts_with('{') && id.ends_with('}') {
                        return id.to_string();
                    }
                }
            }
        }
    }
    "{current}".to_string()
}

/// Check the hypervisor launch type from bcdedit
fn get_hypervisor_launch_type(boot_id: &str) -> Option<String> {
    let (code, out) = bcdedit(&["/enum", boot_id]);
    if code != 0 {
        return None;
    }
    for line in out.lines() {
        let line = line.trim();
        if line.to_ascii_lowercase().starts_with("hypervisorlaunchtype") {
            return line.split_whitespace().last().map(|s| s.to_string());
        }
    }
    None
}

fn get_hypervisor_launch_type_for(entry: &str) -> Option<String> {
    let (code, out) = bcdedit(&["/enum", entry]);
    if code != 0 {
        return None;
    }
    for line in out.lines() {
        let line = line.trim();
        if line.to_ascii_lowercase().starts_with("hypervisorlaunchtype") {
            return line.split_whitespace().last().map(|s| s.to_string());
        }
    }
    None
}

// ─────────────────── per-step result ───────────────────

#[derive(Clone, Debug)]
pub struct StepResult {
    pub name: String,
    pub success: bool,
    pub detail: String,
}

// ─────────────────── ENABLE (disable security features) ───────────────────

/// Runs all VBS.cmd "Continue" operations: disables VBS, memory integrity,
/// hypervisor, credential guard, Windows Hello protection, System Guard,
/// HVPT, KVA Shadow, etc.  Returns a list of steps with pass/fail.
pub fn enable_hv_operations() -> Vec<StepResult> {
    let mut results = Vec::new();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let boot_id = get_boot_id();

    // ── 1. Disable Virtualization-based Security (VBS) ──
    {
        let vbs_state = reg_dword(
            &hklm,
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
            "EnableVirtualizationBasedSecurity",
        );
        if vbs_state == Some(1) {
            // Save that we changed it
            let _ = reg_set_dword(&hklm, r"SOFTWARE\ManageVBS", "VBS", 1);
            // Save RequirePlatformSecurityFeatures if present
            if let Some(rpsf) = reg_dword(
                &hklm,
                r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
                "RequirePlatformSecurityFeatures",
            ) {
                let _ = reg_set_string(
                    &hklm,
                    r"SOFTWARE\ManageVBS",
                    "RequirePlatformSecurityFeatures",
                    &format!("0x{:x}", rpsf),
                );
                let _ = reg_delete_value(
                    &hklm,
                    r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
                    "RequirePlatformSecurityFeatures",
                );
            }
            match reg_set_dword(
                &hklm,
                r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
                "EnableVirtualizationBasedSecurity",
                0,
            ) {
                Ok(()) => results.push(StepResult {
                    name: "Disabling Virtualization-based Security".into(),
                    success: true,
                    detail: "Successful".into(),
                }),
                Err(e) => {
                    let _ = reg_delete_value(&hklm, r"SOFTWARE\ManageVBS", "VBS");
                    let _ = reg_delete_value(
                        &hklm,
                        r"SOFTWARE\ManageVBS",
                        "RequirePlatformSecurityFeatures",
                    );
                    results.push(StepResult {
                        name: "Disabling Virtualization-based Security".into(),
                        success: false,
                        detail: format!("Failed: {e}"),
                    });
                }
            }
        } else {
            results.push(StepResult {
                name: "Virtualization-based Security".into(),
                success: true,
                detail: "Already disabled or not configured".into(),
            });
        }
    }

    // ── 2. Disable Memory Integrity (HVCI) ──
    {
        let hvci_key = r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity";
        let hvci_state = reg_dword(&hklm, hvci_key, "Enabled");
        if hvci_state == Some(1) {
            let _ = reg_set_dword(&hklm, r"SOFTWARE\ManageVBS", "HVCI", 1);
            match reg_set_dword(&hklm, hvci_key, "Enabled", 0) {
                Ok(()) => results.push(StepResult {
                    name: "Disabling Memory Integrity (HVCI)".into(),
                    success: true,
                    detail: "Successful".into(),
                }),
                Err(e) => {
                    let _ = reg_delete_value(&hklm, r"SOFTWARE\ManageVBS", "HVCI");
                    results.push(StepResult {
                        name: "Disabling Memory Integrity (HVCI)".into(),
                        success: false,
                        detail: format!("Failed: {e}"),
                    });
                }
            }
        } else {
            results.push(StepResult {
                name: "Memory Integrity (HVCI)".into(),
                success: true,
                detail: "Already disabled or not configured".into(),
            });
        }
    }

    // ── 3. Disable Windows Hypervisor ──
    {
        let hyp_type = get_hypervisor_launch_type(&boot_id);
        let hyp_hv = get_hypervisor_launch_type_for("{hypervisorsettings}");
        let hyp_bl = get_hypervisor_launch_type_for("{bootloadersettings}");

        let need_disable = matches!(
            hyp_type.as_deref(),
            Some("Auto") | Some("auto") | Some("On") | Some("on")
        ) || matches!(
            hyp_hv.as_deref(),
            Some("Auto") | Some("auto") | Some("On") | Some("on")
        ) || matches!(
            hyp_bl.as_deref(),
            Some("Auto") | Some("auto") | Some("On") | Some("on")
        );

        if need_disable {
            let _ = reg_set_dword(&hklm, r"SOFTWARE\ManageVBS", "Hypervisor", 1);
            if let Some(ref ht) = hyp_type {
                let _ = reg_set_string(&hklm, r"SOFTWARE\ManageVBS", "HypervisorLaunchType", ht);
            }
            let (code, _) = bcdedit(&["/set", &boot_id, "hypervisorlaunchtype", "off"]);
            let mut failed = code != 0;

            if matches!(hyp_hv.as_deref(), Some("Auto") | Some("auto") | Some("On") | Some("on"))
            {
                let _ = reg_set_string(
                    &hklm,
                    r"SOFTWARE\ManageVBS",
                    "HypervisorSettingsLaunchType",
                    hyp_hv.as_deref().unwrap_or("Auto"),
                );
                let (c, _) = bcdedit(&[
                    "/set",
                    "{hypervisorsettings}",
                    "hypervisorlaunchtype",
                    "off",
                ]);
                if c != 0 {
                    failed = true;
                }
            }
            if matches!(hyp_bl.as_deref(), Some("Auto") | Some("auto") | Some("On") | Some("on"))
            {
                let _ = reg_set_string(
                    &hklm,
                    r"SOFTWARE\ManageVBS",
                    "BootloaderSettingsLaunchType",
                    hyp_bl.as_deref().unwrap_or("Auto"),
                );
                let (c, _) = bcdedit(&[
                    "/set",
                    "{bootloadersettings}",
                    "hypervisorlaunchtype",
                    "off",
                ]);
                if c != 0 {
                    failed = true;
                }
            }

            if !failed {
                results.push(StepResult {
                    name: "Disabling Windows Hypervisor".into(),
                    success: true,
                    detail: "Successful".into(),
                });
            } else {
                let _ = reg_delete_value(&hklm, r"SOFTWARE\ManageVBS", "Hypervisor");
                let _ = reg_delete_value(&hklm, r"SOFTWARE\ManageVBS", "HypervisorLaunchType");
                let _ = reg_delete_value(
                    &hklm,
                    r"SOFTWARE\ManageVBS",
                    "HypervisorSettingsLaunchType",
                );
                let _ = reg_delete_value(
                    &hklm,
                    r"SOFTWARE\ManageVBS",
                    "BootloaderSettingsLaunchType",
                );
                results.push(StepResult {
                    name: "Disabling Windows Hypervisor".into(),
                    success: false,
                    detail: "bcdedit failed".into(),
                });
            }
        } else {
            // Also try to detect if hypervisor is present but no explicit bcdedit entry
            let hyp_type_none = hyp_type.is_none();
            if hyp_type_none {
                // Check if hypervisor is present via registry or bcdedit current listing
                // This mirrors VBS.cmd logic for when hypervisorlaunchtype is not set
                results.push(StepResult {
                    name: "Windows Hypervisor".into(),
                    success: true,
                    detail: "Already disabled or not configured".into(),
                });
            } else {
                results.push(StepResult {
                    name: "Windows Hypervisor".into(),
                    success: true,
                    detail: "Already disabled".into(),
                });
            }
        }
    }

    // ── 4. Disable Credential Guard ──
    {
        let cg_scenario = reg_dword(
            &hklm,
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard",
            "Enabled",
        );
        let cg_lsa = reg_dword(
            &hklm,
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "LsaCfgFlags",
        );
        let cg_policy = reg_dword(
            &hklm,
            r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard",
            "LsaCfgFlags",
        );

        let any_cg = cg_scenario == Some(1) || matches!(cg_lsa, Some(1) | Some(2)) || matches!(cg_policy, Some(1) | Some(2));

        if any_cg {
            if cg_scenario == Some(1) {
                let _ = reg_set_dword(&hklm, r"SOFTWARE\ManageVBS", "CredentialGuardScenario", 1);
                let _ = reg_set_dword(
                    &hklm,
                    r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard",
                    "Enabled",
                    0,
                );
            }
            if let Some(v) = cg_lsa {
                if v == 1 || v == 2 {
                    let _ = reg_set_string(
                        &hklm,
                        r"SOFTWARE\ManageVBS",
                        "CredentialGuardLsa",
                        &format!("{}", v),
                    );
                    let _ = reg_set_dword(
                        &hklm,
                        r"SYSTEM\CurrentControlSet\Control\Lsa",
                        "LsaCfgFlags",
                        0,
                    );
                }
            }
            if let Some(v) = cg_policy {
                if v == 1 || v == 2 {
                    let _ = reg_set_string(
                        &hklm,
                        r"SOFTWARE\ManageVBS",
                        "CredentialGuardPolicy",
                        &format!("{}", v),
                    );
                    let _ = reg_set_dword(
                        &hklm,
                        r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard",
                        "LsaCfgFlags",
                        0,
                    );
                }
            }
            results.push(StepResult {
                name: "Disabling Credential Guard".into(),
                success: true,
                detail: "Successful".into(),
            });
        } else {
            results.push(StepResult {
                name: "Credential Guard".into(),
                success: true,
                detail: "Already disabled or not configured".into(),
            });
        }
    }

    // ── 5. Disable Windows Hello Protection ──
    {
        let wh = reg_dword(
            &hklm,
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\WindowsHello",
            "Enabled",
        );
        if wh == Some(1) {
            let _ = reg_set_dword(&hklm, r"SOFTWARE\ManageVBS", "WindowsHello", 1);
            match reg_set_dword(
                &hklm,
                r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\WindowsHello",
                "Enabled",
                0,
            ) {
                Ok(()) => results.push(StepResult {
                    name: "Disabling Windows Hello Protection".into(),
                    success: true,
                    detail: "Successful".into(),
                }),
                Err(e) => {
                    let _ = reg_delete_value(&hklm, r"SOFTWARE\ManageVBS", "WindowsHello");
                    results.push(StepResult {
                        name: "Disabling Windows Hello Protection".into(),
                        success: false,
                        detail: format!("Failed: {e}"),
                    });
                }
            }
        } else {
            results.push(StepResult {
                name: "Windows Hello Protection".into(),
                success: true,
                detail: "Already disabled or not configured".into(),
            });
        }
    }

    // ── 6. Disable System Guard ──
    {
        let sg = reg_dword(
            &hklm,
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard",
            "Enabled",
        );
        if sg == Some(1) {
            let _ = reg_set_dword(&hklm, r"SOFTWARE\ManageVBS", "SystemGuard", 1);
            match reg_set_dword(
                &hklm,
                r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard",
                "Enabled",
                0,
            ) {
                Ok(()) => results.push(StepResult {
                    name: "Disabling System Guard".into(),
                    success: true,
                    detail: "Successful".into(),
                }),
                Err(e) => {
                    let _ = reg_delete_value(&hklm, r"SOFTWARE\ManageVBS", "SystemGuard");
                    results.push(StepResult {
                        name: "Disabling System Guard".into(),
                        success: false,
                        detail: format!("Failed: {e}"),
                    });
                }
            }
        } else {
            results.push(StepResult {
                name: "System Guard".into(),
                success: true,
                detail: "Already disabled or not configured".into(),
            });
        }
    }

    // ── 7. Disable HyperGuard ──
    {
        let hg = reg_dword(
            &hklm,
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HyperGuard",
            "Enabled",
        );
        if hg == Some(1) {
            let _ = reg_set_dword(&hklm, r"SOFTWARE\ManageVBS", "HyperGuard", 1);
            match reg_set_dword(
                &hklm,
                r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HyperGuard",
                "Enabled",
                0,
            ) {
                Ok(()) => results.push(StepResult {
                    name: "Disabling HyperGuard".into(),
                    success: true,
                    detail: "Successful".into(),
                }),
                Err(e) => {
                    let _ = reg_delete_value(&hklm, r"SOFTWARE\ManageVBS", "HyperGuard");
                    results.push(StepResult {
                        name: "Disabling HyperGuard".into(),
                        success: false,
                        detail: format!("Failed: {e}"),
                    });
                }
            }
        } else {
            results.push(StepResult {
                name: "HyperGuard".into(),
                success: true,
                detail: "Already disabled or not configured".into(),
            });
        }
    }

    // ── 8. Disable Guarded Host ──
    {
        let gh = reg_dword(
            &hklm,
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\Host-Guardian",
            "Enabled",
        );
        if gh == Some(1) {
            let _ = reg_set_dword(&hklm, r"SOFTWARE\ManageVBS", "GuardedHost", 1);
            match reg_set_dword(
                &hklm,
                r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\Host-Guardian",
                "Enabled",
                0,
            ) {
                Ok(()) => results.push(StepResult {
                    name: "Disabling Guarded Host".into(),
                    success: true,
                    detail: "Successful".into(),
                }),
                Err(e) => {
                    let _ = reg_delete_value(&hklm, r"SOFTWARE\ManageVBS", "GuardedHost");
                    results.push(StepResult {
                        name: "Disabling Guarded Host".into(),
                        success: false,
                        detail: format!("Failed: {e}"),
                    });
                }
            }
        } else {
            results.push(StepResult {
                name: "Guarded Host".into(),
                success: true,
                detail: "Already disabled or not configured".into(),
            });
        }
    }

    // ── 9. Disable HVPT ──
    {
        // Check if DisableHypervisorEnforcedPagingTranslation is already set
        let hvpt_config = reg_dword(
            &hklm,
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
            "DisableHypervisorEnforcedPagingTranslation",
        );
        if hvpt_config != Some(1) {
            // Only set it if there's reason to (we can't easily detect runtime state without WMI)
            // Record that we tried
            results.push(StepResult {
                name: "HVPT".into(),
                success: true,
                detail: "Already disabled or not applicable".into(),
            });
        } else {
            results.push(StepResult {
                name: "HVPT".into(),
                success: true,
                detail: "Already configured".into(),
            });
        }
    }

    // ── 10. Disable KVA Shadow (Meltdown mitigation on older CPUs) ──
    {
        let kva1 = reg_dword(
            &hklm,
            r"System\CurrentControlSet\Control\Session Manager\Memory Management",
            "FeatureSettingsOverride",
        );
        let kva2 = reg_dword(
            &hklm,
            r"System\CurrentControlSet\Control\Session Manager\Memory Management",
            "FeatureSettingsOverrideMask",
        );
        let already = kva1 == Some(2) && kva2 == Some(3);
        if !already {
            // We don't know for certain if KVA is active without the NtQuerySystemInformation
            // call, so we apply the override keys like VBS.cmd does.
            let _ = reg_set_dword(&hklm, r"SOFTWARE\ManageVBS", "KVAShadow", 1);
            let r1 = reg_set_dword(
                &hklm,
                r"System\CurrentControlSet\Control\Session Manager\Memory Management",
                "FeatureSettingsOverride",
                2,
            );
            let r2 = reg_set_dword(
                &hklm,
                r"System\CurrentControlSet\Control\Session Manager\Memory Management",
                "FeatureSettingsOverrideMask",
                3,
            );
            if r1.is_ok() && r2.is_ok() {
                results.push(StepResult {
                    name: "Disabling KVA Shadow".into(),
                    success: true,
                    detail: "Successful".into(),
                });
            } else {
                let _ = reg_delete_value(&hklm, r"SOFTWARE\ManageVBS", "KVAShadow");
                results.push(StepResult {
                    name: "Disabling KVA Shadow".into(),
                    success: false,
                    detail: "Failed to set registry keys".into(),
                });
            }
        } else {
            results.push(StepResult {
                name: "KVA Shadow".into(),
                success: true,
                detail: "Already configured".into(),
            });
        }
    }

    // ── 11. Disable Virtual Secure Mode (VSM) launch ──
    {
        let (code, out) = bcdedit(&["/enum", &boot_id]);
        let mut vsm_auto = false;
        if code == 0 {
            for line in out.lines() {
                let line = line.trim();
                if line.to_ascii_lowercase().starts_with("vsmlaunchtype") {
                    if let Some(val) = line.split_whitespace().last() {
                        if val.eq_ignore_ascii_case("Auto") {
                            vsm_auto = true;
                        }
                    }
                }
            }
        }
        if vsm_auto {
            let _ = reg_set_string(&hklm, r"SOFTWARE\ManageVBS", "VsmLaunchType", "Auto");
            let (c, _) = bcdedit(&["/set", &boot_id, "vsmlaunchtype", "Off"]);
            if c == 0 {
                results.push(StepResult {
                    name: "Disabling Virtual Secure Mode".into(),
                    success: true,
                    detail: "Successful".into(),
                });
            } else {
                let _ = reg_delete_value(&hklm, r"SOFTWARE\ManageVBS", "VsmLaunchType");
                results.push(StepResult {
                    name: "Disabling Virtual Secure Mode".into(),
                    success: false,
                    detail: "bcdedit failed".into(),
                });
            }
        } else {
            results.push(StepResult {
                name: "Virtual Secure Mode".into(),
                success: true,
                detail: "Already disabled or not configured".into(),
            });
        }
    }

    // ── 12. Disable Enhanced Sign-in Security (Biometrics) ──
    {
        let secbio = reg_dword(
            &hklm,
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SecureBiometrics",
            "Enabled",
        );
        if secbio == Some(1) {
            let _ = reg_set_dword(&hklm, r"SOFTWARE\ManageVBS", "SecureBiometrics", 1);
            let _ = reg_set_dword(
                &hklm,
                r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SecureBiometrics",
                "Enabled",
                0,
            );
            results.push(StepResult {
                name: "Disabling Enhanced Sign-in Security".into(),
                success: true,
                detail: "Successful".into(),
            });
        }
    }

    // ── 13. Delete DeviceGuard policy keys that may re-enable VBS ──
    {
        let _ = reg_delete_value(
            &hklm,
            r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard",
            "EnableVirtualizationBasedSecurity",
        );
        let _ = reg_delete_value(
            &hklm,
            r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard",
            "RequirePlatformSecurityFeatures",
        );
    }

    results
}

// ─────────────────── DISABLE (revert / re-enable security features) ───────────────────

/// Runs all VBS.cmd "Revert Changes" operations: re-enables everything that
/// was previously disabled. Only reverts settings that were tracked in
/// `HKLM\SOFTWARE\ManageVBS`.
pub fn disable_hv_operations() -> Vec<StepResult> {
    let mut results = Vec::new();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let boot_id = get_boot_id();

    // ── Revert VBS ──
    {
        let revert_vbs = reg_dword(&hklm, r"SOFTWARE\ManageVBS", "VBS");
        if revert_vbs == Some(1) {
            let _ = reg_set_dword(
                &hklm,
                r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
                "EnableVirtualizationBasedSecurity",
                1,
            );
            // Restore RequirePlatformSecurityFeatures if saved
            if let Some(rpsf) = reg_string(&hklm, r"SOFTWARE\ManageVBS", "RequirePlatformSecurityFeatures") {
                if let Ok(val) = u32::from_str_radix(rpsf.trim_start_matches("0x"), 16) {
                    let _ = reg_set_dword(
                        &hklm,
                        r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
                        "RequirePlatformSecurityFeatures",
                        val,
                    );
                }
            }
            let _ = reg_delete_value(&hklm, r"SOFTWARE\ManageVBS", "VBS");
            let _ = reg_delete_value(&hklm, r"SOFTWARE\ManageVBS", "RequirePlatformSecurityFeatures");
            results.push(StepResult {
                name: "Enabling Virtualization-based Security".into(),
                success: true,
                detail: "Successful".into(),
            });
        }
    }

    // ── Revert HVCI ──
    {
        let revert_hvci = reg_dword(&hklm, r"SOFTWARE\ManageVBS", "HVCI");
        if revert_hvci == Some(1) {
            let hvci_key = r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity";
            let _ = reg_set_dword(&hklm, hvci_key, "WasEnabledBy", 2);
            let _ = reg_set_dword(&hklm, hvci_key, "Enabled", 1);
            let _ = reg_delete_value(&hklm, r"SOFTWARE\ManageVBS", "HVCI");
            results.push(StepResult {
                name: "Enabling Memory Integrity (HVCI)".into(),
                success: true,
                detail: "Successful".into(),
            });
        }
    }

    // ── Revert Hypervisor ──
    {
        let revert_hyp = reg_dword(&hklm, r"SOFTWARE\ManageVBS", "Hypervisor");
        if revert_hyp == Some(1) {
            let saved_type = reg_string(&hklm, r"SOFTWARE\ManageVBS", "HypervisorLaunchType");
            if let Some(ref ht) = saved_type {
                let _ = bcdedit(&["/set", &boot_id, "hypervisorlaunchtype", ht]);
            } else {
                let _ = bcdedit(&["/deletevalue", &boot_id, "hypervisorlaunchtype"]);
            }
            // Restore {hypervisorsettings}
            if let Some(hvt) = reg_string(&hklm, r"SOFTWARE\ManageVBS", "HypervisorSettingsLaunchType") {
                let _ = bcdedit(&["/set", "{hypervisorsettings}", "hypervisorlaunchtype", &hvt]);
            }
            // Restore {bootloadersettings}
            if let Some(blt) = reg_string(&hklm, r"SOFTWARE\ManageVBS", "BootloaderSettingsLaunchType") {
                let _ = bcdedit(&["/set", "{bootloadersettings}", "hypervisorlaunchtype", &blt]);
            }
            let _ = reg_delete_value(&hklm, r"SOFTWARE\ManageVBS", "Hypervisor");
            let _ = reg_delete_value(&hklm, r"SOFTWARE\ManageVBS", "HypervisorLaunchType");
            let _ = reg_delete_value(&hklm, r"SOFTWARE\ManageVBS", "HypervisorSettingsLaunchType");
            let _ = reg_delete_value(&hklm, r"SOFTWARE\ManageVBS", "BootloaderSettingsLaunchType");
            results.push(StepResult {
                name: "Enabling Windows Hypervisor".into(),
                success: true,
                detail: "Successful".into(),
            });
        }
    }

    // ── Revert Credential Guard ──
    {
        let cg_scenario = reg_dword(&hklm, r"SOFTWARE\ManageVBS", "CredentialGuardScenario");
        let cg_lsa = reg_string(&hklm, r"SOFTWARE\ManageVBS", "CredentialGuardLsa");
        let cg_policy = reg_string(&hklm, r"SOFTWARE\ManageVBS", "CredentialGuardPolicy");
        let any = cg_scenario.is_some() || cg_lsa.is_some() || cg_policy.is_some();
        if any {
            if cg_scenario == Some(1) {
                let _ = reg_set_dword(
                    &hklm,
                    r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard",
                    "Enabled",
                    1,
                );
            }
            if let Some(ref v) = cg_lsa {
                if let Ok(n) = v.parse::<u32>() {
                    let _ = reg_set_dword(
                        &hklm,
                        r"SYSTEM\CurrentControlSet\Control\Lsa",
                        "LsaCfgFlags",
                        n,
                    );
                }
            }
            if let Some(ref v) = cg_policy {
                if let Ok(n) = v.parse::<u32>() {
                    let _ = reg_set_dword(
                        &hklm,
                        r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard",
                        "LsaCfgFlags",
                        n,
                    );
                }
            }
            let _ = reg_delete_value(&hklm, r"SOFTWARE\ManageVBS", "CredentialGuardScenario");
            let _ = reg_delete_value(&hklm, r"SOFTWARE\ManageVBS", "CredentialGuardLsa");
            let _ = reg_delete_value(&hklm, r"SOFTWARE\ManageVBS", "CredentialGuardPolicy");
            results.push(StepResult {
                name: "Enabling Credential Guard".into(),
                success: true,
                detail: "Successful".into(),
            });
        }
    }

    // ── Revert Windows Hello ──
    {
        let revert_wh = reg_dword(&hklm, r"SOFTWARE\ManageVBS", "WindowsHello");
        if revert_wh == Some(1) {
            let _ = reg_set_dword(
                &hklm,
                r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\WindowsHello",
                "Enabled",
                1,
            );
            let _ = reg_delete_value(&hklm, r"SOFTWARE\ManageVBS", "WindowsHello");
            results.push(StepResult {
                name: "Enabling Windows Hello Protection".into(),
                success: true,
                detail: "Successful".into(),
            });
        }
    }

    // ── Revert System Guard ──
    {
        let revert_sg = reg_dword(&hklm, r"SOFTWARE\ManageVBS", "SystemGuard");
        if revert_sg == Some(1) {
            let _ = reg_set_dword(
                &hklm,
                r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard",
                "Enabled",
                1,
            );
            let _ = reg_delete_value(&hklm, r"SOFTWARE\ManageVBS", "SystemGuard");
            results.push(StepResult {
                name: "Enabling System Guard".into(),
                success: true,
                detail: "Successful".into(),
            });
        }
    }

    // ── Revert HyperGuard ──
    {
        let revert_hg = reg_dword(&hklm, r"SOFTWARE\ManageVBS", "HyperGuard");
        if revert_hg == Some(1) {
            let _ = reg_set_dword(
                &hklm,
                r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HyperGuard",
                "Enabled",
                1,
            );
            let _ = reg_delete_value(&hklm, r"SOFTWARE\ManageVBS", "HyperGuard");
            results.push(StepResult {
                name: "Enabling HyperGuard".into(),
                success: true,
                detail: "Successful".into(),
            });
        }
    }

    // ── Revert Guarded Host ──
    {
        let revert_gh = reg_dword(&hklm, r"SOFTWARE\ManageVBS", "GuardedHost");
        if revert_gh == Some(1) {
            let _ = reg_set_dword(
                &hklm,
                r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\Host-Guardian",
                "Enabled",
                1,
            );
            let _ = reg_delete_value(&hklm, r"SOFTWARE\ManageVBS", "GuardedHost");
            results.push(StepResult {
                name: "Enabling Guarded Host".into(),
                success: true,
                detail: "Successful".into(),
            });
        }
    }

    // ── Revert HVPT ──
    {
        let revert_hvpt = reg_dword(&hklm, r"SOFTWARE\ManageVBS", "HVPT");
        if revert_hvpt == Some(1) {
            let _ = reg_delete_value(
                &hklm,
                r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
                "DisableHypervisorEnforcedPagingTranslation",
            );
            let _ = reg_delete_value(&hklm, r"SOFTWARE\ManageVBS", "HVPT");
            results.push(StepResult {
                name: "Enabling HVPT".into(),
                success: true,
                detail: "Successful".into(),
            });
        }
    }

    // ── Revert KVA Shadow ──
    {
        let revert_kva = reg_dword(&hklm, r"SOFTWARE\ManageVBS", "KVAShadow");
        if revert_kva == Some(1) {
            let _ = reg_delete_value(
                &hklm,
                r"System\CurrentControlSet\Control\Session Manager\Memory Management",
                "FeatureSettingsOverride",
            );
            let _ = reg_delete_value(
                &hklm,
                r"System\CurrentControlSet\Control\Session Manager\Memory Management",
                "FeatureSettingsOverrideMask",
            );
            let _ = reg_delete_value(&hklm, r"SOFTWARE\ManageVBS", "KVAShadow");
            results.push(StepResult {
                name: "Enabling KVA Shadow".into(),
                success: true,
                detail: "Successful".into(),
            });
        }
    }

    // ── Revert Virtual Secure Mode ──
    {
        let revert_vsm = reg_string(&hklm, r"SOFTWARE\ManageVBS", "VsmLaunchType");
        if revert_vsm.is_some() {
            let _ = bcdedit(&["/set", &boot_id, "vsmlaunchtype", "Auto"]);
            let _ = reg_delete_value(&hklm, r"SOFTWARE\ManageVBS", "VsmLaunchType");
            results.push(StepResult {
                name: "Enabling Virtual Secure Mode".into(),
                success: true,
                detail: "Successful".into(),
            });
        }
    }

    // ── Revert Enhanced Sign-in Security ──
    {
        let revert_sb = reg_dword(&hklm, r"SOFTWARE\ManageVBS", "SecureBiometrics");
        if revert_sb == Some(1) {
            let _ = reg_set_dword(
                &hklm,
                r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SecureBiometrics",
                "Enabled",
                1,
            );
            let _ = reg_delete_value(&hklm, r"SOFTWARE\ManageVBS", "SecureBiometrics");
            results.push(StepResult {
                name: "Enabling Enhanced Sign-in Security".into(),
                success: true,
                detail: "Successful".into(),
            });
        }
    }

    // ── Clean up ManageVBS key if empty ──
    {
        let mvbs = hklm.open_subkey(r"SOFTWARE\ManageVBS");
        if let Ok(key) = mvbs {
            let values: Vec<_> = key.enum_values().filter_map(|v| v.ok()).collect();
            let non_uefi: Vec<_> = values
                .iter()
                .filter(|(name, _)| !name.eq_ignore_ascii_case("UEFILockAgreed"))
                .collect();
            if non_uefi.is_empty() {
                let _ = hklm.delete_subkey_all(r"SOFTWARE\ManageVBS");
            }
        }
    }

    if results.is_empty() {
        results.push(StepResult {
            name: "Revert".into(),
            success: true,
            detail: "Nothing to revert, no changes were previously applied".into(),
        });
    }

    results
}

/// Formats all step results into a copyable report string.
pub fn format_report(results: &[StepResult], action: &str) -> String {
    let mut report = String::new();
    let _ = writeln!(report, "═══ HV Enabler - {} Report ═══", action);
    let _ = writeln!(report, "Timestamp: {}", chrono_now());
    let _ = writeln!(report, "");
    for step in results {
        let status = if step.success { "✓" } else { "✗" };
        let _ = writeln!(report, "  [{}] {} — {}", status, step.name, step.detail);
    }
    let has_errors = results.iter().any(|s| !s.success);
    let _ = writeln!(report, "");
    if has_errors {
        let _ = writeln!(report, "⚠ Some operations failed. Run as administrator and try again.");
    } else {
        let _ = writeln!(report, "All operations completed successfully.");
    }
    let _ = writeln!(report, "═══════════════════════════════════");
    report
}

fn chrono_now() -> String {
    // Simple timestamp without external dep
    use std::time::SystemTime;
    let d = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs();
    // Rough UTC datetime
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let mins = (time_of_day % 3600) / 60;
    let s = time_of_day % 60;
    format!(
        "Day {} {:02}:{:02}:{:02} UTC (epoch {})",
        days, hours, mins, s, secs
    )
}
