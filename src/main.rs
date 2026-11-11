#![windows_subsystem = "windows"]

mod sys;
mod vbs_ops;

use std::cell::Cell;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use slint::{ComponentHandle, ModelRc, SharedString, Timer, TimerMode, VecModel};
use sys::Tri;

slint::include_modules!();

const WINDOW_TITLE: &str = "HV Enabler";

// ─────────────────── log line helpers ───────────────────

/// Determine the tone of a log line based on its content prefix.
fn line_tone(s: &str) -> Tone {
    if s.contains("[✗]") {
        Tone::Bad
    } else if s.contains("[✓]") || s.starts_with("✓") {
        Tone::Good
    } else if s.starts_with("⚠") {
        Tone::Warn
    } else if s.starts_with("═") {
        Tone::Checking // reuse checking for the header/separator lines (pink tint)
    } else {
        Tone::Neutral
    }
}

fn make_log_line(text: &str) -> LogLine {
    LogLine {
        text: SharedString::from(text),
        tone: line_tone(text),
    }
}

// ───────────────────────────── state ─────────────────────────────

/// What the dashboard knows. `None` means "still checking".
#[derive(Clone, Copy)]
struct Model {
    vbs: Option<Tri>,
    hyp: Option<Tri>,
    ts: Option<Tri>,
    /// Core isolation (memory integrity).
    ci: Option<Tri>,
    virt: Option<Tri>,
    sb: Option<Tri>,
    legacy: bool,
    /// HV settings were changed this session and a restart is still needed.
    pending: bool,
}

impl Model {
    const fn new() -> Self {
        Self {
            vbs: None,
            hyp: None,
            ts: None,
            ci: None,
            virt: None,
            sb: None,
            legacy: false,
            pending: false,
        }
    }
}

thread_local! {
    // Only ever touched on the UI thread (background threads hand their
    // results over with `upgrade_in_event_loop`).
    static MODEL: Cell<Model> = Cell::new(Model::new());
}

fn update(f: impl FnOnce(&mut Model)) -> Model {
    MODEL.with(|cell| {
        let mut m = cell.get();
        f(&mut m);
        cell.set(m);
        m
    })
}

// ───────────────────────────── view ─────────────────────────────

fn view(text: &str, tone: Tone) -> RowView {
    RowView {
        text: text.into(),
        tone,
    }
}

fn tri_word(t: Option<Tri>) -> &'static str {
    match t {
        None => "…",
        Some(Tri::On) => "On",
        Some(Tri::Off) => "Off",
        Some(Tri::Unknown) => "Unknown",
    }
}

fn render(ui: &MainWindow, m: &Model) {
    // HV Bypass requires VBS to be OFF and Hypervisor to be OFF
    let hv_ready = m.vbs == Some(Tri::Off) && m.hyp == Some(Tri::Off);
    let hv_wrong = m.vbs == Some(Tri::On) || m.hyp == Some(Tri::On);
    let hv = if m.vbs.is_none() || m.hyp.is_none() {
        view("Checking…", Tone::Checking)
    } else if m.pending {
        view("Restart pending", Tone::Warn)
    } else if hv_ready {
        view("Ready", Tone::Good)
    } else if hv_wrong {
        view("Not ready", Tone::Bad)
    } else {
        view("Unknown", Tone::Neutral)
    };
    let hv_detail = format!(
        "VBS: {}  ·  Hypervisor: {}",
        tri_word(m.vbs),
        tri_word(m.hyp)
    );
    let virt = match m.virt {
        None => view("Checking…", Tone::Checking),
        Some(Tri::On) => view("Enabled", Tone::Good),
        Some(Tri::Off) => view("Disabled", Tone::Bad),
        Some(Tri::Unknown) => view("Unknown", Tone::Neutral),
    };
    let sb = match m.sb {
        None => view("Checking…", Tone::Checking),
        Some(Tri::Off) if m.legacy => view("Legacy BIOS", Tone::Good),
        Some(Tri::Off) => view("Disabled", Tone::Good),
        Some(Tri::On) => view("Enabled", Tone::Bad),
        Some(Tri::Unknown) => view("Unknown", Tone::Neutral),
    };

    let checking = m.vbs.is_none() || m.hyp.is_none() || m.virt.is_none() || m.sb.is_none();
    let ready = hv_ready && m.virt == Some(Tri::On) && m.sb == Some(Tri::Off);
    let status = if checking {
        "Checking system readiness…"
    } else if ready {
        "System is fully HV ready"
    } else {
        "System is not HV ready yet. Check the requirements below."
    };

    ui.set_hv(hv);
    ui.set_hv_detail(hv_detail.into());
    ui.set_virt(virt);
    ui.set_sb(sb);
    ui.set_status_text(status.into());
    ui.set_status_ready(ready && !checking);
}

fn show_banner(ui: &MainWindow, kind: BannerKind, title: &str, detail: &str) {
    ui.set_banner_title(title.into());
    ui.set_banner_detail(detail.into());
    ui.set_banner_kind(kind);
}

// ───────────────────────────── actions ─────────────────────────────

/// Re-reads everything off the UI thread so the window stays smooth.
fn refresh(ui: &MainWindow) {
    let m = update(|m| {
        m.vbs = None;
        m.hyp = None;
        m.ts = None;
        m.ci = None;
        m.virt = None;
        m.sb = None;
    });
    render(ui, &m);

    let weak = ui.as_weak();
    std::thread::spawn(move || {
        let vbs = sys::read_vbs();
        let hyp = sys::read_hypervisor();
        let ts = sys::read_testsigning();
        let ci = sys::read_core_isolation();
        let virt = sys::virtualization();
        let (sb, legacy) = sys::secure_boot();
        // The checks are near-instant; hold the "checking" state for a beat
        // so the change is visible rather than a flicker.
        std::thread::sleep(Duration::from_millis(450));
        let _ = weak.upgrade_in_event_loop(move |ui| {
            let m = update(|m| {
                m.vbs = Some(vbs);
                m.hyp = Some(hyp);
                m.ts = Some(ts);
                m.ci = Some(ci);
                m.virt = Some(virt);
                m.sb = Some(sb);
                m.legacy = legacy;
            });
            render(&ui, &m);
        });
    });
}

/// Which step of Enable / Disable HV failed.
enum HvError {
    CoreIsolation(String),
    TestSigning(String),
}

/// Enable HV:  core isolation off, then test signing on.
/// Disable HV: core isolation on, then test signing off.
/// A core isolation step that is already in the right state is skipped.
fn apply_hv(enable: bool) -> Result<(), HvError> {
    let want_ci = if enable { Tri::Off } else { Tri::On };
    if sys::read_core_isolation() != want_ci {
        sys::set_core_isolation(!enable).map_err(HvError::CoreIsolation)?;
    }
    sys::set_testsigning(enable).map_err(HvError::TestSigning)
}

#[derive(Clone, Copy)]
enum Action {
    Restart,
    Firmware,
}

impl Action {
    fn title(self, secs: u32) -> String {
        match self {
            Action::Restart => format!("Restarting in {secs}s…"),
            Action::Firmware => format!("Opening firmware setup in {secs}s…"),
        }
    }
}

/// 5-second countdown that can be cancelled, then runs shutdown.exe.
fn start_countdown(ui: &MainWindow, timer: &Rc<Timer>, action: Action) {
    const SECONDS: u32 = 5;

    let left = Rc::new(Cell::new(SECONDS));
    show_banner(
        ui,
        BannerKind::Countdown,
        &action.title(SECONDS),
        "Save your work first. Select Cancel to stop.",
    );

    let weak = ui.as_weak();
    let timer_ref = Rc::downgrade(timer);
    timer.start(TimerMode::Repeated, Duration::from_secs(1), move || {
        let Some(ui) = weak.upgrade() else { return };

        let n = left.get().saturating_sub(1);
        left.set(n);
        if n > 0 {
            ui.set_banner_title(action.title(n).into());
            return;
        }

        if let Some(t) = timer_ref.upgrade() {
            t.stop();
        }
        let ok = match action {
            Action::Restart => sys::shutdown(&["/r", "/t", "0"]),
            Action::Firmware => sys::shutdown(&["/r", "/fw", "/t", "0"]),
        };
        if ok {
            show_banner(&ui, BannerKind::Info, "Restarting now…", "");
        } else {
            let (title, detail) = match action {
                Action::Restart => (
                    "Couldn't restart",
                    "Windows didn't accept the restart request. Restart manually instead.",
                ),
                Action::Firmware => (
                    "Couldn't open firmware setup",
                    "This PC may not support it. Restart manually and press Del or F2 during startup.",
                ),
            };
            show_banner(&ui, BannerKind::Error, title, detail);
        }
    });
}

// ─────────────────── log panel helpers ───────────────────

/// Shared log buffer between threads and the UI.
type LogBuffer = Arc<Mutex<Vec<String>>>;

/// Shared report buffer for "Copy Report".
type ReportBuffer = Arc<Mutex<String>>;

fn push_log(buf: &LogBuffer, line: &str) {
    if let Ok(mut v) = buf.lock() {
        v.push(line.to_string());
    }
}

fn flush_log_to_ui(ui: &MainWindow, buf: &LogBuffer) {
    if let Ok(v) = buf.lock() {
        let model: Vec<LogLine> = v.iter().map(|s| make_log_line(s)).collect();
        ui.set_log_lines(ModelRc::new(VecModel::from(model)));
    }
}

// ───────────────────────────── main ─────────────────────────────

fn main() -> Result<(), slint::PlatformError> {
    let ui = MainWindow::new()?;
    let countdown = Rc::new(Timer::default());

    // Shared log and report buffers
    let log_buf: LogBuffer = Arc::new(Mutex::new(Vec::new()));
    let report_buf: ReportBuffer = Arc::new(Mutex::new(String::new()));

    ui.on_refresh({
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                refresh(&ui);
            }
        }
    });

    ui.on_set_hv({
        let weak = ui.as_weak();
        let log_buf = log_buf.clone();
        let report_buf = report_buf.clone();
        move |enable| {
            let Some(ui) = weak.upgrade() else { return };

            let word = if enable { "enabled" } else { "disabled" };
            let (want_vbs, want_hyp) = if enable {
                (Tri::Off, Tri::Off)
            } else {
                (Tri::On, Tri::On)
            };
            let (want_ci, want_ts) = if enable {
                (Tri::Off, Tri::On)
            } else {
                (Tri::On, Tri::Off)
            };

            let current = MODEL.with(|c| c.get());
            if current.vbs == Some(want_vbs) && current.hyp == Some(want_hyp) && !current.pending {
                show_banner(
                    &ui,
                    BannerKind::Info,
                    &format!("HV Bypass is already {word}"),
                    "There's nothing to change.",
                );
                return;
            }

            // Clear log and show the log panel
            if let Ok(mut v) = log_buf.lock() {
                v.clear();
            }
            ui.set_log_lines(ModelRc::new(VecModel::from(Vec::<LogLine>::new())));
            ui.set_show_log(true);
            ui.set_log_has_errors(false);

            let weak = ui.as_weak();
            let log_buf_thread = log_buf.clone();
            let report_buf_thread = report_buf.clone();
            std::thread::spawn(move || {
                // Phase 1: Run the VBS CMD operations
                let action_word = if enable { "Enable HV Bypass" } else { "Disable HV Bypass" };
                push_log(&log_buf_thread, &format!("═══ {} — Starting VBS operations ═══", action_word));

                let vbs_results = if enable {
                    push_log(&log_buf_thread, "Running VBS disable operations...");
                    // Update the UI with progress
                    {
                        let weak2 = weak.clone();
                        let buf2 = log_buf_thread.clone();
                        let _ = weak2.upgrade_in_event_loop(move |ui| {
                            flush_log_to_ui(&ui, &buf2);
                        });
                    }
                    std::thread::sleep(Duration::from_millis(200));
                    vbs_ops::enable_hv_operations()
                } else {
                    push_log(&log_buf_thread, "Reverting VBS changes...");
                    {
                        let weak2 = weak.clone();
                        let buf2 = log_buf_thread.clone();
                        let _ = weak2.upgrade_in_event_loop(move |ui| {
                            flush_log_to_ui(&ui, &buf2);
                        });
                    }
                    std::thread::sleep(Duration::from_millis(200));
                    vbs_ops::disable_hv_operations()
                };

                // Log each VBS step result
                let mut has_errors = false;
                for step in &vbs_results {
                    let icon = if step.success { "✓" } else { "✗" };
                    push_log(
                        &log_buf_thread,
                        &format!("  [{}] {} — {}", icon, step.name, step.detail),
                    );
                    if !step.success {
                        has_errors = true;
                    }
                    // Flush to UI after each step for live feel
                    {
                        let weak2 = weak.clone();
                        let buf2 = log_buf_thread.clone();
                        let err = has_errors;
                        let _ = weak2.upgrade_in_event_loop(move |ui| {
                            flush_log_to_ui(&ui, &buf2);
                            if err {
                                ui.set_log_has_errors(true);
                            }
                        });
                    }
                    std::thread::sleep(Duration::from_millis(120));
                }

                push_log(&log_buf_thread, "");

                // Phase 2: Run the original core isolation + test signing
                push_log(&log_buf_thread, "Applying core isolation and test signing changes...");
                {
                    let weak2 = weak.clone();
                    let buf2 = log_buf_thread.clone();
                    let _ = weak2.upgrade_in_event_loop(move |ui| {
                        flush_log_to_ui(&ui, &buf2);
                    });
                }

                let result = apply_hv(enable);
                let vbs = sys::read_vbs();
                let hyp = sys::read_hypervisor();
                let ci = sys::read_core_isolation();
                let ts = sys::read_testsigning();

                match &result {
                    Ok(()) => {
                        push_log(
                            &log_buf_thread,
                            &format!("  [✓] Core isolation — {}", if enable { "Disabled" } else { "Enabled" }),
                        );
                        push_log(
                            &log_buf_thread,
                            &format!("  [✓] Test signing — {}", if enable { "Enabled" } else { "Disabled" }),
                        );
                    }
                    Err(HvError::CoreIsolation(reason)) => {
                        push_log(
                            &log_buf_thread,
                            &format!("  [✗] Core isolation — Failed: {}", reason),
                        );
                        has_errors = true;
                    }
                    Err(HvError::TestSigning(reason)) => {
                        push_log(
                            &log_buf_thread,
                            &format!("  [✓] Core isolation — {}", if enable { "Disabled" } else { "Enabled" }),
                        );
                        push_log(
                            &log_buf_thread,
                            &format!("  [✗] Test signing — Failed: {}", reason),
                        );
                        has_errors = true;
                    }
                }

                push_log(&log_buf_thread, "");
                if has_errors {
                    push_log(&log_buf_thread, "⚠ Some operations failed. Check errors above.");
                } else {
                    push_log(&log_buf_thread, &format!("✓ All operations completed. HV Bypass {}.", word));
                }
                push_log(&log_buf_thread, "═══════════════════════════════════");

                // Generate report
                let report = vbs_ops::format_report(&vbs_results, action_word);
                if let Ok(mut r) = report_buf_thread.lock() {
                    *r = report;
                }

                // Final UI update
                let final_has_errors = has_errors;
                let _ = weak.upgrade_in_event_loop(move |ui| {
                    flush_log_to_ui(&ui, &log_buf_thread);
                    if final_has_errors {
                        ui.set_log_has_errors(true);
                    }

                    let keep = |now: Tri, want: Tri| if now == Tri::Unknown { want } else { now };
                    match result {
                        Ok(()) => {
                            let m = update(|m| {
                                m.vbs = Some(keep(vbs, want_vbs));
                                m.hyp = Some(keep(hyp, want_hyp));
                                m.ci = Some(keep(ci, want_ci));
                                m.ts = Some(keep(ts, want_ts));
                                m.pending = true;
                            });
                            render(&ui, &m);
                            show_banner(
                                &ui,
                                BannerKind::Restart,
                                &format!("HV Bypass {word}"),
                                "Restart your PC to apply the change.",
                            );
                        }
                        Err(err) => {
                            // Show what actually got changed before the failure.
                            let m = update(|m| {
                                m.vbs = Some(vbs);
                                m.hyp = Some(hyp);
                                m.ci = Some(ci);
                                m.ts = Some(ts);
                            });
                            render(&ui, &m);
                            match err {
                                HvError::CoreIsolation(reason) => show_banner(
                                    &ui,
                                    BannerKind::Error,
                                    "Couldn't change core isolation",
                                    &format!("Run the app as administrator and try again.\n{reason}"),
                                ),
                                HvError::TestSigning(reason) if enable => show_banner(
                                    &ui,
                                    BannerKind::Error,
                                    "Couldn't change test signing",
                                    &format!(
                                        "Secure Boot is the usual cause. Turn it off in BIOS first.\n{reason}"
                                    ),
                                ),
                                HvError::TestSigning(reason) => show_banner(
                                    &ui,
                                    BannerKind::Error,
                                    "Couldn't change test signing",
                                    &reason,
                                ),
                            }
                        }
                    }
                });
            });
        }
    });

    ui.on_restart_now({
        let weak = ui.as_weak();
        let timer = countdown.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                start_countdown(&ui, &timer, Action::Restart);
            }
        }
    });

    ui.on_reboot_firmware({
        let weak = ui.as_weak();
        let timer = countdown.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                start_countdown(&ui, &timer, Action::Firmware);
            }
        }
    });

    ui.on_cancel_countdown({
        let weak = ui.as_weak();
        let timer = countdown.clone();
        move || {
            timer.stop();
            if let Some(ui) = weak.upgrade() {
                ui.set_banner_kind(BannerKind::None);
            }
        }
    });

    ui.on_dismiss_banner({
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_banner_kind(BannerKind::None);
            }
        }
    });

    // ── New callbacks for the log panel ──

    ui.on_toggle_log({
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                let current = ui.get_show_log();
                ui.set_show_log(!current);
            }
        }
    });

    ui.on_close_log({
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_show_log(false);
            }
        }
    });

    ui.on_copy_report({
        let report_buf = report_buf.clone();
        let weak = ui.as_weak();
        move || {
            let text = if let Ok(r) = report_buf.lock() {
                r.clone()
            } else {
                "Failed to read report.".to_string()
            };
            let ok = sys::copy_to_clipboard(&text);
            if let Some(ui) = weak.upgrade() {
                if ok {
                    show_banner(
                        &ui,
                        BannerKind::Info,
                        "Report copied",
                        "The report has been copied to your clipboard.",
                    );
                } else {
                    show_banner(
                        &ui,
                        BannerKind::Error,
                        "Copy failed",
                        "Couldn't copy to clipboard.",
                    );
                }
            }
        }
    });

    // Colour the title bar once the native window exists (try twice in case
    // the first attempt lands before it is created).
    for ms in [120u64, 600] {
        Timer::single_shot(Duration::from_millis(ms), || {
            sys::style_window(WINDOW_TITLE);
        });
    }

    refresh(&ui);
    ui.run()
}
