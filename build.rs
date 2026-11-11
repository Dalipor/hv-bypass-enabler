use embed_manifest::{embed_manifest, manifest::ExecutionLevel, new_manifest};

fn main() {
    slint_build::compile("ui/app.slint").expect("failed to compile ui/app.slint");

    // Ask Windows for administrator rights at launch (shows the UAC prompt
    // before the window opens). bcdedit needs elevation to change anything.
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        embed_manifest(
            new_manifest("HVEnabler").requested_execution_level(ExecutionLevel::RequireAdministrator),
        )
        .expect("unable to embed the application manifest");

        // The exe's icon (Explorer, taskbar, shortcuts). To use your own,
        // replace icon.ico with another .ico file.
        embed_resource::compile("app.rc", embed_resource::NONE)
            .manifest_optional()
            .unwrap();
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=ui/app.slint");
    println!("cargo:rerun-if-changed=app.rc");
    println!("cargo:rerun-if-changed=icon.ico");
}
