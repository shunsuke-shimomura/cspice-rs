extern crate core;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};

const CSPICE_DIR: &str = "CSPICE_DIR";
const CSPICE_CLANG_TARGET: &str = "CSPICE_CLANG_TARGET";
const CSPICE_CLANG_ROOT: &str = "CSPICE_CLANG_ROOT";

// Structure for target information
struct TargetInfo {
    rust_target: String,
    clang_target: String,
    bits: u8,
    cspice_platform: &'static str,
    arch_flags: Vec<String>,
}

impl TargetInfo {
    fn new(target: &str, host: &str) -> Result<Self, String> {
        // Determine bit width
        let bits = determine_bits(target)?;

        // Determine CSPICE download platform
        let cspice_platform = match (env::consts::OS, bits, target) {
            ("linux", 64, _) => "PC_Linux_GCC_64bit",
            ("macos", 64, t) if t.contains("aarch64") => "MacM1_OSX_clang_64bit",
            ("macos", 64, _) => "MacIntel_OSX_AppleC_64bit",
            ("windows", 64, _) => "PC_Windows_VisualC_64bit",
            ("windows", 32, _) => "PC_Windows_VisualC_32bit",
            _ => {
                return Err(format!(
                    "Unsupported platform for CSPICE download: {} {}bit",
                    env::consts::OS,
                    bits
                ))
            }
        };

        // Generate Clang target and flags from Rust target
        let (clang_target, arch_flags) = convert_rust_to_clang_target(target, host);

        Ok(TargetInfo {
            rust_target: target.to_string(),
            clang_target,
            bits,
            cspice_platform,
            arch_flags,
        })
    }
}

fn determine_bits(target: &str) -> Result<u8, String> {
    // Check the first part (architecture) of the target triple
    let arch = target
        .split('-')
        .next()
        .ok_or_else(|| "Invalid target triple".to_string())?;

    match arch {
        // 64-bit architectures
        "x86_64" | "aarch64" | "powerpc64" | "mips64" | "sparc64" => Ok(64),
        // 32-bit architectures
        "i686" | "i586" | "i386" | "arm" | "armv7" | "powerpc" | "mips" | "sparc" => Ok(32),
        // RISC-V
        arch if arch.starts_with("riscv64") => Ok(64),
        arch if arch.starts_with("riscv32") => Ok(32),
        // ARM Thumb
        arch if arch.starts_with("thumbv") => {
            // thumbv6m, thumbv7m, thumbv7em, thumbv8m etc. are all 32-bit
            Ok(32)
        }
        _ => Err(format!(
            "Cannot determine bit width for architecture: {}",
            arch
        )),
    }
}

fn convert_rust_to_clang_target(rust_target: &str, host: &str) -> (String, Vec<String>) {
    let mut arch_flags = Vec::new();

    let clang_target = match rust_target {
        // Apple Silicon
        "aarch64-apple-darwin" => "arm64-apple-darwin".to_string(),
        "aarch64-apple-ios" => "arm64-apple-ios".to_string(),

        // RISC-V - separate CPU extensions
        target if target.starts_with("riscv64gc-") => {
            arch_flags.push("-march=rv64gc".to_string());
            target.replace("riscv64gc-", "riscv64-")
        }
        target if target.starts_with("riscv32gc-") => {
            arch_flags.push("-march=rv32gc".to_string());
            target.replace("riscv32gc-", "riscv32-")
        }

        // Embedded targets - use host target for bindgen
        target
            if target.starts_with("thumbv")
                || (target.contains("-none-") && !target.contains("x86")) =>
        {
            println!(
                "cargo:warning=Using host target '{}' for bindgen instead of '{}'",
                host, rust_target
            );
            host.to_string()
        }

        // Otherwise, use as is
        _ => rust_target.to_string(),
    };

    (clang_target, arch_flags)
}

fn main() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    if std::env::var("DOCS_RS").is_ok() {
        docs_rs(&out_path);
        return;
    }

    // Get environment variables
    let target = env::var("TARGET").expect("TARGET not set");
    let host = env::var("HOST").expect("HOST not set");

    // Parse target information
    let target_info = match TargetInfo::new(&target, &host) {
        Ok(info) => info,
        Err(e) => {
            panic!("Failed to analyze target '{}': {}", target, e);
        }
    };

    println!("cargo:rerun-if-env-changed={}", CSPICE_DIR);
    println!("cargo:rerun-if-env-changed={}", CSPICE_CLANG_TARGET);
    println!("cargo:rerun-if-env-changed={}", CSPICE_CLANG_ROOT);

    let cspice_dir = env::var(CSPICE_DIR)
        .ok()
        .map(PathBuf::from)
        .or_else(locate_cspice);

    #[cfg(feature = "downloadcspice")]
    let cspice_dir = cspice_dir.or_else(|| {
        let downloaded = out_path.join("cspice");
        if !downloaded.exists() {
            println!(
                "Downloading CSPICE for {}",
                target_info.cspice_platform
            );
            download_cspice(&out_path, &target_info);
        }
        Some(downloaded)
    });

    let cspice_dir = cspice_dir.unwrap_or_else(|| {
        panic!(
            "Cannot build: CSPICE_DIR environment variable was not provided, \
             no CSPICE install was found, and feature \"downloadcspice\" is disabled.\n\
             Target: {} ({}bit)\n\
             Would download: {}",
            target_info.rust_target, target_info.bits, target_info.cspice_platform
        )
    });

    if !cspice_dir.is_dir() {
        panic!(
            "Provided {CSPICE_DIR} ({}) is not a directory",
            cspice_dir.display()
        )
    }

    let include_dir = cspice_dir.join("include");

    // Build Clang arguments
    let mut clang_args = target_info.arch_flags.clone();

    // Clang target override from environment variable
    let clang_target = if let Ok(override_target) = env::var(CSPICE_CLANG_TARGET) {
        if !override_target.is_empty() {
            println!(
                "cargo:warning=Using CSPICE_CLANG_TARGET override: {}",
                override_target
            );
            override_target
        } else {
            target_info.clang_target.clone()
        }
    } else {
        target_info.clang_target.clone()
    };

    // Add only if target is not empty (when using host for embedded targets, skip)
    if !clang_target.is_empty() && clang_target != host {
        clang_args.push(format!("--target={}", clang_target));
    }

    // Set sysroot
    if let Ok(sysroot) = env::var(CSPICE_CLANG_ROOT) {
        if !sysroot.is_empty() {
            clang_args.push(format!("--sysroot={}", sysroot));
        }
    }

    // Debug output
    println!(
        "Building for target: {} ({}bit)",
        target_info.rust_target, target_info.bits
    );
    if !clang_args.is_empty() {
        println!("Clang args: {:?}", clang_args);
    }

    let bindings = bindgen::Builder::default()
        .header(include_dir.join("SpiceUsr.h").to_string_lossy())
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .rustfmt_bindings(true)
        .clang_args(clang_args)
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_path.join("bindgen.rs"))
        .expect("Couldn't write bindings!");

    println!(
        "cargo:rustc-link-search=native={}",
        cspice_dir.join("lib").display()
    );
    println!("cargo:rustc-link-lib=static=cspice");
}

// Check for CSPICE installation in system library folders
fn locate_cspice() -> Option<PathBuf> {
    match env::consts::OS {
        "linux" | "macos" if Path::new("/usr/lib/libcspice.a").exists() => {
            println!("Found system CSPICE at /usr");
            Some(PathBuf::from("/usr"))
        }
        _ => None,
    }
}

// Fetch CSPICE source from NAIF servers and extract to `<out_dir>/cspice`
#[cfg(feature = "downloadcspice")]
fn download_cspice(out_dir: &Path, target_info: &TargetInfo) {
    let extension = match env::consts::OS {
        "linux" | "macos" => "tar.Z",
        "windows" => "zip",
        _ => panic!("Cannot download CSPICE for OS: {}", env::consts::OS),
    };

    let url = format!(
        "https://naif.jpl.nasa.gov/pub/naif/toolkit//C/{}/packages/cspice.{}",
        target_info.cspice_platform, extension
    );

    let download_target = out_dir.join(format!("cspice.{}", extension));

    println!("Downloading from: {}", url);
  
    // Tokioランタイムを作成して非同期ダウンロードを実行
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime");

    let downloaded_bytes =
        rt.block_on(async { download_cspice_async(&url, &download_target).await });

    println!("Download complete: {} bytes", downloaded_bytes);

    // Extract package based on platform
    match (env::consts::OS, extension) {
        ("linux" | "macos", "tar.Z") => {
            Command::new("gzip")
                .current_dir(out_dir)
                .args(["-d", "cspice.tar.Z"])
                .status()
                .expect("Failed to extract with gzip");
            Command::new("tar")
                .current_dir(out_dir)
                .args(["xf", "cspice.tar"])
                .status()
                .expect("Failed to extract with tar");

            fs::rename(
                out_dir.join("cspice/lib/cspice.a"),
                out_dir.join("cspice/lib/libcspice.a"),
            )
            .unwrap();
        }
        ("windows", "zip") => {
            Command::new("tar")
                .current_dir(out_dir)
                .args(["xf", "cspice.zip"])
                .status()
                .expect("Failed to extract with tar");
        }
        _ => unreachable!(),
    }

    println!("CSPICE download and extraction complete");
}

// For docs.rs only we will bundle the headers
fn docs_rs(out_dir: &Path) {
    let headers_dir = out_dir.join("docs-rs-headers");
    fs::create_dir_all(&headers_dir).expect("Unable to create CSPICE headers directory");
    let headers_tar = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("docs-rs-headers.tar")
        .canonicalize()
        .unwrap();
    let tar_status = Command::new("tar")
        .arg("-xf")
        .arg(&headers_tar)
        .arg("-C")
        .arg(&headers_dir)
        .status()
        .expect("Unable to call tar");
    assert!(tar_status.success());
    env::set_var("CSPICE_DIR", headers_dir.as_os_str());
}

// Asynchronous download implementation
#[cfg(feature = "downloadcspice")]
async fn download_cspice_async(url: &str, download_target: &PathBuf) -> u64 {
    use futures_util::StreamExt;
    use std::io::Write;

    // HTTP client configuration
    let client = reqwest::Client::builder()
        // Connection timeout: 30 seconds
        .connect_timeout(std::time::Duration::from_secs(30))
        // Read timeout: 60 seconds (maximum wait time for next data chunk)
        .read_timeout(std::time::Duration::from_secs(60))
        // Do not set overall timeout
        .build()
        .expect("Failed to build HTTP client");

    // Send request
    let response = client
        .get(url)
        .send()
        .await
        .expect("Failed to start CSPICE download");

    // Check status code
    if !response.status().is_success() {
        panic!(
            "Failed to download CSPICE: HTTP {} from {}",
            response.status(),
            url
        );
    }

    // Get content size
    let total_size = response.content_length();
    if let Some(size) = total_size {
        println!(
            "Download size: {} bytes ({} MB)",
            size,
            size / (1024 * 1024)
        );
    }

    // Streaming download
    let mut file = std::fs::File::create(download_target).expect("Failed to create download file");

    let mut downloaded = 0u64;
    let mut stream = response.bytes_stream();

    // Show initial progress
    println!("Starting download from {}", url);
    if let Some(total) = total_size {
        println!("Progress: 0 MB / {} MB (0%)", total / (1024 * 1024));
    }

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.expect("Failed to read download chunk");

        file.write_all(&chunk)
            .expect("Failed to write to download file");

        downloaded += chunk.len() as u64;

        // Progress display (every 1MB)
        if downloaded % (1024 * 1024) < chunk.len() as u64 {
            if let Some(total) = total_size {
                let percent = (downloaded as f64 / total as f64 * 100.0) as u32;
                println!(
                    "Progress: {} MB / {} MB ({}%)",
                    downloaded / (1024 * 1024),
                    total / (1024 * 1024),
                    percent
                );
            } else {
                println!("Downloaded {} MB", downloaded / (1024 * 1024));
            }
        }
    }

    file.flush().expect("Failed to flush download file");

    // Verify download completion
    if let Some(total) = total_size {
        if downloaded != total {
            panic!(
                "Download incomplete: got {} bytes, expected {} bytes",
                downloaded, total
            );
        }
    }

    downloaded
}
