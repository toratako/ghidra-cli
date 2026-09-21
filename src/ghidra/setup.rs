use anyhow::{anyhow, Context, Result};
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Deserialize;
use std::fs::File;
use std::io::IsTerminal;
use std::io::Write;
use std::path::{Path, PathBuf};

fn progress_bar(size: u64, quiet: bool) -> ProgressBar {
    if quiet || !std::io::stderr().is_terminal() {
        ProgressBar::hidden()
    } else {
        ProgressBar::new(size)
    }
}

/// GitHub release asset information
#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
    size: u64,
}

/// GitHub release information
#[derive(Deserialize, Debug)]
struct GithubRelease {
    tag_name: String,
    assets: Vec<GithubAsset>,
}

fn release_api_url(version: Option<&str>) -> String {
    let releases = "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases";
    match version {
        Some(version) => format!("{releases}/tags/Ghidra_{version}_build"),
        None => format!("{releases}/latest"),
    }
}

/// Resolve the download URL for a Ghidra release.
/// Version is a release number such as 11.0 or 11.0.1; None fetches the latest release.
pub async fn resolve_version_url(
    version: Option<String>,
    quiet: bool,
) -> Result<(String, String, String)> {
    let mut headers = reqwest::header::HeaderMap::new();
    // Use GITHUB_TOKEN if available (avoids 60 req/hour unauthenticated rate limit)
    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        headers.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", token).parse()?,
        );
    }

    let client = reqwest::Client::builder()
        .user_agent("ghidra-cli")
        .default_headers(headers)
        .build()?;

    let url = release_api_url(version.as_deref());
    let release: GithubRelease = if let Some(ver) = version {
        // Fetch specific version
        if !quiet {
            eprintln!("Fetching release info for Ghidra {}...", ver);
        }
        client
            .get(&url)
            .send()
            .await?
            .error_for_status()
            .context(format!("Could not find Ghidra version {}", ver))?
            .json()
            .await?
    } else {
        // Fetch latest release
        if !quiet {
            eprintln!("Fetching latest Ghidra release info...");
        }
        client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?
    };

    if !quiet {
        eprintln!("Found release: {}", release.tag_name);
    }

    // Find the zip file in assets
    let zip_asset = release
        .assets
        .iter()
        .find(|a| a.name.ends_with(".zip") && !a.name.contains("src"))
        .ok_or_else(|| anyhow!("No zip distribution found in release assets"))?;

    Ok((
        zip_asset.browser_download_url.clone(),
        zip_asset.name.clone(),
        release.tag_name,
    ))
}

/// Download a file with progress bar.
pub async fn download_file(url: &str, path: &Path, quiet: bool) -> Result<()> {
    let client = reqwest::Client::builder()
        .user_agent("ghidra-cli")
        .build()?;

    let res = client
        .get(url)
        .send()
        .await?
        .error_for_status()
        .context("Download request failed")?;

    let total_size = res.content_length().unwrap_or(0);

    let pb = progress_bar(total_size, quiet);
    pb.set_style(ProgressStyle::default_bar()
        .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")?
        .progress_chars("#>-"));
    pb.set_message(format!(
        "Downloading {}",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));

    let mut file = File::create(path)?;
    let mut stream = res.bytes_stream();

    while let Some(item) = stream.next().await {
        let chunk = item.context("Error reading download stream")?;
        file.write_all(&chunk)?;
        pb.inc(chunk.len() as u64);
    }

    pb.finish_with_message("Download complete");
    Ok(())
}

/// Extract a zip file to the target directory.
/// Returns the path to the extracted Ghidra directory.
pub fn extract_zip(zip_path: &Path, target_dir: &Path, quiet: bool) -> Result<PathBuf> {
    if !quiet {
        eprintln!("Extracting...");
    }

    let file = File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    let total_files = archive.len();
    let pb = progress_bar(total_files as u64, quiet);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len}",
            )?
            .progress_chars("#>-"),
    );
    pb.set_message("Extracting files");

    // Track the root directory from the archive
    let mut root_dir: Option<PathBuf> = None;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let enclosed = file
            .enclosed_name()
            .ok_or_else(|| anyhow!("Archive contains an invalid path"))?;
        let first = enclosed
            .components()
            .next()
            .ok_or_else(|| anyhow!("Archive contains an empty path"))?;
        anyhow::ensure!(
            matches!(first, std::path::Component::Normal(_)),
            "Archive must contain a named root directory"
        );
        let entry_root = target_dir.join(first.as_os_str());
        if let Some(root) = &root_dir {
            anyhow::ensure!(
                *root == entry_root,
                "Archive contains multiple root directories"
            );
        } else {
            root_dir = Some(entry_root);
        }
        let outpath = target_dir.join(enclosed);

        if file.name().ends_with('/') {
            std::fs::create_dir_all(&outpath)?;
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    std::fs::create_dir_all(p)?;
                }
            }
            let mut outfile = File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)?;
            // Ghidra compares language sources with their compiled .sla files.
            // Extraction order must not make unchanged sources appear newer.
            if let Some(modified) = file.last_modified() {
                let date = chrono::NaiveDate::from_ymd_opt(
                    modified.year().into(),
                    modified.month().into(),
                    modified.day().into(),
                )
                .and_then(|date| {
                    date.and_hms_opt(
                        modified.hour().into(),
                        modified.minute().into(),
                        modified.second().into(),
                    )
                })
                .context("Archive contains an invalid modification time")?;
                outfile
                    .set_modified(std::time::SystemTime::from(date.and_utc()))
                    .with_context(|| {
                        format!("Preserve modification time of {}", outpath.display())
                    })?;
            }
        }

        // Set permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(mode) = file.unix_mode() {
                std::fs::set_permissions(&outpath, std::fs::Permissions::from_mode(mode)).ok();
            }
        }

        pb.inc(1);
    }

    pb.finish_with_message("Extraction complete");

    root_dir.ok_or_else(|| anyhow!("Could not determine extracted directory"))
}

/// Install Ghidra to the specified directory.
/// Returns the path to the installed Ghidra directory.
pub async fn install_ghidra(
    version: Option<String>,
    target_dir: PathBuf,
    quiet: bool,
) -> Result<PathBuf> {
    // Resolve version and get download URL
    let (download_url, _filename, tag) = resolve_version_url(version, quiet).await?;

    if !quiet {
        eprintln!("Installing Ghidra {} to: {}", tag, target_dir.display());
    }

    std::fs::create_dir_all(&target_dir)?;
    // Download and extraction never share filenames with another invocation or
    // write into a live installation. TempDir cleans up interrupted failures.
    let download = tempfile::Builder::new()
        .prefix(".ghidra-download-")
        .tempdir_in(&target_dir)?;
    let zip_path = download.path().join("distribution.zip");
    download_file(&download_url, &zip_path, quiet).await?;
    publish_archive(&zip_path, &target_dir, quiet)
}

fn publish_archive(zip_path: &Path, target_dir: &Path, quiet: bool) -> Result<PathBuf> {
    std::fs::create_dir_all(target_dir)?;
    let staged = tempfile::Builder::new()
        .prefix(".ghidra-extract-")
        .tempdir_in(target_dir)?;
    let extracted = extract_zip(zip_path, staged.path(), quiet)?;
    super::bridge::find_headless_script(&extracted)
        .context("Installation verification failed before publication")?;
    let root = extracted
        .file_name()
        .ok_or_else(|| anyhow!("Missing installation directory name"))?;
    let destination = target_dir.join(root);
    // Serialize publication; never replace an existing version, including an
    // incomplete tree. --skip-java-check only bypasses the Java prerequisite check.
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(target_dir.join(".ghidra-setup.lock"))?;
    lock.lock()?;
    if destination.try_exists()? {
        super::bridge::find_headless_script(&destination).with_context(|| format!(
            "Existing installation at {} is incomplete; choose another --dir or repair it before retrying", destination.display()))?;
    } else {
        std::fs::rename(&extracted, &destination)?;
    }
    Ok(dunce::canonicalize(destination)?)
}

#[cfg(test)]
mod tests;
