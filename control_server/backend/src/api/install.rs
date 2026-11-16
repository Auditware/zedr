use axum::{
    extract::{Query, State},
    response::Response,
    http::{StatusCode, header, HeaderMap},
};
use serde::Deserialize;

use crate::api::binaries::current_agent_version;
use crate::api::AppState;
use crate::enrollment::{self, Credential};
use crate::error::AppError;

const UNIX_INSTALLER: &str = include_str!("install.sh");

#[derive(Deserialize)]
pub struct InstallQuery {
    key: Option<String>,
}

pub async fn serve_windows_installer(
    State(state): State<AppState>,
    Query(query): Query<InstallQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let presented = enrollment::presented_key(&headers, query.key.as_deref())
        .ok_or_else(|| AppError::BadRequest("Missing enrollment key".to_string()))?;
    let agent_version = validate_credential(&state, &presented).await?;

    let script = generate_windows_installer(&server_url()?, &presented, &agent_version);

    Ok(script_response(script))
}

pub async fn serve_unix_installer(
    State(state): State<AppState>,
    Query(query): Query<InstallQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let script = match enrollment::presented_key(&headers, query.key.as_deref()) {
        Some(presented) => {
            let agent_version = validate_credential(&state, &presented).await?;
            generate_unix_installer(&server_url()?, &presented, &agent_version)
        }
        None => generate_unix_installer(&server_url()?, "", &inert(current_agent_version(), "ZEDR_AGENT_VERSION")?),
    };

    Ok(script_response(script))
}

fn script_response(script: String) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store, no-cache, must-revalidate")
        .body(script.into())
        .unwrap()
}

fn server_url() -> Result<String, AppError> {
    let server_url = std::env::var("ZEDR_SERVER_URL")
        .map_err(|_| AppError::Config("ZEDR_SERVER_URL environment variable must be set".to_string()))?;
    inert(server_url, "ZEDR_SERVER_URL")
}

fn is_inert_in_a_script(value: &str) -> bool {
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '/' | '[' | ']' | '@' | '%' | '+' | '=' | ',' | '~'))
}

fn inert(value: String, name: &str) -> Result<String, AppError> {
    if is_inert_in_a_script(&value) {
        Ok(value)
    } else {
        Err(AppError::Config(format!("{} holds characters that cannot be written into an installer script", name)))
    }
}

async fn validate_credential(state: &AppState, presented: &str) -> Result<String, AppError> {
    if !is_inert_in_a_script(presented) {
        return Err(AppError::Unauthorized);
    }

    let credential = enrollment::usable_credential(&state.pool, presented, chrono::Utc::now().timestamp())
        .await?
        .ok_or(AppError::Unauthorized)?;

    match credential {
        Credential::InstallKey { agent_version, .. } => inert(agent_version, "The agent version of the install key"),
        Credential::FleetToken(_) => inert(current_agent_version(), "ZEDR_AGENT_VERSION"),
    }
}

fn generate_windows_installer(server_url: &str, install_key: &str, agent_version: &str) -> String {
    format!(r#"# zedr Agent Windows Installer (Generated)
# Auto-generated from install key: {}

$ErrorActionPreference = "Stop"

Write-Host "zedr Agent Installer v{}" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {{
    Write-Error "This script must be run as Administrator"
    exit 1
}}

$ControlServerUrl = "{}"
$InstallKey = "{}"
$InstallDir = "C:\Program Files\zedr"
$DataDir = "$env:ProgramData\zedr"
$BinaryPath = "$InstallDir\zedr-agent.exe"
$ServiceName = "zedr-agent"

Write-Host "Detecting system architecture..." -ForegroundColor Cyan
$Arch = if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64") {{ "x64" }} elseif ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") {{ "arm64" }} else {{ "x64" }}
Write-Host "Detected architecture: $Arch" -ForegroundColor Cyan

Write-Host "Downloading agent binary..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

Write-Host "Restricting agent data directory to SYSTEM and Administrators..." -ForegroundColor Cyan
icacls $DataDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) {{
    Write-Error "Failed to restrict $DataDir"
    exit 1
}}

$BinaryUrl = "$ControlServerUrl/api/installers/binaries/windows-$Arch" + "?key=$InstallKey"
try {{
    Invoke-WebRequest -Uri $BinaryUrl -OutFile $BinaryPath -UseBasicParsing
}} catch {{
    Write-Error "Failed to download agent binary from $BinaryUrl"
    exit 1
}}

Write-Host "Staging enrollment key..." -ForegroundColor Cyan
Set-Content -Path "$DataDir\enrollment.key" -Value $InstallKey -NoNewline -Encoding ascii

Write-Host "Creating Windows Service..." -ForegroundColor Cyan
$ServiceExists = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($ServiceExists) {{
    Write-Host "Service already exists, stopping..." -ForegroundColor Yellow
    Stop-Service -Name $ServiceName -Force
    sc.exe delete $ServiceName
    Start-Sleep -Seconds 2
}}

sc.exe create $ServiceName binPath= $BinaryPath start= auto
if ($LASTEXITCODE -ne 0) {{
    Write-Error "Failed to create service"
    exit 1
}}

Write-Host "Configuring service recovery actions..." -ForegroundColor Cyan
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000

Write-Host "Setting service description..." -ForegroundColor Cyan
sc.exe description $ServiceName "zedr Endpoint Detection and Response Agent"

Write-Host "Starting service..." -ForegroundColor Cyan
Start-Service -Name $ServiceName

Start-Sleep -Seconds 2
$Service = Get-Service -Name $ServiceName
if ($Service.Status -eq "Running") {{
    Write-Host "`nInstallation completed successfully!" -ForegroundColor Green
    Write-Host "Service Status: Running" -ForegroundColor Green
    Write-Host "Control Server: $ControlServerUrl" -ForegroundColor Cyan
}} else {{
    Write-Error "Service failed to start. Check Windows Event Viewer for details."
    exit 1
}}
"#, &install_key[..12], agent_version, server_url, install_key)
}

fn generate_unix_installer(server_url: &str, enrollment_key: &str, agent_version: &str) -> String {
    UNIX_INSTALLER
        .replace("__ZEDR_SERVER_URL__", server_url)
        .replace("__ZEDR_AGENT_VERSION__", agent_version)
        .replace("__ZEDR_ENROLLMENT_KEY__", enrollment_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unix_installer_fills_every_placeholder() {
        let script = generate_unix_installer("https://zedr.example.test:7770", "zedr_fleet_abc", "0.1.0");

        assert!(script.contains("CONTROL_SERVER_URL=\"https://zedr.example.test:7770\""));
        assert!(script.contains("ENROLLMENT_KEY=\"zedr_fleet_abc\""));
        assert!(script.contains("AGENT_VERSION=\"0.1.0\""));
        assert!(!script.contains("__ZEDR_"));
    }

    #[test]
    fn test_values_that_could_leave_a_quoted_string_are_refused() {
        for value in ["0.1.0", "https://[2001:db8::1]:7770", "zedr_fleet_0123abcd", "v1.2.3-rc.1+build5"] {
            assert!(is_inert_in_a_script(value), "{} is inert", value);
        }
        for value in ["0.1.0\"; id; \"", "$(id)", "`id`", "a b", "a\nb", "a\\b", "a'b", "a;b", "a&b", "a|b"] {
            assert!(!is_inert_in_a_script(value), "{:?} must be refused", value);
        }
    }
}
