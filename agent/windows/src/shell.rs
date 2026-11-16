use std::process::Command;

pub fn powershell(command_text: &str) -> Command {
    let wrapped_command = format!(
        "$ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         try {{ \
             $result = & {{ {} }}; \
             if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}; \
             if ($result -ne $null) {{ Write-Output $result }}; \
             exit 0 \
         }} catch {{ \
             Write-Error $_.Exception.Message; \
             exit 1 \
         }}",
        command_text.replace("\"", "`\"").replace("$", "`$")
    );

    let mut command = Command::new("powershell.exe");
    command.args([
        "-ExecutionPolicy", "Bypass",
        "-NoProfile",
        "-NoLogo",
        "-NonInteractive",
        "-Command",
        &wrapped_command,
    ]);
    command
}
