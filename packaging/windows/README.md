# Catchment on Windows

Catchment runs as a native Windows service (Service Control Manager). The
service runs as `NT AUTHORITY\LocalService` (least-privileged built-in
account with network access) and restarts automatically on failure.

## Install

From an elevated PowerShell, in the extracted release zip:

```powershell
.\install-service.ps1 -Config .\catchment.example.toml -EnvFile .\catchment.env
```

The script:

1. copies `catchment.exe` to `C:\Program Files\LLCForge\catchment\`;
2. creates `C:\ProgramData\LLCForge\catchment\` (queue, silences, state) and
   restricts it to SYSTEM, Administrators and LocalService;
3. copies the configuration to `C:\ProgramData\LLCForge\catchment\catchment.toml`
   (an existing file is kept);
4. runs `catchment service install --config <path>`;
5. stores `STATE_DIRECTORY` and the secrets from `-EnvFile` in the service's
   registry `Environment` value and starts the service.

Secrets in the registry are readable by local administrators. Configuration
files only ever contain the *names* of environment variables (`*_env`).

## Manage

```powershell
sc.exe query catchment
Restart-Service catchment          # also reloads configuration
& "C:\Program Files\LLCForge\catchment\catchment.exe" service uninstall
```

`catchment service run` started from a console (not by the SCM) runs in the
foreground, which is handy for debugging; Ctrl-C stops it. The configuration
file is also polled every few seconds, so most edits apply without a restart.

## Firewall

Only open the metrics/health port (9184) to your monitoring hosts:

```powershell
New-NetFirewallRule -DisplayName "Catchment metrics" -Direction Inbound -Protocol TCP -LocalPort 9184 -RemoteAddress 192.0.2.0/24 -Action Allow
```
