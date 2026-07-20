use chrono::Utc;
use sentinel_core::{
    DeterministicSentinelGuard, GuardPolicy, GuardRule, SentinelGuard, SentinelGuardRequest,
    PROTECTED_ACTIONS,
};
use serde::Serialize;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;

const PASS: &str = "PASS";
const FAIL: &str = "FAIL";

#[derive(Debug, Clone)]
pub struct CertifyConfig {
    pub repo: PathBuf,
    pub product: String,
    pub strict: bool,
    pub output_dir: Option<PathBuf>,
    pub no_write: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CertificationReport {
    pub product: String,
    pub repository: String,
    pub strict: bool,
    pub passed: bool,
    pub checks: Vec<CertificationCheck>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CertificationCheck {
    pub id: String,
    pub status: String,
    pub detail: String,
    pub evidence: Vec<String>,
}

pub fn run_from_env() -> i32 {
    let args = env::args().skip(1).collect::<Vec<_>>();
    run(args, &mut std::io::stdout(), &mut std::io::stderr())
}

pub fn run(args: Vec<String>, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    if args.is_empty() || args[0] == "--help" || args[0] == "help" {
        let _ = writeln!(stdout, "{}", help_text());
        return 0;
    }

    match args[0].as_str() {
        "certify" => match parse_certify_args(&args[1..]) {
            Ok(config) => match certify(config) {
                Ok((report, writes)) => {
                    let _ = writeln!(
                        stdout,
                        "Sentinel certification {} for {}",
                        if report.passed { "PASSED" } else { "FAILED" },
                        report.product
                    );
                    for path in writes {
                        let _ = writeln!(stdout, "wrote {}", path.display());
                    }
                    if report.passed {
                        0
                    } else {
                        2
                    }
                }
                Err(err) => {
                    let _ = writeln!(stderr, "certify failed: {err}");
                    1
                }
            },
            Err(err) => {
                let _ = writeln!(stderr, "{err}");
                let _ = writeln!(stderr, "{}", help_text());
                1
            }
        },
        other => {
            let _ = writeln!(stderr, "unknown command: {other}");
            let _ = writeln!(stderr, "{}", help_text());
            1
        }
    }
}

pub fn certify(config: CertifyConfig) -> Result<(CertificationReport, Vec<PathBuf>), String> {
    let repo = normalize_path(&config.repo);
    let mut checks = Vec::new();

    checks.push(check_repo_exists(&repo));
    checks.push(check_git_repository(&repo));
    if config.strict {
        checks.push(check_git_clean(&repo));
    }
    checks.extend(check_security_docs(&repo, &config.product));
    checks.push(check_protected_action_inventory(&repo));
    checks.push(check_source_patterns(
        &repo,
        "source_stub_markers",
        stub_patterns(),
        "no executable source stub markers found",
    ));
    checks.push(check_source_patterns(
        &repo,
        "sentinel_bypass_flags",
        bypass_patterns(),
        "no Sentinel bypass or shadow-mode flags found in executable source",
    ));
    checks.push(check_guard_self_test());

    let passed = checks.iter().all(|check| check.status == PASS);
    let report = CertificationReport {
        product: config.product,
        repository: repo.display().to_string(),
        strict: config.strict,
        passed,
        checks,
    };

    let writes = if config.no_write {
        Vec::new()
    } else {
        let output_dir = config
            .output_dir
            .unwrap_or_else(|| repo.join("target").join("sentinel-certification"));
        write_reports(&report, &output_dir)?
    };

    Ok((report, writes))
}

fn parse_certify_args(args: &[String]) -> Result<CertifyConfig, String> {
    let mut repo = None;
    let mut product = None;
    let mut strict = false;
    let mut output_dir = None;
    let mut no_write = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--repo" => {
                i += 1;
                repo = Some(PathBuf::from(
                    args.get(i)
                        .ok_or_else(|| "--repo requires a path".to_string())?,
                ));
            }
            "--product" => {
                i += 1;
                product = Some(
                    args.get(i)
                        .ok_or_else(|| "--product requires a name".to_string())?
                        .to_string(),
                );
            }
            "--strict" => strict = true,
            "--output-dir" => {
                i += 1;
                output_dir = Some(PathBuf::from(
                    args.get(i)
                        .ok_or_else(|| "--output-dir requires a path".to_string())?,
                ));
            }
            "--no-write" => no_write = true,
            "--help" => return Err(help_text()),
            unknown => return Err(format!("unknown certify option: {unknown}")),
        }
        i += 1;
    }

    Ok(CertifyConfig {
        repo: repo.ok_or_else(|| "certify requires --repo <path>".to_string())?,
        product: product.ok_or_else(|| "certify requires --product <name>".to_string())?,
        strict,
        output_dir,
        no_write,
    })
}

fn help_text() -> String {
    [
        "sentinel commands:",
        "",
        "  sentinel certify --repo <path> --product <name> --strict [--output-dir <path>] [--no-write]",
        "",
        "Certification enforces Sentinel adoption docs, protected-action inventory coverage,",
        "strict Git cleanliness, source stub scans, bypass-flag scans, and guard fail-closed",
        "self-tests. Reports are deterministic so a clean tree can stay clean after reruns.",
    ]
    .join("\n")
}

fn normalize_path(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn pass(id: &str, detail: impl Into<String>, evidence: Vec<String>) -> CertificationCheck {
    CertificationCheck {
        id: id.to_string(),
        status: PASS.to_string(),
        detail: detail.into(),
        evidence,
    }
}

fn fail(id: &str, detail: impl Into<String>, evidence: Vec<String>) -> CertificationCheck {
    CertificationCheck {
        id: id.to_string(),
        status: FAIL.to_string(),
        detail: detail.into(),
        evidence,
    }
}

fn check_repo_exists(repo: &Path) -> CertificationCheck {
    if repo.is_dir() {
        pass(
            "repo_exists",
            "repository path exists",
            vec![repo.display().to_string()],
        )
    } else {
        fail(
            "repo_exists",
            "repository path does not exist or is not a directory",
            vec![repo.display().to_string()],
        )
    }
}

fn check_git_repository(repo: &Path) -> CertificationCheck {
    match git(repo, &["rev-parse", "--is-inside-work-tree"]) {
        Ok(output) if output.trim() == "true" => pass(
            "git_repository",
            "path is inside a Git worktree",
            vec![repo.display().to_string()],
        ),
        Ok(output) => fail(
            "git_repository",
            "path is not a Git worktree",
            vec![output.trim().to_string()],
        ),
        Err(err) => fail("git_repository", "git worktree check failed", vec![err]),
    }
}

fn check_git_clean(repo: &Path) -> CertificationCheck {
    match git(repo, &["status", "--porcelain=v1"]) {
        Ok(output) if output.trim().is_empty() => pass(
            "strict_git_clean",
            "working tree was clean before report write",
            Vec::new(),
        ),
        Ok(output) => fail(
            "strict_git_clean",
            "working tree was dirty before report write",
            output
                .lines()
                .take(50)
                .map(|line| line.to_string())
                .collect(),
        ),
        Err(err) => fail("strict_git_clean", "git status check failed", vec![err]),
    }
}

fn check_security_docs(repo: &Path, product: &str) -> Vec<CertificationCheck> {
    let security_dir = repo.join("docs").join("security");
    let required = [
        (
            "master_plan_doc",
            security_dir.join("SENTINEL_IMPERVIOUS_PROTOCOL_MASTER_PLAN.md"),
            vec![
                "Let there be no gate before the Sentinel",
                "No Sentinel, no ship",
            ],
        ),
        (
            "adoption_status_doc",
            security_dir.join("SENTINEL_ADOPTION_STATUS.md"),
            vec![product, "enforce"],
        ),
        (
            "protected_actions_doc",
            security_dir.join("SENTINEL_PROTECTED_ACTIONS.md"),
            vec!["Protected Action", "Release Handling"],
        ),
    ];

    required
        .into_iter()
        .map(|(id, path, required_strings)| check_doc_contains(id, &path, required_strings))
        .collect()
}

fn check_doc_contains(id: &str, path: &Path, required_strings: Vec<&str>) -> CertificationCheck {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) => {
            return fail(
                id,
                "required Sentinel security document is missing or unreadable",
                vec![format!("{}: {err}", path.display())],
            )
        }
    };

    let content_lower = content.to_lowercase();
    let missing = required_strings
        .iter()
        .filter(|needle| !content_lower.contains(&needle.to_lowercase()))
        .map(|needle| needle.to_string())
        .collect::<Vec<_>>();

    if missing.is_empty() {
        pass(
            id,
            "required Sentinel security document is present and contains release-critical markers",
            vec![path.display().to_string()],
        )
    } else {
        fail(
            id,
            "required Sentinel security document is missing release-critical markers",
            missing
                .into_iter()
                .map(|needle| format!("missing `{needle}` in {}", path.display()))
                .collect(),
        )
    }
}

fn check_protected_action_inventory(repo: &Path) -> CertificationCheck {
    let path = repo
        .join("docs")
        .join("security")
        .join("SENTINEL_PROTECTED_ACTIONS.md");
    let content = match fs::read_to_string(&path) {
        Ok(content) => content,
        Err(err) => {
            return fail(
                "protected_action_inventory",
                "protected action inventory is missing or unreadable",
                vec![format!("{}: {err}", path.display())],
            )
        }
    };

    let missing = PROTECTED_ACTIONS
        .iter()
        .filter(|action| !content.contains(**action))
        .map(|action| action.to_string())
        .collect::<Vec<_>>();

    if missing.is_empty() {
        pass(
            "protected_action_inventory",
            "inventory explicitly classifies every canonical Sentinel protected action",
            vec![format!(
                "{} actions covered in {}",
                PROTECTED_ACTIONS.len(),
                path.display()
            )],
        )
    } else {
        fail(
            "protected_action_inventory",
            "inventory does not cover every canonical Sentinel protected action",
            missing,
        )
    }
}

fn check_source_patterns(
    repo: &Path,
    id: &str,
    patterns: Vec<String>,
    pass_detail: &str,
) -> CertificationCheck {
    let files = match source_files(repo) {
        Ok(files) => files,
        Err(err) => {
            return fail(
                id,
                "source scan failed before completion",
                vec![format!("{err}")],
            )
        }
    };

    let mut hits = Vec::new();
    for file in files {
        let Ok(content) = fs::read_to_string(&file) else {
            continue;
        };
        for (line_no, line) in content.lines().enumerate() {
            for pattern in &patterns {
                if line.contains(pattern) {
                    hits.push(format!(
                        "{}:{} contains `{}`",
                        file.display(),
                        line_no + 1,
                        pattern
                    ));
                }
            }
        }
    }

    if hits.is_empty() {
        pass(id, pass_detail, Vec::new())
    } else {
        fail(id, "forbidden source pattern found", hits)
    }
}

fn check_guard_self_test() -> CertificationCheck {
    let guard =
        DeterministicSentinelGuard::new(GuardPolicy::deny_all("certification-deny-all", "strict"));

    for action in PROTECTED_ACTIONS {
        let decision = guard.authorize(&guard_request(action));
        if decision.authorizes_effect() {
            return fail(
                "guard_deny_all_self_test",
                "deny-all policy authorized a protected action",
                vec![action.to_string()],
            );
        }
    }

    let unknown_guard = DeterministicSentinelGuard::new(GuardPolicy::explicit(
        "certification-explicit",
        "strict",
        vec![GuardRule::allow(
            "allow-unknown-test",
            "unknown.execute",
            "workspace://certification/protected",
            "certification.runtime",
            "sentinel-certification",
            "unknown action must still deny",
        )],
    ));
    let unknown_decision = unknown_guard.authorize(&guard_request("unknown.execute"));
    if unknown_decision.authorizes_effect() {
        return fail(
            "guard_unknown_action_self_test",
            "unknown action was authorized by explicit policy",
            vec!["unknown.execute".to_string()],
        );
    }

    pass(
        "guard_fail_closed_self_test",
        "deny-all policy denies every protected action and unknown actions deny even under explicit policy",
        vec![format!("{} protected actions tested", PROTECTED_ACTIONS.len())],
    )
}

fn guard_request(action: &str) -> SentinelGuardRequest {
    SentinelGuardRequest {
        envelope_version: "sentinel.guard.v1".to_string(),
        action: action.to_string(),
        resource: "workspace://certification/protected".to_string(),
        actor_id: Uuid::new_v4(),
        actor_class: "certification.runtime".to_string(),
        subject_system: "sentinel-certification".to_string(),
        request_origin: "sentinel-certify".to_string(),
        timestamp_utc: Utc::now(),
        nonce: Uuid::new_v4(),
        payload_hash: "sha256:certification-payload".to_string(),
        context_digest: "sha256:certification-context".to_string(),
        requested_capability: Some("capability:certification".to_string()),
        consent_reference: None,
        declared_intent: "prove Sentinel fail-closed certification behavior".to_string(),
        irreversible_side_effect: false,
        external_impact: false,
        envelope_digest: "sha256:certification-envelope".to_string(),
    }
}

fn write_reports(report: &CertificationReport, output_dir: &Path) -> Result<Vec<PathBuf>, String> {
    fs::create_dir_all(output_dir)
        .map_err(|err| format!("could not create {}: {err}", output_dir.display()))?;

    let markdown_path = output_dir.join("SENTINEL_CERTIFICATION_REPORT.md");
    let json_path = output_dir.join("SENTINEL_CERTIFICATION_REPORT.json");

    fs::write(&markdown_path, report.to_markdown())
        .map_err(|err| format!("could not write {}: {err}", markdown_path.display()))?;
    let json = serde_json::to_string_pretty(report)
        .map_err(|err| format!("could not serialize certification report: {err}"))?;
    fs::write(&json_path, format!("{json}\n"))
        .map_err(|err| format!("could not write {}: {err}", json_path.display()))?;

    Ok(vec![markdown_path, json_path])
}

impl CertificationReport {
    fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("# Sentinel Certification Report\n\n");
        out.push_str("This report is deterministic by design. It omits timestamps so rerunning certification does not dirty a clean release tree.\n\n");
        out.push_str(&format!("Product: `{}`\n", self.product));
        out.push_str(&format!("Repository: `{}`\n", self.repository));
        out.push_str(&format!("Strict mode: `{}`\n", self.strict));
        out.push_str(&format!(
            "Result: `{}`\n\n",
            if self.passed { "PASS" } else { "FAIL" }
        ));
        out.push_str("## Checks\n\n");
        out.push_str("| Check | Status | Detail |\n");
        out.push_str("| --- | --- | --- |\n");
        for check in &self.checks {
            out.push_str(&format!(
                "| `{}` | `{}` | {} |\n",
                table_escape(&check.id),
                check.status,
                table_escape(&check.detail)
            ));
        }

        out.push_str("\n## Evidence\n\n");
        for check in &self.checks {
            out.push_str(&format!("### `{}`\n\n", check.id));
            if check.evidence.is_empty() {
                out.push_str("- No additional evidence.\n\n");
            } else {
                for item in &check.evidence {
                    out.push_str(&format!("- `{}`\n", item.replace('`', "'")));
                }
                out.push('\n');
            }
        }
        out
    }
}

fn table_escape(value: &str) -> String {
    value.replace('|', "\\|")
}

fn git(repo: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .map_err(|err| format!("failed to launch git: {err}"))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(if stderr.is_empty() {
            format!("git exited with status {}", output.status)
        } else {
            stderr
        })
    }
}

fn source_files(repo: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut files = Vec::new();
    collect_source_files(repo, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_source_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), std::io::Error> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            if should_skip_dir(&name) {
                continue;
            }
            collect_source_files(&path, files)?;
        } else if is_source_file(&path) {
            files.push(path);
        }
    }
    Ok(())
}

fn should_skip_dir(name: &OsStr) -> bool {
    matches!(
        name.to_string_lossy().as_ref(),
        ".git"
            | "target"
            | "node_modules"
            | ".venv"
            | "venv"
            | "env"
            | "dist"
            | "build"
            | "__pycache__"
    )
}

fn is_source_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(OsStr::to_str),
        Some("rs" | "py" | "ts" | "tsx" | "js" | "jsx")
    )
}

fn stub_patterns() -> Vec<String> {
    vec![
        format!("{}!(", "todo"),
        format!("{}!(", "unimplemented"),
        format!("panic!(\"{}", "TODO"),
        format!("panic!(\"{}", "todo"),
        format!("raise {}Error", "NotImplemented"),
        format!("throw new Error(\"{}\")", "not implemented"),
        format!("{}_{}", "SENTINEL", "STUB"),
        format!("{}_{}", "TODO", "SENTINEL"),
    ]
}

fn bypass_patterns() -> Vec<String> {
    vec![
        format!("{}_WITHOUT_{}", "ALLOW", "SENTINEL"),
        format!("{}_{}", "DISABLE", "SENTINEL"),
        format!("{}_{}", "SENTINEL", "BYPASS"),
        format!("{}_{}", "BYPASS", "SENTINEL"),
        format!("{}_{}", "SENTINEL", "DISABLED"),
        format!("{}_{}_{}", "SENTINEL", "SHADOW", "MODE"),
        format!("{}_{}", "SHADOW", "SENTINEL"),
        format!("{}_MODE={}", "SENTINEL", "shadow"),
        format!("{}_ALLOW_WITHOUT_{}", "ARCHETYPES", "CHRONOS"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_certify_command_requires_repo_and_product() {
        let err = parse_certify_args(&["--repo".to_string(), ".".to_string()])
            .expect_err("product is required");
        assert!(err.contains("--product"));
    }

    #[test]
    fn markdown_report_is_deterministic() {
        let report = CertificationReport {
            product: "sentinel-core".to_string(),
            repository: "C:\\sentinel-core".to_string(),
            strict: true,
            passed: true,
            checks: vec![pass("example", "stable", vec!["proof".to_string()])],
        };

        assert_eq!(report.to_markdown(), report.to_markdown());
        assert!(!report.to_markdown().contains("Generated"));
    }

    #[test]
    fn guard_self_test_passes() {
        let check = check_guard_self_test();
        assert_eq!(check.status, PASS);
    }
}
