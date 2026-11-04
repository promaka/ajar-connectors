// SPDX-License-Identifier: Apache-2.0
//! The doctor's findings, one per onboarding step, and the terminal report.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    /// Works, but something will bite later; the fix says what.
    Warn,
    Fail,
    /// Not testable from here; the detail says who can.
    Skip,
}

#[derive(Debug, Clone)]
pub struct Finding {
    /// The onboarding step, e.g. "signing key".
    pub step: &'static str,
    pub status: Status,
    pub detail: String,
    /// Present exactly when the status is Warn or Fail.
    pub fix: Option<String>,
}

impl Finding {
    pub fn ok(step: &'static str, detail: impl Into<String>) -> Self {
        Self {
            step,
            status: Status::Ok,
            detail: detail.into(),
            fix: None,
        }
    }
    pub fn warn(step: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            step,
            status: Status::Warn,
            detail: detail.into(),
            fix: Some(fix.into()),
        }
    }
    pub fn fail(step: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            step,
            status: Status::Fail,
            detail: detail.into(),
            fix: Some(fix.into()),
        }
    }
    pub fn skip(step: &'static str, detail: impl Into<String>) -> Self {
        Self {
            step,
            status: Status::Skip,
            detail: detail.into(),
            fix: None,
        }
    }
}

/// The terminal report, and whether the run is healthy (no Fail anywhere).
pub fn render(findings: &[Finding]) -> (String, bool) {
    let mut out = String::new();
    for (i, f) in findings.iter().enumerate() {
        let tag = match f.status {
            Status::Ok => "ok  ",
            Status::Warn => "warn",
            Status::Fail => "FAIL",
            Status::Skip => "note",
        };
        let dots = ".".repeat(24usize.saturating_sub(f.step.len()));
        out.push_str(&format!(
            "{:>2}. {} {} {}  {}\n",
            i + 1,
            f.step,
            dots,
            tag,
            f.detail
        ));
        if let Some(fix) = &f.fix {
            for line in fix.lines() {
                out.push_str(&format!("      -> {line}\n"));
            }
        }
    }
    out.push('\n');
    let failed = findings.iter().filter(|f| f.status == Status::Fail).count();
    let Some(first) = findings.iter().find(|f| f.status == Status::Fail) else {
        out.push_str("Everything the doctor can check from here checks out.\n");
        out.push_str("If events still do not arrive, the refusal is on the operator's side:\n");
        out.push_str("ask them to look at the sink log for your source_id.\n");
        return (out, true);
    };
    out.push_str(&format!(
        "{failed} check(s) failed. Start with the first one: {}.\n",
        first.step
    ));
    (out, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_run_is_healthy_and_points_at_operator() {
        let (text, healthy) = render(&[Finding::ok("config", "loaded")]);
        assert!(healthy);
        assert!(text.contains("ok"));
        assert!(text.contains("sink log for your source_id"));
    }

    #[test]
    fn first_failure_named_and_fix_printed() {
        let findings = vec![
            Finding::ok("config", "loaded"),
            Finding::fail(
                "signing key",
                "seed is 31 bytes",
                "re-mint with ajar-sink mint",
            ),
            Finding::fail("endpoint", "unreachable", "check the address"),
        ];
        let (text, healthy) = render(&findings);
        assert!(!healthy);
        assert!(text.contains("Start with the first one: signing key."));
        assert!(text.contains("-> re-mint with ajar-sink mint"));
    }

    #[test]
    fn warnings_do_not_fail_the_run() {
        let (text, healthy) = render(&[Finding::warn("clock", "cert is fresh", "check date -u")]);
        assert!(healthy);
        assert!(text.contains("warn"));
        assert!(text.contains("-> check date -u"));
    }
}
