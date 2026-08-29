// SPDX-License-Identifier: Apache-2.0
//! The doctor's findings, one per onboarding step, rendered for a human who is
//! staring at a connector that publishes nothing.

/// How a single check ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The step is provably fine.
    Ok,
    /// The step works but something will bite later; the fix says what.
    Warn,
    /// This step is broken and the fix says what to do about it.
    Fail,
    /// The doctor could not test this step here; the detail says who can.
    Skip,
}

/// One check's outcome: what was seen, and when not fine, what to do.
#[derive(Debug, Clone)]
pub struct Finding {
    /// The onboarding step this check belongs to, e.g. "signing key".
    pub step: &'static str,
    pub status: Status,
    /// What the doctor observed, in plain words.
    pub detail: String,
    /// What to do next. Present exactly when the status is Warn or Fail.
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

/// Render the findings as the terminal report. Returns the text and whether
/// the run counts as healthy (no Fail anywhere).
pub fn render(findings: &[Finding]) -> (String, bool) {
    let mut out = String::new();
    let mut failed = 0usize;
    for (i, f) in findings.iter().enumerate() {
        let tag = match f.status {
            Status::Ok => "ok  ",
            Status::Warn => "warn",
            Status::Fail => "FAIL",
            Status::Skip => "note",
        };
        if f.status == Status::Fail {
            failed += 1;
        }
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
    if failed == 0 {
        out.push_str("Everything the doctor can check from here checks out.\n");
        out.push_str("If events still do not arrive, the refusal is on the operator's side:\n");
        out.push_str("ask them to look at the sink log for your source_id.\n");
    } else {
        let first = findings
            .iter()
            .find(|f| f.status == Status::Fail)
            .expect("counted a failure");
        out.push_str(&format!(
            "{failed} check(s) failed. Start with the first one: {}.\n",
            first.step
        ));
    }
    (out, failed == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clean_run_reports_healthy_and_points_at_the_operator() {
        let (text, healthy) = render(&[Finding::ok("config", "loaded")]);
        assert!(healthy);
        assert!(text.contains("ok"));
        assert!(text.contains("sink log for your source_id"));
    }

    #[test]
    fn the_first_failure_is_named_and_the_fix_is_printed() {
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
