//! The bits of the GitHub API this tool uses.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::json;

/// Where the generated status report starts in a pull request body.
pub const MARKER_START: &str = "<!-- tuf-ci:status -->";

/// Where the generated status report ends in a pull request body.
pub const MARKER_END: &str = "<!-- /tuf-ci:status -->";

/// The name of the check run that reports whether an event can be merged.
pub const CHECK_NAME: &str = "tuf-ci/signatures";

/// A GitHub repository, and a token to act on it with.
pub struct GitHub {
    api: String,
    repo: String,
    token: String,
}

/// A pull request, reduced to the parts this tool needs.
#[derive(Clone, Debug, Deserialize)]
pub struct PullRequest {
    /// The pull request number.
    pub number: u64,
    /// Its description, which is where the status report goes.
    #[serde(default)]
    pub body: Option<String>,
    /// Whether it is open.
    #[serde(default)]
    pub state: String,
}

/// How a check run turned out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Conclusion {
    /// The event is fully signed and can be merged.
    Success,
    /// The event is still gathering signatures. Not a failure — nothing is wrong yet.
    Pending,
    /// The event's metadata is not acceptable.
    Failure,
}

impl Conclusion {
    fn as_str(self) -> &'static str {
        match self {
            Conclusion::Success => "success",
            // `neutral` rather than `failure`: an event part-way through collecting
            // signatures has not failed, it is just not finished. Branch protection still
            // blocks the merge, because only `success` satisfies a required check.
            Conclusion::Pending => "neutral",
            Conclusion::Failure => "failure",
        }
    }
}

impl GitHub {
    /// Build a client from the environment GitHub Actions provides.
    pub fn from_env() -> Result<Self> {
        let token = std::env::var("GITHUB_TOKEN")
            .context("GITHUB_TOKEN is not set; pass the workflow token to this step")?;
        let repo = std::env::var("GITHUB_REPOSITORY")
            .context("GITHUB_REPOSITORY is not set; this command runs inside GitHub Actions")?;
        let api =
            std::env::var("GITHUB_API_URL").unwrap_or_else(|_| "https://api.github.com".to_owned());
        Ok(GitHub {
            api: api.trim_end_matches('/').to_owned(),
            repo,
            token,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}/repos/{}/{path}", self.api, self.repo)
    }

    /// Attach the headers every request needs.
    fn headers<B>(&self, builder: ureq::RequestBuilder<B>) -> ureq::RequestBuilder<B> {
        builder
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("Authorization", format!("Bearer {}", self.token))
            .header("User-Agent", "tuf-ci")
    }

    fn get(&self, url: &str) -> Result<String> {
        read(self.headers(ureq::get(url)).call(), "GET", url)
    }

    fn post(&self, url: &str, body: serde_json::Value) -> Result<String> {
        read(self.headers(ureq::post(url)).send_json(body), "POST", url)
    }

    fn patch(&self, url: &str, body: serde_json::Value) -> Result<String> {
        read(self.headers(ureq::patch(url)).send_json(body), "PATCH", url)
    }

    /// The open pull request for `sha`, if there is one.
    ///
    /// More than one open pull request for the same commit means the report would have to
    /// guess where to go, so that is an error rather than a coin toss.
    pub fn pull_request_for(&self, sha: &str) -> Result<Option<PullRequest>> {
        let body = self.get(&self.url(&format!("commits/{sha}/pulls")))?;
        let all: Vec<PullRequest> =
            serde_json::from_str(&body).context("could not read the list of pull requests")?;
        let mut open: Vec<PullRequest> = all.into_iter().filter(|pr| pr.state == "open").collect();

        match open.len() {
            0 => Ok(None),
            1 => Ok(Some(open.remove(0))),
            n => bail!("{n} open pull requests contain commit {sha}; expected at most one"),
        }
    }

    /// Open a pull request from `head` into `base`.
    pub fn create_pull_request(
        &self,
        head: &str,
        base: &str,
        title: &str,
        body: &str,
    ) -> Result<PullRequest> {
        let response = self.post(
            &self.url("pulls"),
            json!({ "head": head, "base": base, "title": title, "body": body }),
        )?;
        serde_json::from_str(&response).context("could not read the created pull request")
    }

    /// Replace a pull request's description.
    pub fn set_pull_request_body(&self, number: u64, body: &str) -> Result<()> {
        self.patch(
            &self.url(&format!("pulls/{number}")),
            json!({ "body": body }),
        )?;
        Ok(())
    }

    /// Report whether the event at `sha` can be merged.
    ///
    /// This is what branch protection should require: it says the same thing the report
    /// says, in a form the merge button can act on.
    pub fn report_check(
        &self,
        sha: &str,
        conclusion: Conclusion,
        title: &str,
        summary: &str,
    ) -> Result<()> {
        self.post(
            &self.url("check-runs"),
            json!({
                "name": CHECK_NAME,
                "head_sha": sha,
                "status": "completed",
                "conclusion": conclusion.as_str(),
                "output": { "title": title, "summary": summary },
            }),
        )?;
        Ok(())
    }
}

/// Read a response body, turning an HTTP error status into a readable message.
fn read(
    response: std::result::Result<ureq::http::Response<ureq::Body>, ureq::Error>,
    method: &str,
    url: &str,
) -> Result<String> {
    match response {
        Ok(mut response) => response
            .body_mut()
            .read_to_string()
            .with_context(|| format!("reading the response to {method} {url}")),
        Err(ureq::Error::StatusCode(code)) => {
            let hint = match code {
                401 | 403 => {
                    ". Check the token's permissions: this step needs `pull-requests: write` and `checks: write`"
                }
                _ => "",
            };
            bail!("{method} {url} returned HTTP {code}{hint}")
        }
        Err(err) => Err(err).with_context(|| format!("{method} {url} failed")),
    }
}

/// Put `report` into `body` between the markers, leaving everything else alone.
///
/// A pull request description belongs to whoever opened it; the tool owns only the region
/// between its markers. Replacing the whole body on every push would throw away anything a
/// person had written there.
pub fn splice_report(body: &str, report: &str) -> String {
    let block = format!("{MARKER_START}\n{}\n{MARKER_END}", report.trim_end());

    match (body.find(MARKER_START), body.find(MARKER_END)) {
        (Some(start), Some(end)) if end > start => {
            let mut spliced = String::with_capacity(body.len() + block.len());
            spliced.push_str(&body[..start]);
            spliced.push_str(&block);
            spliced.push_str(&body[end + MARKER_END.len()..]);
            spliced
        }
        _ if body.trim().is_empty() => block,
        // Markers missing or malformed: keep whatever is there and append a fresh block
        // rather than overwriting text somebody wrote.
        _ => format!("{}\n\n{block}\n", body.trim_end()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_report_replaces_only_its_own_region() {
        let body = format!(
            "Please review the crates delegation.\n\n{MARKER_START}\nold report\n{MARKER_END}\n\ncc @arlosi"
        );
        let updated = splice_report(&body, "new report");
        assert!(updated.starts_with("Please review the crates delegation."));
        assert!(updated.ends_with("cc @arlosi"));
        assert!(updated.contains("new report"));
        assert!(!updated.contains("old report"));
    }

    #[test]
    fn splicing_is_idempotent() {
        let once = splice_report("", "report");
        let twice = splice_report(&once, "report");
        assert_eq!(once, twice);
    }

    #[test]
    fn an_empty_body_becomes_just_the_report() {
        assert_eq!(
            splice_report("", "report"),
            format!("{MARKER_START}\nreport\n{MARKER_END}")
        );
        assert_eq!(
            splice_report("   \n ", "report"),
            splice_report("", "report")
        );
    }

    #[test]
    fn a_body_without_markers_keeps_its_text() {
        let updated = splice_report("Written by a person.", "report");
        assert!(updated.starts_with("Written by a person."));
        assert!(updated.contains("report"));
        // And a second run then updates in place rather than appending again.
        let again = splice_report(&updated, "newer report");
        assert_eq!(again.matches(MARKER_START).count(), 1);
        assert!(again.starts_with("Written by a person."));
    }

    #[test]
    fn a_body_with_a_mangled_marker_pair_is_not_mangled_further() {
        // End before start: the region is not something we can replace safely.
        let body = format!("{MARKER_END} stray {MARKER_START}");
        let updated = splice_report(&body, "report");
        assert!(updated.starts_with(MARKER_END));
        assert!(updated.contains("report"));
    }

    #[test]
    fn a_pending_event_is_neutral_rather_than_failed() {
        assert_eq!(Conclusion::Pending.as_str(), "neutral");
        assert_eq!(Conclusion::Success.as_str(), "success");
        assert_eq!(Conclusion::Failure.as_str(), "failure");
    }
}
