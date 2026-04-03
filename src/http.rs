use std::time::Duration;

use reqwest::blocking::Client;

pub fn user_agent() -> String {
    format!(
        "{}/{} (+https://github.com/n01e0/pincushion)",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    )
}

pub fn blocking_client(timeout: Duration) -> Result<Client, reqwest::Error> {
    Client::builder()
        .timeout(timeout)
        .user_agent(user_agent())
        .build()
}

pub fn blocking_client_no_redirect(timeout: Duration) -> Result<Client, reqwest::Error> {
    Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(user_agent())
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_agent_mentions_project_and_repo() {
        let user_agent = user_agent();
        assert!(user_agent.starts_with("pincushion/"));
        assert!(user_agent.contains("github.com/n01e0/pincushion"));
    }
}
