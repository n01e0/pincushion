#![allow(dead_code)]

mod config;
mod diff;
mod fetch;
mod inventory;
mod registry;
mod report;
mod review;
mod signals;
mod state;
mod unpack;

fn main() {
    println!("pincushion scaffold is ready");
}

#[cfg(test)]
mod tests {
    use crate::registry::Ecosystem;

    #[test]
    fn ecosystem_labels_are_stable() {
        assert_eq!(Ecosystem::Npm.as_str(), "npm");
        assert_eq!(Ecosystem::Rubygems.as_str(), "rubygems");
        assert_eq!(Ecosystem::Pypi.as_str(), "pypi");
        assert_eq!(Ecosystem::Crates.as_str(), "crates");
    }
}
