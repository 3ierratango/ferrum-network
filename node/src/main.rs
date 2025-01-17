//! Substrate Node Template CLI library.
#![warn(missing_docs)]

mod chain_spec;
#[macro_use]
mod service;
mod cli;
mod command;
mod config;
mod rpc;

fn main() -> sc_cli::Result<()> {
    command::run()
}
