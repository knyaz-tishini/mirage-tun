//! A probe for the split-tunnel driver: it talks the driver's protocol and
//! prints what the driver says.  It changes no routes and no filters of its
//! own — the driver does that, and the probe only asks.
//!
//! Usage: `split-tunnel-probe [application ...]`
//!
//! With no arguments it probes `node.exe`.  The tunnel and the physical
//! address are taken from the command line or guessed.

use std::net::{IpAddr, Ipv4Addr};

use mirage_tun_windows::split_tunnel::{local_address_for, SplitTunnel};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut applications: Vec<String> = Vec::new();
    let mut tunnel: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);
    let mut internet: Option<Ipv4Addr> = None;
    let mut seconds: u64 = 15;

    for arg in &args {
        if let Some(rest) = arg.strip_prefix("--tunnel=") {
            tunnel = rest.parse().expect("--tunnel= must be an address");
        } else if let Some(rest) = arg.strip_prefix("--internet=") {
            internet = Some(rest.parse().expect("--internet= must be an address"));
        } else if let Some(rest) = arg.strip_prefix("--seconds=") {
            seconds = rest.parse().expect("--seconds= must be a number");
        } else {
            applications.push(arg.clone());
        }
    }
    if applications.is_empty() {
        applications.push("node.exe".to_owned());
    }
    let internet = match internet {
        Some(v) => v,
        None => match local_address_for(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))) {
            Some(v) => v,
            None => {
                eprintln!("the physical address could not be guessed; pass --internet=");
                std::process::exit(2);
            }
        },
    };

    println!("the tunnel address: {tunnel}");
    println!("the physical address: {internet}");
    println!("the applications: {applications:?}");

    match SplitTunnel::engage(tunnel, internet, &applications) {
        Ok(split) => {
            println!("engaged, the driver is in the state {}", split.state().unwrap_or(0));
            println!("waiting for the driver's events ({seconds} s)...");
            std::thread::sleep(std::time::Duration::from_secs(seconds));
            println!("the driver is in the state {}", split.state().unwrap_or(0));
            drop(split);
            println!("disengaged");
        }
        Err(e) => {
            eprintln!("the split-tunnel did not engage: {e}");
            std::process::exit(1);
        }
    }
}
