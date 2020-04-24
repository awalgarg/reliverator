use regex::Regex;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Result;

use crate::tls;

#[derive(Clone)]
pub struct Config {
    pub myname: String,
    pub aliases: HashMap<String, String>,
    pub wildcards: HashMap<String, String>,
    pub domains: HashSet<String>,
    pub relay: bool,
    pub ssl: bool,
    pub skipverify: bool,
}

pub fn readconfig(filename: &String) -> Result<Config> {
    let mut myname = "localhost".to_string();
    let mut certfile = "".to_string();
    let mut keyfile = "".to_string();
    let mut aliases = HashMap::new();
    let mut wildcards = HashMap::new();
    let mut domains = HashSet::new();
    let mut skipverify = false;

    let file = File::open(filename)?;
    for line in BufReader::new(file).lines() {
        let line = line?;
        let v: Vec<&str> = line.trim().split(' ').collect();
        if v.len() == 0 {
            continue;
        }
        match v[0] {
            "alias" => {
                aliases.insert(v[1].to_string(), v[2].to_string());
            }
            "wildcard" => {
                wildcards.insert(v[1].to_string(), v[2].to_string());
            }
            "domain" => {
                domains.insert(v[1].to_string());
            }
            "servername" => {
                myname = v[1].to_string();
            }
            "certfile" => {
                certfile = v[1].to_string();
            }
            "keyfile" => {
                keyfile = v[1].to_string();
            }
            "option" => match v[1] {
                "skipverify" => {
                    skipverify = true;
                }
                _ => {
                    println!("unknown config option {}", v[0]);
                }
            },
            _ => {
                println!("unknown config option {}", v[0]);
            }
        }
    }

    let mut ssl = false;
    if certfile != "" && keyfile != "" {
        tls::init(certfile, keyfile)?;
        ssl = true;
    }

    return Ok(Config {
        myname: myname,
        aliases: aliases,
        wildcards: wildcards,
        domains: domains,
        relay: false,
        ssl: ssl,
        skipverify: skipverify,
    });
}

fn split_addr(addr: &String) -> (String, String) {
    let re = Regex::new("([a-zA-Z0-9]+)([a-zA-Z0-9._+]*)@?([a-zA-Z0-9_.]*)").unwrap();
    let captures = re.captures(&addr).unwrap();
    let user = captures.get(1).unwrap().as_str().to_string();
    let domain = match captures.get(3) {
        None => String::new(),
        Some(domain) => domain.as_str().to_string(),
    };
    return (user, domain);
}

pub fn mapuser(addr: &String, config: &Config) -> Option<String> {
    let addr = addr.to_ascii_lowercase();
    let (user, domain) = split_addr(&addr);
    if let Some(user) = config.wildcards.get(&domain) {
        return Some(user.to_string());
    }
    if let Some(alias) = config.aliases.get(&addr) {
        return Some(alias.to_string());
    }
    if config.domains.is_empty() || config.domains.contains(&domain) {
        if let Some(alias) = config.aliases.get(&user) {
            return Some(alias.to_string());
        }
        return Some(user.to_string());
    }
    return None;
}
