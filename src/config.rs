use std::collections::HashMap;
use std::io::Result;
use std::io::BufRead;
use std::io::BufReader;
use std::fs::File;

use crate::tls;

#[derive(Clone)]
pub struct Config {
	pub myname: String,
	pub aliases: HashMap<String, String>,
	pub relay: bool,
	pub ssl: bool,
}

pub fn readconfig(filename: &String) -> Result<Config> {
	let mut myname = "mailserver".to_string();
	let mut certfile = "".to_string();
	let mut keyfile = "".to_string();
	let mut aliases = HashMap::new();

	let file = File::open(filename)?;
	for line in BufReader::new(file).lines() {
		let line = line?;
		let v: Vec<&str> = line.trim().split(' ').collect();
		if v.len() == 0 {
			continue;
		}
		match v[0] {
			"alias" => {
				aliases.insert(v[1].to_string(),
					v[2].to_string());
			},
			"servername" => {
				myname = v[1].to_string();
			},
			"certfile" => {
				certfile = v[1].to_string();
			},
			"keyfile" => {
				keyfile = v[1].to_string();
			},
			_ => {
				println!("unknown config option {}", v[0]);
			},
		}

	}

	let mut ssl = false;
	if certfile != "" && keyfile != "" {
		tls::init(certfile, keyfile)?;
		ssl = true;
	}

	return Ok(Config{
		myname: myname,
		aliases: aliases,
		relay: false,
		ssl: ssl,
	});
}

pub fn mapuser(who: String, config: &Config) -> String {
	match config.aliases.get(&who) {
		Some(who) => return who.to_string(),
		None => return who,
	}
}
