use std::net::TcpListener;
use std::thread;
use std::sync::Mutex;
use std::ffi::CString;
use std::env;
use std::time::Duration;
#[macro_use]
extern crate lazy_static;

mod tls;
mod smtp;
mod dns;
mod config;
mod database;

use crate::smtp::handleclient;
use crate::config::readconfig;
use crate::config::Config;

lazy_static! {
	static ref PWLOCK: Mutex<i32> = Mutex::new(0);
}

use crate::smtp::sendmail;

fn main() {
	let args: Vec<String> = env::args().collect();
	if args.len() == 2 && args[1] == "init" {
		database::init();
		return;
	}

	let config = readconfig(&"reliverator.conf".to_string()).unwrap();
	let c2 = config.clone();
	let t1 = thread::spawn(|| { relaylistener(c2); });
	let c2 = config.clone();
	let t2 = thread::spawn(|| { locallistener(c2); });
	let c2 = config.clone();
	let t3 = thread::spawn(|| { redeliverator(c2); });
	t1.join().expect("oops");
	t2.join().expect("oops");
	t3.join().expect("oops");
}

fn relaylistener(mut config: Config) {
	let relayaddr = "127.0.0.1:587";
	let l = match TcpListener::bind(relayaddr) {
		Ok(l) => l,
		Err(e) => {
			println!("can't listen: {}", e);
			return;
		},
	};
	config.relay = true;
	config.ssl = false;
	listener(l, config);
}

fn locallistener(config: Config) {
	let listenaddr = "0.0.0.0:25";
	let l = match TcpListener::bind(listenaddr) {
		Ok(l) => l,
		Err(e) => {
			println!("can't listen: {}", e);
			return;
		},
	};
	listener(l, config);
}

fn listener(l: TcpListener, config: Config) {
	loop {
		match l.accept() {
			Ok((s, addr)) => {
				let c2 = config.clone();
				thread::spawn(move || {
					handleclient(c2, s, addr);
				});
			},
			Err(e) => {
				println!("error accepting: {}", e);
			},
		}
	}
}

fn redeliverator(config: Config) {
	loop {
		match database::get_overdue_mesg() {
			Err(rusqlite::Error::QueryReturnedNoRows) => {
			},
			Err(e) => {
				println!("error getting row: {}", e);
			},
			Ok(row) => {
				let (mesgid, from, rcpt, mesg, tries) = row;
				match sendmail(&config, &from, &rcpt, mesg) {
					Ok(()) => {
						database::delete_mesg(mesgid);
					},
					Err(e) => {
						println!("error sending: {}", e);
						database::requeue_mesg(mesgid, tries + 1);
					},
				}
			},
		}
		thread::sleep(Duration::from_secs(5));
	}
}

#[link(name = "c")]
extern {
	fn uid_from_user(user: *const i8, uid: *mut i32) -> i32;
	fn chown(path: *const i8, uid: i32, gid: i32) -> i32;
}

fn find_userid(user: &String) -> i32 {
	let _lock = PWLOCK.lock();
	unsafe {
		let mut uid: i32 = -1;
		let cstr = CString::new(user.as_str()).unwrap();
		let rv = uid_from_user(cstr.as_ptr(), &mut uid);
		if rv == -1 {
			return -1;
		}
		return uid;
	}
}

fn gift(filename: &String, user: &String) {
	let uid = find_userid(&user);
	if uid == -1 {
		return;
	}
	unsafe {
		let path = CString::new(filename.as_str()).unwrap().as_ptr();
		chown(path, uid, -1);
	}
}
