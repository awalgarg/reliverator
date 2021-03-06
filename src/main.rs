use std::convert::TryInto;
use std::io::Result;
use std::io::Error;
use std::io::ErrorKind;
use std::env;
use std::ffi::CString;
use std::net::TcpListener;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
#[macro_use]
extern crate lazy_static;

mod config;
mod database;
mod dns;
mod smtp;
mod tls;

use crate::config::readconfig;
use crate::config::Config;
use crate::smtp::handleclient;

lazy_static! {
    static ref PWLOCK: Mutex<i32> = Mutex::new(0);
}

use crate::smtp::sendmail;

const SOFTWARE_VERSION: &str = "develop";

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() == 2 && args[1] == "init" {
        database::init();
        return;
    }
    if args.len() == 2 && args[1] == "version" {
        println!("{}", SOFTWARE_VERSION);
        return;
    }

    let config = match readconfig(&"reliverator.conf".to_string()) {
        Ok(config) => config,
        Err(e) => return println!("error reading config: {}", e),
    };
    let c2 = config.clone();
    let t1 = thread::spawn(|| {
        relaylistener(c2);
    });
    let c2 = config.clone();
    let t2 = thread::spawn(|| {
        locallistener(c2);
    });
    let c2 = config.clone();
    let t3 = thread::spawn(|| {
        redeliverator(c2);
    });
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
        }
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
        }
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
            }
            Err(e) => {
                println!("error accepting: {}", e);
            }
        }
    }
}

fn redeliverator(config: Config) {
    loop {
        match database::get_overdue_mesg() {
            Err(rusqlite::Error::QueryReturnedNoRows) => {}
            Err(e) => {
                println!("error getting row: {}", e);
            }
            Ok(row) => {
                let (mesgid, from, rcpt, mesg, tries) = row;
                match sendmail(&config, &from, &rcpt, mesg) {
                    Ok(()) => {
                        database::delete_mesg(mesgid);
                    }
                    Err(e) => {
                        println!("error sending: {}", e);
                        database::requeue_mesg(mesgid, tries + 1);
                    }
                }
            }
        }
        thread::sleep(Duration::from_secs(5));
    }
}

#[link(name = "c")]
extern "C" {
    fn chown(path: *const i8, uid: i32, gid: i32) -> i32;
}

fn find_userid(user: &str) -> i32 {
    let _lock = PWLOCK.lock();
    unsafe {
        let cstr = CString::new(user).unwrap();
        let pwd = libc::getpwnam(cstr.as_ptr());
        if pwd.is_null() {
            return -1;
        }
        return (*pwd).pw_uid.try_into().unwrap();
    }
}

fn gift(filename: &str, user: &str) -> Result<()> {
    let uid = find_userid(&user);
    if uid == -1 {
        return Ok(());
    }
    unsafe {
        let path = CString::new(filename).unwrap();
        let rv = chown(path.as_ptr(), uid, -1);
	if rv == -1 {
		return Err(Error::new(ErrorKind::Other, "failed to chown!"));
	}
    }
    return Ok(());
}
