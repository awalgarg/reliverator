use chrono;
use rand::Rng;
use regex::Regex;
use std::fs;
use std::fs::OpenOptions;
use std::io::BufRead;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Result;
use std::io::Write;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::str;

use crate::config::mapuser;
use crate::config::Config;
use crate::database::save_mesg_to_db;
use crate::dns::lookupmx;
use crate::dns::revlookup;
use crate::find_userid;
use crate::gift;
use crate::tls;

pub struct Connection {
    config: Config,
    state: u32,
    addr: SocketAddr,
    sessid: String,
    helo: String,
    from: String,
    rcpts: Vec<String>,
    pub secure: bool,
}

fn readline<R: BufRead>(mut r: R) -> Result<String> {
    let mut buf = String::new();
    match r.read_line(&mut buf) {
        Ok(0) => {
            return Err(Error::new(ErrorKind::Other, "eof!"));
        }
        Ok(_) => (),
        Err(e) => {
            return Err(e);
        }
    }
    return Ok(buf);
}

fn readdata<R: BufRead>(mut r: R) -> Result<String> {
    let mut rv = String::new();
    loop {
        let l = readline(&mut r)?;
        if l == ".\r\n" {
            println!("end data");
            return Ok(rv);
        }
        rv.push_str(&l);
    }
}

pub fn handleclient(config: Config, s: TcpStream, addr: SocketAddr) {
    let randid = rand::thread_rng().gen_range(1000000, 10000000);
    let sessid = randid.to_string();
    let conn = Connection {
        config: config,
        state: INTHEBEGINNING,
        addr: addr,
        sessid: sessid,
        helo: String::new(),
        from: String::new(),
        rcpts: Vec::new(),
        secure: false,
    };
    if let Err(e) = processclient(s, conn) {
        println!("error handling client: {}", e)
    }
}

const INTHEBEGINNING: u32 = 1;
const GREETINGS: u32 = 2;
const IVEGOTMAIL: u32 = 3;
const YOUVEGOTMAIL: u32 = 4;
const POSITRONIC: u32 = 5;

fn processclient(mut s: TcpStream, mut conn: Connection) -> Result<()> {
    println!("connection from {}", conn.addr);
    s.write_all(format!("220 {} ESMTP reliverator\r\n", conn.config.myname).as_bytes())?;

    let r = BufReader::new(&s);
    let w = BufWriter::new(&s);
    return mailloop(r, w, &mut conn);
}

pub fn mailloop<R: BufRead, W: Write>(mut r: R, mut w: W, conn: &mut Connection) -> Result<()> {
    loop {
        w.flush()?;
        let l = readline(&mut r)?;
        let l = l.trim();
        let v: Vec<&str> = l.split(' ').collect();
        let cmd = v[0];
        match &cmd.to_ascii_uppercase()[..] {
            "HELP" => {
                w.write_all(b"214 the prognosis is dire\r\n")?;
            }
            "STARTTLS" => {
                if !conn.config.ssl {
                    w.write_all(b"500 that was not good\r\n")?;
                    continue;
                }
                if conn.secure {
                    w.write_all(b"500 that was not good\r\n")?;
                    continue;
                }
                if conn.state != INTHEBEGINNING && conn.state != GREETINGS {
                    w.write_all(b"500 that was not good\r\n")?;
                    continue;
                }
                w.write_all(b"220 this line is secure\r\n")?;
                w.flush()?;
                return tls::server_switch(r, w, conn);
            }
            "HELO" => {
                if conn.state != INTHEBEGINNING && conn.state != GREETINGS {
                    w.write_all(b"500 that was not good\r\n")?;
                    continue;
                }
                if v.len() == 1 {
                    w.write_all(b"501 who now?\r\n")?;
                    continue;
                }
                let g = format!(
                    "250 {} looking good {}\r\n",
                    conn.config.myname,
                    conn.addr.ip()
                );
                w.write_all(g.as_bytes())?;
                conn.helo = v[1].to_string();
                conn.state = GREETINGS;
            }
            "EHLO" => {
                if conn.state != INTHEBEGINNING && conn.state != GREETINGS {
                    w.write_all(b"500 that was not good\r\n")?;
                    continue;
                }
                if v.len() == 1 {
                    w.write_all(b"501 who now?\r\n")?;
                    continue;
                }
                let repl = format!(
                    "250-{} looking good {}\r\n",
                    conn.config.myname,
                    conn.addr.ip()
                );
                w.write_all(repl.as_bytes())?;
                if conn.config.ssl {
                    w.write_all(b"250-STARTTLS\r\n")?;
                }
                w.write_all(b"250-8BITMIME\r\n")?;
                w.write_all(b"250 HELP\r\n")?;
                conn.helo = v[1].to_string();
                conn.state = GREETINGS;
            }
            "MAIL" => {
                if conn.state != GREETINGS {
                    w.write_all(b"500 that was not good\r\n")?;
                    continue;
                }
                match parse_mail_from(l.to_string()) {
                    Err(e) => {
                        println!("didn't parse from: {}", e);
                        w.write_all(b"550 speak clearly please\r\n")?;
                    }
                    Ok(who) => {
                        println!("mail from: {}", who);
                        conn.from = who;
                        w.write_all(b"250 got it\r\n")?;
                        conn.state = IVEGOTMAIL;
                    }
                }
            }
            "RCPT" => {
                if conn.state != IVEGOTMAIL && conn.state != YOUVEGOTMAIL {
                    w.write_all(b"500 that was not good\r\n")?;
                    continue;
                }
                match parse_rcpt_to(l.to_string()) {
                    Err(e) => {
                        println!("didn't parse rcpt: {}", e);
                        w.write_all(b"550 that is not going to work\r\n")?;
                    }
                    Ok(addr) => {
                        if !conn.config.relay {
                            let who = mapuser(&addr, &conn.config);
                            if who.is_none() || find_userid(&who.unwrap()) == -1 {
                                println!("no match for user: {}", addr);
                                w.write_all(b"550 new phone who dis\r\n")?;
                                continue;
                            }
                        }
                        println!("rcpt to: {}", addr);
                        conn.rcpts.push(addr);
                        w.write_all(b"250 righto\r\n")?;
                        conn.state = YOUVEGOTMAIL;
                    }
                }
            }
            "DATA" => {
                if conn.state != YOUVEGOTMAIL {
                    w.write_all(b"500 that was not good\r\n")?;
                    continue;
                }
                w.write_all(b"354 give it to me\r\n")?;
                w.flush()?;
                conn.state = POSITRONIC;
                let data = readdata(&mut r)?;
                match deliver(conn, data) {
                    Err(e) => {
                        println!("delivery failed: {}", e);
                        w.write_all(b"550 that is not going to work\r\n")?;
                        continue;
                    }
                    Ok(()) => {
                        w.write_all(b"250 all aboard\r\n")?;
                    }
                }
                conn.state = GREETINGS;
                conn.from = String::new();
                conn.rcpts = Vec::new();
            }
            "QUIT" => {
                w.write_all(b"221 nachti nachti\r\n")?;
                w.flush()?;
                break;
            }
            cmd => {
                println!("unknown cmd: {}", cmd);
                w.write_all(b"500 that was not good\r\n")?;
            }
        }
    }
    println!("i am done!");
    return Ok(());
}

fn parse_mail_from(from: String) -> Result<String> {
    let re = Regex::new("(?i)mail from: *<(.*)>").unwrap();
    match re.captures(&from) {
        None => {
            println!("didn't like from: {}", from);
            return Err(Error::new(ErrorKind::Other, "bad from!"));
        }
        Some(captures) => {
            return Ok(captures.get(1).unwrap().as_str().to_string());
        }
    }
}

fn parse_rcpt_to(rcpt: String) -> Result<String> {
    let re = Regex::new("(?i)rcpt to: *<(.*)>").unwrap();
    match re.captures(&rcpt) {
        None => {
            println!("didn't like rcpt: {}", rcpt);
            return Err(Error::new(ErrorKind::Other, "bad rcpt!"));
        }
        Some(captures) => {
            return Ok(captures.get(1).unwrap().as_str().to_string());
        }
    }
}

fn extract_domain(rcpt: &String) -> Result<String> {
    let re = Regex::new("([a-zA-Z0-9]+)([a-zA-Z0-9._+]*)@?([a-zA-Z0-9_.]*)").unwrap();
    match re.captures(&rcpt) {
        None => {
            return Err(Error::new(ErrorKind::Other, "bad rcpt!"));
        }
        Some(captures) => {
            return Ok(captures.get(3).unwrap().as_str().to_string());
        }
    }
}

fn deliver(conn: &Connection, data: String) -> Result<()> {
    if conn.config.relay {
        return save_for_relay(&conn, data);
    } else {
        return deliver_local(&conn, data);
    }
}

fn format_received(
    helo: &String,
    revname: &String,
    ipaddr: IpAddr,
    myname: &String,
    proto: &String,
    sessid: &String,
    rcpt: &String,
    timestamp: &String,
) -> String {
    return format!(
        r"Received: from {} ({} [{}])
	by {} (reliverator) with {} id {}
	for <{}>;
	{}
",
        helo, revname, ipaddr, myname, proto, sessid, rcpt, timestamp
    );
}

fn deliver_local(conn: &Connection, data: String) -> Result<()> {
    let now = chrono::Local::now();
    let host = &conn.config.myname;
    let helo = &conn.helo;
    let ipaddr = conn.addr.ip();
    let revname = revlookup(ipaddr);
    let proto = if conn.secure { "ESMTPS" } else { "SMTP" };
    let timestamp = now.to_rfc2822();
    for rcpt in &conn.rcpts {
        let user = match mapuser(&rcpt, &conn.config) {
            Some(user) => user,
            None => {
                println!("where did my rcpt {} go?", rcpt);
                continue;
            }
        };
        let randid = rand::thread_rng().gen_range(1000000, 10000000);
        let fname = format!("{}.{}.{}.{}", now.timestamp(), conn.sessid, randid, host);
        let tmpname = format!("/home/{}/Maildir/tmp/{}", user, fname);
        let mut f = OpenOptions::new().write(true).create_new(true).open(&tmpname)?;

        f.write_all(format!("Return-Path: <{}>\n", conn.from).as_bytes())?;
        f.write_all(format!("Delivered-To: {}\n", rcpt).as_bytes())?;
        let recv = format_received(
            &helo,
            &revname,
            ipaddr,
            &host,
            &proto.to_string(),
            &conn.sessid,
            &rcpt,
            &timestamp,
        );
        f.write_all(recv.as_bytes())?;
        f.write_all(data.as_bytes())?;
        f.sync_all()?;
        gift(&tmpname, &user);
        let newname = format!("/home/{}/Maildir/new/{}", user, fname);
        fs::rename(&tmpname, &newname)?;
        println!("delivered to {}", newname);
    }
    return Ok(());
}

fn save_for_relay(conn: &Connection, data: String) -> Result<()> {
    let now = chrono::Local::now();
    let host = &conn.config.myname;
    let helo = &conn.helo;
    let ipaddr = conn.addr.ip();
    let revname = revlookup(ipaddr);
    let proto = if conn.secure { "ESMTPS" } else { "SMTP" };
    let timestamp = now.to_rfc2822();
    for rcpt in &conn.rcpts {
        let mut mesg = format_received(
            &helo,
            &revname,
            ipaddr,
            &host,
            &proto.to_string(),
            &conn.sessid,
            &rcpt,
            &timestamp,
        );

        mesg.push_str(&data);
        save_mesg_to_db(&conn.from, &rcpt, mesg, now.timestamp(), 0);
    }

    return Ok(());
}

pub fn sendmail(config: &Config, from: &String, rcpt: &String, data: String) -> Result<()> {
    let domain = match extract_domain(&rcpt) {
        Err(e) => return Err(e),
        Ok(domain) => domain,
    };
    let mut mx = match lookupmx(&domain) {
        Ok(mx) => mx,
        Err(_) => domain,
    };
    let hostname = mx.clone();
    mx.push_str(":25");
    println!("connect to {}", mx);
    let s = TcpStream::connect(mx)?;
    let mut r = BufReader::new(&s);
    let mut w = BufWriter::new(&s);

    let l = readline(&mut r)?;
    if !l.starts_with("220 ") {
        return Err(Error::new(ErrorKind::Other, "not a mail server!"));
    }
    let g = format!("ehlo {}\r\n", config.myname);
    w.write_all(g.as_bytes())?;
    w.flush()?;
    let mut secure = false;
    loop {
        let l = readline(&mut r)?;
        if l.starts_with("250 ") {
            break;
        }
        if l.starts_with("250-STARTTLS") {
            secure = true;
        }
        if !l.starts_with("250-") {
            println!("bad ehlo: {}", l);
            return Err(Error::new(ErrorKind::Other, "not a mail server!"));
        }
    }
    if secure {
        w.write_all(b"STARTTLS\r\n")?;
        w.flush()?;
        let l = readline(&mut r)?;
        if l.starts_with("220 ") {
            return tls::client_switch(hostname, &config, &from, &rcpt, data, r, w);
        }
        println!("didn't want to start tls?: {}", l);
    }
    return client_send(&from, &rcpt, data, r, w);
}

pub fn after_switch<R: BufRead, W: Write>(
    config: &Config,
    from: &String,
    rcpt: &String,
    data: String,
    mut r: R,
    mut w: W,
) -> Result<()> {
    let g = format!("ehlo {}\r\n", config.myname);
    w.write_all(g.as_bytes())?;
    w.flush()?;
    loop {
        let l = readline(&mut r)?;
        if l.starts_with("250 ") {
            break;
        }
        if !l.starts_with("250-") {
            println!("bad ehlo: {}", l);
            return Err(Error::new(ErrorKind::Other, "not a mail server!"));
        }
    }
    return client_send(&from, &rcpt, data, r, w);
}

fn client_send<R: BufRead, W: Write>(
    from: &String,
    rcpt: &String,
    data: String,
    mut r: R,
    mut w: W,
) -> Result<()> {
    let mailfrom = format!("MAIL FROM: <{}>\r\n", from);
    w.write_all(mailfrom.as_bytes())?;
    w.flush()?;
    let l = readline(&mut r)?;
    if !l.starts_with("250 ") {
        println!("bad from: {}", l);
        return Err(Error::new(ErrorKind::Other, "didn't like mail from!"));
    }
    let rcpto = format!("RCPT TO: <{}>\r\n", rcpt);
    w.write_all(rcpto.as_bytes())?;
    w.flush()?;
    let l = readline(&mut r)?;
    if !l.starts_with("250 ") {
        println!("bad rcpt: {}", l);
        return Err(Error::new(ErrorKind::Other, "didn't like rcpt to!"));
    }
    w.write_all(b"DATA\r\n")?;
    w.flush()?;
    let l = readline(&mut r)?;
    if !l.starts_with("354 ") {
        println!("no data: {}", l);
        return Err(Error::new(ErrorKind::Other, "doesn't want data!"));
    }
    w.write_all(data.as_bytes())?;
    if !data.ends_with("\r\n") {
        w.write_all(b"\r\n")?;
    }
    w.write_all(b".\r\n")?;
    w.flush()?;
    let l = readline(&mut r)?;
    if !l.starts_with("250 ") {
        println!("bad data: {}", l);
        return Err(Error::new(ErrorKind::Other, "didn't like data!"));
    }
    w.write_all(b"QUIT\r\n")?;
    w.flush()?;
    println!("send successful");

    return Ok(());
}
