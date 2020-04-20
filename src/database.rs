use rusqlite::{params, Connection, Result};
use chrono;

fn open_database() -> Connection {
	let conn = Connection::open("reliverator.db").unwrap();
	return conn;
}

pub fn init() {
	let conn = open_database();
	conn.execute("create table mesgs (mesgid integer primary key, frm text, rcpt text, mesg text, due integer, tries integer);", rusqlite::NO_PARAMS).unwrap();

}

pub fn save_mesg_to_db(from: &String, rcpt: &String, mesg: String, due: i64, tries: i64) {
	let conn = open_database();
	if let Err(e) = conn.execute("insert into mesgs (frm, rcpt, mesg, due, tries) values (?, ?, ?, ?, ?)",
		params![from, rcpt, mesg, due, tries]) {
			println!("failed to save mesg: {}", e);
	}
}

pub fn get_overdue_mesg() -> Result<(i64, String, String, String, i64)> {
	let now = chrono::Local::now().timestamp();
	let conn = open_database();
	conn.query_row("select mesgid, frm, rcpt, mesg, tries from mesgs where due > 0 and due < ? order by due asc",
		       params![now],
		       |row| {
			       let mesgid = row.get(0)?;
			       let from = row.get(1)?;
			       let rcpt = row.get(2)?;
			       let mesg = row.get(3)?;
			       let tries = row.get(4)?;
			       Ok((mesgid, from, rcpt, mesg, tries))
		       })
}

pub fn delete_mesg(mesgid: i64) {
	let conn = open_database();
	if let Err(e) = conn.execute("delete from mesgs where mesgid = ?",
		params![mesgid]) {
			println!("failed to delete mesg: {}", e);
	}
}

pub fn requeue_mesg(mesgid: i64, tries: i64) {
	let now = chrono::Local::now().timestamp();
	let next = match tries {
		1 => now + 600 ,
		2 => now + 3600 ,
		3 => now + 13600 ,
		4 => now + 123600 ,
		_ => {
			println!("it's dead!");
			-1
		},
	};
	let conn = open_database();
	if let Err(e) = conn.execute("update mesgs set due = ?, tries = ? where mesgid = ?",
		params![next, tries, mesgid]) {
			println!("failed to requeue mesg: {}", e);
	}
}


