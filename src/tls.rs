#![allow(improper_ctypes)]

use std::convert::TryInto;
use std::ffi::CStr;
use std::ffi::CString;
use std::io::BufRead;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Result;
use std::io::Write;
use std::slice;

use crate::config::Config;
use crate::smtp::after_switch;
use crate::smtp::mailloop;
use crate::smtp::Connection;

#[repr(C)]
struct SslWrapper {
    dummy: i32,
}
#[repr(C)]
struct ReadHandle<'a> {
    reader: Box<dyn BufRead + 'a>,
}
extern "C" fn read_callback(handle: *mut ReadHandle, buf: *mut u8, buflen: usize) -> i32 {
    unsafe {
        let mut slice = slice::from_raw_parts_mut(buf, buflen);
        let rv = match (*handle).reader.read(&mut slice) {
            Err(_) => return -1,
            Ok(0) => return -1,
            Ok(rv) => rv.try_into().unwrap(),
        };
        return rv;
    }
}
#[repr(C)]
struct WriteHandle<'a> {
    writer: Box<dyn Write + 'a>,
}
extern "C" fn write_callback(handle: *mut WriteHandle, buf: *const u8, buflen: usize) -> i32 {
    unsafe {
        let slice = slice::from_raw_parts(buf, buflen);
        let rv = match (*handle).writer.write(slice) {
            Err(_) => return -1,
            Ok(rv) => rv.try_into().unwrap(),
        };
        if let Err(_) = (*handle).writer.flush() {
            return -1;
        };
        return rv;
    }
}
#[link(name = "bearffi")]
extern "C" {
    fn bear_init(certfile: *const i8, keyfile: *const i8) -> i32;
    fn bear_server(
        reader: *mut ReadHandle,
        readfn: extern "C" fn(*mut ReadHandle, *mut u8, usize) -> i32,
        writer: *mut WriteHandle,
        writefn: extern "C" fn(*mut WriteHandle, *const u8, usize) -> i32,
    ) -> *mut SslWrapper;
    fn bear_client(
        skipverify: bool,
        hostname: *const i8,
        reader: *mut ReadHandle,
        readfn: extern "C" fn(*mut ReadHandle, *mut u8, usize) -> i32,
        writer: *mut WriteHandle,
        writefn: extern "C" fn(*mut WriteHandle, *const u8, usize) -> i32,
    ) -> *mut SslWrapper;
    fn bear_freewrapper(wrapper: *mut SslWrapper);
    fn bear_read(wrapper: *mut SslWrapper, buf: *mut u8, buflen: usize) -> i32;
    fn bear_write(wrapper: *mut SslWrapper, buf: *const u8, buflen: usize) -> i32;
    fn bear_flush(wrapper: *mut SslWrapper) -> i32;
    fn bear_close(wrapper: *mut SslWrapper) -> i32;
    fn bear_error(wrapper: *mut SslWrapper) -> i32;
    fn bear_errormesg(error: i32) -> *const i8;
}

pub fn init(certfile: String, keyfile: String) -> Result<()> {
    unsafe {
        let cc = CString::new(certfile).unwrap();
        let ck = CString::new(keyfile).unwrap();
        let rv = bear_init(cc.as_ptr(), ck.as_ptr());
        if rv != 0 {
            return Err(Error::new(ErrorKind::Other, "can't init tls!"));
        }
        return Ok(());
    }
}

impl Read for SslWrapper {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        unsafe {
            let ptr = buf.as_mut_ptr();
            let len = buf.len();
            let rv = bear_read(self, ptr, len);
            if rv == -1 {
                let error = bear_error(self);
                let mesg = error_mesg(error);
                println!("bear read error {}", mesg);
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("read failed: {}", mesg),
                ));
            }
            return Ok(rv.try_into().unwrap());
        }
    }
}
impl Write for SslWrapper {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        unsafe {
            let ptr = buf.as_ptr();
            let len = buf.len();
            let rv = bear_write(self, ptr, len);
            if rv == -1 {
                let error = bear_error(self);
                let mesg = error_mesg(error);
                println!("bear write error {}", mesg);
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("write failed: {}", mesg),
                ));
            }
            return Ok(rv.try_into().unwrap());
        }
    }
    fn flush(&mut self) -> Result<()> {
        unsafe {
            bear_flush(self);
            return Ok(());
        }
    }
}

pub fn server_switch<R: BufRead, W: Write>(r: R, w: W, conn: &mut Connection) -> Result<()> {
    unsafe {
        let mut rh = ReadHandle {
            reader: Box::new(r),
        };
        let mut wh = WriteHandle {
            writer: Box::new(w),
        };
        let wrapper = bear_server(&mut rh, read_callback, &mut wh, write_callback);
        if wrapper.is_null() {
            return Err(Error::new(ErrorKind::Other, "can't switch to tls!"));
        }
        let newreader = BufReader::new(&mut *wrapper);
        let newwriter = BufWriter::new(&mut *wrapper);
        conn.secure = true;
        let rv = mailloop(newreader, newwriter, conn);
        bear_close(wrapper);
        bear_freewrapper(wrapper);
        return rv;
    }
}

pub fn client_switch<R: BufRead, W: Write>(
    hostname: String,
    config: &Config,
    from: &str,
    rcpt: &str,
    data: String,
    r: R,
    w: W,
) -> Result<()> {
    unsafe {
        let cstr = CString::new(hostname).unwrap();
        let mut rh = ReadHandle {
            reader: Box::new(r),
        };
        let mut wh = WriteHandle {
            writer: Box::new(w),
        };
        let wrapper = bear_client(
            config.skipverify,
            cstr.as_ptr(),
            &mut rh,
            read_callback,
            &mut wh,
            write_callback,
        );
        if wrapper.is_null() {
            return Err(Error::new(ErrorKind::Other, "can't switch to tls!"));
        }
        let newreader = BufReader::new(&mut *wrapper);
        let newwriter = BufWriter::new(&mut *wrapper);
        let rv = after_switch(&config, &from, &rcpt, data, newreader, newwriter);
        bear_close(wrapper);
        bear_freewrapper(wrapper);
        return rv;
    }
}

fn error_mesg(error: i32) -> String {
    unsafe {
        let mesg = bear_errormesg(error);
        return CStr::from_ptr(mesg).to_str().unwrap().to_string();
    }
}
