use std::io::Error;
use std::io::ErrorKind;
use std::io::Result;
use std::net::IpAddr;
use std::str::FromStr;

use domain::bits::DNameBuf;
use domain::bits::ParsedDName;
use domain::iana::{Class, Rtype};
use domain::rdata::Mx;
use domain::resolv::lookup::lookup_addr;
use domain::resolv::Resolver;
use tokio_core::reactor::Core;

pub fn lookupmx(domain: &String) -> Result<String> {
    let mut core = Core::new().unwrap();
    let resolv = Resolver::new(&core.handle());

    let mut domain = domain.clone();
    domain.push('.');
    let name = DNameBuf::from_str(&domain).unwrap();

    let mxquery = resolv.clone().query((name.clone(), Rtype::Mx, Class::In));

    let res = core.run(mxquery).unwrap();

    let mut v = Vec::new();
    for record in res.answer().unwrap().limit_to::<Mx<ParsedDName>>() {
        v.push(record.unwrap().into_data());
    }
    v.sort_by(|a, b| a.preference().cmp(&b.preference()));
    if v.len() > 0 {
        let mut mx = v[0].exchange().to_string();
        mx.pop();
        return Ok(mx);
    }
    return Err(Error::new(ErrorKind::Other, "mx lookup failed"));
}

pub fn revlookup(ip: IpAddr) -> String {
    let mut core = Core::new().unwrap();
    let resolv = Resolver::new(&core.handle());
    let query = lookup_addr(resolv, ip);
    let res = core.run(query).unwrap();
    for name in res.iter() {
        let mut name = name.to_string();
        name.pop();
        return name;
    }
    return "<unknown>".to_string();
}
