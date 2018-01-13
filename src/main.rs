// extern crate openssl;

use std::net::{SocketAddr, UdpSocket};
use std::fmt;
use std::str;
use std::env;
use std::io::{Error, ErrorKind};
use std::{thread, time};
use std::net::TcpStream;
use std::io::{Write, Read};
use std::time::Duration;
// use openssl::ssl::{SslContextBuilder, SslMethod, Ssl, SslStream, SSL_VERIFY_PEER};
// use openssl::x509::{X509StoreContextRef, X509FileType};

struct Array<T> {
    data: [T; 128]
}

impl<T: fmt::Debug> fmt::Debug for Array<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        self.data[..].fmt(formatter)
    }
}

fn job(dns_server: &str, address: &str) -> std::io::Result<()> {
    let ip = dns_server;
    let addr: SocketAddr = ip.parse().unwrap();
    let stream = UdpSocket::bind("0.0.0.0:0").expect("Cannot bind on local port.");

    let split: Vec<&str> = address.split(".").collect();
    let footer = [0x00, 0x00, 0x01, 0x00, 0x01];

    let mut buf_send = vec![0xAA, 0xAA, 0x01, 0x00, 
                            0x00, 0x01, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x00];

    for i in 0..split.len() {
        let val = split[i];
        buf_send.push(val.len() as u8);
        buf_send.extend(val.as_bytes());
    }
    buf_send.extend(footer.iter());

    stream.set_write_timeout(Some(Duration::from_secs(3))).expect("set_write_timeout call failed");
    stream.set_read_timeout(Some(Duration::from_secs(3))).expect("set_read_timeout call failed");

    let result = stream.send_to(&buf_send, addr);
    match result {
        Ok(_) => {
            recv(&stream, &addr)
        },
        Err(e) => {
            print!("Cannot send dns-request from {:?} {:?}", &addr, &e);
            return Err(Error::new(ErrorKind::Other, "Timeout on send_to"))
        }
    }
}

fn recv(stream: &UdpSocket, addr: &SocketAddr) -> std::io::Result<()> {
    let mut buf = [0; 128];
    let result = stream.recv_from(&mut buf);
    match result {
        Ok(_) => {
            let array = Array { data: buf };
            let rcode = buf[3] & 15;
            if rcode == 3 {
                return Err(Error::new(ErrorKind::Other, "Non-Existent Domain"));
            }

            println!("Response:\n{:?}\n{:?}", &array, &String::from_utf8_lossy(&buf));
            println!("ID:       {:?}", &buf[0..2]);
            
            println!("QR:       {:?} {}", &buf[2], check_bit_str(&buf[2], 7));
            println!("Opcode:   {:?} {} {} {} {}", &buf[2], 
                                                check_bit(&buf[2], 6),
                                                check_bit(&buf[2], 5),
                                                check_bit(&buf[2], 4),
                                                check_bit(&buf[2], 3));
            println!("AA:       {:?} {}", &buf[2], check_bit_str(&buf[2], 2));
            println!("TC:       {:?} {}", &buf[2], check_bit_str(&buf[2], 1));
            println!("RD:       {:?} {}", &buf[2], check_bit_str(&buf[2], 0));
            println!("RA:       {:?} {}", &buf[3], check_bit_str(&buf[3], 7));
            println!("Z:        {:?} {} {} {}", &buf[3], 
                                                check_bit(&buf[3], 6),
                                                check_bit(&buf[3], 5),
                                                check_bit(&buf[3], 4));

            println!("RCODE:    {:?} {} {} {} {} - code {}", &buf[3], 
                                                check_bit(&buf[3], 3),
                                                check_bit(&buf[3], 2),
                                                check_bit(&buf[3], 1),
                                                check_bit(&buf[3], 0),
                                                rcode);

            println!("Requests: {} {}", &buf[4], &buf[5]);
            println!("Rspnses:  {} {}", &buf[6], &buf[7]);
            println!("AuthSrvs: {} {}", &buf[8], &buf[9]);
            println!("AddResps: {} {}", &buf[10], &buf[11]);

            let length: usize = buf[12] as usize;
            let boundary = 13 + length;
            println!("Length:   {}", &length);
            println!("Name:     {}", &String::from_utf8_lossy(&buf[13..boundary]).to_owned());
            let length: usize = buf[boundary] as usize;
            let start = boundary + 1;
            let boundary = start + length;
            println!("TLD len:  {}", &length);
            println!("TLD:      {}", &String::from_utf8_lossy(&buf[start..boundary]).to_owned());

            println!("QTYPE:    {} {}", &buf[boundary + 1], &buf[boundary + 2]);
            println!("QCLASS:   {} {}", &buf[boundary + 3], &buf[boundary + 4]);

            println!("NAME:     {} {}", &buf[boundary + 5], &buf[boundary + 6]);
            println!("TYPE:     {} {}", &buf[boundary + 7], &buf[boundary + 8]);
            println!("CLASS:    {} {}", &buf[boundary + 9], &buf[boundary + 10]);
            
            let seconds: u32 =  buf[boundary + 11] as u32 * 256 * 256 * 256 +
                                buf[boundary + 12] as u32 * 256 * 256 +
                                buf[boundary + 13] as u32 * 256 +
                                buf[boundary + 14] as u32;
            println!("TTL:      {} {} {} {} - {} seconds", &buf[boundary + 11], 
                                                &buf[boundary + 12],
                                                &buf[boundary + 13], 
                                                &buf[boundary + 14],
                                                &seconds);
            println!("RDLENGTH: {} {}", &buf[boundary + 15], 
                                                &buf[boundary + 16]);
            println!("RDDATA:   {}.{}.{}.{}", &buf[boundary + 17], 
                                                &buf[boundary + 18], 
                                                &buf[boundary + 19], 
                                                &buf[boundary + 20]);
        },
        Err(e) => {
            print!("Cannot receive dns-response from {:?} {:?}", addr, &e);
            return Err(Error::new(ErrorKind::Other, "Timeout on recv"))
        }
    }

    Ok(())
}

fn check_bit(value: &u8, bit_position: u8) -> bool {
    if bit_position > 7 {
        return false
    }

    let check_val = 1 << bit_position;
    return value & check_val == check_val;
}

fn check_bit_str(value: &u8, bit_position: u8) -> String {
    if check_bit(value, bit_position) {
        return "true".to_owned();
    }
    
    return "false".to_owned();
}

// pub fn verify_callback(domain: &str, preverify_ok: bool, x509_ctx: &X509StoreContextRef) -> bool {
//     true
// }

fn send_push() {
    let sock = "216.58.211.138:80".parse().unwrap();
    let mut stream = TcpStream::connect_timeout(&sock, Duration::from_secs(3));
    match stream {
        Ok(ref mut r) => {

    // let mut stream = TcpStream::connect("216.58.211.138:443").unwrap();
    // let mut ctx = SslContextBuilder::new(SslMethod::tls()).unwrap();
    // ctx.set_default_verify_paths().unwrap();
    // let ctx = ctx.build();
    // let mut ssl = Ssl::new(&ctx).unwrap();
    // let domain = "fcm.googleapis.com".to_owned();
    // ssl.set_verify_callback(SSL_VERIFY_PEER, move |p, x| verify_callback(&domain, p, x));

    // let mut ssl_stream = ssl.connect(stream).unwrap();

            let body = "{ \
                    \"to\":\"token\", \
                    \"priority\":\"high\", \
                    \"notification\": { \
                        \"title\":\"Dns failure!\", \
                        \"body\":\"Restart of Dnsmasq is required.\", \
                        \"sound\":\"default\" \
                    } \
                }";
            let length = body.len();
            let data = format!("POST /fcm/send HTTP/1.1\r\n\
                        Host: fcm.googleapis.com\r\n\
                        Authorization: key=key\r\n\
                        Content-Type: application/json\r\n\
                        Content-Length: {}\r\n\r\n\
                        {}", &length, &body);

            let _ = r.write(&data.as_bytes());

            let mut buf = [0; 256];
            let result = r.read(&mut buf);
            match result {
                Ok(r) => {
                    println!("Sent {} {}", r, String::from_utf8_lossy(&buf));
                },
                Err(e) => {
                    println!("Error {}", e);
                }
            }
        },
        Err(e) => {
            println!("FCM Error {}", e);
        }
    }    
}

fn main() {
    let dns_server = env::args().nth(1).expect("No DNS server specified.");
    let address = env::args().nth(2).expect("No test address specified.");
    let delay: u64 = env::args().nth(3).expect("No delay specified.").parse().unwrap();
    let sleep_millis = time::Duration::from_millis(delay);
    let temp_sleep_millis = time::Duration::from_millis(2000);
    let retry_count = 3;
    let mut count = 0;

    loop {
        let result = job(&dns_server, &address);
        match result {
            Ok(_) => {
                count = 0;
                println!("\n+ OK\n");
                thread::sleep(sleep_millis);
            },
            Err(e) => {
                if count == retry_count {
                    println!("--> DNS failed after {} retries. Sending push... {}", retry_count, e);
                    send_push();
                    thread::sleep(sleep_millis);
                } else {
                    println!("--> Failed, retrying... {} {}", count, e);
                    count += 1;
                    thread::sleep(temp_sleep_millis);
                }
            }
        }
    }
}
