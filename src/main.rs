use pehp;
use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Please provide the filename of the PE to parse");
        process::exit(0x0);
    }
    let headers = pehp::parse_pe_headers(&args[1]);
    println!("{:?}", headers.coff_headers.characteristics.characteristics_list);
}