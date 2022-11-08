#![allow(dead_code)]
#![allow(unused_variables)]

mod structs;
mod utils;
use structs::DOSHeaders;
use structs::COFFHeaders;
use structs::StandardFields;
use structs::WindowsSpecific;
use structs::Headers;
use structs::DataDirectories;
use structs::Characteristics;
use structs::CharacteristicsVal;
use utils::consume_u16_from_buffer;
use utils::consume_u32_from_buffer;
use utils::consume_u64_from_buffer;
use std::fs;
use std::vec::Vec;
use std::io::Read;

fn read_file(filename: &String) -> Vec<u8> {
    let mut file = fs::File::open(&filename).expect("Could not open file");
    let metadata = fs::metadata(&filename).expect("unable to read metadata");
    let mut file_content = vec![0; metadata.len() as usize];
    file.read(&mut file_content).expect("Failed to read file");
    file_content
}

fn parse_dos(dos_headers: &[u8], headers: &mut DOSHeaders) {
    let mut index: usize = 0;
    headers.magic = consume_u16_from_buffer(&dos_headers, &mut index);
    headers.last_size = consume_u16_from_buffer(&dos_headers, &mut index);
    headers.pages_in_file = consume_u16_from_buffer(&dos_headers, &mut index);
    headers.relocations = consume_u16_from_buffer(&dos_headers, &mut index);
    headers.header_size_in_paragraph = consume_u16_from_buffer(&dos_headers, &mut index);
    headers.min_extra_paragraph_needed = consume_u16_from_buffer(&dos_headers, &mut index);
    headers.max_extra_paragraph_needed = consume_u16_from_buffer(&dos_headers, &mut index);
    headers.initial_ss = consume_u16_from_buffer(&dos_headers, &mut index);
    headers.initial_sp = consume_u16_from_buffer(&dos_headers, &mut index);
    headers.checksum = consume_u16_from_buffer(&dos_headers, &mut index);
    headers.initial_ip = consume_u16_from_buffer(&dos_headers, &mut index);
    headers.initial_cs = consume_u16_from_buffer(&dos_headers, &mut index);
    headers.file_add_of_relocation_table = consume_u16_from_buffer(&dos_headers, &mut index);
    headers.overlay_number = consume_u16_from_buffer(&dos_headers, &mut index);
    headers.reserved_one = dos_headers[index..index+8].try_into().expect("Failed to convert slice to [u8; 36]");
    index += 8;
    headers.oem_identifier = consume_u16_from_buffer(&dos_headers, &mut index);
    headers.oem_information = consume_u16_from_buffer(&dos_headers, &mut index);
    headers.reserved_two = dos_headers[index..index+20].try_into().expect("Failed to convert slice to [u8; 36]");
    index += 20;
    headers.offset_to_pe_headers =consume_u32_from_buffer(&dos_headers, &mut index);
}

fn parse_characteristics(value: &mut u16, characteristics: &mut Characteristics) {
    let mut iter: u16 = 0x8000;
    characteristics.value = *value;
    while iter >= 1 {
        if *value >= iter {
            characteristics.characteristics_list.push(CharacteristicsVal::from_u16(iter));
            *value -= iter;
        } 
        iter /= 2;
    }
}

fn parse_coff(coff_headers: &[u8], headers: &mut COFFHeaders) {
    let mut index: usize = 0;
    headers.magic = consume_u32_from_buffer(&coff_headers, &mut index);
    headers.target_machine = consume_u16_from_buffer(&coff_headers, &mut index);
    headers.number_of_sections = consume_u16_from_buffer(&coff_headers, &mut index);
    headers.time_date_stamp = consume_u32_from_buffer(&coff_headers, &mut index);
    headers.pointer_to_symbol_table = consume_u32_from_buffer(&coff_headers, &mut index);
    headers.number_of_symbols = consume_u32_from_buffer(&coff_headers, &mut index);
    headers.size_of_optional_headers = consume_u16_from_buffer(&coff_headers, &mut index);
    let mut characteristics_value = consume_u16_from_buffer(&coff_headers, &mut index);
    parse_characteristics(&mut characteristics_value, &mut headers.characteristics);
}

fn parse_standard_fields(standard_fields: &[u8], headers: &mut StandardFields) {
    let mut index: usize = 0;
    headers.magic = consume_u16_from_buffer(&standard_fields, &mut index);
    headers.major_linker_version = standard_fields[index];
    headers.minor_linker_version = standard_fields[index + 1];
    index += 2;
    headers.size_of_code = consume_u32_from_buffer(&standard_fields, &mut index);
    headers.size_of_initialized_data = consume_u32_from_buffer(&standard_fields, &mut index);
    headers.size_of_uninitialized_data = consume_u32_from_buffer(&standard_fields, &mut index);
    headers.address_of_entry_point = consume_u32_from_buffer(&standard_fields, &mut index);
    headers.base_of_code = consume_u32_from_buffer(&standard_fields, &mut index);
    if headers.magic == 0x108 {
        headers.base_of_data = consume_u32_from_buffer(&standard_fields, &mut index);
    }
}

fn parse_windows_specific(windows_specific: &[u8], pe_32: &bool, headers: &mut WindowsSpecific) {
    let mut index: usize = 0;
    if *pe_32 {
        headers.image_base = consume_u32_from_buffer(&windows_specific, &mut index) as u64;
    } else {
        headers.image_base = consume_u64_from_buffer(&windows_specific, &mut index);
    }
    headers.section_alignment = consume_u32_from_buffer(&windows_specific, &mut index);
    headers.file_alignment = consume_u32_from_buffer(&windows_specific, &mut index);
    headers.major_operating_system_version = consume_u16_from_buffer(&windows_specific, &mut index);
    headers.minor_operating_system_version = consume_u16_from_buffer(&windows_specific, &mut index);
    headers.major_image_version = consume_u16_from_buffer(&windows_specific, &mut index);
    headers.minor_image_version = consume_u16_from_buffer(&windows_specific, &mut index);
    headers.major_subsystem_version = consume_u16_from_buffer(&windows_specific, &mut index);
    headers.minor_subsystem_version = consume_u16_from_buffer(&windows_specific, &mut index);
    headers.win32_version_value = consume_u32_from_buffer(&windows_specific, &mut index);
    headers.size_of_image = consume_u32_from_buffer(&windows_specific, &mut index);
    headers.size_of_headers = consume_u32_from_buffer(&windows_specific, &mut index);
    headers.checksum = consume_u32_from_buffer(&windows_specific, &mut index);
    headers.subsystem = consume_u16_from_buffer(&windows_specific, &mut index);
    headers.dll_characteristics = consume_u16_from_buffer(&windows_specific, &mut index);
    if *pe_32 {
        headers.size_of_stack_reserve = consume_u32_from_buffer(&windows_specific, &mut index) as u64;
        headers.size_of_stack_commit = consume_u32_from_buffer(&windows_specific, &mut index) as u64;
        headers.size_of_heap_reserve = consume_u32_from_buffer(&windows_specific, &mut index) as u64;
        headers.size_of_heap_commit = consume_u32_from_buffer(&windows_specific, &mut index) as u64;
    } else {
        headers.size_of_stack_reserve = consume_u64_from_buffer(&windows_specific, &mut index);
        headers.size_of_stack_commit = consume_u64_from_buffer(&windows_specific, &mut index);
        headers.size_of_heap_reserve = consume_u64_from_buffer(&windows_specific, &mut index);
        headers.size_of_heap_commit = consume_u64_from_buffer(&windows_specific, &mut index);
    }
    headers.loader_flags = consume_u32_from_buffer(&windows_specific, &mut index);
    headers.number_of_rva_and_sizes = consume_u32_from_buffer(&windows_specific, &mut index);
}

fn parse_data_directories(data_directories: &[u8], number_of_directories: u32, headers: &mut DataDirectories) {
    let mut index: usize = 0;
    for x in 0..number_of_directories {
        headers.directories[(x as usize)].virtual_address = consume_u32_from_buffer(&data_directories, &mut index);
        headers.directories[(x as usize)].size = consume_u32_from_buffer(&data_directories, &mut index);
    }
}

pub fn parse_pe_headers(filename: &String) -> Headers {

    // false: pe32+, true: pe32
    let pe_32: bool; 

    let file = read_file(filename);
    let mut headers = Headers::default();

    // Parse DOS headers
    parse_dos(&file[0..64], &mut headers.dos_headers);
    
    // Parse COFF headers
    let coff_headers_start = headers.dos_headers.offset_to_pe_headers as usize;
    let coff_headers_end = coff_headers_start + 24;
    parse_coff(&file[coff_headers_start..coff_headers_end], &mut headers.coff_headers);

    // Parse optional headers - standard fields
    let mut standard_fields_end = coff_headers_end + 28;
    parse_standard_fields(&file[coff_headers_end..standard_fields_end], &mut headers.optional_headers.standard_fields);
    pe_32 = headers.optional_headers.standard_fields.magic == 0x108;
    if !pe_32 {
        standard_fields_end -= 4;
    }

    // Parse optional headers - windows specific
    let mut windows_specific_end = standard_fields_end + 68;
    if !pe_32 {
        windows_specific_end += 20;
    }
    parse_windows_specific(&file[standard_fields_end..windows_specific_end], &pe_32, &mut headers.optional_headers.windows_specific);

    // Parse data directories
    let data_directories_end = windows_specific_end + (8 * (headers.optional_headers.windows_specific.number_of_rva_and_sizes as usize));
    parse_data_directories(&file[windows_specific_end..data_directories_end], headers.optional_headers.windows_specific.number_of_rva_and_sizes, &mut headers.optional_headers.data_directories);

    headers
}