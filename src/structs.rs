#![allow(dead_code)]
#![allow(unused_variables)]

use std::fmt;
use std::vec::Vec;

// Structures definitions

pub struct Headers {
    pub dos_headers: DOSHeaders,
    pub coff_headers: COFFHeaders,
    pub optional_headers: OptionalHeaders,
}

pub struct DOSHeaders {
    pub magic: u16,
    pub last_size: u16,
    pub pages_in_file: u16,
    pub relocations: u16,
    pub header_size_in_paragraph: u16,
    pub min_extra_paragraph_needed: u16,
    pub max_extra_paragraph_needed: u16,
    pub initial_ss: u16,
    pub initial_sp: u16,
    pub checksum: u16,
    pub initial_ip: u16,
    pub initial_cs: u16,
    pub file_add_of_relocation_table: u16,
    pub overlay_number: u16,
    pub reserved_one: [u8; 8],
    pub oem_identifier: u16,
    pub oem_information: u16,
    pub reserved_two: [u8; 20],
    pub offset_to_pe_headers: u32,
}

#[derive(Debug)]
pub enum CharacteristicsVal {
    IMAGE_FILE_RELOCS_STRIPPED = 0x0001,
    IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002,
    IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004,
    IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008,
    IMAGE_FILE_AGGRESSIVE_WS_TRIM = 0x0010,
    IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020,
    IMAGE_FILE_BYTES_REVERSED_LO = 0x0080,
    IMAGE_FILE_32BIT_MACHINE = 0x0100,
    IMAGE_FILE_DEBUG_STRIPPED = 0x0200,
    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400,
    IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800,
    IMAGE_FILE_SYSTEM = 0x1000,
    IMAGE_FILE_DLL = 0x2000,
    IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000,
    IMAGE_FILE_BYTES_REVERSED_HI = 0x8000,
}

pub struct Characteristics {
    pub value: u16,
    pub characteristics_list: Vec<CharacteristicsVal>,
}

pub struct COFFHeaders { 
    pub magic: u32,
    pub target_machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_headers: u16,
    pub characteristics: Characteristics,
}

pub struct OptionalHeaders {
    pub standard_fields: StandardFields,
    pub windows_specific: WindowsSpecific,
    pub data_directories: DataDirectories,
}

pub struct StandardFields {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
}

pub struct WindowsSpecific {
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

pub struct DataDirectories {
    pub directories: [DataDirectory; 16],
}

#[derive(Copy)]
#[derive(Clone)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}


// Default trait implementation for the structs

impl Default for Headers {
    fn default() -> Headers {
        Headers {
            dos_headers: DOSHeaders::default(),
            coff_headers: COFFHeaders::default(),
            optional_headers: OptionalHeaders::default(),
        }
    }
}

impl Default for DOSHeaders {
    fn default() -> DOSHeaders {
        DOSHeaders {
            magic: 0,
            last_size: 0,
            pages_in_file: 0,
            relocations: 0,
            header_size_in_paragraph: 0,
            min_extra_paragraph_needed: 0,
            max_extra_paragraph_needed: 0,
            initial_ss: 0,
            initial_sp: 0,
            checksum: 0,
            initial_ip: 0,
            initial_cs: 0,
            file_add_of_relocation_table: 0,
            overlay_number: 0,
            reserved_one: [0; 8],
            oem_identifier: 0,
            oem_information: 0,
            reserved_two: [0; 20],
            offset_to_pe_headers: 0,            
        }
    }
}

impl Default for Characteristics {
    fn default() -> Characteristics { 
        Characteristics {
            characteristics_list: Vec::new(),
            value: 0,
        }
    }
}

impl Default for COFFHeaders {
    fn default() -> COFFHeaders {
        COFFHeaders {
            magic: 0,
            target_machine: 0,
            number_of_sections: 0,
            time_date_stamp: 0,
            pointer_to_symbol_table: 0,
            number_of_symbols: 0,
            size_of_optional_headers: 0,
            characteristics: Characteristics::default(),
        }
    }
}

impl Default for OptionalHeaders {
    fn default() -> OptionalHeaders {
        OptionalHeaders {
            standard_fields: StandardFields::default(),
            windows_specific: WindowsSpecific::default(),
            data_directories: DataDirectories::default(),
        }
    }
}

impl Default for StandardFields {
    fn default() -> StandardFields {
        StandardFields {
            magic: 0,
            major_linker_version: 0,
            minor_linker_version: 0,
            size_of_code: 0,
            size_of_initialized_data: 0,
            size_of_uninitialized_data: 0,
            address_of_entry_point: 0,
            base_of_code: 0,
            base_of_data: 0,
        }
    }
}

impl Default for WindowsSpecific {
    fn default() -> WindowsSpecific {
        WindowsSpecific {
            image_base: 0,
            section_alignment: 0,
            file_alignment: 0,
            major_operating_system_version: 0,
            minor_operating_system_version: 0,
            major_image_version: 0,
            minor_image_version: 0,
            major_subsystem_version: 0,
            minor_subsystem_version: 0,
            win32_version_value: 0,
            size_of_image: 0,
            size_of_headers: 0,
            checksum: 0,
            subsystem: 0,
            dll_characteristics: 0,
            size_of_stack_reserve: 0,
            size_of_stack_commit: 0,
            size_of_heap_reserve: 0,
            size_of_heap_commit: 0,
            loader_flags: 0,
            number_of_rva_and_sizes: 0,
        }
    }
}

impl Default for DataDirectories {
    fn default() -> DataDirectories {
        DataDirectories {
            directories: [DataDirectory::default(); 16],
        }
    }
}

impl Default for DataDirectory {
    fn default() -> DataDirectory {
        DataDirectory {
            virtual_address: 0,
            size: 0,
        }
    }
}

// TryFrom implementation for structs

impl CharacteristicsVal {
    pub fn from_u16(val: u16) -> CharacteristicsVal {
        match val {
            0x0001 => CharacteristicsVal::IMAGE_FILE_RELOCS_STRIPPED,
            0x0002 => CharacteristicsVal::IMAGE_FILE_EXECUTABLE_IMAGE,
            0x0004 => CharacteristicsVal::IMAGE_FILE_LINE_NUMS_STRIPPED,
            0x0008 => CharacteristicsVal::IMAGE_FILE_LOCAL_SYMS_STRIPPED,
            0x0010 => CharacteristicsVal::IMAGE_FILE_AGGRESSIVE_WS_TRIM ,
            0x0020 => CharacteristicsVal::IMAGE_FILE_LARGE_ADDRESS_AWARE,
            0x0080 => CharacteristicsVal::IMAGE_FILE_BYTES_REVERSED_LO,
            0x0100 => CharacteristicsVal::IMAGE_FILE_32BIT_MACHINE,
            0x0200 => CharacteristicsVal::IMAGE_FILE_DEBUG_STRIPPED,
            0x0400 => CharacteristicsVal::IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP,
            0x0800 => CharacteristicsVal::IMAGE_FILE_NET_RUN_FROM_SWAP,
            0x1000 => CharacteristicsVal::IMAGE_FILE_SYSTEM,
            0x2000 => CharacteristicsVal::IMAGE_FILE_DLL,
            0x4000 => CharacteristicsVal::IMAGE_FILE_UP_SYSTEM_ONLY,
            0x8000 => CharacteristicsVal::IMAGE_FILE_BYTES_REVERSED_HI,
            _ => panic!("Failed to convert to CharacteristicsVal"),
        }
    }
}


// Display trait implementation for the structs

impl fmt::Display for Headers {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "HEADERS
{}
{}
{}",
        self.dos_headers, self.coff_headers, self.optional_headers)
    }
}

impl fmt::Display for DOSHeaders {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "DOS Headers

---------------------------
magic: 0x{:x}
last_size: 0x{:x}
pages_in_file: 0x{:x}
relocations: 0x{:x}
header_size_in_paragraph: 0x{:x}
min_extra_paragraph_needed: 0x{:x}
max_extra_paragraph_needed: 0x{:x}
initial_ss: 0x{:x}
initial_sp: 0x{:x}
checksum: 0x{:x}
initial_ip: 0x{:x}
initial_cs: 0x{:x}
file_add_of_relocation_table: 0x{:x}
overlay_number: 0x{:x}
oem_identifier: 0x{:x}
oem_information: 0x{:x}
offset_to_pe_headers: 0x{:x}
---------------------------",
        self.magic, self.last_size, self.pages_in_file, self.relocations, self.header_size_in_paragraph, self.min_extra_paragraph_needed, self.max_extra_paragraph_needed, self.initial_ss, self.initial_sp, self.checksum, self.initial_ip, self.initial_cs, self.file_add_of_relocation_table, self.overlay_number, self.oem_identifier, self.oem_information, self.offset_to_pe_headers)
    }
}

impl fmt::Display for COFFHeaders {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "COFF Headers

---------------------------
magic: 0x{:x}
target_machine: 0x{:x}
number_of_sections: 0x{:x}
time_date_stamp: 0x{:x}
pointer_to_symbol_table: 0x{:x}
number_of_symbols: 0x{:x}
size_of_optional_headers: 0x{:x}
---------------------------", 
        self.magic, self.target_machine, self.number_of_sections, self.time_date_stamp, self.pointer_to_symbol_table, self.number_of_symbols, self.size_of_optional_headers)
    }
}

impl fmt::Display for OptionalHeaders {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Optional Headers
{}
{}
{}",
        self.standard_fields, self.windows_specific, self.data_directories)
    }
}

impl fmt::Display for StandardFields {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Standard fields

---------------------------
magic: 0x{:x}
major_linker_version: 0x{:x}
minor_linker_version: 0x{:x}
size_of_code: 0x{:x}
size_of_initialized_data: 0x{:x}
size_of_uninitialized_data: 0x{:x}
address_of_entry_point: 0x{:x}
base_of_code: 0x{:x}
base_of_data: 0x{:x}
---------------------------", 
        self.magic, self.major_linker_version, self.minor_linker_version, self.size_of_code, self.size_of_initialized_data, self.size_of_uninitialized_data, self.address_of_entry_point, self.base_of_code, self.base_of_data)
    }
}

impl fmt::Display for WindowsSpecific {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Windows-specific field

---------------------------
image_base: 0x{:x}
section_alignment: 0x{:x}
file_alignment: 0x{:x}
major_operating_system_version: 0x{:x}
minor_operating_system_version: 0x{:x}
major_image_version: 0x{:x}
minor_image_version: 0x{:x}
major_subsystem_version: 0x{:x}
minor_subsystem_version: 0x{:x}
win32_version_value: 0x{:x}
size_of_image: 0x{:x}
size_of_headers: 0x{:x}
checksum: 0x{:x}
subsystem: 0x{:x}
dll_characteristics: 0x{:x}
size_of_stack_reserve: 0x{:x}
size_of_stack_commit: 0x{:x}
size_of_heap_reserve: 0x{:x}
size_of_heap_commit: 0x{:x}
loader_flags: 0x{:x}
number_of_rva_and_sizes: 0x{:x}
---------------------------", 
        self.image_base, self.section_alignment, self.file_alignment, self.major_operating_system_version, self.minor_operating_system_version, self.major_image_version, self.minor_image_version, self.major_subsystem_version, self.minor_subsystem_version, self.win32_version_value, self.size_of_image, self.size_of_headers, self.checksum, self.subsystem, self.dll_characteristics, self.size_of_stack_reserve, self.size_of_stack_commit, self.size_of_heap_reserve, self.size_of_heap_commit, self.loader_flags, self.number_of_rva_and_sizes)
    }
}

impl fmt::Display for DataDirectories {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Data Directories

---------------------------");
        for d in self.directories {
            write!(f, "{}", d);
        }
        Ok(())
    }
}

impl fmt::Display for DataDirectory {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "
virtual_address: 0x{:x}
size: 0x{:x}        
        ",
        self.virtual_address, self.size)
    }
}






