#![allow(dead_code)]
#![allow(unused_variables)]

pub fn consume_u64_from_buffer(buffer: &[u8], index: &mut usize) -> u64 {
    let mut arr: [u8; 8] = [0; 8];
    arr.copy_from_slice(&buffer[*index..*index+8]);
    let ret = u64::from_le_bytes(arr);
    *index += 8;
    ret
}

pub fn consume_u32_from_buffer(buffer: &[u8], index: &mut usize) -> u32 {
    let mut arr: [u8; 4] = [0; 4];   
    arr.copy_from_slice(&buffer[*index..*index+4]);
    let ret = u32::from_le_bytes(arr);
    *index += 4;
    ret
}

pub fn consume_u16_from_buffer(buffer: &[u8], index: &mut usize) -> u16 {
    let mut arr: [u8; 2] = [0; 2];   
    arr.copy_from_slice(&buffer[*index..*index+2]);
    let ret = u16::from_le_bytes(arr);
    *index += 2;
    ret
}