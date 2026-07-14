//! DEX 文件解析模块
//!
//! 提供 DEX 文件的解析能力，支持从文件或内存中解析 DEX 格式。

use crate::Result;
use byteorder::{LittleEndian, ReadBytesExt};
use std::collections::HashMap;
use std::io::{Cursor, Read};

#[derive(Debug, Clone)]
pub struct DexHeader {
    pub magic: [u8; 8],
    pub checksum: u32,
    pub signature: [u8; 20],
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub link_size: u32,
    pub link_off: u32,
    pub map_off: u32,
    pub string_ids_size: u32,
    pub string_ids_off: u32,
    pub type_ids_size: u32,
    pub type_ids_off: u32,
    pub proto_ids_size: u32,
    pub proto_ids_off: u32,
    pub field_ids_size: u32,
    pub field_ids_off: u32,
    pub method_ids_size: u32,
    pub method_ids_off: u32,
    pub class_defs_size: u32,
    pub class_defs_off: u32,
    pub data_size: u32,
    pub data_off: u32,
}

#[derive(Debug, Clone)]
pub struct DexStringId {
    pub string_data_off: u32,
}

#[derive(Debug, Clone)]
pub struct DexTypeId {
    pub descriptor_idx: u32,
}

#[derive(Debug, Clone)]
pub struct DexMethodId {
    pub class_idx: u32,
    pub proto_idx: u32,
    pub name_idx: u32,
}

#[derive(Debug, Clone)]
pub struct DexClassDef {
    pub class_idx: u32,
    pub access_flags: u32,
    pub superclass_idx: u32,
    pub interfaces_off: u32,
    pub source_file_idx: u32,
    pub annotations_off: u32,
    pub class_data_off: u32,
    pub static_values_off: u32,
}

#[derive(Debug, Clone)]
pub struct DexMethodInfo {
    pub class_name: String,
    pub method_name: String,
    pub descriptor: String,
    pub access_flags: u32,
}

pub struct DexFile {
    data: Vec<u8>,
    header: DexHeader,
    strings: Vec<String>,
    types: Vec<String>,
    methods: Vec<DexMethodInfo>,
}

impl DexFile {
    pub fn from_file(path: &str) -> Result<Self> {
        let data = std::fs::read(path)?;
        Self::from_bytes(&data)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data);
        let header = Self::read_header(&mut cursor)?;

        if !Self::is_valid_magic(&header.magic) {
            return Err(crate::FridaError::Other("无效的 DEX 文件格式".to_string()).into());
        }

        let strings = Self::read_strings(data, &header)?;
        let types = Self::read_types(data, &header, &strings)?;
        let methods = Self::read_methods(data, &header, &strings, &types)?;

        Ok(DexFile {
            data: data.to_vec(),
            header,
            strings,
            types,
            methods,
        })
    }

    pub fn header(&self) -> &DexHeader {
        &self.header
    }

    pub fn strings(&self) -> &[String] {
        &self.strings
    }

    pub fn types(&self) -> &[String] {
        &self.types
    }

    pub fn methods(&self) -> &[DexMethodInfo] {
        &self.methods
    }

    pub fn find_method(&self, method_name: &str) -> Vec<&DexMethodInfo> {
        self.methods
            .iter()
            .filter(|m| m.method_name == method_name)
            .collect()
    }

    pub fn find_class_methods(&self, class_name: &str) -> Vec<&DexMethodInfo> {
        self.methods
            .iter()
            .filter(|m| m.class_name == class_name || m.class_name.ends_with(&format!("/{}", class_name)))
            .collect()
    }

    pub fn search_string(&self, pattern: &str) -> Vec<(u32, &str)> {
        self.strings
            .iter()
            .enumerate()
            .filter(|(_, s)| s.contains(pattern))
            .map(|(i, s)| (i as u32, s.as_str()))
            .collect()
    }

    fn read_header(cursor: &mut Cursor<&[u8]>) -> Result<DexHeader> {
        let mut magic = [0u8; 8];
        cursor.read_exact(&mut magic)?;

        Ok(DexHeader {
            magic,
            checksum: cursor.read_u32::<LittleEndian>()?,
            signature: {
                let mut sig = [0u8; 20];
                cursor.read_exact(&mut sig)?;
                sig
            },
            file_size: cursor.read_u32::<LittleEndian>()?,
            header_size: cursor.read_u32::<LittleEndian>()?,
            endian_tag: cursor.read_u32::<LittleEndian>()?,
            link_size: cursor.read_u32::<LittleEndian>()?,
            link_off: cursor.read_u32::<LittleEndian>()?,
            map_off: cursor.read_u32::<LittleEndian>()?,
            string_ids_size: cursor.read_u32::<LittleEndian>()?,
            string_ids_off: cursor.read_u32::<LittleEndian>()?,
            type_ids_size: cursor.read_u32::<LittleEndian>()?,
            type_ids_off: cursor.read_u32::<LittleEndian>()?,
            proto_ids_size: cursor.read_u32::<LittleEndian>()?,
            proto_ids_off: cursor.read_u32::<LittleEndian>()?,
            field_ids_size: cursor.read_u32::<LittleEndian>()?,
            field_ids_off: cursor.read_u32::<LittleEndian>()?,
            method_ids_size: cursor.read_u32::<LittleEndian>()?,
            method_ids_off: cursor.read_u32::<LittleEndian>()?,
            class_defs_size: cursor.read_u32::<LittleEndian>()?,
            class_defs_off: cursor.read_u32::<LittleEndian>()?,
            data_size: cursor.read_u32::<LittleEndian>()?,
            data_off: cursor.read_u32::<LittleEndian>()?,
        })
    }

    fn is_valid_magic(magic: &[u8; 8]) -> bool {
        magic[0..4] == [0x64, 0x65, 0x78, 0x0A]
    }

    fn read_strings(data: &[u8], header: &DexHeader) -> Result<Vec<String>> {
        let mut strings = Vec::with_capacity(header.string_ids_size as usize);
        let mut cursor = Cursor::new(data);

        for i in 0..header.string_ids_size {
            let offset = header.string_ids_off + i * 4;
            cursor.set_position(offset as u64);
            let string_data_off = cursor.read_u32::<LittleEndian>()?;
            
            let s = Self::read_string_data(data, string_data_off);
            strings.push(s);
        }

        Ok(strings)
    }

    fn decode_uleb128(cursor: &mut Cursor<&[u8]>) -> usize {
        let mut result = 0usize;
        let mut shift = 0usize;
        let mut byte;
        
        loop {
            match cursor.read_u8() {
                Ok(b) => byte = b,
                Err(_) => break,
            }
            
            result |= ((byte & 0x7F) as usize) << shift;
            shift += 7;
            
            if (byte & 0x80) == 0 {
                break;
            }
            
            if shift >= 32 {
                break;
            }
        }
        
        result
    }

    fn read_string_data(data: &[u8], offset: u32) -> String {
        let mut cursor = Cursor::new(&data[offset as usize..]);
        
        let length = Self::decode_uleb128(&mut cursor);
        
        let mut buf = vec![0u8; length];
        if cursor.read_exact(&mut buf).is_ok() {
            String::from_utf8_lossy(&buf).to_string()
        } else {
            String::new()
        }
    }

    fn read_types(data: &[u8], header: &DexHeader, strings: &[String]) -> Result<Vec<String>> {
        let mut types = Vec::with_capacity(header.type_ids_size as usize);
        let mut cursor = Cursor::new(data);

        for i in 0..header.type_ids_size {
            let offset = header.type_ids_off + i * 4;
            cursor.set_position(offset as u64);
            let descriptor_idx = cursor.read_u32::<LittleEndian>()?;
            
            if descriptor_idx < strings.len() as u32 {
                types.push(strings[descriptor_idx as usize].clone());
            } else {
                types.push(String::new());
            }
        }

        Ok(types)
    }

    fn read_methods(data: &[u8], header: &DexHeader, strings: &[String], types: &[String]) -> Result<Vec<DexMethodInfo>> {
        let mut methods = Vec::with_capacity(header.method_ids_size as usize);
        let mut cursor = Cursor::new(data);

        for i in 0..header.method_ids_size {
            let offset = header.method_ids_off + i * 8;
            cursor.set_position(offset as u64);
            
            let class_idx = cursor.read_u16::<LittleEndian>()? as u32;
            let proto_idx = cursor.read_u16::<LittleEndian>()? as u32;
            let name_idx = cursor.read_u32::<LittleEndian>()?;

            let class_name = if class_idx < types.len() as u32 {
                types[class_idx as usize].clone()
            } else {
                String::new()
            };

            let method_name = if name_idx < strings.len() as u32 {
                strings[name_idx as usize].clone()
            } else {
                String::new()
            };

            let descriptor = if proto_idx < header.proto_ids_size {
                Self::read_proto_descriptor(data, header, proto_idx, strings)
            } else {
                String::new()
            };

            methods.push(DexMethodInfo {
                class_name,
                method_name,
                descriptor,
                access_flags: 0,
            });
        }

        Ok(methods)
    }

    fn read_proto_descriptor(data: &[u8], header: &DexHeader, proto_idx: u32, strings: &[String]) -> String {
        let proto_off = header.proto_ids_off + proto_idx * 12;
        let mut cursor = Cursor::new(&data[proto_off as usize..]);
        
        let shorty_idx = cursor.read_u32::<LittleEndian>().unwrap_or(0);
        
        if shorty_idx < strings.len() as u32 {
            strings[shorty_idx as usize].clone()
        } else {
            String::new()
        }
    }
}