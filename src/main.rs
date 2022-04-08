use std::fmt::Debug;
use std::io::Read;
use std::marker::PhantomData;

use object::macho::{LinkeditDataCommand, MachHeader32, MachHeader64, LC_FUNCTION_STARTS};
use object::read::macho::{LoadCommandIterator, MachHeader};
use object::{Endianness, FileKind, ReadRef};

use anyhow::{anyhow, Context};

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args_os().skip(1);
    if args.len() < 1 {
        eprintln!("Usage: {} <path>", std::env::args().next().unwrap());
        std::process::exit(1);
    }
    let path = args.next().unwrap();

    let mut data = Vec::new();
    let mut file = std::fs::File::open(path)?;
    file.read_to_end(&mut data)?;
    let data = &data[..];
    let kind = FileKind::parse(data)?;
    let is_64 = match kind {
        FileKind::MachO32 => false,
        FileKind::MachO64 => true,
        _ => {
            eprintln!("Unrecognized file kind {:?}", kind);
            std::process::exit(1);
        }
    };
    let macho = MachOData::new(data, 0, is_64);
    if let Some(bind_symbol_tables) = macho.bind_symbol_tables()? {
        println!("Bind symbols:");
        if !bind_symbol_tables.bind_symbols.is_empty() {
            for sym in &bind_symbol_tables.bind_symbols {
                println!("{:?}", sym);
            }
        } else {
            println!("No bind symbols.");
        }
        println!("Weak bind symbols:");
        if !bind_symbol_tables.weak_bind_symbols.is_empty() {
            for sym in &bind_symbol_tables.weak_bind_symbols {
                println!("{:?}", sym);
            }
        } else {
            println!("No weak bind symbols.");
        }
        println!("Lazy bind symbols:");
        if !bind_symbol_tables.lazy_bind_symbols.is_empty() {
            for sym in &bind_symbol_tables.lazy_bind_symbols {
                println!("{:?}", sym);
            }
        } else {
            println!("No lazy bind symbols.");
        }
    } else {
        println!("Did not find any bind symbol information.");
    }
    Ok(())
}

pub struct MachOData<'data, R: ReadRef<'data>> {
    data: R,
    header_offset: u64,
    is_64: bool,
    _phantom: PhantomData<&'data ()>,
}

impl<'data, R: ReadRef<'data>> MachOData<'data, R> {
    pub fn new(data: R, header_offset: u64, is_64: bool) -> Self {
        Self {
            data,
            header_offset,
            is_64,
            _phantom: PhantomData,
        }
    }

    /// Read the list of function start addresses from the LC_FUNCTION_STARTS mach-O load command.
    /// This information is usually present even in stripped binaries. It's a uleb128 encoded list
    /// of deltas between the function addresses, with a zero delta terminator.
    pub fn get_function_starts(&self) -> anyhow::Result<Option<Vec<u32>>> {
        let data = self.function_start_data()?;
        let data = if let Some(data) = data {
            data
        } else {
            return Ok(None);
        };
        let mut function_starts = Vec::new();
        let mut prev_address = 0;
        let mut bytes = data;
        while let Some((delta, rest)) = read_uleb128(bytes) {
            if delta == 0 {
                break;
            }
            bytes = rest;
            let address = prev_address + delta;
            function_starts.push(address as u32);
            prev_address = address;
        }

        Ok(Some(function_starts))
    }

    fn load_command_iter<M: MachHeader>(
        &self,
    ) -> object::read::Result<(M::Endian, LoadCommandIterator<M::Endian>)> {
        let header = M::parse(self.data, self.header_offset)?;
        let endian = header.endian()?;
        let load_commands = header.load_commands(endian, self.data, self.header_offset)?;
        Ok((endian, load_commands))
    }

    fn load_command_iter_gen(
        &self,
    ) -> object::read::Result<(Endianness, LoadCommandIterator<Endianness>)> {
        if self.is_64 {
            self.load_command_iter::<MachHeader64<Endianness>>()
        } else {
            self.load_command_iter::<MachHeader32<Endianness>>()
        }
    }

    fn function_start_data(&self) -> object::read::Result<Option<&'data [u8]>> {
        let (endian, mut commands) = self.load_command_iter_gen()?;
        while let Ok(Some(command)) = commands.next() {
            if command.cmd() == LC_FUNCTION_STARTS {
                let command: &LinkeditDataCommand<_> = command.data()?;
                let dataoff: u64 = command.dataoff.get(endian).into();
                let datasize: u64 = command.datasize.get(endian).into();
                let data = self.data.read_bytes_at(dataoff, datasize).ok();
                return Ok(data);
            }
        }
        Ok(None)
    }

    fn bind_data(&self) -> anyhow::Result<Option<(&'data [u8], &'data [u8], &'data [u8])>> {
        let (endian, mut commands) = self.load_command_iter_gen()?;
        while let Some(command) = commands.next()? {
            if let Some(dyld_info) = command.dyld_info()? {
                let bind_off: u64 = dyld_info.bind_off.get(endian).into();
                let bind_size: u64 = dyld_info.bind_size.get(endian).into();
                let weak_bind_off: u64 = dyld_info.weak_bind_off.get(endian).into();
                let weak_bind_size: u64 = dyld_info.weak_bind_size.get(endian).into();
                let lazy_bind_off: u64 = dyld_info.lazy_bind_off.get(endian).into();
                let lazy_bind_size: u64 = dyld_info.lazy_bind_size.get(endian).into();

                let bind_data = self
                    .data
                    .read_bytes_at(bind_off, bind_size)
                    .map_err(|_| anyhow!("couldn't read file"))?;
                let weak_bind_data = self
                    .data
                    .read_bytes_at(weak_bind_off, weak_bind_size)
                    .map_err(|_| anyhow!("couldn't read file"))?;
                let lazy_bind_data = self
                    .data
                    .read_bytes_at(lazy_bind_off, lazy_bind_size)
                    .map_err(|_| anyhow!("couldn't read file"))?;
                return Ok(Some((bind_data, weak_bind_data, lazy_bind_data)));
            }
        }
        Ok(None)
    }

    fn bind_symbol_tables(&self) -> anyhow::Result<Option<BindSymbolTables>> {
        let symbols = match self.bind_data()? {
            Some((bind_data, weak_bind_data, lazy_bind_data)) => BindSymbolTables {
                bind_symbols: decode_bound_symbols(bind_data, self.is_64)?,
                weak_bind_symbols: decode_bound_symbols(weak_bind_data, self.is_64)?,
                lazy_bind_symbols: decode_bound_symbols(lazy_bind_data, self.is_64)?,
            },
            None => return Ok(None),
        };
        Ok(Some(symbols))
    }
}

struct BindSymbolTables<'a> {
    pub bind_symbols: Vec<BoundSymbol<'a>>,
    pub weak_bind_symbols: Vec<BoundSymbol<'a>>,
    pub lazy_bind_symbols: Vec<BoundSymbol<'a>>,
}

#[derive(Clone, Copy)]
struct BoundSymbol<'a> {
    pub name_bytes: &'a [u8],
    pub segment: u8,
    pub segment_offset: i64,
    pub lib_ordinal: i32,
}

impl<'a> Debug for BoundSymbol<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "segment {} {} 0x{:x}: {} (from library {})",
            self.segment,
            if self.segment_offset >= 0 { "+" } else { "-" },
            self.segment_offset.abs(),
            &String::from_utf8_lossy(self.name_bytes),
            self.lib_ordinal
        )
    }
}

fn decode_bound_symbols(mut data: &[u8], is_64: bool) -> anyhow::Result<Vec<BoundSymbol>> {
    // Based on https://reverseengineering.stackexchange.com/a/14064

    let pointer_width = if is_64 { 8 } else { 4 };

    let mut sym = BoundSymbol {
        name_bytes: b"",
        segment: 0,
        segment_offset: 0,
        lib_ordinal: 0,
    };

    let mut symbols = Vec::new();

    while !data.is_empty() {
        let byte = data[0];
        let opcode = byte & object::macho::BIND_OPCODE_MASK;
        let immediate = byte & object::macho::BIND_IMMEDIATE_MASK;
        data = &data[1..];

        match opcode {
            object::macho::BIND_OPCODE_DONE => {}
            object::macho::BIND_OPCODE_SET_DYLIB_ORDINAL_IMM => {
                sym.lib_ordinal = immediate.into();
            }
            object::macho::BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => {
                let (val, rest) = read_uleb128(data).ok_or_else(|| anyhow!("Invalid uleb128"))?;
                data = rest;
                sym.lib_ordinal = val.try_into().context("couldn't convert to i32")?;
            }
            object::macho::BIND_OPCODE_SET_DYLIB_SPECIAL_IMM => {
                sym.lib_ordinal = -i32::try_from(immediate).context("couldn't convert to i32")?;
            }
            object::macho::BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => {
                let name_end = memchr::memchr(0, data).ok_or_else(|| anyhow!("No null byte"))?;
                sym.name_bytes = &data[..name_end];
                data = &data[name_end + 1..];
            }
            object::macho::BIND_OPCODE_SET_TYPE_IMM => {}
            object::macho::BIND_OPCODE_SET_ADDEND_SLEB => {
                let (_, rest) = read_uleb128(data).ok_or_else(|| anyhow!("Invalid uleb128"))?;
                data = rest;
            }
            object::macho::BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                sym.segment = immediate;
                let (offset, rest) =
                    read_uleb128(data).ok_or_else(|| anyhow!("Invalid uleb128"))?;
                data = rest;
                sym.segment_offset = offset as i64;
            }
            object::macho::BIND_OPCODE_ADD_ADDR_ULEB => {
                let (addend, rest) =
                    read_uleb128(data).ok_or_else(|| anyhow!("Invalid uleb128"))?;
                data = rest;
                sym.segment_offset += addend as i64;
            }
            object::macho::BIND_OPCODE_DO_BIND => {
                symbols.push(sym);
            }
            object::macho::BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                symbols.push(sym);
                let (addend, rest) =
                    read_uleb128(data).ok_or_else(|| anyhow!("Invalid uleb128"))?;
                data = rest;
                sym.segment_offset += addend as i64;
            }
            object::macho::BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                symbols.push(sym);
                sym.segment_offset += immediate as i64 * pointer_width;
            }
            object::macho::BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                let (times, rest) = read_uleb128(data).ok_or_else(|| anyhow!("Invalid uleb128"))?;
                let (skip, rest) = read_uleb128(rest).ok_or_else(|| anyhow!("Invalid uleb128"))?;
                data = rest;
                for _ in 0..times {
                    symbols.push(sym);
                    sym.segment_offset += pointer_width + skip as i64;
                }
            }
            _ => {
                eprintln!(
                    "warning: unknown bind opcode {}, immediate {}",
                    opcode, immediate
                );
            }
        }
    }
    Ok(symbols)
}

fn read_uleb128(mut bytes: &[u8]) -> Option<(u64, &[u8])> {
    const CONTINUATION_BIT: u8 = 1 << 7;

    let mut result = 0;
    let mut shift = 0;

    while !bytes.is_empty() {
        let byte = bytes[0];
        bytes = &bytes[1..];
        if shift == 63 && byte != 0x00 && byte != 0x01 {
            return None;
        }

        let low_bits = u64::from(byte & !CONTINUATION_BIT);
        result |= low_bits << shift;

        if byte & CONTINUATION_BIT == 0 {
            return Some((result, bytes));
        }

        shift += 7;
    }
    None
}
