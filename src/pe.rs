use std::ffi::CStr;
use std::os::raw::c_char;

use ::Export;

const DOS_MAGIC: u16 = 0x5a4d;
const PE_MAGIC: u32 = 0x4550;

unsafe fn read_at<Ty: Copy>(offset: usize) -> Ty {
    *(offset as *mut Ty)
}

/// Gets pointer to the import table of an image which has been loaded to memory.
/// Preconditions: `image_base` must be address of first byte of the image (MS-DOS header).
pub unsafe fn import_ptr(image_base: usize,
                         dll_name: &[u8],
                         import: &Export
                         ) -> Option<*mut usize>
{
    import_table(image_base).and_then(|(imps, size, is_64)| {
        let mut pos = 0;
        while pos + 0x14 <= size {
            let name_offset = read_at::<u32>(imps + pos as usize + 0xc) as usize;
            if name_offset == 0 {
                return None;
            }
            let name_addr = image_base + name_offset;
            let name = CStr::from_ptr(name_addr as *const c_char);
            if name.to_bytes().eq_ignore_ascii_case(dll_name) {
                let lookups = image_base + read_at::<u32>(imps + pos as usize) as usize;
                let addresses = image_base + read_at::<u32>(imps + pos as usize + 0x10) as usize;
                return Some((lookups, addresses, is_64));
            }
            pos += 0x14;
        }
        None
    }).and_then(|(lookups, addresses, is_64)| {
        let mut pos = 0;
        loop {
            let val = if is_64 {
                // PE32+ has the high bits unused anyways, other than
                // the highest one which is the name/ordinal bool bool.
                let val = read_at::<u32>(lookups + pos);
                let high = read_at::<u32>(lookups + pos + 4);
                val | (high & 0x8000_0000)
            } else {
                read_at::<u32>(lookups + pos)
            };
            if val == 0 {
                return None;
            }
            match *import {
                Export::Name(name) => {
                    if val & 0x8000_0000 == 0 {
                        let name_addr = image_base + val as usize + 2;
                        let func_name = CStr::from_ptr(name_addr as *const c_char);
                        if func_name.to_bytes() == name {
                            return Some((addresses + pos) as *mut usize);
                        }
                    }
                }
                Export::Ordinal(ord) => {
                    if val & 0x8000_0000 != 0 && (val & 0xffff) as u16 == ord {
                        return Some((addresses + pos) as *mut usize);
                    }
                }
            }
            pos += if is_64 { 0x8 } else { 0x4 };
        }
    })
}

unsafe fn import_table(image_base: usize) -> Option<(usize, u32, bool)> {
    if read_at::<u16>(image_base) != DOS_MAGIC {
        return None;
    }
    let pe_offset = read_at::<u32>(image_base + 0x3c);
    if read_at::<u32>(image_base + pe_offset as usize) != PE_MAGIC {
        return None;
    }
    let coff_header = image_base + pe_offset as usize + 4;
    let opt_header_size = read_at::<u16>(coff_header + 0x10);
    let opt_header = coff_header + 0x14;
    if opt_header_size < 0x70 {
        return None;
    }
    let (is_64, import_data_dir) = match read_at::<u16>(opt_header) {
        0x10b => (false, opt_header + 0x68),
        0x20b => (true, opt_header + 0x78),
        _ => return None,
    };
    let import_table_offset = read_at::<u32>(import_data_dir);
    let import_table_size = read_at::<u32>(import_data_dir + 0x4);
    Some((image_base + import_table_offset as usize, import_table_size, is_64))
}

#[test]
fn test_import_ptr() {
    unsafe {
        let addr = ::platform::exe_handle() as usize;
        assert!(import_ptr(addr, b"kernel32.dll", &Export::Name(b"GetProcAddress")).is_some());
        assert!(import_ptr(addr, b"KERNEL32.dll", &Export::Name(b"GetProcAddress")).is_some());
        assert!(import_ptr(addr, b"kernel32.dll", &Export::Name(b"HeapAlloc")).is_some());
        assert!(import_ptr(addr, b"kernel32.dll", &Export::Name(b"getprocaddress")).is_none());
        assert!(import_ptr(addr, b"kernel32.dll", &Export::Name(b"DoesNotExist")).is_none());
        assert!(import_ptr(addr, b"user32.dll", &Export::Name(b"VirtualAlloc")).is_none());
        assert!(import_ptr(addr, b"zzzqqqwhatever", &Export::Name(b"VirtualAlloc")).is_none());
    }
}
