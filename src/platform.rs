use kernel32::{GetModuleHandleW, CreateFileW, SetStdHandle, HeapCreate, HeapAlloc};
use kernel32::{VirtualProtect, VirtualQuery};
use winapi::{DWORD, HANDLE, STD_ERROR_HANDLE, CREATE_ALWAYS, MEMORY_BASIC_INFORMATION};
use winapi::{PAGE_EXECUTE_READWRITE, GENERIC_WRITE, FILE_SHARE_READ, FILE_ATTRIBUTE_NORMAL};

use std::{mem, ptr};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::raw::c_void;
use std::path::Path;
use ::{HookableAsmWrap, ToPointer};

pub fn nop() -> u8 {
    0x90
}

pub fn exe_addr() -> *const c_void {
    unsafe {
        mem::transmute(GetModuleHandleW(ptr::null()))
    }
}

pub fn library_addr(lib: &str) -> *const c_void {
    unsafe {
        mem::transmute(GetModuleHandleW(winapi_str(lib).as_ptr()))
    }
}

fn winapi_str<T: AsRef<OsStr>>(input: T) -> Vec<u16> {
    input.as_ref().encode_wide().chain(Some(0)).collect::<Vec<u16>>()
}

/// Unprotects module, allowing its memory to be written and reapplies protection on drop.
/// As with most of the other utilities, it is not thread-safe to unprotect same module from multiple
/// threads.
pub struct MemoryProtection {
    protections: Vec<(*mut c_void, DWORD, DWORD)>,
}

impl MemoryProtection {
    pub fn new(start: *const c_void) -> MemoryProtection {
        let mut protections = Vec::new();
        unsafe {
            let mut mem_info: MEMORY_BASIC_INFORMATION = mem::uninitialized();
            let mut tmp: DWORD = 0;
            VirtualQuery(start, &mut mem_info, mem::size_of::<MEMORY_BASIC_INFORMATION>() as u32);
            while mem_info.Type == 0x1000000 { // 0x1000000 is MEM_IMAGE
                VirtualProtect(mem_info.BaseAddress, mem_info.RegionSize, PAGE_EXECUTE_READWRITE, &mut tmp);
                protections.push((mem_info.BaseAddress, mem_info.RegionSize, mem_info.Protect));
                let next = mem_info.BaseAddress.offset(mem_info.RegionSize as isize);
                VirtualQuery(next, &mut mem_info, mem::size_of::<MEMORY_BASIC_INFORMATION>() as u32);
            }
        }
        MemoryProtection {
            protections: protections,
        }
    }
}

impl Drop for MemoryProtection {
    fn drop(&mut self) {
        unsafe {
            let mut tmp: DWORD = 0;
            for tp in self.protections.iter() {
                VirtualProtect(tp.0, tp.1, tp.2, &mut tmp);
            }
        }
    }
}

pub unsafe fn redirect_stderr(filename: &Path) -> bool {
    let handle = CreateFileW(winapi_str(filename).as_ptr(), GENERIC_WRITE, FILE_SHARE_READ,
        ptr::null_mut(), CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, ptr::null_mut());
    if handle != ptr::null_mut() {
        SetStdHandle(STD_ERROR_HANDLE, handle) != 0
    } else {
        false
    }
}

pub struct ExecutableHeap {
    handle: HANDLE,
}

impl ExecutableHeap {
    pub fn new() -> ExecutableHeap {
        let options = 0x00040000;
        ExecutableHeap {
            handle: unsafe { HeapCreate(options, 0, 0) },
        }
    }
    pub fn allocate(&mut self, size: usize) -> *mut u8 {
        unsafe { mem::transmute(HeapAlloc(self.handle, 0, size as u32)) }
    }
}

pub unsafe fn call_ins<T: ToPointer>(src: T, tgt: *const u8) {
    let mut ptr = src.ptr();
    *ptr = 0xe8;
    ptr = ptr.offset(1);
    let val: usize = mem::transmute::<_, usize>(tgt).overflowing_sub(mem::transmute::<_, usize>(ptr) + 4).0;
    let hook_ptr: *mut usize = mem::transmute(ptr);
    *hook_ptr = val;
}

pub unsafe fn jump_hook<T: ToPointer>(src: T, tgt: *const u8) {
    let mut ptr = src.ptr();
    *ptr = 0xe9;
    ptr = ptr.offset(1);
    let val: usize = mem::transmute::<_, usize>(tgt).overflowing_sub(mem::transmute::<_, usize>(ptr) + 4).0;
    let hook_ptr: *mut usize = mem::transmute(ptr);
    *hook_ptr = val;
}

unsafe fn x86_sib_ins_size(ins: *const u8) -> usize {
    let sib = if (*ins.offset(1) & 0x7) == 0x4 { 1 } else { 0 };
    match (*ins.offset(1) & 0xc0) >> 6 {
        0 => if (*ins.offset(1) & 0x7) == 0x5 { 6 + sib } else { 2 + sib },
        1 => 3 + sib,
        2 => 6 + sib,
        _ => 2, // No sib
    }
}

unsafe fn x86_ins_size(ins: *const u8) -> usize {
    match *ins {
        0x50 ... 0x62 => 1,
        0x68 => 5,
        0x84 ... 0x90 | 0xff => x86_sib_ins_size(ins),
        0x83 | 0xc6 => x86_sib_ins_size(ins) + 1,
        0x81 => x86_sib_ins_size(ins) + 4,
        0xa1 | 0xb9 | 0xba | 0xe8 | 0xe9 => 5,
        n => panic!("Unimpl ins size 0x{:x}", n),
    }
}

unsafe fn x86_copy_instructions(mut src: *const u8, mut dst: *mut u8, mut len: isize) {
    while len > 0 {
        let ins_len = x86_ins_size(src) as isize;
        // Relative jumps need to be handled differently
        match *src {
            0xe8 | 0xe9 => {
                assert!(ins_len == 5);
                ptr::copy_nonoverlapping(src, dst, 5);
                let diff = mem::transmute::<_, usize>(dst).overflowing_sub(mem::transmute(src)).0;
                let jump_offset: *mut usize = mem::transmute(dst.offset(1));
                *jump_offset = (*jump_offset).overflowing_sub(diff).0;

            }
            _ => ptr::copy_nonoverlapping(src, dst, ins_len as usize),
        }
        src = src.offset(ins_len);
        dst = dst.offset(ins_len);
        len -= ins_len;
    }
}

pub unsafe fn call_hook<T: ToPointer>(src: T, tgt: *const u8, heap: &mut ExecutableHeap) {
    let ptr = src.ptr();
    let mut wrapper_size = 0isize;
    while wrapper_size < 5 {
        wrapper_size += x86_ins_size(ptr.offset(wrapper_size)) as isize;
    }
    let wrapper = heap.allocate(1 + 5 + wrapper_size as usize + 6);
    *wrapper.offset(0) = 0x60; // Pushad
    *wrapper.offset(1 + 5) = 0x61; // Popad
    x86_copy_instructions(ptr, wrapper.offset(1 + 5 + 1), wrapper_size);
    for i in 5..wrapper_size {
        *ptr.offset(i) = nop();
    }
    jump_hook(src, wrapper);
    *wrapper.offset(1) = 0xe8;
    let val: usize = mem::transmute::<_, usize>(tgt).overflowing_sub(mem::transmute::<_, usize>(wrapper) + 6).0;
    let hook_ptr: *mut usize = mem::transmute(wrapper.offset(2));
    *hook_ptr = val;
    // Jump back to original code
    jump_hook(wrapper.offset(wrapper_size + 7), ptr.offset(wrapper_size));
}

const OPT_HOOK_ENTRY: &'static [u8] = &[
    0x60, // pushad
    // Allocates 2 dwords on stack and pushes pointer to them as argument
    0x50, // push eax
    0x50, // push eax
    0x54, // push esp
    0x68, // push dword ...
];

const OPT_HOOK_END: &'static [u8] = &[
    0x59,                   // Pop ecx
    0x58,                   // Pop eax
    0x85, 0xc9,             // Test ecx, ecx
    0x61,                   // Popad
    0x74, 0x07,             // Je no_ret
    0x8b, 0x44, 0xe4, 0xdc, // Mov eax, [esp - 24]
];

/*
pushad
push eax
push eax
push esp                <- arg last = dword **ok, value
push dword hook_addr    <- arg last - 1
HOOK SPECIFIC:
    push [arg]
    push [arg]
    etc
    push [arg]              <- arg 1
call intermediate_hook
add esp, argc
pop ecx
pop eax
test ecx, ecx
popad
je no_ret
mov eax, [esp - 24]
ret stdcall_size
no_ret:
(rest)
jmp continue
*/

pub unsafe fn optional_hook<T, Hook>(src: T, target: *const u8, heap: &mut ExecutableHeap)
where Hook: HookableAsmWrap,
      T: ToPointer {
    let src = src.ptr();
    let src_copy_size = {
        let mut size = 0;
        while size < 5 {
            size += x86_ins_size(src.offset(size as isize));
        }
        size
    };

    let hook_stack_args_size = Hook::stack_args_count() as u8;
    let hook_argc = Hook::arg_count() as u8;
    let hook_pushargs = Hook::opt_push_args_asm();
    let intermediate_hook = Hook::opt_hook_intermediate();
    // + 4 for hook address, + 5 for intermediate call, + 3 for add esp, args,
    // + 3 for skip ret size, + 5 for continue jmp
    let wrapper_size = OPT_HOOK_ENTRY.len() + 4 + hook_pushargs.len() + 5 + 3 +
        OPT_HOOK_END.len() + 3 + src_copy_size + 5;

    let wrapper_code = heap.allocate(wrapper_size);
    ptr::copy_nonoverlapping(OPT_HOOK_ENTRY.as_ptr(), wrapper_code, OPT_HOOK_ENTRY.len());
    let mut pos = wrapper_code.offset(OPT_HOOK_ENTRY.len() as isize);
    ptr::copy_nonoverlapping(target, pos, 4);
    pos = pos.offset(4);
    ptr::copy_nonoverlapping(hook_pushargs.as_ptr(), pos, hook_pushargs.len());
    pos = pos.offset(hook_pushargs.len() as isize);
    call_ins(pos, intermediate_hook);
    pos = pos.offset(5);
    // Add esp, hook_argc
    *pos.offset(0) = 0x83;
    *pos.offset(1) = 0xc4;
    *pos.offset(2) = (hook_argc + 2) * 4;
    pos = pos.offset(3);
    ptr::copy_nonoverlapping(OPT_HOOK_END.as_ptr(), pos, OPT_HOOK_END.len());
    pos = pos.offset(OPT_HOOK_END.len() as isize);
    // Ret skipping the original code
    pos = if hook_stack_args_size == 0 {
        *pos.offset(0) = 0xc3;
        pos.offset(1)
    } else {
        *pos.offset(0) = 0xc2;
        *pos.offset(1) = hook_stack_args_size * 4;
        *pos.offset(2) = 0x0;
        pos.offset(3)
    };
    x86_copy_instructions(src, pos, src_copy_size as isize);
    pos = pos.offset(src_copy_size as isize);
    jump_hook(src, wrapper_code);
    jump_hook(pos, src.offset(src_copy_size as isize));
}

#[test]
fn test_x86_ins_size() {
    let inss = vec![vec![0x89, 0x45, 0xfc], vec![0xc6, 0x05, 0xfb, 0x01, 0xe8, 0xdc, 0xfa],
    vec![0xc6, 0x45, 0xfb, 0x01], vec![0x55], vec![0x60], vec![0x8b, 0xec], vec![0x83, 0xec, 0x0c]];
    unsafe {
        for ins in inss {
            assert_eq!(ins.len(), x86_ins_size(ins.as_ptr()));
        }
    }
}

#[test]
fn test_x86_copy_ins() {
    let ins1 = vec![0x89, 0x45, 0xfc, 0xff];
    let mut ins2 = vec![0xe8, 0x50, 0x60, 0x70, 0x80, 0xff, 0xff, 0xff, 0xff, 0xff];
    unsafe {
        let mut tgt = vec![0; 5];
        x86_copy_instructions(ins1.as_ptr(), tgt.as_mut_ptr(), 1);
        assert_eq!(tgt, vec![0x89, 0x45, 0xfc, 0x00, 0x00]);
        x86_copy_instructions(ins2.as_ptr(), ins2.as_mut_ptr().offset(5), 1);
        assert_eq!(ins2, vec![0xe8, 0x50, 0x60, 0x70, 0x80, 0xe8, 0x4b, 0x60, 0x70, 0x80]);
    }
}
