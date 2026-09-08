use std::{io, mem, ptr};
use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    SetupDiGetClassDevsExW, SetupDiGetDevicePropertyW,
};
use windows_sys::Win32::Devices::Properties::DEVPROP_TYPE_BINARY;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_INVALID_DATA, FILETIME, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::windows::{
    device::GUID_NETWORK_ADAPTER,
    ffi::{destroy_device_info_list, encode_utf16, enum_device_info},
    tun::adapter::{
        adapter_matches_scan, adapter_scan_flags, get_device_name, DEVPKEY_Wintun_OwningProcess,
    },
};

pub(super) const WINTUN_ENUMERATOR: &str = "ROOT\\Wintun";

#[repr(C)]
pub struct OwningProcess {
    process_id: u32,
    creation_time: FILETIME,
}

pub fn check_adapter_if_orphaned_devices_win7(
    adapter_name: &str,
    include_live: bool,
) -> io::Result<bool> {
    let device_name = encode_utf16(WINTUN_ENUMERATOR);
    let dev_info = unsafe {
        SetupDiGetClassDevsExW(
            &GUID_NETWORK_ADAPTER,
            device_name.as_ptr(),
            ptr::null_mut(),
            adapter_scan_flags(include_live),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if dev_info == INVALID_HANDLE_VALUE as isize {
        if unsafe { GetLastError() } != ERROR_INVALID_DATA {
            return Err(io::Error::last_os_error());
        }
        return Ok(false);
    }

    let mut index = 0;
    let result = loop {
        match enum_device_info(dev_info, index) {
            Some(Ok(devinfo_data)) => {
                match adapter_matches_scan(
                    adapter_name,
                    include_live,
                    || unsafe {
                        let mut ptype = mem::zeroed();
                        let mut buf: [u8; mem::size_of::<OwningProcess>()] = mem::zeroed();

                        let ok = SetupDiGetDevicePropertyW(
                            dev_info,
                            &devinfo_data,
                            &DEVPKEY_Wintun_OwningProcess,
                            &mut ptype,
                            &mut buf as _,
                            buf.len() as _,
                            ptr::null_mut(),
                            0,
                        );

                        if ok != 0 && ptype == DEVPROP_TYPE_BINARY {
                            // SAFETY: buf has byte alignment; OwningProcess requires alignment 4.
                            let owning_process =
                                std::ptr::read_unaligned(buf.as_ptr() as *const OwningProcess);
                            Ok(process_is_stale(&owning_process))
                        } else {
                            Ok(true)
                        }
                    },
                    || get_device_name(dev_info, &devinfo_data),
                ) {
                    Ok(true) => break Ok(true),
                    Ok(false) => {}
                    Err(error) => break Err(error),
                }
            }
            Some(Err(error)) => break Err(error),
            None => break Ok(false),
        }

        index += 1;
    };
    match (result, destroy_device_info_list(dev_info)) {
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
    }
}

fn process_is_stale(owning_process: &OwningProcess) -> bool {
    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            owning_process.process_id,
        )
    };
    if process.is_null() {
        return true;
    }
    let mut creation_time: FILETIME = unsafe { std::mem::zeroed() };
    let mut unused: FILETIME = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        GetProcessTimes(
            process,
            &mut creation_time,
            &mut unused,
            &mut unused,
            &mut unused,
        )
    };
    _ = unsafe { CloseHandle(process) };
    if ret == 0 {
        return false;
    }
    creation_time.dwHighDateTime != owning_process.creation_time.dwHighDateTime
        || creation_time.dwLowDateTime != owning_process.creation_time.dwLowDateTime
}
