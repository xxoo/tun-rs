use std::{io, mem, ptr};

use crate::windows::{
    device::GUID_NETWORK_ADAPTER,
    ffi::{
        call_class_installer, destroy_device_info_list, encode_utf16, enum_device_info,
        open_dev_reg_key,
    },
};
use windows_sys::Win32::Foundation::{
    DEVPROPKEY, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_DATA, INVALID_HANDLE_VALUE,
};
use windows_sys::{
    core::GUID,
    Wdk::System::SystemServices::RtlGetVersion,
    Win32::{
        Devices::{
            DeviceAndDriverInstallation::{
                CM_Get_DevNode_Status, SetupDiGetClassDevsExW, SetupDiGetDevicePropertyW,
                SetupDiSetClassInstallParamsW, CM_DEVNODE_STATUS_FLAGS, CR_SUCCESS,
                DICS_FLAG_GLOBAL, DIF_REMOVE, DIREG_DRV, DI_REMOVEDEVICE_GLOBAL, DN_HAS_PROBLEM,
                HDEVINFO, SP_CLASSINSTALL_HEADER, SP_DEVINFO_DATA, SP_REMOVEDEVICE_PARAMS,
            },
            Properties::{DEVPROPID_FIRST_USABLE, DEVPROP_TYPE_STRING},
        },
        System::Registry::KEY_QUERY_VALUE,
        System::SystemInformation::OSVERSIONINFOW,
    },
};
use winreg::RegKey;

#[allow(non_upper_case_globals)]
pub const DEVPKEY_Wintun_Name: DEVPROPKEY = DEVPROPKEY {
    fmtid: GUID {
        data1: 0x3361c968,
        data2: 0x2f2e,
        data3: 0x4660,
        data4: [0xb4, 0x7e, 0x69, 0x9c, 0xdc, 0x4c, 0x32, 0xb9],
    },
    pid: DEVPROPID_FIRST_USABLE + 1,
};

#[allow(non_upper_case_globals)]
pub const DEVPKEY_Wintun_OwningProcess: DEVPROPKEY = DEVPROPKEY {
    fmtid: GUID {
        data1: 0x3361c968,
        data2: 0x2f2e,
        data3: 0x4660,
        data4: [0xb4, 0x7e, 0x69, 0x9c, 0xdc, 0x4c, 0x32, 0xb9],
    },
    pid: DEVPROPID_FIRST_USABLE + 3,
};

pub(super) fn adapter_name_matches(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

fn classify_exact_matches(matches: &[(bool, bool)]) -> io::Result<Option<usize>> {
    let mut exact = None;
    for (index, &(name_matches, guid_matches)) in matches.iter().enumerate() {
        match (name_matches, guid_matches) {
            (false, false) => {}
            (true, true) if exact.is_none() => exact = Some(index),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Wintun adapter identity is ambiguous",
                ));
            }
        }
    }
    Ok(exact)
}

fn parse_device_guid(value: &str) -> io::Result<u128> {
    let value = match (value.strip_prefix('{'), value.strip_suffix('}')) {
        (Some(value), Some(_)) => &value[..value.len() - 1],
        (None, None) => value,
        _ => "",
    };
    let bytes = value.as_bytes();
    if bytes.len() != 36
        || bytes[8] != b'-'
        || bytes[13] != b'-'
        || bytes[18] != b'-'
        || bytes[23] != b'-'
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Wintun NetCfgInstanceId is not a GUID",
        ));
    }
    let mut guid = 0_u128;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            continue;
        }
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Wintun NetCfgInstanceId is not a GUID",
                ));
            }
        };
        guid = (guid << 4) | u128::from(nibble);
    }
    if guid == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Wintun NetCfgInstanceId is zero",
        ));
    }
    Ok(guid)
}

fn get_device_guid(devinfo: HDEVINFO, devinfo_data: &SP_DEVINFO_DATA) -> io::Result<u128> {
    let key = open_dev_reg_key(
        devinfo,
        devinfo_data,
        DICS_FLAG_GLOBAL,
        0,
        DIREG_DRV,
        KEY_QUERY_VALUE,
    )?;
    let key = RegKey::predef(key as _);
    let value: String = key.get_value("NetCfgInstanceId")?;
    parse_device_guid(&value)
}

fn open_wintun_device_set() -> io::Result<Option<HDEVINFO>> {
    let windows_seven = is_windows_seven()?;
    let device_name = encode_utf16(if windows_seven {
        super::adapter_win7::WINTUN_ENUMERATOR
    } else {
        "SWD\\Wintun"
    });
    let dev_info = unsafe {
        SetupDiGetClassDevsExW(
            &GUID_NETWORK_ADAPTER,
            device_name.as_ptr(),
            ptr::null_mut(),
            0,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if dev_info != INVALID_HANDLE_VALUE as isize {
        return Ok(Some(dev_info));
    }
    let error = io::Error::last_os_error();
    if windows_seven && error.raw_os_error() == Some(ERROR_INVALID_DATA as i32) {
        Ok(None)
    } else {
        Err(error)
    }
}

fn scan_exact_adapter(
    dev_info: HDEVINFO,
    adapter_name: &str,
    adapter_guid: u128,
) -> io::Result<Option<SP_DEVINFO_DATA>> {
    let mut devices = Vec::new();
    let mut matches = Vec::new();
    let mut index = 0;
    loop {
        let Some(devinfo_data) = enum_device_info(dev_info, index) else {
            break;
        };
        let devinfo_data = devinfo_data?;
        let name = get_device_name(dev_info, &devinfo_data)?;
        let guid = get_device_guid(dev_info, &devinfo_data)?;
        matches.push((
            adapter_name_matches(adapter_name, &name),
            adapter_guid == guid,
        ));
        devices.push(devinfo_data);
        index += 1;
    }
    Ok(classify_exact_matches(&matches)?.map(|index| devices[index]))
}

fn finish_device_set<T>(dev_info: HDEVINFO, result: io::Result<T>) -> io::Result<T> {
    match (result, destroy_device_info_list(dev_info)) {
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
    }
}

fn validate_exact_identity(adapter_name: &str, adapter_guid: u128) -> io::Result<()> {
    if adapter_name.is_empty() || adapter_guid == 0 {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Wintun adapter identity",
        ))
    } else {
        Ok(())
    }
}

/// Returns whether SetupAPI contains exactly one adapter with both identity halves.
/// Any partial or duplicate match is an error.
pub fn wintun_adapter_exists_exact(adapter_name: &str, adapter_guid: u128) -> io::Result<bool> {
    validate_exact_identity(adapter_name, adapter_guid)?;
    let Some(dev_info) = open_wintun_device_set()? else {
        return Ok(false);
    };
    let result =
        scan_exact_adapter(dev_info, adapter_name, adapter_guid).map(|item| item.is_some());
    finish_device_set(dev_info, result)
}

fn remove_adapter(dev_info: HDEVINFO, adapter: &SP_DEVINFO_DATA) -> io::Result<()> {
    let params = SP_REMOVEDEVICE_PARAMS {
        ClassInstallHeader: SP_CLASSINSTALL_HEADER {
            cbSize: mem::size_of::<SP_CLASSINSTALL_HEADER>() as u32,
            InstallFunction: DIF_REMOVE,
        },
        Scope: DI_REMOVEDEVICE_GLOBAL,
        HwProfile: 0,
    };
    let ok = unsafe {
        SetupDiSetClassInstallParamsW(
            dev_info,
            adapter,
            &params as *const SP_REMOVEDEVICE_PARAMS as *const SP_CLASSINSTALL_HEADER,
            mem::size_of::<SP_REMOVEDEVICE_PARAMS>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    call_class_installer(dev_info, adapter, DIF_REMOVE)
}

/// Idempotently removes only the unique adapter matching both name and GUID.
pub fn remove_wintun_adapter_exact(adapter_name: &str, adapter_guid: u128) -> io::Result<()> {
    validate_exact_identity(adapter_name, adapter_guid)?;
    let Some(dev_info) = open_wintun_device_set()? else {
        return Ok(());
    };
    let result = scan_exact_adapter(dev_info, adapter_name, adapter_guid).and_then(|adapter| {
        let Some(adapter) = adapter else {
            return Ok(());
        };
        let rescanned = scan_exact_adapter(dev_info, adapter_name, adapter_guid)?;
        let Some(rescanned) = rescanned else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Wintun adapter identity changed before removal",
            ));
        };
        if rescanned.DevInst != adapter.DevInst {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Wintun adapter identity changed before removal",
            ));
        }
        remove_adapter(dev_info, &rescanned)
    });
    finish_device_set(dev_info, result)?;
    if wintun_adapter_exists_exact(adapter_name, adapter_guid)? {
        Err(io::Error::other("Wintun adapter remains after removal"))
    } else {
        Ok(())
    }
}

pub fn check_adapter_if_orphaned_devices(
    adapter_name: &str,
    include_live: bool,
) -> io::Result<bool> {
    if is_windows_seven()? {
        return super::adapter_win7::check_adapter_if_orphaned_devices_win7(
            adapter_name,
            include_live,
        );
    }

    let device_name = encode_utf16("SWD\\Wintun");
    let dev_info = unsafe {
        SetupDiGetClassDevsExW(
            &GUID_NETWORK_ADAPTER,
            device_name.as_ptr(),
            ptr::null_mut(),
            0,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if dev_info == INVALID_HANDLE_VALUE as isize {
        return Err(io::Error::last_os_error());
    }

    let mut index = 0;
    let result = loop {
        match enum_device_info(dev_info, index) {
            Some(Ok(devinfo_data)) => {
                let status = match dev_node_status(&devinfo_data) {
                    Ok(status) => status,
                    Err(error) => break Err(error),
                };
                if !include_live && status & DN_HAS_PROBLEM == 0 {
                    index += 1;
                    continue;
                }

                let name = match get_device_name(dev_info, &devinfo_data) {
                    Ok(name) => name,
                    Err(error) => break Err(error),
                };

                if adapter_name_matches(adapter_name, &name) {
                    break Ok(true);
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

pub fn get_device_name(devinfo: HDEVINFO, devinfo_data: &SP_DEVINFO_DATA) -> io::Result<String> {
    let mut prop_type: u32 = 0;
    let mut required_size: u32 = 0;
    let ok = unsafe {
        SetupDiGetDevicePropertyW(
            devinfo,
            devinfo_data,
            &DEVPKEY_Wintun_Name,
            &mut prop_type,
            ptr::null_mut(),
            0,
            &mut required_size,
            0,
        )
    };
    if ok == 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
            return Err(err);
        }
    }
    if required_size < 2 || required_size > 512 || !required_size.is_multiple_of(2) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Wintun adapter name property",
        ));
    }

    let buffer_size = required_size;
    let mut buf: Vec<u16> = vec![0; (buffer_size / 2) as usize];

    let ok = unsafe {
        SetupDiGetDevicePropertyW(
            devinfo,
            devinfo_data,
            &DEVPKEY_Wintun_Name,
            &mut prop_type,
            buf.as_mut_ptr() as *mut u8,
            buffer_size,
            &mut required_size,
            0,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if prop_type != DEVPROP_TYPE_STRING
        || required_size < 2
        || required_size > buffer_size
        || required_size > 512
        || !required_size.is_multiple_of(2)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Wintun adapter name property",
        ));
    }
    buf.truncate((required_size / 2) as usize);
    let Some((&0, name)) = buf.split_last() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unterminated Wintun adapter name",
        ));
    };
    if name.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Wintun adapter name",
        ));
    }
    String::from_utf16(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid UTF-16 Wintun adapter name",
        )
    })
}

fn is_windows_seven() -> io::Result<bool> {
    let mut info = OSVERSIONINFOW {
        dwOSVersionInfoSize: mem::size_of::<OSVERSIONINFOW>() as u32,
        dwMajorVersion: 0,
        dwMinorVersion: 0,
        dwBuildNumber: 0,
        dwPlatformId: 0,
        szCSDVersion: [0; 128],
    };
    if unsafe { RtlGetVersion(ptr::addr_of_mut!(info)) } != 0 {
        return Err(io::Error::other("failed to query the Windows version"));
    }
    Ok(info.dwMajorVersion == 6 && info.dwMinorVersion == 1)
}

#[cfg(test)]
mod tests {
    use super::{adapter_name_matches, classify_exact_matches, parse_device_guid};

    #[test]
    fn wintun_names_are_case_insensitive() {
        assert!(adapter_name_matches("Linq0", "linq0"));
    }

    #[test]
    fn exact_identity_requires_one_dual_match() {
        assert_eq!(classify_exact_matches(&[(false, false)]).unwrap(), None);
        assert_eq!(
            classify_exact_matches(&[(false, false), (true, true)]).unwrap(),
            Some(1)
        );
        assert!(classify_exact_matches(&[(true, false)]).is_err());
        assert!(classify_exact_matches(&[(false, true)]).is_err());
        assert!(classify_exact_matches(&[(true, true), (true, true)]).is_err());
    }

    #[test]
    fn device_guid_parser_is_canonical_and_nonzero() {
        let expected = 0x0123456789abcdef8123456789abcdef;
        assert_eq!(
            parse_device_guid("{01234567-89AB-CDEF-8123-456789ABCDEF}").unwrap(),
            expected
        );
        assert_eq!(
            parse_device_guid("01234567-89ab-cdef-8123-456789abcdef").unwrap(),
            expected
        );
        assert!(parse_device_guid("00000000-0000-0000-0000-000000000000").is_err());
        assert!(parse_device_guid("{01234567-89ab-cdef-8123-456789abcdef").is_err());
        assert!(parse_device_guid("not-a-guid").is_err());
    }
}

fn dev_node_status(devinfo_data: &SP_DEVINFO_DATA) -> io::Result<CM_DEVNODE_STATUS_FLAGS> {
    let mut pulstatus = 0;
    let mut pulproblemnumber = 0;

    let cr = unsafe {
        CM_Get_DevNode_Status(
            &mut pulstatus,
            &mut pulproblemnumber,
            devinfo_data.DevInst,
            0,
        )
    };

    if cr != CR_SUCCESS {
        return Err(io::Error::last_os_error());
    }

    Ok(pulstatus)
}
