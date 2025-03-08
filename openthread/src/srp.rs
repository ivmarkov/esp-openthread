use core::cell::RefCell;
use core::ffi::CStr;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::net::{Ipv6Addr, SocketAddrV6};

use log::{debug, info};

use crate::sys::{
    otDnsTxtEntry, otError_OT_ERROR_NO_BUFS, otIp6Address, otSrpClientAddService,
    otSrpClientClearHostAndServices, otSrpClientClearService, otSrpClientEnableAutoHostAddress,
    otSrpClientEnableAutoStartMode, otSrpClientGetHostInfo, otSrpClientGetKeyLeaseInterval,
    otSrpClientGetLeaseInterval, otSrpClientGetServerAddress, otSrpClientGetServices,
    otSrpClientGetTtl, otSrpClientHostInfo, otSrpClientIsAutoStartModeEnabled,
    otSrpClientIsRunning, otSrpClientItemState,
    otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_ADDING,
    otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_REFRESHING,
    otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_REGISTERED,
    otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_REMOVED,
    otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_REMOVING,
    otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_TO_ADD,
    otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_TO_REFRESH,
    otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_TO_REMOVE, otSrpClientRemoveHostAndServices,
    otSrpClientRemoveService, otSrpClientService, otSrpClientSetHostAddresses,
    otSrpClientSetHostName, otSrpClientSetKeyLeaseInterval, otSrpClientSetLeaseInterval,
    otSrpClientSetTtl, otSrpClientStart, otSrpClientStop,
};
use crate::{ot, to_ot_addr, to_sock_addr, OpenThread, OtContext, OtError};

pub struct SrpServiceId(usize, PhantomData<*const ()>);

unsafe impl Send for SrpServiceId {}

pub struct OtSrpResources<const SRP_SVCS: usize, const SRP_BUF_SZ: usize> {
    services: MaybeUninit<[otSrpClientService; SRP_SVCS]>,
    taken: MaybeUninit<[bool; SRP_SVCS]>,
    conf: MaybeUninit<[u8; SRP_BUF_SZ]>,
    buffers: MaybeUninit<[[u8; SRP_BUF_SZ]; SRP_SVCS]>,
    state: MaybeUninit<RefCell<OtSrpState<'static>>>,
}

impl<const SRP_SVCS: usize, const SRP_BUF_SZ: usize> OtSrpResources<SRP_SVCS, SRP_BUF_SZ> {
    #[allow(clippy::declare_interior_mutable_const)]
    const INIT_SERVICE: otSrpClientService = otSrpClientService {
        mName: core::ptr::null(),
        mInstanceName: core::ptr::null(),
        mSubTypeLabels: core::ptr::null(),
        mTxtEntries: core::ptr::null(),
        mPort: 0,
        mPriority: 0,
        mWeight: 0,
        mNumTxtEntries: 0,
        mState: 0,
        mData: 0,
        mNext: core::ptr::null_mut(),
        mLease: 0,
        mKeyLease: 0,
    };
    #[allow(clippy::declare_interior_mutable_const)]
    const INIT_BUFFERS: [u8; SRP_BUF_SZ] = [0; SRP_BUF_SZ];

    pub const fn new() -> Self {
        Self {
            services: MaybeUninit::uninit(),
            taken: MaybeUninit::uninit(),
            conf: MaybeUninit::uninit(),
            buffers: MaybeUninit::uninit(),
            state: MaybeUninit::uninit(),
        }
    }

    pub(crate) fn init(&mut self) -> &mut RefCell<OtSrpState<'static>> {
        self.services.write([Self::INIT_SERVICE; SRP_SVCS]);
        self.taken.write([false; SRP_SVCS]);
        self.conf.write(Self::INIT_BUFFERS);
        self.buffers.write([Self::INIT_BUFFERS; SRP_SVCS]);

        let buffers: &mut [[u8; SRP_BUF_SZ]; SRP_SVCS] = unsafe { self.buffers.assume_init_mut() };

        #[allow(clippy::missing_transmute_annotations)]
        self.state.write(RefCell::new(unsafe {
            core::mem::transmute(OtSrpState {
                services: self.services.assume_init_mut(),
                taken: self.taken.assume_init_mut(),
                conf: self.conf.assume_init_mut(),
                buffers: core::slice::from_raw_parts_mut(
                    buffers.as_mut_ptr() as *mut _,
                    SRP_BUF_SZ * SRP_SVCS,
                ),
                buf_len: SRP_BUF_SZ,
            })
        }));

        info!("OpenThread SRP resources initialized");

        unsafe { self.state.assume_init_mut() }
    }
}

impl<const SRP_SVCS: usize, const SRP_BUF_SZ: usize> Default
    for OtSrpResources<SRP_SVCS, SRP_BUF_SZ>
{
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) struct OtSrpState<'a> {
    services: &'a mut [otSrpClientService],
    taken: &'a mut [bool],
    conf: &'a mut [u8],
    buffers: &'a mut [u8],
    buf_len: usize,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum SrpState {
    ToAdd,
    Adding,
    ToRefresh,
    Refreshing,
    ToRemove,
    Removing,
    Removed,
    Registered,
    Other(u32),
}

#[allow(non_upper_case_globals)]
impl From<otSrpClientItemState> for SrpState {
    fn from(value: otSrpClientItemState) -> Self {
        match value {
            otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_TO_ADD => Self::ToAdd,
            otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_ADDING => Self::Adding,
            otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_TO_REFRESH => Self::ToRefresh,
            otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_REFRESHING => Self::Refreshing,
            otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_TO_REMOVE => Self::ToRemove,
            otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_REMOVING => Self::Removing,
            otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_REMOVED => Self::Removed,
            otSrpClientItemState_OT_SRP_CLIENT_ITEM_STATE_REGISTERED => Self::Registered,
            other => Self::Other(other),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct SrpConf<'a> {
    pub host_name: &'a str,
    pub host_addrs: &'a [Ipv6Addr],
    pub ttl: u32,
    pub default_lease_secs: u32,
    pub default_key_lease_secs: u32,
}

impl<'a> SrpConf<'a> {
    pub const fn new() -> Self {
        Self {
            host_name: "ot-device",
            host_addrs: &[],
            ttl: 60,
            default_lease_secs: 0,
            default_key_lease_secs: 0,
        }
    }

    fn store(&self, ot_srp: &mut otSrpClientHostInfo, buf: &mut [u8]) -> Result<(), OtError> {
        let mut offset = 0;

        let (addrs, buf) = SrpService::align_min::<otIp6Address>(buf, self.host_addrs.len())?;

        ot_srp.mName = SrpService::store_str(self.host_name, buf, &mut offset)?.as_ptr();

        for ip in self.host_addrs {
            let addr = &mut addrs[offset];
            addr.mFields.m8 = ip.octets();
        }

        ot_srp.mAddresses = addrs.as_ptr();
        ot_srp.mNumAddresses = addrs.len() as _;
        ot_srp.mAutoAddress = addrs.is_empty();

        Ok(())
    }
}

impl Default for SrpConf<'_> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct SrpService<'a> {
    pub name: &'a str,
    pub instance_name: &'a str,
    pub subtype_labels: &'a [&'a str],
    pub txt_entries: &'a [(&'a str, &'a [u8])],
    pub port: u16,
    pub priority: u16,
    pub weight: u16,
    pub lease_secs: u32,
    pub key_lease_secs: u32,
}

impl<'a> SrpService<'a> {
    fn store(&self, ot_srp: &mut otSrpClientService, buf: &mut [u8]) -> Result<(), OtError> {
        let (txt_entries, buf) = Self::align_min::<otDnsTxtEntry>(buf, self.txt_entries.len())?;
        let (subtype_labels, strs) =
            Self::align_min::<*const char>(buf, self.subtype_labels.len() + 1)?;

        let mut offset = 0;

        ot_srp.mName = Self::store_str(self.name, strs, &mut offset)?.as_ptr();
        ot_srp.mInstanceName = Self::store_str(self.instance_name, strs, &mut offset)?.as_ptr();

        let mut index = 0;

        for subtype_label in self.subtype_labels {
            let subtype_label = Self::store_str(subtype_label, strs, &mut offset)?;
            subtype_labels[index] = subtype_label.as_ptr() as *const _;

            index += 1;
        }

        subtype_labels[index] = core::ptr::null();

        for (key, value) in self.txt_entries {
            let txt_entry = &mut txt_entries[index];

            txt_entry.mKey = Self::store_str(key, strs, &mut offset)?.as_ptr();
            txt_entry.mValue = Self::store_data(value, strs, &mut offset)?.as_ptr();
            txt_entry.mValueLength = value.len() as _;

            index += 1;
        }

        ot_srp.mSubTypeLabels = subtype_labels.as_ptr() as *const _;
        ot_srp.mTxtEntries = txt_entries.as_ptr();
        ot_srp.mNumTxtEntries = self.txt_entries.len() as _;
        ot_srp.mPort = self.port;
        ot_srp.mPriority = self.priority;
        ot_srp.mWeight = self.weight;
        ot_srp.mLease = self.lease_secs;
        ot_srp.mKeyLease = self.key_lease_secs;

        Ok(())
    }

    fn align_min<T>(buf: &mut [u8], count: usize) -> Result<(&mut [T], &mut [u8]), OtError> {
        if count == 0 {
            return Ok((&mut [], buf));
        }

        let size = Self::est_size::<T>(count);

        if size >= buf.len() {
            Err(OtError::new(otError_OT_ERROR_NO_BUFS))?;
        }

        let (t_buf, buf) = buf.split_at_mut(size);

        let (_, t_buf, _) = unsafe { t_buf.align_to_mut::<T>() };

        assert!(count == t_buf.len() || count == t_buf.len() + 1);

        Ok((t_buf, buf))
    }

    fn est_size<T>(count: usize) -> usize {
        let align = core::mem::align_of::<T>();
        let mut size = core::mem::size_of::<T>();
        if size % align != 0 {
            size += align - (size % align);
        }

        count * size + align
    }

    fn store_str<'t>(
        str: &str,
        buf: &'t mut [u8],
        offset: &mut usize,
    ) -> Result<&'t CStr, OtError> {
        let buf = &mut buf[*offset..];

        if str.len() + 1 >= buf.len() {
            Err(OtError::new(otError_OT_ERROR_NO_BUFS))?;
        }

        buf[..str.len()].copy_from_slice(str.as_bytes());
        buf[str.len()] = 0;

        *offset += str.len() + 1;

        Ok(unsafe { CStr::from_bytes_with_nul_unchecked(&buf[..str.len() + 1]) })
    }

    fn store_data<'t>(
        data: &[u8],
        buf: &'t mut [u8],
        offset: &mut usize,
    ) -> Result<&'t [u8], OtError> {
        let buf = &mut buf[*offset..];

        if data.len() >= buf.len() {
            Err(OtError::new(otError_OT_ERROR_NO_BUFS))?;
        }

        buf[..data.len()].copy_from_slice(data);

        *offset += data.len();

        Ok(&buf[..data.len()])
    }
}

impl From<&otSrpClientService> for SrpService<'_> {
    fn from(ot_srp: &otSrpClientService) -> Self {
        Self {
            name: if !ot_srp.mName.is_null() {
                unsafe { CStr::from_ptr(ot_srp.mName).to_str().unwrap() }
            } else {
                ""
            },
            instance_name: if !ot_srp.mInstanceName.is_null() {
                unsafe { CStr::from_ptr(ot_srp.mInstanceName).to_str().unwrap() }
            } else {
                ""
            },
            subtype_labels: &[], // TODO subtype_labels.as_slice(),
            txt_entries: &[],    // TODO txt_entries.as_slice(),
            port: ot_srp.mPort,
            priority: ot_srp.mPriority,
            weight: ot_srp.mWeight,
            lease_secs: ot_srp.mLease,
            key_lease_secs: ot_srp.mKeyLease,
        }
    }
}

impl OpenThread<'_> {
    pub fn srp_conf<F, R>(&self, f: F) -> Result<R, OtError>
    where
        F: FnOnce(&SrpConf, SrpState) -> Result<R, OtError>,
    {
        let mut ot = self.activate();
        let instance = ot.state().ot.instance;
        let _ = ot.state().srp()?;

        let info = unsafe { otSrpClientGetHostInfo(instance).as_ref().unwrap() };

        let conf = SrpConf {
            host_name: if !info.mName.is_null() {
                unsafe { CStr::from_ptr(info.mName).to_str().unwrap() }
            } else {
                ""
            },
            host_addrs: if info.mNumAddresses > 0 && !info.mAddresses.is_null() {
                unsafe {
                    core::slice::from_raw_parts(
                        info.mAddresses as *const _,
                        info.mNumAddresses as _,
                    )
                }
            } else {
                &[]
            },
            ttl: unsafe { otSrpClientGetTtl(instance) },
            default_lease_secs: unsafe { otSrpClientGetLeaseInterval(instance) },
            default_key_lease_secs: unsafe { otSrpClientGetKeyLeaseInterval(instance) },
        };

        f(&conf, info.mState.into())
    }

    pub fn srp_set_conf(&self, conf: &SrpConf) -> Result<(), OtError> {
        let mut ot = self.activate();
        let instance = ot.state().ot.instance;
        let srp = ot.state().srp()?;

        ot!(unsafe { otSrpClientSetHostName(instance, c"".as_ptr()) })?;
        ot!(unsafe { otSrpClientEnableAutoHostAddress(instance) })?;

        let mut srp_conf = otSrpClientHostInfo {
            mName: core::ptr::null(),
            mAddresses: core::ptr::null(),
            mNumAddresses: 0,
            mAutoAddress: true,
            mState: 0,
        };

        conf.store(&mut srp_conf, srp.conf)?;

        ot!(unsafe { otSrpClientSetHostName(instance, srp_conf.mName) })?;

        if !conf.host_addrs.is_empty() {
            ot!(unsafe {
                otSrpClientSetHostAddresses(instance, srp_conf.mAddresses, srp_conf.mNumAddresses)
            })?;
        }

        unsafe {
            otSrpClientSetLeaseInterval(instance, conf.default_lease_secs);
        }
        unsafe {
            otSrpClientSetKeyLeaseInterval(instance, conf.default_key_lease_secs);
        }
        unsafe {
            otSrpClientSetTtl(instance, conf.ttl);
        }

        Ok(())
    }

    pub fn srp_running(&self) -> Result<bool, OtError> {
        let mut ot = self.activate();
        let instance = ot.state().ot.instance;
        let _ = ot.state().srp()?;

        Ok(unsafe { otSrpClientIsRunning(instance) })
    }

    pub fn srp_autostart_enabled(&self) -> Result<bool, OtError> {
        let mut ot = self.activate();
        let instance = ot.state().ot.instance;
        let _ = ot.state().srp()?;

        Ok(unsafe { otSrpClientIsAutoStartModeEnabled(instance) })
    }

    pub fn srp_autostart(&self) -> Result<(), OtError> {
        let mut ot = self.activate();
        let instance = ot.state().ot.instance;
        let _ = ot.state().srp()?;

        unsafe {
            otSrpClientEnableAutoStartMode(
                instance,
                Some(OtContext::plat_c_srp_auto_start_callback),
                instance as _,
            );
        }

        Ok(())
    }

    pub fn srp_start(&self, server_addr: SocketAddrV6) -> Result<(), OtError> {
        let mut ot = self.activate();
        let instance = ot.state().ot.instance;
        let _ = ot.state().srp()?;

        ot!(unsafe { otSrpClientStart(instance, &to_ot_addr(&server_addr)) })
    }

    pub fn srp_stop(&self) -> Result<(), OtError> {
        let mut ot = self.activate();
        let instance = ot.state().ot.instance;
        let _ = ot.state().srp()?;

        unsafe {
            otSrpClientStop(instance);
        }

        Ok(())
    }

    pub fn srp_server_addr(&self) -> Result<Option<SocketAddrV6>, OtError> {
        let mut ot = self.activate();
        let instance = ot.state().ot.instance;
        let _ = ot.state().srp()?;

        let addr = unsafe { otSrpClientGetServerAddress(instance).as_ref().unwrap() };
        let addr = to_sock_addr(&addr.mAddress, addr.mPort, 0);

        // OT documentation notes that if the SRP client is not running
        // this will return the unspecified addr (0.0.0.0.0.0.0.0)
        Ok((!addr.ip().is_unspecified()).then_some(addr))
    }

    pub fn srp_add_service(&self, service: &SrpService) -> Result<SrpServiceId, OtError> {
        let mut ot = self.activate();
        let instance = ot.state().ot.instance;
        let srp = ot.state().srp()?;

        let slot = srp
            .taken
            .iter()
            .position(|&taken| !taken)
            .ok_or(OtError::new(otError_OT_ERROR_NO_BUFS))?;

        let service_data = &mut srp.services[slot];
        let buf = &mut srp.buffers[srp.buf_len * slot..srp.buf_len * (slot + 1)];

        service.store(service_data, buf)?;

        ot!(unsafe { otSrpClientAddService(instance, service_data) })?;

        debug!("Service added");

        srp.taken[slot] = true;

        Ok(SrpServiceId(slot, PhantomData))
    }

    pub fn srp_remove_service(&self, service: SrpServiceId, clear: bool) -> Result<(), OtError> {
        let mut ot = self.activate();
        let instance = ot.state().ot.instance;
        let srp = ot.state().srp()?;

        assert!(service.0 < srp.taken.len());
        assert!(srp.taken[service.0]);

        if clear {
            ot!(unsafe { otSrpClientClearService(instance, &mut srp.services[service.0]) })?;
        } else {
            // TODO
            ot!(unsafe { otSrpClientRemoveService(instance, &mut srp.services[service.0]) })?;
        }

        debug!("Service removed");

        srp.taken[service.0] = false;

        Ok(())
    }

    pub fn srp_remove_all(&self, clear: bool) -> Result<(), OtError> {
        let mut ot = self.activate();
        let instance = ot.state().ot.instance;
        let srp = ot.state().srp()?;

        if clear {
            unsafe {
                otSrpClientClearHostAndServices(instance);
            }
        } else {
            // TODO
            ot!(unsafe { otSrpClientRemoveHostAndServices(instance, true, false) })?;
        }

        debug!("Hostname and all services removed");

        srp.taken.fill(false);

        Ok(())
    }

    pub fn srp_services<F>(&self, mut f: F) -> Result<(), OtError>
    where
        F: FnMut(Option<(&SrpService, SrpState, SrpServiceId)>),
    {
        let mut ot = self.activate();
        let instance = ot.state().ot.instance;
        let srp = ot.state().srp()?;

        let service: *const otSrpClientService = unsafe { otSrpClientGetServices(instance) };

        while !service.is_null() {
            let service = unsafe { &*service };

            let slot = srp
                .services
                .iter()
                .position(|s| core::ptr::eq(s, service))
                .unwrap();

            f(Some((
                &service.into(),
                service.mState.into(),
                SrpServiceId(slot, PhantomData),
            )));
        }

        f(None);

        Ok(())
    }
}
