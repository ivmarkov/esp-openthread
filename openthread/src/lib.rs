//! A safe API for OpenThread (`openthread-sys`)

#![no_std]
#![allow(async_fn_in_trait)]

use core::cell::{RefCell, RefMut};
use core::ffi::c_void;
use core::future::poll_fn;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::net::Ipv6Addr;
use core::pin::pin;
use core::ptr::addr_of_mut;

use embassy_futures::select::{Either, Either3};

use embassy_time::Instant;

use log::{debug, info, trace, warn};

use platform::OT_ACTIVE_STATE;

use rand_core::RngCore;

pub use dataset::*;
pub use openthread_sys as sys;
pub use radio::*;
use signal::Signal;
pub use udp::*;

mod dataset;
#[cfg(feature = "embassy-net-driver-channel")]
pub mod enet;
#[cfg(any(feature = "esp32h2", feature = "esp32c6"))]
pub mod esp;
mod platform;
mod radio;
mod signal;
#[cfg(feature = "srp-client")]
mod srp_client;
mod udp;

use sys::{
    otChangedFlags, otDatasetSetActive, otError, otError_OT_ERROR_DROP, otError_OT_ERROR_FAILED,
    otError_OT_ERROR_NONE, otError_OT_ERROR_NO_BUFS, otInstance, otInstanceInitSingle,
    otIp6GetUnicastAddresses, otIp6NewMessageFromBuffer, otIp6Send, otIp6SetEnabled,
    otIp6SetReceiveCallback, otMessage, otMessageFree,
    otMessagePriority_OT_MESSAGE_PRIORITY_NORMAL, otMessageRead, otMessageSettings,
    otOperationalDataset, otPlatAlarmMilliFired, otPlatRadioEnergyScanDone, otPlatRadioReceiveDone,
    otPlatRadioTxDone, otPlatRadioTxStarted, otRadioFrame, otSetStateChangedCallback,
    otTaskletsProcess, otThreadSetEnabled, OT_RADIO_FRAME_MAX_SIZE,
};

/// A newtype wrapper over the native OpenThread error type (`otError`).
///
/// This type is used to represent errors that can occur when interacting with the OpenThread library.
///
/// Brings extra ergonomics to the error handling, by providing a more Rust-like API.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct OtError(otError);

impl OtError {
    /// Create a new `OtError` from a raw `otError` value.
    pub const fn new(value: otError) -> Self {
        Self(value)
    }

    /// Convert to the raw `otError` value.
    pub fn into_inner(self) -> otError {
        self.0
    }
}

impl From<u32> for OtError {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

/// A macro for converting an `otError` value to a `Result<(), OtError>` value.
macro_rules! ot {
    ($code: expr) => {{
        match $code {
            $crate::sys::otError_OT_ERROR_NONE => Ok(()),
            err => Err($crate::OtError::new(err)),
        }
    }};
}

pub(crate) use ot;

/// An extension trait for converting a `Result<(), OtError>` to a raw `otError` OpenThread error code.
pub trait IntoOtCode {
    /// Convert the `Result<(), OtError>` to a raw `otError` OpenThread error code.
    fn into_ot_code(self) -> otError;
}

impl IntoOtCode for Result<(), OtError> {
    fn into_ot_code(self) -> otError {
        match self {
            Ok(_) => otError_OT_ERROR_NONE,
            Err(e) => e.into_inner(),
        }
    }
}

/// A type representing one OpenThread instance.
#[derive(Copy, Clone)]
pub struct OpenThread<'a> {
    state: &'a RefCell<OtState<'static>>,
    #[cfg(feature = "udp")]
    udp_state: Option<&'a RefCell<OtUdpState<'static>>>,
}

impl<'a> OpenThread<'a> {
    /// Create a new OpenThread instance.
    ///
    /// Arguments:
    /// - `rng`: A mutable reference to a random number generator that will be used by OpenThread.
    /// - `resources`: A mutable reference to the OpenThread resources.
    ///
    /// Returns:
    /// - In case there were no errors related to initializing the OpenThread library, the OpenThread instance.
    pub fn new(rng: &'a mut dyn RngCore, resources: &'a mut OtResources) -> Result<Self, OtError> {
        // Needed so that we convert from the the actual `'a` lifetime of `rng` to the fake `'static` lifetime in `OtResources`
        #[allow(clippy::missing_transmute_annotations)]
        let state = resources.init(unsafe { core::mem::transmute(rng) });

        let mut this = Self {
            state,
            udp_state: None,
        };

        this.init()?;

        Ok(this)
    }

    /// Create a new OpenThread instance with support for native OpenThread UDP sockets.
    ///
    /// Arguments:
    /// - `rng`: A mutable reference to a random number generator that will be used by OpenThread.
    /// - `resources`: A mutable reference to the OpenThread resources.
    /// - `udp_resources`: A mutable reference to the OpenThread UDP resources.
    ///
    /// Returns:
    /// - In case there were no errors related to initializing the OpenThread library, the OpenThread instance.
    pub fn new_with_udp<const UDP_SOCKETS: usize, const UDP_RX_SZ: usize>(
        rng: &'a mut dyn RngCore,
        resources: &'a mut OtResources,
        udp_resources: &'a mut OtUdpResources<UDP_SOCKETS, UDP_RX_SZ>,
    ) -> Result<Self, OtError> {
        // Needed so that we convert from the the actual `'a` lifetime of `rng` to the fake `'static` lifetime in `OtResources`
        #[allow(clippy::missing_transmute_annotations)]
        let state = resources.init(unsafe { core::mem::transmute(rng) });
        let udp_state = udp_resources.init();

        let mut this = Self {
            state,
            udp_state: Some(udp_state),
        };

        this.init()?;

        Ok(this)
    }

    /// Set a new active dataset in the OpenThread stack.
    ///
    /// Arguments:
    /// - `dataset`: A reference to the new dataset to be set.
    pub fn set_dataset(&self, dataset: &OperationalDataset<'_>) -> Result<(), OtError> {
        let mut ot = self.activate();
        let state = ot.state();

        dataset.store_raw(&mut state.ot.dataset_resources.dataset);

        ot!(unsafe { otDatasetSetActive(state.ot.instance, &state.ot.dataset_resources.dataset) })
    }

    /// Brings the OpenThread IPv6 interface up or down.
    pub fn enable_ipv6(&self, enable: bool) -> Result<(), OtError> {
        let mut ot = self.activate();
        let state = ot.state();

        ot!(unsafe { otIp6SetEnabled(state.ot.instance, enable) })
    }

    /// This function starts/stops the Thread protocol operation.
    ///
    /// TODO: The interface must be up when calling this function.
    pub fn enable_thread(&self, enable: bool) -> Result<(), OtError> {
        let mut ot = self.activate();
        let state = ot.state();

        ot!(unsafe { otThreadSetEnabled(state.ot.instance, enable) })
    }

    /// Gets the list of IPv6 addresses currently assigned to the Thread interface
    ///
    /// Arguments:
    /// - `buf`: A mutable reference to a buffer where the IPv6 addresses will be stored.
    ///
    /// Returns:
    /// - The total number of IPv6 addresses available. If this number is greater than
    ///   the length of the buffer, only the first `buf.len()` addresses will be stored in the buffer.
    pub fn ipv6_addrs(&self, buf: &mut [(Ipv6Addr, u8)]) -> Result<usize, OtError> {
        let mut ot = self.activate();
        let state = ot.state();

        let mut addrs_ptr = unsafe { otIp6GetUnicastAddresses(state.ot.instance) };

        let mut offset = 0;

        while !addrs_ptr.is_null() {
            let addrs = unsafe { addrs_ptr.as_ref() }.unwrap();

            if offset < buf.len() {
                buf[offset] = (
                    unsafe { addrs.mAddress.mFields.m8 }.into(),
                    addrs.mPrefixLength,
                );
            }

            offset += 1;
            addrs_ptr = addrs.mNext;
        }

        Ok(offset)
    }

    /// Wait for the OpenThread stack to change its state.
    ///
    /// NOTE:
    /// It is not advised to call this method concurrently from multiple async tasks
    /// because it uses a single waker registration. Thus, while the method will not panic,
    /// the tasks will fight with each other by each re-registering its own waker, thus keeping the CPU constantly busy.
    pub async fn wait_changed(&self) {
        poll_fn(move |cx| self.activate().state().ot.changes.poll_wait(cx)).await;
    }

    /// Run the OpenThread stack with the provided radio implementation, by:
    ///
    /// Arguments:
    /// - `radio`: The radio to be used by the OpenThread stack.
    ///
    /// NOTE:
    /// It is not advised to call this method concurrently from multiple async tasks
    /// because it uses a single waker registration. Thus, while the method will not panic,
    /// the tasks will fight with each other by each re-registering its own waker, thus keeping the CPU constantly busy.
    pub async fn run<R>(&self, radio: R) -> !
    where
        R: Radio,
    {
        let mut radio = pin!(self.run_radio(radio));
        let mut alarm = pin!(self.run_alarm());
        let mut openthread = pin!(self.run_tasklets());

        let result =
            embassy_futures::select::select3(&mut radio, &mut alarm, &mut openthread).await;

        match result {
            Either3::First(r) | Either3::Second(r) | Either3::Third(r) => r,
        }
    }

    /// Wait for an IPv6 packet to be available.
    ///
    /// NOTE:
    /// It is not advised to call this method concurrently from multiple async tasks
    /// because it uses a single waker registration. Thus, while the method will not panic,
    /// the tasks will fight with each other by each re-registering its own waker, thus keeping the CPU constantly busy.
    pub async fn wait_rx_available(&self) -> Result<(), OtError> {
        trace!("Waiting for IPv6 packet reception availability");

        poll_fn(move |cx| self.activate().state().ot.rx_ipv6.poll_wait_triggered(cx)).await;

        Ok(())
    }

    /// Receive an IPv6 packet.
    /// If there is no packet available, this function will async-wait until a packet is available.
    ///
    /// Arguments:
    /// - `buf`: A mutable reference to a buffer where the received packet will be stored.
    ///
    /// Returns:
    /// - The length of the received packet.
    ///
    /// NOTE:
    /// It is not advised to call this method concurrently from multiple async tasks
    /// because it uses a single waker registration. Thus, while the method will not panic,
    /// the tasks will fight with each other by each re-registering its own waker, thus keeping the CPU constantly busy.
    pub async fn rx(&self, buf: &mut [u8]) -> Result<usize, OtError> {
        if buf.is_empty() {
            return Ok(0);
        }

        trace!("Waiting for IPv6 packet reception");

        let msg = poll_fn(move |cx| self.activate().state().ot.rx_ipv6.poll_wait(cx)).await;

        let _ = self.activate();

        let len = unsafe { otMessageRead(msg, 0, buf.as_mut_ptr() as *mut _, buf.len() as _) as _ };

        unsafe {
            otMessageFree(msg);
        }

        debug!("Received IPv6 packet: {:02x?}", &buf[..len]);

        Ok(len)
    }

    /// Transmit an IPv6 packet.
    ///
    /// Arguments:
    /// - `packet`: The packet to be transmitted.
    pub fn tx(&self, packet: &[u8]) -> Result<(), OtError> {
        self.activate().tx_ip6(packet)
    }

    /// Initialize the OpenThread state, by:
    /// - Initializing the OpenThread C library (returning the OpenThread singleton) TBD: Support more than one OT instance in future
    /// - Setting the state change callback into the OpenThread C library
    /// - Setting the IPv6 receive callback into the OpenThread C library
    ///
    /// NOTE: This method assumes that tbe `OtState` contents is already initialized
    /// (i.e. all signals are in their initial values, and the data which represents OpenThread C types is all zeroed-out)
    fn init(&mut self) -> Result<(), OtError> {
        {
            // TODO: Not ideal but we have to activate even before we have the instance
            // Reason: `otPlatEntropyGet` is called back
            let mut ot = self.activate();
            let state = ot.state();

            state.ot.instance = unsafe { otInstanceInitSingle() };

            info!("OpenThread instance initialized at {:p}", state.ot.instance);

            // TODO: Remove on drop

            ot!(unsafe {
                otSetStateChangedCallback(
                    state.ot.instance,
                    Some(OtContext::plat_c_change_callback),
                    state.ot.instance as *mut _,
                )
            })?;

            unsafe {
                otIp6SetReceiveCallback(
                    state.ot.instance,
                    Some(OtContext::plat_c_ip6_receive_callback),
                    state.ot.instance as *mut _,
                )
            }
        }

        Ok(())
    }

    /// An async loop that waits until the latest alarm (if any) expires and then notifies the OpenThread C library
    /// Based on `embassy-time` for simplicity and for achieving platform-neutrality.
    async fn run_alarm(&self) -> ! {
        let alarm = || poll_fn(move |cx| self.activate().state().ot.alarm.poll_wait(cx));

        loop {
            trace!("Waiting for trigger alarm request");

            let Some(mut when) = alarm().await else {
                continue;
            };

            debug!("Got trigger alarm request: {when}, waiting for it to trigger");

            loop {
                let result =
                    embassy_futures::select::select(alarm(), embassy_time::Timer::at(when)).await;

                match result {
                    Either::First(new_when) => {
                        if let Some(new_when) = new_when {
                            debug!("Alarm interrupted by new alarm: {new_when}");
                            when = new_when;
                        } else {
                            debug!("Alarm cancelled");
                            break;
                        }
                    }
                    Either::Second(_) => {
                        // TODO: Rather than signalling the OT spin loop, notify OT directly?
                        debug!("Alarm triggered, notifying OT main loop");

                        {
                            let mut ot = self.activate();
                            let state = ot.state();

                            unsafe { otPlatAlarmMilliFired(state.ot.instance) };
                        }

                        break;
                    }
                }
            }
        }
    }

    /// An async loop that sends or receives IEEE 802.15.4 frames, based on commands issued by the OT loop
    ///
    /// Needs to be a separate async loop, because OpenThread C is unaware of async/await and futures,
    /// however, the Radio driver is async.
    async fn run_radio<R>(&self, mut radio: R) -> !
    where
        R: Radio,
    {
        let radio_cmd = || poll_fn(move |cx| self.activate().state().ot.radio.poll_wait(cx));

        loop {
            trace!("Waiting for radio command");

            let (mut cmd, mut conf) = radio_cmd().await;
            debug!("Got radio command: {cmd:?}");

            // TODO: Borrow it from the resources
            let mut psdu_buf = [0_u8; OT_RADIO_FRAME_MAX_SIZE as usize];

            loop {
                // TODO: Only do this if the conf changed
                debug!("Setting radio config: {conf:?}");
                let _ = radio.set_config(&conf).await;

                match cmd {
                    RadioCommand::Conf => break,
                    RadioCommand::Tx => {
                        let psdu_len = {
                            let mut ot = self.activate();
                            let state = ot.state();

                            let psdu_len = state.ot.radio_resources.snd_frame.mLength as usize;
                            psdu_buf[..psdu_len]
                                .copy_from_slice(&state.ot.radio_resources.snd_psdu[..psdu_len]);

                            unsafe {
                                otPlatRadioTxStarted(
                                    state.ot.instance,
                                    &mut state.ot.radio_resources.snd_frame,
                                );
                            }

                            psdu_len
                        };

                        trace!("About to Tx 802.15.4 frame {:02x?}", &psdu_buf[..psdu_len]);

                        let mut new_cmd = pin!(radio_cmd());
                        let mut tx = pin!(radio.transmit(&psdu_buf[..psdu_len]));

                        let result = embassy_futures::select::select(&mut new_cmd, &mut tx).await;

                        match result {
                            Either::First((new_cmd, new_conf)) => {
                                let mut ot = self.activate();
                                let state = ot.state();

                                // Reporting send failure because we got interrupted
                                // by a new command
                                unsafe {
                                    otPlatRadioTxDone(
                                        state.ot.instance,
                                        &mut state.ot.radio_resources.snd_frame,
                                        &mut state.ot.radio_resources.ack_frame,
                                        otError_OT_ERROR_FAILED,
                                    );
                                }

                                debug!("Tx interrupted by new command: {new_cmd:?}");

                                cmd = new_cmd;
                                conf = new_conf;
                            }
                            Either::Second(result) => {
                                let mut ot = self.activate();
                                let state = ot.state();

                                unsafe {
                                    otPlatRadioTxDone(
                                        state.ot.instance,
                                        &mut state.ot.radio_resources.snd_frame,
                                        &mut state.ot.radio_resources.ack_frame,
                                        if result.is_ok() {
                                            otError_OT_ERROR_NONE
                                        } else {
                                            otError_OT_ERROR_FAILED
                                        },
                                    );
                                }

                                debug!("Tx done: {result:?}");

                                break;
                            }
                        }
                    }
                    RadioCommand::Rx(channel) => {
                        trace!("Waiting for Rx on channel {channel}");

                        let result = {
                            let mut new_cmd = pin!(radio_cmd());
                            let mut rx = pin!(radio.receive(channel, &mut psdu_buf));

                            embassy_futures::select::select(&mut new_cmd, &mut rx).await
                        };

                        match result {
                            Either::First((new_cmd, new_conf)) => {
                                let mut ot = self.activate();
                                let state = ot.state();

                                // Reporting receive failure because we got interrupted
                                // by a new command
                                unsafe {
                                    otPlatRadioReceiveDone(
                                        state.ot.instance,
                                        &mut state.ot.radio_resources.rcv_frame,
                                        otError_OT_ERROR_FAILED,
                                    );
                                }

                                debug!("Rx interrupted by new command: {new_cmd:?}");

                                cmd = new_cmd;
                                conf = new_conf;
                            }
                            Either::Second(result) => {
                                // https://github.com/espressif/esp-idf/blob/release/v5.3/components/ieee802154/private_include/esp_ieee802154_frame.h#L20
                                // TODO: Not sure we actually need any of this...
                                const IEEE802154_FRAME_TYPE_OFFSET: usize = 0; // .. as we have removed the PHR and we are indexing the PSDU
                                const IEEE802154_FRAME_TYPE_MASK: u8 = 0x07;
                                const IEEE802154_FRAME_TYPE_BEACON: u8 = 0x00;
                                const IEEE802154_FRAME_TYPE_DATA: u8 = 0x01;
                                const IEEE802154_FRAME_TYPE_ACK: u8 = 0x02;
                                const IEEE802154_FRAME_TYPE_COMMAND: u8 = 0x03;

                                let mut ot = self.activate();
                                let state = ot.state();

                                let Ok(psdu_meta) = result else {
                                    warn!("Rx failed: {result:?}");

                                    // Reporting receive failure because we got a driver error
                                    unsafe {
                                        otPlatRadioReceiveDone(
                                            state.ot.instance,
                                            &mut state.ot.radio_resources.rcv_frame,
                                            otError_OT_ERROR_FAILED,
                                        );
                                    }

                                    break;
                                };

                                debug!(
                                    "Rx done, got frame: {psdu_meta:?}, {:02x?}",
                                    &psdu_buf[..psdu_meta.len]
                                );

                                state.ot.radio_resources.rcv_psdu[..psdu_meta.len]
                                    .copy_from_slice(&psdu_buf[..psdu_meta.len]);

                                let instance = state.ot.instance;

                                let resources = &mut state.ot.radio_resources;
                                let rcv_psdu = &resources.rcv_psdu[..psdu_meta.len];
                                let rcv_frame = &mut resources.rcv_frame;

                                fn frame_type(psdu: &[u8]) -> u8 {
                                    if psdu.len() == IEEE802154_FRAME_TYPE_OFFSET {
                                        return 0;
                                    }

                                    psdu[IEEE802154_FRAME_TYPE_OFFSET] & IEEE802154_FRAME_TYPE_MASK
                                }

                                /// Convert from RSSI (Received Signal Strength Indicator) to LQI (Link Quality
                                /// Indication)
                                ///
                                /// RSSI is a measure of incoherent (raw) RF power in a channel. LQI is a
                                /// cumulative value used in multi-hop networks to assess the cost of a link.
                                fn rssi_to_lqi(rssi: i8) -> u8 {
                                    if rssi < -80 {
                                        0
                                    } else if rssi > -30 {
                                        0xff
                                    } else {
                                        let lqi_convert = ((rssi as u32).wrapping_add(80)) * 255;
                                        (lqi_convert / 50) as u8
                                    }
                                }

                                match frame_type(rcv_psdu) {
                                    IEEE802154_FRAME_TYPE_DATA => {
                                        debug!("Got data frame, reporting");

                                        let rssi = psdu_meta.rssi.unwrap_or(0);

                                        rcv_frame.mLength = rcv_psdu.len() as u16;
                                        rcv_frame.mRadioType = 1; // ????
                                        rcv_frame.mChannel = channel;
                                        rcv_frame.mInfo.mRxInfo.mRssi = rssi;
                                        rcv_frame.mInfo.mRxInfo.mLqi = rssi_to_lqi(rssi);
                                        rcv_frame.mInfo.mRxInfo.mTimestamp =
                                            Instant::now().as_micros();

                                        unsafe {
                                            otPlatRadioReceiveDone(
                                                instance,
                                                rcv_frame,
                                                otError_OT_ERROR_NONE,
                                            );
                                        }
                                    }
                                    IEEE802154_FRAME_TYPE_BEACON
                                    | IEEE802154_FRAME_TYPE_COMMAND => {
                                        warn!("Received beacon or MAC command frame, triggering scan done");

                                        // ed_rss for H2 and C6 is the same
                                        const ENERGY_DETECT_RSS: i8 = 16;

                                        unsafe {
                                            otPlatRadioEnergyScanDone(
                                                state.ot.instance,
                                                ENERGY_DETECT_RSS,
                                            );
                                        }
                                    }
                                    IEEE802154_FRAME_TYPE_ACK => {
                                        debug!("Received ack frame");
                                    }
                                    _ => {
                                        // Drop unsupported frames
                                        warn!("Unsupported frame type received");
                                    }
                                }

                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    /// Spins the OpenThread C library loop by processing tasklets if they are pending
    /// or otherwise waiting until notified that there are pending tasklets
    async fn run_tasklets(&self) -> ! {
        loop {
            trace!("About to process Openthread tasklets");

            self.activate().process_tasklets();

            poll_fn(move |cx| self.activate().state().ot.tasklets.poll_wait(cx)).await;
        }
    }

    /// Activates the OpenThread stack.
    ///
    /// IMPORTANT: The OpenThread native C API can ONLY be called when this method is called and
    /// the returned `OpenThread` instance is in scope.
    ///
    /// IMPORTTANT: Do NOT hold on the `activate`d `OpenThread` instance accross `.await` points!
    ///
    /// Returns:
    /// - An `OpenThread` instance that represents the activated OpenThread stack.
    ///
    /// What activation means in the context of the `openthread` crate is as follows:
    /// - The global `OT_ACTIVE_STATE` variable is set to the current `OtActiveState` instance (which is a borrowed reference to the current `OtState` instance)
    ///   This is necessary so that when an native OpenThread C API "ot*" function is called, OpenThread can call us "back" via the `otPlat*` API
    /// - While the returned `OpenThread` instance is in scope, the data of `OtState` stays mutably borrowed
    fn activate(&self) -> OtContext<'_> {
        OtContext::activate_for(&self)
    }

    // #[cfg(feature = "srp-client")]
    // pub fn setup_srp_client_autostart(
    //     &mut self,
    //     callback: Option<
    //         unsafe extern "C" fn(aServerSockAddr: *const otSockAddr, aContext: *mut c_void),
    //     >,
    // ) -> Result<(), Error> {
    //     if !callback.is_some() {
    //         srp_client::enable_srp_autostart(self.instance);
    //         return Ok(());
    //     }
    //     srp_client::enable_srp_autostart_with_callback_and_context(
    //         self.instance,
    //         callback,
    //         core::ptr::null_mut(),
    //     );

    //     Ok(())
    // }

    // #[cfg(feature = "srp-client")]
    // pub fn setup_srp_client_host_addr_autoconfig(&mut self) -> Result<(), Error> {
    //     srp_client::set_srp_client_host_addresses_auto_config(self.instance)?;
    //     Ok(())
    // }

    // #[cfg(feature = "srp-client")]
    // pub fn setup_srp_client_set_hostname(&mut self, host_name: &str) -> Result<(), Error> {
    //     srp_client::set_srp_client_host_name(self.instance, host_name.as_ptr() as _)?;
    //     Ok(())
    // }

    // #[cfg(feature = "srp-client")]
    // pub fn setup_srp_client_with_addr(
    //     &mut self,
    //     host_name: &str,
    //     addr: otSockAddr,
    // ) -> Result<(), Error> {
    //     srp_client::set_srp_client_host_name(self.instance, host_name.as_ptr() as _)?;
    //     srp_client::srp_client_start(self.instance, addr)?;
    //     Ok(())
    // }

    // // For now, txt entries are expected to be provided as hex strings to avoid having to pull in the hex crate
    // // for example a key entry of 'abc' should be provided as '03616263'
    // #[cfg(feature = "srp-client")]
    // pub fn register_service_with_srp_client(
    //     &mut self,
    //     instance_name: &str,
    //     service_name: &str,
    //     service_labels: &[&str],
    //     txt_entry: &str,
    //     port: u16,
    //     priority: Option<u16>,
    //     weight: Option<u16>,
    //     lease: Option<u32>,
    //     key_lease: Option<u32>,
    // ) -> Result<(), Error> {
    //     if !srp_client::is_srp_client_running(self.instance) {
    //         self.setup_srp_client_autostart(None)?;
    //     }

    //     srp_client::add_srp_client_service(
    //         self.instance,
    //         instance_name.as_ptr() as _,
    //         instance_name.len() as _,
    //         service_name.as_ptr() as _,
    //         service_name.len() as _,
    //         service_labels,
    //         txt_entry.as_ptr() as _,
    //         txt_entry.len() as _,
    //         port,
    //         priority,
    //         weight,
    //         lease,
    //         key_lease,
    //     )?;

    //     Ok(())
    // }

    // #[cfg(feature = "srp-client")]
    // pub fn set_srp_client_ttl(&mut self, ttl: u32) {
    //     srp_client::set_srp_client_ttl(self.instance, ttl);
    // }

    // #[cfg(feature = "srp-client")]
    // pub fn get_srp_client_ttl(&mut self) -> u32 {
    //     srp_client::get_srp_client_ttl(self.instance)
    // }

    // #[cfg(feature = "srp-client")]
    // pub fn stop_srp_client(&mut self) -> Result<(), Error> {
    //     srp_client::srp_client_stop(self.instance);
    //     Ok(())
    // }

    // #[cfg(feature = "srp-client")]
    // pub fn get_srp_client_state(&mut self) -> Result<Option<SrpClientItemState>, Error> {
    //     Ok(srp_client::get_srp_client_host_state(self.instance))
    // }

    // #[cfg(feature = "srp-client")]
    // pub fn clear_srp_client_host_buffers(&mut self) {
    //     srp_client::srp_clear_all_client_services(self.instance)
    // }

    // /// If there are any services already registered, unregister them
    // #[cfg(feature = "srp-client")]
    // pub fn srp_unregister_all_services(
    //     &mut self,
    //     remove_keylease: bool,
    //     send_update: bool,
    // ) -> Result<(), Error> {
    //     srp_client::srp_unregister_and_remove_all_client_services(
    //         self.instance,
    //         remove_keylease,
    //         send_update,
    //     )?;
    //     Ok(())
    // }

    // #[cfg(feature = "srp-client")]
    // pub fn srp_clear_service(&mut self, service: SrpClientService) -> Result<(), Error> {
    //     srp_client::srp_clear_service(self.instance, service)?;
    //     Ok(())
    // }

    // #[cfg(feature = "srp-client")]
    // pub fn srp_unregister_service(&mut self, service: SrpClientService) -> Result<(), Error> {
    //     srp_client::srp_unregister_service(self.instance, service)?;
    //     Ok(())
    // }

    // #[cfg(feature = "srp-client")]
    // pub fn srp_get_services(
    //     &mut self,
    // ) -> heapless::Vec<SrpClientService, { srp_client::MAX_SERVICES }> {
    //     srp_client::get_srp_client_services(self.instance)
    // }
}

/// The resources (data) that is necessary for the OpenThread stack to operate.
///
/// A separate type so that it can be allocated outside of the OpenThread futures,
/// thus avoiding expensive mem-moves.
///
/// Can also be statically-allocated.
pub struct OtResources {
    /// The radio resources.
    radio_resources: MaybeUninit<RadioResources>,
    /// The dataset resources.
    dataset_resources: MaybeUninit<DatasetResources>,
    /// The OpenThread state.
    ///
    /// This state borrows the radio and dataset resources thus
    /// making this struct self-referencial.
    /// This is not a problem because the `OpenThread` construction API is designed in such a way,
    /// so that this self-referencial borrowing happens only while `OtResources` itself stays mutably
    /// borrowed, while is the case until the `OpenThread` instance is dropped.
    state: MaybeUninit<RefCell<OtState<'static>>>,
}

impl OtResources {
    /// Create a new `OtResources` instance.
    pub const fn new() -> Self {
        Self {
            radio_resources: MaybeUninit::uninit(),
            dataset_resources: MaybeUninit::uninit(),
            state: MaybeUninit::uninit(),
        }
    }

    /// Initialize the resouces, as they start their life as `MaybeUninit` so as to avoid mem-moves.
    ///
    /// Returns:
    /// - A reference to a `RefCell<OtState>` value that represents the initialized OpenThread state.
    // TODO: Need to manually drop/reset the signals in OtSignals
    fn init(&mut self, rng: &'static mut dyn RngCore) -> &RefCell<OtState<'static>> {
        let radio_resources = unsafe { self.radio_resources.assume_init_mut() };
        let dataset_resources = unsafe { self.dataset_resources.assume_init_mut() };

        radio_resources.init();

        self.state.write(RefCell::new(unsafe {
            core::mem::transmute(OtState {
                rng: Some(rng),
                radio_resources,
                dataset_resources,
                instance: core::ptr::null_mut(),
                rx_ipv6: Signal::new(),
                alarm: Signal::new(),
                tasklets: Signal::new(),
                changes: Signal::new(),
                radio: Signal::new(),
                radio_conf: Config::new(),
            })
        }));

        info!("OpenThread resources initialized");

        unsafe { self.state.assume_init_mut() }
    }
}

impl Default for OtResources {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents an "activated" `OtState` and potentially an activated `OtUdpState`.
///
/// An activated `OtState`/`OtUdpState` is simply the same state but mutably borrowed,
/// for the duration of the activation.
struct OtActiveState<'a> {
    /// The activated `OtState` instance.
    ot: RefMut<'a, OtState<'static>>,
    /// The activated `OtUdpState` instance.
    #[cfg(feature = "udp")]
    udp: Option<RefMut<'a, OtUdpState<'static>>>,
}

impl OtActiveState<'_> {
    /// A utility to get a reference to the UDP state
    ///
    /// This method will panic if the `OpenThread` instance was not
    /// initialized with UDP resources.
    pub(crate) fn udp(&mut self) -> &mut OtUdpState<'static> {
        self.udp.as_mut().unwrap()
    }
}

// A hack so that we can store `OtActiveState` in the global `OT_ACTIVE_STATE` variable
// While it is not really `Send`-safe, we _do_ know that there a single C OpenThread instance, and it will
// always call us back from the thread on which we called it.
unsafe impl Send for OtActiveState<'_> {}

/// Represents an activated `OpenThread` instance.
/// See `OtContext::activate_for` for more information.
struct OtContext<'a> {
    callback: bool,
    _t: PhantomData<&'a mut ()>,
}

impl<'a> OtContext<'a> {
    /// Activates the OpenThread C wrapper by (temporarily) putting the OpenThread state
    /// in the global `OT_ACTIVE_STATE` variable, which allows the OpenThread C library to call us back.
    ///
    /// Activation is therefore a cheap operation which is expected to be done often, for a short duration
    /// (ideally, just to call one or a few OpenThread C functions) and should not persist across await points
    /// (see below).
    ///
    /// The reason to have the notion of activation in the first place is because there are mutiple async agents that
    /// are willing to operate on the same data, i.e.:
    /// - The radio async loop
    /// - The alarm async loop
    /// - The tasklets processing async loop
    /// - The RX, TX and other futures (which might call into OpenThread C by activating it shortly first)
    ///
    /// All of the above tasks operate on the same data (`OtState` / `OtUdpState`) by mutably borrowing it first, either
    /// directly, or by activating (= creating an `OtContext` type instance) and then calling an OpenThread C API.
    ///
    /// Activation is automacally finished when the `OtContext` instance is dropped.
    ///
    /// NOTE: Do NOT hold references to the `OtContext` instance across `.await` points!
    /// NOTE: Do NOT call `activate` twice without dropping the previous instance!
    ///
    /// The above ^^^ will not lead to a memory corruption, but the code will panic due to an attempt
    /// to mutably borrow the `OtState` `RefCell`d data twice.
    fn activate_for(ot: &'a OpenThread) -> Self {
        assert!(unsafe { OT_ACTIVE_STATE.0.get().as_mut() }
            .unwrap()
            .is_none());

        let active = OtActiveState {
            ot: ot.state.borrow_mut(),
            #[cfg(feature = "udp")]
            udp: ot.udp_state.map(|u| u.borrow_mut()),
        };

        // Needed so that we convert from the fake `'static` lifetime in `OT_ACTIVE_STATE` to the actual `'a` lifetime of `ot`
        #[allow(clippy::missing_transmute_annotations)]
        {
            *unsafe { OT_ACTIVE_STATE.0.get().as_mut() }.unwrap() =
                Some(unsafe { core::mem::transmute(active) });
        }

        Self {
            callback: false,
            _t: PhantomData,
        }
    }

    /// Obtain the already activated `OtContext` instance when arriving
    /// back from C into our code, via some of the `otPlat*` wrappers.
    ///
    /// This method is called when the OpenThread C library calls us back.
    fn callback(_instance: *const otInstance) -> Self {
        assert!(unsafe { OT_ACTIVE_STATE.0.get().as_mut() }
            .unwrap()
            .is_some());

        Self {
            callback: true,
            _t: PhantomData,
        }
    }

    /// Gets a reference to the `OtActiveState` instance owned by this `OtContext` instance.
    fn state(&mut self) -> &mut OtActiveState<'a> {
        unsafe { core::mem::transmute(OT_ACTIVE_STATE.0.get().as_mut().unwrap().as_mut().unwrap()) }
    }

    /// Ingest an IPv6 packet into OpenThread.
    fn tx_ip6(&mut self, packet: &[u8]) -> Result<(), OtError> {
        let state = self.state();

        let msg = unsafe {
            otIp6NewMessageFromBuffer(
                state.ot.instance,
                packet.as_ptr(),
                packet.len() as _,
                &otMessageSettings {
                    mLinkSecurityEnabled: true,
                    mPriority: otMessagePriority_OT_MESSAGE_PRIORITY_NORMAL as _,
                },
            )
        };

        if !msg.is_null() {
            debug!("Transmitted IPv6 packet: {:02x?}", packet);

            let res = unsafe { otIp6Send(state.ot.instance, msg) };
            if res != otError_OT_ERROR_DROP {
                ot!(res)
            } else {
                // OpenThread will intentionally drop some multicast and ICMPv6 packets
                // which are not required for the Thread network.
                trace!("Message dropped");
                Ok(())
            }
        } else {
            Err(OtError::new(otError_OT_ERROR_NO_BUFS))
        }
    }

    /// Process the tasklets if they are pending.
    fn process_tasklets(&mut self) {
        unsafe { otTaskletsProcess(self.state().ot.instance) };
    }

    unsafe extern "C" fn plat_c_change_callback(flags: otChangedFlags, context: *mut c_void) {
        let instance = context as *mut otInstance;

        Self::callback(instance).plat_changed(flags);
    }

    unsafe extern "C" fn plat_c_ip6_receive_callback(msg: *mut otMessage, context: *mut c_void) {
        let instance = context as *mut otInstance;

        Self::callback(instance).plat_ipv6_received(msg);
    }

    // /// caller must call this prior to setting up the host config
    // #[cfg(feature = "srp-client")]
    // pub fn set_srp_state_callback(
    //     &mut self,
    //     callback: Option<&'a mut (dyn FnMut(otError, usize, usize, usize) + Send)>,
    // ) {
    //     critical_section::with(|cs| {
    //         let mut srp_change_callback = SRP_CHANGE_CALLBACK.borrow_ref_mut(cs);
    //         *srp_change_callback = unsafe { core::mem::transmute(callback) };
    //     });

    //     unsafe {
    //         otSrpClientSetCallback(
    //             self.instance,
    //             Some(srp_state_callback),
    //             core::ptr::null_mut(),
    //         )
    //     }
    // }

    //
    // All `plat_*` methods below represent the OpenThread C library calling us back.
    // Note that OpenThread C cannot call us back "randomly", as it is not multithreaded and
    // is completely passive.
    //
    // We can get a callback ONLY in the context of _us_ calling an `ot*` OpenThread C API method first.
    // Before the `ot*` method returns, we might get called back via one or more callbacks.
    //

    fn plat_reset(&mut self) -> Result<(), OtError> {
        todo!()
    }

    fn plat_entropy_get(&mut self, buf: &mut [u8]) -> Result<(), OtError> {
        self.state().ot.rng.as_mut().unwrap().fill_bytes(buf);

        Ok(())
    }

    fn plat_tasklets_signal_pending(&mut self) {
        self.state().ot.tasklets.signal(());
    }

    fn plat_ipv6_received(&mut self, msg: *mut otMessage) {
        trace!("Got ipv6 packet");

        let state = self.state();

        if state.ot.rx_ipv6.signaled() {
            unsafe {
                otMessageFree(msg);
            }
        } else {
            state.ot.rx_ipv6.signal(msg);
        }
    }

    fn plat_changed(&mut self, _flags: u32) {
        trace!("Plat changed callback");
        self.state().ot.changes.signal(());
    }

    fn plat_now(&mut self) -> u32 {
        trace!("Plat now callback");
        Instant::now().as_millis() as u32
    }

    fn plat_alarm_set(&mut self, at0_ms: u32, adt_ms: u32) -> Result<(), OtError> {
        trace!("Plat alarm set callback: {at0_ms}, {adt_ms}");

        let instant = embassy_time::Instant::from_millis(at0_ms as _)
            + embassy_time::Duration::from_millis(adt_ms as _);

        self.state().ot.alarm.signal(Some(instant));

        Ok(())
    }

    fn plat_alarm_clear(&mut self) -> Result<(), OtError> {
        trace!("Plat alarm clear callback");
        self.state().ot.alarm.signal(None);

        Ok(())
    }

    fn plat_radio_ieee_eui64(&mut self, mac: &mut [u8; 8]) {
        mac.fill(0);
        trace!("Plat radio IEEE EUI64 callback, MAC: {:02x?}", mac);
    }

    fn plat_radio_caps(&mut self) -> u8 {
        let caps = 0; // TODO
        trace!("Plat radio caps callback, caps: {caps}");

        caps
    }

    fn plat_radio_is_enabled(&mut self) -> bool {
        let enabled = true; // TODO
        trace!("Plat radio is enabled callback, enabled: {enabled}");

        enabled
    }

    fn plat_radio_get_rssi(&mut self) -> i8 {
        let rssi = -128; // TODO
        trace!("Plat radio get RSSI callback, RSSI: {rssi}");

        rssi
    }

    // from https://github.com/espressif/esp-idf/blob/release/v5.3/components/openthread/src/port/esp_openthread_radio.c#L35
    fn plat_radio_receive_sensititivy(&mut self) -> i8 {
        let sens = 0; // TODO
        trace!("Plat radio receive sensitivity callback, sensitivity: {sens}");

        sens
    }

    fn plat_radio_get_promiscuous(&mut self) -> bool {
        let promiscuous = false; // TODO
        trace!("Plat radio get promiscuous callback, promiscuous: {promiscuous}");

        promiscuous
    }

    fn plat_radio_enable(&mut self) -> Result<(), OtError> {
        info!("Plat radio enable callback");
        Ok(()) // TODO
    }

    fn plat_radio_disable(&mut self) -> Result<(), OtError> {
        info!("Plat radio disable callback");
        Ok(()) // TODO
    }

    fn plat_radio_set_promiscuous(&mut self, promiscuous: bool) {
        info!("Plat radio set promiscuous callback, promiscuous: {promiscuous}");

        let state = self.state();

        if state.ot.radio_conf.promiscuous != promiscuous {
            state.ot.radio_conf.promiscuous = promiscuous;

            let conf = state.ot.radio_conf.clone();
            state.ot.radio.signal((RadioCommand::Conf, conf));
        }
    }

    fn plat_radio_set_extended_address(&mut self, address: u64) {
        info!("Plat radio set extended address callback, addr: {address}");

        let state = self.state();

        if state.ot.radio_conf.ext_addr != Some(address) {
            state.ot.radio_conf.ext_addr = Some(address);

            let conf = state.ot.radio_conf.clone();
            state.ot.radio.signal((RadioCommand::Conf, conf));
        }
    }

    fn plat_radio_set_short_address(&mut self, address: u16) {
        info!("Plat radio set short address callback, addr: {address}");

        let state = self.state();

        if state.ot.radio_conf.short_addr != Some(address) {
            state.ot.radio_conf.short_addr = Some(address);

            let conf = state.ot.radio_conf.clone();
            state.ot.radio.signal((RadioCommand::Conf, conf));
        }
    }

    fn plat_radio_set_pan_id(&mut self, pan_id: u16) {
        info!("Plat radio set PAN ID callback, PAN ID: {pan_id}");

        let state = self.state();

        if state.ot.radio_conf.pan_id != Some(pan_id) {
            state.ot.radio_conf.pan_id = Some(pan_id);

            let conf = state.ot.radio_conf.clone();
            state.ot.radio.signal((RadioCommand::Conf, conf));
        }
    }

    fn plat_radio_energy_scan(&mut self, channel: u8, duration: u16) -> Result<(), OtError> {
        info!("Plat radio energy scan callback, channel {channel}, duration {duration}");
        unreachable!()
    }

    fn plat_radio_sleep(&mut self) -> Result<(), OtError> {
        info!("Plat radio sleep callback");
        Ok(()) // TODO
    }

    fn plat_radio_transmit_buffer(&mut self) -> *mut otRadioFrame {
        trace!("Plat radio transmit buffer callback");
        // TODO: This frame is private to us, perhaps don't store it in a RefCell?
        &mut self.state().ot.radio_resources.tns_frame
    }

    fn plat_radio_transmit(&mut self, frame: &otRadioFrame) -> Result<(), OtError> {
        trace!(
            "Plat radio transmit callback: {}, {:02x?}",
            frame.mLength,
            frame.mPsdu
        );

        let state = self.state();

        let psdu = unsafe { core::slice::from_raw_parts_mut(frame.mPsdu, frame.mLength as _) };

        state.ot.radio_resources.snd_frame = *frame;
        state.ot.radio_resources.snd_psdu[..psdu.len()].copy_from_slice(psdu);
        state.ot.radio_resources.snd_frame.mPsdu =
            addr_of_mut!(state.ot.radio_resources.snd_psdu) as *mut _;

        let conf = state.ot.radio_conf.clone();
        state.ot.radio.signal((RadioCommand::Tx, conf));

        Ok(())
    }

    fn plat_radio_receive(&mut self, channel: u8) -> Result<(), OtError> {
        trace!("Plat radio receive callback, channel: {channel}");

        let state = self.state();

        let conf = state.ot.radio_conf.clone();
        state.ot.radio.signal((RadioCommand::Tx, conf));

        Ok(())
    }
}

impl Drop for OtContext<'_> {
    fn drop(&mut self) {
        assert!(unsafe { OT_ACTIVE_STATE.0.get().as_mut() }
            .unwrap()
            .is_some());

        if !self.callback {
            *unsafe { OT_ACTIVE_STATE.0.get().as_mut() }.unwrap() = None;
        }
    }
}

/// The OpenThread state from Rust POV.
///
/// This data lives behind a `RefCell` and is mutably borrowed each time
/// the OpenThread stack is activated, by creating an `OtContext` instance.
struct OtState<'a> {
    /// The OpenThread instance associated with the `OtData` inztance.
    instance: *mut otInstance,
    /// The random number generator associated with the `OtData` instance.
    rng: Option<&'static mut dyn RngCore>,
    /// If not null, an Ipv6 packet egressed from OpenThread and waiting (via `OtRx`) to be ingressed somewhere else
    /// To be used together with `OtSignals::rx_ipv6`
    /// TODO: Maybe unite the two?
    rx_ipv6: Signal<*mut otMessage>,
    /// `Some` in case there is a pending OpenThread awarm which is not due yet
    alarm: Signal<Option<embassy_time::Instant>>,
    /// If `true`, the tasklets need to be run. Set by the OpenThread C library via the `otPlatTaskletsSignalPending` callback
    tasklets: Signal<()>,
    changes: Signal<()>,
    radio: Signal<(RadioCommand, radio::Config)>,
    radio_conf: radio::Config,
    /// Resources for the radio (PHY data frames and their descriptors)
    radio_resources: &'a mut RadioResources,
    /// Resouces for dealing with the operational dataset
    dataset_resources: &'a mut DatasetResources,
}

/// A command for the radio runner to process.
#[derive(Debug)]
enum RadioCommand {
    Conf,
    /// Transmit a frame
    /// The data of the frame is in `OtData::radio_resources.snd_frame` and `OtData::radio_resources.snd_psdu`
    ///
    /// Once the frame is sent (or an error occurs) OpenThread C will be signalled by calling `otPlatRadioTxDone`
    Tx,
    /// Receive a frame on a specific channel
    ///
    /// Once the frame is received, it will be copied to `OtData::radio_resources.rcv_frame` and `OtData::radio_resources.rcv_psdu`
    /// and OpenThread C will be signalled by calling `otPlatRadioReceiveDone`
    Rx(u8),
}

/// Radio-related OpenThread C data carriers
///
/// Note that this structure is self-referential in that its `*_frame` members all
/// contain a pointer to its corresponding `*_psdu` member.
///
/// This is not modelled strictly (i.e. with pinning), because all of these structures are internal and not an API
/// the user can abuse. With that said, care should be taken the self-referencial struct to be properly initialized,
/// before using it and members of the struct should not be swapped-out after that.
///
/// With that said, the structure anyway cannot be moved once we hit the `OpenThread::new*` functions in this crate,
/// because of the signature of the `OpenThread::new*` APIs which **mutably borrow** `OtResources` (and thus this structure too)
/// for the lifetime of the `OpenThread` Rust stack.
struct RadioResources {
    /// The received frame from the radio
    rcv_frame: otRadioFrame,
    /// An empty ACK frame send to `otPlatRadioReceiveDone` TBD why we need that
    ack_frame: otRadioFrame,
    /// A buffer where OpenThread prepares the next frame to be send
    tns_frame: otRadioFrame,
    /// A frame which is to be send to the radio
    snd_frame: otRadioFrame,
    /// The PSDU of the received frame
    /// NOTE:
    rcv_psdu: [u8; OT_RADIO_FRAME_MAX_SIZE as usize],
    tns_psdu: [u8; OT_RADIO_FRAME_MAX_SIZE as usize],
    snd_psdu: [u8; OT_RADIO_FRAME_MAX_SIZE as usize],
    ack_psdu: [u8; OT_RADIO_FRAME_MAX_SIZE as usize],
}

impl RadioResources {
    /// Create a new `RadioResources` instance.
    pub const fn new() -> Self {
        unsafe {
            Self {
                rcv_frame: MaybeUninit::zeroed().assume_init(),
                tns_frame: MaybeUninit::zeroed().assume_init(),
                snd_frame: MaybeUninit::zeroed().assume_init(),
                ack_frame: MaybeUninit::zeroed().assume_init(),
                rcv_psdu: MaybeUninit::zeroed().assume_init(),
                tns_psdu: MaybeUninit::zeroed().assume_init(),
                snd_psdu: MaybeUninit::zeroed().assume_init(),
                ack_psdu: MaybeUninit::zeroed().assume_init(),
            }
        }
    }

    /// Initialize the `RadioResources` instance by doing the self-referential magic.
    ///
    /// For this to work, `init` should be called from inside the `Openthread::new*` API methods that create
    /// all of the public-facing APIs, as at that time `OtResources` is already mutably borrowed and cannot move.
    ///
    /// This method should not be called e.g. from the constructor of `OtResources`, as the value can move once
    /// constructed and before being mutable borrowed into the `openthread::new` API method from above.
    fn init(&mut self) {
        self.rcv_frame.mPsdu = addr_of_mut!(self.rcv_psdu) as *mut _;
        self.tns_frame.mPsdu = addr_of_mut!(self.tns_psdu) as *mut _;
        self.snd_frame.mPsdu = addr_of_mut!(self.snd_psdu) as *mut _;
        self.ack_frame.mPsdu = addr_of_mut!(self.ack_psdu) as *mut _;
    }
}

/// Dataset-related OpenThread C data carriers
struct DatasetResources {
    /// The operational dataset
    dataset: otOperationalDataset,
}

impl DatasetResources {
    /// Create a new `DatasetResources` instance.
    pub const fn new() -> Self {
        unsafe {
            Self {
                dataset: MaybeUninit::zeroed().assume_init(),
            }
        }
    }
}
