use core::cell::RefCell;
use core::ffi::c_void;
use core::future::poll_fn;
use core::mem::MaybeUninit;
use core::net::{Ipv6Addr, SocketAddrV6};

use log::{debug, info, trace};

use crate::signal::Signal;
use crate::sys::{
    __BindgenBitfieldUnit, otError_OT_ERROR_DROP, otError_OT_ERROR_NO_BUFS, otIp6Address,
    otIp6Address__bindgen_ty_1, otMessage, otMessageAppend, otMessageGetLength, otMessageInfo,
    otMessageRead, otNetifIdentifier_OT_NETIF_THREAD, otSockAddr, otUdpBind, otUdpClose,
    otUdpConnect, otUdpNewMessage, otUdpOpen, otUdpSend, otUdpSocket,
};
use crate::{ot, OpenThread, OtContext, OtError};

/// An OpenThread native UDP socket
pub struct UdpSocket<'a> {
    /// The OpenThread stack that the socket is associated with.
    ot: OpenThread<'a>,
    /// The slot in the OpenThread stack's UDP socket array that this socket occupies.
    slot: usize,
}

impl<'a> UdpSocket<'a> {
    /// Create a new UDP socket and bind it to the specified local address.
    pub fn bind(ot: OpenThread<'a>, local: &SocketAddrV6) -> Result<Self, OtError> {
        let this = Self::new(ot)?;

        {
            let mut ot = this.ot.activate();
            let state = ot.state();

            unsafe {
                otUdpBind(
                    state.ot.instance,
                    &mut state.udp.as_mut().unwrap().sockets[this.slot].ot_socket,
                    &to_ot_addr(local),
                    otNetifIdentifier_OT_NETIF_THREAD,
                );
            }
        }

        Ok(this)
    }

    /// Create a new UDP socket and connect it to the specified remote address.
    pub fn connect(ot: OpenThread<'a>, remote: &SocketAddrV6) -> Result<Self, OtError> {
        let this = Self::new(ot)?;

        {
            let mut ot = this.ot.activate();
            let state = ot.state();

            unsafe {
                otUdpConnect(
                    state.ot.instance,
                    &mut state.udp().sockets[this.slot].ot_socket,
                    &to_ot_addr(remote),
                );
            }
        }

        Ok(this)
    }

    /// Create a new unbound and unconnected UDP socket.
    fn new(ot: OpenThread<'a>) -> Result<Self, OtError> {
        let mut active_ot = ot.activate();
        let state = active_ot.state();
        let instance = state.ot.instance;
        let udp = state.udp();

        let slot = udp
            .sockets
            .iter()
            .position(|socket| !socket.taken)
            .ok_or(otError_OT_ERROR_NO_BUFS)?;

        let socket = &mut udp.sockets[slot];
        // TODO socket.socket = UdpSocketData::new();
        socket.taken = true;

        unsafe {
            otUdpOpen(
                instance,
                &mut socket.ot_socket,
                Some(Self::plat_c_udp_receive),
                slot as *mut c_void,
            );
        }

        Ok(Self { ot, slot })
    }

    /// Wait until the socket is ready to receive data.
    ///
    /// NOTE:
    /// It is not advised to call this method concurrently from multiple async tasks
    /// because it uses a single waker registration. Thus, while the method will not panic,
    /// the tasks will fight with each other by each re-registering its own waker, thus keeping the CPU constantly busy.
    pub async fn wait_recv_available(&self) -> Result<(), OtError> {
        poll_fn(move |cx| {
            self.ot.activate().state().udp().sockets[self.slot]
                .rx_peer
                .poll_wait_signaled(cx)
        })
        .await;

        Ok(())
    }

    /// Receive data from the socket.
    /// If there is no UDP packet available, this function will async-wait until a packet is available.
    ///
    /// Arguments:
    /// - `buf`: The buffer to store the received data.
    ///
    /// Returns:
    /// - The number of bytes received.
    /// - The peer address from where the packet was received.
    ///
    /// NOTE:
    /// It is not advised to call this method concurrently from multiple async tasks
    /// because it uses a single waker registration. Thus, while the method will not panic,
    /// the tasks will fight with each other by each re-registering its own waker, thus keeping the CPU constantly busy.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddrV6), OtError> {
        if buf.is_empty() {
            return Ok((0, SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)));
        }

        let (len, src_addr) = poll_fn(move |cx| {
            self.ot.activate().state().udp().sockets[self.slot]
                .rx_peer
                .poll_wait(cx)
        })
        .await;

        let mut ot = self.ot.activate();
        let udp = ot.state().udp();

        let offset = self.slot * udp.buf_len;
        let data = &mut udp.buffers[offset..offset + len];

        let len = len.min(buf.len());
        buf[..len].copy_from_slice(&data[..len]);

        Ok((len, src_addr))
    }

    /// Send data to the specified destination.
    ///
    /// Arguments:
    /// - `data`: The data to send.
    /// - `dst`: The destination address.
    pub async fn send(&self, data: &[u8], dst: &SocketAddrV6) -> Result<(), OtError> {
        let mut ot = self.ot.activate();
        let state = ot.state();
        let instance = state.ot.instance;
        let udp = state.udp();

        let msg = unsafe { otUdpNewMessage(instance, core::ptr::null()) };

        if !msg.is_null() {
            ot!(unsafe { otMessageAppend(msg, data.as_ptr() as *mut _, data.len() as _) })?;

            let mut message_info = otMessageInfo {
                mSockAddr: otIp6Address {
                    mFields: otIp6Address__bindgen_ty_1 { m32: [0, 0, 0, 0] },
                },
                mPeerAddr: otIp6Address {
                    mFields: otIp6Address__bindgen_ty_1 { m32: [0, 0, 0, 0] },
                },
                mSockPort: 0,
                mPeerPort: 0,
                mHopLimit: 0,
                _bitfield_align_1: [0u8; 0],
                _bitfield_1: __BindgenBitfieldUnit::new([0u8; 1]),
            };

            message_info.mPeerAddr.mFields.m8 = dst.ip().octets();
            message_info.mPeerPort = dst.port();

            let socket = &mut udp.sockets[self.slot];

            let res = unsafe { otUdpSend(instance, &mut socket.ot_socket, msg, &message_info) };
            if res != otError_OT_ERROR_DROP {
                ot!(res)?;
            } else {
                // OpenThread will intentionally drop some multicast and ICMPv6 packets
                // which are not required for the Thread network.
                trace!("UDP message dropped");
            }

            debug!("Transmitted UDP packet: {:02x?}", data);

            Ok(())
        } else {
            Err(OtError::new(otError_OT_ERROR_NO_BUFS))
        }
    }

    extern "C" fn plat_c_udp_receive(
        slot: *mut c_void,
        msg: *mut otMessage,
        msg_info: *const otMessageInfo,
    ) {
        let slot: usize = slot as usize;

        let mut ot = OtContext::callback(core::ptr::null_mut());
        let udp = ot.state().udp();

        let socket = &mut udp.sockets[slot];
        if socket.rx_peer.signaled() {
            return;
        }

        let msg = unsafe { &*msg };
        let msg_info = unsafe { &*msg_info };
        let msg_len = unsafe { otMessageGetLength(msg) as usize };

        let buf_len = udp.buf_len;
        if msg_len <= buf_len {
            let offset = slot * buf_len;
            let buf = &mut udp.buffers[offset..offset + buf_len];

            unsafe {
                otMessageRead(
                    msg,
                    0,
                    buf.as_mut_ptr() as *mut _,
                    buf_len.min(msg_len) as _,
                );
            };

            socket
                .rx_peer
                .signal((msg_len, to_sock_addr(&msg_info.mPeerAddr, 0, 0)));
        }
    }
}

impl Drop for UdpSocket<'_> {
    fn drop(&mut self) {
        let mut ot = self.ot.activate();
        let instance = ot.state().ot.instance;
        let udp = ot.state().udp();

        ot!(unsafe { otUdpClose(instance, &mut udp.sockets[self.slot].ot_socket,) }).unwrap();

        udp.sockets[self.slot].taken = false;
    }
}

/// The resources (data) that is necessary for the OpenThread stack to operate with UDP sockets.
///
/// A separate type so that it can be allocated outside of the OpenThread futures,
/// thus avoiding expensive mem-moves.
///
/// Can also be statically-allocated.
pub struct OtUdpResources<const UDP_SOCKETS: usize, const UDP_RX_SZ: usize> {
    /// The UDP sockets that are available for use.
    sockets: MaybeUninit<[UdpSocketCtx; UDP_SOCKETS]>,
    /// The buffers that are used to store received UDP packets.
    buffers: MaybeUninit<[[u8; UDP_RX_SZ]; UDP_SOCKETS]>,
    /// The state of the OpenThread stack, from Rust POV.
    state: MaybeUninit<RefCell<OtUdpState<'static>>>,
}

impl<const UDP_SOCKETS: usize, const UDP_RX_SZ: usize> OtUdpResources<UDP_SOCKETS, UDP_RX_SZ> {
    #[allow(clippy::declare_interior_mutable_const)]
    const INIT_SOCKET: UdpSocketCtx = UdpSocketCtx::new();
    #[allow(clippy::declare_interior_mutable_const)]
    const INIT_BUFFERS: [u8; UDP_RX_SZ] = [0; UDP_RX_SZ];

    /// Create a new `OtResources` instance.
    pub const fn new() -> Self {
        Self {
            sockets: MaybeUninit::uninit(),
            buffers: MaybeUninit::uninit(),
            state: MaybeUninit::uninit(),
        }
    }

    /// Initialize the resouces, as they start their life as `MaybeUninit` so as to avoid mem-moves.
    ///
    /// Returns:
    /// - A reference to a `RefCell<OtUdpState>` value that represents the initialized OpenThread UDP state.
    pub(crate) fn init(&mut self) -> &mut RefCell<OtUdpState<'static>> {
        self.sockets.write([Self::INIT_SOCKET; UDP_SOCKETS]);
        self.buffers.write([Self::INIT_BUFFERS; UDP_SOCKETS]);

        let buffers: &mut [[u8; UDP_RX_SZ]; UDP_SOCKETS] =
            unsafe { self.buffers.assume_init_mut() };

        #[allow(clippy::missing_transmute_annotations)]
        self.state.write(RefCell::new(unsafe {
            core::mem::transmute(OtUdpState {
                sockets: self.sockets.assume_init_mut(),
                buffers: core::slice::from_raw_parts_mut(
                    buffers.as_mut_ptr() as *mut _,
                    UDP_RX_SZ * UDP_SOCKETS,
                ),
                buf_len: UDP_RX_SZ,
            })
        }));

        info!("OpenThread UDP resources initialized");

        unsafe { self.state.assume_init_mut() }
    }
}

impl<const UDP_SOCKETS: usize, const UDP_RX_SZ: usize> Default
    for OtUdpResources<UDP_SOCKETS, UDP_RX_SZ>
{
    fn default() -> Self {
        Self::new()
    }
}

/// The UDP state of the OpenThread stack, from Rust POV.
///
/// This data lives behind a `RefCell` and is mutably borrowed each time
/// the OpenThread stack is activated, by creating an `OtContext` instance.
pub(crate) struct OtUdpState<'a> {
    /// The UDP sockets that are available for use.
    sockets: &'a mut [UdpSocketCtx],
    /// The buffers that are used to store received UDP packets.
    buffers: &'a mut [u8],
    /// The length of each buffer.
    buf_len: usize,
}

/// The internal data associated with each `UdpSocket` instance.
pub(crate) struct UdpSocketCtx {
    /// Whether the data (slot) is taken by a `UdpSocket` instance or not.
    taken: bool,
    /// The OpenThread native UDP socket.
    ot_socket: otUdpSocket,
    /// The signal that is triggered when a UDP packet is received.
    rx_peer: Signal<(usize, SocketAddrV6)>,
}

impl UdpSocketCtx {
    /// Create a new `UdpSocketCtx` instance.
    pub(crate) const fn new() -> Self {
        Self {
            taken: false,
            ot_socket: otUdpSocket {
                mSockName: otSockAddr {
                    mAddress: otIp6Address {
                        mFields: otIp6Address__bindgen_ty_1 { m8: [0; 16] },
                    },
                    mPort: 0,
                },
                mPeerName: otSockAddr {
                    mAddress: otIp6Address {
                        mFields: otIp6Address__bindgen_ty_1 { m8: [0; 16] },
                    },
                    mPort: 0,
                },
                mHandler: None,
                mContext: core::ptr::null_mut(),
                mHandle: core::ptr::null_mut(),
                mNext: core::ptr::null_mut(),
            },
            rx_peer: Signal::new(),
        }
    }
}

/// Convert an `otIp6Address`, port and network interface ID to a `SocketAddrV6`.
fn to_sock_addr(addr: &otIp6Address, port: u16, netif: u32) -> SocketAddrV6 {
    SocketAddrV6::new(Ipv6Addr::from(unsafe { addr.mFields.m8 }), port, 0, netif)
}

/// Convert a `SocketAddrV6` to an `otSockAddr`.
fn to_ot_addr(addr: &SocketAddrV6) -> otSockAddr {
    otSockAddr {
        mAddress: otIp6Address {
            mFields: otIp6Address__bindgen_ty_1 {
                m8: addr.ip().octets(),
            },
        },
        mPort: addr.port(),
    }
}
