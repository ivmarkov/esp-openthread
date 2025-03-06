//! An implementation of an OpenThread Driver for `embassy-net` using the `embassy-net-driver-channel` crate.

use core::{net::Ipv6Addr, pin::pin};

use embassy_futures::select::{select3, Either3};
use embassy_net_driver_channel::{driver::HardwareAddress, RxRunner, StateRunner, TxRunner};

use rand_core::RngCore;

use crate::{OpenThread, OperationalDataset, OtError, OtResources, Radio};

pub use embassy_net_driver_channel::{
    driver::LinkState as EnetLinkState, Device as EnetDriver, State as EnetDriverState,
};

/// Create a new OpenThread driver for `embassy-net`, by internally instantiating the `openthread` API types
/// and combining them with the `embassy-net-driver-channel` runner types.
///
/// The driver is communicating with `embassy-net` and `smoltcp` using naked Ipv6 frames, without
/// any hardware address and any additional framing (like e.g. Ethernet) attached.
///
/// All details about the network stack (i.e. that it is based on IEEE 802.15.4) are abstracted away and
/// invisible to `embassy-net` and `smoltcp`.
///
/// Arguments:
/// - `rng`: A mutable reference to a random number generator.
/// - `state`: A mutable reference to the `embassy-net-driver-channel` state resources.
/// - `resources`: A mutable reference to the `openthread` resources.
///
/// Returns:
/// - In case there were no errors related to initializing the OpenThread library, a tuple containing:
///   - The OpenThread controller
///   - The `embassy-net-driver-channel` state runner (note: this is not really a "runner" per se, but more of a controller to switch on/off the Driver)
///   - A runner that runs both the `openthread` stack as well as the `embassy-net` driver stack
///   - The `embassy-net` Driver for OpenThread
pub fn new<'d, const MTU: usize, const N_RX: usize, const N_TX: usize>(
    rng: &'d mut dyn RngCore,
    state: &'d mut EnetDriverState<MTU, N_RX, N_TX>,
    resources: &'d mut OtResources,
) -> Result<(EnetController<'d>, EnetRunner<'d, MTU>, EnetDriver<'d, MTU>), OtError> {
    let ot = OpenThread::new(rng, resources)?;

    let (runner, device) = embassy_net_driver_channel::new(state, HardwareAddress::Ip);

    let (state_runner, rx_runner, tx_runner) = runner.split();

    Ok((
        EnetController {
            ot,
            state: state_runner,
        },
        EnetRunner {
            ot,
            rx_runner,
            tx_runner,
        },
        device,
    ))
}

pub struct EnetController<'a> {
    ot: OpenThread<'a>,
    state: StateRunner<'a>,
}

impl EnetController<'_> {
    pub fn set_link_state(&mut self, state: EnetLinkState) {
        self.state.set_link_state(state);
    }

    /// Set a new active dataset in the OpenThread stack.
    ///
    /// Arguments:
    /// - `dataset`: A reference to the new dataset to be set.
    pub fn set_dataset(&self, dataset: &OperationalDataset<'_>) -> Result<(), OtError> {
        self.ot.set_dataset(dataset)
    }

    /// Brings the OpenThread IPv6 interface up or down.
    pub fn enable_ipv6(&self, enable: bool) -> Result<(), OtError> {
        self.ot.enable_ipv6(enable)
    }

    /// This function starts/stops the Thread protocol operation.
    ///
    /// TODO: The interface must be up when calling this function.
    pub fn enable_thread(&self, enable: bool) -> Result<(), OtError> {
        self.ot.enable_thread(enable)
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
        self.ot.ipv6_addrs(buf)
    }

    /// Wait for the OpenThread stack to change its state.
    pub async fn wait_changed(&self) {
        self.ot.wait_changed().await
    }
}

/// A runner that runs both the `openthread` stack runner as well as the `embassy-net-driver-channel` runner.
///
/// The runner also does the Ipv6 packets' ingress/egress to/from the `embassy-net` stack and to/from `openthread`.
pub struct EnetRunner<'d, const MTU: usize> {
    ot: OpenThread<'d>,
    rx_runner: RxRunner<'d, MTU>,
    tx_runner: TxRunner<'d, MTU>,
}

impl<const MTU: usize> EnetRunner<'_, MTU> {
    /// Run the OpenThread stack and the `embassy-net-driver-channel` runner.
    ///
    /// Arguments:
    /// - `radio`: The radio to be used by the OpenThread stack.
    pub async fn run<R>(&mut self, mut radio: R) -> !
    where
        R: Radio,
    {
        let mut rx = pin!(Self::run_rx(&self.ot, &mut self.rx_runner));
        let mut tx = pin!(Self::run_tx(&self.ot, &mut self.tx_runner));
        let mut ot = pin!(Self::run_ot(&self.ot, &mut radio));

        match select3(&mut rx, &mut tx, &mut ot).await {
            Either3::First(r) | Either3::Second(r) | Either3::Third(r) => r,
        }
    }

    async fn run_rx(rx: &OpenThread<'_>, rx_runner: &mut RxRunner<'_, MTU>) -> ! {
        loop {
            rx.wait_rx_available().await.unwrap();

            let buf = rx_runner.rx_buf().await;

            let len = rx.rx(buf).await.unwrap();

            rx_runner.rx_done(len);
        }
    }

    async fn run_tx(tx: &OpenThread<'_>, tx_runner: &mut TxRunner<'_, MTU>) -> ! {
        loop {
            let buf = tx_runner.tx_buf().await;

            tx.tx(buf).unwrap();

            tx_runner.tx_done();
        }
    }

    async fn run_ot<R>(runner: &OpenThread<'_>, radio: R) -> !
    where
        R: Radio,
    {
        runner.run(radio).await
    }
}
