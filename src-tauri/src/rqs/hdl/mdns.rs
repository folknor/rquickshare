use mdns_sd::{ServiceDaemon, ServiceInfo};
use tokio::sync::broadcast::Receiver;
use tokio_util::sync::CancellationToken;

use crate::utils::{gen_mdns_endpoint_info, gen_mdns_name, DeviceType};
use crate::DEVICE_NAME;

const INNER_NAME: &str = "MDnsServer";

pub struct MDnsServer {
    daemon: ServiceDaemon,
    service_info: ServiceInfo,
    ble_receiver: Receiver<()>,
}

impl MDnsServer {
    pub fn new(
        endpoint_id: [u8; 4],
        service_port: u16,
        ble_receiver: Receiver<()>,
    ) -> Result<Self, anyhow::Error> {
        let service_info = Self::build_service(endpoint_id, service_port, DeviceType::Laptop)?;

        Ok(Self {
            daemon: ServiceDaemon::new()?,
            service_info,
            ble_receiver,
        })
    }

    pub async fn run(&mut self, ctk: CancellationToken) -> Result<(), anyhow::Error> {
        info!("{INNER_NAME}: service starting");
        let monitor = self.daemon.monitor()?;
        let ble_receiver = &mut self.ble_receiver;

        // Always register - this fork is always visible
        self.daemon.register(self.service_info.clone())?;

        loop {
            tokio::select! {
                _ = ctk.cancelled() => {
                    info!("{INNER_NAME}: tracker cancelled, breaking");
                    break;
                }
                r = monitor.recv_async() => {
                    match r {
                        Ok(_) => continue,
                        Err(err) => return Err(err.into()),
                    }
                },
                _ = ble_receiver.recv() => {
                    debug!("{INNER_NAME}: ble_receiver: got event");
                    // Android can sometimes not see the mDNS service if the service
                    // was running BEFORE Android started the Discovery phase for QuickShare.
                    // So resend a broadcast if there's an Android device sending.
                    self.daemon.register(self.service_info.clone())?;
                },
            }
        }

        // Unregister the mDNS service - we're shutting down
        let receiver = self.daemon.unregister(self.service_info.get_fullname())?;
        if let Ok(event) = receiver.recv() {
            info!("MDnsServer: service unregistered: {:?}", &event);
        }

        Ok(())
    }

    fn build_service(
        endpoint_id: [u8; 4],
        service_port: u16,
        device_type: DeviceType,
    ) -> Result<ServiceInfo, anyhow::Error> {
        // This `name` is going to be random every time RQS service restarts.
        // If that is not desired, derive host_name, etc. via some other means
        let name = gen_mdns_name(endpoint_id);
        let hostname = format!("{name}.local.");
        let device_name = DEVICE_NAME
            .read()
            .map_err(|e| anyhow::anyhow!("Failed to read device name: {e}"))?
            .clone();
        info!("Broadcasting with: device_name={device_name}, host_name={hostname}");
        let endpoint_info = gen_mdns_endpoint_info(device_type as u8, &device_name);

        let properties = [("n", endpoint_info)];
        let si = ServiceInfo::new(
            "_FC9F5ED42C8A._tcp.local.",
            &name,
            &hostname,
            "",
            service_port,
            &properties[..],
        )?
        .enable_addr_auto();

        Ok(si)
    }
}
