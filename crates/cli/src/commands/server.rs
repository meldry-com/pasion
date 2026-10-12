use std::{process::ExitCode, sync::Arc};

use anyhow::Context;
use clap::Parser;
use figment::Figment;
use itertools::Itertools;
use pasion_backend::{lifecycle::LifecycleManager, listener::server::Server};
use pasion_config::{AppConfig, ConfigurationSection};
use tracing::{info, info_span, warn};

#[allow(clippy::struct_excessive_bools)]
#[derive(Parser, Debug, Default)]
pub(super) struct Options {
    /// Do not apply pending database migrations on start
    #[arg(long)]
    no_migrate: bool,

    /// DEPRECATED: default is to apply pending migrations, use `--no-migrate`
    /// to disable
    #[arg(long, hide = true)]
    migrate: bool,

    /// Do not start the task worker
    #[arg(long)]
    no_worker: bool,

    /// Do not sync the configuration with the database
    #[arg(long)]
    no_sync: bool,
}

impl Options {
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        let span = info_span!("cli.run.init").entered();
        let mut shutdown = LifecycleManager::new()?;
        let config = AppConfig::extract(figment).map_err(anyhow::Error::from_boxed)?;
        let listeners_config = config.http.listeners;
        if self.migrate {
            warn!("The --migrate flag is deprecated; migrations run by default.");
        }
        let embedded = pasion_backend::PasionServer::initialize_with_runtime(
            figment,
            pasion_backend::ServerOptions {
                no_migrate: self.no_migrate,
                no_worker: self.no_worker,
                no_sync: self.no_sync,
            },
            shutdown.soft_shutdown_token(),
            shutdown.task_tracker().clone(),
        )
        .await?;
        let state = embedded.state().clone();
        shutdown.register_reloadable(&state.templates);
        shutdown.register_reloadable(&state.activity_tracker);

        let mut fd_manager = listenfd::ListenFd::from_env();

        let mut servers = Vec::new();
        let mut listening_announcements = Vec::with_capacity(listeners_config.len());

        for config in listeners_config {
            let listener_name = config.name.clone();
            let listener_label = listener_name.as_deref().unwrap_or("<unnamed>");

            // Let's first grab all the listeners
            let listeners = pasion_backend::server::build_listeners(&mut fd_manager, &config.binds)
                .with_context(|| format!("could not initialize listener `{listener_label}`"))?;

            // Load the TLS config
            let tls_config = if let Some(tls_config) = config.tls.as_ref() {
                let tls_config = pasion_backend::server::build_tls_server_config(tls_config)?;
                Some(Arc::new(tls_config))
            } else {
                None
            };

            // and build the router
            let router = pasion_backend::server::build_router(
                state.clone(),
                &config.resources,
                config.prefix.as_deref(),
                config.name.as_deref(),
            );

            // Create a Salvo service and hyper handler from the router
            let salvo_service = salvo::Service::new(router);
            let hyper_handler = salvo_service.hyper_handler(
                salvo::conn::SocketAddr::Unknown,
                salvo::conn::SocketAddr::Unknown,
                http::uri::Scheme::HTTP,
                None,
                salvo::conn::ConnCtrl::new(),
                None,
            );
            let handler = move |req: hyper::Request<hyper::body::Incoming>| {
                use hyper::service::Service;
                hyper_handler.call(req)
            };

            // Only announce listeners after every bind has succeeded.
            let proto = if config.tls.is_some() {
                "https"
            } else {
                "http"
            };
            let prefix = config.prefix.clone().unwrap_or_default();
            let addresses = listeners
                .iter()
                .map(|listener| {
                    if let Ok(addr) = listener.local_addr() {
                        format!("{proto}://{addr:?}{prefix}")
                    } else {
                        warn!(
                            "Could not get local address for listener, something might be wrong!"
                        );
                        format!("{proto}://???{prefix}")
                    }
                })
                .join(", ");
            let resources = format!("{:?}", config.resources);
            let announcement = if config.proxy_protocol {
                format!("Listening on {addresses} with resources {resources} (with Proxy Protocol)")
            } else {
                format!("Listening on {addresses} with resources {resources}")
            };
            listening_announcements.push((listener_name, announcement));

            servers.extend(listeners.into_iter().map(move |listener| {
                let mut server = Server::new(listener, handler.clone());
                if let Some(tls_config) = &tls_config {
                    server = server.with_tls(tls_config.clone());
                }
                if config.proxy_protocol {
                    server = server.with_proxy();
                }
                server
            }));
        }

        for (listener_name, announcement) in listening_announcements {
            if let Some(listener_name) = listener_name.as_deref() {
                info!(listener = listener_name, "{announcement}");
            } else {
                info!("{announcement}");
            }
        }

        span.exit();

        shutdown
            .task_tracker()
            .spawn(pasion_backend::listener::server::run_servers(
                servers,
                shutdown.soft_shutdown_token(),
                shutdown.hard_shutdown_token(),
            ));

        let exit_code = shutdown.run().await;

        Ok(exit_code)
    }
}
