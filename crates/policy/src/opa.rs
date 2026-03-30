//! OPA (Open Policy Agent) WASM policy provider.
//!
//! This module implements policy evaluation using compiled OPA Rego policies
//! running as WebAssembly modules via the `opa-wasm` crate.

use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use opa_wasm::{
    Runtime,
    wasmtime::{Config, Engine, Module, OptLevel, Store},
};
use pasion_data::{PolicyData, Ulid};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::model::{
    AuthorizationGrantInput, ClientRegistrationInput, EmailInput, EvaluationResult, RegisterInput,
};
use crate::provider::{PolicyEvaluator, PolicyProviderFactory};
use crate::{Data, Entrypoints, EvaluationError, InstantiateError, LoadError};

struct DynamicData {
    version: Option<Ulid>,
    merged: serde_json::Value,
}

/// OPA WASM policy provider factory.
///
/// Loads and manages compiled OPA Rego policies (`.wasm` files) and creates
/// [`OpaEvaluator`] instances for per-request policy evaluation.
pub struct OpaProviderFactory {
    engine: Engine,
    module: Module,
    data: Data,
    dynamic_data: ArcSwap<DynamicData>,
    entrypoints: Entrypoints,
}

impl OpaProviderFactory {
    /// Load an OPA WASM policy from an async reader.
    ///
    /// # Errors
    ///
    /// Returns an error if the WASM module can't be loaded or compiled.
    #[tracing::instrument(name = "opa.load", skip(source))]
    pub async fn load(
        mut source: impl AsyncRead + std::marker::Unpin,
        data: Data,
        entrypoints: Entrypoints,
    ) -> Result<Self, LoadError> {
        let mut config = Config::default();
        config.async_support(true);
        config.cranelift_opt_level(OptLevel::SpeedAndSize);

        let engine = Engine::new(&config).map_err(LoadError::Engine)?;

        // Read and compile the module
        let mut buf = Vec::new();
        source.read_to_end(&mut buf).await?;
        // Compilation is CPU-bound, so spawn that in a blocking task
        let (engine, module) = tokio::task::spawn_blocking(move || {
            let module = Module::new(&engine, buf)?;
            anyhow::Ok((engine, module))
        })
        .await?
        .map_err(LoadError::Compilation)?;

        let merged = data.to_value().map_err(LoadError::InvalidData)?;
        let dynamic_data = ArcSwap::new(Arc::new(DynamicData {
            version: None,
            merged,
        }));

        let factory = Self {
            engine,
            module,
            data,
            dynamic_data,
            entrypoints,
        };

        // Try to instantiate a test instance
        factory
            .instantiate_internal()
            .await
            .map_err(LoadError::Instantiate)?;

        Ok(factory)
    }

    async fn instantiate_internal(&self) -> Result<OpaEvaluator, InstantiateError> {
        let data = self.dynamic_data.load();
        self.instantiate_with_data(&data.merged).await
    }

    async fn instantiate_with_data(
        &self,
        data: &serde_json::Value,
    ) -> Result<OpaEvaluator, InstantiateError> {
        let mut store = Store::new(&self.engine, ());
        let runtime = Runtime::new(&mut store, &self.module)
            .await
            .map_err(InstantiateError::Runtime)?;

        // Check that we have the required entrypoints
        let policy_entrypoints = runtime.entrypoints();

        for e in self.entrypoints.all() {
            if !policy_entrypoints.contains(e) {
                return Err(InstantiateError::MissingEntrypoint {
                    entrypoint: e.to_owned(),
                });
            }
        }

        let instance = runtime
            .with_data(&mut store, data)
            .await
            .map_err(InstantiateError::LoadData)?;

        Ok(OpaEvaluator {
            store,
            instance,
            entrypoints: self.entrypoints.clone(),
        })
    }
}

#[async_trait]
impl PolicyProviderFactory for OpaProviderFactory {
    async fn instantiate(&self) -> Result<Box<dyn PolicyEvaluator>, InstantiateError> {
        let evaluator = self.instantiate_internal().await?;
        Ok(Box::new(evaluator))
    }

    async fn set_dynamic_data(&self, dynamic_data: PolicyData) -> Result<bool, LoadError> {
        // Check if the version of the dynamic data we have is the same as the one we're
        // trying to set
        if self.dynamic_data.load().version == Some(dynamic_data.id) {
            // Don't do anything if the version is the same
            return Ok(false);
        }

        let static_data = self.data.to_value().map_err(LoadError::InvalidData)?;
        let merged =
            crate::merge_data(static_data, dynamic_data.data).map_err(LoadError::InvalidData)?;

        // Try to instantiate with the new data
        self.instantiate_with_data(&merged)
            .await
            .map_err(LoadError::Instantiate)?;

        // If instantiation succeeds, swap the data
        self.dynamic_data.store(Arc::new(DynamicData {
            version: Some(dynamic_data.id),
            merged,
        }));

        Ok(true)
    }
}

/// OPA WASM policy evaluator instance.
///
/// Created by [`OpaProviderFactory::instantiate`]. Each instance holds its own
/// WASM store and is intended for single-request use.
pub struct OpaEvaluator {
    store: Store<()>,
    instance: opa_wasm::Policy<opa_wasm::DefaultContext>,
    entrypoints: Entrypoints,
}

#[async_trait]
impl PolicyEvaluator for OpaEvaluator {
    async fn evaluate_email(
        &mut self,
        input: EmailInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        let [res]: [EvaluationResult; 1] = self
            .instance
            .evaluate(&mut self.store, &self.entrypoints.email, &input)
            .await?;
        Ok(res)
    }

    async fn evaluate_register(
        &mut self,
        input: RegisterInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        let [res]: [EvaluationResult; 1] = self
            .instance
            .evaluate(&mut self.store, &self.entrypoints.register, &input)
            .await?;
        Ok(res)
    }

    async fn evaluate_client_registration(
        &mut self,
        input: ClientRegistrationInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        let [res]: [EvaluationResult; 1] = self
            .instance
            .evaluate(
                &mut self.store,
                &self.entrypoints.client_registration,
                &input,
            )
            .await?;
        Ok(res)
    }

    async fn evaluate_authorization_grant(
        &mut self,
        input: AuthorizationGrantInput<'_>,
    ) -> Result<EvaluationResult, EvaluationError> {
        let [res]: [EvaluationResult; 1] = self
            .instance
            .evaluate(
                &mut self.store,
                &self.entrypoints.authorization_grant,
                &input,
            )
            .await?;
        Ok(res)
    }
}
