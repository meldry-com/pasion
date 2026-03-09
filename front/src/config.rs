/// Application configuration, loaded from window.APP_CONFIG or defaults.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AppConfig {
    pub root: String,
    pub graphql_endpoint: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            root: "/".to_string(),
            graphql_endpoint: "/graphql".to_string(),
        }
    }
}

/// Get the app configuration.
/// In WASM, this reads from window.APP_CONFIG. Otherwise uses defaults.
pub fn get_config() -> AppConfig {
    #[cfg(target_arch = "wasm32")]
    {
        use web_sys::window;

        if let Some(win) = window() {
            if let Ok(val) = js_sys::Reflect::get(&win, &"APP_CONFIG".into()) {
                if !val.is_undefined() && !val.is_null() {
                    let root = js_sys::Reflect::get(&val, &"root".into())
                        .ok()
                        .and_then(|v| v.as_string())
                        .unwrap_or_else(|| "/".to_string());
                    let graphql_endpoint =
                        js_sys::Reflect::get(&val, &"graphqlEndpoint".into())
                            .ok()
                            .and_then(|v| v.as_string())
                            .unwrap_or_else(|| "/graphql".to_string());
                    return AppConfig {
                        root,
                        graphql_endpoint,
                    };
                }
            }
        }
    }

    AppConfig::default()
}

/// Resolve the full GraphQL URL based on the current location.
pub fn graphql_url() -> String {
    let config = get_config();

    #[cfg(target_arch = "wasm32")]
    {
        if let Some(win) = web_sys::window() {
            if let Ok(location) = win.location().href() {
                if let Ok(base) = web_sys::Url::new_with_base(&config.graphql_endpoint, &location) {
                    return base.href();
                }
            }
        }
    }

    config.graphql_endpoint
}
