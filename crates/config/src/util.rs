use figment::Figment;
use serde::de::DeserializeOwned;

/// Trait implemented by all configuration section to help loading specific part
/// of the config and generate the sample config.
pub trait ConfigurationSection: Sized + DeserializeOwned {
    /// Specify where this section should live relative to the root.
    /// Use `""` for root-level configuration sections.
    const PATH: &'static str;

    /// Validate the configuration section
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid
    fn validate(
        &self,
        _figment: &Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        Ok(())
    }

    /// Extract configuration from a Figment instance.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration could not be loaded
    fn extract(
        figment: &Figment,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync + 'static>> {
        let this: Self = if Self::PATH.is_empty() {
            figment.extract()?
        } else {
            figment.extract_inner(Self::PATH)?
        };
        this.validate(figment)?;
        Ok(this)
    }
}

/// Extension trait for [`ConfigurationSection`] to allow extracting the
/// configuration section from a [`Figment`] or return the default value if the
/// section is not present.
pub trait ConfigurationSectionExt: ConfigurationSection + Default {
    /// Extract the configuration section from the given [`Figment`], or return
    /// the default value if the section is not present.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration section is invalid.
    fn extract_or_default(
        figment: &Figment,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync + 'static>> {
        if !Self::PATH.is_empty() && !figment.contains(Self::PATH) {
            return Ok(Self::default());
        }

        let this: Self = if Self::PATH.is_empty() {
            figment.extract()?
        } else {
            figment.extract_inner(Self::PATH)?
        };
        this.validate(figment)?;
        Ok(this)
    }
}

impl<T: ConfigurationSection + Default> ConfigurationSectionExt for T {}
