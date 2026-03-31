use std::{collections::HashMap, fs::File, io::BufReader, str::FromStr};

use camino::{Utf8Path, Utf8PathBuf};
use icu_experimental::relativetime::{
    RelativeTimeFormatter, RelativeTimeFormatterOptions, options::Numeric,
};
use icu_locid::{Locale, ParserError};
use icu_locid_transform::fallback::{
    LocaleFallbackPriority, LocaleFallbackSupplement, LocaleFallbacker, LocaleFallbackerWithConfig,
};
use icu_plurals::{PluralRules, PluralsError};
use icu_provider::{
    DataError, DataErrorKind, DataKey, DataLocale, DataRequest, DataRequestMetadata, data_key,
    fallback::LocaleFallbackConfig,
};
use icu_provider_adapters::fallback::LocaleFallbackProvider;
use thiserror::Error;
use writeable::Writeable;

use crate::{sprintf::Message, translations::TranslationTree};

/// Fake data key for errors
const DATA_KEY: DataKey = data_key!("pasion/translations@1");

const FALLBACKER: LocaleFallbackerWithConfig<'static> = LocaleFallbacker::new().for_config({
    let mut config = LocaleFallbackConfig::const_default();
    config.priority = LocaleFallbackPriority::Collation;
    config.fallback_supplement = Some(LocaleFallbackSupplement::Collation);
    config
});

/// Construct a [`DataRequest`] for the given locale
pub fn data_request_for_locale(locale: &DataLocale) -> DataRequest<'_> {
    let mut metadata = DataRequestMetadata::default();
    metadata.silent = true;
    DataRequest { locale, metadata }
}

/// Error type for loading translations
#[derive(Debug, Error)]
pub enum LoadError {
    #[error("Failed to load translation directory {path:?}")]
    ReadDir {
        path: Utf8PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to read translation file {path:?}")]
    ReadFile {
        path: Utf8PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to deserialize translation file {path:?}")]
    Deserialize {
        path: Utf8PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("Invalid locale for file {path:?}")]
    InvalidLocale {
        path: Utf8PathBuf,
        #[source]
        source: ParserError,
    },

    #[error("Invalid file name {path:?}")]
    InvalidFileName { path: Utf8PathBuf },
}

/// A translator for a set of translations.
#[derive(Debug)]
pub struct Translator {
    /// Locale-keyed translation data, stored in insertion order is irrelevant.
    locale_trees: HashMap<DataLocale, TranslationTree>,
    /// Fallback-aware plural-rule provider.
    plural_provider: LocaleFallbackProvider<icu_plurals::provider::Baked>,
    /// The ultimate fallback locale when the chain hits `und`.
    default_locale: DataLocale,
}

impl Translator {
    /// Create a new translator from a set of translations.
    #[must_use]
    pub fn new(translations: HashMap<DataLocale, TranslationTree>) -> Self {
        let owned_fallbacker = LocaleFallbacker::new().static_to_owned();
        let plural_provider = LocaleFallbackProvider::new_with_fallbacker(
            icu_plurals::provider::Baked,
            owned_fallbacker,
        );

        Self {
            locale_trees: translations,
            plural_provider,
            // TODO: make this configurable
            default_locale: icu_locid::locale!("en").into(),
        }
    }

    /// Load a set of translations from a directory.
    ///
    /// The directory should contain one JSON file per locale, with the locale
    /// being the filename without the extension, e.g. `en-US.json`.
    ///
    /// # Parameters
    ///
    /// * `path` - The path to load from.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be read, or if any of the files
    /// cannot be parsed.
    pub fn load_from_path(path: &Utf8Path) -> Result<Self, LoadError> {
        let entries = path.read_dir_utf8().map_err(|source| LoadError::ReadDir {
            path: path.to_owned(),
            source,
        })?;

        let mut collected: HashMap<DataLocale, TranslationTree> = HashMap::new();

        for dir_result in entries {
            let dir_entry = dir_result.map_err(|source| LoadError::ReadDir {
                path: path.to_owned(),
                source,
            })?;

            let file_path = dir_entry.into_path();

            let stem = file_path
                .file_stem()
                .ok_or_else(|| LoadError::InvalidFileName {
                    path: file_path.clone(),
                })?;

            let locale = Locale::from_str(stem).map_err(|source| LoadError::InvalidLocale {
                path: file_path.clone(),
                source,
            })?;

            let handle = File::open(&file_path).map_err(|source| LoadError::ReadFile {
                path: file_path.clone(),
                source,
            })?;

            let tree: TranslationTree =
                serde_json::from_reader(BufReader::new(handle)).map_err(|source| {
                    LoadError::Deserialize {
                        path: file_path.clone(),
                        source,
                    }
                })?;

            collected.insert(locale.into(), tree);
        }

        Ok(Self::new(collected))
    }

    /// Resolve a locale to its translation tree, if present.
    fn tree_for(&self, locale: &DataLocale) -> Option<&TranslationTree> {
        self.locale_trees.get(locale)
    }

    /// Build a `DataError` for a missing locale or key.
    fn missing_locale_error(&self, locale: &DataLocale) -> DataError {
        DataErrorKind::MissingLocale.with_req(DATA_KEY, data_request_for_locale(locale))
    }

    fn missing_key_error(&self, locale: &DataLocale) -> DataError {
        DataErrorKind::MissingDataKey.with_req(DATA_KEY, data_request_for_locale(locale))
    }

    /// Get a message from the tree by key, with locale fallback.
    ///
    /// Returns the message and the locale it was found in.
    /// If the message is not found, returns `None`.
    ///
    /// # Parameters
    ///
    /// * `locale` - The locale to use.
    /// * `key` - The key to look up, which is a dot-separated path.
    #[must_use]
    pub fn message_with_fallback(
        &self,
        locale: DataLocale,
        key: &str,
    ) -> Option<(&Message, DataLocale)> {
        // Direct hit before entering the fallback loop.
        if let Ok(msg) = self.message(&locale, key) {
            return Some((msg, locale));
        }

        let mut chain = FALLBACKER.fallback_for(locale);

        loop {
            let candidate = chain.get();

            if let Ok(msg) = self.message(candidate, key) {
                return Some((msg, chain.take()));
            }

            if candidate.is_und() {
                // Last resort: the configured default locale.
                let msg = self.message(&self.default_locale, key).ok()?;
                return Some((msg, self.default_locale.clone()));
            }

            chain.step();
        }
    }

    /// Get a message from the tree by key.
    ///
    /// # Parameters
    ///
    /// * `locale` - The locale to use.
    /// * `key` - The key to look up, which is a dot-separated path.
    ///
    /// # Errors
    ///
    /// Returns an error if the requested locale is not found, or if the
    /// requested key is not found.
    pub fn message(&self, locale: &DataLocale, key: &str) -> Result<&Message, DataError> {
        let tree = self
            .tree_for(locale)
            .ok_or_else(|| self.missing_locale_error(locale))?;

        tree.message(key)
            .ok_or_else(|| self.missing_key_error(locale))
    }

    /// Get a plural message from the tree by key, with locale fallback.
    ///
    /// Returns the message and the locale it was found in.
    /// If the message is not found, returns `None`.
    ///
    /// # Parameters
    ///
    /// * `locale` - The locale to use.
    /// * `key` - The key to look up, which is a dot-separated path.
    /// * `count` - The count to use for pluralization.
    #[must_use]
    pub fn plural_with_fallback(
        &self,
        locale: DataLocale,
        key: &str,
        count: usize,
    ) -> Option<(&Message, DataLocale)> {
        let mut chain = FALLBACKER.fallback_for(locale);

        loop {
            let candidate = chain.get();

            if let Ok(msg) = self.plural(candidate, key, count) {
                return Some((msg, chain.take()));
            }

            // Stop if we hit the `und` locale
            if candidate.is_und() {
                return None;
            }

            chain.step();
        }
    }

    /// Get a plural message from the tree by key.
    ///
    /// # Parameters
    ///
    /// * `locale` - The locale to use.
    /// * `key` - The key to look up, which is a dot-separated path.
    /// * `count` - The count to use for pluralization.
    ///
    /// # Errors
    ///
    /// Returns an error if the requested locale is not found, or if the
    /// requested key is not found.
    pub fn plural(
        &self,
        locale: &DataLocale,
        key: &str,
        count: usize,
    ) -> Result<&Message, PluralsError> {
        let rules = PluralRules::try_new_cardinal_unstable(&self.plural_provider, locale)?;
        let category = rules.category_for(count);

        let tree = self
            .tree_for(locale)
            .ok_or_else(|| self.missing_locale_error(locale))?;

        tree.pluralize(key, category)
            .ok_or_else(|| self.missing_key_error(locale).into())
    }

    /// Format a relative date
    ///
    /// # Parameters
    ///
    /// * `locale` - The locale to use.
    /// * `days` - The number of days to format, where 0 = today, 1 = tomorrow,
    ///   -1 = yesterday, etc.
    ///
    /// # Errors
    ///
    /// Returns an error if the requested locale is not found.
    pub fn relative_date(
        &self,
        locale: &DataLocale,
        days: i64,
    ) -> Result<String, icu_experimental::relativetime::RelativeTimeError> {
        // TODO: this is not using the fallbacker
        let opts = RelativeTimeFormatterOptions {
            numeric: Numeric::Auto,
        };
        let formatter = RelativeTimeFormatter::try_new_long_day(locale, opts)?;
        let writeable = formatter.format(days.into());
        Ok(writeable.write_to_string().into_owned())
    }

    /// Format time
    ///
    /// # Parameters
    ///
    /// * `locale` - The locale to use.
    /// * `time` - The time to format.
    ///
    /// # Errors
    ///
    /// Returns an error if the requested locale is not found.
    pub fn short_time<T: icu_datetime::input::IsoTimeInput>(
        &self,
        locale: &DataLocale,
        time: &T,
    ) -> Result<String, icu_datetime::DateTimeError> {
        // TODO: this is not using the fallbacker
        let time_length = icu_datetime::options::length::Time::Short;
        let fmt = icu_datetime::TimeFormatter::try_new_with_length(locale, time_length)?;
        Ok(fmt.format_to_string(time))
    }

    /// Get a list of available locales.
    #[must_use]
    pub fn available_locales(&self) -> Vec<DataLocale> {
        self.locale_trees.keys().cloned().collect()
    }

    /// Check if a locale is available.
    #[must_use]
    pub fn has_locale(&self, locale: &DataLocale) -> bool {
        self.locale_trees.contains_key(locale)
    }

    /// Choose the best available locale from a list of candidates.
    #[must_use]
    pub fn choose_locale(&self, iter: impl Iterator<Item = DataLocale>) -> DataLocale {
        for candidate in iter {
            // Exact match?
            if self.has_locale(&candidate) {
                return candidate;
            }

            // Walk the fallback chain for this candidate.
            let mut chain = FALLBACKER.fallback_for(candidate);
            loop {
                let current = chain.get();
                if current.is_und() {
                    break;
                }

                if self.has_locale(current) {
                    return chain.take();
                }

                chain.step();
            }
        }

        // Nothing matched; return the default.
        self.default_locale.clone()
    }
}

#[cfg(test)]
mod tests {
    use camino::Utf8PathBuf;
    use icu_locid::locale;

    use crate::{sprintf::arg_list, translator::Translator};

    fn translator() -> Translator {
        let root: Utf8PathBuf = env!("CARGO_MANIFEST_DIR").parse().unwrap();
        let test_data = root.join("test_data");
        Translator::load_from_path(&test_data).unwrap()
    }

    #[test]
    fn test_message() {
        let translator = translator();

        let message = translator.message(&locale!("en").into(), "hello").unwrap();
        let formatted = message.format(&arg_list!()).unwrap();
        assert_eq!(formatted, "Hello!");

        let message = translator.message(&locale!("fr").into(), "hello").unwrap();
        let formatted = message.format(&arg_list!()).unwrap();
        assert_eq!(formatted, "Bonjour !");

        let message = translator
            .message(&locale!("en-US").into(), "hello")
            .unwrap();
        let formatted = message.format(&arg_list!()).unwrap();
        assert_eq!(formatted, "Hey!");

        // Try the fallback chain
        let result = translator.message(&locale!("en-US").into(), "goodbye");
        assert!(result.is_err());

        let (message, locale) = translator
            .message_with_fallback(locale!("en-US").into(), "goodbye")
            .unwrap();
        let formatted = message.format(&arg_list!()).unwrap();
        assert_eq!(formatted, "Goodbye!");
        assert_eq!(locale, locale!("en").into());
    }

    #[test]
    fn test_plurals() {
        let translator = translator();

        let message = translator
            .plural(&locale!("en").into(), "active_sessions", 1)
            .unwrap();
        let formatted = message.format(&arg_list!(count = 1)).unwrap();
        assert_eq!(formatted, "1 active session.");

        let message = translator
            .plural(&locale!("en").into(), "active_sessions", 2)
            .unwrap();
        let formatted = message.format(&arg_list!(count = 2)).unwrap();
        assert_eq!(formatted, "2 active sessions.");

        // In english, zero is plural
        let message = translator
            .plural(&locale!("en").into(), "active_sessions", 0)
            .unwrap();
        let formatted = message.format(&arg_list!(count = 0)).unwrap();
        assert_eq!(formatted, "0 active sessions.");

        let message = translator
            .plural(&locale!("fr").into(), "active_sessions", 1)
            .unwrap();
        let formatted = message.format(&arg_list!(count = 1)).unwrap();
        assert_eq!(formatted, "1 session active.");

        let message = translator
            .plural(&locale!("fr").into(), "active_sessions", 2)
            .unwrap();
        let formatted = message.format(&arg_list!(count = 2)).unwrap();
        assert_eq!(formatted, "2 sessions actives.");

        // In french, zero is singular
        let message = translator
            .plural(&locale!("fr").into(), "active_sessions", 0)
            .unwrap();
        let formatted = message.format(&arg_list!(count = 0)).unwrap();
        assert_eq!(formatted, "0 session active.");

        // Try the fallback chain
        let result = translator.plural(&locale!("en-US").into(), "active_sessions", 1);
        assert!(result.is_err());

        let (message, locale) = translator
            .plural_with_fallback(locale!("en-US").into(), "active_sessions", 1)
            .unwrap();
        let formatted = message.format(&arg_list!(count = 1)).unwrap();
        assert_eq!(formatted, "1 active session.");
        assert_eq!(locale, locale!("en").into());
    }
}
