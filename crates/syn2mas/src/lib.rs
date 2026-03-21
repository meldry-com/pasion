mod mas_writer;
mod palpo_reader;

mod migration;
mod progress;
mod telemetry;

type RandomState = rustc_hash::FxBuildHasher;
type HashMap<K, V> = rustc_hash::FxHashMap<K, V>;

pub use self::{
    mas_writer::{MasWriter, checks::mas_pre_migration_checks, locking::LockedMasDatabase},
    migration::migrate,
    progress::{Progress, ProgressCounter, ProgressStage},
    palpo_reader::{
        PalpoReader,
        checks::{
            palpo_config_check, palpo_config_check_against_pasion_config, palpo_database_check,
        },
        config as palpo_config,
    },
};
