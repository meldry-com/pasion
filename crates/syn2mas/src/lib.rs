mod mas_writer;
mod synapse_reader;

mod migration;
mod progress;
mod telemetry;

type RandomState = rustc_hash::FxBuildHasher;
type HashMap<K, V> = rustc_hash::FxHashMap<K, V>;

pub use self::{
    mas_writer::{MasWriter, checks::mas_pre_migration_checks, locking::LockedMasDatabase},
    migration::migrate,
    progress::{Progress, ProgressCounter, ProgressStage},
    synapse_reader::{
        SynapseReader,
        checks::{
            synapse_config_check, synapse_config_check_against_mas_config, synapse_database_check,
        },
        config as synapse_config,
    },
};
