use figment::{Figment, providers::Format};
use rand_core::SeedableRng;
use serde_saphyr::figment::Yaml;

use crate::{ConfigurationSection, RootConfig};

#[tokio::test]
async fn generated_config_survives_yaml_export_and_runtime_reload() {
    // Exercise the same generation, dump and loading APIs as the CLI. This
    // includes multiline secret keys, tagged enum settings and URL scalars.
    let mut rng = rand_chacha::ChaChaRng::from_seed([17; 32]);
    let generated = RootConfig::generate(&mut rng).await.unwrap();
    let yaml = serde_saphyr::to_string(&generated).unwrap();
    let figment = Figment::from(Yaml::string(&yaml));
    let reloaded = RootConfig::extract(&figment).unwrap();
    assert_eq!(
        serde_json::to_value(&reloaded).unwrap(),
        serde_json::to_value(&generated).unwrap(),
        "YAML export must preserve configuration values on runtime reload"
    );
}
