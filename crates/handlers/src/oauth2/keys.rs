use mas_jose::jwk::PublicJsonWebKeySet;
use mas_keystore::Keystore;
use salvo::prelude::*;

#[handler]
#[tracing::instrument(name = "handlers.oauth2.keys.get", skip_all)]
pub async fn get(depot: &Depot) -> Json<PublicJsonWebKeySet> {
    let key_store = depot
        .get::<Keystore>("keystore")
        .expect("Keystore not found in depot");
    let jwks = key_store.public_jwks();
    Json(jwks)
}
