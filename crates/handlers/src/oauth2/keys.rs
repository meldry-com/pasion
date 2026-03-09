// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

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
