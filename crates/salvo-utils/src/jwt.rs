// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use mas_jose::jwt::Jwt;
use salvo::prelude::*;

pub struct JwtResponse<T>(pub Jwt<'static, T>);

impl<T: Send> Scribe for JwtResponse<T> {
    fn render(self, res: &mut Response) {
        res.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/jwt"),
        );
        res.render(Text::Plain(self.0.into_string()));
    }
}
