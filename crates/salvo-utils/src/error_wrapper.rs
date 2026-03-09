// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use salvo::prelude::*;

use crate::InternalError;

/// A simple wrapper around an error that implements Salvo's [`Scribe`] trait.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ErrorWrapper<T>(#[from] pub T);

impl<T> Scribe for ErrorWrapper<T>
where
    T: std::error::Error + Send + Sync + 'static,
{
    fn render(self, res: &mut Response) {
        InternalError::from(self.0).render(res);
    }
}
