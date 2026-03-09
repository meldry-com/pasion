-- no-transaction
-- Copyright 2024, 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Validate the FK constraint that was added in the previous migration
ALTER TABLE queue_jobs
  VALIDATE CONSTRAINT queue_jobs_next_attempt_id_fkey;
