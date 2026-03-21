-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- This adds a `last_active_at` timestamp and a `last_active_ip` column
-- to the `oauth2_sessions`, `user_sessions` and `compat_sessions` tables.
-- The timestamp is indexed with the `user_id`, as they are likely to be queried together.
ALTER TABLE "oauth2_sessions"
    ADD COLUMN "last_active_at" TIMESTAMP WITH TIME ZONE,
    ADD COLUMN "last_active_ip" INET;

CREATE INDEX "oauth2_sessions_user_id_last_active_at"
    ON "oauth2_sessions" ("user_id", "last_active_at");


ALTER TABLE "user_sessions"
    ADD COLUMN "last_active_at" TIMESTAMP WITH TIME ZONE,
    ADD COLUMN "last_active_ip" INET;

CREATE INDEX "user_sessions_user_id_last_active_at"
    ON "user_sessions" ("user_id", "last_active_at");


ALTER TABLE "compat_sessions"
    ADD COLUMN "last_active_at" TIMESTAMP WITH TIME ZONE,
    ADD COLUMN "last_active_ip" INET;

CREATE INDEX "compat_sessions_user_id_last_active_at"
    ON "compat_sessions" ("user_id", "last_active_at");