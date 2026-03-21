-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.


-- Adds an index on the last_active_at column of the sessions tables
CREATE INDEX "compat_sessions_last_active_at_idx" ON "compat_sessions" ("last_active_at");
CREATE INDEX "oauth2_sessions_last_active_at_idx" ON "oauth2_sessions" ("last_active_at");
CREATE INDEX "user_sessions_last_active_at_idx" ON "user_sessions" ("last_active_at");
