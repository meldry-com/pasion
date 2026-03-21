-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- Adds various endpoint overrides for oauth providers
ALTER TABLE upstream_oauth_providers
    ADD COLUMN "jwks_uri_override" TEXT,
    ADD COLUMN "authorization_endpoint_override" TEXT,
    ADD COLUMN "token_endpoint_override" TEXT,
    ADD COLUMN "discovery_mode" TEXT NOT NULL DEFAULT 'oidc',
    ADD COLUMN "pkce_mode" TEXT NOT NULL DEFAULT 'auto';
