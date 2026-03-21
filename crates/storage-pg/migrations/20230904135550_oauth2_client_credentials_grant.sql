-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- This makes the user_id in the oauth2_sessions nullable, which allows us to create user-less sessions
ALTER TABLE oauth2_sessions
    ALTER COLUMN user_id DROP NOT NULL;

-- This adds a column to the oauth2_clients to allow them to use the client_credentials flow
ALTER TABLE oauth2_clients
    ADD COLUMN grant_type_client_credentials boolean NOT NULL DEFAULT false;