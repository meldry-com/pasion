-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- This adds a flag to the OAuth 2.0 clients to indicate whether they are static (i.e. defined in config) or not.
ALTER TABLE oauth2_clients
    ADD COLUMN is_static
        BOOLEAN NOT NULL
        DEFAULT FALSE;