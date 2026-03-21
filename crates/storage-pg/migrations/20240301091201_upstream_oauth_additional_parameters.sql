-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- Adds a column to the upstream_oauth_providers table to store additional parameters to be sent to the OAuth provider.
-- Parameters are stored as [["key", "value"], ["key", "value"], ...] in a JSONB column to keep key ordering.
ALTER TABLE upstream_oauth_providers 
    ADD COLUMN additional_parameters JSONB;
