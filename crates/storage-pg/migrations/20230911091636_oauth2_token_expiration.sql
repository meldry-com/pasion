-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- This makes the `expires_at` column nullable on the `oauth2_access_tokens`.
-- This is to allow permanent tokens to be created via the admin API.
ALTER TABLE oauth2_access_tokens
    ALTER COLUMN expires_at DROP NOT NULL;

