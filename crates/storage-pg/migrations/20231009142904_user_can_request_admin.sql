-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- Adds a `can_request_admin` column to the `users` table
ALTER TABLE users
    ADD COLUMN can_request_admin BOOLEAN NOT NULL DEFAULT FALSE;