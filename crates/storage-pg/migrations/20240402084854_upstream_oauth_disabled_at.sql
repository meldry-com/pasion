-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.


-- Adds a `disabled_at` column to the `upstream_oauth_providers` table, to soft-delete providers.
ALTER TABLE "upstream_oauth_providers"
  ADD COLUMN "disabled_at" TIMESTAMP WITH TIME ZONE;
