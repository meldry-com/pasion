-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- Adds human readable branding information to the upstream_oauth_providers table
ALTER TABLE upstream_oauth_providers
    ADD COLUMN human_name text,
    ADD COLUMN brand_name text;
