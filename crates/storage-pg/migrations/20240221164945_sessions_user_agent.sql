-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- Adds user agent columns to oauth and compat sessions tables
ALTER TABLE oauth2_sessions ADD COLUMN user_agent TEXT;
ALTER TABLE compat_sessions ADD COLUMN user_agent TEXT;
