-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- This adds a user_agent column to the user_sessions table
ALTER TABLE user_sessions ADD COLUMN user_agent TEXT;