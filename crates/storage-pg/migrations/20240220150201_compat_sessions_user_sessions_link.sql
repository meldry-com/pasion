-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- Adds an optional link between the compatibility sessions and the user sessions
ALTER TABLE compat_sessions
    ADD COLUMN user_session_id UUID
        REFERENCES user_sessions (user_session_id)
        ON DELETE SET NULL;
