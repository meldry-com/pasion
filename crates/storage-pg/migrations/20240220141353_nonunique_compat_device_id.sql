-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- Drops the unique constraint on the device_id column in the compat_sessions table
ALTER TABLE compat_sessions
    DROP CONSTRAINT compat_sessions_device_id_unique;
