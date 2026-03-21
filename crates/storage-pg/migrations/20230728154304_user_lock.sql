-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- Add a new column in on the `users` to record when an account gets locked
ALTER TABLE "users"
    ADD COLUMN "locked_at"
        TIMESTAMP WITH TIME ZONE
        DEFAULT NULL;