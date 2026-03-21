use async_graphql::SimpleObject;
use mas_matrix::HomeserverConnection;

#[derive(SimpleObject)]
pub struct MatrixUser {
    /// The Matrix ID of the user.
    mxid: String,

    /// The display name of the user, if any.
    display_name: Option<String>,

    /// The avatar URL of the user, if any.
    avatar_url: Option<String>,

    /// Whether the user is deactivated on the homeserver.
    deactivated: bool,
}

impl MatrixUser {
    pub(crate) async fn load<C: HomeserverConnection + ?Sized>(
        conn: &C,
        user: &str,
    ) -> Result<MatrixUser, anyhow::Error> {
        let info = conn.query_user(user).await?;

        let mxid = conn.mxid(user);

        Ok(MatrixUser {
            mxid,
            display_name: info.displayname,
            avatar_url: info.avatar_url,
            deactivated: info.deactivated,
        })
    }
}
