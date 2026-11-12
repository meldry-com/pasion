//! Device management scoped to the authenticated user, independent of
//! pagination.
use pasion_data::{
    BoxRepository, Clock, Pagination, RepositoryAccess, User,
    oauth2::{OAuth2SessionFilter, OAuth2SessionRepository},
    personal::{PersonalSessionFilter, PersonalSessionRepository},
    queue::{QueueJobRepositoryExt as _, SyncDevicesJob},
    user::UserRepository,
};
use salvo::{oapi::ToSchema, prelude::*};
use serde::Serialize;

use super::{
    DepotExt, RouteError, extract_bound_activity_tracker, extract_session_info, get_requester,
    make_clock, make_rng,
};

#[derive(Serialize, ToSchema)]
pub struct DeviceDetail {
    device_id: String,
    session_count: usize,
}

#[derive(Serialize, ToSchema)]
pub struct DeviceCollection {
    devices: Vec<DeviceDetail>,
}

fn add_session_devices(
    counts: &mut std::collections::BTreeMap<String, usize>,
    scope: &oauth2_types::scope::Scope,
) {
    let ids: std::collections::BTreeSet<_> = scope
        .iter()
        .filter_map(|token| {
            token
                .strip_prefix("urn:matrix:client:device:")
                .or_else(|| token.strip_prefix("urn:matrix:org.matrix.msc2967.client:device:"))
        })
        .filter(|id| !id.is_empty())
        .collect();
    for id in ids {
        *counts.entry(id.to_owned()).or_default() += 1;
    }
}

async fn list_devices(
    repo: &mut BoxRepository,
    user: &User,
) -> Result<Vec<DeviceDetail>, RouteError> {
    let mut counts = std::collections::BTreeMap::new();
    let mut pagination = Pagination::first(500);
    loop {
        let page = repo
            .oauth2_session()
            .list(
                OAuth2SessionFilter::new().for_user(user).active_only(),
                pagination,
            )
            .await?;
        for edge in page.edges {
            add_session_devices(&mut counts, &edge.node.scope);
            pagination = pagination.after(edge.cursor);
        }
        if !page.has_next_page {
            break;
        }
    }
    let mut pagination = Pagination::first(500);
    loop {
        let page = repo
            .personal_session()
            .list(
                PersonalSessionFilter::new()
                    .for_actor_user(user)
                    .active_only(),
                pagination,
            )
            .await?;
        for edge in page.edges {
            add_session_devices(&mut counts, &edge.node.0.scope);
            pagination = pagination.after(edge.cursor);
        }
        if !page.has_next_page {
            break;
        }
    }
    Ok(counts
        .into_iter()
        .map(|(device_id, session_count)| DeviceDetail {
            device_id,
            session_count,
        })
        .collect())
}

async fn device_session_count(
    repo: &mut BoxRepository,
    user: &User,
    device: &str,
) -> Result<usize, RouteError> {
    let oauth = repo
        .oauth2_session()
        .count(
            OAuth2SessionFilter::new()
                .for_user(user)
                .for_device(device)
                .active_only(),
        )
        .await?;
    let personal = repo
        .personal_session()
        .count(
            PersonalSessionFilter::new()
                .for_actor_user(user)
                .for_device(device)
                .active_only(),
        )
        .await?;
    Ok(oauth + personal)
}

#[endpoint]
pub async fn get_device(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<DeviceCollection>, RouteError> {
    let device_id: Option<String> = req.query("device_id");
    let clock = make_clock();
    let activity = extract_bound_activity_tracker(req, depot);
    let session = extract_session_info(req, depot);
    let (requester, mut repo) =
        get_requester(&clock, &activity, depot.repo().await?, &session).await?;
    let user = requester.user().ok_or(RouteError::Unauthorized)?;
    let devices = if let Some(device_id) = device_id {
        if device_id.is_empty() {
            return Err(RouteError::BadRequest("missing device_id".into()));
        }
        let session_count = device_session_count(&mut repo, user, &device_id).await?;
        if session_count == 0 {
            return Err(RouteError::NotFound);
        }
        vec![DeviceDetail {
            device_id,
            session_count,
        }]
    } else {
        list_devices(&mut repo, user).await?
    };
    repo.cancel().await?;
    Ok(Json(DeviceCollection { devices }))
}

async fn revoke_device(
    mut repo: BoxRepository,
    clock: &dyn Clock,
    user: &User,
    device: &str,
) -> Result<(), RouteError> {
    repo.user().acquire_lock_for_sync(user).await?;
    repo.oauth2_session()
        .finish_bulk(
            clock,
            OAuth2SessionFilter::new()
                .for_user(user)
                .for_device(device)
                .active_only(),
        )
        .await?;
    repo.personal_session()
        .revoke_bulk(
            clock,
            PersonalSessionFilter::new()
                .for_actor_user(user)
                .for_device(device)
                .active_only(),
        )
        .await?;
    repo.queue_job()
        .schedule_job(&mut make_rng(), clock, SyncDevicesJob::new(user))
        .await?;
    repo.save().await?;
    Ok(())
}

#[endpoint]
pub async fn delete_device(
    req: &mut Request,
    depot: &Depot,
) -> Result<Json<serde_json::Value>, RouteError> {
    let device: String = req
        .query("device_id")
        .filter(|id: &String| !id.is_empty())
        .ok_or_else(|| RouteError::BadRequest("missing device_id".into()))?;
    let clock = make_clock();
    let activity = extract_bound_activity_tracker(req, depot);
    let session = extract_session_info(req, depot);
    let (requester, repo) = get_requester(&clock, &activity, depot.repo().await?, &session).await?;
    let user = requester.user().ok_or(RouteError::Unauthorized)?;
    revoke_device(repo, &clock, user, &device).await?;
    Ok(Json(serde_json::json!({"status": "ENDED"})))
}

#[cfg(test)]
mod tests {
    use pasion_data::{
        PgRepositoryFactory, RepositoryFactory as _, clock::SystemClock,
        personal::session::PersonalSessionOwner,
    };

    #[test]
    fn device_listing_counts_scope_aliases_once_per_session() {
        let mut counts = std::collections::BTreeMap::new();
        add_session_devices(
            &mut counts,
            &"urn:matrix:client:device:A urn:matrix:org.matrix.msc2967.client:device:A"
                .parse()
                .unwrap(),
        );
        add_session_devices(&mut counts, &"urn:matrix:client:device:B".parse().unwrap());
        add_session_devices(&mut counts, &"urn:matrix:client:device:A".parse().unwrap());
        assert_eq!(
            counts.into_iter().collect::<Vec<_>>(),
            [("A".to_owned(), 2), ("B".to_owned(), 1)]
        );
    }

    use super::*;

    #[tokio::test]
    async fn device_lookup_and_logout_isolate_the_device_and_user() {
        let pool = pasion_data::test_utils::setup_test_pool().await;
        let factory = PgRepositoryFactory::new(pool);
        let clock = SystemClock::default();
        let mut rng = make_rng();
        let mut repo = factory.create().await.unwrap();
        let alice = repo
            .user()
            .add(&mut rng, &clock, "alice".into())
            .await
            .unwrap();
        let bob = repo
            .user()
            .add(&mut rng, &clock, "bob".into())
            .await
            .unwrap();
        for (user, scope) in [
            (&alice, "urn:matrix:client:device:A"),
            (&alice, "urn:matrix:org.matrix.msc2967.client:device:A"),
            (&alice, "urn:matrix:client:device:B"),
            (&bob, "urn:matrix:client:device:A"),
        ] {
            repo.personal_session()
                .add(
                    &mut rng,
                    &clock,
                    PersonalSessionOwner::User(user.id),
                    user,
                    "Phone".into(),
                    scope.parse().unwrap(),
                )
                .await
                .unwrap();
        }
        repo.save().await.unwrap();
        let mut repo = factory.create().await.unwrap();
        let devices = list_devices(&mut repo, &alice).await.unwrap();
        assert_eq!(
            devices
                .iter()
                .map(|d| (d.device_id.as_str(), d.session_count))
                .collect::<Vec<_>>(),
            [("A", 2), ("B", 1)]
        );
        assert_eq!(
            device_session_count(&mut repo, &alice, "A").await.unwrap(),
            2
        );
        assert_eq!(
            device_session_count(&mut repo, &alice, "missing")
                .await
                .unwrap(),
            0
        );
        repo.cancel().await.unwrap();
        revoke_device(factory.create().await.unwrap(), &clock, &alice, "A")
            .await
            .unwrap();
        let mut repo = factory.create().await.unwrap();
        assert_eq!(
            device_session_count(&mut repo, &alice, "A").await.unwrap(),
            0
        );
        assert_eq!(
            device_session_count(&mut repo, &alice, "B").await.unwrap(),
            1
        );
        assert_eq!(device_session_count(&mut repo, &bob, "A").await.unwrap(), 1);
        repo.cancel().await.unwrap();
    }
}
