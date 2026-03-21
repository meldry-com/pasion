use async_graphql::{ID, Object};

/// An anonymous viewer
#[derive(Default, Clone, Copy)]
pub struct Anonymous;

#[Object]
impl Anonymous {
    pub async fn id(&self) -> ID {
        "anonymous".into()
    }
}
