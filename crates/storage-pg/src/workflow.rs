// Workflow repository -- PostgreSQL implementation.
//
// TODO: Implement once the corresponding Diesel schema and migrations are in place.

use async_trait::async_trait;
use pasion_data_model::{
    Clock, WorkflowEvent, WorkflowInstance, WorkflowInstanceStatus, WorkflowStep,
    WorkflowStepStatus,
};
use pasion_storage::workflow::{
    NewWorkflowEvent, NewWorkflowInstance, NewWorkflowStep, WorkflowRepository,
};
use rand::RngCore;
use ulid::Ulid;

use crate::DatabaseError;

/// PostgreSQL implementation of [`WorkflowRepository`].
pub struct PgWorkflowRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgWorkflowRepository<'c> {
    /// Create a new [`PgWorkflowRepository`] from an active PostgreSQL connection.
    #[must_use]
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

#[async_trait]
impl WorkflowRepository for PgWorkflowRepository<'_> {
    type Error = DatabaseError;

    async fn lookup_instance(
        &mut self,
        _id: Ulid,
    ) -> Result<Option<WorkflowInstance>, Self::Error> {
        todo!()
    }

    async fn add_instance(
        &mut self,
        _rng: &mut (dyn RngCore + Send),
        _clock: &dyn Clock,
        _params: NewWorkflowInstance,
    ) -> Result<WorkflowInstance, Self::Error> {
        todo!()
    }

    async fn set_instance_status(
        &mut self,
        _clock: &dyn Clock,
        _workflow_instance: WorkflowInstance,
        _status: WorkflowInstanceStatus,
    ) -> Result<WorkflowInstance, Self::Error> {
        todo!()
    }

    async fn lookup_step(
        &mut self,
        _id: Ulid,
    ) -> Result<Option<WorkflowStep>, Self::Error> {
        todo!()
    }

    async fn list_steps(
        &mut self,
        _workflow_instance: &WorkflowInstance,
    ) -> Result<Vec<WorkflowStep>, Self::Error> {
        todo!()
    }

    async fn add_step(
        &mut self,
        _rng: &mut (dyn RngCore + Send),
        _clock: &dyn Clock,
        _workflow_instance: &WorkflowInstance,
        _params: NewWorkflowStep,
    ) -> Result<WorkflowStep, Self::Error> {
        todo!()
    }

    async fn set_step_status(
        &mut self,
        _clock: &dyn Clock,
        _workflow_step: WorkflowStep,
        _status: WorkflowStepStatus,
    ) -> Result<WorkflowStep, Self::Error> {
        todo!()
    }

    async fn append_event(
        &mut self,
        _rng: &mut (dyn RngCore + Send),
        _clock: &dyn Clock,
        _workflow_instance: &WorkflowInstance,
        _workflow_step: Option<&WorkflowStep>,
        _params: NewWorkflowEvent,
    ) -> Result<WorkflowEvent, Self::Error> {
        todo!()
    }

    async fn list_events(
        &mut self,
        _workflow_instance: &WorkflowInstance,
    ) -> Result<Vec<WorkflowEvent>, Self::Error> {
        todo!()
    }
}
