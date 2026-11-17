// Copyright 2024, 2025 Taidge Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::module_name_repetitions)]

use pasion_data::{Pagination, pagination::Edge};
use salvo::oapi::ToSchema;
use schemars::JsonSchema;
use serde::Serialize;
use ulid::Ulid;

use super::model::Resource;

/// Related links
#[derive(Serialize, JsonSchema)]
struct PaginationLinks {
    /// The canonical link to the current page
    #[serde(rename = "self")]
    self_: String,

    /// The link to the first page of results
    #[serde(skip_serializing_if = "Option::is_none")]
    first: Option<String>,

    /// The link to the last page of results
    #[serde(skip_serializing_if = "Option::is_none")]
    last: Option<String>,

    /// The link to the next page of results
    ///
    /// Only present if there is a next page
    #[serde(skip_serializing_if = "Option::is_none")]
    next: Option<String>,

    /// The link to the previous page of results
    ///
    /// Only present if there is a previous page
    #[serde(skip_serializing_if = "Option::is_none")]
    prev: Option<String>,
}

#[derive(Serialize, JsonSchema)]
struct PaginationMeta {
    /// The total number of results
    #[serde(skip_serializing_if = "Option::is_none")]
    count: Option<usize>,
}

impl PaginationMeta {
    fn is_empty(&self) -> bool {
        self.count.is_none()
    }
}

/// A top-level response with a page of resources
#[derive(Serialize, JsonSchema)]
pub struct PaginatedResponse<T> {
    /// Response metadata
    #[serde(skip_serializing_if = "PaginationMeta::is_empty")]
    #[schemars(with = "Option<PaginationMeta>")]
    meta: PaginationMeta,

    /// The list of resources
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Vec<SingleResource<T>>>,

    /// Related links
    links: PaginationLinks,
}

fn url_with_pagination(base: &str, pagination: Pagination) -> String {
    let (path, query) = base.split_once('?').unwrap_or((base, ""));
    let mut query = query.to_owned();

    if let Some(before) = pagination.before {
        query = format!("{query}&page[before]={before}");
    }

    if let Some(after) = pagination.after {
        query = format!("{query}&page[after]={after}");
    }

    let count = pagination.count;
    match pagination.direction {
        pasion_data::pagination::PaginationDirection::Forward => {
            query = format!("{query}&page[first]={count}");
        }
        pasion_data::pagination::PaginationDirection::Backward => {
            query = format!("{query}&page[last]={count}");
        }
    }

    // Remove the first '&'
    let query = query.trim_start_matches('&');

    format!("{path}?{query}")
}

impl<T: Resource> PaginatedResponse<T> {
    pub fn for_page(
        page: pasion_data::Page<T>,
        current_pagination: Pagination,
        count: Option<usize>,
        base: &str,
    ) -> Self {
        let links = PaginationLinks {
            self_: url_with_pagination(base, current_pagination),
            first: Some(url_with_pagination(
                base,
                Pagination::first(current_pagination.count),
            )),
            last: Some(url_with_pagination(
                base,
                Pagination::last(current_pagination.count),
            )),
            next: page.has_next_page.then(|| {
                url_with_pagination(
                    base,
                    current_pagination
                        .clear_before()
                        .after(page.edges.last().unwrap().cursor),
                )
            }),
            prev: if page.has_previous_page {
                Some(url_with_pagination(
                    base,
                    current_pagination
                        .clear_after()
                        .before(page.edges.first().unwrap().cursor),
                ))
            } else {
                None
            },
        };

        let data = page
            .edges
            .into_iter()
            .map(SingleResource::from_edge)
            .collect();

        Self {
            meta: PaginationMeta { count },
            data: Some(data),
            links,
        }
    }

    pub fn for_count_only(count: usize, base: &str) -> Self {
        let links = PaginationLinks {
            self_: base.to_owned(),
            first: None,
            last: None,
            next: None,
            prev: None,
        };

        Self {
            meta: PaginationMeta { count: Some(count) },
            data: None,
            links,
        }
    }
}

/// A single resource, with its type, ID, attributes and related links
#[derive(Serialize, JsonSchema)]
struct SingleResource<T> {
    /// The type of the resource
    #[serde(rename = "type")]
    type_: &'static str,

    /// The ID of the resource
    #[schemars(with = "super::schema::Ulid")]
    id: Ulid,

    /// The attributes of the resource
    attributes: T,

    /// Related links
    links: SelfLinks,

    /// Metadata about the resource
    #[serde(skip_serializing_if = "SingleResourceMeta::is_empty")]
    #[schemars(with = "Option<SingleResourceMeta>")]
    meta: SingleResourceMeta,
}

/// Metadata associated with a resource
#[derive(Serialize, JsonSchema)]
struct SingleResourceMeta {
    /// Information about the pagination of the resource
    #[serde(skip_serializing_if = "Option::is_none")]
    page: Option<SingleResourceMetaPage>,
}

impl SingleResourceMeta {
    fn is_empty(&self) -> bool {
        self.page.is_none()
    }
}

/// Pagination metadata for a resource
#[derive(Serialize, JsonSchema)]
struct SingleResourceMetaPage {
    /// The cursor of this resource in the paginated result
    cursor: String,
}

impl<T: Resource> SingleResource<T> {
    fn new(resource: T) -> Self {
        let self_ = resource.path();
        Self {
            type_: T::KIND,
            id: resource.id(),
            attributes: resource,
            links: SelfLinks { self_ },
            meta: SingleResourceMeta { page: None },
        }
    }

    fn from_edge<C: ToString>(edge: Edge<T, C>) -> Self {
        let cursor = edge.cursor.to_string();
        let mut resource = Self::new(edge.node);
        resource.meta.page = Some(SingleResourceMetaPage { cursor });
        resource
    }
}

/// Related links
#[derive(Serialize, JsonSchema)]
struct SelfLinks {
    /// The canonical link to the current resource
    #[serde(rename = "self")]
    self_: String,
}

/// A top-level response with a single resource
#[derive(Serialize, JsonSchema)]
pub struct SingleResponse<T> {
    data: SingleResource<T>,
    links: SelfLinks,
}

impl<T: Resource> SingleResponse<T> {
    /// Create a new single response with the given resource and link to itself
    pub fn new(resource: T, self_: String) -> Self {
        Self {
            data: SingleResource::new(resource),
            links: SelfLinks { self_ },
        }
    }

    /// Create a new single response using the canonical path for the resource
    pub fn new_canonical(resource: T) -> Self {
        let self_ = resource.path();
        Self::new(resource, self_)
    }
}

/// A single error
#[derive(Serialize, JsonSchema)]
struct Error {
    /// A human-readable title for the error
    title: String,
}

impl Error {
    fn from_error(error: &(dyn std::error::Error + 'static)) -> Self {
        Self {
            title: error.to_string(),
        }
    }
}

/// A top-level response with a list of errors
#[derive(Serialize, JsonSchema)]
pub struct ErrorResponse {
    /// The list of errors
    errors: Vec<Error>,
}

impl ErrorResponse {
    /// Create a new error response from any Rust error
    pub fn from_error(error: &(dyn std::error::Error + 'static)) -> Self {
        let mut errors = Vec::new();
        let mut head = Some(error);
        while let Some(error) = head {
            errors.push(Error::from_error(error));
            head = error.source();
        }
        Self { errors }
    }
}

// ---------------------------------------------------------------------------
// ToSchema implementations for response wrappers.
//
// Keep the real resource attributes and page item shape in the generated API.

fn resource_schema<T: Resource + ToSchema>(
    components: &mut salvo::oapi::Components,
) -> salvo::oapi::RefOr<salvo::oapi::Schema> {
    use salvo::oapi::*;
    Object::new()
        .property(
            "type",
            Object::new()
                .schema_type(BasicType::String)
                .enum_values([T::KIND]),
        )
        .property("id", Object::new().schema_type(BasicType::String))
        .property("attributes", T::to_schema(components))
        .property("links", self_links_schema())
        .property(
            "meta",
            Object::new()
                .property(
                    "page",
                    Object::new()
                        .property("cursor", Object::new().schema_type(BasicType::String))
                        .required("cursor"),
                )
                .required("page"),
        )
        .required("type")
        .required("id")
        .required("attributes")
        .required("links")
        .into()
}

fn self_links_schema() -> salvo::oapi::Object {
    use salvo::oapi::*;
    Object::new()
        .property("self", Object::new().schema_type(BasicType::String))
        .required("self")
}

impl<T: Resource + ToSchema> ToSchema for PaginatedResponse<T> {
    fn to_schema(
        components: &mut salvo::oapi::Components,
    ) -> salvo::oapi::RefOr<salvo::oapi::Schema> {
        use salvo::oapi::*;
        let mut links = self_links_schema();
        for field in ["first", "last", "next", "prev"] {
            links = links.property(field, Object::new().schema_type(BasicType::String));
        }
        Object::new()
            .property(
                "meta",
                Object::new()
                    .property("count", Object::new().schema_type(BasicType::Integer))
                    .required("count"),
            )
            .property("data", Array::new().items(resource_schema::<T>(components)))
            .property("links", links)
            .required("links")
            .into()
    }
}

impl<T: Resource + ToSchema> ToSchema for SingleResponse<T> {
    fn to_schema(
        components: &mut salvo::oapi::Components,
    ) -> salvo::oapi::RefOr<salvo::oapi::Schema> {
        use salvo::oapi::*;
        Object::new()
            .property("data", resource_schema::<T>(components))
            .property("links", self_links_schema())
            .required("data")
            .required("links")
            .into()
    }
}

#[cfg(test)]
mod schema_tests {
    use super::*;
    use crate::handlers::admin::{model::PersonalSession, v1::personal_sessions};

    #[test]
    fn personal_session_openapi_documents_bare_required_create_and_optional_rotation() {
        let router = salvo::Router::with_path("api/admin/v1").push(
            salvo::Router::with_path("personal-sessions")
                .post(personal_sessions::add_session)
                .push(
                    salvo::Router::with_path("{id}/regenerate")
                        .post(personal_sessions::regenerate_session),
                ),
        );
        let doc = salvo::oapi::OpenApi::new("test", "1").merge_router(&router);
        let doc = serde_json::to_value(doc).unwrap();
        let create = &doc["paths"]["/api/admin/v1/personal-sessions"]["post"]["requestBody"];
        assert_eq!(create["required"], true);
        let schema = &create["content"]["application/json"]["schema"];
        let name = schema["$ref"]
            .as_str()
            .unwrap()
            .strip_prefix("#/components/schemas/")
            .unwrap();
        let schema = &doc["components"]["schemas"][name];
        let required = schema["required"].as_array().unwrap();
        for field in ["actor_user_id", "human_name", "scope"] {
            assert!(
                required.iter().any(|value| value == field),
                "missing required {field}"
            );
        }
        assert!(schema["properties"]["data"].is_null());
        assert!(!required.iter().any(|value| value == "expires_in"));
        assert_eq!(
            doc["paths"]["/api/admin/v1/personal-sessions/{id}/regenerate"]["post"]["requestBody"]
                ["required"],
            false
        );
    }

    #[test]
    fn personal_session_response_schema_preserves_attributes_and_page_array() {
        let mut components = salvo::oapi::Components::new();
        let single = serde_json::to_value(SingleResponse::<PersonalSession>::to_schema(
            &mut components,
        ))
        .unwrap();
        let attrs = &single["properties"]["data"]["properties"]["attributes"];
        let component_name = attrs["$ref"]
            .as_str()
            .unwrap()
            .strip_prefix("#/components/schemas/")
            .unwrap();
        let components = serde_json::to_value(components).unwrap();
        let model = &components["schemas"][component_name];
        for field in [
            "human_name",
            "actor_user_id",
            "owner_user_id",
            "owner_client_id",
            "expires_at",
            "access_token",
        ] {
            assert!(!model["properties"][field].is_null(), "missing {field}");
        }
        assert!(
            !model["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "access_token")
        );
        let mut components = salvo::oapi::Components::new();
        let page = serde_json::to_value(PaginatedResponse::<PersonalSession>::to_schema(
            &mut components,
        ))
        .unwrap();
        assert_eq!(page["properties"]["data"]["type"], "array");
        assert!(!page["properties"]["data"]["items"]["properties"]["attributes"]["$ref"].is_null());
    }
}
