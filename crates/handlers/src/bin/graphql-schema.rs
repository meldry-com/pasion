#![forbid(unsafe_code)]
#![deny(
    clippy::all,
    clippy::str_to_string,
    rustdoc::broken_intra_doc_links,
    clippy::future_not_send
)]
#![warn(clippy::pedantic)]

fn main() {
    let schema = pasion_handlers::graphql_schema_builder().finish();
    println!("{}", schema.sdl());
}
