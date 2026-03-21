mod add;
mod get;
mod list;
mod revoke;
mod unrevoke;
mod update;

pub use self::{
    add::{doc as add_doc, handler as add},
    get::{doc as get_doc, handler as get},
    list::{doc as list_doc, handler as list},
    revoke::{doc as revoke_doc, handler as revoke},
    unrevoke::{doc as unrevoke_doc, handler as unrevoke},
    update::{doc as update_doc, handler as update},
};
