mod add;
mod delete;
mod get;
mod list;

pub use self::{
    add::{doc as add_doc, handler as add},
    delete::{doc as delete_doc, handler as delete},
    get::{doc as get_doc, handler as get},
    list::{doc as list_doc, handler as list},
};
