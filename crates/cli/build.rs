use vergen_gitcl::{Emitter, GitclBuilder, RustcBuilder};

fn main() -> anyhow::Result<()> {
    // Register the custom cfg so rustc knows about it
    println!("cargo::rustc-check-cfg=cfg(tokio_unstable)");

    // VERGEN_GIT_DESCRIBE can be set externally to override the version;
    // however some CI environments set it to an empty string, which
    // confuses vergen.  Clear it in that case so vergen falls back to
    // running `git describe` itself.
    if std::env::var("VERGEN_GIT_DESCRIBE")
        .is_ok_and(|v| v.is_empty())
    {
        #[allow(unsafe_code)]
        // SAFETY: build scripts are single-threaded.
        unsafe {
            std::env::remove_var("VERGEN_GIT_DESCRIBE");
        }
    }

    let git = GitclBuilder::default()
        .describe(true, false, Some("v*.*.*"))
        .build()?;

    let rustc = RustcBuilder::default().semver(true).build()?;

    Emitter::default()
        .add_instructions(&git)?
        .add_instructions(&rustc)?
        .emit()?;

    Ok(())
}
