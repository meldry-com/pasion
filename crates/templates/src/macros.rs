/// Helper macro: counts tokens to determine array length at compile time.
macro_rules! count {
    () => (0_usize);
    ( $x:tt $($xs:tt)* ) => (1_usize + count!($($xs)*));
}

/// Declares strongly-typed template rendering methods on [`Templates`] and
/// generates a `check` module that renders each template with sample data.
///
/// Each entry maps a method name to its context type and template file path.
/// The macro also collects all template paths into a static array so that
/// missing templates can be detected at startup.
///
/// Syntax is intentionally function-like to minimise syntax highlighter
/// confusion.
#[macro_export]
macro_rules! register_templates {
    {
        $(
            extra = { $( $extra_template:expr ),* $(,)? };
        )?

        $(
            $( #[ $attr:meta ] )*
            pub fn $name:ident
                $(< $( #[sample( $generic_default:tt )] $lt:tt $( : $clt:tt $(+ $dlt:tt )* )? ),+ >)?
                ( $param:ty )
            {
                $template:expr
            }
        )*
    } => {
        /// All template paths registered via the `register_templates!` macro.
        static TEMPLATES: [&'static str; count!( $( $template )* )] = [ $( $template, )* ];

        impl Templates {
            $(
                $(#[$attr])?
                ///
                /// # Errors
                ///
                /// Returns an error if the template fails to render.
                pub fn $name
                    $(< $( $lt $( : $clt $(+ $dlt )* )? ),+ >)?
                    (&self, context: &$param)
                -> Result<String, TemplateError> {
                    let ctx = ::minijinja::value::Value::from_serialize(context);

                    let env = self.environment.load();
                    let tmpl = env.get_template($template)
                        .map_err(|source| TemplateError::Missing { template: $template, source })?;
                    tmpl.render(ctx)
                        .map_err(|source| TemplateError::Render { template: $template, source })
                }
            )*
        }

        /// Module that renders every registered template with sample contexts
        /// for validation purposes.
        pub mod check {
            use super::*;

            /// Render all templates with all sample data variants.
            ///
            /// Returns a map from `(template_path, sample_identifier)` to the
            /// rendered output.
            ///
            /// # Errors
            ///
            /// Returns an error if any template fails to render with any sample.
            pub(crate) fn all<R: Rng + Clone>(templates: &Templates, now: chrono::DateTime<chrono::Utc>, rng: &R) -> anyhow::Result<::std::collections::BTreeMap<(&'static str, SampleIdentifier), String>> {
                let mut results = ::std::collections::BTreeMap::new();
                $(
                    {
                        let mut rng = rng.clone();
                        let rendered = $name $(::< _ $( , $generic_default ),* >)? (templates, now, &mut rng)?;
                        results.extend(
                            rendered
                                .into_iter()
                                .map(|(sample_id, html)| (($template, sample_id), html))
                        );
                    }
                )*
                Ok(results)
            }

            $(
                #[doc = concat!("Render the `", $template, "` template with sample contexts")]
                ///
                /// Returns the sample renders.
                ///
                /// # Errors
                ///
                /// Returns an error if the template fails to render with any of the sample.
                pub(crate) fn $name
                    < __R: Rng + Clone $( , $( $lt $( : $clt $(+ $dlt )* + TemplateContext )? ),+ )? >
                    (templates: &Templates, now: chrono::DateTime<chrono::Utc>, rng: &mut __R)
                -> anyhow::Result<BTreeMap<SampleIdentifier, String>> {
                    let available_locales = templates.translator().available_locales();
                    let samples: BTreeMap<SampleIdentifier, $param > = TemplateContext::sample(now, rng, &available_locales);

                    let tpl_name = $template;
                    let mut output = BTreeMap::new();
                    for (sample_id, sample_ctx) in samples {
                        let ctx_json = serde_json::to_value(&sample_ctx)?;
                        ::tracing::info!(name = tpl_name, %ctx_json, "Rendering template");
                        let html = templates. $name (&sample_ctx)
                            .with_context(|| format!("Failed to render sample template {tpl_name:?}-{sample_id:?} with context {ctx_json}"))?;
                        output.insert(sample_id, html);
                    }

                    Ok(output)
                }
            )*
        }
    };
}
