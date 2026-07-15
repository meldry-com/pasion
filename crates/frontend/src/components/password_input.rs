use dioxus::prelude::*;

/// Password strength level.
#[derive(Debug, Clone, Copy, PartialEq)]
enum PasswordStrength {
    Empty,
    Weak,
    Fair,
    Good,
    Strong,
}

impl PasswordStrength {
    fn from_score(score: u8) -> Self {
        match score {
            0 | 1 => PasswordStrength::Weak,
            2 => PasswordStrength::Fair,
            3 => PasswordStrength::Good,
            _ => PasswordStrength::Strong,
        }
    }

    fn score(self) -> u8 {
        match self {
            PasswordStrength::Empty => 0,
            PasswordStrength::Weak => 1,
            PasswordStrength::Fair => 2,
            PasswordStrength::Good => 3,
            PasswordStrength::Strong => 4,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            PasswordStrength::Empty => "",
            PasswordStrength::Weak => "Weak",
            PasswordStrength::Fair => "Fair",
            PasswordStrength::Good => "Good",
            PasswordStrength::Strong => "Strong",
        }
    }

    /// Stable slug used as a `data-strength` attribute so styling (colors,
    /// bar width) lives in CSS and adapts to light/dark mode.
    fn slug(&self) -> &'static str {
        match self {
            PasswordStrength::Empty => "empty",
            PasswordStrength::Weak => "weak",
            PasswordStrength::Fair => "fair",
            PasswordStrength::Good => "good",
            PasswordStrength::Strong => "strong",
        }
    }
}

/// Use the same zxcvbn scoring algorithm as the backend password manager.
fn estimate_strength(password: &str) -> PasswordStrength {
    if password.is_empty() {
        return PasswordStrength::Empty;
    }
    PasswordStrength::from_score(u8::from(zxcvbn::zxcvbn(password, &[]).score()))
}

const PASSWORD_INPUT_CSS: &str = r#"
.password-field-control{position:relative;display:block;width:100%}
.password-field-control .form-input{padding-right:44px}
.password-visibility-toggle{
    position:absolute;right:6px;top:50%;transform:translateY(-50%);
    width:34px;height:34px;padding:0;border:0;border-radius:6px;
    display:inline-flex;align-items:center;justify-content:center;
    color:var(--text-secondary);background:transparent;cursor:pointer;
}
.password-visibility-toggle:hover{background:var(--surface-hover);color:var(--text-primary)}
.password-visibility-toggle:focus-visible{outline:2px solid var(--primary);outline-offset:1px}
.password-visibility-toggle svg{width:18px;height:18px}
.pw-policy{display:block;margin-top:4px;font-size:12px}
.pw-policy.met{color:var(--success)}
.pw-policy.unmet{color:var(--critical)}
"#;

#[component]
pub fn PasswordInput(
    value: String,
    oninput: EventHandler<FormEvent>,
    #[props(default = "form-input".to_string())] class: String,
    #[props(default = "current-password".to_string())] autocomplete: String,
    #[props(default)] placeholder: String,
    #[props(default)] required: bool,
    #[props(default)] id: String,
    #[props(default)] name: String,
) -> Element {
    let mut visible = use_signal(|| false);
    let is_visible = visible();
    let accessible_label = if is_visible {
        "Hide password"
    } else {
        "Show password"
    };

    rsx! {
        style { {PASSWORD_INPUT_CSS} }
        div { class: "password-field-control",
            input {
                class,
                id,
                name,
                r#type: if is_visible { "text" } else { "password" },
                autocomplete,
                required,
                placeholder,
                value,
                oninput: move |event| oninput.call(event),
            }
            button {
                class: "password-visibility-toggle",
                r#type: "button",
                aria_label: accessible_label,
                aria_pressed: is_visible,
                title: accessible_label,
                onclick: move |_| visible.toggle(),
                if is_visible {
                    svg { xmlns: "http://www.w3.org/2000/svg", view_box: "0 0 24 24", fill: "none", stroke: "currentColor", stroke_width: "2",
                        path { d: "M3 3l18 18" }
                        path { d: "M10.6 10.6a2 2 0 002.8 2.8" }
                        path { d: "M9.9 4.2A10.5 10.5 0 0112 4c5 0 9 5 9 8a9.8 9.8 0 01-2 3.2" }
                        path { d: "M6.6 6.6C4.4 8 3 10.2 3 12c0 3 4 8 9 8a9.8 9.8 0 004.2-.9" }
                    }
                } else {
                    svg { xmlns: "http://www.w3.org/2000/svg", view_box: "0 0 24 24", fill: "none", stroke: "currentColor", stroke_width: "2",
                        path { d: "M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z" }
                        circle { cx: "12", cy: "12", r: "3" }
                    }
                }
            }
        }
    }
}

#[component]
pub fn PasswordCreationDoubleInput(
    new_password: Signal<String>,
    new_password_again: Signal<String>,
    force_invalid: Option<bool>,
) -> Element {
    let passwords_match =
        new_password.read().eq(&*new_password_again.read()) || new_password_again.read().is_empty();
    let show_mismatch = !passwords_match && !new_password_again.read().is_empty();
    let force_invalid = force_invalid.unwrap_or(false);

    let password_val = new_password.read().clone();
    let strength = estimate_strength(&password_val);
    let site_config = crate::use_site_config().0;
    let minimum_complexity = {
        let binding = site_config.read();
        match &*binding {
            Some(Ok(config)) => config.minimum_password_complexity.clamp(0, 4) as u8,
            _ => 0,
        }
    };

    rsx! {
        div { class: "form-field",
            label { class: "form-label", r#for: "new-password", "New password" }
            PasswordInput {
                class: if force_invalid { "form-input invalid" } else { "form-input" },
                id: "new-password",
                name: "new_password",
                autocomplete: "new-password".to_string(),
                required: true,
                value: new_password.read().clone(),
                oninput: move |e: FormEvent| new_password.set(e.value()),
            }
            if force_invalid {
                span { class: "form-error", "Password does not meet the requirements." }
            }

            // Password strength indicator
            if strength != PasswordStrength::Empty {
                div { class: "pw-strength",
                    div { class: "pw-strength-track",
                        div {
                            class: "pw-strength-bar",
                            "data-strength": "{strength.slug()}",
                        }
                    }
                    span {
                        class: "pw-strength-label",
                        "data-strength": "{strength.slug()}",
                        "{strength.label()}"
                    }
                }
                if minimum_complexity > 0 {
                    span {
                        class: if strength.score() >= minimum_complexity { "pw-policy met" } else { "pw-policy unmet" },
                        if strength.score() >= minimum_complexity {
                            "Meets the configured password policy"
                        } else {
                            "Needs a zxcvbn score of at least {minimum_complexity}/4"
                        }
                    }
                }
            }
        }
        div { class: "form-field",
            label { class: "form-label", r#for: "confirm-new-password", "Confirm new password" }
            PasswordInput {
                class: if show_mismatch { "form-input invalid" } else { "form-input" },
                id: "confirm-new-password",
                name: "confirm_new_password",
                autocomplete: "new-password".to_string(),
                required: true,
                value: new_password_again.read().clone(),
                oninput: move |e: FormEvent| new_password_again.set(e.value()),
            }
            if show_mismatch {
                span { class: "form-error", "Passwords do not match." }
            }
        }
    }
}

#[component]
pub fn AccountManagementPasswordPreview() -> Element {
    rsx! {
        div { class: "password-preview",
            div {
                span { class: "password-dots", "••••••••" }
            }
            Link {
                class: "btn btn-secondary btn-sm",
                to: crate::pages::Route::PasswordChange {},
                "Change password"
            }
        }
    }
}
