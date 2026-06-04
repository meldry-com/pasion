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

/// Estimate password strength based on length and character variety.
fn estimate_strength(password: &str) -> PasswordStrength {
    if password.is_empty() {
        return PasswordStrength::Empty;
    }

    let len = password.len();
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    let variety_count = [has_lower, has_upper, has_digit, has_special]
        .iter()
        .filter(|&&v| v)
        .count();

    // Score based on length and variety
    if len < 8 {
        PasswordStrength::Weak
    } else if len < 12 {
        if variety_count >= 3 {
            PasswordStrength::Good
        } else {
            PasswordStrength::Fair
        }
    } else if len < 16 {
        if variety_count >= 3 {
            PasswordStrength::Strong
        } else {
            PasswordStrength::Good
        }
    } else {
        // 16+ characters
        if variety_count >= 2 {
            PasswordStrength::Strong
        } else {
            PasswordStrength::Good
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

    rsx! {
        div { class: "form-field",
            label { class: "form-label", "New password" }
            input {
                class: if force_invalid { "form-input invalid" } else { "form-input" },
                r#type: "password",
                autocomplete: "new-password",
                required: true,
                value: "{new_password}",
                oninput: move |e| new_password.set(e.value()),
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
            }
        }
        div { class: "form-field",
            label { class: "form-label", "Confirm new password" }
            input {
                class: if show_mismatch { "form-input invalid" } else { "form-input" },
                r#type: "password",
                autocomplete: "new-password",
                required: true,
                value: "{new_password_again}",
                oninput: move |e| new_password_again.set(e.value()),
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
