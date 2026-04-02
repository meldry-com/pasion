# Pasion translation file
# Auto-converted from JSON format

## action

action-back = Back
action-cancel = Cancel
action-continue = Continue
action-create-account = Create Account
action-sign-in = Sign in
action-sign-out = Sign out
action-skip = Skip
action-start-over = Start over

## app

# Human readable name of the application
app-human-name = Pasion
# Name of the application
app-name = pasion
# Introduction text displayed on the home page
app-technical-description =
    OpenID Connect discovery document: <a class="cpd-link" data-kind="primary" href="{ $discovery_url }">{ $discovery_url }</a>

## branding

branding-privacy-policy-alt = Link to the service privacy policy
branding-privacy-policy-link = Privacy Policy
branding-terms-and-conditions-alt = Link to the service terms and conditions
branding-terms-and-conditions-link = Terms & Conditions

## common

common-display-name = Display Name
common-email-address = Email address
common-loading = Loading…
common-mxid = Matrix ID
common-password = Password
common-password-confirm = Confirm password
common-username = Username

## error

# Error message displayed when an unexpected error occurs
error-unexpected = Unexpected error

## pasion

pasion-account-deactivated-description =
    This account (<em>{ $mxid }</em>) has been deleted. If this is not expected, contact your server administrator.
pasion-account-deactivated-heading = Account deleted
pasion-account-locked-description =
    This account (<em>{ $mxid }</em>) has been locked. If this is not expected, contact your server administrator.
pasion-account-locked-heading = Account locked
pasion-account-logged-out-description = This session has been terminated. Sign out to be able to log back in
pasion-account-logged-out-heading = Session terminated
pasion-back-to-homepage = Go back to the homepage
pasion-captcha-noscript =
    This form is protected by a CAPTCHA and requires JavaScript to be enabled to submit it. Please enable JavaScript in your browser and reload this page.
# Button to change the user's password
pasion-change-password-change = Change password
# Confirmation field for the new password
pasion-change-password-confirm = Confirm password
# Field for the user's current password
pasion-change-password-current = Current password
# Heading on the change password page
pasion-change-password-heading = Change my password
# Field for the user's new password
pasion-change-password-new = New password
# During the registration flow, the user is asked to choose a display name. This is the description of that form.
pasion-choose-display-name-description = This is the name other people will see. You can change this at any time.
# During the registration flow, the user is asked to choose a display name. This is the headline of that form.
pasion-choose-display-name-headline = Choose your display name
pasion-consent-continue-to = Continue to <span>{ $client_name }</span>?
pasion-consent-scope-list-preface = By continuing, you allow <span>{ $client_name }</span> to:
pasion-consent-this-will-setup =
    This will set up { $client_name } (<span>{ $client_uri }</span>) with your <span>{ $server_name }</span> account.
pasion-consent-use-another-account = Use another account
pasion-device-card-access-requested = Access requested
pasion-device-card-device-code = Code
pasion-device-card-generic-device = Device
pasion-device-card-ip-address = IP address
pasion-device-code-link-description = Link a device
pasion-device-code-link-headline = Enter the code displayed on your device
pasion-device-consent-denied-description = You denied access to { $client_name }. You can close this window.
pasion-device-consent-denied-heading = Access denied
pasion-device-consent-granted-description = You granted access to { $client_name }. You can close this window.
pasion-device-consent-granted-heading = Access granted
pasion-device-consent-this-will-setup =
    Another device wants to set up { $client_name } (<span>{ $client_uri }</span>) with your <span>{ $server_name }</span> account. Make sure you recognise that device.
# The automatic device name generated for a client, e.g. 'Element on iPhone'
pasion-device-display-name-client-on-device = { $client_name } on { $device_name }
# Part of the automatic device name for the platfom, e.g. 'Safari for macOS'
pasion-device-display-name-name-for-platform = { $name } for { $platform }
pasion-device-display-name-unknown-device = Unknown device
pasion-email-in-use-description =
    If you have forgotten your account credentials, you can recover your account. You can also start over and use a different email address.
pasion-email-in-use-title = The email address <span>{ $email }</span> is already in use
# Greeting at the top of emails sent to the user
pasion-emails-greeting = Hello { $username },
pasion-emails-recovery-click-button = Click on the button below to create a new password:
pasion-emails-recovery-copy-link = Copy the following link and paste it into a browser to create a new password:
pasion-emails-recovery-create-new-password = Create new password
pasion-emails-recovery-fallback = The button doesn't work for you?
pasion-emails-recovery-headline = You requested a password reset for your { $server_name } account.
pasion-emails-recovery-subject = Reset your account password ({ $mxid })
pasion-emails-recovery-you-can-ignore =
    If you didn't ask for a new password, you can ignore this email. Your current password will continue to work.
# The body of the email sent to verify an email address (HTML)
pasion-emails-verify-body-html = Your verification code to confirm this email address is: <strong>{ $code }</strong>
# The body of the email sent to verify an email address (text)
pasion-emails-verify-body-text = Your verification code to confirm this email address is: { $code }
# The subject line of the email sent to verify an email address
pasion-emails-verify-subject = Your email verification code is: { $code }
pasion-errors-captcha = CAPTCHA verification failed, please try again
pasion-errors-denied-policy = Denied by policy: { $policy }
pasion-errors-email-banned = Email is banned by the server policy
pasion-errors-email-domain-banned = Email domain is banned by the server policy
pasion-errors-email-domain-not-allowed = Email domain is not allowed by the server policy
pasion-errors-email-not-allowed = Email is not allowed by the server policy
pasion-errors-field-required = This field is required
pasion-errors-invalid-credentials = Invalid credentials
pasion-errors-password-mismatch = Password fields don't match
pasion-errors-rate-limit-exceeded = You've made too many requests in a short period. Please wait a few minutes and try again.
pasion-errors-username-all-numeric = Username cannot consist solely of numbers
# Error message shown on registration, when the username matches a pattern that is banned by the server policy.
pasion-errors-username-banned = Username is banned by the server policy
pasion-errors-username-invalid-chars = Username contains invalid characters. Use lowercase letters, numbers, dashes and underscores only.
# Error message shown on registration, when the username *does not match* any of the patterns that are allowed by the server policy.
pasion-errors-username-not-allowed = Username is not allowed by the server policy
pasion-errors-username-taken = This username is already taken
pasion-errors-username-too-long = Username is too long
pasion-errors-username-too-short = Username is too short
pasion-legacy-consent-this-will-setup = This will set up <span>{ $client_name }</span> with your <span>{ $server_name }</span> account.
pasion-login-call-to-register = Don't have an account yet?
# Button to log in with an upstream provider
pasion-login-continue-with-provider = Continue with { $provider }
pasion-login-description = Please sign in to continue:
# On the login page, link to the account recovery process
pasion-login-forgot-password = Forgot password?
pasion-login-headline = Sign in
pasion-login-link-description = Linking your <span class="break-keep text-links">{ $provider }</span> account
pasion-login-link-headline = Sign in to link
pasion-login-no-login-methods = No login methods available.
pasion-login-username-or-email = Username or Email
pasion-navbar-my-account = My account
pasion-navbar-register = Create an account
# Displayed in the navbar when the user is signed in
pasion-navbar-signed-in-as = Signed in as <span class="font-semibold">{ $username }</span>.
pasion-not-found-description = The page you were looking for doesn't exist or has been moved
pasion-not-found-heading = Page not found
# Suggestions for the user to log in as a different user
pasion-not-you = Not { $username }?
# Separator between the login methods
pasion-or-separator = Or
# Displayed when an authorization request is denied by the policy
pasion-policy-violation-description =
    This might be because of the client which authored the request, the currently logged in user, or the request itself.
# Displayed when an authorization request is denied by the policy
pasion-policy-violation-heading = The authorization request was denied by the policy enforced by this service
pasion-policy-violation-logged-as = Logged as <span class="font-semibold">{ $username }</span>
# Description on the error page shown when a user tries to use a recovery link that has already been used
pasion-recovery-consumed-description = To create a new password, start over and select “Forgot password”.
# Title on the error page shown when a user tries to use a recovery link that has already been used
pasion-recovery-consumed-heading = The link to reset your password has already been used
pasion-recovery-disabled-description = If you have lost your credentials, please contact the administrator to recover your account.
pasion-recovery-disabled-heading = Account recovery is disabled
# Description on the page shown when a user tries to use an expired recovery link
pasion-recovery-expired-description = Request a new email that will be sent to: <span>{ $email }</span>.
# Title on the page shown when a user tries to use an expired recovery link
pasion-recovery-expired-heading = The link to reset your password has expired
pasion-recovery-expired-resend-email = Resend email
# Label for the password confirmation field
pasion-recovery-finish-confirm = Enter new password again
# Description for the final password recovery page
pasion-recovery-finish-description = Choose a new password for your account.
# Heading for the final password recovery page
pasion-recovery-finish-heading = Reset your password
# Label for the new password field
pasion-recovery-finish-new = New password
# Button to save the new password and continue
pasion-recovery-finish-save-and-continue = Save and continue
# Button to change the email address for the password recovery link
pasion-recovery-progress-change-email = Try a different email
# The description of the password recovery page, informing the user that an email has been sent to reset their password
pasion-recovery-progress-description =
    We sent an email with a link to reset your password if there's an account using <span>{ $email }</span>.
# The title of the password recovery page, informing the user that an email has been sent to reset their password
pasion-recovery-progress-heading = Check your email
# Button to resend the email with the password recovery link
pasion-recovery-progress-resend-email = Resend email
# The description of the page to initiate an account recovery
pasion-recovery-start-description = An email will be sent with a link to reset your password.
# The title of the page to initiate an account recovery
pasion-recovery-start-heading = Enter your email to continue
# Displayed on the registration page to suggest to log in instead
pasion-register-call-to-login = Already have an account?
pasion-register-continue-with-email = Continue with email address
pasion-register-continue-with-password = Continue with password
pasion-register-create-account-description = Choose a username to continue.
pasion-register-create-account-heading = Create an account
pasion-register-terms-of-service = I agree to the <a href="{ $tos_uri }" data-kind="primary" class="cpd-link">Terms and Conditions</a>
pasion-registration-token-description = Enter a registration token provided by the homeserver administrator.
pasion-registration-token-field = Registration token
pasion-registration-token-headline = Registration token
# Displayed when the 'urn:palpo:admin:*' scope is requested
pasion-scope-palpo-admin = Administer the server (urn:palpo:admin:*)
pasion-scope-pasion-admin = Manage users (urn:pasion:admin)
pasion-scope-send-messages = Send new messages on your behalf
# Displayed when the 'urn:matrix:client:api:*' scope is requested
pasion-scope-view-messages = View your existing messages and data
# Displayed when the 'openid' scope is requested
pasion-scope-view-profile = See your profile info and contact details
# Page shown when the user tries to link an upstream account that is already linked to another account
pasion-upstream-oauth2-link-mismatch-heading = This upstream account is already linked to another account.
pasion-upstream-oauth2-register-choose-username-description = This cannot be changed later.
# Displayed when creating a new account from an SSO login, and the username is not forced
pasion-upstream-oauth2-register-choose-username-heading = Choose your username
# Displayed when creating a new account from an SSO login, and the username is pre-filled and forced
pasion-upstream-oauth2-register-create-account = Create a new account
pasion-upstream-oauth2-register-enforced-by-policy = Enforced by server policy
# Tells the user what display name will be imported
pasion-upstream-oauth2-register-forced-display-name = Will use the following display name
# Tells the user which email address will be imported
pasion-upstream-oauth2-register-forced-email = Will use the following email address
# Tells the user which username will be used
pasion-upstream-oauth2-register-forced-localpart = Will use the following username
pasion-upstream-oauth2-register-import-data-description = Confirm the information that will be linked to your new { $server_name } account.
pasion-upstream-oauth2-register-import-data-heading = Import your data
pasion-upstream-oauth2-register-imported-from-upstream = Imported from your upstream account
pasion-upstream-oauth2-register-imported-from-upstream-with-name = Imported from your { $human_name } account
# Button to link an existing account after an SSO login
pasion-upstream-oauth2-register-link-existing = Link to an existing account
pasion-upstream-oauth2-register-provider-name = { $human_name } account
pasion-upstream-oauth2-register-signup-with-upstream-heading = Continue signing up with your { $human_name } account
# Option to let the user import their display name after an SSO login
pasion-upstream-oauth2-register-suggested-display-name = Import display name
# Option to let the user import their email address after an SSO login
pasion-upstream-oauth2-register-suggested-email = Import email address
pasion-upstream-oauth2-register-use = Use
pasion-upstream-oauth2-suggest-link-action = Link
pasion-upstream-oauth2-suggest-link-heading = Link to your existing account
pasion-verify-email-6-digit-code = 6-digit code
pasion-verify-email-description = Enter the 6-digit code sent to: <em>{ $email }</em>
pasion-verify-email-headline = Verify your email
