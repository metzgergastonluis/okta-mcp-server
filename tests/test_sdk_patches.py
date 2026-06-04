"""Tests for the vendored okta SDK monkeypatch (sdk_patches.apply_sdk_patches).

okta SDK 3.4.1 is too strict for Springboard prod data and breaks list_applications
two ways: (1) it rejects unknown Application.features enum values (real prod apps
carry AUTO_CONFIRM_IMPORTS), and (2) it marks ~15 SamlApplicationSettingsSignOn
fields as required, but prod SAML apps return only a partial signOn block. The patch
relaxes both. See docs/superpowers/specs/2026-06-03-okta-mcp-skill-design.md.
"""

from okta.models.saml_application import SamlApplication
from okta.models.saml_application_settings_sign_on import SamlApplicationSettingsSignOn
from okta_mcp_server.utils.sdk_patches import apply_sdk_patches

# Modeled on the real "Springboard Collaborative Program Resource Site" prod app.
PRS_FEATURES = [
    "IMPORT_PROFILE_UPDATES", "PUSH_PENDING_USERS", "PUSH_NEW_USERS",
    "AUTO_CONFIRM_IMPORTS", "PUSH_USER_DEACTIVATION", "SCIM_PROVISIONING",
    "PUSH_PASSWORD_UPDATES", "GROUP_PUSH", "REACTIVATE_USERS",
    "EXCLUDE_USERNAME_UPDATE_ON_PROFILE_PUSH", "IMPORT_NEW_USERS",
    "PUSH_PROFILE_UPDATES",
]


def test_unknown_feature_parses_after_patch():
    apply_sdk_patches()
    app = SamlApplication(
        id="0oatest", label="PRS", signOnMode="SAML_2_0",
        status="ACTIVE", features=PRS_FEATURES,
    )
    assert app.features == PRS_FEATURES


def test_known_features_still_parse_after_patch():
    apply_sdk_patches()
    app = SamlApplication(
        id="0oatest2", label="Plain", signOnMode="SAML_2_0",
        status="ACTIVE", features=["SSO"],
    )
    assert app.features == ["SSO"]


def test_apply_is_idempotent():
    apply_sdk_patches()
    apply_sdk_patches()  # second call must not raise
    app = SamlApplication(
        id="0oatest3", label="Again", signOnMode="SAML_2_0",
        status="ACTIVE", features=["AUTO_CONFIRM_IMPORTS"],
    )
    assert app.features == ["AUTO_CONFIRM_IMPORTS"]


def test_partial_saml_signon_parses_after_patch():
    # Prod SAML apps return only a partial signOn block; okta SDK 3.4.1 marks ~15
    # of these fields required and raises "Field required" without the patch.
    apply_sdk_patches()
    signon = SamlApplicationSettingsSignOn.model_validate(
        {"defaultRelayState": None, "attributeStatements": []}
    )
    assert signon.audience is None
    assert signon.sso_acs_url is None
