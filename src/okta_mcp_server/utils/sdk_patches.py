# Local patches to the pinned okta SDK (3.4.1).
#
# okta SDK 3.4.1 is too strict for the live data Springboard's prod org returns,
# and `list_applications` fails (or silently returns zero apps) without these
# patches. Two independent problems, both fixed here:
#
# 1. Application.features enum: the SDK hardcodes a feature allow-list and raises
#    on anything outside it. Okta has since shipped flags the SDK doesn't know
#    (e.g. AUTO_CONFIRM_IMPORTS, on several prod SCIM apps). The validator is an
#    ordinary Python function pydantic invokes at runtime, so swapping its
#    __code__ for a passthrough fixes Application and every sign-on-mode subclass
#    at once (they share the inherited validator). No model_rebuild needed.
#
# 2. SamlApplicationSettingsSignOn over-required fields: the SDK marks ~15 signOn
#    fields (audience, recipient, destination, ...) as required, but Okta returns
#    SAML apps with only a partial signOn block, so deserialization raises
#    "Field required". We give those fields a default of None (making them
#    optional) and model_rebuild so the recompiled core schema accepts partial
#    objects.
#
# Both are the same class of bug: Okta returns partial objects the SDK's model
# refuses to parse. This is a read/debug tool, so accepting partial objects is
# the right tradeoff.
#
# NOTE for future re-vendoring: if the okta SDK is bumped, re-check whether these
# patches are still needed and whether the model/validator layout changed.

from loguru import logger

_PATCHED = False


def _passthrough_features_validate_enum(cls, value):
    return value


def _relax_features_enum() -> None:
    """Make Application.features accept unknown enum values instead of raising."""
    from okta.models.application import Application

    dec = Application.__pydantic_decorators__.field_validators.get("features_validate_enum")
    if dec is None:
        logger.warning(
            "okta SDK Application.features_validate_enum not found; skipping enum patch "
            "(SDK layout may have changed). Apps with unknown feature values will still fail to parse."
        )
        return

    func = getattr(dec.func, "__func__", dec.func)
    func.__code__ = _passthrough_features_validate_enum.__code__
    logger.debug("Applied okta SDK patch: relaxed Application.features enum validation")


def _relax_required_fields(model) -> int:
    """Give every required-without-default field on `model` a None default.

    Returns the number of fields relaxed. Caller rebuilds the model.
    """
    from pydantic_core import PydanticUndefined

    relaxed = 0
    for field in model.model_fields.values():
        if field.default is PydanticUndefined and field.default_factory is None:
            field.default = None
            relaxed += 1
    return relaxed


def _relax_saml_signon_required() -> None:
    """Make over-required SamlApplicationSettingsSignOn fields optional."""
    from okta.models.saml_application_settings_sign_on import SamlApplicationSettingsSignOn

    relaxed = _relax_required_fields(SamlApplicationSettingsSignOn)
    if relaxed:
        SamlApplicationSettingsSignOn.model_rebuild(force=True)
        logger.debug(f"Applied okta SDK patch: relaxed {relaxed} required SamlApplicationSettingsSignOn fields")


def apply_sdk_patches() -> None:
    """Relax okta SDK strictness so list_applications parses prod data. Idempotent."""
    global _PATCHED
    if _PATCHED:
        return

    # Each patch is independent — one failing must not block the other, and a
    # failure must never crash server startup.
    for patch in (_relax_features_enum, _relax_saml_signon_required):
        try:
            patch()
        except Exception as exc:
            logger.warning(
                f"Failed to apply okta SDK patch {patch.__name__}: {type(exc).__name__}: {exc}. "
                "list_applications may still fail to parse some prod apps."
            )

    _PATCHED = True
