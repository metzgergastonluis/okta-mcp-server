# Local patches to the pinned okta SDK (3.4.1).
#
# okta SDK 3.4.1's Application.features enum validator hardcodes a feature
# allow-list and raises ValueError on anything outside it. Okta has since
# shipped feature flags the SDK doesn't know about (e.g. AUTO_CONFIRM_IMPORTS,
# present on several Springboard prod SCIM apps), which makes list_applications
# fail or silently return zero apps. We relax that one validator to pass unknown
# values through instead of raising.
#
# The validator is an ordinary Python function pydantic invokes at runtime, so
# swapping its __code__ for a passthrough fixes Application and every sign-on-mode
# subclass at once (they share the inherited validator). No model_rebuild needed.
#
# NOTE for future re-vendoring: if the okta SDK is bumped, re-check whether this
# patch is still needed and whether the validator's location/name changed.

from loguru import logger

_PATCHED = False


def _passthrough_features_validate_enum(cls, value):
    return value


def apply_sdk_patches() -> None:
    """Relax okta SDK Application.features enum validation. Idempotent."""
    global _PATCHED
    if _PATCHED:
        return

    try:
        from okta.models.application import Application

        decorators = Application.__pydantic_decorators__.field_validators
        dec = decorators.get("features_validate_enum")
        if dec is None:
            logger.warning(
                "okta SDK Application.features_validate_enum not found; "
                "skipping SDK patch (SDK layout may have changed)"
                " Apps with unknown feature values will still fail to parse."
            )
            _PATCHED = True
            return

        func = getattr(dec.func, "__func__", dec.func)
        func.__code__ = _passthrough_features_validate_enum.__code__
        logger.debug("Applied okta SDK patch: relaxed Application.features enum validation")
    except Exception as exc:  # never let a patch failure crash server startup
        logger.warning(f"Failed to apply okta SDK patch: {type(exc).__name__}: {exc} Validator left unpatched; apps with unknown feature values will still fail to parse.")

    _PATCHED = True
