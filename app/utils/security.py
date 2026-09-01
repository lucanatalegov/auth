# app/utils/security.py

import hashlib


def hash_password(value: str) -> str:
    """
    SHA-256 esadecimale della password, SENZA salt.

    Uso previsto: correlazione/audit nei log (es. riconoscere tentativi
    ripetuti con la stessa password senza loggarla in chiaro), NON idoneo
    a conservare credenziali persistenti — un hash non salato è vulnerabile
    a rainbow table per password deboli/comuni.
    """
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def mask_password(value: str) -> str:
    """Sostituisce tutti i caratteri con asterischi."""
    if not value:
        return ""
    return "*" * len(value)


def apply_password_case(value: str, case_mode: str) -> str:
    """
    Applica upper/lower/nothing alla password, PRIMA della validazione Pydantic
    (pattern, lunghezza, ecc.). case_mode atteso: "upper" | "lower" | "none"
    (qualunque altro valore, incluso mancante, si comporta come "none").
    """
    if case_mode == "upper":
        return value.upper()
    if case_mode == "lower":
        return value.lower()
    return value
