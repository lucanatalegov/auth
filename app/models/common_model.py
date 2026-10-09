# app/models/common_model.py
from typing import Optional

from pydantic import BaseModel, Field

from app.utils.request_context import APPLICATION_HEADER, APPLICATION_MAX_LENGTH


class ApplicationHeader(BaseModel):
    """Header facoltativo su tutti gli endpoint applicativi (non su /health):
    nome dell'applicazione chiamante, riportato nel campo "application" di
    ogni riga di log. Se assente, nei log si usa l'utente della Basic Auth."""

    x_application: Optional[str] = Field(
        None,
        alias=APPLICATION_HEADER,
        max_length=APPLICATION_MAX_LENGTH,
        description=(
            "Nome dell'applicazione chiamante, riportato nel campo `application` dei log. "
            "Facoltativo: se assente, nei log si usa l'utente della Basic Auth. "
            f"Max {APPLICATION_MAX_LENGTH} caratteri."
        ),
        json_schema_extra={"example": "sportello"},
    )
