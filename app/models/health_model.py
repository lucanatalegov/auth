# app/models/health_model.py
from pydantic import BaseModel, Field


class HealthQuery(BaseModel):
    """Query string della GET /health."""

    debug: bool = Field(
        False,
        description=(
            "Se true, il check SOAP esegue una vera richiesta di login "
            "(health.soap_check_login + password fittizia) verso il servizio "
            "esterno reale. Se false (default), verifica solo che il servizio "
            "sia in ascolto (connessione TCP, nessuna richiesta inviata)."
        ),
    )


class HealthResponse(BaseModel):
    status:       str   = Field(..., description="UP | DEGRADED | DOWN")
    version:      str   = Field(..., description="release.patch.build")
    elapsed_time: float = Field(..., description="Tempo impiegato dal server per evadere la richiesta, in millisecondi.")
    postgres:     dict  = Field(..., description="Statistiche PostgreSQL")
    soap:         dict  = Field(..., description="Raggiungibilità servizio SOAP esterno")
