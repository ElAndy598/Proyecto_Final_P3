from __future__ import annotations

from enum import Enum


class EstadoCredencial(str, Enum):
    ACTIVA = "ACTIVA"
    BLOQUEADA = "BLOQUEADA"
    EXPIRADA = "EXPIRADA"
    PERDIDA = "PERDIDA"


class EstadoPin(str, Enum):
    ACTIVO = "ACTIVO"
    BLOQUEADO = "BLOQUEADO"


class ResultadoAutenticacion(str, Enum):
    EXITO = "EXITO"
    FALLO = "FALLO"


class MetodoIngreso(str, Enum):
    CEDULA = "CEDULA"
    RFID = "RFID"
    PIN_GESTUAL = "PIN_GESTUAL"
    PATRON_GESTUAL = "PATRON_GESTUAL"


class TipoArea(str, Enum):
    LABORATORIO = "LABORATORIO"
    BODEGA = "BODEGA"
    AREA_SENSIBLE = "AREA_SENSIBLE"


class EstadoPermiso(str, Enum):
    ACTIVO = "ACTIVO"
    SUSPENDIDO = "SUSPENDIDO"
    EXPIRADO = "EXPIRADO"
