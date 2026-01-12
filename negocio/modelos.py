from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, time, date
from typing import List, Optional

from .enums import (
    EstadoCredencial,
    EstadoPermiso,
    EstadoPin,
    MetodoIngreso,
    ResultadoAutenticacion,
    TipoArea,
)
from .exceptions import ValidacionError


def _require_non_empty(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidacionError(f"{field_name} no puede estar vacío.")
    return value.strip()

def _require_int_range(value: int, field_name: str, min_v: int, max_v: int) -> int:
    if not isinstance(value, int) or not (min_v <= value <= max_v):
        raise ValidacionError(f"{field_name} debe estar entre {min_v} y {max_v}.")
    return value

@dataclass
class Estudiante:
    cedula: str
    nombres: str
    apellidos: str
    correo_institucional: str
    id_banner: str
    carrera: str
    estado: str = "ACTIVO"

    def __post_init__(self) -> None:
        self.cedula = _require_non_empty(self.cedula, "cédula")
        if not self.cedula.isdigit():
            raise ValidacionError("cédula debe contener solo dígitos.")
        # Nota: no valida algoritmo de cédula para no bloquear datos de prueba.

        self.nombres = _require_non_empty(self.nombres, "nombres")
        self.apellidos = _require_non_empty(self.apellidos, "apellidos")
        self.correo_institucional = _require_non_empty(self.correo_institucional, "correo institucional")
        self.id_banner = _require_non_empty(self.id_banner, "ID Banner")
        self.carrera = _require_non_empty(self.carrera, "carrera")

@dataclass
class AreaAcceso:
    id_area: str
    nombre: str
    tipo: TipoArea
    ubicacion: str
    hora_apertura: time
    hora_cierre: time

    def __post_init__(self) -> None:
        self.id_area = _require_non_empty(self.id_area, "id_area")
        self.nombre = _require_non_empty(self.nombre, "nombre")
        self.ubicacion = _require_non_empty(self.ubicacion, "ubicación")
        if not isinstance(self.hora_apertura, time) or not isinstance(self.hora_cierre, time):
            raise ValidacionError("hora_apertura y hora_cierre deben ser tipo datetime.time.")

    def es_accesible_ahora(self, ahora: datetime) -> bool:
        t = ahora.time()
        # Caso simple: apertura < cierre (mismo día)
        return self.hora_apertura <= t <= self.hora_cierre

@dataclass
class CredencialRFID:
    serial: str
    cedula_propietario: str
    fecha_emision: date
    fecha_expiracion: date
    estado: EstadoCredencial = EstadoCredencial.ACTIVA
    intentos_fallidos: int = 0
    intentos_exitosos: int = 0
    ultimo_acceso: Optional[datetime] = None

    def __post_init__(self) -> None:
        self.serial = _require_non_empty(self.serial, "serial RFID")
        self.cedula_propietario = _require_non_empty(self.cedula_propietario, "cédula propietario")
        if self.fecha_expiracion < self.fecha_emision:
            raise ValidacionError("fecha_expiracion no puede ser anterior a fecha_emision.")

    def esta_vigente(self, hoy: date) -> bool:
        if self.estado in (EstadoCredencial.BLOQUEADA, EstadoCredencial.PERDIDA):
            return False
        if hoy > self.fecha_expiracion:
            return False
        return True

@dataclass
class PinGestual:
    id_pin: str
    id_area: str
    secuencia_gestos: List[int]  # cada gesto: 0..31
    estado: EstadoPin = EstadoPin.ACTIVO
    intentos_fallidos: int = 0
    max_intentos: int = 3

    def __post_init__(self) -> None:
        self.id_pin = _require_non_empty(self.id_pin, "id_pin")
        self.id_area = _require_non_empty(self.id_area, "id_area")
        if len(self.secuencia_gestos) == 0:
            raise ValidacionError("secuencia_gestos no puede estar vacía.")
        self.secuencia_gestos = [
            _require_int_range(g, "gesto", 0, 31) for g in self.secuencia_gestos
        ]
        self.max_intentos = _require_int_range(self.max_intentos, "max_intentos", 1, 10)


@dataclass
class PatronGestual:
    id_patron: str
    cedula_propietario: str
    secuencia_gestos: List[int]  # 0..31
    fecha_captura: datetime

    # Opcional: tiempos (simulan biometría sin prometer visión compleja)
    tiempos_entre_gestos: Optional[List[float]] = None

    def __post_init__(self) -> None:
        self.id_patron = _require_non_empty(self.id_patron, "id_patron")
        self.cedula_propietario = _require_non_empty(self.cedula_propietario, "cédula propietario")
        if len(self.secuencia_gestos) == 0:
            raise ValidacionError("secuencia_gestos del patrón no puede estar vacía.")
        self.secuencia_gestos = [
            _require_int_range(g, "gesto", 0, 31) for g in self.secuencia_gestos
        ]
        if self.tiempos_entre_gestos is not None:
            if len(self.tiempos_entre_gestos) != max(0, len(self.secuencia_gestos) - 1):
                raise ValidacionError(
                    "tiempos_entre_gestos debe tener longitud len(secuencia)-1."
                )
            if any(t < 0 for t in self.tiempos_entre_gestos):
                raise ValidacionError("tiempos_entre_gestos no puede contener valores negativos.")

@dataclass
class PermisoAcceso:
    id_permiso: str
    cedula_usuario: str
    id_area: str
    estado: EstadoPermiso = EstadoPermiso.ACTIVO
    vigente_desde: Optional[date] = None
    vigente_hasta: Optional[date] = None

    def __post_init__(self) -> None:
        self.id_permiso = _require_non_empty(self.id_permiso, "id_permiso")
        self.cedula_usuario = _require_non_empty(self.cedula_usuario, "cédula usuario")
        self.id_area = _require_non_empty(self.id_area, "id_area")
        if self.vigente_desde and self.vigente_hasta and self.vigente_hasta < self.vigente_desde:
            raise ValidacionError("vigente_hasta no puede ser anterior a vigente_desde.")

    def es_vigente(self, hoy: date) -> bool:
        if self.estado != EstadoPermiso.ACTIVO:
            return False
        if self.vigente_desde and hoy < self.vigente_desde:
            return False
        if self.vigente_hasta and hoy > self.vigente_hasta:
            return False
        return True

@dataclass
class RegistroAutenticacion:
    id_registro: str
    timestamp: datetime
    cedula_usuario: str
    id_area: str
    metodo: MetodoIngreso
    factores: List[MetodoIngreso] = field(default_factory=list)
    resultado: ResultadoAutenticacion = ResultadoAutenticacion.FALLO
    motivo: str = ""
    id_permiso: Optional[str] = None

    def __post_init__(self) -> None:
        self.id_registro = _require_non_empty(self.id_registro, "id_registro")
        self.cedula_usuario = _require_non_empty(self.cedula_usuario, "cédula usuario")
        self.id_area = _require_non_empty(self.id_area, "id_area")

@dataclass
class Acceso:
    id_acceso: str
    cedula_usuario: str
    id_area: str
    fecha_entrada: datetime
    registro_exitoso_id: str
    fecha_salida: Optional[datetime] = None

    def __post_init__(self) -> None:
        self.id_acceso = _require_non_empty(self.id_acceso, "id_acceso")
        self.cedula_usuario = _require_non_empty(self.cedula_usuario, "cédula usuario")
        self.id_area = _require_non_empty(self.id_area, "id_area")
        self.registro_exitoso_id = _require_non_empty(self.registro_exitoso_id, "registro_exitoso_id")
