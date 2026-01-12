from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Dict, List, Optional

from .exceptions import RecursoNoEncontradoError
from .modelos import (
    Acceso,
    AreaAcceso,
    CredencialRFID,
    Estudiante,
    PermisoAcceso,
    PinGestual,
    PatronGestual,
    RegistroAutenticacion,
)

@dataclass
class RepoEstudiantes:
    _data: Dict[str, Estudiante] = field(default_factory=dict)

    def guardar(self, e: Estudiante) -> None:
        self._data[e.cedula] = e

    def obtener(self, cedula: str) -> Estudiante:
        try:
            return self._data[cedula]
        except KeyError as ex:
            raise RecursoNoEncontradoError(f"Estudiante no encontrado: {cedula}") from ex

    def buscar(self, cedula: str) -> Optional[Estudiante]:
        return self._data.get(cedula)

    def listar(self) -> List[Estudiante]:
        return list(self._data.values())

@dataclass
class RepoAreas:
    _data: Dict[str, AreaAcceso] = field(default_factory=dict)

    def guardar(self, a: AreaAcceso) -> None:
        self._data[a.id_area] = a

    def obtener(self, id_area: str) -> AreaAcceso:
        try:
            return self._data[id_area]
        except KeyError as ex:
            raise RecursoNoEncontradoError(f"Area no encontrada: {id_area}") from ex

    def buscar(self, id_area: str) -> Optional[AreaAcceso]:
        return self._data.get(id_area)

    def listar(self) -> List[AreaAcceso]:
        return list(self._data.values())


@dataclass
class RepoRFID:
    _data: Dict[str, CredencialRFID] = field(default_factory=dict)  # serial -> credencial

    def guardar(self, c: CredencialRFID) -> None:
        self._data[c.serial] = c

    def obtener_por_serial(self, serial: str) -> CredencialRFID:
        try:
            return self._data[serial]
        except KeyError as ex:
            raise RecursoNoEncontradoError(f"Credencial RFID no encontrada: {serial}") from ex

    def listar(self) -> List[CredencialRFID]:
        return list(self._data.values())

@dataclass
class RepoPins:
    _data: Dict[str, PinGestual] = field(default_factory=dict)  # id_area -> pin

    def guardar(self, p: PinGestual) -> None:
        self._data[p.id_area] = p

    def obtener_por_area(self, id_area: str) -> PinGestual:
        try:
            return self._data[id_area]
        except KeyError as ex:
            raise RecursoNoEncontradoError(f"PIN no encontrado para área: {id_area}") from ex

    def listar(self) -> list[PinGestual]:
        return list(self._data.values())


@dataclass
class RepoPatrones:
    _data: Dict[str, PatronGestual] = field(default_factory=dict)  # cedula -> patron

    def guardar(self, p: PatronGestual) -> None:
        self._data[p.cedula_propietario] = p

    def obtener_por_usuario(self, cedula: str) -> PatronGestual:
        try:
            return self._data[cedula]
        except KeyError as ex:
            raise RecursoNoEncontradoError(f"Patrón no encontrado para usuario: {cedula}") from ex

    def listar(self) -> List[PatronGestual]:
        return list(self._data.values())

@dataclass
class RepoPermisos:
    _data: Dict[str, PermisoAcceso] = field(default_factory=dict)  # id_permiso -> permiso

    def guardar(self, p: PermisoAcceso) -> None:
        self._data[p.id_permiso] = p

    def buscar_permiso(self, cedula: str, id_area: str, hoy: date) -> Optional[PermisoAcceso]:
        for p in self._data.values():
            if p.cedula_usuario == cedula and p.id_area == id_area and p.es_vigente(hoy):
                return p
        return None

    def listar(self) -> List[PermisoAcceso]:
        return list(self._data.values())

@dataclass
class RepoRegistros:
    _data: List[RegistroAutenticacion] = field(default_factory=list)

    def agregar(self, r: RegistroAutenticacion) -> None:
        self._data.append(r)

    def listar(self) -> List[RegistroAutenticacion]:
        return list(self._data)

    def listar_por_usuario(self, cedula: str) -> List[RegistroAutenticacion]:
        return [r for r in self._data if r.cedula_usuario == cedula]

    def listar_por_area(self, id_area: str) -> List[RegistroAutenticacion]:
        return [r for r in self._data if r.id_area == id_area]


@dataclass
class RepoAccesos:
    _data: List[Acceso] = field(default_factory=list)

    def agregar(self, a: Acceso) -> None:
        self._data.append(a)

    def listar(self) -> List[Acceso]:
        return list(self._data)
