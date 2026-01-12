from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .exceptions import AutorizacionError
from .repositorios import RepoAreas, RepoPermisos


@dataclass
class ServicioAutorizacion:
    repo_areas: RepoAreas
    repo_permisos: RepoPermisos

    def verificar_permiso_y_horario(self, *, cedula: str, id_area: str, ahora: datetime):
        area = self.repo_areas.obtener(id_area)
        print(f"[DEBUG] ahora={ahora.time()} apertura={area.hora_apertura} cierre={area.hora_cierre}")

        if not area.es_accesible_ahora(ahora):
            raise AutorizacionError("Acceso denegado: fuera de horario permitido.")

        permiso = self.repo_permisos.buscar_permiso(cedula=cedula, id_area=id_area, hoy=ahora.date())
        if permiso is None:
            raise AutorizacionError("Acceso denegado: el usuario no tiene permiso vigente para esta área.")

        return permiso
