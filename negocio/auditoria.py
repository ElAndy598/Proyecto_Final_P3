from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import uuid4

from .enums import MetodoIngreso, ResultadoAutenticacion
from .modelos import RegistroAutenticacion
from .repositorios import RepoRegistros


@dataclass
class ServicioAuditoria:
    repo_registros: RepoRegistros

    def registrar(
        self,
        *,
        cedula_usuario: str,
        id_area: str,
        metodo: MetodoIngreso,
        factores: list[MetodoIngreso],
        resultado: ResultadoAutenticacion,
        motivo: str = "",
        id_permiso: str | None = None,
    ) -> RegistroAutenticacion:
        r = RegistroAutenticacion(
            id_registro=str(uuid4()),
            timestamp=datetime.now(),
            cedula_usuario=cedula_usuario,
            id_area=id_area,
            metodo=metodo,
            factores=factores,
            resultado=resultado,
            motivo=motivo,
            id_permiso=id_permiso,
        )
        self.repo_registros.agregar(r)
        return r
