from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import uuid4

from infraestructura.arduino_adapter import IActuadorAcceso
from infraestructura.sensor_gestos import ISensorGestos

from .auditoria import ServicioAuditoria
from .enums import MetodoIngreso, ResultadoAutenticacion
from .exceptions import AutenticacionError, AutorizacionError
from .servicio_autenticacion import ServicioAutenticacion
from .servicio_autorizacion import ServicioAutorizacion


@dataclass
class CasoUsoAcceso:
    servicio_autorizacion: ServicioAutorizacion
    servicio_autenticacion: ServicioAutenticacion
    servicio_auditoria: ServicioAuditoria

    def solicitar_acceso(
            self,
            *,
            cedula: str,
            id_area: str,
            serial_rfid: str,
            sensor: ISensorGestos,
            actuador: IActuadorAcceso,
            gesto_cierre: int | None = 0,
    ):
        ahora = datetime.now()
        factores_ok: list[MetodoIngreso] = []
        permiso = None

        try:
            # 1) Autorización (DENTRO del try para poder registrar fallos)
            permiso = self.servicio_autorizacion.verificar_permiso_y_horario(
                cedula=cedula, id_area=id_area, ahora=ahora
            )

            # 2) RFID
            self.servicio_autenticacion.validar_rfid(
                serial=serial_rfid, cedula_esperada=cedula, ahora=ahora
            )
            factores_ok.append(MetodoIngreso.RFID)

            # 3) PIN (4)
            sec_pin, _ = sensor.capturar_secuencia(4, gesto_cierre=gesto_cierre)
            if len(sec_pin) != 4:
                raise AutenticacionError("PIN gestual incompleto: cancelado por cierre.")
            self.servicio_autenticacion.validar_pin(id_area=id_area, secuencia_capturada=sec_pin)
            factores_ok.append(MetodoIngreso.PIN_GESTUAL)

            # 4) Patrón (10)
            sec_pat, tiempos = sensor.capturar_secuencia(10, gesto_cierre=gesto_cierre)
            if len(sec_pat) != 10:
                raise AutenticacionError("Patrón incompleto: cancelado por cierre.")
            self.servicio_autenticacion.validar_patron(
                cedula=cedula, secuencia_capturada=sec_pat, tiempos=tiempos
            )
            factores_ok.append(MetodoIngreso.PATRON_GESTUAL)

            # 5) Éxito: actuador + auditoría + acceso
            actuador.indicar_exito()
            actuador.abrir_puerta()

            registro = self.servicio_auditoria.registrar(
                cedula_usuario=cedula,
                id_area=id_area,
                metodo=MetodoIngreso.RFID,
                factores=factores_ok,
                resultado=ResultadoAutenticacion.EXITO,
                motivo="",
                id_permiso=permiso.id_permiso,
            )

            from .modelos import Acceso

            acceso = Acceso(
                id_acceso=str(uuid4()),
                cedula_usuario=cedula,
                id_area=id_area,
                fecha_entrada=ahora,
                registro_exitoso_id=registro.id_registro,
            )
            self.servicio_autenticacion.repo_accesos.agregar(acceso)

            return acceso, registro

        except (AutenticacionError, AutorizacionError) as ex:
            actuador.indicar_fallo()
            self.servicio_auditoria.registrar(
                cedula_usuario=cedula,
                id_area=id_area,
                metodo=MetodoIngreso.RFID,
                factores=factores_ok,
                resultado=ResultadoAutenticacion.FALLO,
                motivo=str(ex),
                id_permiso=permiso.id_permiso if permiso else None,
            )
            raise
