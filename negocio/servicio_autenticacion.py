from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import uuid4

from infraestructura.arduino_adapter import IActuadorAcceso
from infraestructura.sensor_gestos import ISensorGestos

from .enums import EstadoCredencial, EstadoPin, MetodoIngreso, ResultadoAutenticacion
from .exceptions import AutenticacionError, ValidacionError
from .modelos import Acceso
from .repositorios import RepoAccesos, RepoPatrones, RepoPins, RepoRFID

@dataclass
class ServicioAutenticacion:
    repo_rfid: RepoRFID
    repo_pins: RepoPins
    repo_patrones: RepoPatrones
    repo_accesos: RepoAccesos

    max_intentos_rfid: int = 3
    max_intentos_pin: int = 3
    umbral_similitud_patron: float = 0.9

    def validar_rfid(self, *, serial: str, cedula_esperada: str, ahora: datetime) -> None:
        cred = self.repo_rfid.obtener_por_serial(serial)

        if cred.cedula_propietario != cedula_esperada:
            cred.intentos_fallidos += 1
            raise AutenticacionError("RFID no corresponde al usuario.")

        if not cred.esta_vigente(ahora.date()):
            cred.intentos_fallidos += 1
            if ahora.date() > cred.fecha_expiracion:
                cred.estado = EstadoCredencial.EXPIRADA
            raise AutenticacionError("RFID inválida/expirada/bloqueada.")

        # Reset de fallos y exito
        cred.intentos_exitosos += 1
        cred.intentos_fallidos = 0
        cred.ultimo_acceso = ahora

    def validar_pin(self, *, id_area: str, secuencia_capturada: list[int]) -> None:
        pin = self.repo_pins.obtener_por_area(id_area)

        if pin.estado == EstadoPin.BLOQUEADO:
            raise AutenticacionError("PIN gestual bloqueado para esta área.")

        if secuencia_capturada != pin.secuencia_gestos:
            pin.intentos_fallidos += 1
            if pin.intentos_fallidos >= self.max_intentos_pin:
                pin.estado = EstadoPin.BLOQUEADO
            raise AutenticacionError("PIN gestual incorrecto.")

        # exito
        pin.intentos_fallidos = 0

    def validar_patron(self, *, cedula: str, secuencia_capturada: list[int], tiempos: list[float] | None) -> None:
        patron = self.repo_patrones.obtener_por_usuario(cedula)

        if len(secuencia_capturada) == 0:
            raise ValidacionError("La secuencia capturada del patrón está vacía.")

        # Similitud discreta. Si longitudes difieren, se penaliza.
        n = max(len(patron.secuencia_gestos), len(secuencia_capturada))
        matches = 0
        for i in range(min(len(patron.secuencia_gestos), len(secuencia_capturada))):
            if patron.secuencia_gestos[i] == secuencia_capturada[i]:
                matches += 1
        similitud = matches / n

        if similitud < self.umbral_similitud_patron:
            raise AutenticacionError(
                f"Patrón gestual no coincide (similitud={similitud:.2f}, umbral={self.umbral_similitud_patron:.2f})."
            )

        # Opcional: validación ligera de timing (si ambos existen)
        if patron.tiempos_entre_gestos is not None and tiempos is not None:
            if len(patron.tiempos_entre_gestos) == len(tiempos):
                # tolerancia simple: cada delta dentro de ±40%
                for ref, got in zip(patron.tiempos_entre_gestos, tiempos):
                    if ref == 0:
                        continue
                    if not (0.6 * ref <= got <= 1.4 * ref):
                        raise AutenticacionError("Patrón gestual: timings fuera de tolerancia.")

    def autenticar_mfa(
        self,
        *,
        cedula: str,
        id_area: str,
        serial_rfid: str,
        sensor_pin: ISensorGestos,
        sensor_patron: ISensorGestos,
        actuador: IActuadorAcceso,
        gesto_cierre: int | None = 0,
    ) -> Acceso:
        """Ejecuta MFA completo. Lanza excepciones si falla.
        Nota: la autorización (permiso/horario) se maneja en otro servicio.
        """
        ahora = datetime.now()

        # Factor 1: RFID
        self.validar_rfid(serial=serial_rfid, cedula_esperada=cedula, ahora=ahora)

        # Factor 2: PIN gestual (4)
        sec_pin, _ = sensor_pin.capturar_secuencia(4, gesto_cierre=gesto_cierre)
        if len(sec_pin) != 4:
            raise AutenticacionError("PIN gestual incompleto: captura cancelada por cierre.")
        self.validar_pin(id_area=id_area, secuencia_capturada=sec_pin)

        # Factor 3: Patrón biométrico (10)
        sec_pat, tiempos = sensor_patron.capturar_secuencia(10, gesto_cierre=gesto_cierre)
        if len(sec_pat) != 10:
            raise AutenticacionError("Patrón gestual incompleto: captura cancelada por cierre.")
        self.validar_patron(cedula=cedula, secuencia_capturada=sec_pat, tiempos=tiempos)

        # Si aqui, todo bien
        actuador.indicar_exito()
        actuador.abrir_puerta()

        acceso = Acceso(
            id_acceso=str(uuid4()),
            cedula_usuario=cedula,
            id_area=id_area,
            fecha_entrada=ahora,
            registro_exitoso_id="",
        )
        self.repo_accesos.agregar(acceso)
        return acceso
