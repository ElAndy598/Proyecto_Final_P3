from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from time import sleep
from typing import Optional

from negocio.exceptions import IntegracionHardwareError


class IActuadorAcceso(ABC):
    """Contrato para actuadores: LEDs / cerradura / alarma."""

    @abstractmethod
    def indicar_exito(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def indicar_fallo(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def abrir_puerta(self) -> None:
        raise NotImplementedError


@dataclass
class ArduinoSimulado(IActuadorAcceso):
    """Simula Arduino mostrando acciones en consola."""

    def indicar_exito(self) -> None:
        print("[ARDUINO] LED VERDE: acceso concedido")

    def indicar_fallo(self) -> None:
        print("[ARDUINO] LED ROJO: acceso denegado")

    def abrir_puerta(self) -> None:
        print("[ARDUINO] PUERTA ABIERTA (simulado)")


class ArduinoSerial(IActuadorAcceso):
    """
    Implementación real con pyserial.

    IMPORTANTE: .ino actual lee SIEMPRE 5 bytes (uno por dedo) y enciende/apaga LEDs.
    Por eso aquí 'enviar_leds()' manda exactamente 5 bytes.
    """

    def __init__(self, *, puerto: str, baudrate: int = 9600, timeout: float = 1.0) -> None:
        try:
            import serial  # type: ignore
        except Exception as ex:
            raise IntegracionHardwareError(f"pyserial no disponible: {ex}")

        try:
            self._serial = serial.Serial(port=puerto, baudrate=baudrate, timeout=timeout)
        except Exception as ex:
            raise IntegracionHardwareError(f"No se pudo abrir puerto {puerto}: {ex}")

        # Muchas placas reinician al abrir serial
        sleep(2.0)

    def close(self) -> None:
        try:
            self._serial.close()
        except Exception:
            pass

    def enviar_leds(self, dedos: list[int]) -> None:
        """Envía 5 bytes [thumb,index,middle,ring,pinky] con valores 0/1."""
        if len(dedos) != 5:
            raise IntegracionHardwareError("Arduino requiere exactamente 5 valores (5 dedos).")
        if any(d not in (0, 1) for d in dedos):
            raise IntegracionHardwareError("Cada dedo debe ser 0 o 1.")

        try:
            self._serial.write(bytes(dedos))
            self._serial.flush()
        except Exception as ex:
            raise IntegracionHardwareError(f"Fallo enviando datos al Arduino: {ex}")

    # Señales simples usando SOLO el protocolo actual (5 bytes)
    def indicar_exito(self) -> None:
        # Parpadeo "todo encendido" 2 veces
        for _ in range(2):
            self.enviar_leds([1, 1, 1, 1, 1])
            sleep(0.15)
            self.enviar_leds([0, 0, 0, 0, 0])
            sleep(0.15)

    def indicar_fallo(self) -> None:
        # Parpadeo alternado 2 veces
        for _ in range(2):
            self.enviar_leds([1, 0, 1, 0, 1])
            sleep(0.15)
            self.enviar_leds([0, 1, 0, 1, 0])
            sleep(0.15)
        self.enviar_leds([0, 0, 0, 0, 0])

    def abrir_puerta(self) -> None:
        # Con tu .ino actual no hay “cerradura”, así que lo representamos con patrón
        self.enviar_leds([1, 1, 1, 1, 1])
        sleep(0.4)
        self.enviar_leds([0, 0, 0, 0, 0])

class NullActuador(IActuadorAcceso):
    def indicar_exito(self) -> None:
        pass
    def indicar_fallo(self) -> None:
        pass
    def abrir_puerta(self) -> None:
        pass
    def enviar_leds(self, dedos: list[int]) -> None:
        pass

