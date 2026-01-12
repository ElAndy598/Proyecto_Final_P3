class DominioError(Exception):
    """Error base del dominio de negocio."""


class ValidacionError(DominioError):
    """Entrada inválida o datos inconsistentes."""


class AutenticacionError(DominioError):
    """Fallo de autenticación (RFID/PIN/Patrón)."""


class AutorizacionError(DominioError):
    """Fallo de autorización (sin permiso / fuera de horario)."""


class RecursoNoEncontradoError(DominioError):
    """Entidad solicitada no existe en el repositorio."""


class IntegracionHardwareError(DominioError):
    """Fallo al comunicarse con webcam/Arduino u otros adaptadores."""
