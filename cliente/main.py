from __future__ import annotations

import os
from typing import Callable, Optional
from dataclasses import dataclass
from datetime import date, datetime, time

from infraestructura.arduino_adapter import (
    ArduinoSerial,
    ArduinoSimulado,
    IActuadorAcceso,
    NullActuador,
)
from infraestructura.sensor_gestos import (
    ISensorGestos,
    SensorGestosSimulado,
    SensorGestosWebcamMediapipeTasks,
)

from negocio.auditoria import ServicioAuditoria
from negocio.caso_uso_acceso import CasoUsoAcceso
from negocio.enums import EstadoCredencial, EstadoPermiso, TipoArea
from negocio.exceptions import (
    AutenticacionError,
    AutorizacionError,
    DominioError,
    IntegracionHardwareError,
)
from negocio.modelos import (
    AreaAcceso,
    CredencialRFID,
    Estudiante,
    PatronGestual,
    PermisoAcceso,
    PinGestual,
)
from negocio.repositorios import (
    RepoAccesos,
    RepoAreas,
    RepoEstudiantes,
    RepoPatrones,
    RepoPermisos,
    RepoPins,
    RepoRFID,
    RepoRegistros,
)
from negocio.servicio_autenticacion import ServicioAutenticacion
from negocio.servicio_autorizacion import ServicioAutorizacion

@dataclass
class AppContext:
    repo_est: RepoEstudiantes
    repo_areas: RepoAreas
    repo_permisos: RepoPermisos
    repo_rfid: RepoRFID
    repo_pins: RepoPins
    repo_patrones: RepoPatrones
    repo_registros: RepoRegistros
    repo_accesos: RepoAccesos
    caso_uso: CasoUsoAcceso
    sensor: ISensorGestos
    actuador: IActuadorAcceso


# ------------------ Seed demo (opcional) ------------------

def _seed(repo_est, repo_areas, repo_permisos, repo_rfid, repo_pins, repo_pat) -> None:
    e = Estudiante(
        cedula="0102030405",
        nombres="Estud Nombre1",
        apellidos="Estud Apellido1",
        correo_institucional="stud1@udla.edu.ec",
        id_banner="B001",
        carrera="Ciberseguridad",
    )
    repo_est.guardar(e)

    a = AreaAcceso(
        id_area="LAB-101",
        nombre="Laboratorio Redes",
        tipo=TipoArea.LABORATORIO,
        ubicacion="Bloque A",
        hora_apertura=time(7, 0),
        hora_cierre=time(20, 0),
    )
    repo_areas.guardar(a)

    p = PermisoAcceso(
        id_permiso="PERM-001",
        cedula_usuario=e.cedula,
        id_area=a.id_area,
        estado=EstadoPermiso.ACTIVO,
        vigente_desde=date.today(),
        vigente_hasta=date.today().replace(year=date.today().year + 1),
    )
    repo_permisos.guardar(p)

    r = CredencialRFID(
        serial="RFID-12345",
        cedula_propietario=e.cedula,
        fecha_emision=date.today().replace(year=date.today().year - 1),
        fecha_expiracion=date.today().replace(year=date.today().year + 1),
        estado=EstadoCredencial.ACTIVA,
    )
    repo_rfid.guardar(r)

    pin = PinGestual(id_pin="PIN-001", id_area=a.id_area, secuencia_gestos=[1, 3, 7, 15])
    repo_pins.guardar(pin)

    patron = PatronGestual(
        id_patron="PAT-001",
        cedula_propietario=e.cedula,
        secuencia_gestos=[1, 1, 2, 3, 5, 8, 13, 21, 3, 1],
        fecha_captura=datetime.now(),
        tiempos_entre_gestos=None,
    )
    repo_pat.guardar(patron)


# ------------------ Helpers input ------------------

def pedir_no_vacio(etiqueta: str) -> str:
    while True:
        v = input(f"{etiqueta}: ").strip()
        if v:
            return v
        print("No puede estar vacío.")

def pedir_int_rango(etiqueta: str, minimo: int, maximo: int) -> int:
    while True:
        s = input(f"{etiqueta} ({minimo}-{maximo}): ").strip()
        try:
            n = int(s)
            if minimo <= n <= maximo:
                return n
            print("Fuera de rango.")
        except ValueError:
            print("Debe ser un número entero.")

def pedir_fecha(etiqueta: str) -> date:
    while True:
        s = input(f"{etiqueta} (YYYY-MM-DD): ").strip()
        try:
            return date.fromisoformat(s)
        except ValueError:
            print("Formato inválido. Ejemplo: 2026-01-10")


# ------------------ Infra wiring ------------------

def construir_actuador() -> IActuadorAcceso:
    puerto = os.getenv("ARDUINO_PORT")
    if not puerto:
        return NullActuador()

    try:
        return ArduinoSerial(puerto=puerto, baudrate=9600, timeout=1.0)
    except IntegracionHardwareError as ex:
        print(f"[AVISO] Arduino no disponible: {ex}")
        return ArduinoSimulado()

def construir_sensor(actuador: Optional[IActuadorAcceso]) -> ISensorGestos:
    """
    Construye el sensor REAL (webcam) con parámetros controlables por variables de entorno.

    Objetivo:
    - No simular: usar webcam + MediaPipe/Tasks.
    - Hacer PIN (4) más repetible: opción de exigir 'sin mano' entre dígitos.
    - Evitar crasheos: validación de parámetros + errores claros.
    """

    # --- Parámetros base ---
    camera_index = int(os.getenv("CAMERA_INDEX", "0"))
    mostrar_preview = os.getenv("GESTOS_PREVIEW", "1") == "1"

    stable_frames = int(os.getenv("GESTOS_STABLE_FRAMES", "10"))
    debounce_s = float(os.getenv("GESTOS_DEBOUNCE_S", "0.9"))

    # --- Regla “sin mano entre dígitos” (recomendado para PIN) ---
    # 1 = habilitado, 0 = deshabilitado
    pin_require_no_hand = os.getenv("PIN_REQUIRE_NO_HAND", "1") == "1"
    no_hand_frames = int(os.getenv("NO_HAND_FRAMES", "6"))

    debug = os.getenv("DEBUG", "0") == "1"

    # Validaciones mínimas (evitan comportamientos raros y crasheos silenciosos)
    if camera_index < 0:
        raise IntegracionHardwareError("CAMERA_INDEX inválido (debe ser >= 0).")

    if stable_frames < 1:
        raise IntegracionHardwareError("GESTOS_STABLE_FRAMES inválido (mínimo 1).")

    if debounce_s < 0:
        raise IntegracionHardwareError("GESTOS_DEBOUNCE_S inválido (debe ser >= 0).")

    if no_hand_frames < 1:
        raise IntegracionHardwareError("NO_HAND_FRAMES inválido (mínimo 1).")

    # Construcción del sensor webcam
    # Nota: arduino puede ser None (tu caso actual).
    try:
        # Si tu clase ya soporta estos parámetros en __init__, perfecto.
        sensor = SensorGestosWebcamMediapipeTasks(
            camera_index=camera_index,
            mostrar_preview=mostrar_preview,
            stable_frames=stable_frames,
            debounce_s=debounce_s,
            arduino=actuador,  # en tu diseño, el actuador puede exponer enviar_leds o similar
            pin_require_no_hand=pin_require_no_hand,
            no_hand_frames=no_hand_frames,
            debug=debug,
        )
    except TypeError:
        # Compatibilidad: si aún no agregaste esos parámetros al __init__,
        # los configuramos por atributos (sin romper nada).
        sensor = SensorGestosWebcamMediapipeTasks(
            camera_index=camera_index,
            mostrar_preview=mostrar_preview,
            stable_frames=stable_frames,
            debounce_s=debounce_s,
            arduino=actuador,
        )
        # Seteo “suave” (solo si existen en tu implementación)
        for k, v in {
            "pin_require_no_hand": pin_require_no_hand,
            "no_hand_frames": no_hand_frames,
            "debug": debug,
        }.items():
            if hasattr(sensor, k):
                setattr(sensor, k, v)

    if debug:
        print(
            "[CFG] SensorGestosWebcam configurado -> "
            f"camera_index={camera_index}, preview={mostrar_preview}, "
            f"stable_frames={stable_frames}, debounce_s={debounce_s}, "
            f"pin_require_no_hand={pin_require_no_hand}, no_hand_frames={no_hand_frames}"
        )

    return sensor


# ------------------ Acciones menú ------------------

def accion_crear_estudiante(ctx: AppContext) -> None:
    cedula = pedir_no_vacio("Cédula")
    nombres = pedir_no_vacio("Nombres")
    apellidos = pedir_no_vacio("Apellidos")
    correo = pedir_no_vacio("Correo institucional")
    banner = pedir_no_vacio("ID Banner")
    carrera = pedir_no_vacio("Carrera")

    ctx.repo_est.guardar(
        Estudiante(
            cedula=cedula,
            nombres=nombres,
            apellidos=apellidos,
            correo_institucional=correo,
            id_banner=banner,
            carrera=carrera,
        )
    )
    print("Estudiante creado/actualizado.")

def accion_listar_estudiantes(ctx: AppContext) -> None:
    ests = ctx.repo_est.listar()
    if not ests:
        print("No hay estudiantes registrados.")
        return
    for e in ests:
        print(f"- {e.cedula} | {e.nombres} {e.apellidos} | {e.carrera}")

def accion_crear_area(ctx: AppContext) -> None:
    id_area = pedir_no_vacio("ID área (ej: LAB-101)")
    nombre = pedir_no_vacio("Nombre")
    ubicacion = pedir_no_vacio("Ubicación")

    tipo = TipoArea.LABORATORIO

    hora_apertura = time(pedir_int_rango("Hora apertura", 0, 23), pedir_int_rango("Minuto apertura", 0, 59))
    hora_cierre = time(pedir_int_rango("Hora cierre", 0, 23), pedir_int_rango("Minuto cierre", 0, 59))

    ctx.repo_areas.guardar(
        AreaAcceso(
            id_area=id_area,
            nombre=nombre,
            tipo=tipo,
            ubicacion=ubicacion,
            hora_apertura=hora_apertura,
            hora_cierre=hora_cierre,
        )
    )
    print("Área creada/actualizada.")

def accion_listar_areas(ctx: AppContext) -> None:
    areas = ctx.repo_areas.listar()
    if not areas:
        print("No hay áreas registradas.")
        return
    for a in areas:
        print(f"- {a.id_area} | {a.nombre} | {a.tipo.value} | {a.ubicacion} | {a.hora_apertura}-{a.hora_cierre}")

def accion_asignar_permiso(ctx: AppContext) -> None:
    cedula = pedir_no_vacio("Cédula")
    id_area = pedir_no_vacio("ID área (ej: LAB-101)")
    id_permiso = pedir_no_vacio("ID permiso")

    est = ctx.repo_est.buscar(cedula)
    if not est:
        print("No existe ese estudiante. Cree el estudiante primero.")
        return

    area = ctx.repo_areas.buscar(id_area)
    if not area:
        print("No existe esa área. Cree el área primero.")
        return

    vigente_desde = pedir_fecha("Vigente desde")
    vigente_hasta = pedir_fecha("Vigente hasta")
    if vigente_hasta < vigente_desde:
        print("Error: vigente_hasta no puede ser menor que vigente_desde.")
        return

    print("Estado permiso: 1) ACTIVO  2) SUSPENDIDO")
    op = input("Opción: ").strip()
    estado = EstadoPermiso.ACTIVO if op != "2" else EstadoPermiso.SUSPENDIDO

    ctx.repo_permisos.guardar(
        PermisoAcceso(
            id_permiso=id_permiso,
            cedula_usuario=cedula,
            id_area=id_area,
            estado=estado,
            vigente_desde=vigente_desde,
            vigente_hasta=vigente_hasta,
        )
    )
    print("Permiso creado/actualizado.")

def accion_asignar_rfid(ctx: AppContext) -> None:
    serial = pedir_no_vacio("Serial RFID")
    cedula = pedir_no_vacio("Cédula propietaria")
    emision = pedir_fecha("Fecha emisión")
    expiracion = pedir_fecha("Fecha expiración")

    # Validación mínima: estudiante existe
    if not ctx.repo_est.buscar(cedula):
        print("No existe ese estudiante. Cree el estudiante primero.")
        return

    ctx.repo_rfid.guardar(
        CredencialRFID(
            serial=serial,
            cedula_propietario=cedula,
            fecha_emision=emision,
            fecha_expiracion=expiracion,
            estado=EstadoCredencial.ACTIVA,
        )
    )
    print("RFID asignada.")

def accion_configurar_pin(ctx: AppContext) -> None:
    id_pin = pedir_no_vacio("ID PIN (ej: PIN-001)")
    id_area = pedir_no_vacio("ID área")

    if not ctx.repo_areas.buscar(id_area):
        print("No existe esa área. Cree el área primero.")
        return

    print("Ponga la mano frente a la cámara. Registre 4 gestos.")
    sec, _ = ctx.sensor.capturar_secuencia(4, gesto_cierre=19, timeout_s=60)
    if len(sec) != 4:
        print("PIN incompleto/cancelado.")
        return

    ctx.repo_pins.guardar(PinGestual(id_pin=id_pin, id_area=id_area, secuencia_gestos=sec))
    print(f"PIN configurado: {sec}")

def accion_enrolar_patron(ctx: AppContext) -> None:
    id_pat = pedir_no_vacio("ID Patrón (ej: PAT-001)")
    cedula = pedir_no_vacio("Cédula propietaria")

    if not ctx.repo_est.buscar(cedula):
        print("No existe ese estudiante. Cree el estudiante primero.")
        return

    print("Ponga la mano frente a la cámara. Registre 10 gestos.")
    sec, tiempos = ctx.sensor.capturar_secuencia(10, gesto_cierre=19, timeout_s=120)
    if len(sec) != 10:
        print("Patrón incompleto/cancelado.")
        return

    ctx.repo_patrones.guardar(
        PatronGestual(
            id_patron=id_pat,
            cedula_propietario=cedula,
            secuencia_gestos=sec,
            fecha_captura=datetime.now(),
            tiempos_entre_gestos=tiempos,
        )
    )
    print(f"Patrón enrolado: {sec}")

def accion_intentar_acceso(ctx: AppContext) -> None:
    cedula = pedir_no_vacio("Cédula")
    id_area = pedir_no_vacio("ID área (ej: LAB-101)")
    serial = pedir_no_vacio("Serial RFID (ej: RFID-12345)")

    try:
        acceso, registro = ctx.caso_uso.solicitar_acceso(
            cedula=cedula,
            id_area=id_area,
            serial_rfid=serial,
            sensor=ctx.sensor,
            actuador=ctx.actuador,
            gesto_cierre=19,
        )
        print(f"Acceso concedido. ID acceso={acceso.id_acceso}, registro={registro.id_registro}")
    except (AutorizacionError, AutenticacionError) as ex:
        print(f"Acceso denegado: {ex}")
    except DominioError as ex:
        print(f"Error de dominio: {ex}")

def accion_ver_registros(ctx: AppContext) -> None:
    regs = ctx.repo_registros.listar()
    if not regs:
        print("No hay registros.")
        return
    for r in regs:
        print(
            f"[{r.timestamp:%Y-%m-%d %H:%M:%S}] usuario={r.cedula_usuario} area={r.id_area} "
            f"resultado={r.resultado} factores={','.join([f.value for f in r.factores])} motivo={r.motivo}"
        )

def accion_cargar_seed_y_mostrar(ctx: AppContext) -> None:
    _seed(ctx.repo_est, ctx.repo_areas, ctx.repo_permisos, ctx.repo_rfid, ctx.repo_pins, ctx.repo_patrones)
    print("Seed cargada.")
    print("\n[Seed] Estudiantes:")
    accion_listar_estudiantes(ctx)
    print("\n[Seed] Áreas:")
    accion_listar_areas(ctx)


# ------------------ Menú ------------------

def imprimir_menu() -> None:
    print("\n--- Sistema de Control de Acceso MFA ---")
    print("1) Crear estudiante")
    print("2) Listar estudiantes")
    print("3) Crear área")
    print("4) Listar áreas")
    print("5) Asignar permiso")
    print("6) Asignar RFID")
    print("7) Configurar PIN (por área)")
    print("8) Enrolar patrón (por estudiante)")
    print("9) Intentar acceso")
    print("10) Ver registros de autenticación")
    print("D) Cargar datos demo (seed) [opcional]")
    print("0) Salir")

def main_loop(ctx: AppContext) -> None:
    acciones: dict[str, Callable[[AppContext], None]] = {
        "1": accion_crear_estudiante,
        "2": accion_listar_estudiantes,
        "3": accion_crear_area,
        "4": accion_listar_areas,
        "5": accion_asignar_permiso,
        "6": accion_asignar_rfid,
        "7": accion_configurar_pin,
        "8": accion_enrolar_patron,
        "9": accion_intentar_acceso,
        "10": accion_ver_registros,
        "D": accion_cargar_seed_y_mostrar,
    }

    while True:
        imprimir_menu()
        op = input("Opción: ").strip().upper()
        if op == "0":
            print("Saliendo...")
            # Cierre elegante del serial si aplica
            if hasattr(ctx.actuador, "close"):
                try:
                    ctx.actuador.close()  # type: ignore[attr-defined]
                except Exception:
                    pass
            break

        accion = acciones.get(op)
        if not accion:
            print("Opción inválida.")
            continue

        try:
            accion(ctx)
        except DominioError as ex:
            print(f"Error de dominio: {ex}")
        except Exception as ex:
            print(f"[ERROR] {type(ex).__name__}: {ex}")

def main() -> None:
    repo_est = RepoEstudiantes()
    repo_areas = RepoAreas()
    repo_permisos = RepoPermisos()
    repo_rfid = RepoRFID()
    repo_pins = RepoPins()
    repo_patrones = RepoPatrones()
    repo_registros = RepoRegistros()
    repo_accesos = RepoAccesos()

    svc_autorizacion = ServicioAutorizacion(repo_areas=repo_areas, repo_permisos=repo_permisos)
    svc_autenticacion = ServicioAutenticacion(
        repo_rfid=repo_rfid,
        repo_pins=repo_pins,
        repo_patrones=repo_patrones,
        repo_accesos=repo_accesos,
    )
    svc_auditoria = ServicioAuditoria(repo_registros=repo_registros)

    caso_uso = CasoUsoAcceso(
        servicio_autorizacion=svc_autorizacion,
        servicio_autenticacion=svc_autenticacion,
        servicio_auditoria=svc_auditoria,
    )

    actuador = construir_actuador()
    sensor = SensorGestosWebcamMediapipeTasks(
        mostrar_preview=True,
        stable_frames=10,
        debounce_s=0.9,
        arduino=actuador,
    )

    ctx = AppContext(
        repo_est=repo_est,
        repo_areas=repo_areas,
        repo_permisos=repo_permisos,
        repo_rfid=repo_rfid,
        repo_pins=repo_pins,
        repo_patrones=repo_patrones,
        repo_registros=repo_registros,
        repo_accesos=repo_accesos,
        caso_uso=caso_uso,
        sensor=sensor,
        actuador=actuador,
    )

    main_loop(ctx)

if __name__ == "__main__":
    main()
