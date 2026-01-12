from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Tuple

from negocio.exceptions import IntegracionHardwareError, ValidacionError


class ISensorGestos(ABC):
    """Contrato para capturar gestos.

    Un gesto se representa como entero 0..31 (bitmask 5 dedos).
    """

    @abstractmethod
    def capturar_secuencia(
        self,
        cantidad: int,
        *,
        gesto_cierre: int | None = None,
        timeout_s: float | None = None,
    ) -> Tuple[List[int], List[float] | None]:
        raise NotImplementedError


@dataclass
class SensorGestosSimulado(ISensorGestos):
    """Simulado simple (útil si no hay webcam)."""
    secuencias: list[list[int]]

    def capturar_secuencia(
        self,
        cantidad: int,
        *,
        gesto_cierre: int | None = None,
        timeout_s: float | None = None,
    ) -> Tuple[List[int], List[float] | None]:
        if cantidad <= 0:
            raise ValidacionError("cantidad debe ser > 0")
        if not self.secuencias:
            raise IntegracionHardwareError("No hay secuencias simuladas configuradas.")
        seq = self.secuencias.pop(0)
        return seq[:cantidad], None


class SensorGestosWebcamMediapipeTasks(ISensorGestos):
    """
    Captura gestos desde webcam con MediaPipe Tasks (HandLandmarker .task).

    - Convierte dedos [thumb,index,middle,ring,pinky] (0/1) a bitmask 0..31.
    - Si se pasa `arduino` y expone `enviar_leds(dedos: list[int])`, refleja LEDs.
    """

    def __init__(
        self,
        *,
        camera_index: int = 0,
        mostrar_preview: bool = True,
        stable_frames: int = 5,
        debounce_s: float = 0.6,
        flip: bool = True,
        model_path: str | None = None,
        arduino: object | None = None,
    ) -> None:
        self.camera_index = camera_index
        self.mostrar_preview = mostrar_preview
        self.stable_frames = max(1, stable_frames)
        self.debounce_s = max(0.0, debounce_s)
        self.flip = flip
        self.arduino = arduino

        # Imports “tardíos” para no reventar el proyecto si faltan dependencias.
        try:
            import cv2  # type: ignore
        except Exception as ex:
            raise IntegracionHardwareError(f"No se pudo importar opencv (cv2): {ex}")

        try:
            import mediapipe as mp  # type: ignore
            from mediapipe.tasks import python  # type: ignore
            from mediapipe.tasks.python import vision  # type: ignore
        except Exception as ex:
            raise IntegracionHardwareError(f"No se pudo importar mediapipe/tasks: {ex}")

        self._cv2 = cv2
        self._mp = mp
        self._mp_python = python
        self._mp_vision = vision

        self.model_path = self._resolver_model_path(model_path)

    def _resolver_model_path(self, model_path: str | None) -> str:
        if model_path:
            p = Path(model_path).expanduser().resolve()
            if not p.exists():
                raise IntegracionHardwareError(f"No existe el model .task en: {p}")
            return str(p)

        # Busca ../models/hand_landmarker.task relativo a src/infraestructura/sensor_gestos.py
        base = Path(__file__).resolve()
        # .../src/infraestructura/sensor_gestos.py -> .../ (proyecto)
        proyecto = base.parents[2] if len(base.parents) >= 3 else base.parent
        candidato = (proyecto / "models" / "hand_landmarker.task").resolve()
        if not candidato.exists():
            raise IntegracionHardwareError(
                "No se encontró models/hand_landmarker.task.\n"
                f"Ruta esperada: {candidato}\n"
                "Crea la carpeta models/ en la raíz del proyecto y coloca ahí el archivo .task."
            )
        return str(candidato)

    @staticmethod
    def _dedos_a_bitmask(dedos: list[int]) -> int:
        # [thumb,index,middle,ring,pinky] => 1,2,4,8,16
        return dedos[0] * 1 + dedos[1] * 2 + dedos[2] * 4 + dedos[3] * 8 + dedos[4] * 16

    def _detectar_dedos(self, lm, handedness: str) -> list[int]:
        """
        lm: lista de landmarks (0..20) con x,y normalizados.
        handedness: "Right"/"Left"

        Mejora: aplica "márgenes" (deadzone) para reducir falsos positivos.
        """
        # Índices estándar MediaPipe Hands
        TH_TIP, TH_IP = 4, 3
        IDX_TIP, IDX_PIP = 8, 6
        MID_TIP, MID_PIP = 12, 10
        RING_TIP, RING_PIP = 16, 14
        PINK_TIP, PINK_PIP = 20, 18

        # --- Ajustes (calibración) ---
        # Si se incluye el dedo medio cuando solo levanta índice, SUBIR MARGEN_Y.
        MARGEN_Y = 0.04
        # Para pulgar
        MARGEN_X = 0.03

        dedos = [0, 0, 0, 0, 0]

        # Pulgar (x) con margen
        dx_thumb = lm[TH_TIP].x - lm[TH_IP].x
        if handedness.lower() == "right":
            dedos[0] = 1 if dx_thumb > MARGEN_X else 0
        else:
            # En left, se invierte
            dedos[0] = 1 if (-dx_thumb) > MARGEN_X else 0

        # Otros dedos (y) con margen
        dedos[1] = 1 if lm[IDX_TIP].y < (lm[IDX_PIP].y - MARGEN_Y) else 0
        dedos[2] = 1 if lm[MID_TIP].y < (lm[MID_PIP].y - MARGEN_Y) else 0
        dedos[3] = 1 if lm[RING_TIP].y < (lm[RING_PIP].y - MARGEN_Y) else 0
        dedos[4] = 1 if lm[PINK_TIP].y < (lm[PINK_PIP].y - MARGEN_Y) else 0

        return dedos

    def capturar_secuencia(
        self,
        cantidad: int,
        *,
        gesto_cierre: int | None = None,
        timeout_s: float | None = None,
    ) -> Tuple[List[int], List[float] | None]:
        if cantidad <= 0:
            raise ValidacionError("cantidad debe ser > 0")

        cv2 = self._cv2
        mp = self._mp
        vision = self._mp_vision
        python = self._mp_python

        # Landmarker
        base_options = python.BaseOptions(model_asset_path=self.model_path)
        options = vision.HandLandmarkerOptions(
            base_options=base_options,
            running_mode=vision.RunningMode.VIDEO,
            num_hands=1,
            min_hand_detection_confidence=0.6,
            min_hand_presence_confidence=0.6,
            min_tracking_confidence=0.6,
        )
        landmarker = vision.HandLandmarker.create_from_options(options)

        # Cámara (en Windows, CAP_DSHOW evita bloqueos)
        cap = cv2.VideoCapture(self.camera_index, cv2.CAP_DSHOW)

        if not cap.isOpened():
            landmarker.close()
            raise IntegracionHardwareError("No se pudo abrir la webcam (isOpened=False).")

        # Warm-up frames
        ok = False
        for _ in range(30):
            ok, _ = cap.read()
            if ok:
                break
        if not ok:
            cap.release()
            landmarker.close()
            raise IntegracionHardwareError("La webcam abrió, pero no entrega frames (cap.read() siempre False).")

        secuencia: List[int] = []
        tiempos: List[float] = []
        t_prev: datetime | None = None

        last_accept_ts: datetime | None = None
        stable_count = 0
        current_candidate: int | None = None

        start_ts = datetime.now()
        t0_ms = int(start_ts.timestamp() * 1000)

        # conexiones para dibujar (pairs)
        HAND_CONNECTIONS = [
            (0, 1), (1, 2), (2, 3), (3, 4),
            (0, 5), (5, 6), (6, 7), (7, 8),
            (5, 9), (9, 10), (10, 11), (11, 12),
            (9, 13), (13, 14), (14, 15), (15, 16),
            (13, 17), (17, 18), (18, 19), (19, 20),
            (0, 17)
        ]

        win = "SensorGestosWebcam"
        try:
            while len(secuencia) < cantidad:
                if timeout_s is not None:
                    if (datetime.now() - start_ts).total_seconds() > timeout_s:
                        break

                ok, frame = cap.read()
                if not ok:
                    continue

                if self.flip:
                    frame = cv2.flip(frame, 1)

                h, w = frame.shape[:2]

                rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                mp_image = mp.Image(image_format=mp.ImageFormat.SRGB, data=rgb)

                ts_ms = int(datetime.now().timestamp() * 1000) - t0_ms
                result = landmarker.detect_for_video(mp_image, ts_ms)

                gesto: int | None = None
                dedos: list[int] | None = None
                mano = "?"

                if result.hand_landmarks:
                    lm = result.hand_landmarks[0]
                    if result.handedness and result.handedness[0]:
                        mano = result.handedness[0][0].category_name  # "Right"/"Left"

                    dedos = self._detectar_dedos(lm, mano)
                    gesto = self._dedos_a_bitmask(dedos)

                    # espejo de LEDs si hay Arduino (opcional)
                    if self.arduino is not None and hasattr(self.arduino, "enviar_leds"):
                        try:
                            self.arduino.enviar_leds(dedos)  # type: ignore[attr-defined]
                        except Exception:
                            pass

                    if self.mostrar_preview:
                        # bbox
                        xs = [p.x for p in lm]
                        ys = [p.y for p in lm]
                        x1, y1 = int(min(xs) * w), int(min(ys) * h)
                        x2, y2 = int(max(xs) * w), int(max(ys) * h)
                        cv2.rectangle(frame, (x1, y1), (x2, y2), (0, 255, 0), 2)

                        # conexiones
                        pts = [(int(p.x * w), int(p.y * h)) for p in lm]
                        for a, b in HAND_CONNECTIONS:
                            cv2.line(frame, pts[a], pts[b], (0, 255, 0), 2, cv2.LINE_AA)
                        for (px, py) in pts:
                            cv2.circle(frame, (px, py), 3, (0, 255, 0), -1, cv2.LINE_AA)

                # overlay superior
                if self.mostrar_preview:
                    msg1 = f"Captura {len(secuencia)}/{cantidad} | ESC=salir | cierre={gesto_cierre if gesto_cierre is not None else '-'}"
                    msg2 = (
                        f"Estabilizando {stable_count}/{self.stable_frames}"
                        if gesto is not None else
                        "Sin mano detectada"
                    )
                    if gesto is not None and dedos is not None:
                        msg3 = f"Gesto={gesto} bin={gesto:05b} dedos={dedos} mano={mano}"
                    else:
                        msg3 = ""

                    # texto grande con fondo
                    def put_line(y: int, s: str) -> None:
                        if not s:
                            return
                        cv2.putText(frame, s, (10, y), cv2.FONT_HERSHEY_SIMPLEX, 0.9, (0, 0, 0), 4, cv2.LINE_AA)
                        cv2.putText(frame, s, (10, y), cv2.FONT_HERSHEY_SIMPLEX, 0.9, (255, 255, 255), 2, cv2.LINE_AA)

                    put_line(35, msg1)
                    put_line(70, msg2)
                    put_line(105, msg3)

                    cv2.imshow(win, frame)
                    k = cv2.waitKey(1) & 0xFF
                    if k == 27 or k == ord("q"):  # ESC o q
                        break

                # lógica de estabilidad
                if gesto is None:
                    stable_count = 0
                    current_candidate = None
                    continue

                if current_candidate == gesto:
                    stable_count += 1
                else:
                    current_candidate = gesto
                    stable_count = 1

                if stable_count < self.stable_frames:
                    continue

                # debounce
                now = datetime.now()
                if last_accept_ts is not None:
                    if (now - last_accept_ts).total_seconds() < self.debounce_s:
                        continue

                # gesto de cierre
                if gesto_cierre is not None and gesto == gesto_cierre:
                    break

                # aceptar gesto
                if t_prev is not None:
                    tiempos.append((now - t_prev).total_seconds())
                t_prev = now

                secuencia.append(gesto)
                last_accept_ts = now
                stable_count = 0
                current_candidate = None

        finally:
            cap.release()
            if self.mostrar_preview:
                try:
                    cv2.destroyAllWindows()
                except Exception:
                    pass
            landmarker.close()

        return secuencia, tiempos if tiempos else None
