import hashlib
import io
import sqlite3
import tempfile
import unittest
from contextlib import chdir, closing, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from app import reporte_auditoria as reportes


class PruebasAuditoria(unittest.TestCase):
    def test_configuracion_yaml(self):
        with tempfile.TemporaryDirectory() as carpeta:
            ruta = Path(carpeta) / "config.yaml"
            ruta.write_text("servicio:\n  puerto: 8080\n", encoding="utf-8")
            self.assertEqual(reportes.cargar_configuracion(ruta), {"servicio": {"puerto": 8080}})

    def test_consulta_por_cliente_con_apostrofo(self):
        with tempfile.TemporaryDirectory() as carpeta:
            ruta = Path(carpeta) / "reportes.db"
            with closing(sqlite3.connect(ruta)) as conexion:
                conexion.execute("CREATE TABLE reportes (cliente TEXT)")
                conexion.executemany("INSERT INTO reportes VALUES (?)", [("o'brien_ltd",), ("acme",)])
                conexion.commit()
            self.assertEqual(reportes.buscar_reportes_cliente("o'brien_ltd", ruta), [("o'brien_ltd",)])
            self.assertEqual(reportes.buscar_reportes_cliente("desconocido", ruta), [])

    @patch.object(reportes.subprocess, "run")
    def test_argumentos_del_conversor(self, ejecutar):
        for nombre in ("informe.html", "a.b-c_1.html", "_1.html"):
            with self.subTest(nombre=nombre), tempfile.TemporaryDirectory() as carpeta, chdir(carpeta):
                Path(nombre).write_text("<p>Reporte</p>", encoding="utf-8")
                salida = reportes.convertir_a_pdf(nombre)
                self.assertEqual(salida, nombre + ".pdf")
                ejecutar.assert_called_with(["wkhtmltopdf", "./" + nombre, "./" + salida], check=False)

    @patch.object(reportes.subprocess, "run")
    def test_solo_convierte_archivos_locales_publicados(self, ejecutar):
        with tempfile.TemporaryDirectory() as carpeta, chdir(carpeta), redirect_stdout(io.StringIO()):
            self.assertEqual(reportes.convertir_a_pdf("ausente.html"), "ausente.html.pdf")
            Path("datos.txt").write_text("prueba", encoding="utf-8")
            Path("enlace.html").symlink_to("datos.txt")
            self.assertEqual(reportes.convertir_a_pdf("enlace.html"), "enlace.html.pdf")
        ejecutar.assert_not_called()

    @patch.object(reportes.subprocess, "run")
    def test_rechaza_nombres_invalidos(self, ejecutar):
        for nombre in ("", "x", ".html", ".x.html", "-x.html", "informe final.html",
                       "carpeta/informe.html", "letrañ.html", "x.html\n"):
            with self.subTest(nombre=nombre), self.assertRaises(ValueError):
                reportes.convertir_a_pdf(nombre)
        ejecutar.assert_not_called()

    @patch.object(reportes.subprocess, "run", side_effect=FileNotFoundError)
    def test_aviso_sin_conversor(self, _ejecutar):
        salida = io.StringIO()
        with tempfile.TemporaryDirectory() as carpeta, chdir(carpeta), redirect_stdout(salida):
            Path("x.html").touch()
            self.assertEqual(reportes.convertir_a_pdf("x.html"), "x.html.pdf")
        self.assertIn("no se generó el PDF", salida.getvalue())

    def test_hash_con_sal_aleatoria(self):
        primero = reportes.hash_password_legacy("ejemplo")
        segundo = reportes.hash_password_legacy("ejemplo")
        sal, derivado = primero.split(":")
        self.assertNotEqual(sal, segundo.split(":")[0])
        self.assertEqual(len(bytes.fromhex(sal)), 16)
        esperado = hashlib.pbkdf2_hmac("sha256", b"ejemplo", bytes.fromhex(sal), 600_000)
        self.assertEqual(esperado.hex(), derivado)

    def test_notificacion_registra_solo_el_estado_de_la_clave(self):
        for clave, estado in (("", "sin configurar"), ("valor_de_prueba", "configurada")):
            with self.subTest(estado=estado), patch.object(reportes, "NOTIFICATION_API_KEY", clave):
                salida = io.StringIO()
                with redirect_stdout(salida):
                    self.assertTrue(reportes.notificar_cliente("a@example.invalid", "prueba"))
                self.assertEqual(salida.getvalue(), f"[NotifyAPI: {estado}] -> a@example.invalid: prueba\n")
