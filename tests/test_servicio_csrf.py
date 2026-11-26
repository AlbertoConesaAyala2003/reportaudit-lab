import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

# Importar el servicio igual que al ejecutar python app/servicio.py.
with patch.object(sys, "path", [str(Path(__file__).resolve().parents[1] / "app"), *sys.path]):
    import servicio


class PruebasConversionCSRF(unittest.TestCase):
    def setUp(self):
        self.cliente = servicio.app.test_client()

    def formulario(self):
        respuesta = self.cliente.get("/convertir?archivo=informe.html")
        self.assertEqual(respuesta.status_code, 200)
        token = re.search(r'name="csrf_token" value="([^"]+)"', respuesta.get_data(as_text=True))
        self.assertIsNotNone(token)
        return {"archivo": "informe.html", "csrf_token": token.group(1)}

    @patch.object(servicio, "convertir_a_pdf", return_value="informe.html.pdf")
    def test_solo_convierte_al_confirmar(self, convertir):
        datos = self.formulario()
        convertir.assert_not_called()
        respuesta = self.cliente.post("/convertir", data=datos)
        self.assertEqual(respuesta.status_code, 200)
        self.assertEqual(respuesta.json, {"archivo_pdf": "informe.html.pdf"})
        convertir.assert_called_once_with("informe.html")

    @patch.object(servicio, "convertir_a_pdf")
    def test_rechaza_token_ausente_invalido_y_de_otra_sesion(self, convertir):
        datos = self.formulario()
        for token in ("", "invalido"):
            with self.subTest(token=token):
                self.assertEqual(self.cliente.post("/convertir", data={**datos, "csrf_token": token}).status_code, 400)
        self.assertEqual(servicio.app.test_client().post("/convertir", data=datos).status_code, 400)
        convertir.assert_not_called()

    def test_nombre_invalido_en_ambos_metodos(self):
        datos = self.formulario()
        datos["archivo"] = "informe final.html"
        self.assertEqual(self.cliente.get("/convertir", query_string={"archivo": datos["archivo"]}).status_code, 400)
        self.assertEqual(self.cliente.post("/convertir", data=datos).status_code, 400)
