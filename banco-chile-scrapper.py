import re
from urllib.parse import urljoin, urlparse, urlunparse
from http.cookiejar import Cookie

import requests

class BancoChileScraper:

    USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36"
    RUT_FORMAT_REGEX = r"\d{1,2}[.]?\d{3}[.]?\d{3}-?[\dk]"
    API_BASE_URL = "https://portalpersonas.bancochile.cl/mibancochile/rest/persona/"
    LOGIN_URL = "https://login.bancochile.cl/bancochile-web/persona/login/index.html"
    API_REFERER = "https://portalpersonas.bancochile.cl/mibancochile-web/front/persona/index.html"

    def __init__(self, username, password):
        if not re.match(self.RUT_FORMAT_REGEX, username):
            raise ValueError("Username doesn't have RUT format.")
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": self.USER_AGENT,
                "Referer": self.LOGIN_URL,
                "Origin": self._get_origin(self.LOGIN_URL),
            }
        )
        self.logged_in = False

    def login(self):
        response = self.session.get(self.LOGIN_URL)
        response.raise_for_status()
        self._call("perfilamiento/home", enforce_login=False)
        raw_username = self.username.replace(".", "").replace("-", "")
        rut_number = f"{int(raw_username[:-1]):,d}".replace(",", ".")
        formatted_username = f"{rut_number}-{raw_username[-1]}"
        data = {
            "username2": [raw_username, formatted_username],
            "userpassword": self.password,
            "request_id": "",
            "ctx": "persona",
            "username": raw_username,
            "password": f"00000000{self.password}"[-8:],
        }
        response = self.session.post(
            "https://login.bancochile.cl/oam/server/auth_cred_submit", data
        )
        if (
            response.status_code != 200
            or urlunparse(urlparse(response.url)._replace(fragment="")) != self.API_REFERER
        ):
            raise Exception("Login failed.")
        self.session.headers["Referer"] = self.API_REFERER
        self.session.headers["Origin"] = self._get_origin(self.API_REFERER)
        self.logged_in = True

    def get_transactions(self):
        products = self._call(
            'https://portalpersonas.bancochile.cl/mibancochile/rest/persona/selectorproductos/selectorProductos/obtenerProductos').json()
        
        accounts = [product for product in products["productos"] if product["tipo"] == "cuenta"]

        cartola_request = {
            "cuentasSeleccionadas": [{
                "nombreCliente": products["nombre"],
                "rutCliente": products["rut"],
                "numero": accounts[0]["numero"],
                "mascara": accounts[0]["mascara"],
                "selected": True,
                "codigoProducto": accounts[0]["codigo"],
                "claseCuenta": accounts[0]["claseCuenta"],
                "moneda": accounts[0]["codigoMoneda"]
            }],
            "cabecera": {"paginacionDesde": {}, "statusGenerico": True}}

        transactions = self._call('https://portalpersonas.bancochile.cl/mibancochile/rest/persona/movimientos/getcartola', method="post", json=cartola_request).json()
        return transactions

    def _call(self, url, *args, enforce_login=True, method="get", **kwargs):
        if enforce_login and not self.logged_in:
            raise ValueError("Scraper should be logged in.")
        response = self.session.request(
            method,
            urljoin(self.API_BASE_URL, url),
            *args,
            **kwargs,
        )
        response.raise_for_status()
        return response

    def _get_origin(self, referer):
        parsed = urlparse(referer)
        return f"{parsed.scheme}://{parsed.netloc}"


if __name__ == "__main__":
    username = input("BancoChile username: ")
    password = input("BancoChile password: ")
    banco = BancoChileScraper(username, password)
    banco.login()
    print(banco.get_transactions())
