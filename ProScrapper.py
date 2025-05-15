import os
import requests
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from requests.exceptions import HTTPError, RequestException
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import tkinter as tk
from tkinter import filedialog, scrolledtext
import pefile
import logging
import dns.resolver
import json
import time

logging.basicConfig(filename='Tracking.log', level=logging.INFO, format='%(asctime)s:%(levelname)s:%(message)s')

# Función para cargar la cache de IPs del honeypot
def cargar_cache_honeypot():
    if os.path.exists('cache_honeypot.json'):
        with open('cache_honeypot.json', 'r') as archivo:
            return json.load(archivo)
    return {}

# Guardar IPs en cache honeypot
def guardar_cache_honeypot(cache_honeypot):
    with open('cache_honeypot.json', 'w') as archivo:
        json.dump(cache_honeypot, archivo, indent=4)

# Diccionario de descripciones para funciones de red
def cargar_descripciones_funciones():
    with open("descripciones_funciones.json", "r", encoding="utf-8") as file:
        return json.load(file)

descripciones_funciones = cargar_descripciones_funciones()
cache_honeypot = cargar_cache_honeypot()  # Carga el cache de IPs del honeypot

def cargar_cache():
    if os.path.exists('cachevisita.json'):
        with open('cachevisita.json', 'r') as archivo:
            return json.load(archivo)
    return {}

def guardar_cache(cache):
    with open('cachevisita.json', 'w') as archivo:
        json.dump(cache, archivo, indent=4)

def registrar_ip_sospechosa(ip):
    if ip not in cache_honeypot:
        logging.info(f"Registrando IP sospechosa en honeypot: {ip}")
        cache_honeypot[ip] = time.strftime('%Y-%m-%d %H:%M:%S')
        guardar_cache_honeypot(cache_honeypot)

def obtener_contenido_con_selenium(url):
    options = webdriver.ChromeOptions()
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    driver.get(url)
    time.sleep(2)  # Espera para que la página cargue completamente
    
    page_source = driver.page_source
    driver.quit()
    return page_source

def cargar_rastreadores(archivo_json):
    with open(archivo_json, 'r') as archivo:
        return json.load(archivo)

# Función modificada de rastreadores con detección de honeypot
def encontrar_rastreadores(url, cache, archivo_json="rastreadores_conocidos.json"):
    rastreadores_conocidos = cargar_rastreadores(archivo_json)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept-Language': 'es-ES,es;q=0.9,en;q=0.8',
        'Referer': 'https://www.google.com',
    }
    
    # Endpoint de honeypot para detectar actividad sospechosa
    honeypot_endpoints = ["http://honeypot.localtest.com/special-path", "http://honeypot.localtest.com/hidden"]

    # Verificar y registrar IPs de honeypot
    for endpoint in honeypot_endpoints:
        try:
            respuesta_honeypot = requests.get(endpoint, headers=headers)
            if respuesta_honeypot.status_code == 200:
                ip = respuesta_honeypot.headers.get('X-Forwarded-For', respuesta_honeypot.raw._connection.sock.getpeername()[0])
                registrar_ip_sospechosa(ip)
        except requests.RequestException as e:
            logging.error(f"Error al acceder al honeypot {endpoint}: {e}")

    # Código para buscar rastreadores en la URL (el resto de la función permanece igual)
    if url in cache:
        logging.info(f"Usando cache para la URL {url}")
        return cache[url]


    try:
        for intento in range(3):
            try:
                respuesta = requests.get(url, headers=headers)
                respuesta.raise_for_status()
                page_content = respuesta.text
                break  # Salir si la solicitud fue exitosa
            except HTTPError as e:
                logging.warning(f"HTTPError para {url}: {e}")
                if intento == 2:  # Último intento
                    # Intentar con Selenium como respaldo
                    logging.info(f"Intentando acceder a {url} usando Selenium.")
                    page_content = obtener_contenido_con_selenium(url)
                    if not page_content:
                        return [f"Error al acceder a {url} incluso con Selenium: {e}"]
            time.sleep(2 ** intento)  # Exponential backoff
        
        # Análisis del contenido de la página
        sopa = BeautifulSoup(page_content, 'html.parser')
        scripts = sopa.find_all('script')
        rastreadores = set()
        deteccion_fingerprinting_canvas = False
        deteccion_cname_cloaking = False

        # Detección de rastreadores en los scripts de la página
        for script in scripts:
            script_str = str(script)
            for clave, valor in rastreadores_conocidos.items():
                if clave in script_str:
                    rastreadores.add(valor)
            if 'canvas' in script_str and 'getContext' in script_str and ('toDataURL' in script_str or 'toBlob' in script_str):
                deteccion_fingerprinting_canvas = True

        # Detección de rastreadores en los scripts de la página
        for script in scripts:
            script_str = str(script)
            for clave, valor in rastreadores_conocidos.items():
                if clave in script_str:
                    rastreadores.add(valor)
            if 'canvas' in script_str and 'getContext' in script_str and ('toDataURL' in script_str or 'toBlob' in script_str):
                deteccion_fingerprinting_canvas = True

        # Detección de CNAME cloaking
        url_parseada = urlparse(url)
        try:
            respuestas = dns.resolver.resolve(url_parseada.netloc, 'CNAME')
            for rdata in respuestas:
                if any(dominio_rastreador in rdata.target.to_text() for dominio_rastreador in rastreadores_conocidos):
                    deteccion_cname_cloaking = True
                    break
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass
        #Registro de rastradores detectados
        if 'set-cookie' in respuesta.headers:
            rastreadores.add('Cookies')
        if deteccion_fingerprinting_canvas:
            rastreadores.add('Canvas Fingerprinting')
        if deteccion_cname_cloaking:
            rastreadores.add('CNAME Cloaking')

        resultado = list(rastreadores) if rastreadores else ["No se encontraron rastreadores."]
        cache[url] = resultado  # Guardar en cache
        guardar_cache(cache)
        return resultado
    except RequestException as e:
        logging.error(f"Error general al encontrar rastreadores para la URL {url}: {e}")
        return [f"Error al encontrar rastreadores para la URL {url}: {e}"]
    
# Añadir funciones principales para interfaz tkinter (sin cambios) y main
def analizar_ejecutable():
    raiz = tk.Tk()
    raiz.withdraw()  # Oculta la ventana principal de tkinter
    ruta_archivo = filedialog.askopenfilename(title="Seleccionar un archivo ejecutable", filetypes=[("Archivos ejecutables", "*.exe")])
    if ruta_archivo:
        try:
            pe = pefile.PE(ruta_archivo)
            importaciones_sospechosas = []
            funciones_red = [
    "connect", "send", "recv", "socket", "HttpOpenRequest", "InternetOpenUrl", "WSAStartup", 
    "InternetConnect", "URLDownloadToFile", "avcodec_send_packet", "WSADuplicateSocketW", 
    "WSARecv", "WSARecvFrom", "WSASend", "WSASendTo", "WSASocketW", "closesocket", 
    "ioctlsocket", "recvfrom", "sendto", "ConnectNamedPipe", "DisconnectNamedPipe", 
    "WinHttpConnect", "WinHttpSendRequest", "InternetOpen", "InternetCloseHandle", 
    "HttpSendRequest", "HttpQueryInfo", "InternetReadFile", "InternetWriteFile", 
    "GetAddrInfoW", "Bind", "Listen", "Accept", "WSACleanup", "setsockopt", 
    "shutdown", "select", "TransmitFile", "TransmitPackets", "WSAAsyncSelect"
]

            for entrada in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entrada.imports:
                    # Convertimos ambos a minúsculas para una comparación insensible a mayúsculas
                    nombre_funcion = imp.name.decode('utf-8').lower() if imp.name else ""
                    if any(func_red.lower() in nombre_funcion for func_red in funciones_red):
                        print({imp.name.decode('utf-8')})
                        # Convertimos la clave de descripciones a minúsculas para evitar problemas de capitalización
                        descripcion = descripciones_funciones.get(nombre_funcion, 'Función desconocida')
                        importaciones_sospechosas.append(f"{nombre_funcion}: {descripcion}")

            resultado_analisis = f"Importaciones relacionadas con la red:\n" + "\n".join(importaciones_sospechosas) if importaciones_sospechosas else "Ninguna"
        except Exception as e:
            logging.error(f"Error al analizar el ejecutable {ruta_archivo}: {e}")
            resultado_analisis = str(e)
    else:
        resultado_analisis = "No se seleccionó ningún archivo."
    raiz.destroy()  # Cerrar la ventana de tkinter
    return resultado_analisis

def principal():
    cache = cargar_cache()

    def analizar_url():
        url = entrada_url.get()
        if not urlparse(url).scheme:
            url = 'http://' + url
        rastreadores = encontrar_rastreadores(url, cache)
        texto_resultado.delete(1.0, tk.END)
        for i, rastreador in enumerate(rastreadores, start=1):
            texto_resultado.insert(tk.END, f"{i}. {rastreador}\n")

    def analizar_exe():
        resultado = analizar_ejecutable()
        texto_resultado.delete(1.0, tk.END)
        texto_resultado.insert(tk.END, f"{resultado}\n")

    raiz = tk.Tk()
    raiz.title("Analizador de Seguimiento")
    raiz.geometry("800x600")  # Tamaño inicial de la ventana

    marco = tk.Frame(raiz, bg='black')
    marco.pack(fill=tk.BOTH, expand=True)

    marco_superior = tk.Frame(marco, bg='white')
    marco_superior.pack(side=tk.TOP, fill=tk.X)

    tk.Label(marco_superior, text="Ingrese la URL para analizar:", bg='white', fg='black').pack(pady=10)
    entrada_url = tk.Entry(marco_superior, width=50)
    entrada_url.pack(pady=10)

    boton_analizar_url = tk.Button(marco_superior, text="Analizar URL", command=analizar_url)
    boton_analizar_url.pack(pady=10)

    boton_analizar_exe = tk.Button(marco_superior, text="Analizar Ejecutable", command=analizar_exe)
    boton_analizar_exe.pack(pady=10)

    texto_resultado = scrolledtext.ScrolledText(marco, width=80, height=20, wrap=tk.WORD, background="black", foreground="green")
    texto_resultado.pack(pady=10, fill=tk.BOTH, expand=True)

    raiz.mainloop()

if __name__ == '__main__':
    principal()