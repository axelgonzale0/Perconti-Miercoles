import tkinter as tk
from tkinter import ttk, messagebox
import socket
import subprocess
import platform

# --------------------------- UTILIDADES ---------------------------

def es_ipv4(s):
    s = s.strip()
    partes = s.split(".")
    if len(partes) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in partes)
    except:
        return False

def ejecutar_comando(cmd):
    try:
        salida = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode(errors="ignore")
        return salida
    except:
        return ""

# --------------------------- FUNCIONES RED ---------------------------

def obtener_ip_local():
    try:
        sistema = platform.system()
        if sistema == "Windows":
            salida = ejecutar_comando("ipconfig")
            for linea in salida.splitlines():
                l = linea.strip()
                if ("Dirección IPv4" in l or "IPv4 Address" in l) and ":" in l:
                    posible = l.split(":")[-1].strip()
                    if es_ipv4(posible):
                        return posible
        else:
            salida = ejecutar_comando("ip addr")
            for linea in salida.splitlines():
                l = linea.strip()
                if "inet " in l and "/" in l:
                    token = l.split()[1]
                    ip = token.split("/")[0]
                    if es_ipv4(ip):
                        return ip

        # fallback UDP socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            if es_ipv4(ip):
                return ip
        except:
            pass

        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        if es_ipv4(ip) and not ip.startswith("127."):
            return ip

        return "No disponible"
    except:
        return "No disponible"

def obtener_mascara():
    try:
        import re
        salida = ejecutar_comando("ipconfig")

        for linea in salida.splitlines():
            low = linea.lower()
            if "máscara" in low or "subnet" in low or "mask" in low:
                ips = re.findall(r'(\d{1,3}(?:\.\d{1,3}){3})', linea)
                if ips:
                    return ips[-1]

        ips_255 = re.findall(r'(255(?:\.\d{1,3}){3})', salida)
        if ips_255:
            return ips_255[0]

        return "No disponible"
    except:
        return "No disponible"

def obtener_gateway():
    try:
        salida = ejecutar_comando("ipconfig")
        lineas = salida.splitlines()

        for i, linea in enumerate(lineas):
            l = linea.strip()
            if "Puerta de enlace predeterminada" in l or "Default Gateway" in l:
                if ":" in l:
                    posible = l.split(":")[-1].strip()
                    if es_ipv4(posible):
                        return posible

                j = i + 1
                while j < len(lineas):
                    siguiente = lineas[j].strip()
                    if siguiente == "":
                        j += 1
                        continue
                    partes = siguiente.split()
                    for t in partes:
                        if es_ipv4(t):
                            return t
                    j += 1
        return "No disponible"
    except:
        return "No disponible"

# --------------------------- FUNCIONES PING ---------------------------

def cambiar_ping(event):
    """Cuando seleccionas algo del combobox, lo coloca en el Entry."""
    entrada_ping.delete(0, tk.END)
    entrada_ping.insert(0, combo_ping.get())

def ejecutar_ping():
    destino = entrada_ping.get().strip()
    if destino == "":
        messagebox.showwarning("Error", "Debes escribir un dominio o elegir uno.")
        return

    comando = f"ping -n 4 {destino}" if platform.system() == "Windows" else f"ping -c 4 {destino}"

    try:
        proceso = subprocess.Popen(comando, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        salida, error = proceso.communicate(timeout=10)

        area_resultados.delete("1.0", tk.END)
        if salida:
            area_resultados.insert(tk.END, salida)
        elif error:
            area_resultados.insert(tk.END, error)
        else:
            area_resultados.insert(tk.END, "Sin respuesta.")
    except:
        area_resultados.insert(tk.END, "Error en el ping.")

def actualizar_datos():
    label_ip_valor.config(text=obtener_ip_local())
    label_hostname_valor.config(text=socket.gethostname())
    label_gateway_valor.config(text=obtener_gateway())
    label_mascara_valor.config(text=obtener_mascara())

# --------------------------- TKINTER UI ---------------------------

ventana = tk.Tk()
ventana.title("Comandos e Información de la Red")
ventana.geometry("650x560")

titulo = tk.Label(ventana, text="Información de la Red", font=("Arial", 16, "bold"))
titulo.pack(pady=10)

frame_info = tk.Frame(ventana)
frame_info.pack(pady=10, padx=10, anchor="w")

# Labels de info
tk.Label(frame_info, text="IP Local:", font=("Arial", 12)).grid(row=0, column=0, sticky="w")
label_ip_valor = tk.Label(frame_info, text="...", font=("Arial", 12))
label_ip_valor.grid(row=0, column=1, sticky="w", padx=10)

tk.Label(frame_info, text="Hostname:", font=("Arial", 12)).grid(row=1, column=0, sticky="w")
label_hostname_valor = tk.Label(frame_info, text="...", font=("Arial", 12))
label_hostname_valor.grid(row=1, column=1, sticky="w", padx=10)

tk.Label(frame_info, text="Gateway:", font=("Arial", 12)).grid(row=2, column=0, sticky="w")
label_gateway_valor = tk.Label(frame_info, text="...", font=("Arial", 12))
label_gateway_valor.grid(row=2, column=1, sticky="w", padx=10)

tk.Label(frame_info, text="Máscara:", font=("Arial", 12)).grid(row=3, column=0, sticky="w")
label_mascara_valor = tk.Label(frame_info, text="...", font=("Arial", 12))
label_mascara_valor.grid(row=3, column=1, sticky="w", padx=10)

btn_actualizar = tk.Button(ventana, text="Actualizar Datos", font=("Arial", 12), command=actualizar_datos)
btn_actualizar.pack(pady=10)

# --------------------------- PING ---------------------------

frame_ping = tk.LabelFrame(ventana, text="Ping", padx=10, pady=10)
frame_ping.pack(fill="both", padx=10, pady=10)

tk.Label(frame_ping, text="Elegir servidor:", font=("Arial", 12)).grid(row=0, column=0, sticky="w")

# --- LISTA DESPLEGABLE ---
combo_ping = ttk.Combobox(
    frame_ping,
    values=["google.com", "cloudflare.com", "facebook.com", "youtube.com", "8.8.8.8", "1.1.1.1"],
    font=("Arial", 12),
    width=25
)
combo_ping.grid(row=0, column=1, padx=6)
combo_ping.bind("<<ComboboxSelected>>", cambiar_ping)

tk.Label(frame_ping, text="Dominio/IP manual:", font=("Arial", 12)).grid(row=1, column=0, sticky="w")

entrada_ping = tk.Entry(frame_ping, font=("Arial", 12), width=30)
entrada_ping.grid(row=1, column=1, padx=6)
entrada_ping.insert(0, "google.com")

btn_ping = tk.Button(frame_ping, text="Ejecutar Ping", font=("Arial", 12), command=ejecutar_ping)
btn_ping.grid(row=1, column=2, padx=6)

area_resultados = tk.Text(frame_ping, height=12, font=("Courier", 10))
area_resultados.grid(row=2, column=0, columnspan=3, pady=10, sticky="nsew")

frame_ping.grid_rowconfigure(2, weight=1)
frame_ping.grid_columnconfigure(1, weight=1)

actualizar_datos()

ventana.mainloop()
