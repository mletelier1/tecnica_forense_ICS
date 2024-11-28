import os
import pandas as pd
import matplotlib.pyplot as plt
from fpdf import FPDF
from datetime import datetime

# Configuración de directorios
infectados = "DIR/TRAFICO_INFECTADO/"
normales = "DIR/TRAFICO_NORMAL/"

# Validar directorios y pedir rutas si no existen
if not os.path.isdir(infectados):
    print(f"Directorio de tráfico infectado no encontrado: {infectados}")
    infectados = input("Por favor ingresa la ruta del directorio de tráfico infectado: ").strip()
    if not os.path.isdir(infectados):
        raise FileNotFoundError(f"El directorio ingresado tampoco es válido: {infectados}")

if not os.path.isdir(normales):
    print(f"Directorio de tráfico normal no encontrado: {normales}")
    normales = input("Por favor ingresa la ruta del directorio de tráfico normal: ").strip()
    if not os.path.isdir(normales):
        raise FileNotFoundError(f"El directorio ingresado tampoco es válido: {normales}")

# Definir paths de conn.log y table_ip.csv
logs_infectados = os.path.join(infectados, "conn.log")
logs_normales = os.path.join(normales, "conn.log")
table_ip_path = os.path.join(normales, "table_ip.csv")

# Verificar la existencia de table_ip.csv
if not os.path.isfile(table_ip_path):
    raise FileNotFoundError(f"Archivo 'table_ip.csv' no encontrado en: {table_ip_path}")

# Diccionario de puertos conocidos
PUERTOS_CONOCIDOS = {
    53: "DNS - Protocolo de resolución de nombres (UDP/TCP)",
    5353: "mDNS - Multicast DNS para redes locales (UDP)",
    5355: "LLMNR - Link-Local Multicast Name Resolution (UDP)",
    1900: "SSDP - Simple Service Discovery Protocol (UDP)",
    3702: "WS-Discovery - Web Services Discovery (UDP)",
    138: "NetBIOS Datagram Service - Comunicación en red local (UDP)",
    3: "RFC de prueba - Uso desconocido (TCP/UDP)",
    67: "DHCP - Configuración dinámica de hosts (UDP)",
    137: "NetBIOS Name Service - Resolución de nombres en red local (TCP/UDP)",
    547: "DHCPv6 - Configuración dinámica en redes IPv6 (UDP)"
}
# Puertos seleccionados para el gráfico
PUERTOS_SELECCIONADOS = [138, 67, 547, 137, 3702, 1900, 5353, 3, 53, 20000, 49158]

def leer_reporte_analisis(file_path):
    datos = {
        "File name": None,
        "Number of packets": None,
        "File size": None,
        "Capture duration": None,
        "Earliest packet time": None,
        "Latest packet time": None,
        "Capture oper-sys": None,
        "Capture application": None,
        "SHA256": None,
        "SHA1": None,
        "Inicio del análisis forense": None,
        "Análisis concluido": None,
        "Versión de Zeek": None,
        "Versión de Python": None,
        "Sistema Operativo": None,
        "Hash conn.log": None,
        "Hash dns.log": None,
        "Hash weird.log": None,
    }

    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Archivo {file_path} no encontrado.")

    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()

            # Capturar valores específicos
            if line.startswith("File name:"):
                datos["File name"] = line.split(":", 1)[-1].strip()
            elif line.startswith("Number of packets:"):
                datos["Number of packets"] = line.split(":", 1)[-1].strip()
            elif line.startswith("File size:"):
                datos["File size"] = line.split(":", 1)[-1].strip()
            elif line.startswith("Capture duration:"):
                datos["Capture duration"] = line.split(":", 1)[-1].strip()
            elif line.startswith("Earliest packet time:"):
                datos["Earliest packet time"] = line.split(":", 1)[-1].strip()
            elif line.startswith("Latest packet time:"):
                datos["Latest packet time"] = line.split(":", 1)[-1].strip()
            elif line.startswith("Capture oper-sys:"):
                datos["Capture oper-sys"] = line.split(":", 1)[-1].strip()
            elif line.startswith("Capture application:"):
                datos["Capture application"] = line.split(":", 1)[-1].strip()
            elif line.startswith("SHA256:"):
                datos["SHA256"] = line.split(":", 1)[-1].strip()
            elif line.startswith("SHA1:"):
                datos["SHA1"] = line.split(":", 1)[-1].strip()
            elif line.startswith("Hash del archivo conn.log:"):
                datos["Hash conn.log"] = line.split(":", 1)[-1].strip()
            elif line.startswith("Hash del archivo dns.log:"):
                datos["Hash dns.log"] = line.split(":", 1)[-1].strip()
            elif line.startswith("Hash del archivo weird.log:"):
                datos["Hash weird.log"] = line.split(":", 1)[-1].strip()
            elif line.startswith("[") and "Inicio del análisis forense" in line:
                datos["Inicio del análisis forense"] = line.split("]")[0].strip("[]")
            elif line.startswith("[") and "Finalización del análisis forense" in line:
                datos["Análisis concluido"] = line.split("]")[0].strip("[]")
            elif line.startswith("Versión de Zeek:"):
                datos["Versión de Zeek"] = line.split(":", 1)[-1].strip()
            elif line.startswith("Versión de Python:"):
                datos["Versión de Python"] = line.split(":", 1)[-1].strip()
            elif line.startswith("Sistema Operativo:"):
                datos["Sistema Operativo"] = line.split(":", 1)[-1].strip()

    print("Datos procesados desde el reporte:", datos)  # Verificación
    return datos


# Leer conn.log
def leer_conn_log(log_path):
    columnas = ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'service', 
                'duration', 'orig_bytes', 'resp_bytes', 'conn_state', 'local_orig', 'local_resp', 
                'missed_bytes', 'history', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes', 'tunnel_parents']
    df = pd.read_csv(log_path, sep='\t', comment='#', names=columnas, low_memory=False)
    df['orig_bytes'] = pd.to_numeric(df['orig_bytes'], errors='coerce').fillna(0)
    df['resp_bytes'] = pd.to_numeric(df['resp_bytes'], errors='coerce').fillna(0)
    df['ts'] = pd.to_datetime(df['ts'], unit='s', errors='coerce')
    df['total_bytes'] = df['orig_bytes'] + df['resp_bytes']
    return df

# Leer table_ip.csv
def leer_table_ip(csv_path):
    return pd.read_csv(csv_path)

# Ajustar duración del tráfico normal
def extrapolar_trafico_normal(df_normal, duracion_infectado):
    duracion_normal = (df_normal['ts'].max() - df_normal['ts'].min()).total_seconds()
    if duracion_normal == 0:
        raise ValueError("Duración del tráfico normal insuficiente para extrapolar.")
    factor = duracion_infectado / duracion_normal
    df_normal['total_bytes'] *= factor
    return df_normal

# Crear glosario de puertos
# Crear glosario de puertos solo para los seleccionados
def agregar_glosario_puertos(pdf, puertos_seleccionados):
    pdf.set_font("Arial", size=10)
    pdf.cell(200, 10, txt="Glosario de Puertos Seleccionados", ln=True, align='L')
    for puerto in puertos_seleccionados:
        descripcion = PUERTOS_CONOCIDOS.get(puerto, "Protocolo y tráfico no identificado")
        pdf.multi_cell(200, 10, txt=f"Puerto {puerto}: {descripcion}", border=0, align='L')


# Agregar tabla genérica al PDF con mayor ancho para la columna de descripción
def agregar_tabla_csv_en_hoja(pdf, df):
    pdf.ln(120)  # Espacio suficiente para evitar superposición con gráficos
    pdf.set_font("Arial", size=10)
    pdf.cell(200, 10, txt="Tabla del CSV", ln=True, align='C')
    
    # Anchos personalizados para las columnas
    col_widths = [40 if col != 'Descripcion' else 100 for col in df.columns]

    # Agregar encabezados
    for col, width in zip(df.columns, col_widths):
        pdf.cell(width, 10, txt=str(col), border=1, align='C')
    pdf.ln()

    # Agregar filas
    for _, row in df.iterrows():
        for col, width in zip(df.columns, col_widths):
            if col == 'Descripcion':  # Usar multi_cell para la columna de descripción
                x, y = pdf.get_x(), pdf.get_y()
                pdf.multi_cell(width, 10, txt=str(row[col]), border=1, align='L')
                pdf.set_xy(x + width, y)  # Ajustar la posición para las siguientes columnas
            else:
                pdf.cell(width, 10, txt=str(row[col]), border=1, align='C')
        pdf.ln()


# Generar gráficos
def plot_comparison(data_infectado, data_normal, title, ylabel, filename, logy=False):
    indices = data_infectado.index.union(data_normal.index)
    data_infectado = data_infectado.reindex(indices, fill_value=0)
    data_normal = data_normal.reindex(indices, fill_value=0)
    
    fig, ax = plt.subplots(figsize=(10, 6))
    width = 0.35
    x = range(len(indices))
    ax.bar([i - width/2 for i in x], data_infectado, width=width, color='red', label='Infectado')
    ax.bar([i + width/2 for i in x], data_normal, width=width, color='blue', label='Normal')
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.set_xticks(x)
    ax.set_xticklabels(indices, rotation=45)
    ax.legend()
    if logy:
        ax.set_yscale('log')
    plt.tight_layout()
    plt.savefig(filename)
    plt.close(fig)

# Generar PDF con gráficos y tablas
def generar_pdf_con_reporte(reporte_path, df_infectado, df_normal, df_table_ip, output_pdf):
    # Leer datos del reporte
    datos_reporte = leer_reporte_analisis(reporte_path)

    pdf = FPDF(format='Legal')  # Tamaño Legal
    fecha_actual = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    duracion_infectado = (df_infectado['ts'].max() - df_infectado['ts'].min()).total_seconds()
    duracion_normal = (df_normal['ts'].max() - df_normal['ts'].min()).total_seconds()

    # Página 1: CAPTURA Y EXAMEN DE DATOS, ANÁLISIS DE DATOS y PRESENTACIÓN DE LOS DATOS
    pdf.add_page()
    pdf.set_font("Arial", size=14)
    pdf.cell(200, 10, txt="Reporte de Análisis de Tráfico", ln=True, align='C')
    pdf.ln(10)  # Espacio entre líneas

   # Sección 1: CAPTURA Y EXAMEN DE DATOS
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="CAPTURA Y EXAMEN DE DATOS", ln=True, align='L')
    for key in [
        "File name", "Number of packets", "File size", "Capture duration", 
        "Earliest packet time", "Latest packet time", "Capture oper-sys", 
        "Capture application", "SHA256", "SHA1"  # Incluimos SHA256 y SHA1
    ]:
        if datos_reporte[key]:
         pdf.cell(200, 10, txt=f"{key}: {datos_reporte[key]}", ln=True, align='L')
    pdf.ln(10)


    # Sección 2: ANÁLISIS DE DATOS
    pdf.cell(200, 10, txt="ANÁLISIS DE DATOS", ln=True, align='L')
    if datos_reporte["Inicio del análisis forense"]:
        pdf.cell(200, 10, txt=f"Inicio del análisis forense: {datos_reporte['Inicio del análisis forense']}", ln=True, align='L')
    if datos_reporte["Análisis concluido"]:
        pdf.cell(200, 10, txt=f"El análisis del tráfico capturado ha concluido el: {datos_reporte['Análisis concluido']}", ln=True, align='L')

    for key in [
        "Versión de Zeek", "Versión de Python", "Sistema Operativo", 
        "Hash conn.log", "Hash dns.log", "Hash weird.log"
    ]:
        if datos_reporte[key]:
            pdf.cell(200, 10, txt=f"{key}: {datos_reporte[key]}", ln=True, align='L')
    pdf.ln(10)  # Espacio entre secciones

    # Sección 3: PRESENTACIÓN DE LOS DATOS
    pdf.cell(200, 10, txt="PRESENTACIÓN DE LOS DATOS", ln=True, align='L')
    pdf.cell(200, 10, txt=f"Reporte generado: {fecha_actual}", ln=True, align='L')
    pdf.cell(200, 10, txt=f"Duración del tráfico infectado: {duracion_infectado / 60:.2f} minutos", ln=True, align='L')
    pdf.cell(200, 10, txt=f"Duración del tráfico normal: {duracion_normal / 60:.2f} minutos", ln=True, align='L')

    # Gráfico y tabla: IPs de Origen
    # Gráfico y tabla: IPs de Origen
    plot_comparison(
        df_infectado['id.orig_h'][df_infectado['id.orig_h'].str.contains(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", na=False)].value_counts(),
        df_normal['id.orig_h'][df_normal['id.orig_h'].str.contains(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", na=False)].value_counts(),
        "IPs de Origen más Comunes",
        "Conexiones (Log)",
        "ips_origen_v4.png",
         logy=True
    )
    pdf.add_page()
    pdf.image("ips_origen_v4.png", x=10, y=20, w=190)
    agregar_tabla_csv_en_hoja(pdf, df_table_ip)

    # Gráfico y tabla: IPs de Destino
    plot_comparison(
        df_infectado['id.resp_h'][df_infectado['id.resp_h'].str.contains(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", na=False)].value_counts(),
        df_normal['id.resp_h'][df_normal['id.resp_h'].str.contains(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", na=False)].value_counts(),
        "IPs de Destino más Comunes",
        "Conexiones (Log)",
        "ips_destino_v4.png",
        logy=True
    )
    pdf.add_page()
    pdf.image("ips_destino_v4.png", x=10, y=20, w=190)
    agregar_tabla_csv_en_hoja(pdf, df_table_ip)
    
    
    # Filtrar por puertos seleccionados
    infectado_puertos = df_infectado['id.resp_p'].value_counts()
    normal_puertos = df_normal['id.resp_p'].value_counts()

    # Crear filtros con los puertos seleccionados
    infectado_puertos = infectado_puertos[infectado_puertos.index.isin(PUERTOS_SELECCIONADOS)]
    normal_puertos = normal_puertos[normal_puertos.index.isin(PUERTOS_SELECCIONADOS)]

    # Gráfico de Puertos Seleccionados
    plot_comparison(
        infectado_puertos,
         normal_puertos,
            "Puertos de Destino Seleccionados",
         "Conexiones",
         "puertos_destino_seleccionados.png",
         logy=True
    
    )  
    pdf.add_page()
    pdf.image("puertos_destino_seleccionados.png", x=10, y=20, w=190)


   # Parámetros configurables
    desplazar_minutos = 6  # Desplazar el gráfico de tráfico normal hacia la derecha (en minutos)
    factor_altura_normal = 0.5  # Escalar la altura del gráfico normal
    tiempo_excluir = 5  # Excluir los primeros minutos del tráfico normal para evitar picos

    # Configuración de suavizado
    suavizar_infectado = True  # Suavizar el tráfico infectado
    suavizar_normal = True  # Suavizar el tráfico normal
    ventana_suavizado = 5  # Tamaño de la ventana para la media móvil


   # Gráfico de evolución en el tiempo
    fig, ax = plt.subplots(figsize=(10, 6))

    # Resamplear los datos por minuto
    infectado_resampled = df_infectado.resample('1min', on='ts')['total_bytes'].sum()
    normal_resampled = df_normal.resample('1min', on='ts')['total_bytes'].sum()

    # Escalar la altura del tráfico normal
    normal_resampled *= factor_altura_normal

    # Desplazar el tráfico normal hacia la derecha
    normal_resampled.index += pd.Timedelta(minutes=desplazar_minutos)

    # Eliminar los primeros minutos del tráfico normal para evitar el peak inicial
    if len(normal_resampled) > tiempo_excluir:
     normal_resampled = normal_resampled.iloc[tiempo_excluir:]

    # Suavizar los datos si está habilitado
    if suavizar_infectado:
     infectado_resampled = infectado_resampled.rolling(window=ventana_suavizado, min_periods=1).mean()

    if suavizar_normal:
      normal_resampled = normal_resampled.rolling(window=ventana_suavizado, min_periods=1).mean()

    # Graficar los datos resampleados
    infectado_resampled.plot(ax=ax, label='Infectado', color='red')
    normal_resampled.plot(ax=ax, label='Normal', color='blue')

    # Configurar el título, etiquetas y leyenda
    ax.set_title("Evolución del Tráfico en el Tiempo")
    ax.set_ylabel("Total de Bytes")
    ax.set_yscale('log')  # Escala logarítmica en el eje Y
    ax.legend()

    # Guardar el gráfico
    plt.tight_layout()
    plt.savefig("evolucion_trafico.png")
    plt.close(fig)



    # Agregar el gráfico al PDF
    pdf.add_page()
    pdf.image("evolucion_trafico.png", x=10, y=20, w=190)



    # Glosario de puertos
    pdf.add_page()
    agregar_glosario_puertos(pdf, PUERTOS_SELECCIONADOS)


    # Guardar PDF
    pdf.output(output_pdf)

if __name__ == "__main__":
    print("Leyendo logs infectados...")
    df_infectado = leer_conn_log(logs_infectados)

    print("Leyendo logs normales...")
    df_normal = leer_conn_log(logs_normales)

    print("Leyendo tabla de IPs...")
    df_table_ip = leer_table_ip(table_ip_path)

    print("Extrapolando tráfico normal...")
    df_normal = extrapolar_trafico_normal(df_normal, (df_infectado['ts'].max() - df_infectado['ts'].min()).total_seconds())

    # Validar el archivo reporte_analisis.txt
    reporte_path = os.path.join(infectados, "reporte_analisis.txt")
    print(f"Ruta del reporte: {reporte_path}")

    if not os.path.isfile(reporte_path):
        raise FileNotFoundError(f"Archivo de reporte no encontrado: {reporte_path}")

    print("Leyendo reporte de análisis...")
    datos_reporte = leer_reporte_analisis(reporte_path)

    print("Datos extraídos del reporte:")
    for clave, valor in datos_reporte.items():
        print(f"{clave}: {valor}")

    print("Generando PDF con reporte...")
    generar_pdf_con_reporte(reporte_path, df_infectado, df_normal, df_table_ip, "presentacion_resultados.pdf")
    print("Reporte generado: presentacion_resultados.pdf")
