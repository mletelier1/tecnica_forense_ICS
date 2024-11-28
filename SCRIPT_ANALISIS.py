import os
import subprocess
import sys
import hashlib
import platform
from datetime import datetime, timedelta, timezone
from collections import Counter
import shutil  # Para buscar la ruta de Zeek automáticamente


def encontrar_zeek():
    """
    Busca la ruta de Zeek en el sistema utilizando shutil.which.
    """
    zeek_path = shutil.which("zeek")
    if not zeek_path:
        print("Error: Zeek no está instalado o no está en el PATH del sistema.")
        sys.exit(1)  # Salir del programa si no se encuentra Zeek
    return zeek_path


def generar_local_zeek(analysis_dir):
    """
    Genera un archivo local.zeek para configurar Zeek con la zona horaria deseada.
    """
    local_zeek_path = os.path.join(analysis_dir, "local.zeek")
    with open(local_zeek_path, "w") as f:
        f.write("""
        redef Log::use_local_tz = T;
        redef Log::default_ts_format = "%Y-%m-%d %H:%M:%S %z";
        """)
    print(f"Archivo local.zeek generado en {local_zeek_path}")
    return local_zeek_path


def registrar_evento(reporte, evento):
    """
    Registra un evento en el reporte y lo imprime en la terminal.
    """
    reporte.write(f"[{datetime.now()}] {evento}\n")
    print(evento)  # También imprime el evento en la terminal


def calcular_hash(archivo):
    """
    Calcula el hash SHA-256 de un archivo.
    """
    print(f"Calculando el hash SHA-256 de {archivo}...")
    sha256_hash = hashlib.sha256()
    with open(archivo, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def obtener_capinfos(pcap_path, reporte):
    """
    Ejecuta capinfos para obtener metadatos del tráfico.
    """
    print(f"Obteniendo metadatos del tráfico con capinfos para {pcap_path}...")
    try:
        capinfos_output = subprocess.getoutput(f'capinfos "{pcap_path}"')
        reporte.write("\n--- Metadatos del Tráfico (capinfos) ---\n")
        reporte.write(f"{capinfos_output}\n")
    except Exception as e:
        reporte.write(f"Error al obtener metadatos del tráfico: {e}\n")
        print(f"Error al obtener metadatos del tráfico: {e}")


def convertir_utc_a_local(utc_timestamp, offset_horas=-3):
    """
    Convierte un timestamp UTC a hora local con un offset dado (en horas).
    """
    utc_time = datetime.fromtimestamp(utc_timestamp, tz=timezone.utc)
    local_time = utc_time + timedelta(hours=offset_horas)
    return local_time.strftime('%Y-%m-%d %H:%M:%S')


def analizar_logs_conn(ruta_zeek_logs, reporte):
    """
    Analiza el archivo conn.log generado por Zeek.
    """
    conn_log_path = os.path.join(ruta_zeek_logs, "conn.log")
    if os.path.exists(conn_log_path):
        print("Analizando conexiones (conn.log)...")
        reporte.write("\n--- Resumen de Conexiones ---\n")
        ip_origen_counter = Counter()
        ip_destino_counter = Counter()
        bytes_counter = Counter()
        duraciones = []
        puertos_destino_counter = Counter()
        total_udp_conexiones = 0
        tamanios_paquetes = []

        with open(conn_log_path, 'r') as conn_log:
            for line in conn_log:
                try:
                    if not line.startswith('#'):
                        parts = line.split()
                        ts = float(parts[0])  # Timestamp en UTC
                        proto = parts[6]
                        ip_origen = parts[2]
                        ip_destino = parts[4]
                        puerto_destino = parts[5]

                        bytes_transmitidos = int(parts[8]) if parts[8].isdigit() else 0
                        duracion = float(parts[9]) if parts[9].replace('.', '', 1).isdigit() else 0

                        ip_origen_counter[ip_origen] += 1
                        ip_destino_counter[ip_destino] += 1
                        puertos_destino_counter[puerto_destino] += 1
                        bytes_counter[bytes_transmitidos] += 1
                        duraciones.append(duracion)

                        if proto == "udp":
                            total_udp_conexiones += 1
                            tamanios_paquetes.append(bytes_transmitidos)

                        local_time = convertir_utc_a_local(ts)
                        reporte.write(f"Hora Local: {local_time}, Origen: {ip_origen}, Destino: {ip_destino}, Proto: {proto}\n")
                except (ValueError, IndexError) as e:
                    print(f"Error al procesar la línea: {e}\nContenido de la línea: {line}")
                except Exception as e:
                    print(f"Error inesperado al procesar la línea: {e}")

        reporte.write("\n--- IPs de Origen más comunes ---\n")
        for ip, count in ip_origen_counter.most_common(5):
            reporte.write(f"IP: {ip}, Veces: {count}\n")

        reporte.write("\n--- IPs de Destino más comunes ---\n")
        for ip, count in ip_destino_counter.most_common(5):
            reporte.write(f"IP: {ip}, Veces: {count}\n")

        reporte.write("\n--- Bytes Transmitidos más comunes ---\n")
        for bytes_transmitidos, count in bytes_counter.most_common(5):
            reporte.write(f"Bytes: {bytes_transmitidos}, Veces: {count}\n")

        reporte.write(f"\nDuración promedio de las conexiones: {sum(duraciones) / len(duraciones) if duraciones else 0} segundos\n")
        reporte.write(f"Duración máxima de una conexión: {max(duraciones) if duraciones else 0} segundos\n")

        reporte.write("\n--- Puertos de Destino más comunes ---\n")
        for puerto, count in puertos_destino_counter.most_common(5):
            reporte.write(f"Puerto: {puerto}, Veces: {count}\n")

        if total_udp_conexiones > 0:
            reporte.write("\n--- Análisis de Tráfico UDP ---\n")
            reporte.write(f"Total de conexiones UDP: {total_udp_conexiones}\n")
            if tamanios_paquetes:
                reporte.write(f"Tamaño promedio de paquetes UDP: {sum(tamanios_paquetes) / len(tamanios_paquetes)} bytes\n")
                reporte.write(f"Tamaño máximo de paquete UDP: {max(tamanios_paquetes)} bytes\n")


def analizar_logs_zeek(ruta_zeek_logs, reporte):
    """
    Analiza todos los logs generados por Zeek y escribe información en el reporte.
    """
    print("Analizando logs generados por Zeek...")
    logs = ["conn.log", "dns.log", "http.log", "notice.log", "files.log", "weird.log"]
    for log_name in logs:
        log_path = os.path.join(ruta_zeek_logs, log_name)
        if os.path.exists(log_path):
            print(f"Procesando {log_name}...")
            hash_value = calcular_hash(log_path)
            reporte.write(f"Hash del archivo {log_name}: {hash_value}\n")


def analizar_pcap(pcap_path):
    """
    Ejecuta Zeek sobre un archivo pcap y analiza los logs generados.
    """
    analysis_dir = os.path.join(os.path.dirname(pcap_path), "ANALISIS")
    os.makedirs(analysis_dir, exist_ok=True)

    # Generar archivo local.zeek
    local_zeek_path = generar_local_zeek(analysis_dir)

    reporte_path = os.path.join(analysis_dir, "reporte_analisis.txt")
    with open(reporte_path, 'w') as reporte:
        registrar_evento(reporte, "Inicio del análisis forense")

        pcap_hash = calcular_hash(pcap_path)
        reporte.write(f"Hash SHA-256 del archivo .pcap: {pcap_hash}\n")

        try:
            print(f"Ejecutando Zeek para analizar {pcap_path}...")
            with open(os.path.join(analysis_dir, "zeek_output.log"), "w") as output_log, open(os.path.join(analysis_dir, "zeek_error.log"), "w") as error_log:
                subprocess.run(
                    [zeek_path, "-r", pcap_path, local_zeek_path],
                    cwd=analysis_dir,
                    check=True,
                    stdout=output_log,
                    stderr=error_log
                )
            registrar_evento(reporte, "Zeek ejecutado correctamente")
            analizar_logs_zeek(analysis_dir, reporte)

        except subprocess.CalledProcessError as e:
            registrar_evento(reporte, "Error al ejecutar Zeek")
            reporte.write(f"Detalles del error: {e}\n")
            print(f"Error al ejecutar Zeek: {e}")

        registrar_evento(reporte, "Finalización del análisis forense")


if __name__ == "__main__":
    os.environ["TZ"] = "America/Santiago"  # Define la zona horaria globalmente
    zeek_path = encontrar_zeek()
    if len(sys.argv) < 2:
        print("Uso: python3 SCRIPT_ANALISIS.py <ruta_del_pcap>")
    else:
        analizar_pcap(sys.argv[1])
