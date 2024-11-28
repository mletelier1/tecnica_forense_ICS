# Manual de Uso: Técnica de Análisis Forense Post-Incidente

Este repositorio contiene los scripts necesarios para implementar una técnica de análisis forense post-incidente en entornos industriales. La metodología está diseñada para ser aplicada de manera versátil a cualquier topología de red y protocolo industrial. El proyecto se ejemplifica en un entorno simulado de una subestación eléctrica automatizada.

---

## Requisitos Previos

### Instalación de Dependencias

El entorno base para ejecutar esta técnica está desarrollado en **Ubuntu**. Antes de ejecutar los scripts, asegúrate de instalar las siguientes herramientas:

```bash
# Actualizar paquetes
sudo apt update && sudo apt upgrade -y

# Instalar Tshark para capturas de tráfico
sudo apt install tshark -y

# Instalar Zeek para análisis de tráfico
sudo apt install zeek -y

# Instalar Python y librerías necesarias
sudo apt install python3 python3-pip -y
pip3 install pandas matplotlib fpdf
```

## Configuración Inicial

Antes de ejecutar los scripts, es necesario realizar una configuración inicial para asegurarte de que todo esté correctamente preparado.

### Identificar la Interfaz de Red

Para capturar el tráfico de red, es esencial identificar la interfaz de red activa en tu sistema. Usa el siguiente comando para listar todas las interfaces disponibles:

```bash
ip a
```
### Modifica la variable 
Modifica la variable INTERFACE en el script de captura para reflejar tu interfaz de red.

## Etapas del Análisis Forense

La técnica consta de cuatro etapas, cada una respaldada por un script específico. A continuación, se describe el propósito y el uso de cada una

---
### Colección de Datos (Captura)

La primera etapa consiste en capturar el tráfico de red en tiempo real, preservando la integridad de los datos mediante la generación de hashes SHA-256 para cada archivo capturado. Este proceso es automatizado y está diseñado para funcionar de forma continua.

Script
ETAPA_CAPTURA.SH

#### Configurar script

1. Configura BASE_DIR para definir la carpeta base donde se almacenarán los archivos de captura.
2. Interfaz: Asegúrate de definir correctamente INTERFACE para reflejar la interfaz de red utilizada.

#### Ejecutar script

``` bash
bash ETAPA_CAPTURA.SH
```

#### Salida
1. Archivos .pcap de tráfico capturado, almacenados en intervalos de 5 minutos.
2. Archivos .txt con los hashes SHA-256 correspondientes.

---

### Examinación de Datos

En esta etapa, los archivos .pcap capturados se consolidan por horas y se clasifican por protocolos (TCP, UDP, ICMP, DNP3, etc.). Este proceso simplifica el manejo de grandes volúmenes de datos y prepara la información para su análisis posterior.

Script
ETAPA_EXAMINACION.SH

#### Configurar script

1. Rutas: Configura BASE_DIR para definir las carpetas de entrada y salida de los datos procesados.

#### Ejecutar script

``` bash
bash ETAPA_EXAMINACION.SH
```

#### Salida
1. Archivos .pcap consolidados por hora.
2. Carpetas organizadas por protocolos con los datos correspondientes.
3. Archivos .txt con estadísticas básicas.

---
### Análisis de Datos

El análisis se centra en identificar patrones sospechosos y generar logs detallados de tráfico utilizando Zeek. Esta etapa automatiza el análisis para reducir la intervención humana y asegura la trazabilidad.

Script
ETAPA_ANALISIS.PY

#### Configurar script

1. Zeek debe estar correctamente instalado y en el PATH del sistema.

#### Ejecutar script

``` bash
python ETAPA_ANALISIS.py /RUTA_PCAP_A_ANALIZAR.pcap

```

#### Salida
1. Directorio ANALISIS con logs generados por Zeek, como conn.log, dns.log, y weird.log.
2. Reporte de conexiones y patrones detectados en un archivo reporte_analisis.txt.

---
### Reporte de Datos

La etapa final genera un reporte PDF que resume los hallazgos de las etapas anteriores. Incluye gráficos comparativos, tablas descriptivas, y glosarios que destacan las diferencias entre tráfico normal e infectado.

Script
ETAPA_REPORTE.PY

#### Configurar script

Antes de ejecutar el script, asegúrate de:

1. Tráfico normal capturado y procesado en formato .pcap.
2. Logs generados por Zeek para el tráfico normal e infectado.
3. Editar el .py y cambiar directorios dentro.

#### Ejecutar script

``` bash
python ETAPA_REPORTE.py

```

#### Salida
1. Gráficos de IPs más frecuentes, puertos utilizados, y evolución temporal del tráfico.
2. Tablas comparativas y glosarios de protocolos.
3. Resumen detallado de tráfico normal vs. infectado.

---

<small>Técnica de análisis forense realizada el año 2024, Ing. Civil Electrónica, PUCV Matías Letelier A.</small>

