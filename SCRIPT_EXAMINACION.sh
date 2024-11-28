# Directorios
BASE_DIR="$HOME/Documentos/DATOS"
SOURCE_DIR="$BASE_DIR/ALL_CAPTURES" 
TARGET_DIR="$BASE_DIR"

# Configuración de la opción de revisión
MODE="A"  #debug para pruebas

# Función para generar estadísticas globales por hora
generar_estadisticas_globales() {
    local fecha=$1
    local hora=$2
    local year=$(echo "$fecha" | cut -d'-' -f1)
    local month=$(echo "$fecha" | cut -d'-' -f2)
    local month_name=$(date -d "$year-$month-01" +%B | awk '{print toupper($0)}')
    local unificado_dir="$TARGET_DIR/$year/MES_${month}_${month_name}/${fecha}_${month_name}/${hora}HRS"
    local archivo_unificado="$unificado_dir/LOG_PCAP_UNIFICADO_${hora}HRS.pcap"
    local stat_file="$unificado_dir/STAT_GLOBAL_${hora}HRS.txt"

    # Verificar si el archivo de estadísticas ya existe
    if [ ! -f "$stat_file" ]; then
        echo "Generando estadísticas globales para la hora ${hora}HRS" > "$stat_file"
        echo "----------------------------------------------------" >> "$stat_file"
        
        # Resumen de cantidad de frames por protocolo
        echo "Resumen de frames por protocolo:" >> "$stat_file"
        
        for proto in tcp udp icmp dnp3; do
            frames=$(tshark -r "$archivo_unificado" -Y "$proto" | wc -l)
            if [ -z "$frames" ]; then
                frames=0
            fi
            echo "$proto: Frames: $frames" >> "$stat_file"
        done

        echo "-------------------------------------" >> "$stat_file"

        # Conversaciones IP
        echo "Resumen de conversaciones IP (top 10):" >> "$stat_file"
        tshark -r "$archivo_unificado" -q -z conv,ip | head -n 12 >> "$stat_file"
        echo "-------------------------------------" >> "$stat_file"

        # Puertos más utilizados
        echo "Puertos más utilizados (top 10):" >> "$stat_file"
        tshark -r "$archivo_unificado" -T fields -e _ws.col.Protocol -e tcp.port -e udp.port | sort | uniq -c | sort -nr | head -n 10 >> "$stat_file"
        echo "-------------------------------------" >> "$stat_file"

        # Lista de IPs origen
        echo "Lista de IPs origen:" >> "$stat_file"
        tshark -r "$archivo_unificado" -T fields -e ip.src | sort | uniq -c | sort -nr | head -n 20 >> "$stat_file"
        echo "-------------------------------------" >> "$stat_file"

        # Añadir estadísticas de capinfos al final del archivo de estadísticas
        echo "Resumen detallado con capinfos:" >> "$stat_file"
        capinfos "$archivo_unificado" >> "$stat_file"
        echo "-------------------------------------" >> "$stat_file"

        echo "Estadísticas generales escritas en $stat_file"
    else
        echo "El archivo de estadísticas ya existe para la hora ${hora}HRS."
    fi

    echo "Estadísticas globales generadas correctamente."
}

# Función para unificar los archivos PCAP por hora
unificar_pcaps_por_hora() {
    local fecha=$1
    local hora=$2

    local year=$(echo "$fecha" | cut -d'-' -f1)
    local month=$(echo "$fecha" | cut -d'-' -f2)
    local month_name=$(date -d "$year-$month-01" +%B | awk '{print toupper($0)}')
    local hora_dir="$TARGET_DIR/$year/MES_${month}_${month_name}/${fecha}_${month_name}/${hora}HRS"

    # Verificar si la unificación ya se realizó
    if [ -d "$hora_dir" ] && [ -f "$hora_dir/LOG_PCAP_UNIFICADO_${hora}HRS.pcap" ]; then
        echo "Los archivos ya fueron unificados para la hora ${hora}HRS. Saltando..."
        return
    fi

    mkdir -p "$hora_dir"

    local pcap_unificado="$hora_dir/LOG_PCAP_UNIFICADO_${hora}HRS.pcap"
    
    echo "Unificando archivos PCAP para la hora ${hora}HRS..."

    # Unificar los PCAPs de la hora en un archivo único
    mergecap -w "$pcap_unificado" "$SOURCE_DIR"/*_${fecha}_${hora}*.pcap

    # Generar el archivo hash para el PCAP unificado
    sha256sum "$pcap_unificado" > "${pcap_unificado}.sha256.txt"
    echo "Archivos .pcap unificados correctamente para la hora ${hora}HRS"

    # Filtrar por protocolos y crear carpetas y hashes
    for proto in udp tcp dnp3 icmp; do
        local proto_dir="$hora_dir/${proto^^}"
        mkdir -p "$proto_dir"
        local filtro_pcap="$proto_dir/${proto}.pcap"
        tshark -r "$pcap_unificado" -Y "$proto" -w "$filtro_pcap"
        sha256sum "$filtro_pcap" > "${filtro_pcap}.sha256.txt"
        echo "Creando archivo filtrado para $proto y hash generado."
    done

    # Generar estadísticas globales
    generar_estadisticas_globales "$fecha" "$hora"
}

# Monitorear la carpeta para nuevos archivos .pcap y procesarlos
monitorear_nuevos_pcaps() {
    while true; do
        # Definir el intervalo de espera según el modo
        if [ "$MODE" == "debug" ]; then
            INTERVALO="600"  # 10 minutos
            echo "MODO DEBUG: Esperando al final del intervalo de 10 minutos..."
        else
            INTERVALO="3600"  # 1 hora
            echo "Esperando al final de la hora actual..."
        fi

        sleep $INTERVALO

        # Obtener la hora actual y verificar si hay que procesar la hora anterior
        hora_actual=$(date +"%H")
        if [ "$hora_actual" -eq "00" ]; then
            fecha=$(date -d "yesterday" +"%Y-%m-%d")
            hora_a_procesar="23"
        else
            fecha=$(date +"%Y-%m-%d")
            hora_a_procesar=$(printf "%02d" $((10#$hora_actual - 1)))
        fi

        unificar_pcaps_por_hora "$fecha" "$hora_a_procesar"
    done
}

# Procesar los archivos existentes
for pcap in "$SOURCE_DIR"/*.pcap; do
    nombre_archivo=$(basename "$pcap")
    fecha=$(echo "$nombre_archivo" | cut -d'_' -f2)
    hora=$(echo "$nombre_archivo" | cut -d'_' -f3 | cut -d'-' -f1)

    # Solo procesar las horas pasadas
    hora_actual=$(date +"%H")
    if [ "$hora" -lt "$hora_actual" ]; then
        unificar_pcaps_por_hora "$fecha" "$hora"
    fi
done

# Monitorear nuevos archivos bucle infinito.pcap
monitorear_nuevos_pcaps

