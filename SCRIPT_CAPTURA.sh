# Directorios 
BASE_DIR="~/Documentos"
OUTPUT_DIR="$BASE_DIR/ALL_CAPTURES"
INTERFACE="enp0s3"

# Intervalo de captura en segundos 
INTERVAL=300

# Crear el directorio de salida si no existe
mkdir -p "$OUTPUT_DIR"

# Captura continua en bucle
while true; do
    # Generar un ID único y la marca de tiempo
    ID=$(uuidgen)
    TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
    
    # Nombre de archivo de captura y hash
    PCAP_FILE="${OUTPUT_DIR}/${ID}_${TIMESTAMP}.pcap"
    HASH_FILE="${OUTPUT_DIR}/${ID}_${TIMESTAMP}.txt"

    # Captura el tráfico por el intervalo especificado en formato .pcap
    tshark -i "$INTERFACE" -a duration:$INTERVAL -F pcap -w "$PCAP_FILE"

    # Generar el hash del archivo de captura
    sha256sum "$PCAP_FILE" > "$HASH_FILE"

    echo "Captura guardada en: $PCAP_FILE"
    echo "Hash guardado en: $HASH_FILE"
done
