#!/bin/bash

if ! command -v jq &> /dev/null; then
    echo "Erreur : jq n'est pas installé. Veuillez installer jq avant de continuer."
    exit 1
fi

# Vérifier si debsecan est installé
if ! command -v debsecan &> /dev/null; then
    echo "Erreur : debsecan n'est pas installé. Veuillez installer debsecan avant de continuer."
    exit 1
fi

# Remplacez 'YOUR_API_KEY' par votre clé d'API OpenCVE
API_KEY="XXX"
cve_report_server_key="XXX"
extrargs="--only-fixed"
#extrargs=""
cve_server="http://192.168.1.247"
cve_report_server=http://192.168.1.247:5000
# Définir la valeur maximale du score CVSS
cvss_score_max=1.0
# Définir la variable pour ignorer le score CVSS
ignore_cvss_score=true

source /etc/os-release

# Afficher le nom de la distribution
echo "Distribution: $NAME"
echo "Version: $VERSION"
echo "Codename: $VERSION_CODENAME"

# Exécuter debsecan et capturer la sortie
debsecan_output=$(debsecan --suite $VERSION_CODENAME --no-obsolete --format detail $extrargs)

# Liste pour stocker les CVE avec leurs détails
cve_list=()

# Variables temporaires pour stocker les informations en cours de lecture
cve=""
installed_package=""
installed_version=""
count=0
# Lire chaque ligne de la sortie de debsecan


while IFS= read -r line; do
    # Si la ligne commence par CVE-, c'est une nouvelle CVE
    if [[ "$line" =~ ^CVE-[0-9]{4}-[0-9]{4,} ]]; then
        # Vérifier si la CVE existe déjà dans cve_list
        if ! grep -q "\"CVE\": \"$cve\"" <<< "${cve_list[@]}"; then
            # Si nous avons déjà des informations en attente, ajouter la CVE précédente à la liste
            if [[ -n "$cve" && -n "$installed_package" && -n "$installed_version" ]]; then
                cve_list+=("{\"nom-paquet\": \"$installed_package\", \"version\": \"$installed_version\", \"CVE\": \"$cve\"}")
            fi
        fi
        # Réinitialiser les variables pour la nouvelle CVE
        cve=$(echo "$line" | awk '{print $1}')
        installed_package=""
        installed_version=""
    elif grep -q "^\s*installed:" <<< "$line"; then
        # Capturer le nom du paquet installé et sa version
        installed_info=$(echo "$line")
        if [[ -n "$installed_info" ]]; then
            installed_package=$(echo "$installed_info" | awk '{print $2}')
            installed_version=$(echo "$installed_info" | awk '{print $3}')
        fi
    fi
done <<< "$debsecan_output"

# Ajouter la dernière CVE à la liste (si elle existe et n'a pas été ajoutée)
if [[ -n "$cve" && -n "$installed_package" && -n "$installed_version" ]]; then
    if ! grep -q "\"CVE\": \"$cve\"" <<< "${cve_list[@]}"; then
        cve_list+=("{\"nom-paquet\": \"$installed_package\", \"version\": \"$installed_version\", \"CVE\": \"$cve\"}")
    fi
fi



# Liste pour stocker les CVE avec un score CVSS élevé
cvss_list=()

# Faire une requête à l'API OpenCVE pour chaque CVE
for cve_data in "${cve_list[@]}"; do
    cve=$(jq -r '.CVE' <<< "$cve_data")
    echo "Testing $cve"
    if [[ ! "$ignore_cvss_score" == true ]]; then
    response=$(curl -s -H "Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3" \
                    -H "Accept-Encoding: gzip, deflate, br, zstd" \
                    -H "Authorization: Basic $API_KEY" \
                    "$cve_server/api/cve/$cve")

    cvss_score=$(echo "$response" | jq -r '.cvss.v3 // .cvss.v2 // "Not Available"')
   fi
    echo "CVSS Score for $cve: $cvss_score"

    if [[ "$cvss_score" != "Not Available" ]] && ( [[ "$ignore_cvss_score" == true ]] || (( $(echo "$cvss_score > $cvss_score_max" | bc -l) )) ); then
        echo "Adding $cve_data to list"
        cvss_list+=("$cve_data")
    elif [[ "$ignore_cvss_score" == true ]]; then
        echo "Adding $cve_data to list"
        cvss_list+=("$cve_data")
    fi
done

# Créer la structure JSON
json_data=$(jq -n \
    --arg name "$(hostname)" \
    --arg ip "$(hostname -I | awk '{print $1}')" \
    --argjson data "$(printf '%s\n' "${cvss_list[@]}" | jq -s .)" \
    '{NOM: $name, IP: $ip, "données": $data}')


# Envoyer les données au serveur Python
curl -X POST $cve_report_server/upload \
    -H "x-api-key: $cve_report_server_key" \
    -H "Content-Type: application/json" \
    -d "$json_data"
