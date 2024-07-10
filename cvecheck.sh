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

# Remplacez 'YOUR_API_KEY' par votre clé d'API OpenCVE basé sur le base64 de votre user:password
API_KEY="XXX="
extrargs="--only-fixed"
#extrargs=""
cve_server="XXX"
# Définir la valeur maximale du score CVSS
cvss_score_max=3.0
# Définir la variable pour ignorer le score CVSS
ignore_cvss_score=false

source /etc/os-release

# Afficher le nom de la distribution
echo "Distribution: $NAME"
echo "Version: $VERSION"
echo "Codename: $VERSION_CODENAME"

# Exécuter debsecan et capturer la sortie
debsecan_output=$(debsecan --suite $VERSION_CODENAME --no-obsolete --format summary $extrargs | tr -s " " ";")

# Extraire les CVE de la sortie debsecan
declare -A cve_packages
while IFS= read -r line; do
    cve=$(echo "$line" | cut -d ';' -f 1)
    package=$(echo "$line" | cut -d ';' -f 2)
    if [[ $cve == CVE* ]]; then
        cve_packages["$cve"]="$package"
    fi
done <<< "$debsecan_output"

# Liste pour stocker les CVE et packages avec score CVSS élevé
cvss_list=()

# Faire une requête à l'API OpenCVE et extraire le score CVSS
for cve_id in "${!cve_packages[@]}"; do
    echo "testing $cve_id"
    response=$(curl -s -H "Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3" \
                    -H "Accept-Encoding: gzip, deflate, br, zstd" \
                    -H "Authorization: Basic $API_KEY" \
                    "$cve_server/api/cve/$cve_id")

   cvss_score=$(echo "$response" | jq -r '.cvss.v3 // .cvss.v2 // "Not Available"')
        echo $cvss_score
    if [[ "$cvss_score" != "Not Available" ]] && ( [[ "$ignore_cvss_score" == true ]] || (( $(echo "$cvss_score > $cvss_score_max" | bc -l) )) ); then
        package=${cve_packages[$cve_id]}
        cve_url="$cve_server/cve/$cve_id"
        echo "adding ${cve_id} ( ${package} ) to list"
        cvss_list+=("Package: $package, CVE: $cve_id, CVSS Score: $cvss_score, URL: $cve_url")
    elif [[ "$ignore_cvss_score" == true ]]; then
        package=${cve_packages[$cve_id]}
        cve_url="$cve_server/cve/$cve_id"
        echo "adding ${cve_id} ( ${package} ) to list"
        cvss_list+=("Package: $package, CVE: $cve_id, CVSS Score: $cvss_score, URL: $cve_url")
    fi
done
if [[ "$ignore_cvss_score" == true ]]; then
        echo "CVE avec un score CVSS trouvés"
        for entry in "${cvss_list[@]}"; do
        echo "$entry"
        done
else
# Afficher les résultats
        echo "CVE avec un score CVSS supérieur à $cvss_score_max:"
        for entry in "${cvss_list[@]}"; do
        echo "$entry"
        done
fi
