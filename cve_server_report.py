from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from functools import wraps, lru_cache
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

app = Flask(__name__)

# Configuration de la base de données SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Clé API pour l'authentification
API_KEY = 'XXX'
API_OPENCVE_KEY = "XXX"
OPENCVE_SERVER = "http://XX"
# Cache mémoire pour les détails des CVE
@lru_cache(maxsize=4096)
def get_cve_details(cve_id):
    # Fonction pour récupérer les détails d'une CVE depuis l'API OpenCVE
    url = f'{OPENCVE_SERVER}/api/cve/{cve_id}'
    headers = {'Accept-Language': 'fr', 'Authorization': f'Basic {API_OPENCVE_KEY}'}
    start_time = time.time()  # Chronométrer le temps de début de la requête
    print(f"call {url}")
    try:
        response = requests.get(url, headers=headers)
        response_time = time.time() - start_time  # Calculer le temps de réponse
        if response.status_code == 200:
            print(f"time: {response_time}")
            return response.json(), response_time
        else:
            print(f"time: {response_time}")
            return None, response_time
    except requests.exceptions.RequestException as e:
        response_time = time.time() - start_time  # En cas d'erreur, calculer le temps de réponse
        print(f"Error fetching CVE details for {cve_id}: {str(e)}")
        return None, response_time

# Table d'association pour les relations many-to-many entre Server et Package
server_package = db.Table('server_package',
    db.Column('server_id', db.Integer, db.ForeignKey('server.id'), primary_key=True),
    db.Column('package_id', db.Integer, db.ForeignKey('package.id'), primary_key=True)
)

# Modèle pour les serveurs
class Server(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    ip = db.Column(db.String(120), nullable=False)
    packages = db.relationship('Package', secondary=server_package, backref=db.backref('servers', lazy=True))

# Table intermédiaire pour relier les paquets et les CVE
class PackageCVE(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    package_id = db.Column(db.Integer, db.ForeignKey('package.id'), nullable=False)
    cve = db.Column(db.String(50), nullable=False)
    db.UniqueConstraint('package_id', 'cve', name='unique_package_cve')

# Modèle pour les paquets
class Package(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    version = db.Column(db.String(50), nullable=False)
    cves = db.relationship('PackageCVE', backref='package', lazy=True)

def require_api_key(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if request.headers.get('x-api-key') == API_KEY:
            return func(*args, **kwargs)
        else:
            return jsonify({"message": "Unauthorized"}), 401
    return decorated_function

@app.route('/upload', methods=['POST'])
@require_api_key
def upload_json():
    if request.is_json:
        content = request.get_json()

        server_name = content.get('NOM')
        server_ip = content.get('IP')
        data = content.get('données')

        if not server_name or not server_ip or not data:
            return jsonify({"message": "Invalid JSON structure"}), 400

        server = Server.query.filter_by(name=server_name).first()
        if not server:
            server = Server(name=server_name, ip=server_ip)
            db.session.add(server)
            db.session.commit()

        # Dissocier tous les paquets actuels
        server.packages = []

        for item in data:
            package_name = item.get('nom-paquet')
            package_version = item.get('version')
            package_cve = item.get('CVE')

            package = Package.query.filter_by(name=package_name, version=package_version).first()
            if not package:
                package = Package(name=package_name, version=package_version)
                db.session.add(package)
                db.session.commit()

            # Ajouter le CVE au paquet
            package_cve_entry = PackageCVE.query.filter_by(package_id=package.id, cve=package_cve).first()
            if not package_cve_entry:
                package_cve_entry = PackageCVE(package_id=package.id, cve=package_cve)
                db.session.add(package_cve_entry)
                db.session.commit()

            if package not in server.packages:
                server.packages.append(package)

        db.session.commit()

        return jsonify({"message": "Data uploaded successfully"}), 201
    else:
        return jsonify({"message": "Request must be JSON"}), 400

@app.route('/data/<server_name>', methods=['GET'])
@require_api_key
def get_data(server_name):
    server = Server.query.filter_by(name=server_name).first()
    if server:
        packages = []
        cve_ids = [cve.cve for pkg in server.packages for cve in pkg.cves]

        # Utilisation de ThreadPoolExecutor pour récupérer les détails des CVE en parallèle
        MAX_THREADS = 4  # Nombre maximal de threads à utiliser
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = {executor.submit(get_cve_details, cve_id): cve_id for cve_id in cve_ids}
            for future in as_completed(futures):
                cve_id = futures[future]
                try:
                    cve_details, response_time = future.result()
                    if cve_details:
                        cves = {
                            "CVE": cve_id,
                            "details": cve_details,
                            "response_time": response_time  # Ajouter le temps de réponse à la réponse JSON
                        }
                    else:
                        cves = {
                            "CVE": cve_id,
                            "details": {"message": f"Détails de la CVE {cve_id} non disponibles"},
                            "response_time": response_time  # Ajouter le temps de réponse à la réponse JSON
                        }
                    packages.append(cves)
                except Exception as e:
                    print(f"Error fetching CVE details for {cve_id}: {str(e)}")

        return jsonify({"IP": server.ip, "données": packages})
    else:
        return jsonify({"message": "Server not found"}), 404

if __name__ == '__main__':
    db.create_all()  # Crée les tables dans la base de données si elles n'existent pas
#    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)

    from waitress import serve
    serve(app, host='0.0.0.0', port=5000)
