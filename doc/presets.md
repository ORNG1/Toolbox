# Documentations presets Toolbox

## Outils intégrés 
Les outils intégrés à la Toolbox sont les suivants :
    - Nmap (reconnaissance et scan de ports réseau d'une cible)
    - Nikto (scan de la sécurité/vulnérabilités d'un serveur Web)
    - SQLMap (Injections SQL sur applications Web et API)
    - Hydra (Crackage de mot de passe par brute force sur protocoles réseau)
    - John the Ripper (Crackage de Hash de mot de passe)

## Détail de chaque preset / fonction

Nmap (Reconnaissance & Scan réseau) : 
    - Scan rapide : détéction des 100 ports les plus communs.
    - Scan de services & OS : Identification des versions des services et du système d'exploitation.
    - Scan complet (Full TCP) : Analyse des 65535 ports pour (très long et détectable) 
    - Audit de scripts (NSE) : lancement des scripts par défaut pour détecter les vulnérabilités connues.


Nikto (Vérification de serveur Web) :
    - Scan Standard : Vérification des fichiers dangereux, des CGI et des versions de serveur obsolètes.
    - Scan SSL/TLS : Analyse de la configuration du certificat et des protocoles de chiffrement (via couplage ou options Nikto).
    - Énumération de Répertoires : Recherche de dossiers sensibles oubliés (type /admin, /config).
    - Tuning spécifique : Scan ciblé uniquement sur les vulnérabilités de type "XSS" ou "Injection de fichiers".


SQLMap (Injections SQL) :
    - Test de Vulnérabilité (Banner) : Vérifie simplement si l'URL est injectable sans extraire de données.
    - Énumération des Bases : Liste toutes les bases de données disponibles sur le serveur cible.
    - Extraction des Tables : Récupère la structure d'une base spécifique pour identifier les données sensibles (comptes, mots de passe).
    - Dump complet : Extraction des données.


Hydra (Attaque brute-force en ligne) :
    - SSH Brute-force : Test d'un dictionnaire de mots de passe sur le port 22 pour le pôle Infrastructure.
    - FTP Brute-force : Tentative de connexion sur les services de transfert de fichiers.
    - HTTP Form Auth : Test de formulaires de connexion Web (ex: /login.php).
    - Énumération de comptes : Test de noms d'utilisateurs communs sans forcément chercher le mot de passe.


John the Ripper (Crackage de Hash) :
    - Mode "Single Crack" : Utilisation des informations de l'utilisateur (nom, prénom) pour deviner des mots de passe simples.
    - Attaque par Dictionnaire : Test d'une liste de mots de passe connus (type Rockyou) sur un fichier de hash fourni.
    - Mode Incremental (Brute-force) : Test de toutes les combinaisons possibles (très long, idéal pour illustrer le besoin de puissance).
    - Audit de conformité : Vérification rapide si les mots de passe respectent la politique de sécurité interne.