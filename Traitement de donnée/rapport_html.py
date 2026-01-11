# rapport_html.py
import webbrowser
def generer_html(
    table,
    stats,
    chemin_html,
    nom_source,
    img_ip_src,
    img_ip_dst,
    img_ports,
    img_lengths,
    img_proto,
    img_requetes,
    img_ssh_sessions,
    img_ssh_volume,
    img_ssh_flags,
):
    html = f"""
<!DOCTYPE html>
<html lang="fr" data-bs-theme="dark">
<head>
  <meta charset="UTF-8">
  <title>Analyse réseau</title>
  <!-- Thème Bootswatch Cyborg -->
  <link rel="stylesheet"
        href="https://bootswatch.com/5/cyborg/bootstrap.min.css">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-primary mb-4">
  <div class="container">
    <span class="navbar-brand mb-0 h1">Analyse des traces réseau</span>
  </div>
</nav>

<div class="container mb-5">

  <!-- Card axes d'analyse -->
  <div class="card mb-4">
    <div class="card-header">
      Axes d'analyse recommandés
    </div>
    <div class="card-body">
      <p class="card-text">
        Ce rapport permet de visualiser rapidement les IP les plus actives, les ports les plus sollicités,
        la longueur des paquets et la répartition des protocoles pour identifier des comportements anormaux.
      </p>
      <p class="card-text">
        Les informations ci-dessous proviennent de l’analyse du résultat de la commande <code>tcpdump</code>,
        outil de capture de paquets largement utilisé pour le diagnostic réseau et l’analyse de sécurité.
      </p>
    </div>
  </div>

  <!-- Résumé -->
  <div class="card mb-4">
    <div class="card-header">
      Résumé du fichier
    </div>
    <div class="card-body">
      <p class="card-text"><strong>Fichier analysé :</strong> {nom_source}</p>
      <p class="card-text"><strong>Nombre total de paquets analysés :</strong> {stats['nb_total']}</p>
      <p class="card-text"><strong>Volume total :</strong> {stats['octets_total']} octets</p>
    </div>
  </div>

  <!-- Card : Vue synthétique du trafic -->
  <div class="card mb-4">
    <div class="card-header">
      Vue synthétique du trafic
    </div>
    <div class="card-body">
      <div class="row g-4">

        <div class="col-12 col-lg-6">
          <h5 class="text-center mb-2">Top IP source</h5>
          <img src="{img_ip_src}" class="img-fluid rounded mb-2" alt="Top IP source">
          <p class="small text-muted">
            Ce graphique met en évidence les machines qui émettent le plus de requêtes
            et permet de repérer rapidement une IP potentiellement à l’origine d’un scan ou d’un débit inhabituel.
          </p>
        </div>

        <div class="col-12 col-lg-6">
          <h5 class="text-center mb-2">Top IP destination</h5>
          <img src="{img_ip_dst}" class="img-fluid rounded mb-2" alt="Top IP destination">
          <p class="small text-muted">
            Ce graphique montre quelles machines reçoivent le plus de trafic et peut indiquer
            une cible de scan, de DDoS ou un serveur fortement sollicité.
          </p>
        </div>

        <div class="col-12 col-lg-6">
          <h5 class="text-center mb-2">10 ports les plus utilisés</h5>
          <img src="{img_ports}" class="img-fluid rounded mb-2" alt="Ports les plus utilisés">
          <p class="small text-muted">
            La répartition des ports aide à identifier les services les plus exposés (HTTP, HTTPS, SSH, etc.)
            et à repérer d’éventuels scans de ports sur des services inattendus.
          </p>
        </div>

        <div class="col-12 col-lg-6">
          <h5 class="text-center mb-2">Distribution de la longueur des paquets</h5>
          <img src="{img_lengths}" class="img-fluid rounded mb-2" alt="Longueur des paquets">
          <p class="small text-muted">
            L’analyse de la taille des paquets permet de voir si le trafic est principalement composé
            de petits paquets (scans, SYN) ou de flux plus volumineux (transferts de données).
          </p>
        </div>

        <div class="col-12 col-lg-6">
          <h5 class="text-center mb-2">Nombre de requêtes (par IP source)</h5>
          <img src="{img_requetes}" class="img-fluid rounded mb-2" alt="Nombre de requêtes">
          <p class="small text-muted">
            Ce graphique résume le nombre total de requêtes par IP source et sert à confirmer ou infirmer
            le rôle d’une machine dans une activité suspecte ou anormalement bavarde.
          </p>
        </div>

        <div class="col-12 col-lg-6">
          <h5 class="text-center mb-2">Répartition des protocoles</h5>
          <img src="{img_proto}" class="img-fluid rounded mb-2" alt="Répartition des protocoles">
          <p class="small text-muted">
            La répartition des protocoles indique si le trafic est conforme à l’usage prévu
            (web, DNS, SSH) ou s’il contient une proportion inhabituelle de certains services.
          </p>
        </div>

      </div>
    </div>
  </div>

  <!-- Card : Activité SSH -->
  <div class="card mb-4">
    <div class="card-header">
      Activité SSH
    </div>
    <div class="card-body">
      <div class="row g-4">

        <div class="col-12 col-lg-6">
          <h5 class="text-center mb-2">Sessions SSH approximées</h5>
          <img src="{img_ssh_sessions}" class="img-fluid rounded mb-2" alt="Sessions SSH">
          <p class="small text-muted">
            Ce graphique représente, pour chaque couple client → serveur en SSH, le nombre de paquets
            observés, ce qui donne une idée du nombre et de l’intensité des sessions actives.
          </p>
        </div>

        <div class="col-12 col-lg-6">
          <h5 class="text-center mb-2">Volume échangé par session SSH</h5>
          <img src="{img_ssh_volume}" class="img-fluid rounded mb-2" alt="Volume SSH par session">
          <p class="small text-muted">
            La comparaison des octets client → serveur et serveur → client par session permet
            de repérer des connexions déséquilibrées, par exemple un débit anormal côté serveur.
          </p>
        </div>

        <div class="col-12 col-lg-6">
          <h5 class="text-center mb-2">Répartition des flags TCP (SSH)</h5>
          <img src="{img_ssh_flags}" class="img-fluid rounded mb-2" alt="Flags SSH">
          <p class="small text-muted">
            La répartition des flags (SYN, FIN, RST, PSH, ACK…) sur le trafic SSH aide à repérer
            des terminaisons brutales (beaucoup de RST) ou des sessions qui poussent surtout des données.
          </p>
        </div>

      </div>
    </div>
  </div>

</div> <!-- /.container -->

</body>
</html>
"""
    with open(chemin_html, "w", encoding="utf-8") as f:
        f.write(html)
