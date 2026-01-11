#!/usr/bin/env python3
# prog_reseau_gui.py

# Imports des bibliothèques nécessaires pour l'interface graphique,
# la lecture/écriture de fichiers, les expressions régulières,
# les statistiques et les graphes.
import tkinter as tk
from tkinter import filedialog, messagebox
import re
import csv
from collections import Counter, defaultdict
import os

import matplotlib.pyplot as plt  # Pour générer les graphiques.

from rapport_html import generer_html  # Fonction qui génère le rapport HTML final.


# =======================
# 0. Répertoire de sortie
# =======================

def get_output_dir():
    """
    Retourne le chemin du répertoire dans lequel seront sauvegardés
    les fichiers générés (CSV, HTML, images).
    Crée le dossier 'Fichier renvoyé' s'il n'existe pas.
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))  # Dossier où se trouve ce script.
    out_dir = os.path.join(base_dir, "Fichier renvoyé")    # Sous-dossier de sortie.
    os.makedirs(out_dir, exist_ok=True)                    # Création si nécessaire.
    return out_dir


# =======================
# 1. Sélection du fichier
# =======================

def choisir_fichier_reseau():
    """
    Ouvre une boîte de dialogue pour permettre à l'utilisateur de choisir
    un fichier texte contenant les traces réseau (tcpdump/wireshark).
    """
    chemin_fichier = filedialog.askopenfilename(
        title="Sélectionner un fichier texte réseau",
        filetypes=[("Fichiers texte", "*.txt"), ("Tous les fichiers", "*.*")]
    )
    return chemin_fichier


def lire_fichier(chemin):
    """
    Lit le fichier texte ligne par ligne et renvoie une liste de lignes
    sans le caractère de fin de ligne.
    """
    with open(chemin, "r", encoding="utf-8") as f:
        return [l.rstrip("\n") for l in f]


# =======================
# 2. Parsing des lignes
# =======================

# Expression régulière permettant d'extraire les informations d'une ligne IP :
# heure, IP/port source, IP/port destination, flags TCP et longueur.
REG_IP = re.compile(
    r'^(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+'
    r'(?P<src>[\w\.-]+)\.(?P<src_port>[\w\d]+)\s*>\s*'
    r'(?P<dst>[\w\.-]+)\.(?P<dst_port>[\w\d]+):\s*'
    r'Flags\s+\[(?P<flags>[^\]]*)\].*?'
    r'length\s+(?P<length>\d+)'
)


def split_host_port(nom):
    """
    Sépare un nom de type 'hote.port' en deux parties :
    - host : tout sauf le dernier élément
    - port : dernier élément
    Si aucun point n'est présent, renvoie le nom complet et 'vide' comme port.
    """
    parts = nom.split(".")
    if len(parts) >= 2:
        host = ".".join(parts[:-1])
        port = parts[-1]
    else:
        host = nom
        port = "vide"
    return host, port


def ligne_vers_dict(ligne):
    """
    Convertit une ligne de texte en dictionnaire avec les champs utiles :
    heure, src_host, src_port, dst_host, dst_port, flags, length.
    Renvoie None si la ligne ne correspond pas au format attendu.
    """
    m = REG_IP.match(ligne)
    if not m:
        return None
    d = m.groupdict()

    # Récupération et séparation des hôtes et ports source/destination.
    src_full = d["src"]
    dst_full = d["dst"]
    src_host, src_port2 = split_host_port(src_full)
    dst_host, dst_port2 = split_host_port(dst_full)

    # Construction du dictionnaire standardisé.
    return {
        "heure": d["time"],
        "src_host": src_host,
        "src_port": d.get("src_port") or src_port2,
        "dst_host": dst_host,
        "dst_port": d.get("dst_port") or dst_port2,
        "flags": d["flags"],
        "length": int(d["length"]),
    }


def construire_tableau(lignes):
    """
    Applique 'ligne_vers_dict' à chaque ligne du fichier et
    construit une table (liste de dictionnaires) pour les lignes valides.
    """
    table = []
    for l in lignes:
        evt = ligne_vers_dict(l)
        if evt is not None:
            table.append(evt)
    return table


def ecrire_csv(table, chemin_csv):
    """
    Écrit le contenu de la table (liste de dictionnaires) dans un fichier CSV.
    Les colonnes sont : heure, src_host, src_port, dst_host, dst_port, flags, length.
    """
    if not table:
        return
    champs = ["heure", "src_host", "src_port", "dst_host", "dst_port", "flags", "length"]
    with open(chemin_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=champs, delimiter=";")
        w.writeheader()
        for e in table:
            w.writerow(e)


def analyser_globale(table):
    """
    Calcule des statistiques globales :
    - nombre total de paquets
    - somme totale des longueurs (octets).
    """
    total = len(table)
    total_octets = sum(e["length"] for e in table)
    return {
        "nb_total": total,
        "octets_total": total_octets,
    }


# =======================
# 2bis. Statistiques génériques
# =======================

def stats_ip_sources(table, top_n=10):
    """
    Renvoie le top N des IP sources les plus fréquentes
    sous forme de liste (ip, nombre d'occurrences).
    """
    c = Counter(e["src_host"] for e in table)
    return c.most_common(top_n)


def stats_ip_destinations(table, top_n=10):
    """
    Renvoie le top N des IP destinations les plus fréquentes.
    """
    c = Counter(e["dst_host"] for e in table)
    return c.most_common(top_n)


def stats_ports(table, top_n=10):
    """
    Renvoie le top N des ports de destination les plus utilisés.
    """
    c = Counter(str(e["dst_port"]) for e in table)
    return c.most_common(top_n)


def stats_longueurs(table):
    """
    Renvoie la liste des longueurs de paquets,
    utilisée pour tracer un histogramme.
    """
    return [e["length"] for e in table]


def stats_protocoles(table):
    """
    Classe les paquets par grande famille de protocole
    en se basant sur le port de destination :
    DNS, SSH, HTTP, HTTPS ou AUTRES.
    """
    counts = Counter()
    for e in table:
        port = str(e["dst_port"])
        if port in ("53", "domain"):
            counts["DNS"] += 1
        elif port in ("22", "ssh"):
            counts["SSH"] += 1
        elif port in ("80", "http"):
            counts["HTTP"] += 1
        elif port in ("443", "https"):
            counts["HTTPS"] += 1
        else:
            counts["AUTRES"] += 1
    return counts


# =======================
# 2ter. Statistiques SSH
# =======================

def filtrer_ssh(table):
    """
    Filtre les paquets appartenant au trafic SSH :
    on garde les paquets où le port source ou destination vaut 22 ou 'ssh'.
    """
    ssh_pkts = []
    for e in table:
        if (str(e["src_port"]) == "22" or str(e["dst_port"]) == "22"
            or e["src_port"] == "ssh" or e["dst_port"] == "ssh"):
            ssh_pkts.append(e)
    return ssh_pkts


def stats_ssh_sessions(table):
    """
    Approximation de sessions SSH :
    - clé = (src_host, dst_host)
    - 'client' = côté où le port != 22
    - 'serveur' = côté où le port = 22
    On calcule pour chaque couple :
      - nombre de paquets
      - octets totaux
      - octets client->serveur
      - octets serveur->client
    """
    sessions = defaultdict(lambda: {
        "pkts": 0,
        "bytes_total": 0,
        "bytes_client": 0,
        "bytes_server": 0,
    })
    ssh_pkts = filtrer_ssh(table)

    for e in ssh_pkts:
        key = (e["src_host"], e["dst_host"])
        s = sessions[key]
        s["pkts"] += 1
        s["bytes_total"] += e["length"]

        # Détermination du sens client / serveur.
        if str(e["src_port"]) == "22" or e["src_port"] == "ssh":
            s["bytes_server"] += e["length"]  # Le serveur envoie vers le client.
        else:
            s["bytes_client"] += e["length"]  # Le client envoie vers le serveur.

    return sessions


def stats_flags_ssh(table):
    """
    Répartition des flags TCP pour le trafic SSH (port 22).
    On compte le nombre de paquets contenant chaque lettre de flag (S, F, R, P, A, etc.).
    """
    ssh_pkts = filtrer_ssh(table)
    counts = Counter()
    for e in ssh_pkts:
        for ch in e["flags"]:
            if ch.isalpha():
                counts[ch] += 1
    return counts


# =======================
# 2quater. Génération des graphes
# =======================

def plot_bar(labels, values, title, xlabel, ylabel, path):
    """
    Crée un graphique en barres simple et l'enregistre dans un fichier image.
    """
    plt.figure(figsize=(8, 4))
    plt.bar(range(len(labels)), values)
    plt.xticks(range(len(labels)), labels, rotation=45, ha="right")
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.tight_layout()
    plt.savefig(path)
    plt.close()


def plot_hist(data, title, xlabel, ylabel, path, bins=20):
    """
    Crée un histogramme à partir de la liste 'data' et l'enregistre.
    """
    plt.figure(figsize=(8, 4))
    plt.hist(data, bins=bins)
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.tight_layout()
    plt.savefig(path)
    plt.close()


def plot_pie(labels, values, title, path):
    """
    Crée un diagramme circulaire et l'enregistre.
    Si toutes les valeurs sont nulles, on affiche un message 'Aucune donnée'.
    """
    plt.figure(figsize=(5, 5))
    if sum(values) == 0:
        labels = ["Aucune donnée"]
        values = [1]
    plt.pie(values, labels=labels, autopct="%1.1f%%", startangle=90)
    plt.title(title)
    plt.tight_layout()
    plt.savefig(path)
    plt.close()


def generer_graphiques_synthese(table, output_dir):
    """
    Génère les graphiques de synthèse :
    - Top IP sources
    - Nombre de requêtes par IP source
    - Top IP destinations
    - Top ports de destination
    - Distribution des longueurs de paquets
    - Répartition des protocoles
    Renvoie un dictionnaire contenant les chemins des images.
    """
    # IP sources (nombre de requêtes)
    top_src = stats_ip_sources(table)
    if not top_src:
        top_src = [("Aucune IP", 0)]
    labels_src = [ip for ip, n in top_src]
    values_src = [n for ip, n in top_src]
    img_ip_src = os.path.join(output_dir, "ip_sources.png")
    plot_bar(labels_src, values_src,
             "Top IP source", "IP source", "Nombre de paquets", img_ip_src)

    # Nombre de requêtes par IP source (graphique dédié)
    img_requetes = os.path.join(output_dir, "requetes_par_ip.png")
    plot_bar(labels_src, values_src,
             "Nombre de requêtes par IP source",
             "IP source", "Nombre de requêtes", img_requetes)

    # IP destinations
    top_dst = stats_ip_destinations(table)
    if not top_dst:
        top_dst = [("Aucune IP", 0)]
    labels_dst = [ip for ip, n in top_dst]
    values_dst = [n for ip, n in top_dst]
    img_ip_dst = os.path.join(output_dir, "ip_destinations.png")
    plot_bar(labels_dst, values_dst,
             "Top IP destination", "IP destination", "Nombre de paquets", img_ip_dst)

    # Ports les plus utilisés
    top_ports = stats_ports(table)
    if not top_ports:
        top_ports = [("aucun", 0)]
    labels_ports = [p for p, n in top_ports]
    values_ports = [n for p, n in top_ports]
    img_ports = os.path.join(output_dir, "ports_top10.png")
    plot_bar(labels_ports, values_ports,
             "10 ports les plus utilisés", "Port destination", "Nombre de paquets", img_ports)

    # Longueur des paquets
    lengths = stats_longueurs(table)
    if not lengths:
        lengths = [0]
    img_lengths = os.path.join(output_dir, "longueurs_paquets.png")
    plot_hist(lengths,
              "Distribution de la longueur des paquets",
              "Longueur (octets)", "Nombre de paquets", img_lengths)

    # Répartition des protocoles
    proto_counts = stats_protocoles(table)
    labels_proto = list(proto_counts.keys())
    values_proto = list(proto_counts.values())
    if not labels_proto:
        labels_proto = ["Aucun"]
        values_proto = [1]
    img_proto = os.path.join(output_dir, "protocoles.png")
    plot_pie(labels_proto, values_proto,
             "Répartition des protocoles (par port destination)", img_proto)

    return {
        "img_ip_src": img_ip_src,
        "img_ip_dst": img_ip_dst,
        "img_ports": img_ports,
        "img_lengths": img_lengths,
        "img_proto": img_proto,
        "img_requetes": img_requetes,
    }


def generer_graphiques_ssh(table, output_dir):
    """
    Génère les graphiques spécifiques au trafic SSH :
    - Paquets par session SSH
    - Volume client/serveur par session
    - Répartition des flags TCP
    Renvoie un dictionnaire avec les chemins des images.
    """
    # Stats de sessions SSH
    sessions = stats_ssh_sessions(table)
    if not sessions:
        # Si aucune session, on crée une session fictive pour garder un graphe.
        sessions = {("aucune_session", "ssh"): {
            "pkts": 0,
            "bytes_total": 0,
            "bytes_client": 0,
            "bytes_server": 0,
        }}

    labels_sess = [f"{src}->{dst}" for (src, dst) in sessions.keys()]
    pkts_sess = [s["pkts"] for s in sessions.values()]
    bytes_total = [s["bytes_total"] for s in sessions.values()]
    bytes_client = [s["bytes_client"] for s in sessions.values()]
    bytes_server = [s["bytes_server"] for s in sessions.values()]

    # Nombre de paquets par session SSH (approximation du nombre de sessions actives).
    img_ssh_sessions = os.path.join(output_dir, "ssh_sessions_nb.png")
    plot_bar(labels_sess, pkts_sess,
             "Paquets par session SSH (approx.)",
             "Session (client -> serveur)", "Nombre de paquets", img_ssh_sessions)

    # Volume client / serveur par session (barres côte à côte).
    img_ssh_volume = os.path.join(output_dir, "ssh_sessions_volume.png")
    plt.figure(figsize=(8, 4))
    x = range(len(labels_sess))
    plt.bar([i - 0.2 for i in x], bytes_client, width=0.4, label="Client -> Serveur")
    plt.bar([i + 0.2 for i in x], bytes_server, width=0.4, label="Serveur -> Client")
    plt.xticks(list(x), labels_sess, rotation=45, ha="right")
    plt.title("Volume échangé par session SSH")
    plt.xlabel("Session (client -> serveur)")
    plt.ylabel("Octets")
    plt.legend()
    plt.tight_layout()
    plt.savefig(img_ssh_volume)
    plt.close()

    # Répartition des flags sur le trafic SSH.
    flags_counts = stats_flags_ssh(table)
    labels_flags = list(flags_counts.keys()) or ["Aucun"]
    values_flags = list(flags_counts.values()) or [1]
    img_ssh_flags = os.path.join(output_dir, "ssh_flags.png")
    plot_pie(labels_flags, values_flags,
             "Répartition des flags TCP (SSH)", img_ssh_flags)

    return {
        "img_ssh_sessions": img_ssh_sessions,
        "img_ssh_volume": img_ssh_volume,
        "img_ssh_flags": img_ssh_flags,
    }


# =======================
# 3. Interface graphique
# =======================

def afficher_resultat(texte_resultat, chemin_csv, chemin_html, stats, output_dir):
    """
    Met à jour la zone de texte de l'interface pour afficher :
    - le dossier de sortie
    - les noms des fichiers générés
    - les statistiques globales (nb de paquets, octets).
    """
    texte_resultat.config(state="normal")
    texte_resultat.delete("1.0", tk.END)
    texte_resultat.insert(
        tk.END,
        f"Fichiers générés dans : {output_dir}\n\n"
        f"- {os.path.basename(chemin_csv)}\n"
        f"- {os.path.basename(chemin_html)}\n\n"
        f"Paquets totaux : {stats['nb_total']}\n"
        f"Octets totaux : {stats['octets_total']}\n"
    )
    texte_resultat.config(state="disabled")


def traiter_fichier(texte_resultat):
    """
    Chaîne complète de traitement lorsqu'on clique sur le bouton :
    - choix du fichier
    - parsing et construction de la table
    - calcul des stats
    - génération des CSV, graphiques et rapport HTML
    - ouverture du rapport dans le navigateur
    - affichage d'un résumé dans la zone de texte.
    """
    chemin = choisir_fichier_reseau()
    if not chemin:
        return  # L'utilisateur a annulé la sélection.

    lignes = lire_fichier(chemin)
    table = construire_tableau(lignes)

    if not table:
        messagebox.showwarning("Erreur", "Aucun paquet IP valide n'a été trouvé dans ce fichier.")
        return

    output_dir = get_output_dir()

    # Chemins de sortie pour le CSV et le rapport HTML.
    chemin_csv = os.path.join(output_dir, "reseau_analyse.csv")
    chemin_html = os.path.join(output_dir, "rapport_reseau.html")

    # Écriture du CSV et calcul des statistiques globales.
    ecrire_csv(table, chemin_csv)
    stats = analyser_globale(table)

    # Graphes vue synthétique.
    imgs_synthese = generer_graphiques_synthese(table, output_dir)
    # Graphes SSH.
    imgs_ssh = generer_graphiques_ssh(table, output_dir)

    # Génération du rapport HTML complet.
    generer_html(
        table,
        stats,
        chemin_html,
        nom_source=chemin,
        **imgs_synthese,
        **imgs_ssh,
    )

    # Ouverture automatique du rapport HTML dans le navigateur.
    import webbrowser
    webbrowser.open_new_tab(chemin_html)

    # Affichage du résumé dans la zone de texte + message de fin.
    afficher_resultat(texte_resultat, chemin_csv, chemin_html, stats, output_dir)
    messagebox.showinfo(
        "Terminé",
        f"Traitement terminé.\nTous les fichiers ont été générés dans :\n{output_dir}"
    )


def main():
    """
    Crée la fenêtre principale Tkinter, les widgets
    et lance la boucle principale de l'interface.
    """
    global fenetre
    fenetre = tk.Tk()
    fenetre.title("Traitement réseau - SAÉ1.5")
    fenetre.geometry("700x320")

    # Zone de texte affichant le résumé des résultats.
    texte_resultat = tk.Text(fenetre, height=10, width=80)
    texte_resultat.pack(padx=10, pady=10)
    texte_resultat.config(state="disabled")

    # Bouton pour choisir un fichier et lancer le traitement.
    btn_choisir = tk.Button(
        fenetre,
        text="Choisir un fichier texte réseau",
        command=lambda: traiter_fichier(texte_resultat)
    )
    btn_choisir.pack(pady=10)

    # Bouton pour quitter l'application.
    btn_quitter = tk.Button(fenetre, text="Quitter", command=fenetre.quit)
    btn_quitter.pack(pady=10)

    # Boucle principale Tkinter.
    fenetre.mainloop()


if __name__ == "__main__":
    # Point d'entrée du programme : lance l'interface graphique.
    main()
