import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk, filedialog, Menu, font, simpledialog
from queue import Queue
import time
from datetime import datetime, time as dt_time
import webbrowser
import os
import json
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import pickle
import random
import schedule
from tkinter import Toplevel, Label, Entry, Button, StringVar, BooleanVar, IntVar
import re
import platform
import sys
import argparse

class PortScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("PortScanner")
        self.root.geometry("1000x800")
        
        # Variables de contrôle
        self.scan_queue = Queue()
        self.stop_flag = False
        self.threads = []
        self.scan_results = []
        self.start_time = None
        self.end_time = None
        self.scheduled_scans = []
        self.email_settings = {
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'email_from': '',
            'email_password': '',
            'email_to': '',
            'save_password': False
        }
        
        self.load_settings()
        
        # Polices
        self.bold_font = font.Font(family="Helvetica", size=10, weight="bold")
        self.normal_font = font.Font(family="Arial", size=9)
        
        # Thèmes améliorés
        self.themes = {
            "light": {
                "bg": "#ffffff",
                "fg": "#333333",
                "primary": "#2c3e50",
                "secondary": "#e74c3c",
                "accent": "#3498db",
                "text": "#2c3e50",
                "entry_bg": "#ecf0f1",
                "entry_fg": "black",
                "button": "#e74c3c",
                "button_text": "white",
                "gradient1": "#ff5e62",  
                "gradient2": "#ff9966"   
            },
            "dark": {
                "bg": "#1a1a1a",
                "fg": "#f1f1f1",
                "primary": "#9b59b6",
                "secondary": "#e74c3c",
                "accent": "#3498db",
                "text": "#f1f1f1",
                "entry_bg": "#2d2d2d",
                "entry_fg": "white",
                "button": "#9b59b6",
                "button_text": "white",
                "gradient1": "#4776E6",  
                "gradient2": "#8E54E9"   
            }
        }
        self.current_theme = "light"
        
        self.setup_ui()
        self.load_services()
        self.apply_theme()

    def load_settings(self):
        """Charge les paramètres depuis le fichier de configuration"""
        try:
            if os.path.exists("scanner_settings.json"):
                with open("scanner_settings.json", "r") as f:
                    settings = json.load(f)
                    self.email_settings.update(settings.get('email_settings', {}))
                    self.scheduled_scans = settings.get('scheduled_scans', [])
        except Exception as e:
            print(f"Erreur lors du chargement des paramètres: {e}")

    def save_settings(self):
        """Sauvegarde les paramètres dans le fichier de configuration"""
        try:
            settings = {
                'email_settings': self.email_settings,
                'scheduled_scans': self.scheduled_scans
            }
            with open("scanner_settings.json", "w") as f:
                json.dump(settings, f, indent=4)
        except Exception as e:
            print(f"Erreur lors de la sauvegarde des paramètres: {e}")

    def run_scheduled_scans(self):
        """Exécute les scans programmés"""
        while True:
            schedule.run_pending()
            time.sleep(1)

    def setup_ui(self):
        """Configuration de l'interface utilisateur"""
        self.style = ttk.Style()
        
        # Frame principal
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header avec logo
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.title_label = ttk.Label(
            header_frame, 
            text="PORTSCANNER", 
            font=font.Font(family="Helvetica", size=14, weight="bold"),
            anchor="center"
        )
        self.title_label.pack(fill=tk.X)
        
        # Frame de configuration
        config_frame = ttk.LabelFrame(main_frame, text=" PARAMÈTRES ", padding=15)
        config_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Grid configuration
        config_frame.columnconfigure(1, weight=1)
        
        # Adresse IP (prise en charge des plages)
        ttk.Label(config_frame, text="Adresse IP (ou plage):").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.ip_entry = tk.Entry(config_frame, width=25, font=self.normal_font)
        self.ip_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        self.ip_entry.insert(0, "192.168.1.1-192.168.1.10")
        
        # Plage de ports
        ttk.Label(config_frame, text="Ports à scanner:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.ports_entry = tk.Entry(config_frame, width=25, font=self.normal_font)
        self.ports_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=5)
        self.ports_entry.insert(0, "20-23,80,443,3389")
        
        # Boutons de contrôle
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.scan_btn = ttk.Button(
            btn_frame, 
            text="LANCER LE SCAN", 
            command=self.start_scan,
            style="Accent.TButton"
        )
        self.scan_btn.pack(side=tk.LEFT, expand=True, padx=5)
        
        self.stop_btn = ttk.Button(
            btn_frame,
            text="ARRÊTER",
            state=tk.DISABLED,
            command=self.stop_scan
        )
        self.stop_btn.pack(side=tk.LEFT, expand=True, padx=5)
        
        self.report_btn = ttk.Button(
            btn_frame,
            text="GÉNÉRER RAPPORT",
            command=self.generate_report
        )
        self.report_btn.pack(side=tk.LEFT, expand=True, padx=5)
        
        self.email_btn = ttk.Button(
            btn_frame,
            text="ENVOYER PAR EMAIL",
            command=self.send_email_dialog
        )
        self.email_btn.pack(side=tk.LEFT, expand=True, padx=5)
        
        self.schedule_btn = ttk.Button(
            btn_frame,
            text="PLANIFIER SCAN",
            command=self.schedule_scan_dialog
        )
        self.schedule_btn.pack(side=tk.LEFT, expand=True, padx=5)
        
        # Résultats
        results_frame = ttk.LabelFrame(main_frame, text=" RÉSULTATS ", padding=15)
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        self.results = scrolledtext.ScrolledText(
            results_frame,
            wrap=tk.WORD,
            font=self.normal_font,
            padx=10,
            pady=10
        )
        self.results.pack(fill=tk.BOTH, expand=True)
        
        # Barre de statut
        self.status_var = tk.StringVar(value="Prêt à scanner")
        status_bar = ttk.Frame(main_frame, height=25)
        status_bar.pack(fill=tk.X, pady=(10, 0))
        
        self.status_label = ttk.Label(
            status_bar, 
            textvariable=self.status_var, 
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        self.status_label.pack(fill=tk.X)
        
        # Barre de progression
        self.progress = ttk.Progressbar(
            main_frame, 
            orient="horizontal", 
            mode="determinate",
            style="Horizontal.TProgressbar"
        )
        self.progress.pack(fill=tk.X, pady=(10, 0))
        
        # Menu
        self.setup_menu()
        
        # Tags pour les liens
        self.results.tag_config("link", foreground="blue", underline=1)
        self.results.tag_bind("link", "<Button-1>", self.open_link)
        self.results.tag_bind("link", "<Enter>", lambda e: self.results.config(cursor="hand2"))
        self.results.tag_bind("link", "<Leave>", lambda e: self.results.config(cursor=""))

    def apply_theme(self):
        """Applique le thème sélectionné"""
        theme = self.themes[self.current_theme]
        
        # Configuration du style
        self.style.theme_use('clam')
        
        # Couleurs de base
        self.style.configure('.', 
                           background=theme["bg"],
                           foreground=theme["fg"],
                           fieldbackground=theme["entry_bg"],
                           selectbackground=theme["accent"],
                           selectforeground="white")
        
        # Frames
        self.style.configure('TFrame', background=theme["bg"])
        self.style.configure('TLabelframe', 
                           background=theme["bg"], 
                           foreground=theme["primary"],
                           bordercolor=theme["gradient1"],
                           lightcolor=theme["gradient1"],
                           darkcolor=theme["gradient2"])

        self.style.configure('TLabelframe.Label', 
                           background=theme["bg"], 
                           foreground=theme["primary"])
        
        # Labels
        self.style.configure('TLabel', 
                           background=theme["bg"], 
                           foreground=theme["text"])
        
        # Boutons avec dégradé
        self.style.configure('TButton', 
                           background=theme["gradient1"],
                           foreground=theme["button_text"],
                           font=self.normal_font,
                           padding=5,
                           borderwidth=1,
                           focusthickness=3,
                           focuscolor=theme["gradient2"])
        
        self.style.map('TButton',
                     background=[('active', theme["gradient2"]),
                                ('pressed', theme["gradient1"])])
        
        self.style.configure('Accent.TButton', 
                           background=theme["secondary"],
                           foreground="white",
                           font=self.bold_font,
                           padding=8)
        
        # Barre de progression
        self.style.configure('Horizontal.TProgressbar', 
                           background=theme["gradient1"],
                           troughcolor=theme["entry_bg"],
                           bordercolor=theme["gradient2"],
                           lightcolor=theme["gradient1"],
                           darkcolor=theme["gradient2"])
        
        # Entrées
        for entry in [self.ip_entry, self.ports_entry]:
            entry.config(
                bg=theme["entry_bg"],
                fg=theme["entry_fg"],
                insertbackground=theme["entry_fg"],
                selectbackground=theme["accent"],
                selectforeground="white",
                highlightcolor=theme["gradient1"],
                highlightbackground=theme["gradient2"]
            )
        
        # Zone de texte avec couleurs fixes pour une bonne lisibilité
        text_bg = "#FFFFFF" if self.current_theme == "light" else "#1E1E1E"
        text_fg = "#000000" if self.current_theme == "light" else "#FFFFFF"
        
        self.results.config(
            bg=text_bg,
            fg=text_fg,
            insertbackground=text_fg
        )
        
        # Barre de statut avec dégradé
        self.status_label.config(
            background=theme["primary"],
            foreground="white"
        )

    def setup_menu(self):
        """Configure le menu principal"""
        menubar = Menu(self.root)
        
        # Menu Fichier
        file_menu = Menu(menubar, tearoff=0)
        file_menu.add_command(label="Exporter les résultats", command=self.export_results)
        file_menu.add_command(label="Importer les résultats", command=self.import_results)
        file_menu.add_separator()
        file_menu.add_command(label="Paramètres Email", command=self.email_settings_dialog)
        file_menu.add_separator()
        file_menu.add_command(label="Quitter", command=self.root.quit)
        menubar.add_cascade(label="Fichier", menu=file_menu)
        
        # Menu Affichage
        view_menu = Menu(menubar, tearoff=0)
        view_menu.add_command(label="Thème Clair", command=lambda: self.set_theme("light"))
        view_menu.add_command(label="Thème Sombre", command=lambda: self.set_theme("dark"))
        menubar.add_cascade(label="Affichage", menu=view_menu)
        
        # Menu Planification
        schedule_menu = Menu(menubar, tearoff=0)
        schedule_menu.add_command(label="Gérer les scans programmés", command=self.manage_scheduled_scans)
        menubar.add_cascade(label="Planification", menu=schedule_menu)
        
        self.root.config(menu=menubar)

    def set_theme(self, theme_name):
        """Change le thème de l'application"""
        self.current_theme = theme_name
        self.apply_theme()

    def load_services(self):
        """Charge les services associés aux ports"""
        try:
            if os.path.exists("services.json"):
                with open("services.json", "r") as f:
                    self.services = json.load(f)
            else:
                # Liste de services par défaut
                self.services = {
                    "20": "FTP Data",
                    "21": "FTP Control",
                    "22": "SSH",
                    "23": "Telnet",
                    "25": "SMTP",
                    "53": "DNS",
                    "80": "HTTP",
                    "443": "HTTPS",
                    "3389": "RDP",
                }
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de charger les services:\n{e}")
            self.services = {}

    def parse_ip_range(self, ip_str):
        """Convertit une plage d'IP en liste d'adresses individuelles"""
        if '-' in ip_str:
            start_ip, end_ip = ip_str.split('-')
            start = list(map(int, start_ip.split('.')))
            end = list(map(int, end_ip.split('.')))
            
            ip_list = []
            while start <= end:
                ip_list.append('.'.join(map(str, start)))
                
                # Incrémentation de l'adresse IP
                start[3] += 1
                for i in (3, 2, 1):
                    if start[i] > 255:
                        start[i] = 0
                        start[i-1] += 1
            
            return ip_list
        elif ',' in ip_str:
            return [ip.strip() for ip in ip_str.split(',')]
        else:
            return [ip_str]

    def parse_ports(self, port_str):
        """Analyse la plage de ports"""
        ports = set()
        for part in port_str.split(','):
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.update(range(start, end + 1))
            elif part:
                ports.add(int(part))
        return sorted(ports)

    def scan_port(self, ip, port):
        """Scan un port avec différentes techniques"""
        results = {}
        
        # Technique standard avec timeout réduit pour accélérer
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                result = s.connect_ex((ip, port))
                if result == 0:
                    try:
                        s.send(b"GET / HTTP/1.0\r\n\r\n")
                        banner = s.recv(1024).decode(errors='ignore').strip()
                        results["standard"] = (True, banner)
                    except:
                        results["standard"] = (True, "")
                else:
                    results["standard"] = (False, "")
        except:
            results["standard"] = (False, "")
        
        return results

    def scan_worker(self):
        """Thread worker pour le scan"""
        while not self.stop_flag:
            try:
                ip, port = self.scan_queue.get_nowait()
                port_results = self.scan_port(ip, port)
                
                for technique, (is_open, banner) in port_results.items():
                    if is_open:
                        service = self.services.get(str(port), "Inconnu")
                        result = {
                            'ip': ip,
                            'port': port,
                            'service': service,
                            'technique': technique,
                            'banner': banner[:200] if banner else "",
                            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        }
                        
                        self.scan_results.append(result)
                        
                        display_text = f"[{result['timestamp']}] {ip}:{port} ({service}) - {technique}"
                        if banner:
                            display_text += f"\nBannière: {banner[:100]}{'...' if len(banner) > 100 else ''}"
                        
                        self.results.insert(tk.END, display_text + "\n\n")
                        
                        # Ajout de lien pour les ports web
                        if port in [80, 443, 8080, 8443]:
                            protocol = "https" if port in [443, 8443] else "http"
                            url = f"{protocol}://{ip}" + ("" if port in [80, 443] else f":{port}")
                            self.results.insert(tk.END, f"Lien: {url}\n\n", ("link", url))
                        
                        self.results.see(tk.END)
                
                self.progress.step(1)
                self.scan_queue.task_done()
            except:
                time.sleep(0.1)
                if self.scan_queue.empty():
                    break

    def start_scan(self):
        """Démarre le scan avec gestion des plages d'IP"""
        try:
            ip_str = self.ip_entry.get()
            ports = self.parse_ports(self.ports_entry.get())
            ip_list = self.parse_ip_range(ip_str)
            
            if not ports or not ip_list:
                messagebox.showwarning("Attention", "Veuillez spécifier une plage d'IP et des ports valides")
                return
            
            self.stop_flag = False
            self.scan_results = []
            self.results.delete(1.0, tk.END)
            
            total = len(ports) * len(ip_list)
            self.progress.config(maximum=total)
            self.progress['value'] = 0
            
            for ip in ip_list:
                for port in ports:
                    self.scan_queue.put((ip, port))
            
            self.scan_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.start_time = datetime.now()
            self.status_var.set(f"Scan en cours - 0/{total} combinaisons IP:Port analysées")
            
            # Démarrer les threads (limité à 100 threads max)
            self.threads = []
            for _ in range(min(100, total)):
                t = threading.Thread(target=self.scan_worker, daemon=True)
                t.start()
                self.threads.append(t)
            
            # Vérifier la fin du scan
            threading.Thread(target=self.check_scan_completion, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de démarrer le scan:\n{e}")

    def check_scan_completion(self):
        """Vérifie si le scan est terminé"""
        while not self.scan_queue.empty() and not self.stop_flag:
            completed = self.progress['value']
            total = self.progress['maximum']
            self.status_var.set(f"Scan en cours - {completed}/{total} combinaisons IP:Port analysées")
            time.sleep(0.5)
        
        self.end_time = datetime.now()
        self.scan_complete()

    def scan_complete(self):
        """Actions à effectuer lorsque le scan est terminé"""
        self.stop_flag = True
        for t in self.threads:
            t.join(timeout=1)
        
        duration = self.end_time - self.start_time if self.start_time and self.end_time else None
        
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        
        if duration:
            self.status_var.set(f"Scan terminé en {duration.total_seconds():.2f} secondes")
            self.results.insert(tk.END, f"\n\nScan terminé à {self.end_time}\n")
            self.results.insert(tk.END, f"Durée totale: {duration.total_seconds():.2f} secondes\n")
            self.results.insert(tk.END, f"Ports ouverts trouvés: {len(self.scan_results)}\n")
        else:
            self.status_var.set("Scan terminé")
            self.results.insert(tk.END, "\n\nScan terminé\n")

    def stop_scan(self):
        """Arrête le scan en cours"""
        if messagebox.askyesno("Confirmation", "Voulez-vous vraiment arrêter le scan ?"):
            self.stop_flag = True
            self.status_var.set("Scan arrêté par l'utilisateur")
            self.results.insert(tk.END, "\n\nScan arrêté manuellement\n")

    def generate_report(self, open_in_browser=True, email_report=False):
        """Génère un rapport avec des couleurs fixes pour une bonne lisibilité"""
        if not self.scan_results:
            messagebox.showwarning("Attention", "Aucun résultat à exporter")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("Fichier HTML", "*.html"), ("Fichier TXT", "*.txt")],
            title="Enregistrer le rapport"
        )
        
        if not file_path:
            return
            
        try:
            duration = self.end_time - self.start_time if self.start_time and self.end_time else None
            
            if file_path.endswith('.html'):
                html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Rapport de Scan Port</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: white;
            color: black;
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }}
        .info {{
            background-color: #f5f5f5;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
            margin-top: 20px;
            background-color: white;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #3498db;
            color: white;
        }}
        tr:nth-child(even) {{
            background-color: #f2f2f2;
        }}
        .open {{
            color: green;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <h1>Rapport de Scan Port</h1>
    <div class="info">
        <p><strong>Cible:</strong> {self.ip_entry.get()}</p>
        <p><strong>Ports scannés:</strong> {self.ports_entry.get()}</p>
        <p><strong>Début du scan:</strong> {self.start_time}</p>
        <p><strong>Fin du scan:</strong> {self.end_time}</p>
        <p><strong>Durée:</strong> {duration.total_seconds():.2f} secondes</p>
        <p><strong>Ports ouverts:</strong> {len(self.scan_results)}</p>
    </div>
    <table>
        <tr>
            <th>IP</th>
            <th>Port</th>
            <th>Service</th>
            <th>Technique</th>
            <th>Bannière</th>
        </tr>"""
                
                for result in sorted(self.scan_results, key=lambda x: (x['ip'], x['port'])):
                    html_content += f"""
        <tr>
            <td>{result['ip']}</td>
            <td>{result['port']}</td>
            <td>{result['service']}</td>
            <td>{result['technique']}</td>
            <td>{result['banner'] or 'Aucune'}</td>
        </tr>"""
                
                html_content += """
    </table>
</body>
</html>"""
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                
                if open_in_browser:
                    webbrowser.open_new_tab(f"file://{os.path.abspath(file_path)}")
            
            else:  # Format TXT
                txt_content = f"""Rapport de Scan Port
================================
Cible: {self.ip_entry.get()}
Ports scannés: {self.ports_entry.get()}
Début: {self.start_time}
Fin: {self.end_time}
Durée: {duration.total_seconds():.2f} secondes
Ports ouverts: {len(self.scan_results)}

Détails des ports ouverts:
-------------------------\n"""
                
                for result in sorted(self.scan_results, key=lambda x: (x['ip'], x['port'])):
                    txt_content += f"""
IP: {result['ip']}
Port: {result['port']} ({result['service']})
Technique: {result['technique']}
Bannière: {result['banner'] or 'Aucune'}
----------------------------------------\n"""
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(txt_content)
            
            messagebox.showinfo("Succès", f"Rapport généré: {file_path}")
            
            if email_report:
                self.send_email(file_path)
            
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur génération rapport:\n{e}")

    def create_system_task(self, scan_info):
        """Crée une tâche système autonome"""
        try:
            script_content = f"""import os
import sys
from datetime import datetime

# Configuration du scan
target_ip = "{scan_info['ip']}"
target_ports = "{scan_info['ports']}"
report_file = "scan_report_{scan_info['name']}_" + datetime.now().strftime('%Y%m%d_%H%M%S') + ".html"

print(f"Exécution du scan programmé: {scan_info['name']}")
print(f"IP: {target_ip}")
print(f"Ports: {target_ports}")

# Exécuter le scan (remplacer par votre code de scan)
os.system(f'python "{os.path.abspath(__file__)}" --scheduled "{scan_info["name"]}"')
"""
            
            script_path = f"scan_{scan_info['name'].replace(' ', '_')}.py"
            with open(script_path, 'w') as f:
                f.write(script_content)
            
            if platform.system() == "Windows":
                cmd = f'schtasks /create /tn "PortScan_{scan_info["name"]}" /tr "{sys.executable} {os.path.abspath(script_path)}" /sc daily /st {scan_info["time"]}'
                os.system(cmd)
            elif platform.system() == "Linux":
                hour, minute = scan_info['time'].split(':')
                cron_line = f"{minute} {hour} * * * {sys.executable} {os.path.abspath(script_path)}\n"
                with open("/tmp/cron_job", "w") as f:
                    f.write(cron_line)
                os.system("crontab /tmp/cron_job")
            
            messagebox.showinfo("Succès", f"Tâche programmée: {scan_info['name']}")
            
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur création tâche:\n{e}")

    def save_scheduled_scan(self, scan_info, dialog=None):
        """Enregistre et programme le scan"""
        try:
            # Validation des données
            if not scan_info['name']:
                messagebox.showerror("Erreur", "Veuillez donner un nom au scan")
                return
                
            if not scan_info['ip']:
                messagebox.showerror("Erreur", "Veuillez spécifier une plage d'IP")
                return
                
            if not scan_info['ports']:
                messagebox.showerror("Erreur", "Veuillez spécifier des ports à scanner")
                return
                
            # Validation de l'heure
            try:
                h, m = map(int, scan_info['time'].split(':'))
                if not (0 <= h < 24 and 0 <= m < 60):
                    raise ValueError
            except:
                messagebox.showerror("Erreur", "Heure invalide. Format attendu: HH:MM")
                return
            
            # Ajouter la date de création
            scan_info['created_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            self.scheduled_scans.append(scan_info)
            self.save_settings()
            
            # Planification interne (pour les tests)
            def run_scheduled_scan():
                self.ip_entry.delete(0, tk.END)
                self.ip_entry.insert(0, scan_info['ip'])
                self.ports_entry.delete(0, tk.END)
                self.ports_entry.insert(0, scan_info['ports'])
                self.start_scan()
                
                if scan_info.get('send_email', False):
                    self.root.after(10000, lambda: self.send_email_dialog())
            
            # Correspondance entre les noms français et anglais des jours
            day_mapping = {
                "Lundi": "monday",
                "Mardi": "tuesday",
                "Mercredi": "wednesday",
                "Jeudi": "thursday",
                "Vendredi": "friday",
                "Samedi": "saturday",
                "Dimanche": "sunday"
            }
            
            # Planification réelle avec schedule
            if 'days' in scan_info:
                selected_days = [day for day, selected in scan_info['days'].items() if selected]
                
                if selected_days:  # Si des jours spécifiques sont sélectionnés
                    for day in selected_days:
                        if day in day_mapping:
                            getattr(schedule.every(), day_mapping[day]).at(scan_info['time']).do(run_scheduled_scan)
                else:  # Tous les jours si aucun jour spécifique n'est sélectionné
                    schedule.every().day.at(scan_info['time']).do(run_scheduled_scan)
            else:  # Par défaut, tous les jours
                schedule.every().day.at(scan_info['time']).do(run_scheduled_scan)
            
            # Démarrer le thread de gestion des tâches planifiées
            threading.Thread(target=self.run_scheduled_scans, daemon=True).start()
            
            messagebox.showinfo("Succès", f"Scan '{scan_info['name']}' programmé!")
            
            if dialog:
                dialog.destroy()
            
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur programmation:\n{e}")

    def email_settings_dialog(self):
        """Affiche la boîte de dialogue des paramètres email"""
        dialog = Toplevel(self.root)
        dialog.title("Paramètres Email")
        dialog.geometry("500x350")
        dialog.resizable(False, False)
        
        # Variables
        smtp_server = StringVar(value=self.email_settings['smtp_server'])
        smtp_port = StringVar(value=str(self.email_settings['smtp_port']))
        email_from = StringVar(value=self.email_settings['email_from'])
        email_password = StringVar(value=self.email_settings['email_password'])
        email_to = StringVar(value=self.email_settings['email_to'])
        save_password = BooleanVar(value=self.email_settings['save_password'])
        
        # Frame principal
        main_frame = ttk.Frame(dialog, padding=15)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Configuration du serveur SMTP
        ttk.Label(main_frame, text="Serveur SMTP:").grid(row=0, column=0, sticky="w", pady=5)
        ttk.Entry(main_frame, textvariable=smtp_server, width=30).grid(row=0, column=1, sticky="ew", pady=5)
        
        ttk.Label(main_frame, text="Port SMTP:").grid(row=1, column=0, sticky="w", pady=5)
        ttk.Entry(main_frame, textvariable=smtp_port, width=30).grid(row=1, column=1, sticky="ew", pady=5)
        
        # Email from
        ttk.Label(main_frame, text="Email (expéditeur):").grid(row=2, column=0, sticky="w", pady=5)
        ttk.Entry(main_frame, textvariable=email_from, width=30).grid(row=2, column=1, sticky="ew", pady=5)
        
        # Mot de passe
        ttk.Label(main_frame, text="Mot de passe:").grid(row=3, column=0, sticky="w", pady=5)
        ttk.Entry(main_frame, textvariable=email_password, show="*", width=30).grid(row=3, column=1, sticky="ew", pady=5)
        
        # Email to
        ttk.Label(main_frame, text="Email (destinataire):").grid(row=4, column=0, sticky="w", pady=5)
        ttk.Entry(main_frame, textvariable=email_to, width=30).grid(row=4, column=1, sticky="ew", pady=5)
        
        # Sauvegarder le mot de passe
        ttk.Checkbutton(main_frame, text="Sauvegarder le mot de passe", variable=save_password).grid(row=5, column=0, columnspan=2, sticky="w", pady=5)
        
        # Boutons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=6, column=0, columnspan=2, pady=15)
        
        ttk.Button(btn_frame, text="Enregistrer", command=lambda: self.save_email_settings(
            smtp_server.get(),
            smtp_port.get(),
            email_from.get(),
            email_password.get(),
            email_to.get(),
            save_password.get(),
            dialog
        )).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="Annuler", command=dialog.destroy).pack(side=tk.LEFT, padx=5)

    def save_email_settings(self, smtp_server, smtp_port, email_from, email_password, email_to, save_password, dialog):
        """Sauvegarde les paramètres email"""
        try:
            self.email_settings = {
                'smtp_server': smtp_server,
                'smtp_port': int(smtp_port),
                'email_from': email_from,
                'email_password': email_password if save_password else '',
                'email_to': email_to,
                'save_password': save_password
            }
            
            self.save_settings()
            dialog.destroy()
            messagebox.showinfo("Succès", "Paramètres email enregistrés")
        except ValueError:
            messagebox.showerror("Erreur", "Le port SMTP doit être un nombre")
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible d'enregistrer les paramètres:\n{e}")

    def send_email_dialog(self):
        """Affiche la boîte de dialogue pour envoyer un email"""
        if not self.scan_results:
            messagebox.showwarning("Attention", "Aucun résultat à envoyer")
            return
            
        if not self.email_settings['email_from'] or not self.email_settings['email_to']:
            messagebox.showwarning("Attention", "Veuillez configurer les paramètres email d'abord")
            self.email_settings_dialog()
            return
            
        # Demander confirmation
        if messagebox.askyesno("Confirmation", f"Envoyer le rapport à {self.email_settings['email_to']} ?"):
            # Générer un rapport temporaire
            temp_file = "temp_report.html"
            try:
                self.generate_report(open_in_browser=False, email_report=True)
            except Exception as e:
                messagebox.showerror("Erreur", f"Impossible d'envoyer l'email:\n{e}")

    def send_email(self, attachment_path=None):
        """Envoie un email avec les résultats du scan"""
        try:
            if not self.email_settings['email_from'] or not self.email_settings['email_to']:
                messagebox.showwarning("Attention", "Veuillez configurer les paramètres email d'abord")
                self.email_settings_dialog()
                return
            
            # Création du message
            msg = MIMEMultipart()
            msg['From'] = self.email_settings['email_from']
            msg['To'] = self.email_settings['email_to']
            msg['Subject'] = f"Rapport de scan - {self.ip_entry.get()} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            
            # Corps du message
            body = f"""
Rapport de scan de ports
Cible: {self.ip_entry.get()}
Ports scannés: {self.ports_entry.get()}
Début: {self.start_time}
Fin: {self.end_time}
Durée: {(self.end_time - self.start_time).total_seconds():.2f} secondes
Ports ouverts: {len(self.scan_results)}
"""
            msg.attach(MIMEText(body, 'plain'))
            
            # Pièce jointe
            if attachment_path:
                with open(attachment_path, "rb") as f:
                    part = MIMEApplication(f.read(), Name=os.path.basename(attachment_path))
                part['Content-Disposition'] = f'attachment; filename="{os.path.basename(attachment_path)}"'
                msg.attach(part)
            
            # Configuration SMTP (avec gestion des différents fournisseurs)
            smtp_config = {
                'gmail.com': ('smtp.gmail.com', 587),
                'outlook.com': ('smtp.office365.com', 587),
                'yahoo.com': ('smtp.mail.yahoo.com', 465),
                'free.fr': ('smtp.free.fr', 465)
            }

            domain = self.email_settings['email_from'].split('@')[-1]
            smtp_server, smtp_port = smtp_config.get(domain, ('smtp.gmail.com', 587))

            # Connexion et envoi
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.ehlo()
                if smtp_port == 587:  # STARTTLS
                    server.starttls()
                server.login(self.email_settings['email_from'],
                            self.email_settings['email_password'])
                server.send_message(msg)
            
            messagebox.showinfo("Succès", f"Email envoyé à {self.email_settings['email_to']}")
        except Exception as e:
            error_msg = f"""
Erreur d'envoi email:
{str(e)}

Vérifiez:
1. Vos identifiants SMTP
2. L'activation des accès moins sécurisés
3. Le mot de passe d'application (si 2FA activé)
4. Les paramètres de votre fournisseur email
"""
            messagebox.showerror("Erreur", error_msg)

    def schedule_scan_dialog(self):
        """Affiche la boîte de dialogue pour programmer un scan"""
        dialog = Toplevel(self.root)
        dialog.title("Planifier un scan complet")
        dialog.geometry("500x400")
        
        # Variables
        scan_name = StringVar()
        ip_range = StringVar(value=self.ip_entry.get())
        ports = StringVar(value=self.ports_entry.get())
        hour = StringVar(value="12")
        minute = StringVar(value="00")
        days = {
            "Lundi": BooleanVar(value=True),
            "Mardi": BooleanVar(value=True),
            "Mercredi": BooleanVar(value=True),
            "Jeudi": BooleanVar(value=True),
            "Vendredi": BooleanVar(value=True),
            "Samedi": BooleanVar(value=False),
            "Dimanche": BooleanVar(value=False)
        }
        send_email = BooleanVar(value=True)
        
        # Frame principal
        main_frame = ttk.Frame(dialog, padding=15)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Configuration du scan
        ttk.Label(main_frame, text="Nom du scan:").grid(row=0, column=0, sticky="w", pady=5)
        ttk.Entry(main_frame, textvariable=scan_name, width=25).grid(row=0, column=1, sticky="ew", pady=5)
        
        ttk.Label(main_frame, text="Plage d'IP:").grid(row=1, column=0, sticky="w", pady=5)
        ttk.Entry(main_frame, textvariable=ip_range, width=25).grid(row=1, column=1, sticky="ew", pady=5)
        
        ttk.Label(main_frame, text="Ports à scanner:").grid(row=2, column=0, sticky="w", pady=5)
        ttk.Entry(main_frame, textvariable=ports, width=25).grid(row=2, column=1, sticky="ew", pady=5)
        
        # Heure
        ttk.Label(main_frame, text="Heure:").grid(row=3, column=0, sticky="w", pady=5)
        time_frame = ttk.Frame(main_frame)
        time_frame.grid(row=3, column=1, sticky="ew")
        
        ttk.Entry(time_frame, textvariable=hour, width=2).pack(side=tk.LEFT)
        ttk.Label(time_frame, text=":").pack(side=tk.LEFT)
        ttk.Entry(time_frame, textvariable=minute, width=2).pack(side=tk.LEFT)
        
        # Jours
        ttk.Label(main_frame, text="Jours:").grid(row=4, column=0, sticky="nw", pady=5)
        days_frame = ttk.Frame(main_frame)
        days_frame.grid(row=4, column=1, sticky="w")
        
        for i, (day, var) in enumerate(days.items()):
            ttk.Checkbutton(days_frame, text=day, variable=var).grid(row=i//2, column=i%2, sticky="w")
        
        # Options
        ttk.Checkbutton(main_frame, text="Envoyer par email après scan", variable=send_email).grid(row=5, column=0, columnspan=2, sticky="w", pady=5)
        
        # Boutons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=6, column=0, columnspan=2, pady=15)
        
        ttk.Button(btn_frame, text="Planifier", command=lambda: self.save_scheduled_scan({
            'name': scan_name.get(),
            'ip': ip_range.get(),
            'ports': ports.get(),
            'time': f"{hour.get()}:{minute.get()}",
            'days': {day: var.get() for day, var in days.items()},
            'send_email': send_email.get()
        }, dialog)).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="Annuler", command=dialog.destroy).pack(side=tk.LEFT, padx=5)

    def manage_scheduled_scans(self):
        """Affiche la fenêtre de gestion des scans programmés"""
        dialog = Toplevel(self.root)
        dialog.title("Gérer les scans programmés")
        dialog.geometry("700x400")
        
        # Frame principal
        main_frame = ttk.Frame(dialog, padding=15)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Liste des scans programmés
        ttk.Label(main_frame, text="Scans programmés:", font=self.bold_font).pack(anchor="w")
        
        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Treeview pour afficher les scans
        columns = ("name", "time", "days", "ip", "ports", "email", "created")
        tree = ttk.Treeview(tree_frame, columns=columns, show="headings")

        # Définition des colonnes
        tree.heading("name", text="Nom")
        tree.heading("time", text="Heure")
        tree.heading("days", text="Jours")
        tree.heading("ip", text="IP")
        tree.heading("ports", text="Ports")
        tree.heading("email", text="Email")
        tree.heading("created", text="Créé le")
        
        tree.column("name", width=120)
        tree.column("time", width=60)
        tree.column("days", width=120)
        tree.column("ip", width=100)
        tree.column("ports", width=100)
        tree.column("email", width=60)
        tree.column("created", width=120)
        
        # Ajout des données
        for scan in self.scheduled_scans:
            days = ", ".join([day for day, selected in scan['days'].items() if selected]) if 'days' in scan else "Tous les jours"
            email = "Oui" if scan.get('send_email', False) else "Non"
            tree.insert("", tk.END, values=(
                scan['name'],
                scan['time'],
                days,
                scan['ip'],
                scan['ports'],
                email,
                scan.get('created_at', 'N/A')
            ))
        
        # Barre de défilement
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        tree.pack(side="left", fill=tk.BOTH, expand=True)
        
        # Boutons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(btn_frame, text="Supprimer", command=lambda: self.delete_scheduled_scan(tree, dialog)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Fermer", command=dialog.destroy).pack(side=tk.RIGHT, padx=5)

    def delete_scheduled_scan(self, tree, dialog):
        """Supprime un scan programmé"""
        selected = tree.selection()
        if not selected:
            messagebox.showwarning("Attention", "Veuillez sélectionner un scan à supprimer")
            return
            
        if messagebox.askyesno("Confirmation", "Voulez-vous vraiment supprimer ce scan programmé ?"):
            # Supprimer de la liste
            item = tree.item(selected[0])
            scan_name = item['values'][0]
            
            self.scheduled_scans = [scan for scan in self.scheduled_scans if scan['name'] != scan_name]
            self.save_settings()
            
            # Supprimer de l'affichage
            tree.delete(selected[0])
            
            messagebox.showinfo("Succès", f"Scan '{scan_name}' supprimé")

    def open_link(self, event):
        """Ouvre un lien dans le navigateur"""
        index = self.results.index(f"@{event.x},{event.y}")
        for tag in self.results.tag_names(index):
            if tag.startswith("link"):
                url = self.results.tag_cget(tag, "text")
                webbrowser.open_new(url)
                break

    def export_results(self):
        """Exporte les résultats au format binaire"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".psr",
            filetypes=[("Fichier PortScanner", "*.psr")]
        )
        if file_path:
            try:
                data = {
                    'results': self.scan_results,
                    'config': {
                        'ip': self.ip_entry.get(),
                        'ports': self.ports_entry.get(),
                        'start_time': str(self.start_time),
                        'end_time': str(self.end_time)
                    }
                }
                with open(file_path, 'wb') as f:
                    pickle.dump(data, f)
                messagebox.showinfo("Succès", "Résultats exportés")
            except Exception as e:
                messagebox.showerror("Erreur", str(e))

    def import_results(self):
        """Importe des résultats précédemment exportés"""
        file_path = filedialog.askopenfilename(
            filetypes=[("Fichier PortScanner", "*.psr")]
        )
        if file_path:
            try:
                with open(file_path, 'rb') as f:
                    data = pickle.load(f)
                
                self.scan_results = data.get('results', [])
                if 'config' in data:
                    self.ip_entry.delete(0, tk.END)
                    self.ip_entry.insert(0, data['config'].get('ip', ''))
                    self.ports_entry.delete(0, tk.END)
                    self.ports_entry.insert(0, data['config'].get('ports', ''))
                    self.start_time = datetime.strptime(data['config'].get('start_time'), '%Y-%m-%d %H:%M:%S.%f') if data['config'].get('start_time') else None
                    self.end_time = datetime.strptime(data['config'].get('end_time'), '%Y-%m-%d %H:%M:%S.%f') if data['config'].get('end_time') else None
                
                self.results.delete(1.0, tk.END)
                for result in self.scan_results:
                    self.results.insert(tk.END, f"{result['ip']}:{result['port']} ({result['service']})\n")
                
                messagebox.showinfo("Succès", "Résultats importés")
                self.report_btn.config(state=tk.NORMAL)
            except Exception as e:
                messagebox.showerror("Erreur", str(e))

if __name__ == "__main__":
    # Gestion des arguments en ligne de commande
    parser = argparse.ArgumentParser()
    parser.add_argument("--scheduled", help="Exécute un scan programmé")
    args = parser.parse_args()
    
    root = tk.Tk()
    app = PortScanner(root)
    
    if args.scheduled:
        for scan in app.scheduled_scans:
            if scan['name'] == args.scheduled:
                app.ip_entry.delete(0, tk.END)
                app.ip_entry.insert(0, scan['ip'])
                app.ports_entry.delete(0, tk.END)
                app.ports_entry.insert(0, scan['ports'])
                app.start_scan()
                break
    
    root.mainloop()