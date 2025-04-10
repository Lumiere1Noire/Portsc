import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk, filedialog
from queue import Queue
import time
from datetime import datetime
import webbrowser
import os

class PortScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("PortScanner")
        self.setup_ui()
        self.scan_queue = Queue()
        self.stop_flag = False
        self.threads = []
        self.scan_results = []
        
        # Configuration des services connus
        self.services = {
            20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 80: "HTTP", 443: "HTTPS",
            3389: "RDP", 8080: "HTTP", 8443: "HTTPS"
        }
        
    def setup_ui(self):
        # Interface utilisateur
        tk.Label(self.root, text="Plage IP (ex: 192.168.1.1-254):").grid(row=0, column=0, sticky="w")
        self.ip_range = tk.Entry(self.root, width=30)
        self.ip_range.grid(row=0, column=1, columnspan=2, sticky="ew")
        self.ip_range.insert(0, "192.168.1.1-254")
        
        tk.Label(self.root, text="Ports (ex: 80,443 ou 20-25):").grid(row=1, column=0, sticky="w")
        self.ports_input = tk.Entry(self.root, width=30)
        self.ports_input.grid(row=1, column=1, columnspan=2, sticky="ew")
        self.ports_input.insert(0, "20-25,80,443,3389,8080,8443")
        
        # Boutons
        self.scan_btn = tk.Button(self.root, text="Démarrer Scan", command=self.start_scan)
        self.scan_btn.grid(row=2, column=0, pady=5, sticky="ew")
        
        self.stop_btn = tk.Button(self.root, text="Arrêter", state=tk.DISABLED, command=self.stop_scan)
        self.stop_btn.grid(row=2, column=1, pady=5, sticky="ew")
        
        self.report_btn = tk.Button(self.root, text="Générer Rapport", state=tk.DISABLED, command=self.generate_report)
        self.report_btn.grid(row=2, column=2, pady=5, sticky="ew")
        
        # Affichage des résultats
        self.results = scrolledtext.ScrolledText(self.root, width=85, height=20, wrap=tk.WORD)
        self.results.grid(row=3, columnspan=3, sticky="nsew")
        
        # Barre de progression
        self.progress = ttk.Progressbar(self.root, orient="horizontal", mode="determinate")
        self.progress.grid(row=4, columnspan=3, sticky="ew")
        
        # Configuration du redimensionnement
        self.root.grid_rowconfigure(3, weight=1)
        self.root.grid_columnconfigure(1, weight=1)

    def parse_ports(self, port_str):
        ports = set()
        for part in port_str.split(','):
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.update(range(start, end+1))
            elif part:
                ports.add(int(part))
        return sorted(ports)

    def parse_ips(self, ip_range):
        if '-' not in ip_range:
            return [ip_range]
            
        base, end_part = ip_range.split('-', 1)
        base_parts = list(map(int, base.split('.')))
        
        # Gestion des formats comme 192.168.1.1-254
        if '.' in end_part:
            end_parts = list(map(int, end_part.split('.')))
        else:
            end_parts = base_parts.copy()
            end_parts[3] = int(end_part)
        
        ips = []
        current = base_parts.copy()
        
        while current <= end_parts:
            ips.append(".".join(map(str, current)))
            current[3] += 1
            for i in (3, 2, 1):
                if current[i] > 255:
                    current[i] = 0
                    current[i-1] += 1
                    if current[i-1] > 255:
                        break
        
        return ips

    def scan_port(self, ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((ip, port))
                if result == 0:
                    banner = ""
                    try:
                        s.settimeout(1.0)
                        if port in [80, 8080, 443, 8443]:
                            s.send(b"GET / HTTP/1.0\r\n\r\n")
                        else:
                            s.send(b"\r\n")
                        banner = s.recv(256).decode(errors='ignore').strip()
                    except:
                        pass
                    return True, banner
        except:
            pass
        return False, ""

    def worker(self):
        while not self.stop_flag:
            try:
                ip, port = self.scan_queue.get_nowait()
                is_open, banner = self.scan_port(ip, port)
                
                if is_open:
                    service = self.services.get(port, "Inconnu")
                    result = {
                        'ip': ip,
                        'port': port,
                        'service': service,
                        'banner': banner[:200] if banner else "Aucune bannière"
                    }
                    
                    self.scan_results.append(result)
                    
                    display_text = f"{ip}:{port} ({service})"
                    if banner:
                        display_text += f" - {banner[:50]}{'...' if len(banner) > 50 else ''}"
                    
                    self.results.insert(tk.END, display_text + "\n")
                    self.results.see(tk.END)
                
                self.progress.step(1)
                self.scan_queue.task_done()
            except:
                time.sleep(0.1)

    def start_scan(self):
        try:
            ips = self.parse_ips(self.ip_range.get())
            ports = self.parse_ports(self.ports_input.get())
        except Exception as e:
            messagebox.showerror("Erreur", f"Saisie invalide:\n{e}")
            return

        self.stop_flag = False
        self.scan_results = []
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.report_btn.config(state=tk.DISABLED)
        self.results.delete(1.0, tk.END)
        
        total_tasks = len(ips) * len(ports)
        if total_tasks == 0:
            messagebox.showwarning("Avertissement", "Aucune IP ou port à scanner")
            return
            
        self.progress.config(maximum=total_tasks)
        self.progress['value'] = 0
        
        for ip in ips:
            for port in ports:
                self.scan_queue.put((ip, port))
        
        self.threads = []
        for _ in range(min(100, total_tasks)):  # Limité à 100 threads max
            t = threading.Thread(target=self.worker, daemon=True)
            t.start()
            self.threads.append(t)
        
        threading.Thread(target=self.check_completion, daemon=True).start()

    def check_completion(self):
        while not self.scan_queue.empty() and not self.stop_flag:
            time.sleep(0.5)
        
        self.scan_complete()

    def scan_complete(self):
        self.stop_flag = True
        for t in self.threads:
            t.join(timeout=1)
        
        self.threads = []
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.report_btn.config(state=tk.NORMAL if self.scan_results else tk.DISABLED)
        self.results.insert(tk.END, f"\nScan terminé - {len(self.scan_results)} ports ouverts trouvés\n")

    def stop_scan(self):
        if messagebox.askyesno("Confirmation", "Voulez-vous vraiment arrêter le scan ?"):
            self.stop_flag = True
            self.results.insert(tk.END, "\nScan arrêté par l'utilisateur\n")

    def generate_report(self):
        if not self.scan_results:
            messagebox.showwarning("Avertissement", "Aucun résultat à exporter")
            return
            
        default_filename = f"scan_ports_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        file_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("Fichier HTML", "*.html"), ("Tous fichiers", "*.*")],
            title="Enregistrer le rapport",
            initialfile=default_filename
        )
        
        if not file_path:
            return
            
        try:
            html_content = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Rapport de Scan de Ports</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; }}
        .info {{ color: #7f8c8d; margin-bottom: 20px; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; }}
        th {{ background-color: #3498db; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        tr:hover {{ background-color: #e3f2fd; }}
        .banner {{ max-width: 400px; overflow-wrap: break-word; }}
    </style>
</head>
<body>
    <h1>Rapport de Scan de Ports</h1>
    <div class="info">
        <p>Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}</p>
        <p>Nombre de ports ouverts trouvés : {len(self.scan_results)}</p>
    </div>
    
    <table>
        <thead>
            <tr>
                <th>Adresse IP</th>
                <th>Port</th>
                <th>Service</th>
                <th>Bannière</th>
            </tr>
        </thead>
        <tbody>
"""
            
            for result in sorted(self.scan_results, key=lambda x: (x['ip'], x['port'])):
                html_content += f"""
            <tr>
                <td>{result['ip']}</td>
                <td>{result['port']}</td>
                <td>{result['service']}</td>
                <td class="banner">{result['banner'] or 'Aucune'}</td>
            </tr>
"""
            
            html_content += """
        </tbody>
    </table>
</body>
</html>"""
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            # Ouvrir le rapport dans le navigateur
            try:
                webbrowser.open(f"file://{os.path.abspath(file_path)}")
            except:
                pass
                
            messagebox.showinfo("Succès", f"Rapport généré avec succès:\n{file_path}")
            
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de la génération du rapport:\n{str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PortScanner(root)
    root.mainloop()