# Import library
import re
from datetime import datetime
import os

# Path file log & alert
log_file_path = '/home/recoon/log-parser/logs/sample.log'
alert_file_path = '/home/recoon/log-parser/alerts/alerts.txt'

# Pola regex untuk mendeteksi serangan
patterns = {
	'SQL Injection': r"(?:')|(?:--)|(/\*)|(\*/)|(\b(SELECT|UNION|INSERT|DROP|OR|AND)\b)",
	'XSS Attack': r"<script.*?>. *?>. *?</script>",
	'Directory Traversal': r"\.\./",
	'Remote File Inclusion': r"http[s]?://.*\.(txt|php|sh)",
	'Brute Force Login': r'"POST\s+/.*login.*\s+HTTP.*"\s+401',
	'Admin Area Access': r'"GET\s+/admin/.*\s+HTTP.*"\s+403'
}

# Membaca file log
with open(log_file_path, 'r') as logfile:
	lines = logfile.readlines()

# Menghapus file alert sebelumnya
if os.path.exists(alert_file_path):
	open(alert_file_path, 'w').close()

# Menghitung brute-force
brute_force_counter = {}

# Memproses log
for line in lines:
	for attack_name, pattern in patterns.items():
		if re.search(pattern, line, re.IGNORECASE):
			# Mengambil IP dan waktu dari log
			ip_match = re.match(r"(\d+\.\d+\.\d+)", line)
			ip = ip_match.group(1) if ip_match else "Unknown IP"

			# Format waktu di alert
			timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

			# Format alert
			alert = f"[ALERT] [{timestamp}] {attack_name} detected from {ip}\n"
			with open(alert_file_path, 'a') as alertfile:
				alertfile.write(alert)

			# Catat brute-force
			if attack_name == 'Brute Force Login':
				brute_force_counter[ip] = brute_force_counter.get(ip, 0) + 1
# Threshold brute-force
for ip, count in brute_force_counter.items():
	if count >= 3:
		timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
		alert = f"[ALERT] [{timestamp}] Brute Force detected from {ip} (attempts: {count})\n"
		with open(alert_file_path, 'a') as alertfile:
			alertfile.write(alert)

print("Log analysis complete. ALerts saved to alerts.txt.")
