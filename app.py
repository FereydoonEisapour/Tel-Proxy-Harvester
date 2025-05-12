# Standard library imports
import requests
from bs4 import BeautifulSoup
import os
import sys
import time
import geoip2.database
from pathlib import Path
import re
import json
import base64

# System configuration to enforce UTF-8 encoding for standard output
sys.stdout.reconfigure(encoding='utf-8')

# ========================
# Directory Configuration
# ========================
# Organized directory structure for data storage
PROTOCOLS_DIR = os.path.join("Servers", "Protocols")      # Protocol-specific server configurations
REGIONS_DIR = os.path.join("Servers", "Regions")          # Country-based server groupings
REPORTS_DIR = os.path.join("Servers", "Reports")          # Logs and extraction analytics
MERGED_DIR = os.path.join("Servers", "Merged")            # Consolidated server list
CHANNELS_DIR = os.path.join("Servers", "Channels")        # Per-channel configuration storage

CHANNELS_FILE = "files/telegram_sources.txt" # Input file

# Create directories if they don't exist
for directory in [PROTOCOLS_DIR, REGIONS_DIR, REPORTS_DIR, MERGED_DIR, CHANNELS_DIR]:
    os.makedirs(directory, exist_ok=True)

# ========================
# Operational Parameters
# ========================
SLEEP_TIME = 10                   # Anti-rate-limiting delay between batches (seconds)
BATCH_SIZE = 10                  # Channels processed before sleep interval
FETCH_CONFIG_LINKS_TIMEOUT = 15  # HTTP request timeout for Telegram scraping (seconds)

# Maximum entries per file
MAX_CHANNEL_SERVERS = 200         # Max entries per channel file
MAX_PROTOCOL_SERVERS = 10000        # Max entries per protocol file
MAX_REGION_SERVERS = 10000          # Max entries per region file
MAX_MERGED_SERVERS = 10000        # Max entries in merged file

# ========================
# Critical File Paths
# ========================
LOG_FILE = os.path.join(REPORTS_DIR, "extraction_report.log")  # Master log file
GEOIP_DATABASE_PATH = Path("files/db/GeoLite2-Country.mmdb")   # MaxMind GeoLite2 database
MERGED_SERVERS_FILE = os.path.join(MERGED_DIR, "merged_servers.txt")  # Unified server list

# ========================
# Protocol Detection Patterns
# ========================
# Regex patterns for exact protocol matching (negative lookbehind prevents partial matches)
PATTERNS = {
    'vmess': r'(?<![a-zA-Z0-9_])vmess://[^\s<>]+',           # VMess  
    'vless': r'(?<![a-zA-Z0-9_])vless://[^\s<>]+',           # VLESS 
    'trojan': r'(?<![a-zA-Z0-9_])trojan://[^\s<>]+',         # Trojan 
    'hysteria': r'(?<![a-zA-Z0-9_])hysteria://[^\s<>]+',     # Hysteria v1  
    'hysteria2': r'(?<![a-zA-Z0-9_])hysteria2://[^\s<>]+',   # Hysteria v2 
    'tuic': r'(?<![a-zA-Z0-9_])tuic://[^\s<>]+',             # TUIC  
    'ss': r'(?<![a-zA-Z0-9_])ss://[^\s<>]+',                 # Shadowsocks  
    'wireguard': r'(?<![a-zA-Z0-9_])wireguard://[^\s<>]+',   # Wireguard  
    'warp': r'(?<![a-zA-Z0-9_])warp://[^\s<>]+'              # Warp  
}

def parse_server_link(link):
    """Parses a server link to extract protocol, IP, port, and UUID for deduplication."""
    try:
        link = link.strip()
        
        protocol = link.split('://')[0].lower()
        if protocol not in ['vless', 'vmess', 'trojan', 'ss']:
            return None, None, None, None

        if protocol == 'vmess':
            vmess_data = json.loads(base64.b64decode(link.split('://')[1]).decode('utf-8'))
            ip = vmess_data.get('add', '')
            port = str(vmess_data.get('port', ''))
            uuid = vmess_data.get('id', '')
            return protocol, ip, port, uuid

        match = re.match(r'^(vless|trojan|ss)://([0-9a-f\-]+|[^\@]+)\@([^\:]+):(\d+)', link)
        if not match:
            return None, None, None, None
        
        protocol, uuid, ip, port = match.groups()
        
        if protocol == 'ss':
            uuid = link.split('@')[0].split('://')[1]
        
        return protocol, ip, port, uuid

    except Exception:
        return None, None, None, None

def normalize_telegram_url(url):
    """
    Normalizes Telegram channel URLs to the standard format with /s/.
    Example: Converts https://t.me/Hope_Net to https://t.me/s/Hope_Net.
    """
    url = url.strip()
    if url.startswith("https://t.me/"):
        parts = url.split('/')
        if len(parts) >= 4 and parts[3] != 's':
            # Convert to https://t.me/s/... format
            return f"https://t.me/s/{'/'.join(parts[3:])}"
    return url

def extract_channel_name(url):
    """Extracts normalized channel name from Telegram URL."""
    return url.split('/')[-1].replace('s/', '')

def count_servers_in_file(file_path):
    """Counts valid server entries in a text file."""
    if not os.path.exists(file_path):
        return 0
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return len([line for line in f if line.strip()])
    except Exception as e:
        print(f"Error counting servers in {file_path}: {e}")
        return 0

def get_current_counts():
    """Generates comprehensive server statistics."""
    counts = {}
    
    # Protocol-specific counts
    for proto in PATTERNS:
        proto_file = os.path.join(PROTOCOLS_DIR, f"{proto}.txt")
        counts[proto] = count_servers_in_file(proto_file)
    
    # Consolidated server count
    counts['total'] = count_servers_in_file(MERGED_SERVERS_FILE)
    
    # Regional distribution analysis
    regional_servers = 0
    country_data = {}
    for region_file in Path(REGIONS_DIR).glob("*.txt"):
        country = region_file.stem
        count = count_servers_in_file(region_file)
        country_data[country] = count
        regional_servers += count
    
    # Geo-IP resolution metrics
    counts['successful'] = regional_servers
    counts['failed'] = counts['total'] - regional_servers
    
    return counts, country_data

def get_channel_stats():
    """Compiles contribution metrics per Telegram channel."""
    channel_stats = {}
    for channel_file in Path(CHANNELS_DIR).glob("*.txt"):
        channel_name = channel_file.stem
        count = count_servers_in_file(channel_file)
        channel_stats[channel_name] = count
    return channel_stats

def save_extraction_data(channel_stats, country_data):
    """Persists extraction metrics to log file."""
    current_counts, country_stats = get_current_counts()
    
    try:
        with open(LOG_FILE, 'w', encoding='utf-8') as log:
            # Regional statistics
            log.write("=== Country Statistics ===\n")
            log.write(f"Total Servers: {current_counts['total']}\n")
            log.write(f"Successful Geo-IP Resolutions: {current_counts['successful']}\n")
            log.write(f"Failed Geo-IP Resolutions: {current_counts['failed']}\n")
            for country, count in sorted(country_stats.items(), key=lambda x: x[1], reverse=True):
                log.write(f"{country:<20} : {count}\n")
            
            # Protocol distribution
            log.write("\n=== Server Type Summary ===\n")
            sorted_protocols = sorted(PATTERNS.keys(), key=lambda x: current_counts[x], reverse=True)
            for proto in sorted_protocols:
                log.write(f"{proto.upper():<20} : {current_counts[proto]}\n")
            
            # Channel contributions
            log.write("\n=== Channel Statistics ===\n")
            for channel, total in sorted(channel_stats.items(), key=lambda x: x[1], reverse=True):
                log.write(f"{channel:<20}: {total}\n")
                
    except Exception as e:
        print(f"Error writing to log file: {e}")

def fetch_config_links(url):
    """Scrapes Telegram channel content for proxy configuration links."""
    try:
        response = requests.get(url, timeout=FETCH_CONFIG_LINKS_TIMEOUT)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Extract all code blocks and plain text
        message_tags = soup.find_all(['div', 'span'], class_='tgme_widget_message_text')
        code_blocks = soup.find_all(['code', 'pre'])
        
        configs = {proto: set() for proto in PATTERNS}
        configs["all"] = set()
        
        # Process code blocks separately
        for code_tag in code_blocks:
            code_text = code_tag.get_text().strip()
            # Remove ``` and ` from start and end
            clean_text = re.sub(r'^(`{1,3})|(`{1,3})$', '', code_text, flags=re.MULTILINE)
            
            for proto, pattern in PATTERNS.items():
                matches = re.findall(pattern, clean_text)
                if matches:
                    configs[proto].update(matches)
                    configs["all"].update(matches)
        
        # Process general message text
        for tag in message_tags:
            general_text = tag.get_text().strip()
            
            for proto, pattern in PATTERNS.items():
                matches = re.findall(pattern, general_text)
                if matches:
                    configs[proto].update(matches)
                    configs["all"].update(matches)
        
        return {k: list(v) for k, v in configs.items()}
    
    except requests.exceptions.RequestException as e:
        print(f"Connection error for {url}: {e}")
        return None

def load_existing_configs():
    """Loads previously extracted configurations to prevent duplicates."""
    existing = {proto: set() for proto in PATTERNS}
    existing["merged"] = set()
    
    # Protocol-specific entries
    for proto in PATTERNS:
        proto_file = os.path.join(PROTOCOLS_DIR, f"{proto}.txt")
        if os.path.exists(proto_file):
            try:
                with open(proto_file, 'r', encoding='utf-8') as f:
                    existing[proto] = set(f.read().splitlines())
            except Exception as e:
                print(f"Error reading {proto} configs: {e}")
    
    # Merged entries
    if os.path.exists(MERGED_SERVERS_FILE):
        try:
            with open(MERGED_SERVERS_FILE, 'r', encoding='utf-8') as f:
                existing['merged'] = set(f.read().splitlines())
        except Exception as e:
            print(f"Error reading merged configs: {e}")
    
    return existing

def trim_file(file_path, max_lines):
    """Trim file to keep only the latest entries up to max_lines."""
    if not os.path.exists(file_path):
        return
    try:
        with open(file_path, 'r+', encoding='utf-8') as f:
            lines = f.readlines()
            if len(lines) > max_lines:
                f.seek(0)
                f.truncate()
                f.writelines(lines[:max_lines])
    except Exception as e:
        print(f"Error trimming {file_path}: {e}")

def deduplicate_configs(configs, existing_keys):
    """Deduplicates a list of configs based on (ip, port, uuid) keys."""
    unique_configs = {}
    for link in configs:
        protocol, ip, port, uuid = parse_server_link(link)
        if not protocol or ip == '127.0.0.1':
            continue
        key = (ip, port, uuid)
        if key not in existing_keys and key not in unique_configs:
            unique_configs[key] = link
    return list(unique_configs.values())

def process_channel(url):
    """Executes full processing pipeline for a Telegram channel with deduplication."""
    existing_configs = load_existing_configs()
    channel_name = extract_channel_name(url)
    channel_file = os.path.join(CHANNELS_DIR, f"{channel_name}.txt")
    
    configs = fetch_config_links(url)
    if not configs:
        return 0, 0  # Early exit on failure

    all_channel_configs = set()
    for proto_links in configs.values():
        all_channel_configs.update(proto_links)

    # Load existing channel configs and their keys
    existing_channel_configs = set()
    existing_channel_keys = set()
    if os.path.exists(channel_file):
        with open(channel_file, 'r', encoding='utf-8') as f:
            existing_channel_configs = set(f.read().splitlines())
        for link in existing_channel_configs:
            protocol, ip, port, uuid = parse_server_link(link)
            if protocol and ip != '127.0.0.1':
                existing_channel_keys.add((ip, port, uuid))
    
    # Deduplicate new channel configs
    new_channel_configs = deduplicate_configs(all_channel_configs - existing_channel_configs, existing_channel_keys)
    if new_channel_configs:
        updated_channel_configs = new_channel_configs + list(existing_channel_configs)
        with open(channel_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(updated_channel_configs[:MAX_CHANNEL_SERVERS]) + '\n')

    # Protocol processing
    for proto, links in configs.items():
        if proto == "all":
            continue
        # Load existing protocol keys
        existing_proto_keys = set()
        for link in existing_configs[proto]:
            protocol, ip, port, uuid = parse_server_link(link)
            if protocol and ip != '127.0.0.1':
                existing_proto_keys.add((ip, port, uuid))
        
        # Deduplicate new protocol links
        new_links = deduplicate_configs(set(links) - existing_configs[proto], existing_proto_keys)
        if not new_links:
            continue

        # Update protocol file
        proto_path = os.path.join(PROTOCOLS_DIR, f"{proto}.txt")
        try:
            existing_lines = []
            if os.path.exists(proto_path):
                with open(proto_path, 'r', encoding='utf-8') as f:
                    existing_lines = f.read().splitlines()
            
            updated_lines = new_links + existing_lines
            with open(proto_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(updated_lines[:MAX_PROTOCOL_SERVERS]) + '\n')
        
        except Exception as e:
            print(f"Error writing to {proto} file: {e}")
        
        # Update merged list
        try:
            merged_lines = []
            existing_merged_keys = set()
            if os.path.exists(MERGED_SERVERS_FILE):
                with open(MERGED_SERVERS_FILE, 'r', encoding='utf-8') as f:
                    merged_lines = f.read().splitlines()
                for link in merged_lines:
                    protocol, ip, port, uuid = parse_server_link(link)
                    if protocol and ip != '127.0.0.1':
                        existing_merged_keys.add((ip, port, uuid))
            
            new_merged = deduplicate_configs(new_links, existing_merged_keys)
            updated_merged = new_merged + merged_lines
            with open(MERGED_SERVERS_FILE, 'w', encoding='utf-8') as f:
                f.write('\n'.join(updated_merged[:MAX_MERGED_SERVERS]) + '\n')
        
        except Exception as e:
            print(f"Error updating merged configs: {e}")
        
        existing_configs[proto].update(new_links)

    return 1, len(new_channel_configs)

def download_geoip_database():
    """Downloads GeoLite2-Country database from GitHub."""
    GEOIP_URL = "https://git.io/GeoLite2-Country.mmdb"
    GEOIP_DIR = Path("files/db")
    
    try:
        GEOIP_DIR.mkdir(parents=True, exist_ok=True)
        
        response = requests.get(GEOIP_URL, timeout=30)
        response.raise_for_status()
        
        with open(GEOIP_DATABASE_PATH, 'wb') as f:
            f.write(response.content)
            
        print("✅ GeoLite2 database downloaded successfully")
        return True
    
    except Exception as e:
        print(f"❌ Failed to download GeoIP database: {e}")
        return False

def process_geo_data():
    """Performs geographical analysis using GeoIP database with deduplication."""
    if not GEOIP_DATABASE_PATH.exists():
        print("⚠️ GeoIP database missing. Attempting download...")
        success = download_geoip_database()
        if not success:
            return {}
    
    try:
        geo_reader = geoip2.database.Reader(str(GEOIP_DATABASE_PATH))
    except Exception as e:
        print(f"GeoIP database error: {e}")
        return {}

    country_counter = {}  
    
    # Clear existing region files
    for region_file in Path(REGIONS_DIR).glob("*.txt"):
        region_file.unlink()

    # Process merged configurations
    configs = []
    if os.path.exists(MERGED_SERVERS_FILE):
        with open(MERGED_SERVERS_FILE, 'r', encoding='utf-8') as f:
            configs = [line.strip() for line in f if line.strip()]

    # Deduplicate configs for region processing
    unique_configs = {}
    for link in configs:
        protocol, ip, port, uuid = parse_server_link(link)
        if not protocol or ip == '127.0.0.1':
            continue
        key = (ip, port, uuid)
        if key not in unique_configs:
            unique_configs[key] = link

    for config in unique_configs.values():
        try:
            # Extract IP from common proxy URI formats
            ip = config.split('@')[1].split(':')[0]  
            country_response = geo_reader.country(ip)
            country = country_response.country.name or "Unknown"
            
            country_counter[country] = country_counter.get(country, 0) + 1
            
            region_file = os.path.join(REGIONS_DIR, f"{country}.txt")
            existing_region = []
            existing_region_keys = set()
            if os.path.exists(region_file):
                with open(region_file, 'r', encoding='utf-8') as f:
                    existing_region = f.read().splitlines()
                for link in existing_region:
                    protocol, ip, port, uuid = parse_server_link(link)
                    if protocol and ip != '127.0.0.1':
                        existing_region_keys.add((ip, port, uuid))
            
            if parse_server_link(config)[1:4] not in existing_region_keys:
                updated_region = [config] + existing_region
                with open(region_file, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(updated_region[:MAX_REGION_SERVERS]) + '\n')
                
        except (IndexError, geoip2.errors.AddressNotFoundError, ValueError):
            pass  # Silent fail for invalid formats
        except Exception as e:
            print(f"Geo processing error: {e}")
    
    geo_reader.close()
    return country_counter

if __name__ == "__main__":
    channels_file = CHANNELS_FILE
    
    try:
        # Read and normalize URLs
        with open(channels_file, 'r', encoding='utf-8') as f:
            raw_urls = [line.strip() for line in f if line.strip()]
        
        # Normalize URLs and remove duplicates
        normalized_urls = list({normalize_telegram_url(url) for url in raw_urls})
        
        # Sort and save back to file
        normalized_urls.sort()
        with open(channels_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(normalized_urls))
        
        print(f"✅ Found {len(normalized_urls)} unique channels (standardized)")
        
    except Exception as e:
        print(f"❌ Channel list error: {e}")
        sys.exit(1)

    # Batch processing with rate limiting
    for idx, channel in enumerate(normalized_urls, 1):
        success, _ = process_channel(channel)
        print(f"⌛ Processed {idx}/{len(normalized_urls)} {channel} ")
        if idx % BATCH_SIZE == 0:
            print(f"⏳ Processed {idx}/{len(normalized_urls)} channels, pausing for {SLEEP_TIME} s 🕐")
            time.sleep(SLEEP_TIME)

    print("🌍 Starting geographical analysis...")
    country_data = process_geo_data()
    
    # Generate final reports
    channel_stats = get_channel_stats()
    save_extraction_data(channel_stats, country_data)

    current_counts, _ = get_current_counts()
    print("\n✅ Extraction Complete")
    print(f"📁 Protocols: {PROTOCOLS_DIR}")
    print(f"🗺 Regions: {REGIONS_DIR}")
    print(f"📄 Merged : {MERGED_DIR}")
    print(f"📂 Channels: {CHANNELS_DIR}")
    print(f"\n📊 Final Statistics:")
    print(f"🎉 Total Servers: {current_counts['total']}")
    print(f"✅ Successful Geo-IP Resolutions: {current_counts['successful']}")
    print(f"❌ Failed Geo-IP Resolutions: {current_counts['failed']}")
