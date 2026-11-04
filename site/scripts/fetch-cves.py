import urllib.request
import json
import os
import re
import datetime

NVD_API_KEY = os.environ.get('NVD_API_KEY', '')

def fetch_json(url, headers=None):
    req_headers = {'User-Agent': 'Bugterium-CVE-Fetcher/1.0'}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers)
    with urllib.request.urlopen(req) as response:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        return json.loads(response.read().decode())

def sanitize_text(text):
    if not text:
        return ""
    return re.sub(r'[<>&]', '', text)

def main():
    print("Fetching CISA KEV...")
    try:
        kev_data = fetch_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        vulns = kev_data['vulnerabilities']
        vulns.sort(key=lambda x: x.get('dateAdded', ''), reverse=True)
        top_kev = vulns[:15]
        cve_ids = [v['cveID'] for v in top_kev]
    except Exception as e:
        print(f"Failed to fetch KEV: {e}")
        return

    print(f"Fetching details for {len(cve_ids)} latest KEV CVEs from NVD...")
    ids_str = ",".join(cve_ids)
    nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={ids_str}"

    headers = {}
    if NVD_API_KEY:
        headers['apiKey'] = NVD_API_KEY
        print("Using NVD API Key from Secrets.")

    try:
        nvd_data = fetch_json(nvd_url, headers)
    except Exception as e:
        print(f"Failed to fetch NVD: {e}")
        return

    recent_cves = []
    for item in nvd_data.get('vulnerabilities', []):
        cve = item['cve']
        cve_id = cve['id']

        if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id):
            continue

        raw_desc = next((d['value'] for d in cve['descriptions'] if d['lang'] == 'en'), '')
        desc = sanitize_text(raw_desc)

        metrics = cve.get('metrics', {})
        cvss = 0.0
        if 'cvssMetricV31' in metrics:
            cvss = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
        elif 'cvssMetricV30' in metrics:
            cvss = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
        elif 'cvssMetricV2' in metrics:
            cvss = metrics['cvssMetricV2'][0]['cvssData']['baseScore']

        recent_cves.append({
            'id': cve_id,
            'description': desc,
            'cvss': cvss,
            'epss': 0.0,
            'url': f'https://nvd.nist.gov/vuln/detail/{cve_id}'
        })

    if recent_cves:
        print("Fetching EPSS...")
        try:
            epss_data = fetch_json(f"https://api.first.org/data/v1/epss?cve={ids_str}")
            epss_map = {item['cve']: float(item['epss']) for item in epss_data.get('data', [])}
            for c in recent_cves:
                c['epss'] = epss_map.get(c['id'], 0.0)
        except Exception as e:
            print(f"Failed to fetch EPSS: {e}")

    recent_cves.sort(key=lambda x: (x['cvss'], x['epss']), reverse=True)

    os.makedirs('site/static', exist_ok=True)
    
    # СОХРАНЯЕМ В НОВОМ ФОРМАТЕ
    output_data = {
        "last_sync": datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=4))).strftime("%Y-%m-%d %H:%M GMT+4"),
        "cves": recent_cves
    }
    
    with open('site/static/cve-feed.json', 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2)

    print(f"Saved {len(recent_cves)} CVEs to site/static/cve-feed.json")

if __name__ == '__main__':
    main()