import urllib.request, json
resp = urllib.request.urlopen("http://localhost:8000/api/risks")
data = json.loads(resp.read())
risks = data["risks"]
for r in risks:
    ransomware = "RANSOMWARE" if r["ransomware_linked"] else ""
    kev = "KEV" if r["is_kev"] else ""
    print(f"#{r['rank']}: {r['asset_name']} | {r['vulnerability_name']}")
    print(f"     CVE: {r['cve']} | CVSS: {r['cvss']} | Score: {r['composite_score']:.4f} | NIST: {r['nist_control_id']} {ransomware} {kev}")
    print()
