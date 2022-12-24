import requests

# Replace YOUR_API_KEY with your actual VirusTotal API key
api_key = ""

# Set the base URL 
base_url = "https://www.virustotal.com/api/v3"

def is_hash_malicious(hash):
    endpoint = f"{base_url}/files/{hash}"
    headers = {
        "x-apikey": api_key
    }
    response = requests.get(endpoint, headers=headers)
    data = response.json()
    if "data" in data and "attributes" in data["data"] and "last_analysis_stats" in data["data"]["attributes"]:
        last_analysis_stats = data["data"]["attributes"]["last_analysis_stats"]
        if "malicious" in last_analysis_stats and last_analysis_stats["malicious"] > 0:
            return True
    return False

# Define a list of hashes to check
hashes = ["", ""]

# Iterate through the list of hashes and check each one for maliciousness
for hash in hashes:
    if is_hash_malicious(hash):
        print(f"{hash} is malicious")
    else:
        print(f"{hash} is not malicious")
