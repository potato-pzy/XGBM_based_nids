import requests
 
def check_ip_with_virustotal(ip, api_key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{'86.49.133.106'}"
    headers = {
        "x-apikey": api_key
    } 
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None
    
def main():
    api_key = "77d9d553fa54fc85f938f8ee379abbc4e220e89c711b0b3f9f41b6ceb65eb567"  # Replace with your actual API key
    ip_address = '86.49.133.106'
    
    result = check_ip_with_virustotal(ip_address, api_key)
    if result:
        print(result)

if __name__ == "__main__":
    main()
