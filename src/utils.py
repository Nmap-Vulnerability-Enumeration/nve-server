from requests import get

def get_my_external_ip():
    return get('https://api.ipify.org').text