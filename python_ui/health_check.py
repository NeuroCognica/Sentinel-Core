import urllib.request

if __name__ == "__main__":
    try:
        with urllib.request.urlopen("http://127.0.0.1:8080/health") as resp:
            print(resp.read().decode())
    except Exception as e:
        print(f"ERROR: {e}")
