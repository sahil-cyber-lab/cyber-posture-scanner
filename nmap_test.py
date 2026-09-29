import subprocess

result = subprocess.run(
    ["nmap", "127.0.0.1"],
    capture_output=True,
    text=True
)

print(result.stdout)