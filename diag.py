import os

from dotenv import load_dotenv

from falkordb import FalkorDB

load_dotenv()

host = os.getenv("FALKORDB_HOST", "")
port = int(os.getenv("FALKORDB_PORT", "6379"))
user = os.getenv("FALKORDB_USERNAME") or None
pwd = os.getenv("FALKORDB_PASSWORD") or None

print("host:", host or "(EMPTY: .env not loaded)")
print("port:", port, "| username:", user, "| password set:", bool(pwd))

for ssl in (False, True):
    try:
        g = FalkorDB(host=host, port=port, username=user, password=pwd, ssl=ssl).select_graph("diag")
        print(f"ssl={ssl}: OK ->", g.query("RETURN 1").result_set)
        break
    except Exception as e:
        print(f"ssl={ssl}: FAILED ->", type(e).__name__, str(e)[:200])
