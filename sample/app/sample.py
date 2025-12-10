import sqlite3
import requests
import os

def login_inseguro(con, username, password):
    """Ejemplo de SQL Injection INSEGURO."""
    cur = con.cursor()
    query = f"SELECT id FROM users WHERE username = '{username}' AND password = '{password}'"
    cur.execute(query)
    return cur.fetchone()

def login_seguro(con, username, password):
    """Ejemplo de consulta SQL SEGURA usando parámetros."""
    cur = con.cursor()
    query = "SELECT id FROM users WHERE username = ? AND password = ?"
    cur.execute(query, (username, password))
    return cur.fetchone()

def check_username_github(username):
    """Ejemplo de posible SSRF pero con dominio fijo (api.github.com)."""
    url = f"https://api.github.com/users/{username}"
    response = requests.get(url)
    return response.status_code == 200

def crear_archivo_temporal(username):
    """Ejemplo de Command Injection con os.system."""
    comando = f"touch /tmp/{username}"
    os.system(comando)

if __name__ == "__main__":
    con = sqlite3.connect(":memory:")
    username = input("Usuario: ")
    password = input("Contraseña: ")
    print("Login inseguro:")
    print(login_inseguro(con, username, password))
    print("Login seguro:")
    print(login_seguro(con, username, password))
    print("Check username en GitHub:")
    print(check_username_github(username))
    print("Crear archivo temporal:")
    crear_archivo_temporal(username)
