import os
from pathlib import Path
from dotenv import load_dotenv



env_path = Path(__file__).parent / ".env"
load_dotenv(r"C:\smart_library_ready\cred.env")


print("ENV LOADED:")
print("DB_HOST =", os.getenv("DB_HOST"))
print("DB_USER =", os.getenv("DB_USER"))
print("JWT_SECRET =", os.getenv("JWT_SECRET"))



from typing import List, Optional
from datetime import datetime, timedelta

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr

import mysql.connector
from mysql.connector import Error
import jwt



app = FastAPI(title="Smart Library API with Bearer Auth")



DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "port": int(os.getenv("DB_PORT", 3306)),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "database": os.getenv("DB_NAME"),
}

import secrets
print(secrets.token_urlsafe(20))
SECRET_KEY = os.getenv("JWT_SECRET")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
TOKEN_EXPIRE_MIN = int(os.getenv("TOKEN_EXPIRE_MIN", 60))

security = HTTPBearer()



class User(BaseModel):
    user_name: str
    user_email: EmailStr


class UsersBulk(BaseModel):
    users: List[User]


class UserUpdate(BaseModel):
    user_name: str
    user_email: EmailStr


class UserPatch(BaseModel):
    user_name: Optional[str] = None
    user_email: Optional[EmailStr] = None


class LoginModel(BaseModel):
    user_email: EmailStr

# ================= DB CONNECTION =================

def get_conn():
    try:
        return mysql.connector.connect(**DB_CONFIG)
    except Error as e:
        raise HTTPException(500, f"MySQL error: {e}")

# ================= JWT =================

def create_token(user_id: int):
    payload = {
        "user_id": user_id,
        "exp": datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE_MIN),
        "iat": datetime.utcnow(),
    }

    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials

    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")

# ================= ROUTES =================

@app.get("/")
def root():
    return {"message": "Smart Library API Running with JWT Auth"}

# ---------- CREATE USER ----------

@app.post("/users")
def create_user(user: User):
    conn = get_conn()
    cur = conn.cursor()

    try:
        cur.execute(
            "INSERT INTO users (user_name, user_email) VALUES (%s,%s)",
            (user.user_name, user.user_email)
        )
        conn.commit()
        return {"user_id": cur.lastrowid}

    except mysql.connector.IntegrityError:
        raise HTTPException(400, "Email already exists")

    finally:
        cur.close()
        conn.close()

# ---------- LOGIN ----------

@app.post("/login")
def login(data: LoginModel):
    conn = get_conn()
    cur = conn.cursor(dictionary=True)

    cur.execute("SELECT * FROM users WHERE user_email=%s", (data.user_email,))
    user = cur.fetchone()

    cur.close()
    conn.close()

    if not user:
        raise HTTPException(404, "User not found")

    token = create_token(user["user_id"])

    return {
        "access_token": token,
        "token_type": "bearer"
    }

# ---------- GET ALL ----------

@app.get("/users")
def get_users(payload=Depends(verify_token)):
    conn = get_conn()
    cur = conn.cursor(dictionary=True)

    cur.execute("SELECT * FROM users")
    data = cur.fetchall()

    cur.close()
    conn.close()
    return data

# ---------- GET ONE ----------

@app.get("/users/{user_id}")
def get_user(user_id: int, payload=Depends(verify_token)):
    conn = get_conn()
    cur = conn.cursor(dictionary=True)

    cur.execute("SELECT * FROM users WHERE user_id=%s", (user_id,))
    user = cur.fetchone()

    cur.close()
    conn.close()

    if not user:
        raise HTTPException(404, "User not found")

    return user

# ---------- UPDATE ----------

@app.put("/users/{user_id}")
def update_user(user_id: int, user: UserUpdate, payload=Depends(verify_token)):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        "UPDATE users SET user_name=%s, user_email=%s WHERE user_id=%s",
        (user.user_name, user.user_email, user_id)
    )

    conn.commit()

    if cur.rowcount == 0:
        raise HTTPException(404, "User not found")

    cur.close()
    conn.close()

    return {"updated": True}

# ---------- DELETE ----------

@app.delete("/users/{user_id}")
def delete_user(user_id: int, payload=Depends(verify_token)):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("DELETE FROM users WHERE user_id=%s", (user_id,))
    conn.commit()

    if cur.rowcount == 0:
        raise HTTPException(404, "User not found")

    cur.close()
    conn.close()

    return {"deleted": True}
