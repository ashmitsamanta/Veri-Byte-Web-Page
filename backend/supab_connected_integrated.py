import os
import mimetypes
import re
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, File, Form, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from supabase import create_client

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("SUPABASE_URL or SUPABASE_KEY is missing")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

app = FastAPI(title="Veri-Byte API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_bearer_token(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="Authentication required")
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing access token")
    return token


def get_current_user(authorization: str | None):
    token = get_bearer_token(authorization)
    try:
        response = supabase.auth.get_user(token)
        user = response.user
        if not user:
            raise ValueError("Invalid user")
        return user, token
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired session")


@app.get("/health")
def health():
    return {"success": True, "message": "Veri-Byte backend is running"}


@app.post("/signup")
def signup(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    phone: str = Form(""),
    aadhaar: str = Form(""),
):
    username = username.strip()
    email = email.strip().lower()
    phone = phone.strip()
    aadhaar = re.sub(r"\s", "", aadhaar)

    if not username or not email or not password:
        raise HTTPException(status_code=400, detail="Name, email and password are required")
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if phone and not re.fullmatch(r"[6-9][0-9]{9}", phone):
        raise HTTPException(status_code=400, detail="Invalid Indian mobile number")
    if aadhaar and not re.fullmatch(r"[0-9]{12}", aadhaar):
        raise HTTPException(status_code=400, detail="Aadhaar must contain 12 digits")

    try:
        response = supabase.auth.sign_up({
            "email": email,
            "password": password,
            "options": {
                "data": {
                    "user_name": username,
                    "phone": phone,
                    "aadhaar": aadhaar,
                }
            },
        })
        user = response.user
        if not user:
            raise HTTPException(status_code=400, detail="Could not create account")

        # Keep the existing application table in sync.
        try:
            supabase.table("SIH_user").insert({
                "user_id": user.id,
                "user_name": username,
                "user_email": email,
                "user_number":phone,
                "user_aadhaar_num":aadhaar
            }).execute()
        except Exception as db_error:
            # Auth user was created, so report the DB issue clearly instead of hiding it.
            raise HTTPException(status_code=500, detail=f"Account already exists {db_error}")

        session = response.session
        return {
            "success": True,
            "message": "Account created successfully",
            "user_id": user.id,
            "email": email,
            "access_token": session.access_token if session else None,
            "refresh_token": session.refresh_token if session else None,
            "requires_email_confirmation": session is None,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/signin")
def signin(
    email: str = Form(...),
    password: str = Form(...),
):
    try:
        response = supabase.auth.sign_in_with_password({
            "email": email.strip().lower(),
            "password": password,
        })
        if not response.session:
            raise HTTPException(status_code=401, detail="Login failed. Please confirm your email if required.")
        return {
            "success": True,
            "access_token": response.session.access_token,
            "refresh_token": response.session.refresh_token,
            "user_id": response.user.id,
            "email": response.user.email,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))


@app.get("/me")
def me(authorization: str | None = Header(default=None)):
    user, _ = get_current_user(authorization)
    metadata = user.user_metadata or {}
    return {
        "success": True,
        "user_id": user.id,
        "email": user.email,
        "name": metadata.get("user_name", ""),
        "phone": metadata.get("phone", ""),
        "aadhaar": metadata.get("aadhaar", ""),
    }


@app.post("/upload")
async def upload_document(
    file: UploadFile = File(...),
    authorization: str | None = Header(default=None),
):
    user, token = get_current_user(authorization)

    if not file.filename:
        raise HTTPException(status_code=400, detail="No file selected")

    allowed = {"image/jpeg", "image/png", "image/jpg"}
    content_type = file.content_type or mimetypes.guess_type(file.filename)[0]
    if content_type not in allowed:
        raise HTTPException(status_code=400, detail="Only JPG and PNG images are allowed")

    file_data = await file.read()
    if not file_data:
        raise HTTPException(status_code=400, detail="The selected file is empty")
    if len(file_data) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File is too large. Maximum size is 10 MB")

    safe_name = Path(file.filename).name.replace(" ", "_")
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "", safe_name)
    if not safe_name:
        safe_name = "aadhaar_document.jpg"

    storage_path = f"{user.id}/{safe_name}"

    try:
        authenticated_supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        authenticated_supabase.postgrest.auth(token)
        authenticated_supabase.storage.set_auth(token)
        authenticated_supabase.storage.from_("SIH_user_doc").upload(
            storage_path,
            file_data,
            {"content-type": content_type, "upsert": "true"},
        )
        return {"success": True, "message": "File uploaded successfully", "path": storage_path}
    except Exception as e:
        raise HTTPException(status_code=403, detail=str(e))
