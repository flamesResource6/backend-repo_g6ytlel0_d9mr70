import os
from datetime import datetime, timedelta, timezone, date
from typing import Optional, List, Dict, Any

import jwt
from fastapi import FastAPI, HTTPException, Depends, Body, Query, Cookie
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext

from database import db, create_document, get_documents
from schemas import User, Santri, Pegawai, PembayaranSyariah, GajiPegawai, Transaksi, RefreshToken

# App & CORS
app = FastAPI(title="Riyadlul Huda Treasurer API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth setup
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
ACCESS_EXPIRES_MIN = int(os.getenv("ACCESS_EXPIRES_MIN", "30"))
REFRESH_EXPIRES_DAYS = int(os.getenv("REFRESH_EXPIRES_DAYS", "7"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
http_bearer = HTTPBearer(auto_error=False)

# Helpers

def collection(name: str):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not available")
    return db[name]


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def create_token(payload: dict, expires_delta: timedelta) -> str:
    to_encode = payload.copy()
    exp = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": exp})
    token = jwt.encode(to_encode, JWT_SECRET, algorithm="HS256")
    return token


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # type: ignore
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


async def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(http_bearer)) -> Dict[str, Any]:
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = credentials.credentials
    payload = decode_token(token)
    uid = payload.get("uid")
    if not uid:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    user = collection("user").find_one({"_id": {"$eq": db.client.get_default_database().codec_options.document_class({})}})  # placeholder to satisfy type
    user = collection("user").find_one({"_id": payload.get("uid")})
    if not user:
        # Support older seeds using username/email lookup
        username = payload.get("username")
        if username:
            user = collection("user").find_one({"username": username})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


# Startup: seed admin user
@app.on_event("startup")
def seed_admin():
    if db is None:
        return
    users = collection("user")
    admin = users.find_one({"$or": [{"username": "admin"}, {"email": "bendahara@gmail.com"}]})
    if not admin:
        password_hash = hash_password("bendahara")
        doc = {
            "username": "admin",
            "email": "bendahara@gmail.com",
            "password_hash": password_hash,
            "role": "admin",
            "created_at": datetime.now(timezone.utc),
        }
        users.insert_one(doc)
        # Also create a default refresh token placeholder collection index
        collection("refreshtoken").create_index("user_id")
    # Basic useful indexes
    try:
        collection("santri").create_index([("nis", 1)], unique=True)
        collection("pembayaransyariah").create_index([("santri_id", 1), ("tahun", 1), ("bulan", 1)])
        collection("pegawai").create_index([("nama", 1)])
        collection("gajipegawai").create_index([("pegawai_id", 1), ("tahun", 1), ("bulan", 1)])
    except Exception:
        pass


# Health
@app.get("/")
def root():
    return {"message": "Riyadlul Huda Treasurer API running"}


# Auth routes
@app.post("/auth/login")
def login(username: Optional[str] = Body(None), email: Optional[str] = Body(None), password: str = Body(...)):
    if not username and not email:
        raise HTTPException(status_code=400, detail="Provide username or email")
    q = {"username": username} if username else {"email": email}
    user = collection("user").find_one(q)
    if not user or not verify_password(password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access = create_token({"uid": str(user.get("_id")), "username": user.get("username"), "role": user.get("role", "admin")}, timedelta(minutes=ACCESS_EXPIRES_MIN))
    refresh = create_token({"uid": str(user.get("_id")), "type": "refresh"}, timedelta(days=REFRESH_EXPIRES_DAYS))

    # store refresh
    collection("refreshtoken").insert_one({
        "user_id": str(user.get("_id")),
        "token": refresh,
        "expires_at": datetime.now(timezone.utc) + timedelta(days=REFRESH_EXPIRES_DAYS),
        "created_at": datetime.now(timezone.utc)
    })

    return {"access_token": access, "refresh_token": refresh, "user": {"username": user.get("username"), "email": user.get("email"), "role": user.get("role", "admin")}}


@app.post("/auth/refresh")
def refresh_token(refresh_token: str = Body(..., embed=True)):
    payload = decode_token(refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=400, detail="Invalid refresh token")
    # validate exists
    token_doc = collection("refreshtoken").find_one({"token": refresh_token})
    if not token_doc:
        raise HTTPException(status_code=401, detail="Refresh token not recognized")
    uid = payload.get("uid")
    access = create_token({"uid": uid}, timedelta(minutes=ACCESS_EXPIRES_MIN))
    return {"access_token": access}


@app.get("/me")
def me(user: dict = Depends(get_current_user)):
    return {"username": user.get("username"), "email": user.get("email"), "role": user.get("role", "admin")}


# Utility: pagination

def paginate(cur, page: int, page_size: int):
    total = cur.count() if hasattr(cur, 'count') else collection(cur._Collection__name).count_documents(cur._Cursor__spec)  # type: ignore
    items = list(cur.skip((page - 1) * page_size).limit(page_size))
    return {"items": items, "page": page, "page_size": page_size, "total": total}


# Santri CRUD & queries
@app.post("/santri")
def create_santri(payload: Santri, user: dict = Depends(get_current_user)):
    doc = payload.model_dump()
    doc.update({"created_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc)})
    res = collection("santri").insert_one(doc)
    return {"id": str(res.inserted_id)}


@app.get("/santri")
def list_santri(
    q: Optional[str] = Query(None),
    kelas: Optional[str] = None,
    asrama: Optional[str] = None,
    kobong: Optional[str] = None,
    gender: Optional[str] = None,
    kabupaten: Optional[str] = None,
    aktif: Optional[bool] = None,
    page: int = 1,
    page_size: int = 20,
    user: dict = Depends(get_current_user)
):
    filt: Dict[str, Any] = {}
    if q:
        filt["$or"] = [{"nama": {"$regex": q, "$options": "i"}}, {"nis": {"$regex": q, "$options": "i"}}]
    if kelas: filt["kelas"] = kelas
    if asrama: filt["asrama"] = asrama
    if kobong: filt["kobong"] = kobong
    if gender: filt["gender"] = gender
    if kabupaten: filt["kabupaten"] = kabupaten
    if aktif is not None: filt["aktif"] = aktif
    cur = collection("santri").find(filt)
    items = list(cur.skip((page-1)*page_size).limit(page_size))
    total = collection("santri").count_documents(filt)
    return {"items": items, "page": page, "page_size": page_size, "total": total}


# Pegawai CRUD
@app.post("/pegawai")
def create_pegawai(payload: Pegawai, user: dict = Depends(get_current_user)):
    doc = payload.model_dump()
    doc.update({"created_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc)})
    res = collection("pegawai").insert_one(doc)
    return {"id": str(res.inserted_id)}


@app.get("/pegawai")
def list_pegawai(
    q: Optional[str] = Query(None),
    department: Optional[str] = None,
    role: Optional[str] = None,
    aktif: Optional[bool] = None,
    page: int = 1,
    page_size: int = 20,
    user: dict = Depends(get_current_user)
):
    filt: Dict[str, Any] = {}
    if q:
        filt["$or"] = [{"nama": {"$regex": q, "$options": "i"}}, {"email": {"$regex": q, "$options": "i"}}]
    if department: filt["department"] = department
    if role: filt["role"] = role
    if aktif is not None: filt["aktif"] = aktif
    total = collection("pegawai").count_documents(filt)
    items = list(collection("pegawai").find(filt).skip((page-1)*page_size).limit(page_size))
    return {"items": items, "page": page, "page_size": page_size, "total": total}


# Pembayaran Syariah
@app.post("/syariah")
def create_syariah(payload: PembayaranSyariah, user: dict = Depends(get_current_user)):
    doc = payload.model_dump()
    doc.update({"created_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc)})
    res = collection("pembayaransyariah").insert_one(doc)
    return {"id": str(res.inserted_id)}


@app.get("/syariah")
def list_syariah(
    santri_id: Optional[str] = None,
    tahun: Optional[int] = None,
    bulan: Optional[str] = None,
    status: Optional[str] = None,
    page: int = 1,
    page_size: int = 20,
    user: dict = Depends(get_current_user)
):
    filt: Dict[str, Any] = {}
    if santri_id: filt["santri_id"] = santri_id
    if tahun: filt["tahun"] = tahun
    if bulan: filt["bulan"] = bulan
    if status: filt["status"] = status
    total = collection("pembayaransyariah").count_documents(filt)
    items = list(collection("pembayaransyariah").find(filt).skip((page-1)*page_size).limit(page_size))
    return {"items": items, "page": page, "page_size": page_size, "total": total}


# Gaji Pegawai
@app.post("/gaji")
def create_gaji(payload: GajiPegawai, user: dict = Depends(get_current_user)):
    doc = payload.model_dump()
    doc.update({"created_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc)})
    res = collection("gajipegawai").insert_one(doc)
    return {"id": str(res.inserted_id)}


@app.get("/gaji")
def list_gaji(
    pegawai_id: Optional[str] = None,
    department: Optional[str] = None,
    role: Optional[str] = None,
    tahun: Optional[int] = None,
    bulan: Optional[int] = None,
    status: Optional[str] = None,
    page: int = 1,
    page_size: int = 20,
    user: dict = Depends(get_current_user)
):
    filt: Dict[str, Any] = {}
    if pegawai_id: filt["pegawai_id"] = pegawai_id
    if tahun: filt["tahun"] = tahun
    if bulan: filt["bulan"] = bulan
    if status: filt["status"] = status
    # If filter by department/role, join by lookup (simple approach)
    if department or role:
        # get matching pegawai ids
        p_filt: Dict[str, Any] = {}
        if department: p_filt["department"] = department
        if role: p_filt["role"] = role
        ids = [str(p.get("_id")) for p in collection("pegawai").find(p_filt, {"_id": 1})]
        filt["pegawai_id"] = {"$in": ids} if ids else "__none__"
    total = collection("gajipegawai").count_documents(filt)
    items = list(collection("gajipegawai").find(filt).skip((page-1)*page_size).limit(page_size))
    return {"items": items, "page": page, "page_size": page_size, "total": total}


# Transaksi Umum
@app.post("/transaksi")
def create_transaksi(payload: Transaksi, user: dict = Depends(get_current_user)):
    doc = payload.model_dump()
    doc.update({"created_at": datetime.now(timezone.utc), "updated_at": datetime.now(timezone.utc)})
    res = collection("transaksi").insert_one(doc)
    return {"id": str(res.inserted_id)}


@app.get("/transaksi")
def list_transaksi(
    jenis: Optional[str] = None,
    tahun: Optional[int] = None,
    bulan: Optional[int] = None,
    page: int = 1,
    page_size: int = 20,
    user: dict = Depends(get_current_user)
):
    filt: Dict[str, Any] = {}
    if jenis: filt["jenis"] = jenis
    if tahun or bulan:
        # filter by tanggal range
        start = datetime(tahun or 2000, bulan or 1, 1, tzinfo=timezone.utc)
        end_month = (bulan or 12)
        end_year = (tahun or 2100)
        if bulan:
            if bulan == 12:
                end = datetime((tahun or 2100) + 1, 1, 1, tzinfo=timezone.utc)
            else:
                end = datetime(tahun or 2100, bulan + 1, 1, tzinfo=timezone.utc)
        else:
            end = datetime(end_year + 1, 1, 1, tzinfo=timezone.utc)
        filt["tanggal"] = {"$gte": start.date(), "$lt": end.date()}
    total = collection("transaksi").count_documents(filt)
    items = list(collection("transaksi").find(filt).skip((page-1)*page_size).limit(page_size))
    return {"items": items, "page": page, "page_size": page_size, "total": total}


# Summary/Dashboard
@app.get("/summary")
def summary(
    tahun: Optional[int] = None,
    bulan: Optional[int] = None,
    asrama: Optional[str] = None,
    kelas: Optional[str] = None,
    gender: Optional[str] = None,
    user: dict = Depends(get_current_user)
):
    # Totals
    total_santri = collection("santri").count_documents({"aktif": True})

    sy_filt: Dict[str, Any] = {}
    if tahun: sy_filt["tahun"] = tahun
    if bulan: sy_filt["bulan"] = month_name(bulan)
    if gender or asrama or kelas:
        # need santri filter
        s_filt: Dict[str, Any] = {}
        if gender: s_filt["gender"] = gender
        if asrama: s_filt["asrama"] = asrama
        if kelas: s_filt["kelas"] = kelas
        ids = [str(s.get("_id")) for s in collection("santri").find(s_filt, {"_id": 1})]
        sy_filt["santri_id"] = {"$in": ids} if ids else "__none__"

    total_pemasukan = sum([x.get("nominal", 0) for x in collection("transaksi").find({"jenis": "pemasukan"})])
    total_pengeluaran = sum([x.get("nominal", 0) for x in collection("transaksi").find({"jenis": "pengeluaran"})])

    pembayaran = list(collection("pembayaransyariah").find(sy_filt))
    pembayaran_lunas = [p for p in pembayaran if p.get("status") == "Lunas"]
    pembayaran_belum = [p for p in pembayaran if p.get("status") != "Lunas"]

    # Gaji
    gaji_filt: Dict[str, Any] = {}
    if tahun: gaji_filt["tahun"] = tahun
    if bulan: gaji_filt["bulan"] = bulan
    gaji_items = list(collection("gajipegawai").find(gaji_filt))
    total_gaji_bulan_ini = sum([g.get("total_bersih", 0) for g in gaji_items if g.get("status") == "Dibayar"])
    total_gaji_tertunda = sum([g.get("total_bersih", 0) for g in gaji_items if g.get("status") != "Dibayar"])

    return {
        "total_santri_aktif": total_santri,
        "total_pemasukan": total_pemasukan,
        "total_pengeluaran": total_pengeluaran,
        "pembayaran_syariah_lunas": len(pembayaran_lunas),
        "pembayaran_syariah_belum": len(pembayaran_belum),
        "jumlah_tunggakan": sum([p.get("nominal", 0) for p in pembayaran_belum]),
        "total_gaji_bulan_ini": total_gaji_bulan_ini,
        "total_gaji_tertunda": total_gaji_tertunda,
    }


# Utility endpoints
@app.get("/schema")
def get_schema():
    """Return schema metadata for collections (for tooling/clients)."""
    return {
        "collections": [
            "user", "santri", "pegawai", "pembayaransyariah", "gajipegawai", "transaksi", "refreshtoken"
        ]
    }


# Helpers
MONTHS = [
    "Januari", "Februari", "Maret", "April", "Mei", "Juni",
    "Juli", "Agustus", "September", "Oktober", "November", "Desember"
]


def month_name(m: int) -> str:
    return MONTHS[m-1] if 1 <= m <= 12 else ""


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
