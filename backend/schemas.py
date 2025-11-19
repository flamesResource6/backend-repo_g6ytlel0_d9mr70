"""
Database Schemas for the Riyadlul Huda Treasurer Dashboard

Each Pydantic model represents a MongoDB collection (collection name = lowercase of class name).
These schemas are used for validating request bodies and documenting the API.
"""
from __future__ import annotations
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Literal
from datetime import date, datetime

# -----------------------------
# Core Entities
# -----------------------------
class User(BaseModel):
    username: str = Field(..., min_length=3)
    email: EmailStr
    password_hash: str
    role: str = Field(default="admin")
    created_at: Optional[datetime] = None

class Santri(BaseModel):
    nis: str
    nama: str
    kelas: str
    asrama: str
    kobong: str
    gender: Literal["Putra", "Putri"]
    alamat: Optional[str] = None
    kabupaten: Optional[str] = None
    aktif: bool = True

class Pegawai(BaseModel):
    nip: Optional[str] = None
    nama: str
    role: str
    department: str
    email: Optional[EmailStr] = None
    telp: Optional[str] = None
    alamat: Optional[str] = None
    tanggal_bergabung: Optional[date] = None
    aktif: bool = True

class PembayaranSyariah(BaseModel):
    santri_id: str
    tanggal: date
    bulan: str
    tahun: int
    nominal: float
    status: Literal["Lunas", "Belum"]
    keterangan: Optional[str] = None

class GajiPegawai(BaseModel):
    pegawai_id: str
    bulan: int = Field(ge=1, le=12)
    tahun: int = Field(ge=2000, le=2100)
    gaji_pokok: float = Field(ge=0)
    tunjangan: float = 0
    potongan: float = 0
    total_bersih: float = Field(ge=0)
    status: Literal["Dibayar", "Belum"] = "Belum"
    tanggal_bayar: Optional[date] = None
    keterangan: Optional[str] = None

class Transaksi(BaseModel):
    santri_id: Optional[str] = None
    jenis: str
    nominal: float
    tanggal: date
    keterangan: Optional[str] = None

class RefreshToken(BaseModel):
    user_id: str
    token: str
    expires_at: datetime
