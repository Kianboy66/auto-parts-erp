import asyncio
import hashlib
import hmac
import io
import json
import os
import secrets
import shutil
import sqlite3
import tempfile
import zipfile
from contextlib import contextmanager
from datetime import datetime, time, timedelta
from pathlib import Path
from typing import Any, Optional
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from db import (
    BASE_DIR,
    BACKUP_DIR,
    DB_PATH,
    SAMPLES_DIR,
    get_conn,
    get_shamsi_date,
    get_shamsi_now,
    init_db,
    log_audit,
)
from ocr_engine import ensure_sample_pdfs, extract_invoice_from_pdf

FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
UPLOAD_DIR = os.path.join(BASE_DIR, "data", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)

app = FastAPI(
    title="البرز پارت | سامانه حسابداری فروشگاه قطعات خودرو",
    description="API هسته عملیاتی مدیریت کالا، خرید، فروش، موجودی دو انبار، حساب طرفین و OCR فاکتور خرید.",
    version="1.0.0",
    docs_url="/api-docs",
    redoc_url=None,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Local-session tokens are short-lived runtime credentials. Channel API credentials live in api_tokens.
SESSIONS: dict[str, dict[str, Any]] = {}
LOGIN_ATTEMPTS: dict[str, list[float]] = {}
BACKUP_TASK: Optional[asyncio.Task] = None


@contextmanager
def db_read():
    conn = get_conn()
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def db_transaction():
    conn = get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def app_date(body_date: Optional[str] = None) -> str:
    return body_date or get_shamsi_date()


def safe_int(value: Any, default: int = 0) -> int:
    if value is None or value == "":
        return default
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def row_dict(row: Optional[sqlite3.Row]) -> Optional[dict[str, Any]]:
    return dict(row) if row is not None else None


def rows_dict(rows) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]


def get_setting(conn, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM system_settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(conn, key: str, value: str, username: str = "admin"):
    conn.execute(
        "INSERT INTO system_settings (key, value, updated_by, updated_at) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = excluded.updated_at",
        (key, str(value), username, now_iso()),
    )


def next_number(conn, kind: str) -> str:
    configs = {
        "SALE": ("invoice_seq_counter", "INV-1405-", 5),
        "PURCHASE": ("purchase_seq_counter", "PUR-1405-", 5),
        "TRANSFER": ("transfer_seq_counter", "TRF-1405-", 4),
        "ADJUSTMENT": ("adjustment_seq_counter", "ADJ-1405-", 4),
        "SALE_RETURN": ("sale_return_seq_counter", "SRT-1405-", 4),
        "PURCHASE_RETURN": ("purchase_return_seq_counter", "PRT-1405-", 4),
    }
    key, prefix, width = configs[kind]
    old = safe_int(get_setting(conn, key, "0"))
    new = old + 1
    set_setting(conn, key, str(new))
    return f"{prefix}{new:0{width}d}"


def next_batch_code(conn, product_id: int, warehouse_id: int) -> str:
    count = conn.execute("SELECT COALESCE(MAX(id),0)+1 FROM inventory_batches").fetchone()[0]
    return f"LOT-1405-{product_id:03d}-{warehouse_id}-{count:05d}"


def ensure_user(user: dict[str, Any], *allowed_roles: str):
    if allowed_roles and user["role"] not in allowed_roles:
        raise HTTPException(status_code=403, detail="دسترسی لازم برای انجام این عملیات را ندارید.")


def hash_password(password: str, salt: Optional[str] = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 240000).hex()
    return f"pbkdf2_sha256${salt}${digest}"


def verify_password(stored: str, provided: str) -> tuple[bool, Optional[str]]:
    if stored.startswith("pbkdf2_sha256$"):
        try:
            _, salt, digest = stored.split("$", 2)
            return hmac.compare_digest(hash_password(provided, salt).split("$", 2)[2], digest), None
        except Exception:
            return False, None
    # Upgrade the original demo credentials to a salted PBKDF2 hash at first successful login.
    ok = hmac.compare_digest(stored.encode("utf-8"), provided.encode("utf-8"))
    return ok, hash_password(provided) if ok else None


async def current_user(authorization: Optional[str] = Header(None)) -> dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="برای ادامه وارد حساب کاربری شوید.")
    token = authorization.split(" ", 1)[1].strip()
    user = SESSIONS.get(token)
    if not user:
        raise HTTPException(status_code=401, detail="نشست شما منقضی شده است؛ دوباره وارد شوید.")
    return user


def channel_token_user(authorization: Optional[str]):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="توکن API الزامی است.")
    raw_token = authorization.split(" ", 1)[1].strip()
    with db_transaction() as conn:
        token_row = conn.execute(
            "SELECT t.*, u.username, u.role FROM api_tokens t JOIN users u ON u.id=t.user_id "
            "WHERE t.token=? AND t.is_active=1",
            (raw_token,),
        ).fetchone()
        if not token_row:
            raise HTTPException(status_code=401, detail="توکن API نامعتبر یا غیرفعال است.")
        conn.execute("UPDATE api_tokens SET last_used_at=? WHERE id=?", (get_shamsi_now(), token_row["id"]))
        return dict(token_row)


def require_channel_ability(token_row: dict[str, Any], ability: str):
    abilities = set((token_row.get("abilities") or "").split(","))
    if ability not in abilities and "*" not in abilities:
        raise HTTPException(status_code=403, detail=f"توکن مجوز {ability} ندارد.")


def insert_party_ledger(
    conn,
    party_id: int,
    shamsi_date: str,
    entry_type: str,
    reference_type: str,
    reference_id: Optional[int],
    reference_number: str,
    debit_rial: int,
    credit_rial: int,
    payment_method: str,
    description: str,
    username: str,
):
    conn.execute(
        """INSERT INTO party_ledger_entries (
            party_id, shamsi_date, entry_type, reference_type, reference_id, reference_number,
            debit_rial, credit_rial, payment_method, description, created_by, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            party_id,
            shamsi_date,
            entry_type,
            reference_type,
            reference_id,
            reference_number,
            int(debit_rial),
            int(credit_rial),
            payment_method,
            description,
            username,
            now_iso(),
        ),
    )


def stock_qty(conn, product_id: int, warehouse_id: int) -> int:
    row = conn.execute(
        "SELECT quantity FROM product_warehouse_stocks WHERE product_id=? AND warehouse_id=?",
        (product_id, warehouse_id),
    ).fetchone()
    return int(row["quantity"]) if row else 0


def set_stock(conn, product_id: int, warehouse_id: int, quantity: int):
    conn.execute(
        "INSERT INTO product_warehouse_stocks (product_id, warehouse_id, quantity) VALUES (?, ?, ?) "
        "ON CONFLICT(product_id, warehouse_id) DO UPDATE SET quantity=excluded.quantity",
        (product_id, warehouse_id, int(quantity)),
    )


def add_movement(
    conn,
    product_id: int,
    warehouse_id: int,
    shamsi_date: str,
    movement_type: str,
    reference_number: str,
    qty_change: int,
    stock_after: int,
    unit_price_or_cost_rial: int,
    description: str,
    username: str,
):
    conn.execute(
        """INSERT INTO inventory_movements (
            product_id, warehouse_id, shamsi_date, movement_type, reference_number, qty_change,
            stock_after, unit_price_or_cost_rial, description, created_by, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            product_id,
            warehouse_id,
            shamsi_date,
            movement_type,
            reference_number,
            qty_change,
            stock_after,
            unit_price_or_cost_rial,
            description,
            username,
            now_iso(),
        ),
    )


def create_batch(
    conn,
    product_id: int,
    warehouse_id: int,
    qty: int,
    unit_cost_rial: int,
    source_type: str,
    shamsi_date: str,
    notes: str = "",
    purchase_invoice_id: Optional[int] = None,
    supplier_id: Optional[int] = None,
    batch_code: Optional[str] = None,
    remaining_qty: Optional[int] = None,
) -> int:
    code = batch_code or next_batch_code(conn, product_id, warehouse_id)
    cur = conn.execute(
        """INSERT INTO inventory_batches (
            batch_code, product_id, warehouse_id, source_type, purchase_invoice_id, supplier_id,
            shamsi_date, initial_qty, remaining_qty, unit_cost_rial, notes, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            code,
            product_id,
            warehouse_id,
            source_type,
            purchase_invoice_id,
            supplier_id,
            shamsi_date,
            int(qty),
            int(qty if remaining_qty is None else remaining_qty),
            int(unit_cost_rial),
            notes,
            now_iso(),
        ),
    )
    return int(cur.lastrowid)


def consume_fifo(conn, product_id: int, warehouse_id: int, qty: int, fallback_cost_rial: int):
    """Consumes available positive FIFO lots and returns the exact cost slices.

    When an allowed negative-stock sale/transfer has no physical lot to consume, the remainder is
    explicitly represented as a provisional-cost slice and flagged on the invoice. Subsequent
    purchases never rewrite finalized historical documents.
    """
    old_qty = stock_qty(conn, product_id, warehouse_id)
    need = int(qty)
    breakdown: list[dict[str, Any]] = []
    total_cost = 0
    batches = conn.execute(
        """SELECT * FROM inventory_batches WHERE product_id=? AND warehouse_id=? AND remaining_qty>0
        ORDER BY shamsi_date ASC, id ASC""",
        (product_id, warehouse_id),
    ).fetchall()
    for batch in batches:
        if need <= 0:
            break
        take = min(need, int(batch["remaining_qty"]))
        conn.execute("UPDATE inventory_batches SET remaining_qty=remaining_qty-? WHERE id=?", (take, batch["id"]))
        cost = take * int(batch["unit_cost_rial"])
        total_cost += cost
        breakdown.append(
            {
                "batch_id": int(batch["id"]),
                "batch_code": batch["batch_code"],
                "qty": take,
                "unit_cost_rial": int(batch["unit_cost_rial"]),
                "total_cost_rial": cost,
            }
        )
        need -= take
    if need > 0:
        unit_cost = max(0, int(fallback_cost_rial))
        cost = need * unit_cost
        total_cost += cost
        breakdown.append(
            {
                "batch_id": None,
                "batch_code": "NEGATIVE-STOCK-ESTIMATE",
                "qty": need,
                "unit_cost_rial": unit_cost,
                "total_cost_rial": cost,
                "provisional_cost": True,
            }
        )
    new_qty = old_qty - int(qty)
    set_stock(conn, product_id, warehouse_id, new_qty)
    return breakdown, total_cost, old_qty, new_qty


def ledger_balance(conn, party_id: int) -> int:
    row = conn.execute(
        "SELECT COALESCE(SUM(debit_rial),0)-COALESCE(SUM(credit_rial),0) AS balance FROM party_ledger_entries WHERE party_id=?",
        (party_id,),
    ).fetchone()
    return int(row["balance"] or 0)


def payment_rows(conn, invoice_type: str, invoice_id: int, party_id: int, payments: list, shamsi_date: str, username: str):
    """Persists non-credit payment lines; returns received/paid total."""
    total = 0
    for p in payments:
        amount = safe_int(p.get("amount_rial"))
        method = (p.get("method") or p.get("payment_method") or "CASH").upper()
        if amount <= 0:
            continue
        if method == "CREDIT":
            continue
        if method not in {"CASH", "POS", "CARD_TO_CARD", "CHEQUE"}:
            raise HTTPException(422, f"روش پرداخت نامعتبر است: {method}")
        cheque_id = None
        reference = p.get("reference_no") or ""
        if method == "CHEQUE":
            ch = p.get("cheque") or {}
            cheque_type = "RECEIVED" if invoice_type == "SALE" else "ISSUED"
            cur = conn.execute(
                """INSERT INTO cheques (
                    cheque_type, party_id, invoice_id, cheque_number, sayad_id, bank_name, amount_rial,
                    issue_shamsi_date, due_shamsi_date, status, is_overdue, notes, created_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', 0, ?, ?, ?)""",
                (
                    cheque_type,
                    party_id,
                    invoice_id,
                    str(ch.get("cheque_number") or f"CHQ-{secrets.randbelow(999999):06d}"),
                    ch.get("sayad_id"),
                    ch.get("bank_name") or "نامشخص",
                    amount,
                    shamsi_date,
                    ch.get("due_shamsi_date") or shamsi_date,
                    ch.get("notes"),
                    username,
                    now_iso(),
                ),
            )
            cheque_id = int(cur.lastrowid)
            reference = reference or ch.get("cheque_number") or "چک"
        conn.execute(
            """INSERT INTO invoice_payments (
                invoice_type, invoice_id, party_id, payment_method, amount_rial, cheque_id,
                reference_no, shamsi_date, created_by, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (invoice_type, invoice_id, party_id, method, amount, cheque_id, reference, shamsi_date, username, now_iso()),
        )
        total += amount
    return total


def query_product_rows(conn, search: str = "", warehouse_id: Optional[int] = None, include_inactive: bool = False, include_parents: bool = False):
    params: list[Any] = []
    where = []
    if not include_inactive:
        where.append("p.is_active=1")
    if not include_parents:
        where.append("p.is_parent=0")
    if search:
        where.append("(p.name LIKE ? OR p.sku LIKE ? OR p.barcode LIKE ? OR p.brand LIKE ? OR p.vehicle_compatibility LIKE ?)")
        term = f"%{search}%"
        params.extend([term, term, term, term, term])
    where_sql = " AND ".join(where) or "1=1"
    rows = conn.execute(
        f"""SELECT p.*, COALESCE(SUM(CASE WHEN s.warehouse_id=1 THEN s.quantity ELSE 0 END),0) AS store_qty,
            COALESCE(SUM(CASE WHEN s.warehouse_id=2 THEN s.quantity ELSE 0 END),0) AS repair_qty,
            COALESCE(SUM(s.quantity),0) AS total_qty
            FROM products p LEFT JOIN product_warehouse_stocks s ON s.product_id=p.id
            WHERE {where_sql} GROUP BY p.id ORDER BY p.is_parent DESC, p.name COLLATE NOCASE""",
        params,
    ).fetchall()
    out = rows_dict(rows)
    if warehouse_id:
        for item in out:
            item["warehouse_qty"] = item["store_qty"] if warehouse_id == 1 else item["repair_qty"]
    return out


def calculate_customer_tier(party: dict[str, Any]) -> str:
    tier = (party.get("default_price_tier") or "").upper()
    if tier in {"RETAIL", "WHOLESALE", "COLLEAGUE"}:
        return tier
    customer_type = (party.get("customer_type") or "INDIVIDUAL").upper()
    return "COLLEAGUE" if customer_type == "COLLEAGUE" else "WHOLESALE" if customer_type == "CORPORATE" else "RETAIL"


def get_product(conn, product_id: int):
    row = conn.execute("SELECT * FROM products WHERE id=? AND is_active=1", (product_id,)).fetchone()
    if not row:
        raise HTTPException(404, "کالای فعال با این شناسه پیدا نشد.")
    if row["is_parent"]:
        raise HTTPException(422, "محصول والد قابل فروش نیست؛ یکی از متغیرهای آن را انتخاب کنید.")
    return dict(row)


def create_stock_adjustment(conn, product_id: int, warehouse_id: int, new_qty: int, reason: str, notes: str, user: dict[str, Any]):
    product = get_product(conn, product_id)
    old_qty = stock_qty(conn, product_id, warehouse_id)
    diff = int(new_qty) - old_qty
    if diff == 0:
        raise HTTPException(422, "موجودی جدید با موجودی فعلی برابر است.")
    number = next_number(conn, "ADJUSTMENT")
    date = get_shamsi_date()
    cost = int(product["purchase_price_rial"] or 0)
    if diff > 0:
        set_stock(conn, product_id, warehouse_id, int(new_qty))
        create_batch(conn, product_id, warehouse_id, diff, cost, "ADJUSTMENT_IN", date, notes or reason)
    else:
        breakdown, _, _, _ = consume_fifo(conn, product_id, warehouse_id, -diff, cost)
        # consume_fifo's current stock is old-abs(diff), exactly the requested new value.
    add_movement(conn, product_id, warehouse_id, date, "ADJUSTMENT", number, diff, int(new_qty), cost, reason, user["username"])
    cur = conn.execute(
        """INSERT INTO stock_adjustments (
            adjustment_number, warehouse_id, product_id, shamsi_date, old_qty, new_qty, diff_qty,
            unit_cost_rial, reason, notes, created_by, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (number, warehouse_id, product_id, date, old_qty, new_qty, diff, cost, reason, notes, user["username"], now_iso()),
    )
    log_audit(conn, user.get("id"), user["username"], user["role"], "STOCK_ADJUSTMENT", "STOCK", cur.lastrowid, reason, {"old_qty": old_qty}, {"new_qty": new_qty, "warehouse_id": warehouse_id})
    return {"adjustment_number": number, "old_qty": old_qty, "new_qty": new_qty, "diff_qty": diff}


def build_sale_detail(conn, sale_id: int):
    invoice = conn.execute(
        """SELECT s.*, p.name AS customer_name, p.phone AS customer_phone, w.name AS warehouse_name,
            u.full_name AS created_by_name FROM sales_invoices s
            JOIN parties p ON p.id=s.customer_id JOIN warehouses w ON w.id=s.warehouse_id
            LEFT JOIN users u ON u.username=s.created_by WHERE s.id=?""",
        (sale_id,),
    ).fetchone()
    if not invoice:
        raise HTTPException(404, "فاکتور فروش پیدا نشد.")
    result = dict(invoice)
    result["items"] = rows_dict(
        conn.execute("SELECT * FROM sales_invoice_items WHERE sales_invoice_id=? ORDER BY id", (sale_id,)).fetchall()
    )
    for item in result["items"]:
        item["batch_breakdown"] = json.loads(item.pop("batch_breakdown_json") or "[]")
    result["payments"] = rows_dict(
        conn.execute("SELECT * FROM invoice_payments WHERE invoice_type='SALE' AND invoice_id=? ORDER BY id", (sale_id,)).fetchall()
    )
    result["returns"] = rows_dict(
        conn.execute("SELECT * FROM sales_returns WHERE sales_invoice_id=? ORDER BY id", (sale_id,)).fetchall()
    )
    return result


def auto_backup_exists_today(conn) -> bool:
    date_key = datetime.now(ZoneInfo("Asia/Tehran")).strftime("%Y%m%d")
    prefix = f"alborzpart_auto_daily_{date_key}_%"
    return bool(conn.execute("SELECT id FROM backups WHERE filename LIKE ? LIMIT 1", (prefix,)).fetchone())


def create_backup(backup_type: str = "AUTO_DAILY", username: str = "system") -> dict[str, Any]:
    stamp = datetime.now(ZoneInfo("Asia/Tehran")).strftime("%Y%m%d_%H%M%S")
    filename = f"alborzpart_{backup_type.lower()}_{stamp}.zip"
    destination = os.path.join(BACKUP_DIR, filename)
    tmp_db = os.path.join(BACKUP_DIR, f".snapshot_{stamp}.sqlite")
    src = sqlite3.connect(DB_PATH)
    dst = sqlite3.connect(tmp_db)
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()
    manifest = {
        "product": "Alborz Part ERP",
        "created_at": datetime.now(ZoneInfo("Asia/Tehran")).isoformat(),
        "shamsi_date": get_shamsi_date(),
        "database_file": "erp.sqlite",
        "uploaded_files_included": True,
    }
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.write(tmp_db, "erp.sqlite")
        archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
        if os.path.isdir(UPLOAD_DIR):
            for path in Path(UPLOAD_DIR).rglob("*"):
                if path.is_file():
                    archive.write(str(path), f"uploads/{path.relative_to(UPLOAD_DIR).as_posix()}")
    os.remove(tmp_db)
    # If an operator configured a real secondary volume, make an extra copy there.
    try:
        with db_read() as conn:
            secondary_raw = get_setting(conn, "backup_secondary_path", "").strip()
        if secondary_raw and not (os.name != "nt" and len(secondary_raw) > 2 and secondary_raw[1] == ":"):
            secondary = os.path.expandvars(os.path.expanduser(secondary_raw))
            if not os.path.isabs(secondary):
                secondary = os.path.join(BASE_DIR, secondary)
            os.makedirs(secondary, exist_ok=True)
            shutil.copy2(destination, os.path.join(secondary, filename))
    except Exception as exc:
        print(f"Secondary backup copy skipped: {exc}")
    size = os.path.getsize(destination)
    with db_transaction() as conn:
        cur = conn.execute(
            "INSERT INTO backups (filename,file_path,size_bytes,backup_type,shamsi_datetime,created_by,created_at) VALUES (?,?,?,?,?,?,?)",
            (filename, destination, size, backup_type, get_shamsi_now(), username, now_iso()),
        )
        backup_id = int(cur.lastrowid)
    return {"id": backup_id, "filename": filename, "file_path": destination, "size_bytes": size, "backup_type": backup_type}


def test_backup_file(backup_path: str):
    if not os.path.isfile(backup_path):
        return False, "فایل پشتیبان وجود ندارد."
    try:
        with zipfile.ZipFile(backup_path, "r") as archive:
            names = archive.namelist()
            if "erp.sqlite" not in names:
                return False, "نسخه پشتیبان پایگاه داده را ندارد."
            with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as temp:
                temp.write(archive.read("erp.sqlite"))
                temp_path = temp.name
        test_conn = sqlite3.connect(temp_path)
        result = test_conn.execute("PRAGMA integrity_check").fetchone()[0]
        table_count = test_conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
        test_conn.close()
        os.remove(temp_path)
        if result != "ok" or table_count < 10:
            return False, f"Integrity check failed: {result}; tables={table_count}"
        return True, f"آزمون بازیابی آزمایشی موفق بود؛ {table_count} جدول و ساختار SQLite سالم است."
    except Exception as exc:
        return False, f"خطای آزمون بازیابی: {exc}"


def create_and_verify_auto_backup():
    backup = create_backup("AUTO_DAILY", "system")
    ok, detail = test_backup_file(backup["file_path"])
    with db_transaction() as conn:
        conn.execute(
            "UPDATE backups SET last_restore_tested_at=?,restore_test_status=? WHERE id=?",
            (get_shamsi_now(), "PASSED" if ok else "FAILED: " + detail, backup["id"]),
        )
    return backup, ok, detail


async def daily_backup_scheduler():
    while True:
        now = datetime.now(ZoneInfo("Asia/Tehran"))
        next_run = now.replace(hour=2, minute=0, second=0, microsecond=0)
        if next_run <= now:
            next_run += timedelta(days=1)
        await asyncio.sleep(max(1, (next_run - now).total_seconds()))
        try:
            with db_read() as conn:
                enabled = get_setting(conn, "auto_daily_backup", "1") == "1"
                exists = auto_backup_exists_today(conn)
            if enabled and not exists:
                await asyncio.to_thread(create_and_verify_auto_backup)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            print(f"Daily backup failed: {exc}")


@app.on_event("startup")
async def startup_event():
    init_db()
    ensure_sample_pdfs()
    # Rebase stored paths when a project folder has been moved or unpacked on another host.
    with db_transaction() as conn:
        for row in conn.execute("SELECT id,filename,file_path FROM backups").fetchall():
            candidate = os.path.join(BACKUP_DIR, os.path.basename(row["filename"] or row["file_path"] or ""))
            if os.path.isfile(candidate) and os.path.realpath(candidate) != os.path.realpath(row["file_path"] or ""):
                conn.execute("UPDATE backups SET file_path=? WHERE id=?", (candidate, row["id"]))
        for row in conn.execute("SELECT id,pdf_storage_path FROM purchase_invoices WHERE pdf_storage_path IS NOT NULL").fetchall():
            candidate = os.path.join(UPLOAD_DIR, os.path.basename(row["pdf_storage_path"]))
            if os.path.isfile(candidate) and os.path.realpath(candidate) != os.path.realpath(row["pdf_storage_path"]):
                conn.execute("UPDATE purchase_invoices SET pdf_storage_path=? WHERE id=?", (candidate, row["id"]))
        conn.execute("UPDATE system_settings SET value='backups' WHERE key='backup_local_path' AND value LIKE '/home/%'")
    # Create today's verified backup on startup and continue checking once per Tehran day.
    with db_read() as conn:
        enabled = get_setting(conn, "auto_daily_backup", "1") == "1"
        exists = auto_backup_exists_today(conn)
    if enabled and not exists:
        await asyncio.to_thread(create_and_verify_auto_backup)
    global BACKUP_TASK
    if BACKUP_TASK is None or BACKUP_TASK.done():
        BACKUP_TASK = asyncio.create_task(daily_backup_scheduler(), name="daily-backup-scheduler")


@app.on_event("shutdown")
async def shutdown_event():
    global BACKUP_TASK
    if BACKUP_TASK and not BACKUP_TASK.done():
        BACKUP_TASK.cancel()
        try:
            await BACKUP_TASK
        except asyncio.CancelledError:
            pass
        BACKUP_TASK = None


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def home():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if not os.path.exists(index_path):
        return HTMLResponse("<h1>در حال آماده‌سازی اپلیکیشن…</h1>", status_code=200)
    return FileResponse(index_path)


@app.get("/health", include_in_schema=False)
async def health():
    with db_read() as conn:
        conn.execute("SELECT 1").fetchone()
    return {"status": "ok", "application": "Alborz Part ERP", "version": "1.0.0"}


@app.post("/api/auth/login")
async def login(request: Request):
    body = await request.json()
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    ip = request.client.host if request.client else "local"
    now = datetime.now().timestamp()
    recent = [stamp for stamp in LOGIN_ATTEMPTS.get(ip, []) if now - stamp < 300]
    if len(recent) >= 8:
        raise HTTPException(429, "تعداد تلاش ناموفق زیاد است. چند دقیقه دیگر دوباره امتحان کنید.")
    with db_transaction() as conn:
        row = conn.execute("SELECT * FROM users WHERE username=? AND is_active=1", (username,)).fetchone()
        if not row:
            recent.append(now)
            LOGIN_ATTEMPTS[ip] = recent
            raise HTTPException(401, "نام کاربری یا رمز عبور صحیح نیست.")
        valid, upgraded = verify_password(row["password_hash"], password)
        if not valid:
            recent.append(now)
            LOGIN_ATTEMPTS[ip] = recent
            raise HTTPException(401, "نام کاربری یا رمز عبور صحیح نیست.")
        if upgraded:
            conn.execute("UPDATE users SET password_hash=? WHERE id=?", (upgraded, row["id"]))
        user = {
            "id": int(row["id"]),
            "username": row["username"],
            "full_name": row["full_name"],
            "role": row["role"],
            "role_label": row["role_label"],
            "preferred_currency": row["preferred_currency"],
        }
        token = secrets.token_urlsafe(32)
        SESSIONS[token] = user
        LOGIN_ATTEMPTS.pop(ip, None)
        log_audit(conn, user["id"], username, user["role"], "LOGIN", "USER", user["id"], "ورود به سامانه", None, {"ip": ip})
    return {"token": token, "user": user, "expires_in": "تا زمان توقف سرویس"}


@app.post("/api/auth/logout")
async def logout(user: dict = Depends(current_user), authorization: Optional[str] = Header(None)):
    token = authorization.split(" ", 1)[1].strip() if authorization else ""
    SESSIONS.pop(token, None)
    return {"ok": True}


@app.get("/api/bootstrap")
async def bootstrap(user: dict = Depends(current_user)):
    with db_read() as conn:
        settings = {r["key"]: r["value"] for r in conn.execute("SELECT key,value FROM system_settings").fetchall()}
        warehouses = rows_dict(conn.execute("SELECT * FROM warehouses ORDER BY id").fetchall())
        templates = rows_dict(conn.execute("SELECT id,name,paper_size,is_default,print_currency FROM print_templates ORDER BY id").fetchall())
        return {"user": user, "settings": settings, "warehouses": warehouses, "templates": templates, "today": get_shamsi_date(), "api_docs": "/api-docs"}


@app.get("/api/dashboard")
async def dashboard(user: dict = Depends(current_user)):
    with db_read() as conn:
        today = get_shamsi_date()
        month_prefix = today[:7] + "%"
        sales_today = conn.execute("SELECT COALESCE(SUM(total_rial),0),COALESCE(SUM(real_profit_rial),0),COUNT(*) FROM sales_invoices WHERE shamsi_date=? AND status!='RETURNED_FULL'", (today,)).fetchone()
        sales_month = conn.execute("SELECT COALESCE(SUM(total_rial),0),COALESCE(SUM(real_profit_rial),0),COUNT(*) FROM sales_invoices WHERE shamsi_date LIKE ? AND status!='RETURNED_FULL'", (month_prefix,)).fetchone()
        purchases_today = conn.execute("SELECT COALESCE(SUM(total_rial),0),COUNT(*) FROM purchase_invoices WHERE shamsi_date=?", (today,)).fetchone()
        low_stock = conn.execute(
            """SELECT p.id,p.name,p.barcode,p.min_stock_alert,COALESCE(SUM(CASE WHEN s.warehouse_id=1 THEN s.quantity ELSE 0 END),0) AS store_qty,
            COALESCE(SUM(CASE WHEN s.warehouse_id=2 THEN s.quantity ELSE 0 END),0) AS repair_qty
            FROM products p LEFT JOIN product_warehouse_stocks s ON s.product_id=p.id
            WHERE p.is_active=1 AND p.is_parent=0 GROUP BY p.id
            HAVING store_qty<=p.min_stock_alert OR store_qty<0 ORDER BY store_qty ASC LIMIT 8"""
        ).fetchall()
        unpaid = conn.execute("SELECT COALESCE(SUM(credit_rial),0),COUNT(*) FROM sales_invoices WHERE credit_rial>0 AND status!='RETURNED_FULL'").fetchone()
        due_cheques = conn.execute("SELECT COUNT(*),COALESCE(SUM(amount_rial),0) FROM cheques WHERE status='PENDING' AND (is_overdue=1 OR due_shamsi_date<=?)", (today,)).fetchone()
        stock_value = conn.execute(
            "SELECT COALESCE(SUM(CASE WHEN remaining_qty>0 THEN remaining_qty*unit_cost_rial ELSE 0 END),0) FROM inventory_batches"
        ).fetchone()[0]
        recent_sales = rows_dict(conn.execute(
            "SELECT s.id,s.invoice_number,s.shamsi_date,s.total_rial,s.real_profit_rial,s.credit_rial,p.name AS customer_name,s.created_by FROM sales_invoices s JOIN parties p ON p.id=s.customer_id ORDER BY s.id DESC LIMIT 6"
        ).fetchall())
        recent_purchases = rows_dict(conn.execute(
            "SELECT i.id,i.invoice_number,i.shamsi_date,i.total_rial,i.remaining_rial,p.name AS supplier_name FROM purchase_invoices i JOIN parties p ON p.id=i.supplier_id ORDER BY i.id DESC LIMIT 5"
        ).fetchall())
        sales_daily = rows_dict(conn.execute(
            "SELECT shamsi_date, SUM(total_rial) AS amount, SUM(real_profit_rial) AS profit FROM sales_invoices WHERE shamsi_date LIKE ? GROUP BY shamsi_date ORDER BY shamsi_date DESC LIMIT 7",
            (month_prefix,),
        ).fetchall())
        negative_count = conn.execute("SELECT COUNT(*) FROM product_warehouse_stocks WHERE warehouse_id=1 AND quantity<0").fetchone()[0]
        return {
            "today": today,
            "sales_today_rial": int(sales_today[0]),
            "profit_today_rial": int(sales_today[1]),
            "sales_today_count": int(sales_today[2]),
            "sales_month_rial": int(sales_month[0]),
            "profit_month_rial": int(sales_month[1]),
            "sales_month_count": int(sales_month[2]),
            "purchases_today_rial": int(purchases_today[0]),
            "purchases_today_count": int(purchases_today[1]),
            "unpaid_rial": int(unpaid[0]),
            "unpaid_count": int(unpaid[1]),
            "due_cheques_count": int(due_cheques[0]),
            "due_cheques_rial": int(due_cheques[1]),
            "stock_value_rial": int(stock_value or 0),
            "negative_stock_products": int(negative_count),
            "low_stock": rows_dict(low_stock),
            "recent_sales": recent_sales,
            "recent_purchases": recent_purchases,
            "daily_chart": sales_daily,
        }


@app.get("/api/products")
async def list_products(
    q: str = "",
    include_inactive: bool = False,
    include_parents: bool = False,
    warehouse_id: Optional[int] = None,
    user: dict = Depends(current_user),
):
    with db_read() as conn:
        products = query_product_rows(conn, q, warehouse_id, include_inactive, include_parents)
        return {"items": products, "count": len(products)}


@app.post("/api/products")
async def create_product(request: Request, user: dict = Depends(current_user)):
    ensure_user(user, "admin")
    body = await request.json()
    name = str(body.get("name", "")).strip()
    if not name:
        raise HTTPException(422, "نام کالا الزامی است.")
    is_parent = bool(body.get("is_parent", False))
    barcode = str(body.get("barcode") or "").strip() or None
    initial_qty = max(0, safe_int(body.get("initial_qty")))
    warehouse_id = safe_int(body.get("warehouse_id"), 1) or 1
    with db_transaction() as conn:
        if barcode and conn.execute("SELECT id FROM products WHERE barcode=?", (barcode,)).fetchone():
            raise HTTPException(409, "این بارکد قبلاً برای کالای دیگری ثبت شده است.")
        if not barcode and not is_parent:
            serial = safe_int(get_setting(conn, "barcode_seq_counter", "1020")) + 1
            set_setting(conn, "barcode_seq_counter", str(serial), user["username"])
            barcode = f"AP-1405-{serial:04d}"
            barcode_type = "CODE128"
        else:
            barcode_type = str(body.get("barcode_type") or ("EAN13" if barcode else "CODE128")).upper()
        purchase = max(0, safe_int(body.get("purchase_price_rial")))
        retail = max(0, safe_int(body.get("sale_price_retail_rial")))
        wholesale = max(0, safe_int(body.get("sale_price_wholesale_rial"), retail))
        colleague = max(0, safe_int(body.get("sale_price_colleague_rial"), retail))
        minimum = max(0, safe_int(body.get("min_sale_price_rial")))
        if not is_parent and not (retail or wholesale or colleague):
            raise HTTPException(422, "حداقل یکی از قیمت‌های فروش باید بیشتر از صفر باشد.")
        cur = conn.execute(
            """INSERT INTO products (
                parent_id,is_parent,variant_label,name,sku,barcode,barcode_type,purchase_price_rial,
                sale_price_retail_rial,sale_price_wholesale_rial,sale_price_colleague_rial,min_sale_price_rial,
                suggested_profit_percent,brand,vehicle_compatibility,category,unit,shelf_location,min_stock_alert,
                description,is_active,created_by,updated_by,created_at,updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?,?)""",
            (
                safe_int(body.get("parent_id")) or None,
                int(is_parent),
                body.get("variant_label"),
                name,
                body.get("sku") or None,
                barcode,
                barcode_type,
                purchase,
                retail,
                wholesale,
                colleague,
                minimum,
                float(body.get("suggested_profit_percent") or 25),
                body.get("brand") or None,
                body.get("vehicle_compatibility") or None,
                body.get("category") or None,
                body.get("unit") or "عدد",
                body.get("shelf_location") or None,
                safe_int(body.get("min_stock_alert"), 5),
                body.get("description") or None,
                user["username"],
                user["username"],
                now_iso(),
                now_iso(),
            ),
        )
        product_id = int(cur.lastrowid)
        if initial_qty and not is_parent:
            set_stock(conn, product_id, warehouse_id, initial_qty)
            create_batch(conn, product_id, warehouse_id, initial_qty, purchase, "INITIAL_STOCK", get_shamsi_date(), "موجودی اولیه")
            add_movement(conn, product_id, warehouse_id, get_shamsi_date(), "INITIAL", "OPENING", initial_qty, initial_qty, purchase, "ثبت موجودی اولیه کالا", user["username"])
        log_audit(conn, user["id"], user["username"], user["role"], "CREATE", "PRODUCT", product_id, f"ثبت کالای {name}", None, body)
        return {"id": product_id, "name": name, "barcode": barcode, "barcode_type": barcode_type, "initial_qty": initial_qty}


@app.put("/api/products/{product_id}")
async def update_product(product_id: int, request: Request, user: dict = Depends(current_user)):
    body = await request.json()
    with db_transaction() as conn:
        row = conn.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
        if not row:
            raise HTTPException(404, "کالا پیدا نشد.")
        old = dict(row)
        price_keys = {"purchase_price_rial", "sale_price_retail_rial", "sale_price_wholesale_rial", "sale_price_colleague_rial", "min_sale_price_rial"}
        if any(k in body for k in price_keys):
            ensure_user(user, "admin")
        fields = {
            "name": "name", "sku": "sku", "barcode": "barcode", "barcode_type": "barcode_type",
            "purchase_price_rial": "purchase_price_rial", "sale_price_retail_rial": "sale_price_retail_rial",
            "sale_price_wholesale_rial": "sale_price_wholesale_rial", "sale_price_colleague_rial": "sale_price_colleague_rial",
            "min_sale_price_rial": "min_sale_price_rial", "suggested_profit_percent": "suggested_profit_percent",
            "brand": "brand", "vehicle_compatibility": "vehicle_compatibility", "category": "category", "unit": "unit",
            "shelf_location": "shelf_location", "min_stock_alert": "min_stock_alert", "description": "description",
            "variant_label": "variant_label", "parent_id": "parent_id",
        }
        updates: dict[str, Any] = {}
        for body_key, column in fields.items():
            if body_key in body:
                value = body[body_key]
                if body_key in {"purchase_price_rial", "sale_price_retail_rial", "sale_price_wholesale_rial", "sale_price_colleague_rial", "min_sale_price_rial", "min_stock_alert", "parent_id"}:
                    value = safe_int(value)
                if body_key in {"barcode", "sku", "brand", "vehicle_compatibility", "category", "shelf_location", "description", "variant_label"}:
                    value = str(value or "").strip() or None
                updates[column] = value
        if "barcode" in updates and updates["barcode"]:
            dupe = conn.execute("SELECT id FROM products WHERE barcode=? AND id<>?", (updates["barcode"], product_id)).fetchone()
            if dupe:
                raise HTTPException(409, "این بارکد برای کالای دیگری ثبت شده است.")
        if not updates:
            return {"id": product_id, "updated": False}
        if any(k in body for k in price_keys):
            newvals = {k: safe_int(body.get(k, old[k] or 0)) for k in price_keys}
            if any(newvals[k] != int(old[k] or 0) for k in price_keys):
                conn.execute(
                    """INSERT INTO product_price_history (
                        product_id,old_purchase_rial,new_purchase_rial,old_retail_rial,new_retail_rial,
                        old_wholesale_rial,new_wholesale_rial,old_colleague_rial,new_colleague_rial,
                        changed_by,reason,shamsi_datetime,created_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        product_id, old["purchase_price_rial"], newvals["purchase_price_rial"],
                        old["sale_price_retail_rial"], newvals["sale_price_retail_rial"],
                        old["sale_price_wholesale_rial"], newvals["sale_price_wholesale_rial"],
                        old["sale_price_colleague_rial"], newvals["sale_price_colleague_rial"],
                        user["username"], body.get("price_change_reason") or "ویرایش قیمت کالا", get_shamsi_now(), now_iso(),
                    ),
                )
        updates["updated_by"] = user["username"]
        updates["updated_at"] = now_iso()
        sql = ",".join(f"{key}=?" for key in updates)
        conn.execute(f"UPDATE products SET {sql} WHERE id=?", (*updates.values(), product_id))
        log_audit(conn, user["id"], user["username"], user["role"], "UPDATE", "PRODUCT", product_id, f"ویرایش کالای {old['name']}", old, updates)
        return {"id": product_id, "updated": True}


@app.delete("/api/products/{product_id}")
async def deactivate_product(product_id: int, user: dict = Depends(current_user)):
    ensure_user(user, "admin")
    with db_transaction() as conn:
        row = conn.execute("SELECT name,is_active FROM products WHERE id=?", (product_id,)).fetchone()
        if not row:
            raise HTTPException(404, "کالا پیدا نشد.")
        conn.execute("UPDATE products SET is_active=0,updated_by=?,updated_at=? WHERE id=?", (user["username"], now_iso(), product_id))
        log_audit(conn, user["id"], user["username"], user["role"], "SOFT_DELETE", "PRODUCT", product_id, f"غیرفعال‌سازی کالای {row['name']}", {"is_active": row["is_active"]}, {"is_active": 0})
    return {"ok": True}


@app.get("/api/products/{product_id}/price-history")
async def product_price_history(product_id: int, user: dict = Depends(current_user)):
    with db_read() as conn:
        rows = conn.execute("SELECT * FROM product_price_history WHERE product_id=? ORDER BY id DESC", (product_id,)).fetchall()
        return {"items": rows_dict(rows)}


@app.get("/api/products/{product_id}/label", response_class=HTMLResponse)
async def barcode_label(product_id: int, user: dict = Depends(current_user)):
    with db_read() as conn:
        product = conn.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
        if not product:
            raise HTTPException(404, "کالا پیدا نشد.")
        code = product["barcode"] or ""
        html = f"""<!doctype html><html lang='fa' dir='rtl'><meta charset='utf-8'><title>برچسب کالا</title>
        <style>@page{{size:50mm 30mm;margin:2mm}}body{{font-family:Tahoma,Arial;text-align:center;margin:0;padding:4px;color:#111}}b{{font-size:11px}}.code{{font:16px monospace;letter-spacing:2px;margin-top:7px}}small{{font-size:9px}}</style>
        <b>{product['name']}</b><div class='code'>▌▌ {code} ▌▌</div><small>{product['sku'] or ''} · قیمت {int(product['sale_price_retail_rial'])//10:,} تومان</small><script>window.onload=()=>window.print()</script></html>"""
        return HTMLResponse(html)


@app.get("/api/parties")
async def list_parties(q: str = "", role: str = "", user: dict = Depends(current_user)):
    with db_read() as conn:
        sql = """SELECT p.*,COALESCE(SUM(l.debit_rial),0)-COALESCE(SUM(l.credit_rial),0) AS balance_rial,
                COUNT(l.id) AS ledger_count FROM parties p LEFT JOIN party_ledger_entries l ON l.party_id=p.id
                WHERE p.is_active=1"""
        params: list[Any] = []
        if q:
            sql += " AND (p.name LIKE ? OR p.phone LIKE ? OR p.national_id_or_economic_code LIKE ?)"
            params.extend([f"%{q}%"] * 3)
        if role:
            sql += " AND p.party_role LIKE ?"
            params.append(f"%{role.upper()}%")
        sql += " GROUP BY p.id ORDER BY p.is_system DESC,p.name COLLATE NOCASE"
        return {"items": rows_dict(conn.execute(sql, params).fetchall())}


@app.post("/api/parties")
async def create_party(request: Request, user: dict = Depends(current_user)):
    body = await request.json()
    name = str(body.get("name", "")).strip()
    if not name:
        raise HTTPException(422, "نام شخص/شرکت الزامی است.")
    with db_transaction() as conn:
        cur = conn.execute(
            """INSERT INTO parties (party_role,customer_type,name,phone,national_id_or_economic_code,address,
                credit_limit_rial,default_price_tier,notes,is_system,is_active,created_by,updated_by,created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,0,1,?,?,?)""",
            (
                body.get("party_role", "CUSTOMER").upper(),
                body.get("customer_type", "INDIVIDUAL").upper(),
                name,
                body.get("phone"),
                body.get("national_id_or_economic_code"),
                body.get("address"),
                max(0, safe_int(body.get("credit_limit_rial"), 500000000)),
                body.get("default_price_tier", "RETAIL").upper(),
                body.get("notes"),
                user["username"],
                user["username"],
                now_iso(),
            ),
        )
        party_id = int(cur.lastrowid)
        log_audit(conn, user["id"], user["username"], user["role"], "CREATE", "PARTY", party_id, f"ثبت شخص {name}", None, body)
        return {"id": party_id, "name": name}


@app.put("/api/parties/{party_id}")
async def update_party(party_id: int, request: Request, user: dict = Depends(current_user)):
    body = await request.json()
    allowed = {"name", "phone", "address", "customer_type", "party_role", "credit_limit_rial", "default_price_tier", "national_id_or_economic_code", "notes"}
    updates = {k: body[k] for k in allowed if k in body}
    if not updates:
        return {"updated": False}
    with db_transaction() as conn:
        old = conn.execute("SELECT * FROM parties WHERE id=?", (party_id,)).fetchone()
        if not old:
            raise HTTPException(404, "طرف حساب پیدا نشد.")
        if old["is_system"]:
            ensure_user(user, "admin")
        if "credit_limit_rial" in updates:
            updates["credit_limit_rial"] = max(0, safe_int(updates["credit_limit_rial"]))
        updates["updated_by"] = user["username"]
        conn.execute(f"UPDATE parties SET {','.join(k+'=?' for k in updates)} WHERE id=?", (*updates.values(), party_id))
        log_audit(conn, user["id"], user["username"], user["role"], "UPDATE", "PARTY", party_id, f"ویرایش طرف حساب {old['name']}", dict(old), updates)
    return {"updated": True}


@app.get("/api/parties/{party_id}/ledger")
async def party_ledger(party_id: int, user: dict = Depends(current_user)):
    with db_read() as conn:
        party = conn.execute("SELECT * FROM parties WHERE id=?", (party_id,)).fetchone()
        if not party:
            raise HTTPException(404, "طرف حساب پیدا نشد.")
        entries = rows_dict(conn.execute("SELECT * FROM party_ledger_entries WHERE party_id=? ORDER BY id DESC LIMIT 300", (party_id,)).fetchall())
        balance = ledger_balance(conn, party_id)
        return {"party": dict(party), "balance_rial": balance, "entries": entries}


@app.post("/api/parties/{party_id}/entries")
async def create_party_ledger_entry(party_id: int, request: Request, user: dict = Depends(current_user)):
    ensure_user(user, "admin")
    body = await request.json()
    amount = safe_int(body.get("amount_rial"))
    if amount <= 0:
        raise HTTPException(422, "مبلغ سند باید بزرگ‌تر از صفر باشد.")
    direction = str(body.get("direction") or "DEBIT").upper()
    if direction not in {"DEBIT", "CREDIT"}:
        raise HTTPException(422, "جهت گردش معتبر نیست.")
    description = str(body.get("description") or "").strip()
    if not description:
        raise HTTPException(422, "شرح سند الزامی است.")
    with db_transaction() as conn:
        party = conn.execute("SELECT * FROM parties WHERE id=? AND is_active=1", (party_id,)).fetchone()
        if not party:
            raise HTTPException(404, "طرف حساب فعال پیدا نشد.")
        insert_party_ledger(
            conn, party_id, app_date(body.get("shamsi_date")), body.get("entry_type") or "MANUAL_ENTRY",
            "MANUAL", None, body.get("reference_number") or "", amount if direction == "DEBIT" else 0,
            amount if direction == "CREDIT" else 0, body.get("payment_method") or "ADJUSTMENT", description, user["username"],
        )
        ledger_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        log_audit(conn, user["id"], user["username"], user["role"], "LEDGER_ENTRY", "PARTY", party_id, description, None, {"direction": direction, "amount_rial": amount})
        return {"id": ledger_id, "balance_rial": ledger_balance(conn, party_id)}


@app.get("/api/sales")
async def list_sales(q: str = "", date: str = "", limit: int = 100, user: dict = Depends(current_user)):
    with db_read() as conn:
        sql = """SELECT s.*,p.name AS customer_name,w.name AS warehouse_name FROM sales_invoices s
                JOIN parties p ON p.id=s.customer_id JOIN warehouses w ON w.id=s.warehouse_id WHERE 1=1"""
        params: list[Any] = []
        if q:
            sql += " AND (s.invoice_number LIKE ? OR p.name LIKE ?)"
            params.extend([f"%{q}%", f"%{q}%"])
        if date:
            sql += " AND s.shamsi_date LIKE ?"
            params.append(f"{date}%")
        sql += " ORDER BY s.id DESC LIMIT ?"
        params.append(min(max(limit, 1), 500))
        return {"items": rows_dict(conn.execute(sql, params).fetchall())}


@app.get("/api/sales/{sale_id}")
async def get_sale(sale_id: int, user: dict = Depends(current_user)):
    with db_read() as conn:
        return build_sale_detail(conn, sale_id)


@app.post("/api/sales")
async def create_sale(request: Request, user: dict = Depends(current_user)):
    body = await request.json()
    items = body.get("items") or []
    if not items:
        raise HTTPException(422, "حداقل یک قلم کالا برای فاکتور فروش لازم است.")
    warehouse_id = safe_int(body.get("warehouse_id"), 1) or 1
    if warehouse_id not in (1, 2):
        raise HTTPException(422, "انبار انتخاب‌شده معتبر نیست.")
    shamsi_date = app_date(body.get("shamsi_date"))
    customer_id = safe_int(body.get("customer_id"), 1) or 1
    invoice_discount = max(0, safe_int(body.get("invoice_discount_rial")))
    payments = body.get("payments") or []
    if not payments and safe_int(body.get("paid_rial")) > 0:
        payments = [{"method": body.get("payment_method", "CASH"), "amount_rial": safe_int(body.get("paid_rial")), "cheque": body.get("cheque")}]
    with db_transaction() as conn:
        customer_row = conn.execute("SELECT * FROM parties WHERE id=? AND is_active=1", (customer_id,)).fetchone()
        if not customer_row:
            raise HTTPException(422, "مشتری انتخاب‌شده فعال نیست.")
        customer = dict(customer_row)
        if customer["party_role"] not in ("CUSTOMER", "BOTH", "REPAIR_SHOP"):
            raise HTTPException(422, "نقش طرف حساب اجازه ثبت فروش به او را نمی‌دهد.")
        tier = calculate_customer_tier(customer)
        prepared = []
        subtotal = 0
        row_discounts = 0
        below_min = False
        has_negative_possible = False
        pending_by_product: dict[int, int] = {}
        for raw in items:
            product = get_product(conn, safe_int(raw.get("product_id")))
            qty = safe_int(raw.get("qty"), 1)
            if qty <= 0:
                raise HTTPException(422, f"تعداد کالای «{product['name']}» باید بیشتر از صفر باشد.")
            price_key = {"RETAIL": "sale_price_retail_rial", "WHOLESALE": "sale_price_wholesale_rial", "COLLEAGUE": "sale_price_colleague_rial"}[tier]
            unit_price = safe_int(raw.get("unit_price_rial"), int(product[price_key] or 0))
            if unit_price < 0:
                raise HTTPException(422, "قیمت فروش نمی‌تواند منفی باشد.")
            discount = max(0, safe_int(raw.get("discount_rial")))
            line_before_disc = qty * unit_price
            if discount > line_before_disc:
                raise HTTPException(422, f"تخفیف از مبلغ ردیف کالای «{product['name']}» بیشتر است.")
            line_after_disc = line_before_disc - discount
            min_price = int(product["min_sale_price_rial"] or 0)
            old_stock = stock_qty(conn, product["id"], warehouse_id) - pending_by_product.get(product["id"], 0)
            if old_stock < qty:
                has_negative_possible = True
            pending_by_product[product["id"]] = pending_by_product.get(product["id"], 0) + qty
            prepared.append({"product": product, "qty": qty, "unit_price": unit_price, "discount": discount, "line_before_disc": line_before_disc, "line_after_disc": line_after_disc, "old_stock": old_stock, "min_price": min_price})
            subtotal += line_before_disc
            row_discounts += discount
        before_invoice_discount = subtotal - row_discounts
        if invoice_discount > before_invoice_discount:
            raise HTTPException(422, "تخفیف کل از مبلغ پس از تخفیف ردیف‌ها بیشتر است.")
        total = before_invoice_discount - invoice_discount
        if total <= 0:
            raise HTTPException(422, "مبلغ نهایی فاکتور باید بیشتر از صفر باشد.")
        remaining_preview_discount = invoice_discount
        for index, line in enumerate(prepared):
            if index == len(prepared) - 1:
                allocation = remaining_preview_discount
            elif before_invoice_discount:
                allocation = min(remaining_preview_discount, int((line["line_after_disc"] * invoice_discount + before_invoice_discount // 2) // before_invoice_discount))
            else:
                allocation = 0
            remaining_preview_discount -= allocation
            line["invoice_discount_allocation"] = allocation
            effective_unit = (line["line_after_disc"] - allocation) / max(1, line["qty"])
            if line["min_price"] and effective_unit < line["min_price"]:
                below_min = True
        allow_negative = get_setting(conn, "allow_negative_stock_sale", "1") == "1"
        if has_negative_possible and not allow_negative:
            raise HTTPException(409, "فروش با موجودی منفی در تنظیمات غیرفعال است؛ موجودی را تأمین یا تنظیمات را با مدیر بررسی کنید.")
        if below_min and not body.get("confirm_below_min_price"):
            raise HTTPException(409, "قیمت یک یا چند ردیف از حداقل مجاز پایین‌تر است؛ برای ادامه تأیید مدیر را ثبت کنید.")
        real_paid = sum(max(0, safe_int(p.get("amount_rial"))) for p in payments if (p.get("method") or p.get("payment_method") or "CASH").upper() != "CREDIT")
        if real_paid > total:
            raise HTTPException(422, "جمع پرداخت‌ها از مبلغ فاکتور بیشتر است.")
        credit = total - real_paid
        if customer.get("customer_type") == "WALK_IN" and credit > 0:
            raise HTTPException(422, "فاکتور نسیه باید به مشتری مشخص متصل باشد؛ مشتری متفرقه فقط فروش تسویه‌شده دارد.")
        if credit > 0:
            projected = ledger_balance(conn, customer_id) + credit
            if customer.get("credit_limit_rial", 0) and projected > int(customer["credit_limit_rial"]):
                raise HTTPException(409, "سقف اعتبار مشتری با این فاکتور رد می‌شود.")
        invoice_number = next_number(conn, "SALE")
        cur = conn.execute(
            """INSERT INTO sales_invoices (
                invoice_number,customer_id,warehouse_id,price_tier_used,shamsi_date,subtotal_rial,row_discount_rial,
                invoice_discount_rial,total_rial,paid_rial,credit_rial,total_cogs_rial,real_profit_rial,
                has_negative_stock_items,has_below_min_price_items,status,template_id,notes,created_by,created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                invoice_number, customer_id, warehouse_id, tier, shamsi_date, subtotal, row_discounts, invoice_discount,
                total, real_paid, credit, 0, 0, 0, int(below_min), "FINALIZED", safe_int(body.get("template_id"), 1),
                body.get("notes"), user["username"], now_iso(),
            ),
        )
        sale_id = int(cur.lastrowid)
        remaining_invoice_disc = invoice_discount
        remaining_basis = before_invoice_discount
        total_cogs = 0
        any_negative = False
        for index, line in enumerate(prepared):
            product = line["product"]
            qty = line["qty"]
            line_basis = line["line_after_disc"]
            allocated_disc = int(line.get("invoice_discount_allocation", 0))
            remaining_invoice_disc -= allocated_disc
            remaining_basis -= line_basis
            revenue = max(0, line_basis - allocated_disc)
            breakdown, line_cogs, stock_before, stock_after = consume_fifo(conn, product["id"], warehouse_id, qty, product["purchase_price_rial"])
            negative = stock_before < qty
            any_negative = any_negative or negative
            profit = revenue - line_cogs
            unit_net = revenue // qty
            conn.execute(
                """INSERT INTO sales_invoice_items (
                    sales_invoice_id,product_id,product_name_snapshot,barcode_snapshot,sku_snapshot,vehicle_snapshot,
                    qty,returned_qty,unit_price_rial,min_allowed_price_rial,discount_rial,invoice_discount_allocated_rial,
                    net_unit_price_rial,line_total_rial,line_cogs_rial,line_profit_rial,stock_before_sale,stock_after_sale,
                    is_negative_stock,is_below_min_price,batch_breakdown_json
                ) VALUES (?,?,?,?,?,?,?,0,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    sale_id, product["id"], product["name"], product["barcode"], product["sku"], product["vehicle_compatibility"],
                    qty, line["unit_price"], line["min_price"], line["discount"], allocated_disc, unit_net,
                    line_basis, line_cogs, profit, stock_before, stock_after, int(negative),
                    int(line["min_price"] > 0 and (line_basis / qty) < line["min_price"]),
                    json.dumps(breakdown, ensure_ascii=False),
                ),
            )
            total_cogs += line_cogs
            add_movement(
                conn, product["id"], warehouse_id, shamsi_date, "SALE", invoice_number, -qty, stock_after,
                product["purchase_price_rial"], "ثبت فاکتور فروش", user["username"],
            )
        profit = total - total_cogs
        conn.execute("UPDATE sales_invoices SET total_cogs_rial=?,real_profit_rial=?,has_negative_stock_items=? WHERE id=?", (total_cogs, profit, int(any_negative), sale_id))
        paid_from_rows = payment_rows(conn, "SALE", sale_id, customer_id, payments, shamsi_date, user["username"])
        if paid_from_rows != real_paid:
            raise HTTPException(422, "جمع پرداخت‌های واردشده معتبر نیست.")
        insert_party_ledger(conn, customer_id, shamsi_date, "SALES_INVOICE", "SALE", sale_id, invoice_number, total, 0, "INVOICE", f"فاکتور فروش {invoice_number}", user["username"])
        for payment in payments:
            amount = max(0, safe_int(payment.get("amount_rial")))
            method = (payment.get("method") or payment.get("payment_method") or "CASH").upper()
            if amount and method != "CREDIT":
                insert_party_ledger(conn, customer_id, shamsi_date, "PAYMENT_RECEIVED", "SALE_PAYMENT", sale_id, invoice_number, 0, amount, method, f"دریافت بابت فاکتور {invoice_number}", user["username"])
        log_audit(conn, user["id"], user["username"], user["role"], "CREATE", "SALES_INVOICE", sale_id, f"ثبت فاکتور فروش {invoice_number}", None, {"total_rial": total, "profit_rial": profit, "customer_id": customer_id})
        return {"id": sale_id, "invoice_number": invoice_number, "total_rial": total, "paid_rial": real_paid, "credit_rial": credit, "total_cogs_rial": total_cogs, "real_profit_rial": profit, "has_negative_stock_items": any_negative, "has_below_min_price_items": below_min}


@app.get("/api/purchases")
async def list_purchases(q: str = "", user: dict = Depends(current_user)):
    with db_read() as conn:
        sql = """SELECT i.*,p.name AS supplier_name FROM purchase_invoices i JOIN parties p ON p.id=i.supplier_id WHERE 1=1"""
        params = []
        if q:
            sql += " AND (i.invoice_number LIKE ? OR i.supplier_invoice_no LIKE ? OR p.name LIKE ?)"
            params.extend([f"%{q}%"] * 3)
        sql += " ORDER BY i.id DESC LIMIT 200"
        return {"items": rows_dict(conn.execute(sql, params).fetchall())}


@app.get("/api/purchases/{purchase_id}")
async def get_purchase(purchase_id: int, user: dict = Depends(current_user)):
    with db_read() as conn:
        invoice = conn.execute(
            "SELECT i.*,p.name AS supplier_name,p.phone AS supplier_phone FROM purchase_invoices i JOIN parties p ON p.id=i.supplier_id WHERE i.id=?",
            (purchase_id,),
        ).fetchone()
        if not invoice:
            raise HTTPException(404, "فاکتور خرید پیدا نشد.")
        result = dict(invoice)
        result["items"] = rows_dict(conn.execute("SELECT * FROM purchase_invoice_items WHERE purchase_invoice_id=? ORDER BY id", (purchase_id,)).fetchall())
        result["payments"] = rows_dict(conn.execute("SELECT * FROM invoice_payments WHERE invoice_type='PURCHASE' AND invoice_id=? ORDER BY id", (purchase_id,)).fetchall())
        return result


@app.post("/api/purchases/ocr/preview")
async def purchase_ocr_preview(
    file: UploadFile = File(...),
    supplier_id: Optional[int] = Query(None),
    user: dict = Depends(current_user),
):
    filename = Path(file.filename or "invoice.pdf").name
    if not filename.lower().endswith(".pdf"):
        raise HTTPException(415, "فعلاً فقط فایل PDF پشتیبانی می‌شود.")
    data = await file.read()
    if not data or len(data) > 20 * 1024 * 1024:
        raise HTTPException(413, "فایل خالی است یا از سقف ۲۰ مگابایت بزرگ‌تر است.")
    upload_ref = secrets.token_hex(16) + ".pdf"
    stored_path = os.path.join(UPLOAD_DIR, upload_ref)
    with open(stored_path, "wb") as out:
        out.write(data)
    with db_read() as conn:
        preview = extract_invoice_from_pdf(conn, stored_path, filename, supplier_id)
    preview["upload_ref"] = upload_ref
    preview["stored_filename"] = filename
    log_conn = get_conn()
    try:
        log_audit(log_conn, user["id"], user["username"], user["role"], "OCR_PREVIEW", "PURCHASE_PDF", upload_ref, f"پیش‌نمایش OCR فایل {filename}", None, {"rows": len(preview["rows"]), "engine": preview["engine_name"]})
        log_conn.commit()
    finally:
        log_conn.close()
    return preview


@app.get("/api/samples/pdf/{filename}")
async def download_sample_pdf(filename: str, user: dict = Depends(current_user)):
    allowed = {"factor_kharid_isaco_1405_01.pdf", "factor_scan_ocr_ezam_1405_02.pdf"}
    if filename not in allowed:
        raise HTTPException(404, "نمونه پیدا نشد.")
    ensure_sample_pdfs()
    return FileResponse(os.path.join(SAMPLES_DIR, filename), filename=filename, media_type="application/pdf")


def resolve_purchase_item(conn, line: dict, user: dict):
    product_id = safe_int(line.get("product_id") or line.get("matched_product_id"))
    if product_id:
        product = conn.execute("SELECT * FROM products WHERE id=? AND is_active=1 AND is_parent=0", (product_id,)).fetchone()
        if not product:
            raise HTTPException(422, "کالای انتخاب‌شده برای ردیف خرید معتبر نیست.")
        return dict(product)
    name = str(line.get("new_product_name") or line.get("supplier_item_name") or "").strip()
    if not name:
        raise HTTPException(422, "نام کالای جدید در ردیف خرید خالی است.")
    cost = max(0, safe_int(line.get("unit_price_rial")))
    barcode = str(line.get("barcode") or "").strip() or None
    if barcode:
        existing = conn.execute("SELECT * FROM products WHERE barcode=? AND is_parent=0", (barcode,)).fetchone()
        if existing:
            return dict(existing)
    serial = safe_int(get_setting(conn, "barcode_seq_counter", "1020")) + 1
    set_setting(conn, "barcode_seq_counter", str(serial), user["username"])
    barcode = barcode or f"AP-1405-{serial:04d}"
    retail = int(cost * 1.25)
    cur = conn.execute(
        """INSERT INTO products (name,sku,barcode,barcode_type,purchase_price_rial,sale_price_retail_rial,
            sale_price_wholesale_rial,sale_price_colleague_rial,min_sale_price_rial,suggested_profit_percent,
            brand,vehicle_compatibility,category,unit,shelf_location,min_stock_alert,description,is_active,
            created_by,updated_by,created_at,updated_at)
            VALUES (?,?,?,'CODE128',?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?,?)""",
        (
            name,
            f"SKU-NEW-{serial:04d}",
            barcode,
            cost,
            retail,
            int(cost * 1.15),
            int(cost * 1.10),
            cost,
            25,
            line.get("brand"),
            line.get("vehicle_compatibility"),
            line.get("category") or "متفرقه",
            line.get("unit") or "عدد",
            line.get("shelf_location"),
            5,
            line.get("description"),
            user["username"],
            user["username"],
            now_iso(),
            now_iso(),
        ),
    )
    return dict(conn.execute("SELECT * FROM products WHERE id=?", (cur.lastrowid,)).fetchone())


@app.post("/api/purchases")
async def create_purchase(request: Request, user: dict = Depends(current_user)):
    body = await request.json()
    raw_items = body.get("items") or []
    if not raw_items:
        raise HTTPException(422, "حداقل یک قلم کالا برای فاکتور خرید لازم است.")
    supplier_id = safe_int(body.get("supplier_id"))
    warehouse_id = safe_int(body.get("warehouse_id"), 1) or 1
    shamsi_date = app_date(body.get("shamsi_date"))
    invoice_discount = max(0, safe_int(body.get("invoice_discount_rial")))
    payments = body.get("payments") or []
    if not payments and safe_int(body.get("paid_rial")) > 0:
        payments = [{"method": body.get("payment_method", "CASH"), "amount_rial": safe_int(body.get("paid_rial")), "cheque": body.get("cheque")}]
    with db_transaction() as conn:
        supplier = conn.execute("SELECT * FROM parties WHERE id=? AND is_active=1", (supplier_id,)).fetchone()
        if not supplier or supplier["party_role"] not in ("SUPPLIER", "BOTH"):
            raise HTTPException(422, "تأمین‌کننده معتبر انتخاب کنید.")
        prepared = []
        subtotal = 0
        row_discounts = 0
        for raw in raw_items:
            product = resolve_purchase_item(conn, raw, user)
            qty = safe_int(raw.get("qty"), 1)
            unit_price = max(0, safe_int(raw.get("unit_price_rial"), product["purchase_price_rial"]))
            discount = max(0, safe_int(raw.get("discount_rial")))
            if qty <= 0 or discount > qty * unit_price:
                raise HTTPException(422, "تعداد یا تخفیف ردیف خرید معتبر نیست.")
            prepared.append({"raw": raw, "product": product, "qty": qty, "unit_price": unit_price, "discount": discount, "basis": qty * unit_price - discount})
            subtotal += qty * unit_price
            row_discounts += discount
        basis_total = subtotal - row_discounts
        if invoice_discount > basis_total:
            raise HTTPException(422, "تخفیف کل از مبلغ فاکتور بیشتر است.")
        total = basis_total - invoice_discount
        if total <= 0:
            raise HTTPException(422, "مبلغ فاکتور خرید باید بیشتر از صفر باشد.")
        real_paid = sum(max(0, safe_int(p.get("amount_rial"))) for p in payments if (p.get("method") or p.get("payment_method") or "CASH").upper() != "CREDIT")
        if real_paid > total:
            raise HTTPException(422, "پرداخت از مبلغ فاکتور خرید بیشتر است.")
        invoice_number = next_number(conn, "PURCHASE")
        upload_ref = str(body.get("upload_ref") or "").strip()
        storage_path = None
        if upload_ref:
            candidate = os.path.realpath(os.path.join(UPLOAD_DIR, os.path.basename(upload_ref)))
            if os.path.commonpath([candidate, os.path.realpath(UPLOAD_DIR)]) == os.path.realpath(UPLOAD_DIR) and os.path.isfile(candidate):
                storage_path = candidate
        cur = conn.execute(
            """INSERT INTO purchase_invoices (
                invoice_number,supplier_invoice_no,supplier_id,warehouse_id,shamsi_date,source_mode,pdf_filename,pdf_storage_path,
                subtotal_rial,discount_rial,total_rial,paid_rial,remaining_rial,payment_method,status,notes,created_by,created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                invoice_number, body.get("supplier_invoice_no"), supplier_id, warehouse_id, shamsi_date,
                "PDF_OCR" if body.get("source_mode") == "PDF_OCR" else "MANUAL", body.get("pdf_filename"), storage_path,
                subtotal, row_discounts + invoice_discount, total, real_paid, total - real_paid,
                body.get("payment_method") or "ON_ACCOUNT", "FINALIZED", body.get("notes"), user["username"], now_iso(),
            ),
        )
        purchase_id = int(cur.lastrowid)
        remaining_discount = invoice_discount
        remaining_basis = basis_total
        for index, line in enumerate(prepared):
            if index == len(prepared) - 1:
                allocation = remaining_discount
            elif basis_total:
                allocation = min(remaining_discount, int((line["basis"] * invoice_discount + basis_total // 2) // basis_total))
            else:
                allocation = 0
            remaining_discount -= allocation
            remaining_basis -= line["basis"]
            effective_cost = max(0, (line["basis"] - allocation) // line["qty"])
            product = line["product"]
            old_prices = {
                "purchase_price_rial": int(product["purchase_price_rial"]),
                "sale_price_retail_rial": int(product["sale_price_retail_rial"]),
            }
            conn.execute(
                "UPDATE products SET purchase_price_rial=?,updated_by=?,updated_at=? WHERE id=?",
                (effective_cost, user["username"], now_iso(), product["id"]),
            )
            batch_id = create_batch(conn, product["id"], warehouse_id, line["qty"], effective_cost, "PURCHASE_INVOICE", shamsi_date, f"خرید {invoice_number}", purchase_id, supplier_id)
            existing_stock = stock_qty(conn, product["id"], warehouse_id)
            new_stock = existing_stock + line["qty"]
            set_stock(conn, product["id"], warehouse_id, new_stock)
            line_total = line["basis"] - allocation
            cur_item = conn.execute(
                """INSERT INTO purchase_invoice_items (
                    purchase_invoice_id,product_id,batch_id,supplier_item_name,product_name_snapshot,barcode_snapshot,
                    qty,returned_qty,unit_price_rial,discount_rial,net_unit_cost_rial,line_total_rial
                ) VALUES (?,?,?,?,?,?,?,0,?,?,?,?)""",
                (
                    purchase_id, product["id"], batch_id, line["raw"].get("supplier_item_name") or product["name"], product["name"],
                    product["barcode"], line["qty"], line["unit_price"], line["discount"] + allocation, effective_cost, line_total,
                ),
            )
            add_movement(conn, product["id"], warehouse_id, shamsi_date, "PURCHASE", invoice_number, line["qty"], new_stock, effective_cost, "ثبت خرید و افزایش موجودی", user["username"])
            alias_name = str(line["raw"].get("supplier_item_name") or "").strip()
            if alias_name and line["raw"].get("save_alias", True):
                conn.execute(
                    """INSERT INTO product_supplier_aliases (product_id,supplier_id,supplier_item_name,supplier_item_code,created_by,created_at)
                    VALUES (?,?,?,?,?,?) ON CONFLICT(supplier_id,supplier_item_name) DO UPDATE SET product_id=excluded.product_id,supplier_item_code=excluded.supplier_item_code""",
                    (product["id"], supplier_id, alias_name, line["raw"].get("supplier_item_code"), user["username"], now_iso()),
                )
            if old_prices["purchase_price_rial"] != effective_cost:
                conn.execute(
                    """INSERT INTO product_price_history (
                        product_id,old_purchase_rial,new_purchase_rial,old_retail_rial,new_retail_rial,
                        old_wholesale_rial,new_wholesale_rial,old_colleague_rial,new_colleague_rial,
                        changed_by,reason,shamsi_datetime,created_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        product["id"], old_prices["purchase_price_rial"], effective_cost,
                        old_prices["sale_price_retail_rial"], old_prices["sale_price_retail_rial"],
                        product["sale_price_wholesale_rial"], product["sale_price_wholesale_rial"],
                        product["sale_price_colleague_rial"], product["sale_price_colleague_rial"],
                        user["username"], f"ورود محموله {invoice_number}", get_shamsi_now(), now_iso(),
                    ),
                )
        paid_sum = payment_rows(conn, "PURCHASE", purchase_id, supplier_id, payments, shamsi_date, user["username"])
        if paid_sum != real_paid:
            raise HTTPException(422, "جمع پرداخت‌های خرید معتبر نیست.")
        insert_party_ledger(conn, supplier_id, shamsi_date, "PURCHASE_INVOICE", "PURCHASE", purchase_id, invoice_number, 0, total, "INVOICE", f"فاکتور خرید {invoice_number}", user["username"])
        for payment in payments:
            amount = max(0, safe_int(payment.get("amount_rial")))
            method = (payment.get("method") or payment.get("payment_method") or "CASH").upper()
            if amount and method != "CREDIT":
                insert_party_ledger(conn, supplier_id, shamsi_date, "PAYMENT_MADE", "PURCHASE_PAYMENT", purchase_id, invoice_number, amount, 0, method, f"پرداخت بابت فاکتور خرید {invoice_number}", user["username"])
        log_audit(conn, user["id"], user["username"], user["role"], "CREATE", "PURCHASE_INVOICE", purchase_id, f"ثبت فاکتور خرید {invoice_number}", None, {"total_rial": total, "supplier_id": supplier_id, "source_mode": body.get("source_mode") or "MANUAL"})
        return {"id": purchase_id, "invoice_number": invoice_number, "total_rial": total, "paid_rial": real_paid, "remaining_rial": total - real_paid}


@app.get("/api/purchases/{purchase_id}/pdf")
async def get_purchase_pdf(purchase_id: int, user: dict = Depends(current_user)):
    with db_read() as conn:
        row = conn.execute("SELECT pdf_storage_path,pdf_filename FROM purchase_invoices WHERE id=?", (purchase_id,)).fetchone()
        if not row or not row["pdf_storage_path"] or not os.path.isfile(row["pdf_storage_path"]):
            raise HTTPException(404, "پیوست PDF برای این فاکتور موجود نیست.")
        return FileResponse(row["pdf_storage_path"], filename=row["pdf_filename"] or "invoice.pdf", media_type="application/pdf")


@app.post("/api/stock/adjustments")
async def stock_adjustment(request: Request, user: dict = Depends(current_user)):
    ensure_user(user, "admin")
    body = await request.json()
    reason = str(body.get("reason") or "").strip()
    if not reason:
        raise HTTPException(422, "علت تعدیل موجودی الزامی است.")
    with db_transaction() as conn:
        return create_stock_adjustment(conn, safe_int(body.get("product_id")), safe_int(body.get("warehouse_id"), 1), safe_int(body.get("new_qty")), reason, body.get("notes") or "", user)


@app.get("/api/inventory/movements")
async def inventory_movements(product_id: Optional[int] = None, warehouse_id: Optional[int] = None, limit: int = 250, user: dict = Depends(current_user)):
    with db_read() as conn:
        sql = """SELECT m.*,p.name AS product_name,w.name AS warehouse_name FROM inventory_movements m
                JOIN products p ON p.id=m.product_id JOIN warehouses w ON w.id=m.warehouse_id WHERE 1=1"""
        params = []
        if product_id:
            sql += " AND m.product_id=?"
            params.append(product_id)
        if warehouse_id:
            sql += " AND m.warehouse_id=?"
            params.append(warehouse_id)
        sql += " ORDER BY m.id DESC LIMIT ?"
        params.append(min(max(limit, 1), 1000))
        return {"items": rows_dict(conn.execute(sql, params).fetchall())}


@app.get("/api/inventory/batches")
async def inventory_batches(product_id: Optional[int] = None, warehouse_id: Optional[int] = None, user: dict = Depends(current_user)):
    with db_read() as conn:
        sql = """SELECT b.*,p.name AS product_name,w.name AS warehouse_name,s.name AS supplier_name FROM inventory_batches b
                JOIN products p ON p.id=b.product_id JOIN warehouses w ON w.id=b.warehouse_id
                LEFT JOIN parties s ON s.id=b.supplier_id WHERE 1=1"""
        params = []
        if product_id:
            sql += " AND b.product_id=?"
            params.append(product_id)
        if warehouse_id:
            sql += " AND b.warehouse_id=?"
            params.append(warehouse_id)
        sql += " ORDER BY b.shamsi_date,b.id"
        return {"items": rows_dict(conn.execute(sql, params).fetchall())}


@app.post("/api/transfers")
async def create_transfer(request: Request, user: dict = Depends(current_user)):
    body = await request.json()
    items = body.get("items") or []
    if not items:
        raise HTTPException(422, "حداقل یک قلم کالا برای انتقال لازم است.")
    from_id = safe_int(body.get("from_warehouse_id"), 1)
    to_id = safe_int(body.get("to_warehouse_id"), 2)
    if from_id == to_id or from_id not in (1, 2) or to_id not in (1, 2):
        raise HTTPException(422, "انبار مبدأ و مقصد باید متفاوت و معتبر باشند.")
    shamsi_date = app_date(body.get("shamsi_date"))
    post_to_repair = bool(body.get("post_to_repair_account", True))
    with db_transaction() as conn:
        number = next_number(conn, "TRANSFER")
        total_value = 0
        transfer_items = []
        for raw in items:
            product = get_product(conn, safe_int(raw.get("product_id")))
            qty = safe_int(raw.get("qty"))
            if qty <= 0:
                raise HTTPException(422, f"تعداد انتقال «{product['name']}» باید بیشتر از صفر باشد.")
            allow_negative = bool(body.get("allow_negative_stock", False))
            before = stock_qty(conn, product["id"], from_id)
            if before < qty and not allow_negative:
                raise HTTPException(409, f"موجودی انبار مبدأ برای «{product['name']}» کافی نیست.")
            breakdown, cost, old, new = consume_fifo(conn, product["id"], from_id, qty, product["purchase_price_rial"])
            target_before = stock_qty(conn, product["id"], to_id)
            set_stock(conn, product["id"], to_id, target_before + qty)
            # Preserve cost layers across warehouses, one receiving batch per source layer.
            for slice_ in breakdown:
                if slice_["qty"] <= 0:
                    continue
                create_batch(
                    conn, product["id"], to_id, slice_["qty"], slice_["unit_cost_rial"], "TRANSFER_IN", shamsi_date,
                    f"انتقال {number} از انبار {from_id}", batch_code=None,
                )
            add_movement(conn, product["id"], from_id, shamsi_date, "TRANSFER_OUT", number, -qty, new, product["purchase_price_rial"], "خروج در سند انتقال داخلی", user["username"])
            add_movement(conn, product["id"], to_id, shamsi_date, "TRANSFER_IN", number, qty, target_before + qty, product["purchase_price_rial"], "ورود در سند انتقال داخلی", user["username"])
            total_value += cost
            transfer_items.append({"product_id": product["id"], "product_name": product["name"], "qty": qty, "cost_rial": cost, "batch_breakdown": breakdown})
        repair_mode = "DEBIT_REPAIR" if to_id == 2 else "CREDIT_REPAIR" if from_id == 2 else "NONE"
        cur = conn.execute(
            """INSERT INTO warehouse_transfers (
                transfer_number,from_warehouse_id,to_warehouse_id,shamsi_date,post_to_repair_account,
                repair_entry_mode,total_value_rial,items_json,notes,created_by,created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (number, from_id, to_id, shamsi_date, int(post_to_repair), repair_mode, total_value, json.dumps(transfer_items, ensure_ascii=False), body.get("notes"), user["username"], now_iso()),
        )
        transfer_id = int(cur.lastrowid)
        if post_to_repair and repair_mode != "NONE":
            repair = conn.execute("SELECT id FROM parties WHERE party_role='REPAIR_SHOP' AND is_system=1 LIMIT 1").fetchone()
            if repair:
                debit = total_value if repair_mode == "DEBIT_REPAIR" else 0
                credit = total_value if repair_mode == "CREDIT_REPAIR" else 0
                insert_party_ledger(conn, repair["id"], shamsi_date, "WAREHOUSE_TRANSFER", "TRANSFER", transfer_id, number, debit, credit, "INTERNAL", f"انتقال {number} بین دو انبار", user["username"])
        log_audit(conn, user["id"], user["username"], user["role"], "WAREHOUSE_TRANSFER", "TRANSFER", transfer_id, f"ثبت سند انتقال {number}", None, {"from": from_id, "to": to_id, "value_rial": total_value})
        return {"id": transfer_id, "transfer_number": number, "total_value_rial": total_value, "items": transfer_items}


@app.get("/api/transfers")
async def list_transfers(user: dict = Depends(current_user)):
    with db_read() as conn:
        return {"items": rows_dict(conn.execute(
            """SELECT t.*,wf.name AS from_warehouse_name,wt.name AS to_warehouse_name FROM warehouse_transfers t
            JOIN warehouses wf ON wf.id=t.from_warehouse_id JOIN warehouses wt ON wt.id=t.to_warehouse_id ORDER BY t.id DESC LIMIT 200"""
        ).fetchall())}


@app.post("/api/sales/{sale_id}/returns")
async def create_sales_return(sale_id: int, request: Request, user: dict = Depends(current_user)):
    body = await request.json()
    requested_items = body.get("items") or []
    if not requested_items:
        raise HTTPException(422, "حداقل یک قلم کالا برای مرجوعی لازم است.")
    refund_method = str(body.get("refund_method") or "ACCOUNT_CREDIT").upper()
    if refund_method not in {"ACCOUNT_CREDIT", "CASH"}:
        raise HTTPException(422, "روش بازپرداخت معتبر نیست.")
    with db_transaction() as conn:
        sale = conn.execute("SELECT * FROM sales_invoices WHERE id=?", (sale_id,)).fetchone()
        if not sale:
            raise HTTPException(404, "فاکتور فروش پیدا نشد.")
        return_no = next_number(conn, "SALE_RETURN")
        returned_lines = []
        total_return = 0
        total_cost = 0
        warehouse_id = int(sale["warehouse_id"])
        shamsi_date = app_date(body.get("shamsi_date"))
        for req in requested_items:
            sale_item_id = safe_int(req.get("sales_invoice_item_id"))
            item = conn.execute("SELECT * FROM sales_invoice_items WHERE id=? AND sales_invoice_id=?", (sale_item_id, sale_id)).fetchone()
            if not item:
                raise HTTPException(422, "ردیف انتخاب‌شده متعلق به این فاکتور نیست.")
            qty = safe_int(req.get("qty"))
            available = int(item["qty"]) - int(item["returned_qty"])
            if qty <= 0 or qty > available:
                raise HTTPException(422, f"تعداد مرجوعی برای «{item['product_name_snapshot']}» معتبر نیست؛ حداکثر {available} عدد.")
            full_line_revenue = max(0, int(item["line_total_rial"]) - int(item["invoice_discount_allocated_rial"] or 0))
            already = int(item["returned_qty"])
            value_before = (full_line_revenue * already + int(item["qty"]) // 2) // int(item["qty"])
            value_after = (full_line_revenue * (already + qty) + int(item["qty"]) // 2) // int(item["qty"])
            return_value = max(0, value_after - value_before)
            sale_slices = json.loads(item["batch_breakdown_json"] or "[]")
            previously_returned_rows = conn.execute("SELECT batch_breakdown_json FROM sales_return_items WHERE sales_invoice_item_id=?", (sale_item_id,)).fetchall()
            already_by_batch: dict[str, int] = {}
            for prev in previously_returned_rows:
                for sl in json.loads(prev["batch_breakdown_json"] or "[]"):
                    code = str(sl.get("batch_code"))
                    already_by_batch[code] = already_by_batch.get(code, 0) + int(sl.get("qty", 0))
            need = qty
            return_slices = []
            cogs_restored = 0
            for sl in sale_slices:
                if need <= 0:
                    break
                code = str(sl.get("batch_code"))
                originally_sold = int(sl.get("qty", 0))
                can_restore = max(0, originally_sold - already_by_batch.get(code, 0))
                take = min(need, can_restore)
                if take <= 0:
                    continue
                unit_cost = int(sl.get("unit_cost_rial", 0))
                batch_id = sl.get("batch_id")
                if batch_id:
                    batch_row = conn.execute("SELECT id FROM inventory_batches WHERE id=?", (batch_id,)).fetchone()
                else:
                    batch_row = None
                if batch_row:
                    conn.execute("UPDATE inventory_batches SET remaining_qty=remaining_qty+? WHERE id=?", (take, batch_id))
                else:
                    create_batch(conn, item["product_id"], warehouse_id, take, unit_cost, "SALES_RETURN", shamsi_date, f"مرجوعی از {sale['invoice_number']}")
                cogs_restored += take * unit_cost
                return_slices.append({"batch_id": batch_id, "batch_code": code, "qty": take, "unit_cost_rial": unit_cost, "total_cost_rial": take * unit_cost})
                need -= take
            if need > 0:
                unit_cost = int(item["line_cogs_rial"] / max(1, item["qty"]))
                create_batch(conn, item["product_id"], warehouse_id, need, unit_cost, "SALES_RETURN", shamsi_date, f"مرجوعی از {sale['invoice_number']}")
                cogs_restored += need * unit_cost
                return_slices.append({"batch_code": "RETURN-RECOVERY", "qty": need, "unit_cost_rial": unit_cost, "total_cost_rial": need * unit_cost})
            old_stock = stock_qty(conn, item["product_id"], warehouse_id)
            set_stock(conn, item["product_id"], warehouse_id, old_stock + qty)
            conn.execute("UPDATE sales_invoice_items SET returned_qty=returned_qty+? WHERE id=?", (qty, sale_item_id))
            return_slices_json = json.dumps(return_slices, ensure_ascii=False)
            returned_lines.append({"sales_invoice_item_id": sale_item_id, "product_id": item["product_id"], "product_name": item["product_name_snapshot"], "qty": qty, "return_value_rial": return_value, "cogs_restored_rial": cogs_restored, "batch_breakdown": return_slices})
            total_return += return_value
            total_cost += cogs_restored
            add_movement(conn, item["product_id"], warehouse_id, shamsi_date, "SALES_RETURN", return_no, qty, old_stock + qty, cogs_restored // max(1, qty), "مرجوعی فروش و بازگشت کالا به موجودی", user["username"])
            conn.execute(
                """INSERT INTO sales_return_items (
                    sales_return_id,sales_invoice_item_id,product_id,qty,unit_sale_price_rial,line_total_rial,
                    unit_cost_rial,total_cost_rial,batch_breakdown_json,created_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (0, sale_item_id, item["product_id"], qty, return_value // qty, return_value, cogs_restored // qty, cogs_restored, return_slices_json, now_iso()),
            )
        profit_impact = total_return - total_cost
        cur = conn.execute(
            """INSERT INTO sales_returns (
                return_number,sales_invoice_id,customer_id,warehouse_id,shamsi_date,total_return_rial,
                total_cogs_restored_rial,profit_impact_rial,refund_method,reason,items_json,created_by,created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (return_no, sale_id, sale["customer_id"], warehouse_id, shamsi_date, total_return, total_cost, profit_impact, refund_method, body.get("reason"), json.dumps(returned_lines, ensure_ascii=False), user["username"], now_iso()),
        )
        return_id = int(cur.lastrowid)
        # Backfill the return id on child records created in this transaction.
        conn.execute("UPDATE sales_return_items SET sales_return_id=? WHERE sales_return_id=0 AND sales_invoice_item_id IN (SELECT id FROM sales_invoice_items WHERE sales_invoice_id=?)", (return_id, sale_id))
        insert_party_ledger(conn, sale["customer_id"], shamsi_date, "SALES_RETURN", "SALE_RETURN", return_id, return_no, 0, total_return, "RETURN", f"مرجوعی از فاکتور {sale['invoice_number']}", user["username"])
        if refund_method == "CASH":
            insert_party_ledger(conn, sale["customer_id"], shamsi_date, "PAYMENT_MADE", "SALE_REFUND", return_id, return_no, total_return, 0, "CASH", f"بازپرداخت نقدی مرجوعی {return_no}", user["username"])
        all_items = conn.execute("SELECT COUNT(*) AS total,SUM(CASE WHEN returned_qty>=qty THEN 1 ELSE 0 END) AS returned FROM sales_invoice_items WHERE sales_invoice_id=?", (sale_id,)).fetchone()
        status = "RETURNED_FULL" if all_items["total"] and all_items["returned"] == all_items["total"] else "RETURNED_PARTIAL"
        conn.execute("UPDATE sales_invoices SET status=? WHERE id=?", (status, sale_id))
        log_audit(conn, user["id"], user["username"], user["role"], "SALES_RETURN", "SALES_RETURN", return_id, f"ثبت مرجوعی {return_no} برای فاکتور {sale['invoice_number']}", None, {"total_return_rial": total_return, "status": status})
        return {"id": return_id, "return_number": return_no, "total_return_rial": total_return, "total_cogs_restored_rial": total_cost, "profit_impact_rial": profit_impact, "status": status, "items": returned_lines}


@app.post("/api/purchases/{purchase_id}/returns")
async def create_purchase_return(purchase_id: int, request: Request, user: dict = Depends(current_user)):
    body = await request.json()
    req_items = body.get("items") or []
    if not req_items:
        raise HTTPException(422, "حداقل یک قلم کالا برای مرجوعی خرید لازم است.")
    with db_transaction() as conn:
        purchase = conn.execute("SELECT * FROM purchase_invoices WHERE id=?", (purchase_id,)).fetchone()
        if not purchase:
            raise HTTPException(404, "فاکتور خرید پیدا نشد.")
        return_no = next_number(conn, "PURCHASE_RETURN")
        total = 0
        returned_lines = []
        shamsi_date = app_date(body.get("shamsi_date"))
        for req in req_items:
            item_id = safe_int(req.get("purchase_invoice_item_id"))
            item = conn.execute("SELECT * FROM purchase_invoice_items WHERE id=? AND purchase_invoice_id=?", (item_id, purchase_id)).fetchone()
            if not item:
                raise HTTPException(422, "ردیف مرجوعی متعلق به این فاکتور خرید نیست.")
            qty = safe_int(req.get("qty"))
            available = int(item["qty"]) - int(item["returned_qty"])
            if qty <= 0 or qty > available:
                raise HTTPException(422, f"تعداد مرجوعی «{item['product_name_snapshot']}» معتبر نیست؛ حداکثر {available} عدد.")
            line_value = qty * int(item["net_unit_cost_rial"])
            batch = conn.execute("SELECT * FROM inventory_batches WHERE id=?", (item["batch_id"],)).fetchone() if item["batch_id"] else None
            current_stock = stock_qty(conn, item["product_id"], purchase["warehouse_id"])
            if current_stock < qty:
                raise HTTPException(409, f"موجودی کافی برای مرجوعی «{item['product_name_snapshot']}» در انبار وجود ندارد.")
            if batch and int(batch["remaining_qty"]) >= qty:
                conn.execute("UPDATE inventory_batches SET remaining_qty=remaining_qty-? WHERE id=?", (qty, batch["id"]))
            else:
                rest = qty
                if batch and int(batch["remaining_qty"]) > 0:
                    take = min(rest, int(batch["remaining_qty"]))
                    conn.execute("UPDATE inventory_batches SET remaining_qty=remaining_qty-? WHERE id=?", (take, batch["id"]))
                    rest -= take
                other_batches = conn.execute("SELECT * FROM inventory_batches WHERE product_id=? AND warehouse_id=? AND remaining_qty>0 ORDER BY shamsi_date,id", (item["product_id"], purchase["warehouse_id"])).fetchall()
                for other in other_batches:
                    if rest <= 0:
                        break
                    take = min(rest, int(other["remaining_qty"]))
                    conn.execute("UPDATE inventory_batches SET remaining_qty=remaining_qty-? WHERE id=?", (take, other["id"]))
                    rest -= take
                if rest > 0:
                    raise HTTPException(409, "لایه‌های موجودی برای مرجوعی با موجودی حسابداری هم‌خوانی ندارد.")
            new_stock = current_stock - qty
            set_stock(conn, item["product_id"], purchase["warehouse_id"], new_stock)
            conn.execute("UPDATE purchase_invoice_items SET returned_qty=returned_qty+? WHERE id=?", (qty, item_id))
            add_movement(conn, item["product_id"], purchase["warehouse_id"], shamsi_date, "PURCHASE_RETURN", return_no, -qty, new_stock, item["net_unit_cost_rial"], "برگشت به تأمین‌کننده", user["username"])
            total += line_value
            returned_lines.append({"purchase_invoice_item_id": item_id, "product_id": item["product_id"], "product_name": item["product_name_snapshot"], "qty": qty, "amount_rial": line_value})
        cur = conn.execute(
            """INSERT INTO purchase_returns (return_number,purchase_invoice_id,supplier_id,warehouse_id,shamsi_date,total_return_rial,reason,items_json,created_by,created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (return_no, purchase_id, purchase["supplier_id"], purchase["warehouse_id"], shamsi_date, total, body.get("reason"), json.dumps(returned_lines, ensure_ascii=False), user["username"], now_iso()),
        )
        return_id = int(cur.lastrowid)
        insert_party_ledger(conn, purchase["supplier_id"], shamsi_date, "PURCHASE_RETURN", "PURCHASE_RETURN", return_id, return_no, total, 0, "RETURN", f"برگشت خرید از {purchase['invoice_number']}", user["username"])
        remaining = conn.execute("SELECT SUM(qty-returned_qty) FROM purchase_invoice_items WHERE purchase_invoice_id=?", (purchase_id,)).fetchone()[0]
        status = "RETURNED_FULL" if not remaining else "RETURNED_PARTIAL"
        conn.execute("UPDATE purchase_invoices SET status=? WHERE id=?", (status, purchase_id))
        log_audit(conn, user["id"], user["username"], user["role"], "PURCHASE_RETURN", "PURCHASE_RETURN", return_id, f"ثبت مرجوعی خرید {return_no}", None, {"amount_rial": total})
        return {"id": return_id, "return_number": return_no, "total_return_rial": total, "items": returned_lines}


@app.get("/api/settlements/outstanding")
async def outstanding_invoices(invoice_type: str = "SALE", user: dict = Depends(current_user)):
    with db_read() as conn:
        invoice_type = invoice_type.upper()
        if invoice_type == "SALE":
            rows = conn.execute("""SELECT s.id,s.invoice_number,s.shamsi_date,s.credit_rial AS remaining_rial,p.name AS party_name,p.id AS party_id
                FROM sales_invoices s JOIN parties p ON p.id=s.customer_id WHERE s.credit_rial>0 AND s.status!='RETURNED_FULL' ORDER BY s.id DESC""").fetchall()
        else:
            rows = conn.execute("""SELECT p.id,p.invoice_number,p.shamsi_date,p.remaining_rial,s.name AS party_name,s.id AS party_id
                FROM purchase_invoices p JOIN parties s ON s.id=p.supplier_id WHERE p.remaining_rial>0 AND p.status!='RETURNED_FULL' ORDER BY p.id DESC""").fetchall()
        return {"items": rows_dict(rows)}


@app.post("/api/settlements")
async def add_settlement(request: Request, user: dict = Depends(current_user)):
    body = await request.json()
    invoice_type = str(body.get("invoice_type") or "SALE").upper()
    invoice_id = safe_int(body.get("invoice_id"))
    amount = safe_int(body.get("amount_rial"))
    method = str(body.get("method") or "CASH").upper()
    if invoice_type not in {"SALE", "PURCHASE"} or amount <= 0:
        raise HTTPException(422, "نوع فاکتور یا مبلغ تسویه معتبر نیست.")
    if method == "CREDIT":
        raise HTTPException(422, "روش تسویه نمی‌تواند نسیه باشد.")
    with db_transaction() as conn:
        if invoice_type == "SALE":
            invoice = conn.execute("SELECT * FROM sales_invoices WHERE id=?", (invoice_id,)).fetchone()
            if not invoice:
                raise HTTPException(404, "فاکتور فروش پیدا نشد.")
            remaining = int(invoice["credit_rial"])
            if amount > remaining:
                raise HTTPException(422, "مبلغ تسویه از مانده فاکتور بیشتر است.")
            party_id = int(invoice["customer_id"])
            conn.execute("UPDATE sales_invoices SET paid_rial=paid_rial+?,credit_rial=credit_rial-? WHERE id=?", (amount, amount, invoice_id))
            entry_type, ref_type, debit, credit = "PAYMENT_RECEIVED", "SALE_PAYMENT", 0, amount
        else:
            invoice = conn.execute("SELECT * FROM purchase_invoices WHERE id=?", (invoice_id,)).fetchone()
            if not invoice:
                raise HTTPException(404, "فاکتور خرید پیدا نشد.")
            remaining = int(invoice["remaining_rial"])
            if amount > remaining:
                raise HTTPException(422, "مبلغ تسویه از مانده فاکتور بیشتر است.")
            party_id = int(invoice["supplier_id"])
            conn.execute("UPDATE purchase_invoices SET paid_rial=paid_rial+?,remaining_rial=remaining_rial-? WHERE id=?", (amount, amount, invoice_id))
            entry_type, ref_type, debit, credit = "PAYMENT_MADE", "PURCHASE_PAYMENT", amount, 0
        pay_total = payment_rows(conn, invoice_type, invoice_id, party_id, [{"method": method, "amount_rial": amount, "cheque": body.get("cheque"), "reference_no": body.get("reference_no")}], app_date(body.get("shamsi_date")), user["username"])
        insert_party_ledger(conn, party_id, app_date(body.get("shamsi_date")), entry_type, ref_type, invoice_id, invoice["invoice_number"], debit, credit, method, f"تسویه بابت {invoice['invoice_number']}", user["username"])
        log_audit(conn, user["id"], user["username"], user["role"], "SETTLEMENT", invoice_type, invoice_id, f"ثبت تسویه {amount} ریال برای {invoice['invoice_number']}", {"remaining_rial": remaining}, {"amount_rial": amount})
        return {"ok": True, "amount_rial": pay_total, "remaining_rial": remaining - amount}


@app.get("/api/cheques")
async def list_cheques(status: str = "", user: dict = Depends(current_user)):
    with db_read() as conn:
        sql = "SELECT c.*,p.name AS party_name FROM cheques c JOIN parties p ON p.id=c.party_id WHERE 1=1"
        params = []
        if status:
            sql += " AND c.status=?"
            params.append(status.upper())
        sql += " ORDER BY CASE WHEN c.status='PENDING' THEN 0 ELSE 1 END,c.due_shamsi_date,c.id DESC"
        return {"items": rows_dict(conn.execute(sql, params).fetchall())}


@app.patch("/api/cheques/{cheque_id}")
async def update_cheque(cheque_id: int, request: Request, user: dict = Depends(current_user)):
    body = await request.json()
    new_status = str(body.get("status") or "").upper()
    if new_status not in {"PENDING", "CLEARED", "BOUNCED", "SPENT"}:
        raise HTTPException(422, "وضعیت چک معتبر نیست.")
    with db_transaction() as conn:
        cheque = conn.execute("SELECT * FROM cheques WHERE id=?", (cheque_id,)).fetchone()
        if not cheque:
            raise HTTPException(404, "چک پیدا نشد.")
        old_status = cheque["status"]
        conn.execute("UPDATE cheques SET status=?,is_overdue=? WHERE id=?", (new_status, int(new_status == "PENDING" and cheque["due_shamsi_date"] <= get_shamsi_date()), cheque_id))
        # A bounced cheque reverses the original settlement entry; clearing only changes its state.
        if new_status == "BOUNCED" and old_status != "BOUNCED":
            invoice_type = "SALE" if cheque["cheque_type"] == "RECEIVED" else "PURCHASE"
            if invoice_type == "SALE":
                conn.execute("UPDATE sales_invoices SET paid_rial=MAX(0,paid_rial-?),credit_rial=credit_rial+? WHERE id=?", (cheque["amount_rial"], cheque["amount_rial"], cheque["invoice_id"]))
                debit, credit, entry = cheque["amount_rial"], 0, "CHEQUE_BOUNCED"
            else:
                conn.execute("UPDATE purchase_invoices SET paid_rial=MAX(0,paid_rial-?),remaining_rial=remaining_rial+? WHERE id=?", (cheque["amount_rial"], cheque["amount_rial"], cheque["invoice_id"]))
                debit, credit, entry = 0, cheque["amount_rial"], "CHEQUE_BOUNCED"
            insert_party_ledger(conn, cheque["party_id"], get_shamsi_date(), entry, "CHEQUE", cheque_id, cheque["cheque_number"], debit, credit, "CHEQUE", f"برگشت چک {cheque['cheque_number']}", user["username"])
        log_audit(conn, user["id"], user["username"], user["role"], "CHEQUE_STATUS", "CHEQUE", cheque_id, f"تغییر وضعیت چک به {new_status}", {"status": old_status}, {"status": new_status})
        return {"id": cheque_id, "status": new_status}


@app.get("/api/reports/summary")
async def report_summary(date_from: str = "", date_to: str = "", user: dict = Depends(current_user)):
    with db_read() as conn:
        where_sale = ["1=1"]
        params: list[Any] = []
        if date_from:
            where_sale.append("shamsi_date>=?")
            params.append(date_from)
        if date_to:
            where_sale.append("shamsi_date<=?")
            params.append(date_to)
        clause = " AND ".join(where_sale)
        sales = conn.execute(
            f"""SELECT COUNT(*) AS invoice_count,COALESCE(SUM(total_rial),0) AS revenue,
                COALESCE(SUM(total_cogs_rial),0) AS cogs,COALESCE(SUM(real_profit_rial),0) AS profit,
                COALESCE(SUM(row_discount_rial+invoice_discount_rial),0) AS discounts,
                COALESCE(SUM(CASE WHEN has_negative_stock_items=1 THEN 1 ELSE 0 END),0) AS negative_invoices
                FROM sales_invoices WHERE {clause}""",
            params,
        ).fetchone()
        returns_clause = " AND ".join(["1=1"] + (["shamsi_date>=?"] if date_from else []) + (["shamsi_date<=?"] if date_to else []))
        return_params = ([date_from] if date_from else []) + ([date_to] if date_to else [])
        returns = conn.execute(f"SELECT COALESCE(SUM(total_return_rial),0),COALESCE(SUM(total_cogs_restored_rial),0),COALESCE(SUM(profit_impact_rial),0) FROM sales_returns WHERE {returns_clause}", return_params).fetchone()
        purchase_where = ["1=1"]
        purchase_params = []
        if date_from:
            purchase_where.append("shamsi_date>=?")
            purchase_params.append(date_from)
        if date_to:
            purchase_where.append("shamsi_date<=?")
            purchase_params.append(date_to)
        purchases = conn.execute(f"SELECT COUNT(*),COALESCE(SUM(total_rial),0),COALESCE(SUM(remaining_rial),0) FROM purchase_invoices WHERE {' AND '.join(purchase_where)}", purchase_params).fetchone()
        by_product = conn.execute(
            f"""SELECT i.product_id,i.product_name_snapshot AS product_name,SUM(i.qty-i.returned_qty) AS qty,
                SUM(i.line_total_rial-i.invoice_discount_allocated_rial) AS revenue,
                SUM(i.line_cogs_rial) AS cogs,
                SUM(i.line_profit_rial) AS profit
                FROM sales_invoice_items i JOIN sales_invoices s ON s.id=i.sales_invoice_id
                WHERE {clause}
                GROUP BY i.product_id,i.product_name_snapshot ORDER BY profit DESC LIMIT 12""",
            params,
        ).fetchall()
        daily = conn.execute(
            f"SELECT shamsi_date,SUM(total_rial) AS revenue,SUM(real_profit_rial) AS profit FROM sales_invoices WHERE {clause} GROUP BY shamsi_date ORDER BY shamsi_date",
            params,
        ).fetchall()
        value_by_warehouse = rows_dict(conn.execute(
            """SELECT w.id,w.name,COALESCE(st.qty,0) AS qty,COALESCE(bv.value_rial,0) AS value_rial
            FROM warehouses w
            LEFT JOIN (SELECT warehouse_id,SUM(quantity) AS qty FROM product_warehouse_stocks GROUP BY warehouse_id) st ON st.warehouse_id=w.id
            LEFT JOIN (SELECT warehouse_id,SUM(CASE WHEN remaining_qty>0 THEN remaining_qty*unit_cost_rial ELSE 0 END) AS value_rial FROM inventory_batches GROUP BY warehouse_id) bv ON bv.warehouse_id=w.id
            ORDER BY w.id"""
        ).fetchall())
        return {
            "sales": dict(sales),
            "sales_returns_rial": int(returns[0]),
            "return_cogs_rial": int(returns[1]),
            "return_profit_impact_rial": int(returns[2]),
            "net_revenue_rial": int(sales["revenue"] or 0) - int(returns[0] or 0),
            "net_profit_rial": int(sales["profit"] or 0) - int(returns[2] or 0),
            "purchases": {"invoice_count": int(purchases[0]), "total_rial": int(purchases[1]), "remaining_rial": int(purchases[2])},
            "top_products": rows_dict(by_product),
            "daily": rows_dict(daily),
            "warehouse_values": value_by_warehouse,
            "date_from": date_from,
            "date_to": date_to,
        }


@app.get("/api/reports/stock")
async def report_stock(q: str = "", user: dict = Depends(current_user)):
    with db_read() as conn:
        products = query_product_rows(conn, q, include_inactive=False, include_parents=False)
        for product in products:
            product["store_value_rial"] = max(0, int(product["store_qty"])) * int(product["purchase_price_rial"] or 0)
            product["repair_value_rial"] = max(0, int(product["repair_qty"])) * int(product["purchase_price_rial"] or 0)
            product["low_stock"] = int(product["store_qty"]) <= int(product["min_stock_alert"])
            product["negative_stock"] = int(product["store_qty"]) < 0
        batch_totals = conn.execute("SELECT warehouse_id,COALESCE(SUM(CASE WHEN remaining_qty>0 THEN remaining_qty*unit_cost_rial ELSE 0 END),0) AS value_rial FROM inventory_batches GROUP BY warehouse_id").fetchall()
        return {"items": products, "batch_values": {str(r["warehouse_id"]): int(r["value_rial"]) for r in batch_totals}}


@app.get("/api/reports/export.xlsx")
async def export_report_xlsx(report_type: str = "sales", user: dict = Depends(current_user)):
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment
    from openpyxl.utils import get_column_letter

    with db_read() as conn:
        workbook = Workbook()
        sheet = workbook.active
        if report_type == "stock":
            sheet.title = "موجودی کالا"
            headers = ["شناسه", "نام کالا", "بارکد", "SKU", "انبار فروشگاه", "انبار تعمیرگاه", "قیمت خرید (ریال)", "ارزش خرید (ریال)", "حد هشدار", "دسته"]
            data = query_product_rows(conn, include_inactive=False, include_parents=False)
            sheet.append(headers)
            for p in data:
                sheet.append([p["id"], p["name"], p["barcode"], p["sku"], p["store_qty"], p["repair_qty"], p["purchase_price_rial"], max(0, p["store_qty"]+p["repair_qty"])*p["purchase_price_rial"], p["min_stock_alert"], p["category"]])
        elif report_type == "ledger":
            sheet.title = "گردش اشخاص"
            headers = ["تاریخ شمسی", "نام طرف حساب", "نوع سند", "شماره مرجع", "شرح", "بدهکار (ریال)", "بستانکار (ریال)", "روش پرداخت"]
            sheet.append(headers)
            rows = conn.execute("SELECT l.*,p.name AS party_name FROM party_ledger_entries l JOIN parties p ON p.id=l.party_id ORDER BY l.id DESC LIMIT 5000").fetchall()
            for r in rows:
                sheet.append([r["shamsi_date"], r["party_name"], r["entry_type"], r["reference_number"], r["description"], r["debit_rial"], r["credit_rial"], r["payment_method"]])
        else:
            sheet.title = "فروش و سود"
            headers = ["شماره فاکتور", "تاریخ شمسی", "مشتری", "نوع قیمت", "مبلغ فروش (ریال)", "بهای تمام‌شده (ریال)", "سود واقعی (ریال)", "مانده (ریال)", "موجودی منفی"]
            sheet.append(headers)
            rows = conn.execute("SELECT s.*,p.name AS customer_name FROM sales_invoices s JOIN parties p ON p.id=s.customer_id ORDER BY s.id DESC LIMIT 5000").fetchall()
            for r in rows:
                sheet.append([r["invoice_number"], r["shamsi_date"], r["customer_name"], r["price_tier_used"], r["total_rial"], r["total_cogs_rial"], r["real_profit_rial"], r["credit_rial"], "بله" if r["has_negative_stock_items"] else "خیر"])
        header_fill = PatternFill("solid", fgColor="173D38")
        for cell in sheet[1]:
            cell.fill = header_fill
            cell.font = Font(color="FFFFFF", bold=True)
            cell.alignment = Alignment(horizontal="center", vertical="center")
        sheet.freeze_panes = "A2"
        sheet.auto_filter.ref = sheet.dimensions
        for col in sheet.columns:
            max_len = max((len(str(c.value or "")) for c in col[:100]), default=10)
            sheet.column_dimensions[get_column_letter(col[0].column)].width = min(max(max_len + 3, 14), 42)
        output = io.BytesIO()
        workbook.save(output)
        output.seek(0)
        filename = f"alborzpart_{report_type}_{datetime.now().strftime('%Y%m%d')}.xlsx"
        return StreamingResponse(output, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", headers={"Content-Disposition": f"attachment; filename={filename}"})


@app.get("/api/templates")
async def list_templates(user: dict = Depends(current_user)):
    with db_read() as conn:
        return {"items": rows_dict(conn.execute("SELECT * FROM print_templates ORDER BY id").fetchall())}


@app.put("/api/templates/{template_id}")
async def update_template(template_id: int, request: Request, user: dict = Depends(current_user)):
    ensure_user(user, "admin")
    body = await request.json()
    editable = {"name", "paper_size", "is_default", "store_name", "store_subtitle", "store_address", "store_phone", "social_links", "invoice_title", "number_prefix", "number_padding", "annual_reset", "print_currency", "show_sku", "show_barcode", "show_vehicle", "show_unit_price", "show_discount", "show_row_total", "header_note", "warranty_terms", "footer_note", "show_signature_box"}
    updates = {k: body[k] for k in editable if k in body}
    if not updates:
        return {"updated": False}
    with db_transaction() as conn:
        if not conn.execute("SELECT id FROM print_templates WHERE id=?", (template_id,)).fetchone():
            raise HTTPException(404, "قالب چاپ پیدا نشد.")
        if updates.get("is_default"):
            conn.execute("UPDATE print_templates SET is_default=0")
        sql = ",".join(f"{k}=?" for k in updates)
        conn.execute(f"UPDATE print_templates SET {sql},updated_at=? WHERE id=?", (*updates.values(), now_iso(), template_id))
        log_audit(conn, user["id"], user["username"], user["role"], "TEMPLATE_UPDATE", "PRINT_TEMPLATE", template_id, "ویرایش قالب چاپ", None, updates)
    return {"updated": True}


@app.get("/api/settings")
async def get_settings(user: dict = Depends(current_user)):
    with db_read() as conn:
        return {"items": rows_dict(conn.execute("SELECT * FROM system_settings ORDER BY key").fetchall())}


@app.put("/api/settings")
async def update_settings(request: Request, user: dict = Depends(current_user)):
    ensure_user(user, "admin")
    body = await request.json()
    editable = {"allow_negative_stock_sale", "default_display_currency", "auto_daily_backup", "backup_secondary_path"}
    with db_transaction() as conn:
        for key, value in body.items():
            if key in editable:
                set_setting(conn, key, str(value), user["username"])
        log_audit(conn, user["id"], user["username"], user["role"], "SETTINGS_UPDATE", "SETTINGS", "system", "ویرایش تنظیمات عمومی", None, {k: v for k, v in body.items() if k in editable})
    return {"ok": True}


@app.get("/api/users")
async def list_users(user: dict = Depends(current_user)):
    ensure_user(user, "admin")
    with db_read() as conn:
        return {"items": rows_dict(conn.execute("SELECT id,username,full_name,role,role_label,preferred_currency,is_active,created_at FROM users ORDER BY id").fetchall())}


@app.post("/api/users")
async def create_user(request: Request, user: dict = Depends(current_user)):
    ensure_user(user, "admin")
    body = await request.json()
    username = str(body.get("username") or "").strip()
    password = str(body.get("password") or "")
    full_name = str(body.get("full_name") or "").strip()
    role = str(body.get("role") or "operator")
    if not username or not full_name or len(password) < 8:
        raise HTTPException(422, "نام، نام کاربری و رمز حداقل ۸ کاراکتری لازم است.")
    if role not in {"admin", "operator", "warehouse_repair"}:
        raise HTTPException(422, "نقش کاربری معتبر نیست.")
    try:
        with db_transaction() as conn:
            cur = conn.execute("INSERT INTO users (username,full_name,password_hash,role,role_label,preferred_currency,is_active,created_at) VALUES (?,?,?,?,?,?,1,?)", (username, full_name, hash_password(password), role, body.get("role_label") or {"admin":"مدیر سیستم","operator":"فروشنده / اپراتور","warehouse_repair":"انباردار تعمیرگاه"}[role], body.get("preferred_currency", "TOMAN"), now_iso()))
            log_audit(conn, user["id"], user["username"], user["role"], "CREATE", "USER", cur.lastrowid, f"ایجاد کاربر {username}", None, {"role": role})
        return {"id": cur.lastrowid, "username": username}
    except sqlite3.IntegrityError:
        raise HTTPException(409, "این نام کاربری قبلاً ثبت شده است.")


@app.get("/api/audit")
async def list_audit(limit: int = 150, user: dict = Depends(current_user)):
    ensure_user(user, "admin")
    with db_read() as conn:
        rows = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (min(max(limit, 1), 1000),)).fetchall()
        return {"items": rows_dict(rows)}


@app.get("/api/backups")
async def list_backups(user: dict = Depends(current_user)):
    ensure_user(user, "admin")
    with db_read() as conn:
        return {"items": rows_dict(conn.execute("SELECT * FROM backups ORDER BY id DESC LIMIT 100").fetchall())}


@app.post("/api/backups")
async def create_manual_backup(user: dict = Depends(current_user)):
    ensure_user(user, "admin")
    result = create_backup("MANUAL", user["username"])
    ok, detail = test_backup_file(result["file_path"])
    with db_transaction() as conn:
        conn.execute("UPDATE backups SET last_restore_tested_at=?,restore_test_status=? WHERE id=?", (get_shamsi_now(), "PASSED" if ok else "FAILED: " + detail, result["id"]))
    result["restore_test_status"] = "PASSED" if ok else "FAILED"
    result["test_detail"] = detail
    return result


@app.post("/api/backups/{backup_id}/test")
async def test_backup(backup_id: int, user: dict = Depends(current_user)):
    ensure_user(user, "admin")
    with db_read() as conn:
        backup = conn.execute("SELECT * FROM backups WHERE id=?", (backup_id,)).fetchone()
        if not backup:
            raise HTTPException(404, "نسخه پشتیبان پیدا نشد.")
    ok, detail = test_backup_file(backup["file_path"])
    with db_transaction() as conn:
        conn.execute("UPDATE backups SET last_restore_tested_at=?,restore_test_status=? WHERE id=?", (get_shamsi_now(), "PASSED" if ok else "FAILED: " + detail, backup_id))
    return {"ok": ok, "detail": detail}


@app.get("/api/backups/{backup_id}/download")
async def download_backup(backup_id: int, user: dict = Depends(current_user)):
    ensure_user(user, "admin")
    with db_read() as conn:
        backup = conn.execute("SELECT * FROM backups WHERE id=?", (backup_id,)).fetchone()
        if not backup or not os.path.isfile(backup["file_path"]):
            raise HTTPException(404, "فایل پشتیبان در دسترس نیست.")
        return FileResponse(backup["file_path"], filename=backup["filename"], media_type="application/zip")


@app.get("/api/tokens")
async def list_tokens(user: dict = Depends(current_user)):
    ensure_user(user, "admin")
    with db_read() as conn:
        rows = conn.execute("SELECT t.id,t.name,t.channel_type,t.token,t.abilities,t.last_used_at,t.is_active,t.created_at,u.username FROM api_tokens t JOIN users u ON u.id=t.user_id ORDER BY t.id").fetchall()
        return {"items": rows_dict(rows)}


@app.post("/api/tokens")
async def create_token(request: Request, user: dict = Depends(current_user)):
    ensure_user(user, "admin")
    body = await request.json()
    name = str(body.get("name") or "توکن API جدید").strip()
    token = secrets.token_urlsafe(36)
    abilities = body.get("abilities") or "products:read,inventory:read,prices:read,orders:write"
    with db_transaction() as conn:
        cur = conn.execute("INSERT INTO api_tokens (user_id,name,channel_type,token,abilities,is_active,created_at) VALUES (?,?,?,?,?,1,?)", (user["id"], name, body.get("channel_type", "INTERNAL").upper(), token, abilities, now_iso()))
        log_audit(conn, user["id"], user["username"], user["role"], "TOKEN_CREATE", "API_TOKEN", cur.lastrowid, f"ساخت توکن API {name}", None, {"abilities": abilities})
        return {"id": cur.lastrowid, "name": name, "token": token, "abilities": abilities}


@app.get("/api/channel/v1/products")
async def channel_products(authorization: Optional[str] = Header(None)):
    token = channel_token_user(authorization)
    require_channel_ability(token, "products:read")
    with db_read() as conn:
        products = query_product_rows(conn, include_inactive=False, include_parents=False)
        return {"data": [{"id": p["id"], "name": p["name"], "sku": p["sku"], "barcode": p["barcode"], "brand": p["brand"], "vehicle_compatibility": p["vehicle_compatibility"]} for p in products]}


@app.get("/api/channel/v1/prices")
async def channel_prices(authorization: Optional[str] = Header(None)):
    token = channel_token_user(authorization)
    require_channel_ability(token, "prices:read")
    with db_read() as conn:
        rows = conn.execute("SELECT id,sale_price_retail_rial,sale_price_wholesale_rial,sale_price_colleague_rial FROM products WHERE is_active=1 AND is_parent=0 ORDER BY id").fetchall()
        return {"data": rows_dict(rows), "currency": "IRR"}


@app.get("/api/channel/v1/inventory")
async def channel_inventory(authorization: Optional[str] = Header(None)):
    token = channel_token_user(authorization)
    require_channel_ability(token, "inventory:read")
    with db_read() as conn:
        rows = conn.execute("SELECT product_id,warehouse_id,quantity FROM product_warehouse_stocks ORDER BY product_id,warehouse_id").fetchall()
        return {"data": rows_dict(rows), "source_of_truth": "accounting-application"}


@app.post("/api/channel/v1/orders")
async def channel_create_order(request: Request, authorization: Optional[str] = Header(None)):
    token = channel_token_user(authorization)
    require_channel_ability(token, "orders:write")
    body = await request.json()
    order_no = str(body.get("external_order_no") or "").strip()
    if not order_no:
        raise HTTPException(422, "external_order_no الزامی است.")
    with db_transaction() as conn:
        try:
            cur = conn.execute("INSERT INTO channel_orders (channel_type,external_order_no,customer_name,customer_phone,status,payload_json,created_at) VALUES (?,?,?,?,'DRAFT',?,?)", (token["channel_type"], order_no, body.get("customer_name") or "سفارش آنلاین", body.get("customer_phone"), json.dumps(body, ensure_ascii=False), now_iso()))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "این شماره سفارش کانال قبلاً دریافت شده است.")
        return {"id": cur.lastrowid, "external_order_no": order_no, "status": "DRAFT", "message": "سفارش به پیش‌نویس برگشت‌پذیر ثبت شد؛ موجودی هنوز رزرو/کسر نشده است."}


@app.get("/api/channel/orders")
async def list_channel_orders(user: dict = Depends(current_user)):
    with db_read() as conn:
        rows = conn.execute("SELECT * FROM channel_orders ORDER BY id DESC LIMIT 200").fetchall()
        result = rows_dict(rows)
        for row in result:
            row["payload"] = json.loads(row.pop("payload_json") or "{}")
        return {"items": result}


@app.post("/api/channel/orders/{order_id}/convert")
async def convert_channel_order(order_id: int, user: dict = Depends(current_user)):
    ensure_user(user, "admin", "operator")
    with db_transaction() as conn:
        order = conn.execute("SELECT * FROM channel_orders WHERE id=?", (order_id,)).fetchone()
        if not order:
            raise HTTPException(404, "سفارش کانال پیدا نشد.")
        if order["status"] != "DRAFT":
            raise HTTPException(409, "فقط سفارش پیش‌نویس قابل تبدیل است.")
        payload = json.loads(order["payload_json"] or "{}")
    # Deliberately return the order payload for a user-confirmed sale; online orders are not silently finalized.
    return {"id": order_id, "status": "DRAFT", "payload": payload, "message": "جزئیات آماده بازبینی است؛ فروشنده باید پیش از ثبت فاکتور، ردیف‌ها و موجودی را تأیید کند."}


@app.get("/api/docs/quickstart", response_class=HTMLResponse, include_in_schema=False)
async def quickstart():
    return HTMLResponse("""<!doctype html><html lang='fa' dir='rtl'><meta charset='utf-8'><body style='font:16px Tahoma;max-width:820px;margin:40px auto;line-height:2'><h1>راهنمای اجرای سامانه</h1><p>این نسخه روی یک میزبان محلی/شبکه داخلی اجرا می‌شود. نقطه ورود <code>/</code>، مستندات REST در <code>/api-docs</code> و وضعیت سرویس در <code>/health</code> است.</p><p>حساب آزمایشی مدیر: <b>admin</b> / <b>admin123</b>؛ اپراتور: <b>operator</b> / <b>op123</b>. پس از ورود اول، رمزهای نسخه آزمایشی به هش PBKDF2 ارتقا می‌یابند.</p><p>مبالغ در پایگاه داده به ریال ذخیره می‌شوند؛ رابط کاربری، تومان را با تقسیم بر ۱۰ نمایش می‌دهد. اسناد نهایی‌شده حذف/ویرایش نمی‌شوند و اصلاح با سند جداگانه انجام می‌شود.</p><p>برای نصب Laragon/VPS، README.fa.md را در بسته پروژه ببینید. این نمونه اجرایی از SQLite استفاده می‌کند؛ انتقال به MySQL/Laravel برای استقرار واقعی طبق سند نیازمندی انجام می‌شود.</p></body></html>""")
