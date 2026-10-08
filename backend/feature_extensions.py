import json
import sqlite3
from datetime import datetime
from typing import Any

from fastapi import Depends, HTTPException, Request


def ensure_extended_schema(db_path: str, hash_password, now_iso, get_shamsi_date):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scope TEXT NOT NULL CHECK(scope IN ('PRODUCT','PARTY')),
            parent_id INTEGER,
            name TEXT NOT NULL,
            slug TEXT,
            description TEXT,
            sort_order INTEGER NOT NULL DEFAULT 0,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(scope, parent_id, name)
        );
        CREATE TABLE IF NOT EXISTS sales_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_number TEXT UNIQUE NOT NULL,
            document_type TEXT NOT NULL CHECK(document_type IN ('ORDER','PROFORMA')),
            status TEXT NOT NULL DEFAULT 'DRAFT' CHECK(status IN ('DRAFT','CONFIRMED','CONVERTED','CANCELLED')),
            customer_id INTEGER NOT NULL,
            warehouse_id INTEGER NOT NULL,
            shamsi_date TEXT NOT NULL,
            valid_until TEXT,
            subtotal_rial INTEGER NOT NULL DEFAULT 0,
            discount_rial INTEGER NOT NULL DEFAULT 0,
            total_rial INTEGER NOT NULL DEFAULT 0,
            notes TEXT,
            converted_invoice_id INTEGER,
            created_by TEXT NOT NULL,
            updated_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sales_document_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            product_name_snapshot TEXT NOT NULL,
            qty INTEGER NOT NULL,
            unit_price_rial INTEGER NOT NULL,
            discount_rial INTEGER NOT NULL DEFAULT 0,
            line_total_rial INTEGER NOT NULL
        );
        """
    )
    for table in ("products", "parties"):
        columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        if "category_id" not in columns:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN category_id INTEGER")
    user_columns = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
    if "updated_at" not in user_columns:
        conn.execute("ALTER TABLE users ADD COLUMN updated_at TEXT")

    marker = conn.execute("SELECT value FROM system_settings WHERE key='production_clean_v1'").fetchone()
    if not marker:
        tables = [
            "sales_return_items", "sales_returns", "sales_invoice_items", "invoice_payments", "sales_invoices",
            "purchase_returns", "purchase_invoice_items", "purchase_invoices", "sales_document_items", "sales_documents",
            "inventory_movements", "inventory_batches", "product_price_history", "product_supplier_aliases",
            "product_warehouse_stocks", "stock_adjustments", "warehouse_transfers", "party_ledger_entries",
            "cheques", "channel_orders", "api_tokens", "audit_logs", "backups", "products", "parties", "categories",
            "print_templates", "warehouses"
        ]
        for table in tables:
            conn.execute(f"DELETE FROM {table}")
        conn.execute("DELETE FROM users WHERE username <> 'admin'")
        admin = conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()
        if admin:
            conn.execute(
                "UPDATE users SET full_name=?,role='admin',role_label=?,is_active=1,updated_at=? WHERE username='admin'",
                ("مدیر سیستم", "مدیر اصلی", now_iso()),
            )
        else:
            conn.execute(
                "INSERT INTO users(username,full_name,password_hash,role,role_label,preferred_currency,is_active,created_at,updated_at) VALUES(?,?,?,?,?,'TOMAN',1,?,?)",
                ("admin", "مدیر سیستم", hash_password("ChangeMe-Now-1405"), "admin", "مدیر اصلی", now_iso(), now_iso()),
            )
        conn.execute("INSERT INTO warehouses(code,name,description,is_default) VALUES('MAIN','انبار اصلی','انبار اصلی حسابداری پورکیان',1)")
        conn.execute(
            """INSERT INTO print_templates(
                name,paper_size,is_default,store_name,store_subtitle,invoice_title,number_prefix,number_padding,
                annual_reset,print_currency,show_sku,show_barcode,show_vehicle,show_unit_price,show_discount,
                show_row_total,footer_note,show_signature_box,updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("قالب اصلی", "A4", 1, "حسابداری پورکیان", "کلیه حقوق محفوظ است", "فاکتور فروش", "INV-", 6,
             1, "TOMAN", 1, 1, 1, 1, 1, 1, "© حسابداری پورکیان - کلیه حقوق محفوظ است", 1, now_iso()),
        )
        base_settings = {
            "store_name": "حسابداری پورکیان",
            "store_subtitle": "سامانه حسابداری و مدیریت فروش",
            "default_display_currency": "TOMAN",
            "allow_negative_stock": "0",
            "auto_daily_backup": "1",
            "backup_local_path": "backups",
            "invoice_seq_counter": "0",
            "purchase_seq_counter": "0",
            "barcode_seq_counter": "0",
            "sales_document_seq": "0",
            "production_clean_v1": datetime.now().isoformat(),
        }
        conn.execute("DELETE FROM system_settings")
        for key, value in base_settings.items():
            conn.execute(
                "INSERT INTO system_settings(key,value,updated_by,updated_at) VALUES(?,?,?,?)",
                (key, value, "system", now_iso()),
            )
    conn.commit()
    conn.close()


def register_extended_routes(app, helpers: dict[str, Any]):
    current_user = helpers["current_user"]
    ensure_user = helpers["ensure_user"]
    db_read = helpers["db_read"]
    db_transaction = helpers["db_transaction"]
    rows_dict = helpers["rows_dict"]
    safe_int = helpers["safe_int"]
    hash_password = helpers["hash_password"]
    now_iso = helpers["now_iso"]
    get_shamsi_date = helpers["get_shamsi_date"]
    get_setting = helpers["get_setting"]
    set_setting = helpers["set_setting"]
    log_audit = helpers["log_audit"]

    @app.get("/api/categories")
    async def list_categories(scope: str = "PRODUCT", user: dict = Depends(current_user)):
        scope = scope.upper()
        if scope not in {"PRODUCT", "PARTY"}:
            raise HTTPException(422, "نوع دسته‌بندی معتبر نیست.")
        with db_read() as conn:
            rows = conn.execute("SELECT * FROM categories WHERE scope=? ORDER BY parent_id IS NOT NULL,parent_id,sort_order,name", (scope,)).fetchall()
            return {"items": rows_dict(rows)}

    @app.post("/api/categories")
    async def create_category(request: Request, user: dict = Depends(current_user)):
        ensure_user(user, "admin")
        body = await request.json()
        scope = str(body.get("scope") or "PRODUCT").upper()
        name = str(body.get("name") or "").strip()
        parent_id = safe_int(body.get("parent_id")) or None
        if scope not in {"PRODUCT", "PARTY"} or not name:
            raise HTTPException(422, "نام و نوع دسته‌بندی الزامی است.")
        with db_transaction() as conn:
            if parent_id:
                parent = conn.execute("SELECT id FROM categories WHERE id=? AND scope=?", (parent_id, scope)).fetchone()
                if not parent:
                    raise HTTPException(422, "دسته والد معتبر نیست.")
            cur = conn.execute(
                "INSERT INTO categories(scope,parent_id,name,slug,description,sort_order,is_active,created_at,updated_at) VALUES(?,?,?,?,?,?,1,?,?)",
                (scope, parent_id, name, body.get("slug"), body.get("description"), safe_int(body.get("sort_order")), now_iso(), now_iso()),
            )
            return {"id": cur.lastrowid}

    @app.put("/api/categories/{category_id}")
    async def update_category(category_id: int, request: Request, user: dict = Depends(current_user)):
        ensure_user(user, "admin")
        body = await request.json()
        name = str(body.get("name") or "").strip()
        if not name:
            raise HTTPException(422, "نام دسته‌بندی الزامی است.")
        parent_id = safe_int(body.get("parent_id")) or None
        if parent_id == category_id:
            raise HTTPException(422, "دسته نمی‌تواند والد خودش باشد.")
        with db_transaction() as conn:
            conn.execute("UPDATE categories SET parent_id=?,name=?,description=?,sort_order=?,updated_at=? WHERE id=?", (parent_id, name, body.get("description"), safe_int(body.get("sort_order")), now_iso(), category_id))
        return {"ok": True}

    @app.delete("/api/categories/{category_id}")
    async def delete_category(category_id: int, user: dict = Depends(current_user)):
        ensure_user(user, "admin")
        with db_transaction() as conn:
            if conn.execute("SELECT 1 FROM categories WHERE parent_id=?", (category_id,)).fetchone():
                raise HTTPException(409, "ابتدا زیرشاخه‌های این دسته را حذف یا منتقل کنید.")
            used = conn.execute("SELECT 1 FROM products WHERE category_id=? UNION SELECT 1 FROM parties WHERE category_id=?", (category_id, category_id)).fetchone()
            if used:
                raise HTTPException(409, "این دسته در اطلاعات کالا یا طرف حساب استفاده شده است.")
            conn.execute("DELETE FROM categories WHERE id=?", (category_id,))
        return {"ok": True}

    @app.put("/api/users/{user_id}")
    async def update_user(user_id: int, request: Request, user: dict = Depends(current_user)):
        ensure_user(user, "admin")
        body = await request.json()
        username = str(body.get("username") or "").strip()
        full_name = str(body.get("full_name") or "").strip()
        role = str(body.get("role") or "operator")
        if not username or not full_name or role not in {"admin", "operator", "warehouse_repair"}:
            raise HTTPException(422, "اطلاعات کاربر کامل نیست.")
        role_label = {"admin": "مدیر اصلی", "operator": "کاربر فروش", "warehouse_repair": "مدیر تعمیرگاه"}[role]
        with db_transaction() as conn:
            existing = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
            if not existing:
                raise HTTPException(404, "کاربر پیدا نشد.")
            values = [username, full_name, role, role_label, int(bool(body.get("is_active", True))), body.get("preferred_currency") or "TOMAN", now_iso()]
            sql = "UPDATE users SET username=?,full_name=?,role=?,role_label=?,is_active=?,preferred_currency=?,updated_at=?"
            password = str(body.get("password") or "")
            if password:
                if len(password) < 8:
                    raise HTTPException(422, "رمز عبور باید حداقل ۸ کاراکتر باشد.")
                sql += ",password_hash=?"
                values.append(hash_password(password))
            sql += " WHERE id=?"
            values.append(user_id)
            conn.execute(sql, values)
            log_audit(conn, user["id"], user["username"], user["role"], "USER_UPDATE", "USER", user_id, "ویرایش اطلاعات کاربر", dict(existing), {"username": username, "full_name": full_name, "role": role})
        return {"ok": True}

    def document_detail(conn, document_id: int):
        row = conn.execute("SELECT d.*,p.name customer_name,w.name warehouse_name FROM sales_documents d JOIN parties p ON p.id=d.customer_id JOIN warehouses w ON w.id=d.warehouse_id WHERE d.id=?", (document_id,)).fetchone()
        if not row:
            raise HTTPException(404, "سند پیدا نشد.")
        result = dict(row)
        result["items"] = rows_dict(conn.execute("SELECT * FROM sales_document_items WHERE document_id=? ORDER BY id", (document_id,)).fetchall())
        return result

    @app.get("/api/sales-documents")
    async def list_sales_documents(document_type: str = "", user: dict = Depends(current_user)):
        with db_read() as conn:
            sql = "SELECT d.*,p.name customer_name FROM sales_documents d JOIN parties p ON p.id=d.customer_id"
            params = []
            if document_type:
                sql += " WHERE d.document_type=?"
                params.append(document_type.upper())
            sql += " ORDER BY d.id DESC"
            return {"items": rows_dict(conn.execute(sql, params).fetchall())}

    @app.get("/api/sales-documents/{document_id}")
    async def get_sales_document(document_id: int, user: dict = Depends(current_user)):
        with db_read() as conn:
            return document_detail(conn, document_id)

    async def save_document(body, user, document_id=None):
        document_type = str(body.get("document_type") or "PROFORMA").upper()
        if document_type not in {"ORDER", "PROFORMA"}:
            raise HTTPException(422, "نوع سند معتبر نیست.")
        items = body.get("items") or []
        if not items:
            raise HTTPException(422, "حداقل یک ردیف کالا لازم است.")
        with db_transaction() as conn:
            warehouse_id = safe_int(body.get("warehouse_id"))
            warehouse_row = conn.execute("SELECT id FROM warehouses WHERE id=?", (warehouse_id,)).fetchone()
            if not warehouse_row:
                warehouse_id = conn.execute("SELECT id FROM warehouses WHERE is_default=1 ORDER BY id LIMIT 1").fetchone()[0]
            prepared = []
            subtotal = 0
            for item in items:
                product = conn.execute("SELECT id,name,sale_price_retail_rial FROM products WHERE id=? AND is_active=1", (safe_int(item.get("product_id")),)).fetchone()
                if not product:
                    raise HTTPException(422, "یکی از کالاها معتبر نیست.")
                qty = max(1, safe_int(item.get("qty"), 1))
                price = max(0, safe_int(item.get("unit_price_rial"), product["sale_price_retail_rial"]))
                discount = max(0, safe_int(item.get("discount_rial")))
                total = max(0, qty * price - discount)
                subtotal += total
                prepared.append((product, qty, price, discount, total))
            discount = min(subtotal, max(0, safe_int(body.get("discount_rial"))))
            total = subtotal - discount
            if document_id:
                current = conn.execute("SELECT * FROM sales_documents WHERE id=?", (document_id,)).fetchone()
                if not current or current["status"] == "CONVERTED":
                    raise HTTPException(409, "سند تبدیل‌شده قابل ویرایش نیست.")
                conn.execute("DELETE FROM sales_document_items WHERE document_id=?", (document_id,))
                conn.execute("UPDATE sales_documents SET document_type=?,customer_id=?,warehouse_id=?,shamsi_date=?,valid_until=?,subtotal_rial=?,discount_rial=?,total_rial=?,notes=?,updated_by=?,updated_at=? WHERE id=?", (document_type, safe_int(body.get("customer_id")), warehouse_id, body.get("shamsi_date") or get_shamsi_date(), body.get("valid_until"), subtotal, discount, total, body.get("notes"), user["username"], now_iso(), document_id))
            else:
                seq = safe_int(get_setting(conn, "sales_document_seq", "0")) + 1
                set_setting(conn, "sales_document_seq", str(seq), user["username"])
                prefix = "ORD" if document_type == "ORDER" else "PRE"
                number = f"{prefix}-{datetime.now().year}-{seq:06d}"
                cur = conn.execute("INSERT INTO sales_documents(document_number,document_type,status,customer_id,warehouse_id,shamsi_date,valid_until,subtotal_rial,discount_rial,total_rial,notes,created_by,updated_by,created_at,updated_at) VALUES(?,?,\'DRAFT\',?,?,?,?,?,?,?,?,?,?,?,?)", (number, document_type, safe_int(body.get("customer_id")), warehouse_id, body.get("shamsi_date") or get_shamsi_date(), body.get("valid_until"), subtotal, discount, total, body.get("notes"), user["username"], user["username"], now_iso(), now_iso()))
                document_id = int(cur.lastrowid)
            conn.executemany("INSERT INTO sales_document_items(document_id,product_id,product_name_snapshot,qty,unit_price_rial,discount_rial,line_total_rial) VALUES(?,?,?,?,?,?,?)", [(document_id,p[0]["id"],p[0]["name"],p[1],p[2],p[3],p[4]) for p in prepared])
            return document_detail(conn, document_id)

    @app.post("/api/sales-documents")
    async def create_sales_document(request: Request, user: dict = Depends(current_user)):
        return await save_document(await request.json(), user)

    @app.put("/api/sales-documents/{document_id}")
    async def update_sales_document(document_id: int, request: Request, user: dict = Depends(current_user)):
        return await save_document(await request.json(), user, document_id)

    @app.post("/api/sales-documents/{document_id}/convert")
    async def convert_sales_document(document_id: int, request: Request, user: dict = Depends(current_user)):
        body = await request.json()
        invoice_id = safe_int(body.get("invoice_id"))
        if not invoice_id:
            raise HTTPException(422, "شناسه فاکتور نهایی الزامی است.")
        with db_transaction() as conn:
            invoice = conn.execute("SELECT id FROM sales_invoices WHERE id=?", (invoice_id,)).fetchone()
            if not invoice:
                raise HTTPException(404, "فاکتور نهایی پیدا نشد.")
            conn.execute("UPDATE sales_documents SET status='CONVERTED',converted_invoice_id=?,updated_by=?,updated_at=? WHERE id=?", (invoice_id, user["username"], now_iso(), document_id))
        return {"ok": True, "invoice_id": invoice_id}

    @app.post("/api/sales/{sale_id}/payments")
    async def add_sale_payment(sale_id: int, request: Request, user: dict = Depends(current_user)):
        body = await request.json()
        amount = max(0, safe_int(body.get("amount_rial")))
        method = str(body.get("method") or "CASH").upper()
        if amount <= 0:
            raise HTTPException(422, "مبلغ پرداخت باید بیشتر از صفر باشد.")
        with db_transaction() as conn:
            sale = conn.execute("SELECT * FROM sales_invoices WHERE id=?", (sale_id,)).fetchone()
            if not sale:
                raise HTTPException(404, "فاکتور پیدا نشد.")
            remaining = int(sale["credit_rial"] or 0)
            if amount > remaining:
                raise HTTPException(422, "مبلغ پرداخت از مانده فاکتور بیشتر است.")
            conn.execute("INSERT INTO invoice_payments(invoice_type,invoice_id,party_id,payment_method,amount_rial,reference_no,shamsi_date,created_by,created_at) VALUES('SALE',?,?,?,?,?,?,?,?)", (sale_id, sale["customer_id"], method, amount, body.get("reference_no"), body.get("shamsi_date") or get_shamsi_date(), user["username"], now_iso()))
            conn.execute("UPDATE sales_invoices SET paid_rial=paid_rial+?,credit_rial=credit_rial-? WHERE id=?", (amount, amount, sale_id))
        return {"ok": True, "remaining_rial": remaining - amount}
