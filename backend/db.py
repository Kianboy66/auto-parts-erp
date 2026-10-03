import os
import json
import shutil
import sqlite3
import hashlib
import secrets
from datetime import datetime
from zoneinfo import ZoneInfo

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.path.join(BASE_DIR, "data", "erp.sqlite")
BACKUP_DIR = os.path.join(BASE_DIR, "backups")
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")

os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)
os.makedirs(SAMPLES_DIR, exist_ok=True)


def _seed_password_hash(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 240000).hex()
    return f"pbkdf2_sha256${salt}${digest}"


def get_shamsi_now():
    # Today's date in user's local timezone is 2026-10-03 -> 11 Mehr 1405 (1405/07/11)
    now = datetime.now(ZoneInfo("Asia/Tehran"))
    return f"1405/07/11 - {now.strftime('%H:%M:%S')}"


def get_shamsi_date():
    return "1405/07/11"


def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA busy_timeout = 15000;")
    return conn


def log_audit(conn, user_id, username, user_role, action_type, entity_type, entity_id, description, old_val=None, new_val=None):
    conn.execute(
        """
        INSERT INTO audit_logs (
            user_id, username, user_role, action_type, entity_type, entity_id,
            description, old_value_json, new_value_json, shamsi_datetime, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            username,
            user_role,
            action_type,
            entity_type,
            str(entity_id) if entity_id is not None else "",
            description,
            json.dumps(old_val, ensure_ascii=False) if old_val is not None else None,
            json.dumps(new_val, ensure_ascii=False) if new_val is not None else None,
            get_shamsi_now(),
            datetime.now().isoformat(),
        ),
    )


def init_db():
    conn = get_conn()
    cur = conn.cursor()

    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL, -- 'admin', 'operator', 'warehouse_repair'
            role_label TEXT NOT NULL,
            preferred_currency TEXT NOT NULL DEFAULT 'TOMAN', -- 'TOMAN' or 'RIAL'
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            channel_type TEXT NOT NULL DEFAULT 'WOOCOMMERCE', -- 'WOOCOMMERCE', 'TOROB', 'BASALAM', 'INSTAGRAM', 'INTERNAL'
            token TEXT UNIQUE NOT NULL,
            abilities TEXT NOT NULL DEFAULT 'products:read,inventory:read,prices:read,orders:write',
            last_used_at TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_by TEXT,
            updated_at TEXT
        );

        CREATE TABLE IF NOT EXISTS warehouses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            is_default INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            parent_id INTEGER,
            is_parent INTEGER NOT NULL DEFAULT 0,
            variant_label TEXT,
            name TEXT NOT NULL,
            sku TEXT,
            barcode TEXT UNIQUE,
            barcode_type TEXT NOT NULL DEFAULT 'EAN13', -- 'EAN13' or 'CODE128'
            purchase_price_rial INTEGER NOT NULL DEFAULT 0,
            sale_price_retail_rial INTEGER NOT NULL DEFAULT 0,
            sale_price_wholesale_rial INTEGER NOT NULL DEFAULT 0,
            sale_price_colleague_rial INTEGER NOT NULL DEFAULT 0,
            min_sale_price_rial INTEGER NOT NULL DEFAULT 0,
            suggested_profit_percent REAL NOT NULL DEFAULT 25.0,
            brand TEXT,
            vehicle_compatibility TEXT,
            category TEXT,
            unit TEXT NOT NULL DEFAULT 'عدد',
            shelf_location TEXT,
            min_stock_alert INTEGER NOT NULL DEFAULT 5,
            description TEXT,
            is_active INTEGER NOT NULL DEFAULT 1, -- 1=Active, 0=Soft-Deleted
            created_by TEXT NOT NULL DEFAULT 'admin',
            updated_by TEXT NOT NULL DEFAULT 'admin',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS product_warehouse_stocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            warehouse_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL DEFAULT 0,
            UNIQUE(product_id, warehouse_id)
        );

        CREATE TABLE IF NOT EXISTS product_price_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            old_purchase_rial INTEGER NOT NULL,
            new_purchase_rial INTEGER NOT NULL,
            old_retail_rial INTEGER NOT NULL,
            new_retail_rial INTEGER NOT NULL,
            old_wholesale_rial INTEGER NOT NULL,
            new_wholesale_rial INTEGER NOT NULL,
            old_colleague_rial INTEGER NOT NULL,
            new_colleague_rial INTEGER NOT NULL,
            changed_by TEXT NOT NULL,
            reason TEXT,
            shamsi_datetime TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS product_supplier_aliases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            supplier_id INTEGER,
            supplier_item_name TEXT NOT NULL,
            supplier_item_code TEXT,
            created_by TEXT NOT NULL DEFAULT 'admin',
            created_at TEXT NOT NULL,
            UNIQUE(supplier_id, supplier_item_name)
        );

        CREATE TABLE IF NOT EXISTS parties (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            party_role TEXT NOT NULL, -- 'CUSTOMER', 'SUPPLIER', 'BOTH', 'REPAIR_SHOP'
            customer_type TEXT NOT NULL DEFAULT 'INDIVIDUAL', -- 'INDIVIDUAL' (حقیقی), 'CORPORATE' (حقوقی), 'COLLEAGUE' (همکار/عمده), 'WALK_IN' (متفرقه)
            name TEXT NOT NULL,
            phone TEXT,
            national_id_or_economic_code TEXT,
            address TEXT,
            credit_limit_rial INTEGER NOT NULL DEFAULT 500000000, -- 50M Toman default
            default_price_tier TEXT NOT NULL DEFAULT 'RETAIL', -- 'RETAIL', 'WHOLESALE', 'COLLEAGUE'
            notes TEXT,
            is_system INTEGER NOT NULL DEFAULT 0,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_by TEXT NOT NULL DEFAULT 'admin',
            updated_by TEXT NOT NULL DEFAULT 'admin',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS party_ledger_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            party_id INTEGER NOT NULL,
            shamsi_date TEXT NOT NULL,
            entry_type TEXT NOT NULL, -- 'OPENING', 'PURCHASE_INVOICE', 'PURCHASE_RETURN', 'SALES_INVOICE', 'SALES_RETURN', 'WAREHOUSE_TRANSFER', 'REPAIR_SERVICE', 'PAYMENT_RECEIVED', 'PAYMENT_MADE', 'CHEQUE_CLEARED', 'CHEQUE_BOUNCED'
            reference_type TEXT,
            reference_id INTEGER,
            reference_number TEXT,
            debit_rial INTEGER NOT NULL DEFAULT 0,  -- بدهکار به ما (ما طلبکاریم / پرداخت به تامین کننده / تحویل قطعه به تعمیرگاه)
            credit_rial INTEGER NOT NULL DEFAULT 0, -- بستانکار از ما (ما بدهکاریم / دریافت از مشتری / خدمات تعمیرگاه برای فروشگاه)
            payment_method TEXT,
            description TEXT NOT NULL,
            created_by TEXT NOT NULL DEFAULT 'admin',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS inventory_batches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_code TEXT UNIQUE NOT NULL,
            product_id INTEGER NOT NULL,
            warehouse_id INTEGER NOT NULL DEFAULT 1,
            source_type TEXT NOT NULL, -- 'INITIAL_STOCK', 'PURCHASE_INVOICE', 'TRANSFER_IN', 'SALES_RETURN', 'ADJUSTMENT_IN'
            purchase_invoice_id INTEGER,
            supplier_id INTEGER,
            shamsi_date TEXT NOT NULL,
            initial_qty INTEGER NOT NULL,
            remaining_qty INTEGER NOT NULL,
            unit_cost_rial INTEGER NOT NULL,
            notes TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS purchase_invoices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_number TEXT UNIQUE NOT NULL,
            supplier_invoice_no TEXT,
            supplier_id INTEGER NOT NULL,
            warehouse_id INTEGER NOT NULL DEFAULT 1,
            shamsi_date TEXT NOT NULL,
            source_mode TEXT NOT NULL DEFAULT 'MANUAL', -- 'MANUAL' or 'PDF_OCR'
            pdf_filename TEXT,
            pdf_storage_path TEXT,
            subtotal_rial INTEGER NOT NULL DEFAULT 0,
            discount_rial INTEGER NOT NULL DEFAULT 0,
            total_rial INTEGER NOT NULL DEFAULT 0,
            paid_rial INTEGER NOT NULL DEFAULT 0,
            remaining_rial INTEGER NOT NULL DEFAULT 0,
            payment_method TEXT DEFAULT 'ON_ACCOUNT',
            status TEXT NOT NULL DEFAULT 'FINALIZED', -- 'FINALIZED' (قفل شده), 'RETURNED_PARTIAL', 'RETURNED_FULL'
            notes TEXT,
            created_by TEXT NOT NULL DEFAULT 'admin',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS purchase_invoice_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            purchase_invoice_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            batch_id INTEGER,
            supplier_item_name TEXT,
            product_name_snapshot TEXT NOT NULL,
            barcode_snapshot TEXT,
            qty INTEGER NOT NULL,
            returned_qty INTEGER NOT NULL DEFAULT 0,
            unit_price_rial INTEGER NOT NULL,
            discount_rial INTEGER NOT NULL DEFAULT 0,
            net_unit_cost_rial INTEGER NOT NULL,
            line_total_rial INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS purchase_returns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            return_number TEXT UNIQUE NOT NULL,
            purchase_invoice_id INTEGER NOT NULL,
            supplier_id INTEGER NOT NULL,
            warehouse_id INTEGER NOT NULL,
            shamsi_date TEXT NOT NULL,
            total_return_rial INTEGER NOT NULL,
            reason TEXT,
            items_json TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sales_invoices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_number TEXT UNIQUE NOT NULL,
            customer_id INTEGER NOT NULL,
            warehouse_id INTEGER NOT NULL DEFAULT 1,
            price_tier_used TEXT NOT NULL DEFAULT 'RETAIL',
            shamsi_date TEXT NOT NULL,
            subtotal_rial INTEGER NOT NULL DEFAULT 0,
            row_discount_rial INTEGER NOT NULL DEFAULT 0,
            invoice_discount_rial INTEGER NOT NULL DEFAULT 0,
            total_rial INTEGER NOT NULL DEFAULT 0,
            paid_rial INTEGER NOT NULL DEFAULT 0,
            credit_rial INTEGER NOT NULL DEFAULT 0, -- مانده نسیه به حساب مشتری
            total_cogs_rial INTEGER NOT NULL DEFAULT 0, -- بهای تمام شده واقعی از محموله ها
            real_profit_rial INTEGER NOT NULL DEFAULT 0, -- سود واقعی فاکتور
            has_negative_stock_items INTEGER NOT NULL DEFAULT 0,
            has_below_min_price_items INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'FINALIZED', -- 'FINALIZED', 'RETURNED_PARTIAL', 'RETURNED_FULL'
            template_id INTEGER DEFAULT 1,
            notes TEXT,
            created_by TEXT NOT NULL DEFAULT 'admin',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sales_invoice_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sales_invoice_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            product_name_snapshot TEXT NOT NULL,
            barcode_snapshot TEXT,
            sku_snapshot TEXT,
            vehicle_snapshot TEXT,
            qty INTEGER NOT NULL,
            returned_qty INTEGER NOT NULL DEFAULT 0,
            unit_price_rial INTEGER NOT NULL,
            min_allowed_price_rial INTEGER NOT NULL DEFAULT 0,
            discount_rial INTEGER NOT NULL DEFAULT 0,
            invoice_discount_allocated_rial INTEGER NOT NULL DEFAULT 0,
            net_unit_price_rial INTEGER NOT NULL,
            line_total_rial INTEGER NOT NULL,
            line_cogs_rial INTEGER NOT NULL,
            line_profit_rial INTEGER NOT NULL,
            stock_before_sale INTEGER NOT NULL DEFAULT 0,
            stock_after_sale INTEGER NOT NULL DEFAULT 0,
            is_negative_stock INTEGER NOT NULL DEFAULT 0,
            is_below_min_price INTEGER NOT NULL DEFAULT 0,
            batch_breakdown_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS invoice_payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_type TEXT NOT NULL DEFAULT 'SALE', -- 'SALE' or 'PURCHASE'
            invoice_id INTEGER NOT NULL,
            party_id INTEGER NOT NULL,
            payment_method TEXT NOT NULL, -- 'CASH' (نقدی), 'POS' (کارت خوان), 'CARD_TO_CARD' (کارت به کارت), 'CHEQUE' (چک), 'CREDIT' (نسیه)
            amount_rial INTEGER NOT NULL,
            cheque_id INTEGER,
            reference_no TEXT,
            shamsi_date TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sales_returns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            return_number TEXT UNIQUE NOT NULL,
            sales_invoice_id INTEGER NOT NULL,
            customer_id INTEGER NOT NULL,
            warehouse_id INTEGER NOT NULL,
            shamsi_date TEXT NOT NULL,
            total_return_rial INTEGER NOT NULL,
            total_cogs_restored_rial INTEGER NOT NULL,
            profit_impact_rial INTEGER NOT NULL,
            refund_method TEXT NOT NULL DEFAULT 'ACCOUNT_CREDIT', -- 'ACCOUNT_CREDIT' (کسر از بدهی/بستانکار کردن مشتری) یا 'CASH' (استرداد نقدی)
            reason TEXT,
            items_json TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sales_return_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sales_return_id INTEGER NOT NULL,
            sales_invoice_item_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            qty INTEGER NOT NULL,
            unit_sale_price_rial INTEGER NOT NULL,
            line_total_rial INTEGER NOT NULL,
            unit_cost_rial INTEGER NOT NULL,
            total_cost_rial INTEGER NOT NULL,
            batch_breakdown_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS channel_orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            channel_type TEXT NOT NULL,
            external_order_no TEXT NOT NULL,
            customer_name TEXT NOT NULL,
            customer_phone TEXT,
            status TEXT NOT NULL DEFAULT 'DRAFT',
            payload_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            converted_sales_invoice_id INTEGER,
            UNIQUE(channel_type, external_order_no)
        );

        CREATE TABLE IF NOT EXISTS warehouse_transfers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            transfer_number TEXT UNIQUE NOT NULL,
            from_warehouse_id INTEGER NOT NULL,
            to_warehouse_id INTEGER NOT NULL,
            shamsi_date TEXT NOT NULL,
            post_to_repair_account INTEGER NOT NULL DEFAULT 1, -- 1=ثبت مالی در حساب تعمیرگاه، 0=فقط جابه جایی موجودی
            repair_entry_mode TEXT NOT NULL DEFAULT 'DEBIT_REPAIR', -- 'DEBIT_REPAIR', 'CREDIT_REPAIR', 'NONE'
            total_value_rial INTEGER NOT NULL DEFAULT 0,
            items_json TEXT NOT NULL,
            notes TEXT,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS stock_adjustments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            adjustment_number TEXT UNIQUE NOT NULL,
            warehouse_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            shamsi_date TEXT NOT NULL,
            old_qty INTEGER NOT NULL,
            new_qty INTEGER NOT NULL,
            diff_qty INTEGER NOT NULL,
            unit_cost_rial INTEGER NOT NULL,
            reason TEXT NOT NULL,
            notes TEXT,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS inventory_movements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            warehouse_id INTEGER NOT NULL,
            shamsi_date TEXT NOT NULL,
            movement_type TEXT NOT NULL, -- 'INITIAL', 'PURCHASE', 'PURCHASE_RETURN', 'SALE', 'SALES_RETURN', 'TRANSFER_OUT', 'TRANSFER_IN', 'ADJUSTMENT'
            reference_number TEXT NOT NULL,
            qty_change INTEGER NOT NULL,
            stock_after INTEGER NOT NULL,
            unit_price_or_cost_rial INTEGER NOT NULL DEFAULT 0,
            description TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS cheques (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cheque_type TEXT NOT NULL, -- 'RECEIVED' (دریافتی از مشتری), 'ISSUED' (پرداختی به تامین کننده)
            party_id INTEGER NOT NULL,
            invoice_id INTEGER,
            cheque_number TEXT NOT NULL,
            sayad_id TEXT,
            bank_name TEXT NOT NULL,
            amount_rial INTEGER NOT NULL,
            issue_shamsi_date TEXT NOT NULL,
            due_shamsi_date TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'PENDING', -- 'PENDING' (در جریان), 'CLEARED' (وصول شده), 'BOUNCED' (برگشتی), 'SPENT' (خرج شده)
            is_overdue INTEGER NOT NULL DEFAULT 0,
            notes TEXT,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS print_templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            paper_size TEXT NOT NULL DEFAULT 'A4', -- 'A4' (لیزری HP کامل) یا 'A5_COMPACT' (نیم برگ فشرده)
            is_default INTEGER NOT NULL DEFAULT 0,
            store_name TEXT NOT NULL,
            store_subtitle TEXT,
            store_address TEXT,
            store_phone TEXT,
            social_links TEXT,
            invoice_title TEXT NOT NULL DEFAULT 'فاکتور فروش قطعات و لوازم یدکی خودرو',
            number_prefix TEXT NOT NULL DEFAULT 'INV-1405-',
            number_padding INTEGER NOT NULL DEFAULT 5,
            annual_reset INTEGER NOT NULL DEFAULT 1,
            print_currency TEXT NOT NULL DEFAULT 'TOMAN', -- 'TOMAN' or 'RIAL'
            show_sku INTEGER NOT NULL DEFAULT 1,
            show_barcode INTEGER NOT NULL DEFAULT 1,
            show_vehicle INTEGER NOT NULL DEFAULT 1,
            show_unit_price INTEGER NOT NULL DEFAULT 1,
            show_discount INTEGER NOT NULL DEFAULT 1,
            show_row_total INTEGER NOT NULL DEFAULT 1,
            header_note TEXT,
            warranty_terms TEXT,
            footer_note TEXT,
            show_signature_box INTEGER NOT NULL DEFAULT 1,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT NOT NULL,
            user_role TEXT NOT NULL,
            action_type TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id TEXT,
            description TEXT NOT NULL,
            old_value_json TEXT,
            new_value_json TEXT,
            shamsi_datetime TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS backups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            file_path TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            backup_type TEXT NOT NULL, -- 'AUTO_DAILY' or 'MANUAL'
            shamsi_datetime TEXT NOT NULL,
            last_restore_tested_at TEXT,
            restore_test_status TEXT,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )

    # Lightweight schema evolution for the running MVP database.
    existing_columns = {row[1] for row in cur.execute("PRAGMA table_info(sales_invoice_items)").fetchall()}
    if "invoice_discount_allocated_rial" not in existing_columns:
        cur.execute("ALTER TABLE sales_invoice_items ADD COLUMN invoice_discount_allocated_rial INTEGER NOT NULL DEFAULT 0")
    purchase_columns = {row[1] for row in cur.execute("PRAGMA table_info(purchase_invoices)").fetchall()}
    if "pdf_storage_path" not in purchase_columns:
        cur.execute("ALTER TABLE purchase_invoices ADD COLUMN pdf_storage_path TEXT")

    # Check if already seeded
    count_users = cur.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count_users == 0:
        seed_initial_data(conn)

    conn.commit()
    conn.close()


def seed_initial_data(conn):
    now_iso = datetime.now().isoformat()
    shamsi_today = get_shamsi_date()

    # 1. Users (Section 9: Admin & Salesperson/Operator + Repair Warehouse Role ready)
    conn.executemany(
        """
        INSERT INTO users (username, full_name, password_hash, role, role_label, preferred_currency, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 1, ?)
        """,
        [
            ("admin", "مهندس مهدی رضایی (مدیر فروشگاه)", _seed_password_hash("admin123"), "admin", "مدیر سیستم", "TOMAN", now_iso),
            ("operator", "امیرحسین محمدی (فروشنده و صندوق)", _seed_password_hash("op123"), "operator", "فروشنده / اپراتور", "TOMAN", now_iso),
            ("repair_keeper", "استاد علی کریمی (مسئول تعمیرگاه)", _seed_password_hash("rep123"), "warehouse_repair", "انباردار تعمیرگاه", "TOMAN", now_iso),
        ],
    )

    # 2. API Tokens (Section 3 & 10: Sanctum Token Auth for WooCommerce, Torob, Basalam)
    conn.executemany(
        """
        INSERT INTO api_tokens (user_id, name, channel_type, token, abilities, last_used_at, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 1, ?)
        """,
        [
            (1, "توکن اصلی سایت وردپرس / ووکامرس", "WOOCOMMERCE", "laragon-sanctum-wc-token-1405-9f8a7b6c", "products:read,inventory:read,prices:read,orders:write", "1405/07/11 - 09:30:00", now_iso),
            (1, "توکن موتور جست‌وجوی ترب (Torob API)", "TOROB", "laragon-sanctum-torob-token-1405-3d2e1f", "products:read,inventory:read,prices:read", "1405/07/11 - 08:15:00", now_iso),
            (1, "توکن غرفه باسلام و ربات اینستاگرام", "BASALAM", "laragon-sanctum-basalam-token-1405-7c6b5a", "products:read,inventory:read,prices:read,orders:write", None, now_iso),
        ],
    )

    # 3. System Settings
    settings = [
        ("allow_negative_stock_sale", "1"),
        ("default_display_currency", "TOMAN"),
        ("auto_daily_backup", "1"),
        ("backup_local_path", "backups"),
        ("backup_secondary_path", "D:/Backups/AutoPartsLaragon"),
        ("invoice_seq_counter", "105"),
        ("purchase_seq_counter", "205"),
        ("barcode_seq_counter", "1020"),
    ]
    for k, v in settings:
        conn.execute(
            "INSERT INTO system_settings (key, value, updated_by, updated_at) VALUES (?, ?, 'admin', ?)",
            (k, v, now_iso),
        )

    # 4. Warehouses (Section 2: Store Warehouse & Repair Shop Sub-unit Warehouse)
    conn.executemany(
        """
        INSERT INTO warehouses (id, code, name, description, is_default)
        VALUES (?, ?, ?, ?, ?)
        """,
        [
            (1, "STORE", "انبار فروشگاه مرکزی", "انبار اصلی فروش حضوری و قفسه‌های فروشگاه قطعات خودرو", 1),
            (2, "REPAIR", "انبار واحد تعمیرگاه", "انبار مستقل واحد تعمیرات زیرمجموعه جهت مصرف و خدمات مکانیکی", 0),
        ],
    )

    # 5. Parties (Section 2 & 7: Walk-in, Individual, Corporate, Colleague, Suppliers, and Repair Shop Account)
    parties_data = [
        # ID 1: Walk-in customer (مشتری متفرقه بدون نام)
        (1, "CUSTOMER", "WALK_IN", "مشتری متفرقه (فروش نقدی/حضوری)", "-", "-", "فروش حضوری بدون نام", 0, "RETAIL", "مشتری پیش‌فرض برای فروش‌های نقدی و کارت‌خوان بدون ثبت نام مشتری (فاکتور نسیه برای این حساب مجاز نیست)", 1),
        # ID 2: Repair Shop Independent Account (حساب مستقل تعمیرگاه)
        (2, "REPAIR_SHOP", "COLLEAGUE", "حساب واحد تعمیرگاه زیرمجموعه (استاد علی کریمی)", "09121112233", "0012345678", "جنب فروشگاه - واحد خدمات مکانیکی و جلوبندی", 2000000000, "COLLEAGUE", "حساب مستقل واحد تعمیرات جهت ثبت قطعات تحویلی از فروشگاه (بدهکار) و خدمات انجام‌شده یا برگشت قطعه (بستانکار)", 1),
        # ID 3: Colleague Customer (مشتری همکار)
        (3, "CUSTOMER", "COLLEAGUE", "تعمیرگاه تخصصی برادران محمدی (مشتری همکار)", "09123456789", "0078912345", "خیابان ملت، کوچه کاوه، پلاک ۱۴", 800000000, "COLLEAGUE", "همکار قدیمی - قیمت پیش‌فرض همکار و سقف اعتبار ۸۰ میلیون تومان", 0),
        # ID 4: Corporate Customer (مشتری حقوقی / عمده)
        (4, "CUSTOMER", "CORPORATE", "شرکت حمل‌ونقل و تاکسیرانی شهریار (حقوقی)", "02133445566", "10102030405", "میدان آزادی، بلوار لشگری", 1500000000, "WHOLESALE", "قرارداد تأمین قطعات ناوگان سمند و پژو - قیمت عمده", 0),
        # ID 5: Individual Customer (مشتری حقیقی)
        (5, "CUSTOMER", "INDIVIDUAL", "حسین احمدی (مالک پژو ۲۰۶ تیپ ۵)", "09352223344", "0491122334", "تهرانپارس، فلکه سوم", 150000000, "RETAIL", "مشتری ثابت حقیقی - قیمت خرده", 0),
        # ID 6: Supplier 1 (تأمین‌کننده ۱ - ایساکو/البرز)
        (6, "SUPPLIER", "CORPORATE", "شرکت بازرگانی قطعات یدکی البرز (نمایندگی ایساکو)", "02133998877", "10109988776", "بازار چراغ‌برق، پاساژ کاشانی، طبقه ۲", 0, "WHOLESALE", "تأمین‌کننده اصلی قطعات موتوری و برقی ایساکو و کروز", 0),
        # ID 7: Supplier 2 (تأمین‌کننده ۲ - پخش عظام گستر)
        (7, "SUPPLIER", "CORPORATE", "پخش قطعات خودرو عظام گستر", "02133112244", "10105544332", "خیابان امیرکبیر، پلاک ۲۱۰", 0, "WHOLESALE", "تأمین‌کننده جلوبندی، لنت، دیسک و صفحه و کمک‌فنر", 0),
    ]
    conn.executemany(
        """
        INSERT INTO parties (
            id, party_role, customer_type, name, phone, national_id_or_economic_code,
            address, credit_limit_rial, default_price_tier, notes, is_system, is_active, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
        """,
        [(*p, now_iso) for p in parties_data],
    )

    # 6. Products (Section 4: Parent+Variants, Factory EAN-13 & Internal Code-128 Barcodes, Multi-tier prices in Rial)
    # Note: 1 Toman = 10 Rials. E.g. 850,000 Toman = 8,500,000 Rials.
    products_data = [
        # ID 1: Parent Product (محصول والد غیرقابل فروش مستقیم - لنت ترمز جلو پژو ۲۰۶)
        (1, None, 1, None, "لنت ترمز جلو پژو ۲۰۶ (محصول والد)", "SKU-BRK-206", None, "EAN13", 0, 0, 0, 0, 0, 25.0, "ایساکو / تکستار", "پژو ۲۰۶، پژو ۲۰۷، رانا", "لنت و سیستم ترمز", "دست", "قفسه A - طبقه ۱", 5, "محصول والد شامل متغیرهای تیپ ۲ و تیپ ۵"),
        # ID 2: Variant 1 of ID 1 (متغیر ۱: تیپ ۲)
        (2, 1, 0, "تیپ ۲ (بدون سنسور)", "لنت ترمز جلو پژو ۲۰۶ - تیپ ۲", "SKU-BRK-206-T2", "6260100200301", "EAN13", 6800000, 8800000, 8100000, 7800000, 7500000, 29.4, "تکستار (ایساکو)", "پژو ۲۰۶ تیپ ۲ و ۳", "لنت و سیستم ترمز", "دست", "قفسه A - طبقه ۱ - ردیف ۱", 6, "لنت جلو اصلی بدون سیم سنسور مناسب تیپ ۲"),
        # ID 3: Variant 2 of ID 1 (متغیر ۲: تیپ ۵)
        (3, 1, 0, "تیپ ۵ (سنسوردار دیسکی)", "لنت ترمز جلو پژو ۲۰۶ - تیپ ۵", "SKU-BRK-206-T5", "6260100200302", "EAN13", 8200000, 10800000, 9900000, 9500000, 9100000, 31.7, "تکستار (ایساکو)", "پژو ۲۰۶ تیپ ۵، پژو ۲۰۷، رانا پلاس", "لنت و سیستم ترمز", "دست", "قفسه A - طبقه ۱ - ردیف ۲", 8, "لنت جلو سنسوردار اورجینال مناسب تیپ ۵ و ۲۰۷"),
        # ID 4: Regular Product with EAN-13
        (4, None, 0, None, "کیت کلاچ (دیسک و صفحه و بلبرینگ) پژو ۴۰۵ و پارس", "SKU-CLT-405", "6260100200401", "EAN13", 36000000, 44500000, 41800000, 40500000, 39500000, 23.6, "والئو (Valeo)", "پژو ۴۰۵، پژو پارس، سمند XU7", "موتوری و گیربکس", "دست", "قفسه B - طبقه ۲ - ردیف ۱", 4, "کیت کامل کلاچ والئو جعبه سبز اصلی"),
        # ID 5: Regular Product with EAN-13
        (5, None, 0, None, "شمع موتور سوزنی ایریدیوم پایه بلند (بسته ۴ عددی)", "SKU-SPK-IR4", "6260100200501", "EAN13", 14500000, 18900000, 17400000, 16800000, 16200000, 30.3, "بوش (Bosch)", "دنا پلاس، سمند EF7، پژو ۲۰۶ تیپ ۵", "برق و انژکتور", "دست", "قفسه C - طبقه ۱ - ردیف ۳", 5, "شمع بوش آلمان پایه بلند مناسب موتورهای EF7 و TU5"),
        # ID 6: Product with Internal Code-128 Barcode (تولید داخلی برای برچسب)
        (6, None, 0, None, "تسمه تایم ۱۱۴ دندانه سمند موتور ملی EF7", "SKU-BLT-EF7", "AP-1405-1001", "CODE128", 11200000, 14600000, 13500000, 12900000, 12500000, 30.4, "کنتیننتال / عظام", "سمند EF7، دنا، دنا پلاس", "موتوری و گیربکس", "عدد", "قفسه B - طبقه ۱ - ردیف ۴", 5, "دارای بارکد داخلی Code 128 جهت چاپ لیبل فروشگاه"),
        # ID 7: Fast-moving Product (فیلتر روغن)
        (7, None, 0, None, "فیلتر روغن فلزی پژو ۴۰۵ / پارس / سمند XU7", "SKU-FLT-OIL1", "6260100200701", "EAN13", 950000, 1350000, 1180000, 1120000, 1080000, 42.1, "سرکان (Serkan)", "پژو ۴۰۵، پارس، سمند XU7", "فیلتر و روغن", "عدد", "قفسه D - طبقه ۱ - ردیف ۱", 15, "فیلتر روغن استاندارد با سوپاپ اطمینان"),
        # ID 8: Low-stock Product (کم‌موجودی جهت نمایش در داشبورد)
        (8, None, 0, None, "کمک‌فنر جلو گازی پژو ۲۰۶ و ۲۰۷ (چپ و راست)", "SKU-SHK-206", "6260100200801", "EAN13", 16500000, 21000000, 19600000, 18900000, 18200000, 27.3, "عظام (Ezam)", "پژو ۲۰۶، پژو ۲۰۷", "جلوبندی و تعلیق", "عدد", "قفسه E - طبقه ۳ - ردیف ۲", 6, "کمک‌فنر گازی روغنی با ۱۲ ماه ضمانت عظام"),
        # ID 9: Zero-stock Product (موجودی صفر جهت آزمایش فروش با موجودی منفی!)
        (9, None, 0, None, "واترپمپ کامل پژو ۲۰۶ تیپ ۵ (پروانه فلزی)", "SKU-WTP-TU5", "AP-1405-1002", "CODE128", 9800000, 12800000, 11900000, 11400000, 11000000, 30.6, "ایساکو (ISACO)", "پژو ۲۰۶ تیپ ۵، رانا، ۲۰۷، پارس TU5", "موتوری و گیربکس", "عدد", "قفسه B - طبقه ۳ - ردیف ۲", 4, "موجودی فعلی صفر است - مناسب تست فروش با موجودی منفی و هشدار"),
        # ID 10: Motor Oil
        (10, None, 0, None, "روغن موتور بهران سوپر پیشتاز 10W-40 (گالن ۴ لیتری)", "SKU-OIL-BHR4", "6260100201001", "EAN13", 5400000, 6800000, 6300000, 6100000, 5900000, 25.9, "بهران (Behran)", "انواع خودروهای پژو، سمند، پراید، تیبا", "فیلتر و روغن", "گالن", "قفسه D - طبقه ۲ - ردیف ۱", 10, "روغن نیمه‌سنتتیک API SL/CF"),
    ]
    conn.executemany(
        """
        INSERT INTO products (
            id, parent_id, is_parent, variant_label, name, sku, barcode, barcode_type,
            purchase_price_rial, sale_price_retail_rial, sale_price_wholesale_rial, sale_price_colleague_rial,
            min_sale_price_rial, suggested_profit_percent, brand, vehicle_compatibility, category,
            unit, shelf_location, min_stock_alert, description, is_active, created_by, updated_by, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'admin', 'admin', ?, ?)
        """,
        [(*p, now_iso, now_iso) for p in products_data],
    )

    # 7. Supplier Aliases (Section 5: نام مستعار کالا در فاکتور تامین‌کننده جهت تطبیق خودکار OCR/PDF)
    aliases_data = [
        (3, 6, "لنت جلو 206 تيپ5 سنسوردار تکستار ايساکو", "ISC-2065"),
        (5, 6, "دست شمع سوزني بوش آلمان پايه بلند FR7DE", "BSH-IR4"),
        (7, 6, "فيلتر روغن پژو 405 سرکان اصلي", "SRK-405"),
        (4, 7, "کيت کامل کلاچ 405/پارس والئو سبز", "VAL-405"),
        (8, 7, "کمک جلو 206 گازي عظام کد 108", "EZM-206F"),
        (3, 6, "ISC-2065", "ISC-2065"),
        (4, 7, "CLUTCH-405", "CLUTCH-405"),
        (8, 7, "SHOCK-206", "SHOCK-206"),
    ]
    conn.executemany(
        """
        INSERT INTO product_supplier_aliases (product_id, supplier_id, supplier_item_name, supplier_item_code, created_by, created_at)
        VALUES (?, ?, ?, ?, 'admin', ?)
        """,
        [(*a, now_iso) for a in aliases_data],
    )

    # 8. Initial Warehouse Stocks & FIFO Batches (Section 8: اثبات سود واقعی بر مبنای قیمت خرید واقعی هر محموله!)
    # Notice Product ID 3 (لنت ترمز جلو پژو ۲۰۶ - تیپ ۵) has TWO batches at different purchase prices:
    # Batch 1 (1405/07/02): 4 units bought at 7,800,000 Rial (780,000 Toman) -> 2 remaining
    # Batch 2 (1405/07/08): 10 units bought at 8,200,000 Rial (820,000 Toman) -> 10 remaining
    # When someone sells 5 units of Product ID 3, FIFO automatically consumes 2 units @ 7,800,000 + 3 units @ 8,200,000!
    stocks = [
        # (product_id, store_qty, repair_qty)
        (1, 0, 0),
        (2, 14, 3),
        (3, 12, 4),
        (4, 6, 1),
        (5, 10, 2),
        (6, 8, 2),
        (7, 28, 6),
        (8, 3, 1),  # Low stock (3 < min_stock_alert 6)
        (9, 0, 0),  # Zero stock for testing negative stock sale
        (10, 16, 4),
    ]
    for pid, store_q, rep_q in stocks:
        conn.execute(
            "INSERT INTO product_warehouse_stocks (product_id, warehouse_id, quantity) VALUES (?, 1, ?)",
            (pid, store_q),
        )
        conn.execute(
            "INSERT INTO product_warehouse_stocks (product_id, warehouse_id, quantity) VALUES (?, 2, ?)",
            (pid, rep_q),
        )

    # Create Purchase Invoices & FIFO Batches
    conn.execute(
        """
        INSERT INTO purchase_invoices (
            id, invoice_number, supplier_invoice_no, supplier_id, warehouse_id, shamsi_date,
            source_mode, pdf_filename, subtotal_rial, discount_rial, total_rial, paid_rial, remaining_rial,
            payment_method, status, notes, created_by, created_at
        ) VALUES
        (1, 'PUR-1405-00201', 'F-88410', 6, 1, '1405/07/02', 'MANUAL', NULL, 253700000, 2800000, 250900000, 158000000, 92900000, 'PARTIAL_POS', 'FINALIZED', 'خرید محموله اول مهرماه از بازرگانی البرز (ایساکو)', 'admin', ?),
        (2, 'PUR-1405-00202', 'EZ-9920', 7, 1, '1405/07/08', 'PDF_OCR', 'factor_scan_ocr_ezam_1405_01.pdf', 365500000, 1500000, 364000000, 200000000, 164000000, 'CHEQUE_AND_CASH', 'FINALIZED', 'ورود از فایل PDF اسکن‌شده با OCR فارسی پس از بازبینی و تطبیق نام مستعار', 'admin', ?)
        """,
        (now_iso, now_iso),
    )

    batches_data = [
        # (id, batch_code, product_id, warehouse_id, source_type, purchase_invoice_id, supplier_id, shamsi_date, initial_qty, remaining_qty, unit_cost_rial, notes)
        (1, "LOT-1405-001", 2, 1, "PURCHASE_INVOICE", 1, 6, "1405/07/02", 15, 14, 6800000, "محموله اول لنت تیپ ۲ - ۶۸۰,۰۰۰ تومان"),
        (2, "LOT-1405-002", 3, 1, "PURCHASE_INVOICE", 1, 6, "1405/07/02", 8, 2, 7800000, "محموله قدیم لنت تیپ ۵ با قیمت خرید قبلی ۷۸۰,۰۰۰ تومان (۲ عدد باقی‌مانده)"),
        (3, "LOT-1405-003", 3, 1, "PURCHASE_INVOICE", 2, 7, "1405/07/08", 10, 10, 8200000, "محموله جدید لنت تیپ ۵ با قیمت خرید جدید ۸۲۰,۰۰۰ تومان (۱۰ عدد باز)"),
        (4, "LOT-1405-004", 4, 1, "PURCHASE_INVOICE", 2, 7, "1405/07/08", 7, 6, 36000000, "محموله کیت کلاچ والئو - ۳,۶۰۰,۰۰۰ تومان"),
        (5, "LOT-1405-005", 5, 1, "PURCHASE_INVOICE", 1, 6, "1405/07/02", 12, 10, 14500000, "محموله شمع بوش آلمان - ۱,۴۵۰,۰۰۰ تومان"),
        (6, "LOT-1405-006", 6, 1, "INITIAL_STOCK", None, 6, "1405/07/01", 8, 8, 11200000, "موجودی اولیه تسمه تایم EF7"),
        (7, "LOT-1405-007", 7, 1, "PURCHASE_INVOICE", 1, 6, "1405/07/02", 30, 28, 950000, "محموله فیلتر روغن سرکان - ۹۵,۰۰۰ تومان"),
        (8, "LOT-1405-008", 8, 1, "PURCHASE_INVOICE", 2, 7, "1405/07/08", 4, 3, 16500000, "محموله کمک‌فنر عظام - ۱,۶۵۰,۰۰۰ تومان"),
        (9, "LOT-1405-009", 10, 1, "INITIAL_STOCK", None, None, "1405/07/01", 18, 16, 5400000, "محموله روغن بهران سوپر پیشتاز - ۵۴۰,۰۰۰ تومان"),
        # Repair shop batches
        (10, "LOT-1405-R01", 2, 2, "TRANSFER_IN", None, None, "1405/07/05", 3, 3, 6800000, "انتقالی به انبار تعمیرگاه"),
        (11, "LOT-1405-R02", 3, 2, "TRANSFER_IN", None, None, "1405/07/05", 4, 4, 7800000, "انتقالی به انبار تعمیرگاه"),
        (12, "LOT-1405-R03", 4, 2, "TRANSFER_IN", None, None, "1405/07/06", 1, 1, 36000000, "انتقالی به انبار تعمیرگاه"),
        (13, "LOT-1405-R04", 5, 2, "TRANSFER_IN", None, None, "1405/07/06", 2, 2, 14500000, "انتقالی به انبار تعمیرگاه"),
        (14, "LOT-1405-R05", 6, 2, "TRANSFER_IN", None, None, "1405/07/06", 2, 2, 11200000, "انتقالی به انبار تعمیرگاه"),
        (15, "LOT-1405-R06", 7, 2, "TRANSFER_IN", None, None, "1405/07/06", 6, 6, 950000, "انتقالی به انبار تعمیرگاه"),
        (16, "LOT-1405-R07", 8, 2, "TRANSFER_IN", None, None, "1405/07/06", 1, 1, 16500000, "انتقالی به انبار تعمیرگاه"),
        (17, "LOT-1405-R08", 10, 2, "TRANSFER_IN", None, None, "1405/07/06", 4, 4, 5400000, "انتقالی به انبار تعمیرگاه"),
    ]
    conn.executemany(
        """
        INSERT INTO inventory_batches (
            id, batch_code, product_id, warehouse_id, source_type, purchase_invoice_id,
            supplier_id, shamsi_date, initial_qty, remaining_qty, unit_cost_rial, notes, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [(*b, now_iso) for b in batches_data],
    )

    # Purchase Invoice Items for the 2 seeded purchase invoices
    conn.executemany(
        """
        INSERT INTO purchase_invoice_items (
            purchase_invoice_id, product_id, batch_id, supplier_item_name, product_name_snapshot,
            barcode_snapshot, qty, returned_qty, unit_price_rial, discount_rial, net_unit_cost_rial, line_total_rial
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
        """,
        [
            (1, 2, 1, "لنت جلو 206 تيپ2 تکستار", "لنت ترمز جلو پژو ۲۰۶ - تیپ ۲", "6260100200301", 15, 6900000, 1500000, 6800000, 102000000),
            (1, 3, 2, "لنت جلو 206 تيپ5 سنسوردار تکستار ايساکو", "لنت ترمز جلو پژو ۲۰۶ - تیپ ۵", "6260100200302", 8, 7900000, 800000, 7800000, 62400000),
            (1, 5, 5, "دست شمع سوزني بوش آلمان پايه بلند FR7DE", "شمع موتور سوزنی ایریدیوم پایه بلند (بسته ۴ عددی)", "6260100200501", 4, 14625000, 500000, 14500000, 58000000),
            (1, 7, 7, "فيلتر روغن پژو 405 سرکان اصلي", "فیلتر روغن فلزی پژو ۴۰۵ / پارس / سمند XU7", "6260100200701", 30, 950000, 0, 950000, 28500000),
            (2, 3, 3, "لنت جلو 206 تيپ5 سنسوردار تکستار ايساکو", "لنت ترمز جلو پژو ۲۰۶ - تیپ ۵", "6260100200302", 10, 8350000, 1500000, 8200000, 82000000),
            (2, 4, 4, "کيت کامل کلاچ 405/پارس والئو سبز", "کیت کلاچ (دیسک و صفحه و بلبرینگ) پژو ۴۰۵ و پارس", "6260100200401", 6, 36000000, 0, 36000000, 216000000),
            (2, 8, 8, "کمک جلو 206 گازي عظام کد 108", "کمک‌فنر جلو گازی پژو ۲۰۶ و ۲۰۷ (چپ و راست)", "6260100200801", 4, 16500000, 0, 16500000, 66000000),
        ],
    )

    # 9. Sample Sales Invoices (including today's sales, colleague pricing, and a negative stock sale warning example)
    conn.executemany(
        """
        INSERT INTO sales_invoices (
            id, invoice_number, customer_id, warehouse_id, price_tier_used, shamsi_date,
            subtotal_rial, row_discount_rial, invoice_discount_rial, total_rial, paid_rial, credit_rial,
            total_cogs_rial, real_profit_rial, has_negative_stock_items, has_below_min_price_items,
            status, template_id, notes, created_by, created_at
        ) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'FINALIZED', 1, ?, 'admin', ?)
        """,
        [
            # Sale 1: Today to Colleague Customer (تعمیرگاه برادران محمدی) - Colleague pricing + partial credit
            (
                1, "INV-1405-00101", 3, "COLLEAGUE", "1405/07/11",
                59500000, 500000, 0, 59000000, 35000000, 24000000,
                51600000, 7400000, 0,
                "فروش همکار به تعمیرگاه برادران محمدی (بخشی کارت‌خوان و مابقی نسیه)", now_iso
            ),
            # Sale 2: Today to Individual Customer (حسین احمدی) - Retail pricing, Paid in full via POS
            (
                2, "INV-1405-00102", 5, "RETAIL", "1405/07/11",
                28950000, 450000, 0, 28500000, 28500000, 0,
                21800000, 6700000, 0,
                "فروش سرویس دوره‌ای و شمع و روغن پژو ۲۰۶ تیپ ۵", now_iso
            ),
            # Sale 3: Earlier this month to Corporate Customer (تاکسیرانی شهریار) - Wholesale pricing
            (
                3, "INV-1405-00103", 4, "WHOLESALE", "1405/07/06",
                55500000, 700000, 0, 54800000, 27000000, 27800000,
                46600000, 8200000, 0,
                "تأمین قطعات ناوگان سمند و پژو - پرداخت چک و حساب باز", now_iso
            ),
        ],
    )

    # Sales Invoice Items with exact Batch Breakdown JSON
    sale_items_data = [
        # Sale 1 items:
        (
            1, 4, "کیت کلاچ (دیسک و صفحه و بلبرینگ) پژو ۴۰۵ و پارس", "6260100200401", "SKU-CLT-405", "پژو ۴۰۵، پارس",
            1, 40500000, 39500000, 500000, 40000000, 40000000, 36000000, 4000000, 7, 6, 0,
            json.dumps([{"batch_code": "LOT-1405-004", "qty": 1, "unit_cost_rial": 36000000, "total_cost_rial": 36000000}], ensure_ascii=False)
        ),
        (
            1, 3, "لنت ترمز جلو پژو ۲۰۶ - تیپ ۵", "6260100200302", "SKU-BRK-206-T5", "پژو ۲۰۶ تیپ ۵",
            2, 9500000, 9100000, 0, 9500000, 19000000, 15600000, 3400000, 14, 12, 0,
            json.dumps([{"batch_code": "LOT-1405-002", "qty": 2, "unit_cost_rial": 7800000, "total_cost_rial": 15600000}], ensure_ascii=False)
        ),
        # Sale 2 items:
        (
            2, 5, "شمع موتور سوزنی ایریدیوم پایه بلند (بسته ۴ عددی)", "6260100200501", "SKU-SPK-IR4", "پژو ۲۰۶ تیپ ۵، EF7",
            1, 18900000, 16200000, 400000, 18500000, 18500000, 14500000, 4000000, 11, 10, 0,
            json.dumps([{"batch_code": "LOT-1405-005", "qty": 1, "unit_cost_rial": 14500000, "total_cost_rial": 14500000}], ensure_ascii=False)
        ),
        (
            2, 10, "روغن موتور بهران سوپر پیشتاز 10W-40 (گالن ۴ لیتری)", "6260100201001", "SKU-OIL-BHR4", "عمومی",
            1, 6800000, 5900000, 0, 6800000, 6800000, 5400000, 1400000, 17, 16, 0,
            json.dumps([{"batch_code": "LOT-1405-009", "qty": 1, "unit_cost_rial": 5400000, "total_cost_rial": 5400000}], ensure_ascii=False)
        ),
        (
            2, 7, "فیلتر روغن فلزی پژو ۴۰۵ / پارس / سمند XU7", "6260100200701", "SKU-FLT-OIL1", "پژو، سمند",
            2, 1350000, 1080000, 50000, 1600000, 3200000, 1900000, 1300000, 30, 28, 0,
            json.dumps([{"batch_code": "LOT-1405-007", "qty": 2, "unit_cost_rial": 950000, "total_cost_rial": 1900000}], ensure_ascii=False)
        ),
        # Sale 3 items:
        (
            3, 8, "کمک‌فنر جلو گازی پژو ۲۰۶ و ۲۰۷ (چپ و راست)", "6260100200801", "SKU-SHK-206", "پژو ۲۰۶",
            2, 19600000, 18200000, 400000, 19400000, 38800000, 33000000, 5800000, 5, 3, 0,
            json.dumps([{"batch_code": "LOT-1405-008", "qty": 2, "unit_cost_rial": 16500000, "total_cost_rial": 33000000}], ensure_ascii=False)
        ),
        (
            3, 2, "لنت ترمز جلو پژو ۲۰۶ - تیپ ۲", "6260100200301", "SKU-BRK-206-T2", "پژو ۲۰۶ تیپ ۲",
            2, 8100000, 7500000, 200000, 8000000, 16000000, 13600000, 2400000, 16, 14, 0,
            json.dumps([{"batch_code": "LOT-1405-001", "qty": 2, "unit_cost_rial": 6800000, "total_cost_rial": 13600000}], ensure_ascii=False)
        ),
    ]
    conn.executemany(
        """
        INSERT INTO sales_invoice_items (
            sales_invoice_id, product_id, product_name_snapshot, barcode_snapshot, sku_snapshot, vehicle_snapshot,
            qty, returned_qty, unit_price_rial, min_allowed_price_rial, discount_rial, net_unit_price_rial,
            line_total_rial, line_cogs_rial, line_profit_rial, stock_before_sale, stock_after_sale,
            is_negative_stock, is_below_min_price, batch_breakdown_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
        """,
        sale_items_data,
    )

    # Invoice Payments
    conn.executemany(
        """
        INSERT INTO invoice_payments (invoice_type, invoice_id, party_id, payment_method, amount_rial, cheque_id, reference_no, shamsi_date, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'admin', ?)
        """,
        [
            ("SALE", 1, 3, "POS", 35000000, None, "POS-77412", "1405/07/11", now_iso),
            ("SALE", 1, 3, "CREDIT", 24000000, None, "CREDIT-101", "1405/07/11", now_iso),
            ("SALE", 2, 5, "POS", 28500000, None, "POS-77419", "1405/07/11", now_iso),
            ("SALE", 3, 4, "CHEQUE", 27000000, 1, "CHQ-998120", "1405/07/06", now_iso),
            ("SALE", 3, 4, "CREDIT", 27800000, None, "CREDIT-103", "1405/07/06", now_iso),
            ("PURCHASE", 1, 6, "CARD_TO_CARD", 158000000, None, "PAY-1405-11", "1405/07/02", now_iso),
            ("PURCHASE", 2, 7, "CHEQUE", 120000000, 3, "771005", "1405/07/08", now_iso),
            ("PURCHASE", 2, 7, "CASH", 80000000, None, "CASH-PUR-202", "1405/07/08", now_iso),
        ],
    )

    # 10. Warehouse Transfer & Repair Shop Ledger (Section 2 & 7: انتقال کالا به تعمیرگاه + خدمات تعمیرگاه)
    conn.execute(
        """
        INSERT INTO warehouse_transfers (
            id, transfer_number, from_warehouse_id, to_warehouse_id, shamsi_date,
            post_to_repair_account, repair_entry_mode, total_value_rial, items_json, notes, created_by, created_at
        ) VALUES (
            1, 'TRF-1405-001', 1, 2, '1405/07/05', 1, 'DEBIT_REPAIR', 87600000, ?,
            'تحویل قطعات پرمصرف از انبار فروشگاه به انبار تعمیرگاه (ثبت بدهکار در حساب تعمیرگاه)', 'admin', ?
        )
        """,
        (
            json.dumps(
                [
                    {"product_id": 2, "product_name": "لنت ترمز جلو پژو ۲۰۶ - تیپ ۲", "qty": 3, "unit_price_rial": 6800000, "line_total_rial": 20400000},
                    {"product_id": 3, "product_name": "لنت ترمز جلو پژو ۲۰۶ - تیپ ۵", "qty": 4, "unit_price_rial": 7800000, "line_total_rial": 31200000},
                    {"product_id": 4, "product_name": "کیت کلاچ پژو ۴۰۵ و پارس", "qty": 1, "unit_price_rial": 36000000, "line_total_rial": 36000000},
                ],
                ensure_ascii=False,
            ),
            now_iso,
        ),
    )

    # 11. Party Ledger Entries (Strictly reconciled with every invoice, transfer, service & payment!)
    # Remember: debit_rial = بدهکار به فروشگاه (owes store), credit_rial = بستانکار از فروشگاه (store owes them)
    ledger_rows = [
        # Party 2: Repair Shop (حساب مستقل تعمیرگاه)
        # 1) Received parts from Store (TRF-1405-001): Debit 87,600,000 Rial
        (2, "1405/07/05", "WAREHOUSE_TRANSFER", "TRANSFER", 1, "TRF-1405-001", 87600000, 0, "INTERNAL", "تحویل قطعات از انبار فروشگاه به تعمیرگاه طبق سند انتقال TRF-1405-001"),
        # 2) Performed mechanical service for Store's warranty customer: Credit 22,000,000 Rial
        (2, "1405/07/07", "REPAIR_SERVICE", "SERVICE", 101, "SRV-1405-01", 0, 22000000, "SERVICE", "اجرت تعویض دیسک و صفحه و جلوبندی خودروی مشتری ضمانتی فروشگاه (بستانکار تعمیرگاه)"),
        # 3) Cash/Card settlement from Repair Shop to Store: Credit 30,000,000 Rial
        (2, "1405/07/09", "PAYMENT_RECEIVED", "SETTLEMENT", 201, "REC-1405-01", 0, 30000000, "CARD_TO_CARD", "واریز کارت به کارت توسط استاد کریمی بابت بخشی از حساب قطعات تحویلی"),
        # Net Repair Shop Balance = 87,600,000 - 52,000,000 = +35,600,000 Rial (3,560,000 Toman بدهکار به فروشگاه)

        # Party 3: Colleague Customer (تعمیرگاه برادران محمدی)
        (3, "1405/07/11", "SALES_INVOICE", "SALE", 1, "INV-1405-00101", 59000000, 0, "INVOICE", "فاکتور فروش همکار INV-1405-00101"),
        (3, "1405/07/11", "PAYMENT_RECEIVED", "SALE_PAYMENT", 1, "POS-77412", 0, 35000000, "POS", "دریافت از طریق کارت‌خوان بابت فاکتور INV-1405-00101"),
        # Net Party 3 Balance = +24,000,000 Rial (2,400,000 Toman بدهکار)

        # Party 4: Corporate Customer (تاکسیرانی شهریار)
        (4, "1405/07/06", "SALES_INVOICE", "SALE", 3, "INV-1405-00103", 54800000, 0, "INVOICE", "فاکتور فروش عمده INV-1405-00103"),
        (4, "1405/07/06", "PAYMENT_RECEIVED", "SALE_PAYMENT", 3, "CHQ-998120", 0, 27000000, "CHEQUE", "دریافت چک صیادی شماره 998120 سررسید 1405/07/10 بابت فاکتور INV-1405-00103"),
        # Net Party 4 Balance = +30,000,000 Rial (3,000,000 Toman بدهکار)

        # Party 5: Individual Customer (حسین احمدی)
        (5, "1405/07/11", "SALES_INVOICE", "SALE", 2, "INV-1405-00102", 28500000, 0, "INVOICE", "فاکتور فروش خرده INV-1405-00102"),
        (5, "1405/07/11", "PAYMENT_RECEIVED", "SALE_PAYMENT", 2, "POS-77419", 0, 28500000, "POS", "تسویه کامل کارت‌خوان بابت فاکتور INV-1405-00102"),
        # Net Party 5 Balance = 0 Rial (تسویه کامل)

        # Party 6: Supplier 1 (بازرگانی البرز - ایساکو)
        (6, "1405/07/02", "PURCHASE_INVOICE", "PURCHASE", 1, "PUR-1405-00201", 0, 250900000, "INVOICE", "فاکتور خرید قطعات PUR-1405-00201 (شماره فاکتور تأمین‌کننده F-88410)"),
        (6, "1405/07/02", "PAYMENT_MADE", "PURCHASE_PAYMENT", 1, "PAY-1405-11", 158000000, 0, "CARD_TO_CARD", "پرداخت بخشی از فاکتور خرید PUR-1405-00201"),
        # Net Party 6 Balance = -100,000,000 Rial (10,000,000 Toman بستانکار از ما)

        # Party 7: Supplier 2 (پخش عظام گستر)
        (7, "1405/07/08", "PURCHASE_INVOICE", "PURCHASE", 2, "PUR-1405-00202", 0, 364000000, "INVOICE", "فاکتور خرید PDF/OCR شماره PUR-1405-00202"),
        (7, "1405/07/08", "PAYMENT_MADE", "PURCHASE_PAYMENT", 2, "PAY-1405-18", 200000000, 0, "CHEQUE", "پرداخت چک و نقد بابت فاکتور خرید PUR-1405-00202"),
        # Net Party 7 Balance = -162,000,000 Rial (16,200,000 Toman بستانکار از ما)
    ]
    conn.executemany(
        """
        INSERT INTO party_ledger_entries (
            party_id, shamsi_date, entry_type, reference_type, reference_id, reference_number,
            debit_rial, credit_rial, payment_method, description, created_by, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'admin', ?)
        """,
        [(*r, now_iso) for r in ledger_rows],
    )

    # 12. Cheques (Section 7 & 8: چک‌های سررسیدشده و درجریان برای نمایش در داشبورد و امور مالی)
    cheques_data = [
        (1, "RECEIVED", 4, 3, "998120", "2100049981200001", "بانک ملت", 27000000, "1405/07/06", "1405/07/10", "PENDING", 1, "چک دریافتی از شرکت تاکسیرانی شهریار - سررسید گذشته (نیاز به واگذاری به بانک)"),
        (2, "RECEIVED", 3, None, "445210", "2100084452100009", "بانک صادرات", 45000000, "1405/07/04", "1405/07/11", "PENDING", 1, "چک دریافتی از تعمیرگاه برادران محمدی - سررسید امروز ۱۱ مهر ۱۴۰۵"),
        (3, "ISSUED", 7, 2, "771005", "2100017710050004", "بانک ملی", 120000000, "1405/07/08", "1405/07/25", "PENDING", 0, "چک پرداختی فروشگاه به پخش عظام گستر بابت محموله دوم"),
        (4, "RECEIVED", 3, None, "310988", "2100093109880002", "بانک تجارت", 18000000, "1405/06/20", "1405/07/01", "CLEARED", 0, "چک وصول‌شده اول مهرماه"),
    ]
    conn.executemany(
        """
        INSERT INTO cheques (
            id, cheque_type, party_id, invoice_id, cheque_number, sayad_id, bank_name,
            amount_rial, issue_shamsi_date, due_shamsi_date, status, is_overdue, notes, created_by, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'admin', ?)
        """,
        [(*c, now_iso) for c in cheques_data],
    )

    # 13. Customizable Print Templates (Section 6: قالب لیزری HP A4 و قالب نیم‌برگ فشرده A5)
    templates_data = [
        (
            1,
            "قالب رسمی و کامل A4 (مخصوص چاپگر لیزری HP)",
            "A4",
            1,
            "فروشگاه و تعمیرگاه تخصصی قطعات خودرو البرز پارت",
            "عرضه‌کننده قطعات اصلی ایساکو، عظام، کروز، والئو و بوش",
            "تهران، خیابان امیرکبیر (چراغ‌برق)، نرسیده به سه‌راه ملت، پلاک ۱۴۲",
            "۰۲۱-۳۳۹۹۴۴۵۵ | ۰۹۱۲-۱۱۱۲۲۳۳",
            "اینستاگرام: @alborzpart_auto | تلگرام و واتساپ: ۰۹۱۲۱۱۱۲۲۳۳",
            "فاکتور فروش کالا و قطعات یدکی خودرو",
            "INV-1405-",
            5,
            1,
            "TOMAN",
            1, 1, 1, 1, 1, 1,
            "کلیه قطعات برقی و انژکتوری پیش از نصب تست شوند.",
            "ضمانت اصالت کالا: قطعات مکانیکی و جلوبندی تا ۷ روز با ارائه این فاکتور و سالم بودن کارتن قابل تعویض می‌باشند.",
            "از خرید و اعتماد شما سپاسگزاریم — سامانه جامع حسابداری البرز پارت",
            1,
            now_iso,
        ),
        (
            2,
            "قالب فشرده نیم‌برگ A5 (سریع و کم‌مصرف)",
            "A5_COMPACT",
            0,
            "فروشگاه قطعات یدکی البرز پارت",
            "پخش خرده و همکار قطعات یدکی خودرو",
            "خیابان امیرکبیر، پلاک ۱۴۲",
            "۰۲۱-۳۳۹۹۴۴۵۵",
            "واتساپ ارسال فاکتور: ۰۹۱۲۱۱۱۲۲۳۳",
            "فاکتور فروش (چاپ فشرده نیم‌برگ)",
            "INV-1405-",
            5,
            1,
            "TOMAN",
            0, 0, 1, 1, 1, 1,
            "فاکتور فروش سریع حضوری",
            "مهلت مرجوعی قطعات غیربرقی ۴۸ ساعت با حفظ بسته‌بندی اصلی است.",
            "با تشکر از خرید شما",
            1,
            now_iso,
        ),
    ]
    conn.executemany(
        """
        INSERT INTO print_templates (
            id, name, paper_size, is_default, store_name, store_subtitle, store_address, store_phone,
            social_links, invoice_title, number_prefix, number_padding, annual_reset, print_currency,
            show_sku, show_barcode, show_vehicle, show_unit_price, show_discount, show_row_total,
            header_note, warranty_terms, footer_note, show_signature_box, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        templates_data,
    )

    # 14. Inventory Movements (Kardex)
    movements_data = [
        (3, 1, "1405/07/02", "PURCHASE", "PUR-1405-00201", 8, 8, 7800000, "خرید محموله اول از بازرگانی البرز (ایساکو)", "admin", now_iso),
        (3, 1, "1405/07/05", "TRANSFER_OUT", "TRF-1405-001", -4, 4, 7800000, "انتقال از انبار فروشگاه به انبار تعمیرگاه", "admin", now_iso),
        (3, 2, "1405/07/05", "TRANSFER_IN", "TRF-1405-001", 4, 4, 7800000, "دریافت در انبار تعمیرگاه از انبار فروشگاه", "admin", now_iso),
        (3, 1, "1405/07/08", "PURCHASE", "PUR-1405-00202", 10, 14, 8200000, "خرید محموله دوم از پخش عظام گستر (PDF/OCR)", "admin", now_iso),
        (3, 1, "1405/07/11", "SALE", "INV-1405-00101", -2, 12, 9500000, "فروش همکار به تعمیرگاه برادران محمدی (مصرف از محموله LOT-1405-002)", "admin", now_iso),
        (4, 1, "1405/07/08", "PURCHASE", "PUR-1405-00202", 7, 7, 36000000, "خرید کیت کلاچ والئو از پخش عظام گستر", "admin", now_iso),
        (4, 1, "1405/07/11", "SALE", "INV-1405-00101", -1, 6, 40000000, "فروش همکار به تعمیرگاه برادران محمدی", "admin", now_iso),
    ]
    conn.executemany(
        """
        INSERT INTO inventory_movements (
            product_id, warehouse_id, shamsi_date, movement_type, reference_number,
            qty_change, stock_after, unit_price_or_cost_rial, description, created_by, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        movements_data,
    )

    # 15. Initial Price History & Audit Logs
    conn.execute(
        """
        INSERT INTO product_price_history (
            product_id, old_purchase_rial, new_purchase_rial, old_retail_rial, new_retail_rial,
            old_wholesale_rial, new_wholesale_rial, old_colleague_rial, new_colleague_rial,
            changed_by, reason, shamsi_datetime, created_at
        ) VALUES (
            3, 7800000, 8200000, 10200000, 10800000, 9400000, 9900000, 9000000, 9500000,
            'admin', 'به‌روزرسانی قیمت پس از ورود محموله دوم مهرماه (PUR-1405-00202)', '1405/07/08 - 11:20:00', ?
        )
        """,
        (now_iso,),
    )

    log_audit(
        conn, 1, "admin", "admin", "PRICE_CHANGE", "PRODUCT", 3,
        "تغییر قیمت خرید و فروش کالای «لنت ترمز جلو پژو ۲۰۶ - تیپ ۵» پس از ورود محموله جدید (بدون تغییر در اسناد قبلی)",
        {"purchase_price_rial": 7800000, "sale_price_retail_rial": 10200000},
        {"purchase_price_rial": 8200000, "sale_price_retail_rial": 10800000},
    )
    log_audit(
        conn, 1, "admin", "admin", "PDF_OCR_IMPORT", "PURCHASE_INVOICE", 2,
        "ورود فاکتور خرید PUR-1405-00202 از فایل اسکن‌شده PDF با موتور OCR فارسی و ذخیره نام مستعار کالاها",
        None,
        {"invoice_number": "PUR-1405-00202", "total_rial": 364000000},
    )
    log_audit(
        conn, 1, "admin", "admin", "WAREHOUSE_TRANSFER", "TRANSFER", 1,
        "ثبت سند انتقال TRF-1405-001 از انبار فروشگاه به انبار تعمیرگاه به همراه منظور نمودن بدهکار در حساب تعمیرگاه",
        None,
        {"transfer_number": "TRF-1405-001", "total_value_rial": 87600000},
    )
