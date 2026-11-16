from datetime import datetime, timezone, timedelta
from pathlib import Path
import sqlite3


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIRECTORY = PROJECT_ROOT / "data"

DATABASE_PATH = DATA_DIRECTORY / "cyberrecon.db"


def get_connection():
    """
    Create and return a SQLite database connection.
    """

    DATA_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA foreign_keys = ON"
    )

    return connection


def initialize_database():
    """
    Create all required CyberRecon database
    tables if they do not already exist.
    """

    with get_connection() as connection:

        # -------------------------------------------------
        # USERS
        # -------------------------------------------------

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                username TEXT
                    NOT NULL
                    UNIQUE
                    COLLATE NOCASE,

                email TEXT
                    NOT NULL
                    UNIQUE
                    COLLATE NOCASE,

                password_hash TEXT
                    NOT NULL,

                created_at TEXT
                    NOT NULL
                    DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


        # -------------------------------------------------
        # SCANS
        # -------------------------------------------------

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            scan_id TEXT
                NOT NULL
                UNIQUE,

            target TEXT
                NOT NULL,

            started_at TEXT,
            duration_ms INTEGER,
            checks_performed INTEGER,
            recon_status TEXT,
            analysis_status TEXT,
            domain TEXT,
            ip_address TEXT,
            final_url TEXT,
            http_status INTEGER,
            https_enabled INTEGER,
            response_time REAL,
            redirect_count INTEGER,
            page_title TEXT,
            server TEXT,
            content_type TEXT,

            created_at TEXT
                NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE
            )
            """
        )
        
        scan_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(scans)"
            ).fetchall()
        }

        if "user_id" not in scan_columns:

            connection.execute(
                """
                ALTER TABLE scans
                ADD COLUMN user_id INTEGER
                REFERENCES users(id)
                """
            )


        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
                idx_scans_user
            ON scans(user_id)
            """
        )


        # -------------------------------------------------
        # FINDINGS
        # -------------------------------------------------

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                scan_database_id INTEGER
                    NOT NULL,

                finding_code TEXT,
                name TEXT,
                category TEXT,
                severity TEXT,

                confidence TEXT,
                affected_component TEXT,
                cwe TEXT,
                owasp TEXT,

                evidence TEXT,
                description TEXT,
                recommendation TEXT,

                FOREIGN KEY (
                    scan_database_id
                )
                REFERENCES scans(id)
                ON DELETE CASCADE
            )
            """
        )
        
        finding_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(findings)"
            ).fetchall()
        }


        required_finding_columns = {
            "confidence": "TEXT",
            "affected_component": "TEXT",
            "cwe": "TEXT",
            "owasp": "TEXT",
        }


        for column_name, column_type in required_finding_columns.items():

            if column_name not in finding_columns:

                connection.execute(
                    f"""
                    ALTER TABLE findings
                    ADD COLUMN {column_name} {column_type}
                    """
                )


        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
                idx_findings_scan
            ON findings (
                scan_database_id
            )
            """
        )


# =========================================================
# USER FUNCTIONS
# =========================================================


def create_user(
    username,
    email,
    password_hash,
):
    """
    Create a CyberRecon user account.
    """

    with get_connection() as connection:

        cursor = connection.execute(
            """
            INSERT INTO users (
                username,
                email,
                password_hash
            )
            VALUES (?, ?, ?)
            """,
            (
                username.strip(),
                email.strip().lower(),
                password_hash,
            ),
        )

        return cursor.lastrowid


def get_user_by_username(username):
    """
    Find a user using their username.
    """

    with get_connection() as connection:

        row = connection.execute(
            """
            SELECT
                id,
                username,
                email,
                password_hash,
                created_at

            FROM users

            WHERE username = ?
                COLLATE NOCASE
            """,
            (
                username.strip(),
            ),
        ).fetchone()

    if row is None:
        return None

    return dict(row)


def get_user_by_email(email):
    """
    Find a user using their email address.
    """

    with get_connection() as connection:

        row = connection.execute(
            """
            SELECT
                id,
                username,
                email,
                password_hash,
                created_at

            FROM users

            WHERE email = ?
                COLLATE NOCASE
            """,
            (
                email.strip().lower(),
            ),
        ).fetchone()

    if row is None:
        return None

    return dict(row)


def get_user_by_id(user_id):
    """
    Find a user using their database ID.

    Password hashes are intentionally excluded
    from this function.
    """

    with get_connection() as connection:

        row = connection.execute(
            """
            SELECT
                id,
                username,
                email,
                created_at

            FROM users

            WHERE id = ?
            """,
            (
                user_id,
            ),
        ).fetchone()

    if row is None:
        return None

    return dict(row)


# =========================================================
# ASSESSMENT STORAGE
# =========================================================


def save_assessment(
    assessment,
    user_id,
):
    """
    Save a completed or failed CyberRecon
    assessment and its findings.
    """

    metadata = assessment.get(
        "metadata",
        {},
    )

    recon = assessment.get(
        "recon",
        {},
    )

    findings = assessment.get(
        "findings",
        [],
    )

    target = assessment.get(
        "target",
        "",
    )


    https_enabled = recon.get(
        "https_enabled"
    )

    if https_enabled is not None:
        https_enabled = int(
            bool(https_enabled)
        )


    with get_connection() as connection:

        cursor = connection.execute(
            """
            INSERT INTO scans (
                user_id,
                scan_id,
                target,
                started_at,
                duration_ms,
                checks_performed,
                recon_status,
                analysis_status,
                domain,
                ip_address,
                final_url,
                http_status,
                https_enabled,
                response_time,
                redirect_count,
                page_title,
                server,
                content_type
            )

            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                user_id,
                metadata.get("scan_id"),
                target,
                metadata.get("started_at"),
                metadata.get("duration_ms"),
                metadata.get("checks_performed"),
                metadata.get("recon_status"),
                metadata.get("analysis_status"),
                recon.get("domain"),
                recon.get("ip_address"),
                recon.get("final_url"),
                recon.get("status_code"),
                https_enabled,
                recon.get("response_time"),
                recon.get("redirect_count"),
                recon.get("page_title"),
                recon.get("server"),
                recon.get("content_type"),
            ),
        )

        scan_database_id = (
            cursor.lastrowid
        )


        for finding in findings:

            finding_code = (
                finding.get("finding_code")
                or finding.get("id")
            )

            connection.execute(
                """
                INSERT INTO findings (
                    scan_database_id,
                    finding_code,
                    name,
                    category,
                    severity,
                    confidence,
                    affected_component,
                    cwe,
                    owasp,
                    evidence,
                    description,
                    recommendation
                )

                VALUES (
                    ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    scan_database_id,

                    finding_code,

                    finding.get(
                        "name"
                    ),

                    finding.get(
                        "category"
                    ),

                    finding.get(
                        "severity"
                    ),

                    finding.get(
                        "confidence"
                    ),

                    finding.get(
                        "affected_component"
                    ),

                    finding.get(
                        "cwe"
                    ),

                    finding.get(
                        "owasp"
                    ),

                    finding.get(
                        "evidence"
                    ),

                    finding.get(
                        "description"
                    ),

                    finding.get(
                        "recommendation"
                    ),
                ),
            )


# =========================================================
# SCAN HISTORY
# =========================================================


def get_scan_history(
    user_id,
    limit=50,
):

    with get_connection() as connection:

        rows = connection.execute(
            """
            SELECT
                scans.*,

                COUNT(findings.id)
                    AS total_findings,

                COALESCE(
                    SUM(
                        CASE
                            WHEN findings.severity = 'High'
                            THEN 1
                            ELSE 0
                        END
                    ),
                    0
                ) AS high_count,

                COALESCE(
                    SUM(
                        CASE
                            WHEN findings.severity = 'Medium'
                            THEN 1
                            ELSE 0
                        END
                    ),
                    0
                ) AS medium_count,

                COALESCE(
                    SUM(
                        CASE
                            WHEN findings.severity = 'Low'
                            THEN 1
                            ELSE 0
                        END
                    ),
                    0
                ) AS low_count,

                COALESCE(
                    SUM(
                        CASE
                            WHEN findings.severity = 'Info'
                            THEN 1
                            ELSE 0
                        END
                    ),
                    0
                ) AS info_count

            FROM scans

            LEFT JOIN findings
                ON findings.scan_database_id
                = scans.id

            WHERE scans.user_id = ?

            GROUP BY scans.id

            ORDER BY scans.id DESC

            LIMIT ?
            """,
            (
                user_id,
                limit,
            ),
        ).fetchall()

    return [
        dict(row)
        for row in rows
    ]


def get_scan_by_id(
    scan_id,
    user_id,
):

    with get_connection() as connection:

        scan = connection.execute(
            """
            SELECT *
            FROM scans

            WHERE scan_id = ?
              AND user_id = ?
            """,
            (
                scan_id,
                user_id,
            ),
        ).fetchone()


        if scan is None:
            return None


        findings = connection.execute(
            """
            SELECT
                finding_code,
                name,
                category,
                severity,
                confidence,
                affected_component,
                cwe,
                owasp,
                evidence,
                description,
                recommendation
            
            FROM findings

            WHERE scan_database_id = ?

            ORDER BY id ASC
            """,
            (
                scan["id"],
            ),
        ).fetchall()


    return {
        "scan": dict(scan),

        "findings": [
            dict(finding)
            for finding in findings
        ],
    }


def get_completed_scans(
    user_id,
    limit=100,
):

    with get_connection() as connection:

        rows = connection.execute(
            """
            SELECT
                scan_id,
                target,
                started_at,
                domain,
                analysis_status

            FROM scans

            WHERE analysis_status = 'Completed'
              AND user_id = ?

            ORDER BY id DESC

            LIMIT ?
            """,
            (
                user_id,
                limit,
            ),
        ).fetchall()

    return [
        dict(row)
        for row in rows
    ]


# =========================================================
# DASHBOARD ANALYTICS
# =========================================================


def get_dashboard_analytics(user_id, date_range="all"):
    """
    Retrieve comprehensive, user-isolated dashboard security analytics,
    supporting time-range filtering ('24h', '7d', '30d', 'all').
    """
    if date_range not in ("24h", "7d", "30d", "all"):
        date_range = "all"

    with get_connection() as connection:
        where_scans = "WHERE scans.user_id = ?"
        params = [user_id]

        if date_range == "24h":
            where_scans += " AND scans.created_at >= datetime('now', '-24 hours')"
        elif date_range == "7d":
            where_scans += " AND scans.created_at >= datetime('now', '-7 days')"
        elif date_range == "30d":
            where_scans += " AND scans.created_at >= datetime('now', '-30 days')"

        overview = connection.execute(
            f"""
            SELECT
                COUNT(*) AS total_scans,
                COUNT(DISTINCT scans.target) AS unique_targets,
                SUM(CASE WHEN scans.recon_status = 'Completed' THEN 1 ELSE 0 END) AS successful_scans,
                SUM(CASE WHEN scans.recon_status = 'Failed' THEN 1 ELSE 0 END) AS failed_scans
            FROM scans
            {where_scans}
            """,
            params,
        ).fetchone()

        severity = connection.execute(
            f"""
            SELECT
                COUNT(findings.id) AS total_findings,
                COUNT(DISTINCT findings.finding_code) AS distinct_finding_types,
                SUM(CASE WHEN findings.severity = 'High' THEN 1 ELSE 0 END) AS high_count,
                SUM(CASE WHEN findings.severity = 'Medium' THEN 1 ELSE 0 END) AS medium_count,
                SUM(CASE WHEN findings.severity = 'Low' THEN 1 ELSE 0 END) AS low_count,
                SUM(CASE WHEN findings.severity = 'Info' THEN 1 ELSE 0 END) AS info_count
            FROM scans
            LEFT JOIN findings ON findings.scan_database_id = scans.id
            {where_scans}
            """,
            params,
        ).fetchone()

        recent_scans = connection.execute(
            f"""
            SELECT
                scans.scan_id,
                scans.target,
                scans.started_at,
                scans.recon_status,
                scans.analysis_status,
                COALESCE(COUNT(findings.id), 0) AS total_findings,
                COALESCE(SUM(CASE WHEN findings.severity = 'High' THEN 1 ELSE 0 END), 0) AS high_count,
                COALESCE(SUM(CASE WHEN findings.severity = 'Medium' THEN 1 ELSE 0 END), 0) AS medium_count,
                COALESCE(SUM(CASE WHEN findings.severity = 'Low' THEN 1 ELSE 0 END), 0) AS low_count,
                COALESCE(SUM(CASE WHEN findings.severity = 'Info' THEN 1 ELSE 0 END), 0) AS info_count
            FROM scans
            LEFT JOIN findings ON findings.scan_database_id = scans.id
            {where_scans}
            GROUP BY scans.id
            ORDER BY scans.id DESC
            LIMIT 8
            """,
            params,
        ).fetchall()

        common_findings_raw = connection.execute(
            f"""
            SELECT
                findings.finding_code,
                findings.name,
                findings.severity,
                COUNT(DISTINCT scans.id) AS affected_assessments,
                COUNT(*) AS total_occurrences,
                MAX(scans.scan_id) AS latest_scan_id
            FROM findings
            JOIN scans ON scans.id = findings.scan_database_id
            {where_scans}
            GROUP BY findings.finding_code, findings.name, findings.severity
            ORDER BY affected_assessments DESC, total_occurrences DESC, findings.finding_code ASC
            LIMIT 5
            """,
            params,
        ).fetchall()

        daily_rows = connection.execute(
            f"""
            SELECT
                DATE(scans.created_at) AS scan_date,
                COUNT(*) AS scan_count
            FROM scans
            {where_scans}
            GROUP BY scan_date
            ORDER BY scan_date ASC
            """,
            params,
        ).fetchall()

        target_risk_row = connection.execute(
            f"""
            SELECT scans.target, COUNT(findings.id) AS finding_count
            FROM scans
            JOIN findings ON findings.scan_database_id = scans.id
            {where_scans}
            GROUP BY scans.target
            ORDER BY finding_count DESC
            LIMIT 1
            """,
            params,
        ).fetchone()

        latest_scan_row = connection.execute(
            f"""
            SELECT scan_id, target, started_at, duration_ms
            FROM scans
            {where_scans} AND recon_status = 'Completed'
            ORDER BY id DESC
            LIMIT 1
            """,
            params,
        ).fetchone()

    overview_data = dict(overview) if overview else {}
    severity_data = dict(severity) if severity else {}

    for key in ("total_scans", "unique_targets", "successful_scans", "failed_scans"):
        overview_data[key] = overview_data.get(key) or 0

    for key in ("total_findings", "distinct_finding_types", "high_count", "medium_count", "low_count", "info_count"):
        severity_data[key] = severity_data.get(key) or 0

    total_scans = overview_data["total_scans"]
    success_rate = (
        round((overview_data["successful_scans"] / total_scans) * 100, 1)
        if total_scans
        else 0.0
    )

    common_findings = []
    for idx, row in enumerate(common_findings_raw, 1):
        item = dict(row)
        item["rank"] = idx
        item["occurrence_count"] = item["total_occurrences"]
        item["affected_pct"] = (
            round((item["affected_assessments"] / total_scans) * 100, 1)
            if total_scans
            else 0.0
        )
        common_findings.append(item)

    timeline = []
    days_count = 7 if date_range == "7d" else (30 if date_range == "30d" else (1 if date_range == "24h" else 14))
    daily_map = {row["scan_date"]: row["scan_count"] for row in daily_rows}
    today = datetime.now(timezone.utc).date()
    for i in range(days_count - 1, -1, -1):
        day = today - timedelta(days=i)
        iso = day.isoformat()
        count = daily_map.get(iso, 0)
        label = "Today" if i == 0 else ("Yest." if i == 1 else day.strftime("%b %d"))
        timeline.append({
            "date": iso,
            "label": label,
            "count": count,
        })
    max_activity = max([t["count"] for t in timeline] or [1])
    if max_activity == 0:
        max_activity = 1

    range_labels = {
        "all": "All Time",
        "24h": "Last 24 Hours",
        "7d": "Last 7 Days",
        "30d": "Last 30 Days",
    }

    insights = {
        "top_misconfiguration": common_findings[0] if common_findings else None,
        "highest_risk_target": dict(target_risk_row) if target_risk_row else None,
        "latest_successful_scan": dict(latest_scan_row) if latest_scan_row else None,
        "distinct_finding_types": severity_data["distinct_finding_types"],
        "unique_targets": overview_data["unique_targets"],
    }

    return {
        "overview": overview_data,
        "severity": severity_data,
        "success_rate": success_rate,
        "recent_scans": [dict(scan) for scan in recent_scans],
        "common_findings": common_findings,
        "activity_timeline": timeline,
        "max_activity": max_activity,
        "insights": insights,
        "date_range": date_range,
        "range_label": range_labels.get(date_range, "All Time"),
    }