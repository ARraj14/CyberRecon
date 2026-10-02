from pathlib import Path
import sqlite3


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIRECTORY = PROJECT_ROOT / "data"
DATABASE_PATH = DATA_DIRECTORY / "cyberrecon.db"


def get_connection():
    """
    Create and return a connection to the
    CyberRecon SQLite database.
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
    Create the required database tables
    if they do not already exist.
    """

    with get_connection() as connection:

        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                scan_id TEXT UNIQUE NOT NULL,
                target TEXT NOT NULL,
                started_at TEXT NOT NULL,

                duration_ms REAL,
                checks_performed INTEGER DEFAULT 0,

                recon_status TEXT,
                analysis_status TEXT,

                domain TEXT,
                ip_address TEXT,
                final_url TEXT,
                http_status TEXT,

                https_enabled INTEGER,

                response_time TEXT,
                redirect_count INTEGER,

                page_title TEXT,
                server TEXT,
                content_type TEXT,

                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );


            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                scan_database_id INTEGER NOT NULL,

                finding_code TEXT,
                name TEXT,
                category TEXT,
                severity TEXT,

                evidence TEXT,
                description TEXT,
                recommendation TEXT,

                FOREIGN KEY (
                    scan_database_id
                )
                REFERENCES scans(id)
                ON DELETE CASCADE
            );


            CREATE INDEX IF NOT EXISTS
            idx_findings_scan
            ON findings(scan_database_id);
            """
        )


def save_assessment(assessment):
    """
    Save one assessment and its findings.
    """

    metadata = assessment["metadata"]
    recon = assessment["recon"]
    findings = assessment["findings"]

    with get_connection() as connection:

        cursor = connection.execute(
            """
            INSERT INTO scans (
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
                ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                metadata["scan_id"],
                assessment["target"],
                metadata["started_at"],
                metadata["duration_ms"],
                metadata["checks_performed"],
                metadata["recon_status"],
                metadata["analysis_status"],
                recon.get("domain"),
                recon.get("ip_address"),
                recon.get("final_url"),
                str(
                    recon.get(
                        "status_code",
                        "Unavailable",
                    )
                ),
                int(
                    bool(
                        recon.get(
                            "https_enabled"
                        )
                    )
                ),
                str(
                    recon.get(
                        "response_time",
                        "Unavailable",
                    )
                ),
                recon.get(
                    "redirect_count",
                    0,
                ),
                recon.get("page_title"),
                recon.get("server"),
                recon.get("content_type"),
            ),
        )

        scan_database_id = cursor.lastrowid

        for finding in findings:

            connection.execute(
                """
                INSERT INTO findings (
                    scan_database_id,
                    finding_code,
                    name,
                    category,
                    severity,
                    evidence,
                    description,
                    recommendation
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    scan_database_id,
                    finding["id"],
                    finding["name"],
                    finding["category"],
                    finding["severity"],
                    finding["evidence"],
                    finding["description"],
                    finding["recommendation"],
                ),
            )


def get_scan_history(limit=50):
    """
    Return recent stored assessments.
    """

    with get_connection() as connection:

        rows = connection.execute(
            """
            SELECT
                scans.id,
                scans.scan_id,
                scans.target,
                scans.started_at,
                scans.duration_ms,
                scans.checks_performed,
                scans.recon_status,
                scans.analysis_status,
                scans.http_status,
                scans.https_enabled,

                COUNT(findings.id)
                    AS total_findings,

                SUM(
                    CASE
                        WHEN findings.severity = 'High'
                        THEN 1
                        ELSE 0
                    END
                ) AS high_count,

                SUM(
                    CASE
                        WHEN findings.severity = 'Medium'
                        THEN 1
                        ELSE 0
                    END
                ) AS medium_count,

                SUM(
                    CASE
                        WHEN findings.severity = 'Low'
                        THEN 1
                        ELSE 0
                    END
                ) AS low_count,

                SUM(
                    CASE
                        WHEN findings.severity = 'Info'
                        THEN 1
                        ELSE 0
                    END
                ) AS info_count

            FROM scans

            LEFT JOIN findings
                ON scans.id =
                findings.scan_database_id

            GROUP BY scans.id

            ORDER BY scans.id DESC

            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [
        dict(row)
        for row in rows
    ]