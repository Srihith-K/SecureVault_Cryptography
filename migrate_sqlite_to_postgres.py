import sqlite3

from app import app, db
from app import (
    User,
    File,
    FileVersion,
    FileAccessLog,
    Activity
)


SQLITE_DB = "securevault.db"


def migrate_data():

    sqlite_conn = sqlite3.connect(SQLITE_DB)
    sqlite_conn.row_factory = sqlite3.Row

    cursor = sqlite_conn.cursor()

    with app.app_context():

        print("\nStarting SQLite → PostgreSQL migration...\n")

        # -------------------------------------------------
        # 1. USER
        # -------------------------------------------------

        users = cursor.execute(
            "SELECT * FROM user"
        ).fetchall()

        for row in users:

            existing = db.session.get(User, row["id"])

            if existing:
                print(f"User {row['id']} already exists - skipping")
                continue

            user = User(
                id=row["id"],
                name=row["name"],
                email=row["email"],
                password=row["password"],
                failed_attempts=row["failed_attempts"],
                locked_until=row["locked_until"],
                is_admin=row["is_admin"],
                email_verified=row["email_verified"],
                verification_token=row["verification_token"],
                storage_limit=row["storage_limit"],
                storage_used=row["storage_used"],
                created_at=row["created_at"],
                otp=row["otp"],
                otp_created_at=row["otp_created_at"],
                two_factor_enabled=row["two_factor_enabled"],
                public_key=row["public_key"],
                private_key=row["private_key"],
                profile_picture=row["profile_picture"]
            )

            db.session.add(user)

        db.session.flush()

        print(f"Users transferred: {len(users)}")


        # -------------------------------------------------
        # 2. FILE
        # -------------------------------------------------

        files = cursor.execute(
            "SELECT * FROM file"
        ).fetchall()

        for row in files:

            existing = db.session.get(File, row["id"])

            if existing:
                print(f"File {row['id']} already exists - skipping")
                continue

            file = File(
                id=row["id"],
                filename=row["filename"],
                encrypted_filename=row["encrypted_filename"],
                aes_key_filename=row["aes_key_filename"],
                file_hash=row["file_hash"],
                signature=row["signature"],
                signature_algorithm=row["signature_algorithm"],
                signature_verified=row["signature_verified"],
                owner_id=row["owner_id"],
                upload_date=row["upload_date"],
                file_size=row["file_size"],
                file_type=row["file_type"],
                download_count=row["download_count"],
                last_download=row["last_download"],
                encryption_algorithm=row["encryption_algorithm"],
                integrity_status=row["integrity_status"],
                is_deleted=row["is_deleted"],
                deleted_at=row["deleted_at"],
                deleted_by=row["deleted_by"]
            )

            db.session.add(file)

        db.session.flush()

        print(f"Files transferred: {len(files)}")


        # -------------------------------------------------
        # 3. FILE VERSION
        # -------------------------------------------------

        versions = cursor.execute(
            "SELECT * FROM file_version"
        ).fetchall()

        for row in versions:

            existing = db.session.get(
                FileVersion,
                row["id"]
            )

            if existing:
                print(
                    f"FileVersion {row['id']} already exists - skipping"
                )
                continue

            version = FileVersion(
                id=row["id"],
                file_id=row["file_id"],
                version_number=row["version_number"],
                filename=row["filename"],
                encrypted_filename=row["encrypted_filename"],
                encrypted_key=row["encrypted_key"],
                sha256_hash=row["sha256_hash"],
                file_size=row["file_size"],
                upload_date=row["upload_date"]
            )

            db.session.add(version)

        db.session.flush()

        print(
            f"File versions transferred: {len(versions)}"
        )


        # -------------------------------------------------
        # 4. FILE ACCESS LOG
        # -------------------------------------------------

        logs = cursor.execute(
            "SELECT * FROM file_access_log"
        ).fetchall()

        for row in logs:

            existing = db.session.get(
                FileAccessLog,
                row["id"]
            )

            if existing:
                print(
                    f"AccessLog {row['id']} already exists - skipping"
                )
                continue

            log = FileAccessLog(
                id=row["id"],
                user_id=row["user_id"],
                owner_id=row["owner_id"],
                file_id=row["file_id"],
                filename=row["filename"],
                action=row["action"],
                ip_address=row["ip_address"],
                access_time=row["access_time"]
            )

            db.session.add(log)

        db.session.flush()

        print(
            f"Access logs transferred: {len(logs)}"
        )


        # -------------------------------------------------
        # 5. ACTIVITY
        # -------------------------------------------------

        activities = cursor.execute(
            "SELECT * FROM activity"
        ).fetchall()

        for row in activities:

            existing = db.session.get(
                Activity,
                row["id"]
            )

            if existing:
                print(
                    f"Activity {row['id']} already exists - skipping"
                )
                continue

            activity = Activity(
                id=row["id"],
                user_id=row["user_id"],
                action=row["action"],
                filename=row["filename"],
                timestamp=row["timestamp"]
            )

            db.session.add(activity)

        db.session.flush()

        print(
            f"Activities transferred: {len(activities)}"
        )


        # -------------------------------------------------
        # COMMIT
        # -------------------------------------------------

        db.session.commit()

        print("\n====================================")
        print("Migration completed successfully!")
        print("====================================\n")


    sqlite_conn.close()


if __name__ == "__main__":
    migrate_data()