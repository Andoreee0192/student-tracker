
from app import app, db, AuditLog
import hashlib

with app.app_context():
    try:
        rows = AuditLog.query.order_by(AuditLog.id.asc()).all()

        if not rows:
            print("No audit records found.")
        else:
            previous = "GENESIS"

            for row in rows:
                # Rebuild the link to the preceding record.
                row.previous_hash = previous

                # Recalculate the record hash.
                payload = "|".join([
                    str(row.user_id or "system"),
                    row.action,
                    row.record_type,
                    str(row.record_id or ""),
                    row.created_at.isoformat(),
                    row.previous_hash
                ])

                row.entry_hash = hashlib.sha256(
                    payload.encode("utf-8")
                ).hexdigest()

                previous = row.entry_hash

            db.session.commit()

            print("Audit hash chain rebuilt successfully.")
            print("Records processed:", len(rows))
            print("First record ID:", rows[0].id)
            print("Last record ID:", rows[-1].id)

    except Exception as error:
        db.session.rollback()
        print("Repair failed. Changes rolled back.")
        print("Error:", error)
