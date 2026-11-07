from app import app, AuditLog
import hashlib
import hmac

with app.app_context():
    rows = AuditLog.query.order_by(AuditLog.id.asc()).all()

    failed_hashes = []
    failed_chains = []

    previous = "GENESIS"

    for row in rows:
        payload = "|".join([
            str(row.user_id or "system"),
            row.action,
            row.record_type,
            str(row.record_id or ""),
            row.created_at.isoformat(),
            row.previous_hash
        ])

        expected = hashlib.sha256(
            payload.encode("utf-8")
        ).hexdigest()

        if not hmac.compare_digest(expected, row.entry_hash):
            failed_hashes.append(row.id)

        if row.previous_hash != previous:
            failed_chains.append(row.id)

        previous = row.entry_hash

    print("Total records:", len(rows))
    print("Failed hash records:", failed_hashes)
    print("Failed chain records:", failed_chains)
    print("Latest record ID:", rows[-1].id if rows else "None")