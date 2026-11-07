from app import app, db, Case, encrypt_text, decrypt_text, AESGCM_PREFIX


def migrate_encryption():
    with app.app_context():

        records = Case.query.order_by(Case.id.asc()).all()

        converted = 0
        already_encrypted = 0

        try:
            for case in records:

                old_data = bytes(case.description_encrypted)

                # Skip records already using AES-256-GCM
                if old_data.startswith(AESGCM_PREFIX):
                    original_text = decrypt_text(old_data)

                    if original_text.startswith("[Unable to decrypt:"):
                        raise RuntimeError(
                            f"Could not verify AES-GCM record: {case.case_number}"
                        )

                    already_encrypted += 1
                    continue

                # Decrypt the old Fernet record
                original_text = decrypt_text(old_data)

                if original_text.startswith("[Unable to decrypt:"):
                    raise RuntimeError(
                        f"Could not decrypt old record: {case.case_number}"
                    )

                # Encrypt using AES-256-GCM
                new_data = encrypt_text(original_text)

                # Verify the new encrypted record before saving
                verified_text = decrypt_text(new_data)

                if verified_text != original_text:
                    raise RuntimeError(
                        f"Verification failed: {case.case_number}"
                    )

                case.description_encrypted = new_data
                converted += 1

            # Verify all records before committing
            db.session.flush()

            for case in records:
                verified_text = decrypt_text(
                    bytes(case.description_encrypted)
                )

                if verified_text.startswith("[Unable to decrypt:"):
                    raise RuntimeError(
                        f"Final verification failed: {case.case_number}"
                    )

            db.session.commit()

            print("ENCRYPTION MIGRATION SUCCESSFUL")
            print(f"Total records: {len(records)}")
            print(f"Converted to AES-256-GCM: {converted}")
            print(f"Already AES-256-GCM: {already_encrypted}")

        except Exception as exc:
            db.session.rollback()
            print("MIGRATION CANCELLED")
            print(f"Reason: {exc}")
            print("Database changes have been rolled back.")


if __name__ == "__main__":
    migrate_encryption()