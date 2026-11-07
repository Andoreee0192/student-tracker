from app import app, db
from sqlalchemy import inspect, text

with app.app_context():
    inspector = inspect(db.engine)

    columns = [
        column["name"]
        for column in inspector.get_columns("commitment")
    ]

    if "assigned_supervisor_id" in columns:
        print("Supervisor assignment column already exists.")
    else:
        with db.engine.begin() as connection:
            connection.execute(text("""
                ALTER TABLE commitment
                ADD COLUMN assigned_supervisor_id INTEGER
                REFERENCES user(id)
            """))

        print("Supervisor assignment column added successfully.")

    print("Database migration check completed.")