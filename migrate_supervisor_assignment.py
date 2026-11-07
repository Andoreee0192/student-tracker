from sqlalchemy import inspect, text
from app import app, db

with app.app_context():
    inspector = inspect(db.engine)

    if "commitment" not in inspector.get_table_names():
        raise RuntimeError(
            "The commitment table does not exist. Initialize the database first."
        )

    columns = {
        column["name"]
        for column in inspector.get_columns("commitment")
    }

    if "assigned_supervisor_id" in columns:
        print("assigned_supervisor_id already exists. No change made.")
    else:
        with db.engine.begin() as connection:
            connection.execute(text(
                "ALTER TABLE commitment "
                "ADD COLUMN assigned_supervisor_id INTEGER "
                "REFERENCES user(id)"
            ))
        print("Added assigned_supervisor_id to the commitment table.")

    print("Supervisor assignment database migration finished.")
