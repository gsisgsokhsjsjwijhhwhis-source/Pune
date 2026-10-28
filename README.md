# Device Registry (Pune)

Flask application for registering devices and checking device status.

## Production database

The Render deployment must use the PostgreSQL connection string stored as the Render service's `DATABASE_URL` environment variable. Production SQLite fallback is disabled. The application creates missing tables and, on its first successful connection to an empty PostgreSQL database, imports the existing records from `instance/registry.db` once. It logs the number of admin, user, and device records imported. If PostgreSQL already contains data, it will not merge or overwrite the bundled snapshot.

After verifying that the migration completed and the counts match, remove `instance/registry.db` from the repository. Do not remove it before the migration is verified.

## Render configuration

Start command:

`gunicorn device_registry.app:app`

Build command:

`pip install -r requirements.txt`

Set a stable random `SECRET_KEY` in Render. The database connection string belongs only in Render's secret environment variables; never commit it to GitHub. Set `INITIAL_ADMIN_USER` and a strong `INITIAL_ADMIN_PASSWORD` only if a new database needs its first admin account. Existing admin credentials are preserved by the one-time import.

## Persistence and privacy

PostgreSQL is the live source of truth; the application must not use a deployed SQLite file for live writes. Keep database credentials private. The SQLite snapshot contains personal/device records and password hashes; if the repository was public, assume historical copies may exist and rotate exposed credentials.

## Local development

Install dependencies with `pip install -r requirements.txt`, then run:

`python -m device_registry.app`

For local development only, the app uses `instance/registry.db` if it exists, or creates `registry.db`.
