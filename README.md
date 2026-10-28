# Device Registry (Pune)

Flask application for registering devices and checking device status.

## Production database

All production reads and writes must use the server-side PostgreSQL database configured in Render's `DATABASE_URL`. The application rejects SQLite as a production database and does not import or fall back to a database file from the repository.

The current app uses Supabase PostgreSQL. Keep the connection URL in Render environment variables only. For the shared session pooler, copy the exact connection details from Supabase Dashboard → **Connect** → **Session pooler**; the pooler hostname must not be guessed from the region.

If the existing Render `DATABASE_URL` has correct credentials but the wrong pooler hostname, set `SUPABASE_POOLER_HOST` in Render to the exact hostname shown by Supabase Connect. The app will override only the hostname and preserve the password already in `DATABASE_URL`. `SUPABASE_DB_PORT` defaults to `5432`. Never put the password or full connection URL in this repository or logs.

## Data reconciliation

The old repository SQLite snapshot was checked against the server database. Its three user emails already match server accounts; the snapshot contains changed profile details, so live server values were not overwritten. The differences are preserved in the restricted Supabase table `public.registry_import_archive`.

The three device rows in the snapshot have invalid IMEI lengths (7, 9, and 14 digits rather than 15). They are retained in that restricted archive for review and were not inserted into the active device registry. The previous admin username is retained for audit, but its old password hash is deliberately not copied over the existing server admin credential.

The archive table has row-level security enabled and no public read/write policies. The live application tables remain the source of truth for new records.

## Render configuration

Build command:

`pip install -r requirements.txt`

Start command:

`gunicorn device_registry.app:app`

Set a stable random `SECRET_KEY` in Render. Set `INITIAL_ADMIN_USER` and a strong `INITIAL_ADMIN_PASSWORD` only if a new database has no admin row; the existing server admin is preserved.

## Local development

Install dependencies with `pip install -r requirements.txt`, then run:

`python -m device_registry.app`

Outside Render, the app uses a local SQLite database `registry.db` for development only. Database files and the `instance/` directory are ignored by Git and must never be committed.
