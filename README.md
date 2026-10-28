# Device Registry (Pune)

Flask application for registering devices and checking device status.

## Current deployment data source

The repository includes the existing `instance/registry.db` SQLite database. When that file is present, the app uses it in preference to `DATABASE_URL`, so the Render service can use the local records while the Supabase pooler configuration is repaired.

The current Render start command is:

`gunicorn device_registry.app:app`

Build command:

`pip install -r requirements.txt`

Set a stable, random `SECRET_KEY` in Render. Set `INITIAL_ADMIN_USER` and a strong `INITIAL_ADMIN_PASSWORD` only if a new database needs its first admin account. Existing admin credentials in the local database are preserved.

## Important persistence and privacy caveats

SQLite is local-file storage. On Render, changes made to this database may be lost on redeploy/restart unless the service has a persistent disk mounted at the database location. The bundled database is a snapshot, not a live shared database. If people add/update devices after deployment, use a persistent disk or migrate the data to PostgreSQL before relying on those updates.

The SQLite file may contain personal/device records and password hashes. Keep the repository private if the data is sensitive. If this repository has been public, assume the file and its earlier Git history may have been copied; consider rotating credentials and removing sensitive records/history.

## Restoring the Supabase connection later

The old connection failed with:

`FATAL: (ENOTFOUND) tenant/user postgres.<project-ref> not found`

To move back to PostgreSQL, first verify the project is active and copy the exact URI from Supabase Dashboard → **Connect**. Migrate the local data into that database and verify it before disabling local mode/removing the bundled database. Do not point the app at a blank database or assume a password change alone will fix a tenant/username mismatch.

## Local development

Install dependencies with `pip install -r requirements.txt`, then run:

`python -m device_registry.app`

The app uses `instance/registry.db` when present.
