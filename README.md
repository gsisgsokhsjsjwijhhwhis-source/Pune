# Device Registry (Pune)

Flask application for registering devices and checking device status.

## Deploying on Render

The current Render service starts with:

`gunicorn device_registry.app:app`

Build command:

`pip install -r requirements.txt`

Set these environment variables in the Render service:

- `DATABASE_URL`: PostgreSQL connection URI for the existing production database.
- `SECRET_KEY`: a long, random, stable secret used to sign sessions.
- `INITIAL_ADMIN_USER` and `INITIAL_ADMIN_PASSWORD`: strong initial admin credentials. The initial password is used only when the configured database has no admin row.
- `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`: optional; needed for Google sign-in.

Do not commit `.env`, database files, credentials, or Python bytecode. Render's free web-service filesystem is ephemeral, so local SQLite is not a suitable production store for user/device records.

## Fixing the current database connection error

The observed Render log reports:

`FATAL: (ENOTFOUND) tenant/user postgres.<project-ref> not found`

This means the Supabase shared pooler cannot map the connection's host and username to a project. It is usually a pooler **host or username** mismatch, not simply a wrong password.

1. Open the correct project in the Supabase Dashboard and choose **Connect**.
2. Copy a complete PostgreSQL URI from the dashboard (Session pooler is a suitable starting point for this app).
3. Replace only the password placeholder, URL-encoding special characters in the password if required. Keep the exact host, port, database, and username the dashboard supplied.
4. In Render → this service → Environment, replace `DATABASE_URL` with that URI, save, and review the new deploy logs.

Do not guess a pooler hostname such as `aws-0-...`, substitute a different project reference, switch to SQLite, or create a blank database as a workaround. Those changes can keep the service unavailable or detach it from existing user/device data. If the exact dashboard-provided URI still produces this error, the Supabase project/pooler mapping may require a Supabase support fix.

## Local development

Create a virtual environment, install `requirements.txt`, and run:

`python -m device_registry.app`

For local development, set `DATABASE_URL=sqlite:///registry.db` only if you intend to use a local development database. Never use this as a production data-store replacement.
