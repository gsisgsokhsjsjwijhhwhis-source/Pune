-- Keep the automatic RLS event trigger functional but remove unnecessary
-- Data API execution rights from public roles.
REVOKE EXECUTE ON FUNCTION public.rls_auto_enable()
  FROM PUBLIC, anon, authenticated, service_role;

-- Support user-owned device lookups, joins, and foreign-key maintenance.
CREATE INDEX IF NOT EXISTS ix_device_user_id
  ON public.device (user_id);
