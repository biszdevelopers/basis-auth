DO $$
DECLARE
  portal_client text := nullif(current_setting('basis.management_portal_client_id', true), '');
  root_user uuid := nullif(current_setting('basis.resource_root_user_id', true), '')::uuid;
  own_permissions text[] := ARRAY[
    'BiszPortal.Applications.read.me', 'BiszPortal.Applications.update.me',
    'BiszPortal.Applications.delete.me', 'BiszPortal.Resources.read.me',
    'BiszPortal.Resources.update.me', 'BiszPortal.Resources.delete.me'
  ];
  retired_permissions text[] := ARRAY[
    'biszportal.applications.read', 'biszportal.applications.update',
    'biszportal.applications.delete', 'biszportal.applicationscopes.manage'
  ];
BEGIN
  IF EXISTS (SELECT FROM resource_servers WHERE created_by IS NULL) THEN
    IF root_user IS NULL OR NOT EXISTS (SELECT FROM users WHERE id = root_user) THEN
      RAISE EXCEPTION 'Set BASIS_RESOURCE_ROOT_USER_ID to an existing Basis Auth user before migrating resource ownership';
    END IF;
    UPDATE resource_servers SET created_by = root_user WHERE created_by IS NULL;
  END IF;

  IF NOT EXISTS (SELECT FROM oidc_clients WHERE client_id = portal_client) THEN
    RETURN;
  END IF;

  INSERT INTO oidc_permissions (client_id, permission, description)
  SELECT portal_client, permission, description
  FROM (VALUES
    ('BiszPortal.Applications.read.me', 'Read own applications'),
    ('BiszPortal.Applications.read.others', 'Read other applications'),
    ('BiszPortal.Applications.update.me', 'Update own applications'),
    ('BiszPortal.Applications.update.others', 'Update other applications'),
    ('BiszPortal.Applications.delete.me', 'Delete own applications'),
    ('BiszPortal.Applications.delete.others', 'Delete other applications'),
    ('BiszPortal.Resources.read.me', 'Read own resources'),
    ('BiszPortal.Resources.read.others', 'Read other resources'),
    ('BiszPortal.Resources.update.me', 'Update own resources'),
    ('BiszPortal.Resources.update.others', 'Update other resources'),
    ('BiszPortal.Resources.delete.me', 'Delete own resources'),
    ('BiszPortal.Resources.delete.others', 'Delete other resources')
  ) AS definitions(permission, description)
  ON CONFLICT (client_id, permission) DO NOTHING;

  INSERT INTO default_permissions (application_id, permission)
  SELECT portal_client, permission FROM unnest(own_permissions) AS own(permission)
  ON CONFLICT DO NOTHING;

  INSERT INTO user_permissions (user_id, application_id, permission)
  SELECT existing.user_id, portal_client, own.permission
  FROM (
    SELECT user_id FROM user_applications WHERE application_id = portal_client
    UNION
    SELECT user_id FROM user_permissions WHERE application_id = portal_client
  ) AS existing
  CROSS JOIN unnest(own_permissions) AS own(permission)
  ON CONFLICT DO NOTHING;

  DELETE FROM user_permissions
  WHERE application_id = portal_client AND lower(permission) = ANY(retired_permissions);
  DELETE FROM oidc_permissions
  WHERE client_id = portal_client AND lower(permission) = ANY(retired_permissions);

  UPDATE oidc_clients
  SET permission_catalog_version = permission_catalog_version + 1, updated_at = now()
  WHERE client_id = portal_client;
END $$;
