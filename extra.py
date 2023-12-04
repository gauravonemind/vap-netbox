REMOTE_AUTH_ENABLED = True
REMOTE_AUTH_BACKEND = 'social_core.backends.azuread.AzureADOAuth2'
# TODO: below two input from user.
SOCIAL_AUTH_AZUREAD_OAUTH2_KEY = 'oauth_key_here'
SOCIAL_AUTH_AZUREAD_OAUTH2_SECRET = 'oauth_secret_here'

SOCIAL_AUTH_PIPELINE = (
    'social_core.pipeline.social_auth.social_details',
    'social_core.pipeline.social_auth.social_uid',
    'social_core.pipeline.social_auth.social_user',
    'social_core.pipeline.user.get_username',
    'social_core.pipeline.social_auth.associate_by_email',
    'social_core.pipeline.user.create_user',
    'social_core.pipeline.social_auth.associate_user',
    'netbox.authentication.user_default_groups_handler',
    'social_core.pipeline.social_auth.load_extra_data',
    'social_core.pipeline.user.user_details',
    'netbox.configuration.azuread_map_groups',
    'netbox.configuration.azuread_group_permissions'
)

SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL = True
SOCIAL_AUTH_CLEAN_USERNAMES = True
SOCIAL_AUTH_SANITIZE_REDIRECTS = True
SOCIAL_AUTH_SESSION_EXPIRATION = True
# SOCIAL_AUTH_USER_AGENT = 'netbox/${netbox_release}'

SOCIAL_AUTH_PIPELINE_CONFIG = {
    # TODO: get these values from users
    'AZUREAD_USER_FLAGS_BY_GROUP': {
        "is_staff":  'azuread_user_flags_by_group_is_staff_here'.split(','),
        "is_superuser": 'azuread_user_flags_by_group_is_superuser_here'.split(','),
    },
    'AZUREAD_GROUP_MAP': azuread_group_map_here,
    'AZUREAD_GROUP_PERMISSIONS': azuread_group_permissions_here,
}

def azuread_group_permissions(response, user, backend, *args, **kwargs):
    import jwt

    from django.contrib.auth.models import Group
    from django.contrib.contenttypes.models import ContentType
    from users.models import ObjectPermission

    logger = logging.getLogger('netbox.authentication.azuread_group_permissions')

    jwt_id_token = response['id_token']
    alg = jwt.get_unverified_header(jwt_id_token)['alg']
    user_info = jwt.decode(jwt_id_token, algorithms=[alg], options={"verify_signature": False})

    config = SOCIAL_AUTH_PIPELINE_CONFIG
    if config.get('AZUREAD_GROUP_PERMISSIONS', None):
        groups_dict = config['AZUREAD_GROUP_PERMISSIONS']

        for group_name, i in groups_dict.items():
            if group_name not in user_info['groups']:
                continue

            try:
                group = Group.objects.get(name=group_name)
            except Group.DoesNotExist:
                logger.warning('Azure AD group {} does not exist in NetBox'.format(group_name))
                group = Group.objects.create(name=group_name)
                group.user_set.add(user)

            for ct, permissions in i.items():
                app_label, model_name = ct.split('.')

                try:
                    object_type = ContentType.objects.get(app_label=app_label, model=model_name)
                except ContentType.DoesNotExist:
                    logger.warning('ContentType {} does not exist in NetBox'.format(ct))
                    continue
                for permission in permissions:
                    try:
                        object_permission = ObjectPermission.objects.get(
                            name=f'{group_name} - {model_name}',
                        )
                    except ObjectPermission.DoesNotExist:
                        object_permission = ObjectPermission.objects.create(
                            name=f'{group_name} - {model_name}',
                            enabled=True,
                            actions=[]
                        )
                    object_permission.actions.append(permission)
                    object_permission.save()
                    object_permission.object_types.add(object_type)
                    object_permission.groups.add(group)

                    logger.info(f'Added permission {permission} to group {group_name} for model {model_name}')
    else:
        logger.warning('AZUREAD_GROUP_PERMISSIONS not defined in SOCIAL_AUTH_PIPELINE_CONFIG')

    # Remove orphaned ObjectPermissions
    ObjectPermission.objects.filter(groups__isnull=True, users__isnull=True).delete()


def azuread_map_groups(response, user, backend, *args, **kwargs):
    import jwt
    from django.contrib.auth.models import Group

    logger = logging.getLogger('netbox.authentication.azuread_map_groups')

    jwt_id_token = response['id_token']
    alg = jwt.get_unverified_header(jwt_id_token)['alg']
    user_info = jwt.decode(jwt_id_token, algorithms=[alg], options={"verify_signature": False})

    logger.info('Successfully decoded JWT ID token for user {}'.format(user_info['upn']))

    config = SOCIAL_AUTH_PIPELINE_CONFIG

    if 'AZUREAD_USER_FLAGS_BY_GROUP' not in config and 'AZUREAD_GROUP_MAP' not in config:
        raise ImproperlyConfigured(
            'AZUREAD_USER_FLAGS_BY_GROUP and AZUREAD_GROUP_MAP must be defined in SOCIAL_AUTH_PIPELINE_CONFIG')

    flags_by_group = config.get("AZUREAD_USER_FLAGS_BY_GROUP", {'is_superuser': [], 'is_staff': []})
    group_mapping = config.get("AZUREAD_GROUP_MAP", {})

    if 'is_staff' not in flags_by_group and 'is_superuser' not in flags_by_group:
        raise ImproperlyConfigured(
            "Azure AD group mapping AZUREAD_USER_FLAGS_BY_GROUP is defined but does not contain either is_staff or is_superuser."
        )

    superuser_map = flags_by_group.get('is_superuser', [])
    staff_map = flags_by_group.get('is_staff', [])

    # Set groups and permissions based on returned group list
    is_superuser = False
    is_staff = False

    # Remove user group mappings (if any)
    user.groups.through.objects.filter(user=user).delete()
    logger.info('Removing all group mappings for user {}'.format(user))

    for group_name in user_info['groups']:
        if group_name in superuser_map:
            logger.info('Setting superuser status for user {}'.format(user))
            is_superuser = True
            is_staff = True

        if group_name in staff_map:
            logger.info('Setting staff status for user {}'.format(user))
            is_staff = True

        if group_name in group_mapping:
            try:
                group = Group.objects.get(name=group_mapping[group_name])
            except Group.DoesNotExist:
                logger.warning('Azure AD group {} does not exist in NetBox'.format(group_name))
                group = Group.objects.create(name=group_mapping[group_name])

            group.user_set.add(user)
            logger.info('Added user {} to group {}'.format(user, group))

    user.is_superuser = is_superuser
    user.is_staff = is_staff
    user.save()