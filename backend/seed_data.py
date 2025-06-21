"""
Seed data for development and testing
"""
import json
from datetime import datetime
from app import create_app, db, User, Application, Configuration, ConfigurationItem, AuditLog

def seed_database():
    """Seed the database with sample data"""
    print("Seeding database with sample data...")
    
    # Create sample users
    users_data = [
        {
            'username': 'admin',
            'email': 'admin@example.com',
            'role': 'admin',
            'password': 'admin123'
        },
        {
            'username': 'developer',
            'email': 'dev@example.com',
            'role': 'user',
            'password': 'developer123'
        },
        {
            'username': 'tester',
            'email': 'test@example.com',
            'role': 'user',
            'password': 'tester123'
        }
    ]
    
    users = []
    for user_data in users_data:
        existing_user = User.query.filter_by(username=user_data['username']).first()
        if not existing_user:
            user = User(
                username=user_data['username'],
                email=user_data['email'],
                role=user_data['role']
            )
            user.set_password(user_data['password'])
            db.session.add(user)
            users.append(user)
            print(f"Created user: {user_data['username']}")
        else:
            users.append(existing_user)
            print(f"User already exists: {user_data['username']}")
    
    db.session.flush()
    
    # Create sample applications
    applications_data = [
        {
            'name': 'E-Commerce API',
            'description': 'Main e-commerce application API with user authentication and payment processing',
            'user_index': 0  # admin
        },
        {
            'name': 'Analytics Dashboard',
            'description': 'Real-time analytics and reporting dashboard for business intelligence',
            'user_index': 1  # developer
        },
        {
            'name': 'Mobile App Backend',
            'description': 'Backend services for iOS and Android mobile applications',
            'user_index': 0  # admin
        },
        {
            'name': 'ML Model Service',
            'description': 'Machine learning model serving and inference API',
            'user_index': 1  # developer
        }
    ]
    
    applications = []
    for app_data in applications_data:
        existing_app = Application.query.filter_by(
            name=app_data['name'], 
            user_id=users[app_data['user_index']].id
        ).first()
        
        if not existing_app:
            app = Application(
                name=app_data['name'],
                description=app_data['description'],
                user_id=users[app_data['user_index']].id
            )
            db.session.add(app)
            applications.append(app)
            print(f"Created application: {app_data['name']}")
        else:
            applications.append(existing_app)
            print(f"Application already exists: {app_data['name']}")
    
    db.session.flush()
    
    # Sample configuration data
    sample_configs = [
        {
            'app_index': 0,  # E-Commerce API
            'configs': [
                {
                    'name': 'Production Config',
                    'version': 'v1.0.0',
                    'environment': 'PROD',
                    'items': [
                        {'key': 'database.host', 'value': 'prod-db-cluster.amazonaws.com', 'sensitivity': 'medium'},
                        {'key': 'database.password', 'value': 'super-secret-prod-password', 'sensitivity': 'high'},
                        {'key': 'api.rate_limit', 'value': '1000', 'sensitivity': 'low'},
                        {'key': 'payment.stripe_secret_key', 'value': 'sk_live_51234567890abcdef', 'sensitivity': 'high'},
                        {'key': 'email.smtp_server', 'value': 'smtp.mailgun.org', 'sensitivity': 'medium'},
                        {'key': 'cache.redis_url', 'value': 'redis://prod-cache:6379/0', 'sensitivity': 'medium'},
                        {'key': 'logging.level', 'value': 'INFO', 'sensitivity': 'low'},
                        {'key': 'jwt.secret', 'value': 'prod-jwt-secret-key-very-long', 'sensitivity': 'high'}
                    ]
                },
                {
                    'name': 'Staging Config',
                    'version': 'v1.0.0',
                    'environment': 'UAT',
                    'items': [
                        {'key': 'database.host', 'value': 'staging-db.amazonaws.com', 'sensitivity': 'medium'},
                        {'key': 'database.password', 'value': 'staging-password-123', 'sensitivity': 'high'},
                        {'key': 'api.rate_limit', 'value': '500', 'sensitivity': 'low'},
                        {'key': 'payment.stripe_secret_key', 'value': 'sk_test_51234567890abcdef', 'sensitivity': 'high'},
                        {'key': 'email.smtp_server', 'value': 'smtp.mailtrap.io', 'sensitivity': 'medium'},
                        {'key': 'cache.redis_url', 'value': 'redis://staging-cache:6379/0', 'sensitivity': 'medium'},
                        {'key': 'logging.level', 'value': 'DEBUG', 'sensitivity': 'low'}
                    ]
                }
            ]
        },
        {
            'app_index': 1,  # Analytics Dashboard
            'configs': [
                {
                    'name': 'Dashboard Config',
                    'version': 'v2.1.0',
                    'environment': 'PROD',
                    'items': [
                        {'key': 'database.connection_string', 'value': 'postgresql://analytics:password@prod-analytics-db:5432/analytics', 'sensitivity': 'high'},
                        {'key': 'oauth.google_client_id', 'value': '1234567890-abcdefghijklmnop.apps.googleusercontent.com', 'sensitivity': 'medium'},
                        {'key': 'oauth.google_client_secret', 'value': 'GOCSPX-super-secret-oauth-key', 'sensitivity': 'high'},
                        {'key': 'dashboard.refresh_interval', 'value': '30000', 'sensitivity': 'low'},
                        {'key': 'api.external_data_url', 'value': 'https://api.external-service.com/v1', 'sensitivity': 'medium'},
                        {'key': 'monitoring.datadog_api_key', 'value': 'dd_api_key_123456789abcdef', 'sensitivity': 'high'}
                    ]
                }
            ]
        },
        {
            'app_index': 2,  # Mobile App Backend
            'configs': [
                {
                    'name': 'Mobile API Config',
                    'version': 'v3.0.0',
                    'environment': 'PROD',
                    'items': [
                        {'key': 'push.apns_key_id', 'value': 'ABC123DEF4', 'sensitivity': 'high'},
                        {'key': 'push.fcm_server_key', 'value': 'AAAA1234567890:APA91bF...', 'sensitivity': 'high'},
                        {'key': 'api.base_url', 'value': 'https://api.mobileapp.com/v3', 'sensitivity': 'low'},
                        {'key': 'database.mobile_db_host', 'value': 'mobile-prod-db.cluster.amazonaws.com', 'sensitivity': 'medium'},
                        {'key': 'auth.session_timeout', 'value': '3600', 'sensitivity': 'low'},
                        {'key': 's3.bucket_name', 'value': 'mobile-app-uploads-prod', 'sensitivity': 'medium'},
                        {'key': 's3.access_key_id', 'value': 'AKIAIOSFODNN7EXAMPLE', 'sensitivity': 'high'},
                        {'key': 's3.secret_access_key', 'value': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'sensitivity': 'high'}
                    ]
                },
                {
                    'name': 'Development Config',
                    'version': 'v3.0.0',
                    'environment': 'DEV',
                    'items': [
                        {'key': 'push.apns_key_id', 'value': 'DEV123ABC4', 'sensitivity': 'high'},
                        {'key': 'push.fcm_server_key', 'value': 'AAAA9876543210:APA91bF...', 'sensitivity': 'high'},
                        {'key': 'api.base_url', 'value': 'https://dev-api.mobileapp.com/v3', 'sensitivity': 'low'},
                        {'key': 'database.mobile_db_host', 'value': 'localhost:5432', 'sensitivity': 'medium'},
                        {'key': 'auth.session_timeout', 'value': '7200', 'sensitivity': 'low'},
                        {'key': 'debug.enabled', 'value': 'true', 'sensitivity': 'low'}
                    ]
                }
            ]
        }
    ]
    
    # Create configurations and items
    configurations = []
    for config_data in sample_configs:
        app = applications[config_data['app_index']]
        
        for config_info in config_data['configs']:
            existing_config = Configuration.query.filter_by(
                application_id=app.id,
                name=config_info['name'],
                version=config_info['version'],
                environment=config_info['environment']
            ).first()
            
            if not existing_config:
                # Create sample file content
                file_content = {}
                for item in config_info['items']:
                    keys = item['key'].split('.')
                    current = file_content
                    for key in keys[:-1]:
                        if key not in current:
                            current[key] = {}
                        current = current[key]
                    current[keys[-1]] = item['value']
                
                config = Configuration(
                    name=config_info['name'],
                    version=config_info['version'],
                    environment=config_info['environment'],
                    application_id=app.id,
                    user_id=app.user_id,
                    original_filename=f"{config_info['name'].lower().replace(' ', '_')}.json",
                    original_content=json.dumps(file_content, indent=2)
                )
                db.session.add(config)
                db.session.flush()
                
                # Add configuration items
                for item_data in config_info['items']:
                    item = ConfigurationItem(
                        configuration_id=config.id,
                        key=item_data['key'],
                        value=item_data['value'],
                        sensitivity=item_data['sensitivity']
                    )
                    db.session.add(item)
                
                configurations.append(config)
                print(f"Created configuration: {config_info['name']} for {app.name}")
            else:
                configurations.append(existing_config)
                print(f"Configuration already exists: {config_info['name']} for {app.name}")
    
    # Create some audit logs
    audit_logs_data = [
        {
            'user_index': 0,
            'action': 'user_login',
            'details': {'login_method': 'password', 'success': True}
        },
        {
            'user_index': 0,
            'action': 'application_created',
            'resource_type': 'application',
            'resource_id': 1,
            'details': {'name': 'E-Commerce API'}
        },
        {
            'user_index': 1,
            'action': 'configuration_created',
            'resource_type': 'configuration',
            'resource_id': 1,
            'details': {'name': 'Production Config', 'environment': 'PROD'}
        },
        {
            'user_index': 0,
            'action': 'configuration_downloaded',
            'resource_type': 'configuration',
            'resource_id': 1,
            'details': {'format': 'json'}
        }
    ]
    
    for log_data in audit_logs_data:
        log = AuditLog(
            user_id=users[log_data['user_index']].id,
            action=log_data['action'],
            resource_type=log_data.get('resource_type'),
            resource_id=log_data.get('resource_id'),
            details=log_data.get('details'),
            ip_address='127.0.0.1',
            user_agent='Seed Script'
        )
        db.session.add(log)
    
    # Commit all changes
    try:
        db.session.commit()
        print("\n✅ Database seeded successfully!")
        print("\nSample users created:")
        for user_data in users_data:
            print(f"  - {user_data['username']} / {user_data['password']} ({user_data['role']})")
        print(f"\nCreated {len(applications)} applications with {len(configurations)} configurations")
        print(f"Total configuration items: {sum(len(config['items']) for config_set in sample_configs for config in config_set['configs'])}")
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error seeding database: {e}")
        raise

if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        seed_database()