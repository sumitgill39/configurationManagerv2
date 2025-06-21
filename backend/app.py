import os
import logging
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import redis
import json
from functools import wraps

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_app():
    app = Flask(__name__)
    
    # Configuration
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=int(os.getenv('JWT_EXPIRES_HOURS', '24')))
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///config_manager.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['REDIS_URL'] = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    
    # Initialize extensions
    db = SQLAlchemy(app)
    migrate = Migrate(app, db)
    jwt = JWTManager(app)
    
    # CORS configuration - More permissive for development
    CORS(app, 
         origins=['http://localhost:3000', 'http://localhost:8000', 'http://localhost:80'],
         allow_headers=['Content-Type', 'Authorization'],
         methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
         supports_credentials=True)
    
    # Redis connection (optional)
    try:
        redis_client = redis.from_url(app.config['REDIS_URL'])
        redis_client.ping()
        logger.info("Redis connection established")
    except Exception as e:
        logger.warning(f"Redis connection failed: {e}")
        redis_client = None
    
    # Models
    class User(db.Model):
        __tablename__ = 'users'
        
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(80), unique=True, nullable=False)
        email = db.Column(db.String(120), unique=True, nullable=False)
        password_hash = db.Column(db.String(255), nullable=False)
        role = db.Column(db.String(20), default='user')
        is_active = db.Column(db.Boolean, default=True)
        created_at = db.Column(db.DateTime, default=datetime.utcnow)
        last_login = db.Column(db.DateTime)
        
        # Relationships
        applications = db.relationship('Application', backref='owner', lazy=True, cascade='all, delete-orphan')
        configurations = db.relationship('Configuration', backref='creator', lazy=True)
        
        def set_password(self, password):
            self.password_hash = generate_password_hash(password)
        
        def check_password(self, password):
            return check_password_hash(self.password_hash, password)
        
        def to_dict(self):
            return {
                'id': self.id,
                'username': self.username,
                'email': self.email,
                'role': self.role,
                'is_active': self.is_active,
                'created_at': self.created_at.isoformat() if self.created_at else None,
                'last_login': self.last_login.isoformat() if self.last_login else None
            }
    
    class Application(db.Model):
        __tablename__ = 'applications'
        
        id = db.Column(db.Integer, primary_key=True)
        name = db.Column(db.String(100), nullable=False)
        description = db.Column(db.Text)
        user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
        created_at = db.Column(db.DateTime, default=datetime.utcnow)
        updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
        
        # Relationships
        configurations = db.relationship('Configuration', backref='application', lazy=True, cascade='all, delete-orphan')
        
        def to_dict(self):
            return {
                'id': self.id,
                'name': self.name,
                'description': self.description,
                'user_id': self.user_id,
                'created_at': self.created_at.isoformat(),
                'updated_at': self.updated_at.isoformat(),
                'configuration_count': len(self.configurations)
            }
    
    class Configuration(db.Model):
        __tablename__ = 'configurations'
        
        id = db.Column(db.Integer, primary_key=True)
        name = db.Column(db.String(100), nullable=False)
        version = db.Column(db.String(50), nullable=False)
        environment = db.Column(db.String(20), nullable=False)
        application_id = db.Column(db.Integer, db.ForeignKey('applications.id'), nullable=False)
        user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
        original_filename = db.Column(db.String(255))
        original_content = db.Column(db.Text)
        created_at = db.Column(db.DateTime, default=datetime.utcnow)
        updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
        
        # Relationships
        config_items = db.relationship('ConfigurationItem', backref='configuration', lazy=True, cascade='all, delete-orphan')
        
        def to_dict(self):
            return {
                'id': self.id,
                'name': self.name,
                'version': self.version,
                'environment': self.environment,
                'application_id': self.application_id,
                'user_id': self.user_id,
                'original_filename': self.original_filename,
                'created_at': self.created_at.isoformat(),
                'updated_at': self.updated_at.isoformat(),
                'item_count': len(self.config_items)
            }
    
    class ConfigurationItem(db.Model):
        __tablename__ = 'configuration_items'
        
        id = db.Column(db.Integer, primary_key=True)
        configuration_id = db.Column(db.Integer, db.ForeignKey('configurations.id'), nullable=False)
        key = db.Column(db.String(255), nullable=False)
        value = db.Column(db.Text)
        sensitivity = db.Column(db.String(10), default='low')  # low, medium, high
        created_at = db.Column(db.DateTime, default=datetime.utcnow)
        updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
        
        def to_dict(self):
            return {
                'id': self.id,
                'configuration_id': self.configuration_id,
                'key': self.key,
                'value': self.value,
                'sensitivity': self.sensitivity,
                'created_at': self.created_at.isoformat(),
                'updated_at': self.updated_at.isoformat()
            }
    
    class AuditLog(db.Model):
        __tablename__ = 'audit_logs'
        
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
        action = db.Column(db.String(50), nullable=False)
        resource_type = db.Column(db.String(50))
        resource_id = db.Column(db.Integer)
        details = db.Column(db.JSON)
        ip_address = db.Column(db.String(45))
        user_agent = db.Column(db.Text)
        created_at = db.Column(db.DateTime, default=datetime.utcnow)
        
        def to_dict(self):
            return {
                'id': self.id,
                'user_id': self.user_id,
                'action': self.action,
                'resource_type': self.resource_type,
                'resource_id': self.resource_id,
                'details': self.details,
                'ip_address': self.ip_address,
                'created_at': self.created_at.isoformat()
            }
    
    # Utility functions
    def log_audit(user_id, action, resource_type=None, resource_id=None, details=None):
        try:
            audit_log = AuditLog(
                user_id=user_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                details=details,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )
            db.session.add(audit_log)
            db.session.commit()
        except Exception as e:
            logger.error(f"Audit logging failed: {e}")
    
    def admin_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current_user_id = get_jwt_identity()
            user = User.query.get(current_user_id)
            if not user or user.role != 'admin':
                return jsonify({'error': 'Admin access required'}), 403
            return f(*args, **kwargs)
        return decorated_function
    
    def get_sensitivity(key):
        """Determine sensitivity level of configuration key"""
        key_lower = key.lower()
        
        high_patterns = ['password', 'secret', 'key', 'token', 'connectionstring', 'private']
        medium_patterns = ['server', 'host', 'url', 'username', 'email', 'database', 'endpoint']
        
        for pattern in high_patterns:
            if pattern in key_lower:
                return 'high'
        
        for pattern in medium_patterns:
            if pattern in key_lower:
                return 'medium'
        
        return 'low'
    
    # Routes
    @app.route('/api/health', methods=['GET'])
    def health():
        try:
            # Check database connection
            db.session.execute('SELECT 1')
            db_status = "healthy"
        except Exception as e:
            db_status = f"unhealthy: {str(e)}"
        
        # Check Redis connection
        redis_status = "healthy" if redis_client else "unavailable"
        if redis_client:
            try:
                redis_client.ping()
            except:
                redis_status = "unhealthy"
        
        return jsonify({
            "status": "healthy" if db_status == "healthy" else "degraded",
            "service": "AI Configuration Manager",
            "version": "1.0.0",
            "database": db_status,
            "redis": redis_status,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    # Authentication Routes
    @app.route('/api/auth/register', methods=['POST'])
    def register():
        try:
            data = request.get_json()
            if not data:
                return jsonify({"error": "No JSON data provided"}), 400
                
            username = data.get('username', '').strip()
            email = data.get('email', '').strip()
            password = data.get('password', '')
            role = data.get('role', 'user')
            
            logger.info(f"Registration attempt for username: {username}")
            
            # Validate input
            if not all([username, email, password]):
                return jsonify({"error": "Missing required fields"}), 400
            
            if len(password) < 8:
                return jsonify({"error": "Password must be at least 8 characters"}), 400
            
            if role not in ['user', 'admin']:
                return jsonify({"error": "Invalid role"}), 400
            
            # Check if user already exists
            if User.query.filter((User.username == username) | (User.email == email)).first():
                return jsonify({"error": "Username or email already exists"}), 400
            
            # Create user
            user = User(username=username, email=email, role=role)
            user.set_password(password)
            
            db.session.add(user)
            db.session.commit()
            
            logger.info(f"User created successfully: {username}")
            log_audit(user.id, 'user_registered')
            
            return jsonify({"message": "User registered successfully"}), 201
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Registration error: {e}")
            return jsonify({"error": "Registration failed"}), 500
    
    @app.route('/api/auth/login', methods=['POST'])
    def login():
        try:
            data = request.get_json()
            if not data:
                return jsonify({"error": "No JSON data provided"}), 400
                
            username = data.get('username', '').strip()
            password = data.get('password', '')
            
            logger.info(f"Login attempt for username: {username}")
            
            if not all([username, password]):
                return jsonify({"error": "Missing username or password"}), 400
            
            # Find user by username or email
            user = User.query.filter(
                (User.username == username) | (User.email == username)
            ).first()
            
            if not user:
                logger.warning(f"User not found: {username}")
                return jsonify({"error": "Invalid credentials"}), 401
                
            if not user.check_password(password):
                logger.warning(f"Invalid password for user: {username}")
                return jsonify({"error": "Invalid credentials"}), 401
            
            if not user.is_active:
                logger.warning(f"Inactive user login attempt: {username}")
                return jsonify({"error": "Account is deactivated"}), 401
            
            # Update last login
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Create access token
            access_token = create_access_token(identity=user.id)
            
            logger.info(f"User logged in successfully: {username}")
            log_audit(user.id, 'user_login')
            
            return jsonify({
                "access_token": access_token,
                "user": user.to_dict()
            }), 200
            
        except Exception as e:
            logger.error(f"Login error: {e}")
            return jsonify({"error": "Login failed"}), 500
    
    @app.route('/api/auth/profile', methods=['GET'])
    @jwt_required()
    def profile():
        try:
            user_id = get_jwt_identity()
            logger.info(f"Profile request for user_id: {user_id}")
            
            user = User.query.get(user_id)
            
            if not user:
                logger.warning(f"User not found for user_id: {user_id}")
                return jsonify({"error": "User not found"}), 404
            
            return jsonify({"user": user.to_dict()}), 200
            
        except Exception as e:
            logger.error(f"Profile error: {e}")
            return jsonify({"error": "Failed to get profile"}), 500
    
    # Application Routes
    @app.route('/api/applications', methods=['GET'])
    @jwt_required()
    def get_applications():
        try:
            user_id = get_jwt_identity()
            logger.info(f"Get applications for user_id: {user_id}")
            
            applications = Application.query.filter_by(user_id=user_id).all()
            
            return jsonify({
                "applications": [app.to_dict() for app in applications]
            }), 200
            
        except Exception as e:
            logger.error(f"Get applications error: {e}")
            return jsonify({"error": "Failed to get applications"}), 500
    
    @app.route('/api/applications', methods=['POST'])
    @jwt_required()
    def create_application():
        try:
            user_id = get_jwt_identity()
            data = request.get_json()
            
            if not data:
                return jsonify({"error": "No JSON data provided"}), 400
            
            name = data.get('name', '').strip()
            description = data.get('description', '').strip()
            
            logger.info(f"Create application '{name}' for user_id: {user_id}")
            
            if not name:
                return jsonify({"error": "Application name is required"}), 400
            
            # Check if application name already exists for this user
            existing = Application.query.filter_by(user_id=user_id, name=name).first()
            if existing:
                return jsonify({"error": "Application name already exists"}), 400
            
            application = Application(
                name=name,
                description=description,
                user_id=user_id
            )
            
            db.session.add(application)
            db.session.commit()
            
            logger.info(f"Application created successfully: {application.id}")
            log_audit(user_id, 'application_created', 'application', application.id, {'name': name})
            
            return jsonify({"application": application.to_dict()}), 201
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Create application error: {e}")
            return jsonify({"error": "Failed to create application"}), 500
    
    # Configuration Routes
    @app.route('/api/applications/<int:app_id>/configurations', methods=['GET'])
    @jwt_required()
    def get_configurations(app_id):
        try:
            user_id = get_jwt_identity()
            logger.info(f"Get configurations for app_id: {app_id}, user_id: {user_id}")
            
            # Verify application ownership
            application = Application.query.filter_by(id=app_id, user_id=user_id).first()
            if not application:
                return jsonify({"error": "Application not found"}), 404
            
            configurations = Configuration.query.filter_by(application_id=app_id).all()
            
            return jsonify({
                "configurations": [config.to_dict() for config in configurations]
            }), 200
            
        except Exception as e:
            logger.error(f"Get configurations error: {e}")
            return jsonify({"error": "Failed to get configurations"}), 500
    
    @app.route('/api/applications/<int:app_id>/configurations', methods=['POST'])
    @jwt_required()
    def create_configuration(app_id):
        try:
            user_id = get_jwt_identity()
            logger.info(f"Create configuration for app_id: {app_id}, user_id: {user_id}")
            
            # Verify application ownership
            application = Application.query.filter_by(id=app_id, user_id=user_id).first()
            if not application:
                logger.warning(f"Application not found: {app_id} for user: {user_id}")
                return jsonify({"error": "Application not found"}), 404
            
            data = request.get_json()
            if not data:
                return jsonify({"error": "No JSON data provided"}), 400
            
            name = data.get('name', '').strip()
            version = data.get('version', '').strip()
            environment = data.get('environment', '').strip()
            original_filename = data.get('original_filename', '')
            original_content = data.get('original_content', '')
            config_items = data.get('config_items', [])
            
            logger.info(f"Configuration details: name={name}, version={version}, env={environment}, items={len(config_items)}")
            
            if not all([name, version, environment]):
                return jsonify({"error": "Name, version, and environment are required"}), 400
            
            if environment not in ['DEV', 'QA', 'UAT', 'PROD']:
                return jsonify({"error": "Invalid environment"}), 400
            
            # Check for duplicate configuration
            existing = Configuration.query.filter_by(
                application_id=app_id,
                name=name,
                version=version,
                environment=environment
            ).first()
            
            if existing:
                return jsonify({"error": "Configuration already exists"}), 400
            
            # Create configuration
            configuration = Configuration(
                name=name,
                version=version,
                environment=environment,
                application_id=app_id,
                user_id=user_id,
                original_filename=original_filename,
                original_content=original_content
            )
            
            db.session.add(configuration)
            db.session.flush()  # Get the ID
            
            logger.info(f"Configuration created with ID: {configuration.id}")
            
            # Create configuration items
            for item_data in config_items:
                key = item_data.get('key', '')
                value = item_data.get('value', '')
                sensitivity = item_data.get('sensitivity') or get_sensitivity(key)
                
                if key:
                    config_item = ConfigurationItem(
                        configuration_id=configuration.id,
                        key=key,
                        value=value,
                        sensitivity=sensitivity
                    )
                    db.session.add(config_item)
            
            db.session.commit()
            
            logger.info(f"Configuration saved successfully: {configuration.id}")
            log_audit(user_id, 'configuration_created', 'configuration', configuration.id, {
                'name': name,
                'version': version,
                'environment': environment
            })
            
            return jsonify({"configuration": configuration.to_dict()}), 201
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Create configuration error: {e}")
            return jsonify({"error": "Failed to create configuration"}), 500
    
    @app.route('/api/configurations/<int:config_id>/items', methods=['GET'])
    @jwt_required()
    def get_configuration_items(config_id):
        try:
            user_id = get_jwt_identity()
            
            # Verify configuration ownership
            configuration = Configuration.query.filter_by(id=config_id, user_id=user_id).first()
            if not configuration:
                return jsonify({"error": "Configuration not found"}), 404
            
            items = ConfigurationItem.query.filter_by(configuration_id=config_id).all()
            
            return jsonify({
                "items": [item.to_dict() for item in items]
            }), 200
            
        except Exception as e:
            logger.error(f"Get configuration items error: {e}")
            return jsonify({"error": "Failed to get configuration items"}), 500
    
    # Analytics Routes
    @app.route('/api/analytics/dashboard', methods=['GET'])
    @jwt_required()
    def dashboard_analytics():
        try:
            user_id = get_jwt_identity()
            
            # Get counts
            total_applications = Application.query.filter_by(user_id=user_id).count()
            total_configurations = Configuration.query.filter_by(user_id=user_id).count()
            
            # Get sensitivity distribution
            sensitivity_query = db.session.query(
                ConfigurationItem.sensitivity,
                db.func.count(ConfigurationItem.id)
            ).join(Configuration).filter(
                Configuration.user_id == user_id
            ).group_by(ConfigurationItem.sensitivity).all()
            
            sensitivity_dist = {item[0]: item[1] for item in sensitivity_query}
            
            # Get environment distribution
            env_query = db.session.query(
                Configuration.environment,
                db.func.count(Configuration.id)
            ).filter(Configuration.user_id == user_id).group_by(Configuration.environment).all()
            
            env_dist = {item[0]: item[1] for item in env_query}
            
            # Get recent activity
            recent_logs = AuditLog.query.filter_by(user_id=user_id).order_by(
                AuditLog.created_at.desc()
            ).limit(10).all()
            
            return jsonify({
                "summary": {
                    "total_applications": total_applications,
                    "total_configurations": total_configurations,
                    "sensitivity_distribution": sensitivity_dist,
                    "environment_distribution": env_dist
                },
                "recent_activity": [log.to_dict() for log in recent_logs]
            }), 200
            
        except Exception as e:
            logger.error(f"Dashboard analytics error: {e}")
            return jsonify({"error": "Failed to get analytics"}), 500
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"error": "Resource not found"}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return jsonify({"error": "Internal server error"}), 500
    
    # JWT error handlers
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        logger.warning("Expired token used")
        return jsonify({"error": "Token has expired"}), 401
    
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        logger.warning(f"Invalid token: {error}")
        return jsonify({"error": "Invalid token"}), 401
    
    @jwt.unauthorized_loader
    def missing_token_callback(error):
        logger.warning("Missing token")
        return jsonify({"error": "Authorization token is required"}), 401
    
    # Create tables and default data
    with app.app_context():
        try:
            db.create_all()
            logger.info("Database tables created/verified")
            
            # Create default admin user if it doesn't exist
            admin_user = User.query.filter_by(username='admin').first()
            if not admin_user:
                admin_user = User(
                    username='admin',
                    email='admin@example.com',
                    role='admin'
                )
                admin_user.set_password('admin123')
                db.session.add(admin_user)
                db.session.commit()
                logger.info("Default admin user created: admin/admin123")
                
        except Exception as e:
            logger.error(f"Database initialization error: {e}")
    
    return app

if __name__ == '__main__':
    app = create_app()
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug)