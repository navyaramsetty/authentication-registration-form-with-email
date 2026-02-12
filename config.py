class Config:
    SECRET_KEY = "secret123"

    SQLALCHEMY_DATABASE_URI = "sqlite:///database.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    

    MAIL_SERVER = "smtp.gmail.com"
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = "navyaramsetty@gmail.com"
    MAIL_PASSWORD = "dlvi xxao naui loax"

    JWT_SECRET_KEY = "jwt-secret"
