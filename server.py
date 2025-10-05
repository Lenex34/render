from fastapi import FastAPI, APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List
import uuid
from datetime import datetime, timedelta
import bcrypt
from jose import JWTError, jwt
import aiosmtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.application import MIMEApplication
from email import encoders
from email.utils import encode_rfc2231
import base64


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# Security
SECRET_KEY = os.getenv("SECRET_KEY", "sinapsen-2024")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

security = HTTPBearer()

# MongoDB connection
mongo_url = os.environ.get('MONGO_URL', 'mongodb+srv://serkanakmese_db_user:Kaderaglariniordubugece.3423@servisformu.idsf5wm.mongodb.net/?retryWrites=true&w=majority&appName=servisformu')
client = AsyncIOMotorClient(mongo_url)
db = client['servis_formu']

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create app
app = FastAPI()
api_router = APIRouter(prefix="/api")

# Models
class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    password_hash: str
    role: str = "user"
    created_at: datetime = Field(default_factory=datetime.utcnow)

class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "user"

class UserResponse(BaseModel):
    id: str
    username: str
    role: str
    created_at: datetime

class LoginRequest(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

class EmailRequest(BaseModel):
    to_emails: List[str]
    subject: str
    body: str
    pdf_base64: str
    pdf_filename: str
    logo_base64: str = ""

class SMTPSettings(BaseModel):
    id: str = Field(default_factory=lambda: "smtp_settings")
    smtp_host: str
    smtp_port: int
    smtp_email: str
    smtp_password: str
    smtp_use_tls: bool = True
    mail_body: str = "Sayın Yetkili,\n\nMerhaba,\n\nYapılan işleme ait servis formuna ekten ulaşabilirsiniz.\n\nSaygılarımızla,\nSİNAPSEN"
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class SMTPSettingsUpdate(BaseModel):
    smtp_host: str
    smtp_port: int
    smtp_email: str
    smtp_password: str
    smtp_use_tls: bool = True
    mail_body: str = "Sayın Yetkili,\n\nMerhaba,\n\nYapılan işleme ait servis formuna ekten ulaşabilirsiniz.\n\nSaygılarımızla,\nSİNAPSEN"

class Material(BaseModel):
    name: str
    quantity: str
    unit: str
    unitPrice: str
    totalPrice: float

class ServiceForm(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    formNumber: int
    customerName: str
    authorizedPerson: str
    address: str
    phone: str
    projectNo: str
    email: str
    date: str
    startTime: str
    endTime: str
    serviceType: str
    serviceSummary: str
    description: str
    note: str
    materials: List[Material]
    materialTotal: float
    serviceFee: float
    amount: float
    kdv: float
    grandTotal: float
    customerSignature: str = ""
    customerSignatureName: str = ""
    technicianSignature: str
    technicianSignatureName: str = ""
    customerFeedback: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class ServiceFormCreate(BaseModel):
    formNumber: int
    customerName: str
    authorizedPerson: str
    address: str
    phone: str
    projectNo: str
    email: str
    date: str
    startTime: str
    endTime: str
    serviceType: str
    serviceSummary: str
    description: str
    note: str
    materials: List[Material]
    materialTotal: float
    serviceFee: float
    amount: float
    kdv: float
    grandTotal: float
    customerSignature: str = ""
    customerSignatureName: str = ""
    technicianSignature: str
    technicianSignatureName: str = ""
    customerFeedback: str = ""

class ServiceFormUpdate(BaseModel):
    customerName: str
    authorizedPerson: str
    address: str
    phone: str
    projectNo: str
    email: str
    date: str
    startTime: str
    endTime: str
    serviceType: str
    serviceSummary: str
    description: str
    note: str
    materials: List[Material]
    materialTotal: float
    serviceFee: float
    amount: float
    kdv: float
    grandTotal: float
    customerSignature: str = ""
    customerSignatureName: str = ""
    technicianSignature: str
    technicianSignatureName: str = ""
    customerFeedback: str = ""

# Auth helpers
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash. Bcrypt max 72 bytes."""
    password_bytes = plain_password.encode('utf-8')[:72]
    hashed_bytes = hashed_password.encode('utf-8') if isinstance(hashed_password, str) else hashed_password
    return bcrypt.checkpw(password_bytes, hashed_bytes)

def get_password_hash(password: str) -> str:
    """Hash password with bcrypt. Bcrypt max 72 bytes."""
    password_bytes = password.encode('utf-8')[:72]
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication")
        
        user = await db.users.find_one({"username": username})
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        
        return User(**user)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_admin(current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

# Auth endpoints
@api_router.post("/auth/login", response_model=Token)
async def login(login_data: LoginRequest):
    user = await db.users.find_one({"username": login_data.username})
    if not user or not verify_password(login_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    
    access_token = create_access_token(data={"sub": user["username"]})
    user_response = UserResponse(
        id=user["id"],
        username=user["username"],
        role=user["role"],
        created_at=user["created_at"]
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user_response
    }

@api_router.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        role=current_user.role,
        created_at=current_user.created_at
    )

# User management
@api_router.post("/users", response_model=UserResponse)
async def create_user(user_data: UserCreate, admin: User = Depends(get_current_admin)):
    existing_user = await db.users.find_one({"username": user_data.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    user = User(
        username=user_data.username,
        password_hash=get_password_hash(user_data.password),
        role=user_data.role
    )
    
    await db.users.insert_one(user.dict())
    
    return UserResponse(
        id=user.id,
        username=user.username,
        role=user.role,
        created_at=user.created_at
    )

@api_router.get("/users", response_model=List[UserResponse])
async def get_users(admin: User = Depends(get_current_admin)):
    users = await db.users.find().to_list(1000)
    return [UserResponse(
        id=u["id"],
        username=u["username"],
        role=u["role"],
        created_at=u["created_at"]
    ) for u in users]

@api_router.delete("/users/{user_id}")
async def delete_user(user_id: str, admin: User = Depends(get_current_admin)):
    result = await db.users.delete_one({"id": user_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "User deleted successfully"}

# Service Form endpoints
@api_router.post("/forms")
async def create_form(form_data: ServiceFormCreate, current_user: User = Depends(get_current_user)):
    form = ServiceForm(
        user_id=current_user.id,
        **form_data.dict()
    )
    
    await db.forms.insert_one(form.dict())
    return {"id": form.id, "message": "Form başarıyla kaydedildi"}

@api_router.get("/forms")
async def get_forms(current_user: User = Depends(get_current_user)):
    # Admin herkesi, normal user sadece kendininkini görür
    if current_user.role == "admin":
        forms = await db.forms.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    else:
        forms = await db.forms.find({"user_id": current_user.id}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    
    return forms

@api_router.get("/forms/{form_id}")
async def get_form(form_id: str, current_user: User = Depends(get_current_user)):
    form = await db.forms.find_one({"id": form_id}, {"_id": 0})
    if not form:
        raise HTTPException(status_code=404, detail="Form bulunamadı")
    
    # Yetki kontrolü: Admin veya form sahibi
    if current_user.role != "admin" and form["user_id"] != current_user.id:
        raise HTTPException(status_code=403, detail="Bu forma erişim yetkiniz yok")
    
    return form

@api_router.put("/forms/{form_id}")
async def update_form(form_id: str, form_data: ServiceFormUpdate, current_user: User = Depends(get_current_user)):
    form = await db.forms.find_one({"id": form_id})
    if not form:
        raise HTTPException(status_code=404, detail="Form bulunamadı")
    
    # Yetki kontrolü
    if current_user.role != "admin" and form["user_id"] != current_user.id:
        raise HTTPException(status_code=403, detail="Bu formu düzenleme yetkiniz yok")
    
    # Müşteri imzası varsa ve admin değilse düzenleyemez
    if form.get("customerSignature") and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Müşteri imzalı formlar düzenlenemez. Admin ile iletişime geçin.")
    
    # Güncelle
    update_data = form_data.dict()
    update_data["updated_at"] = datetime.utcnow()
    
    await db.forms.update_one(
        {"id": form_id},
        {"$set": update_data}
    )
    
    return {"message": "Form başarıyla güncellendi"}

@api_router.delete("/forms/{form_id}")
async def delete_form(form_id: str, current_user: User = Depends(get_current_user)):
    form = await db.forms.find_one({"id": form_id})
    if not form:
        raise HTTPException(status_code=404, detail="Form bulunamadı")
    
    # Yetki kontrolü: Sadece admin veya imzasız formun sahibi silebilir
    if current_user.role != "admin":
        if form["user_id"] != current_user.id:
            raise HTTPException(status_code=403, detail="Bu formu silme yetkiniz yok")
        if form.get("customerSignature"):
            raise HTTPException(status_code=403, detail="Müşteri imzalı formlar silinemez. Admin ile iletişime geçin.")
    
    await db.forms.delete_one({"id": form_id})
    return {"message": "Form başarıyla silindi"}

# Mail Body Settings endpoint
@api_router.post("/mail-body-settings")
async def update_mail_body(request: dict, admin: User = Depends(get_current_admin)):
    mail_body = request.get("mail_body", "")
    if not mail_body:
        raise HTTPException(status_code=400, detail="Mail gövdesi boş olamaz")
    
    await db.smtp_settings.update_one(
        {"id": "smtp_settings"},
        {"$set": {"mail_body": mail_body}},
        upsert=True
    )
    
    return {"message": "Mail gövdesi başarıyla kaydedildi"}

# SMTP Settings endpoints
@api_router.get("/smtp-settings")
async def get_smtp_settings(admin: User = Depends(get_current_admin)):
    settings = await db.smtp_settings.find_one({"id": "smtp_settings"})
    if not settings:
        return {"configured": False}
    
    # Şifreyi maskeliyoruz
    return {
        "configured": True,
        "smtp_host": settings.get("smtp_host", ""),
        "smtp_port": settings.get("smtp_port", 587),
        "smtp_email": settings.get("smtp_email", ""),
        "smtp_use_tls": settings.get("smtp_use_tls", True),
        "smtp_password": "********" if settings.get("smtp_password") else "",
        "mail_body": settings.get("mail_body", "Sayın Yetkili,\n\nMerhaba,\n\nYapılan işleme ait servis formuna ekten ulaşabilirsiniz.\n\nSaygılarımızla,\nSİNAPSEN")
    }

@api_router.post("/smtp-settings")
async def update_smtp_settings(settings: SMTPSettingsUpdate, admin: User = Depends(get_current_admin)):
    # Önce SMTP ayarlarını test et
    try:
        # Port 465 = SSL direkt, Port 587 = STARTTLS
        use_ssl = settings.smtp_port == 465
        
        if use_ssl:
            # Port 465: Direkt SSL bağlantısı
            async with aiosmtplib.SMTP(
                hostname=settings.smtp_host, 
                port=settings.smtp_port,
                use_tls=True
            ) as server:
                await server.login(settings.smtp_email, settings.smtp_password)
        else:
            # Port 587 veya diğer: STARTTLS
            async with aiosmtplib.SMTP(hostname=settings.smtp_host, port=settings.smtp_port) as server:
                if settings.smtp_use_tls:
                    await server.starttls()
                await server.login(settings.smtp_email, settings.smtp_password)
        
        logger.info("SMTP connection test successful")
    except aiosmtplib.SMTPAuthenticationError as e:
        logger.error(f"SMTP authentication failed: {str(e)}")
        raise HTTPException(status_code=400, detail="SMTP kimlik doğrulama başarısız. Kullanıcı adı veya şifre hatalı.")
    except aiosmtplib.SMTPConnectError as e:
        logger.error(f"SMTP connection failed: {str(e)}")
        raise HTTPException(status_code=400, detail=f"SMTP sunucusuna bağlanılamadı: {settings.smtp_host}:{settings.smtp_port}")
    except Exception as e:
        logger.error(f"SMTP test failed: {str(e)}")
        raise HTTPException(status_code=400, detail=f"SMTP testi başarısız: {str(e)}")
    
    # Test başarılıysa kaydet
    smtp_settings = SMTPSettings(
        smtp_host=settings.smtp_host,
        smtp_port=settings.smtp_port,
        smtp_email=settings.smtp_email,
        smtp_password=settings.smtp_password,
        smtp_use_tls=settings.smtp_use_tls
    )
    
    await db.smtp_settings.update_one(
        {"id": "smtp_settings"},
        {"$set": smtp_settings.dict()},
        upsert=True
    )
    
    return {"message": "SMTP ayarları test edildi ve başarıyla kaydedildi", "test_passed": True}

# Logo endpoint - Frontend'den logo base64 almak için
@api_router.get("/logo")
async def get_logo():
    """Logo'yu base64 format olarak döndür"""
    try:
        logo_path = ROOT_DIR / "logo.png"
        if logo_path.exists():
            with open(logo_path, "rb") as f:
                logo_data = f.read()
                logo_base64 = base64.b64encode(logo_data).decode('utf-8')
                return {"logo": f"data:image/png;base64,{logo_base64}"}
        else:
            raise HTTPException(status_code=404, detail="Logo dosyası bulunamadı")
    except Exception as e:
        logging.error(f"Logo yüklenemedi: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Logo yüklenemedi: {str(e)}")

# Email endpoint
@api_router.post("/send-email")
async def send_email(email_request: EmailRequest, current_user: User = Depends(get_current_user)):
    try:
        # SMTP ayarlarını MongoDB'dan al
        settings = await db.smtp_settings.find_one({"id": "smtp_settings"})
        
        if not settings:
            raise HTTPException(status_code=500, detail="SMTP ayarları yapılandırılmamış. Lütfen admin panelden SMTP ayarlarını girin.")
        
        smtp_host = settings.get("smtp_host")
        smtp_port = settings.get("smtp_port")
        smtp_email = settings.get("smtp_email")
        smtp_password = settings.get("smtp_password")
        smtp_use_tls = settings.get("smtp_use_tls", True)
        mail_body = settings.get("mail_body", "Sayın Yetkili,\n\nMerhaba,\n\nYapılan işleme ait servis formuna ekten ulaşabilirsiniz.\n\nSaygılarımızla,\nSİNAPSEN")
        
        if not smtp_host or not smtp_email or not smtp_password:
            raise HTTPException(status_code=500, detail="SMTP ayarları eksik")
        
        msg = MIMEMultipart()
        msg['From'] = smtp_email
        msg['To'] = ", ".join(email_request.to_emails)
        msg['Subject'] = email_request.subject
        
        # Mail body'i HTML olarak ekle (ayarlardan gelen + logo)
        # Satır sonlarını <br> ile değiştir
        mail_body_html = mail_body.replace('\n', '<br>')
        
        # Logo varsa HTML'e ekle
        logo_html = ""
        if email_request.logo_base64:
            logo_html = f"""
            <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd;">
                <img src="{email_request.logo_base64}" 
                     alt="Firma Logosu" 
                     style="max-width: 200px; height: auto;" />
            </div>
            """
        
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <div style="white-space: pre-wrap;">{mail_body_html}</div>
            {logo_html}
        </body>
        </html>
        """
        msg.attach(MIMEText(html_body, 'html'))
        
        # PDF ekle
        pdf_data = base64.b64decode(email_request.pdf_base64)
        part = MIMEApplication(pdf_data, _subtype='pdf', name=email_request.pdf_filename)
        part.add_header('Content-Disposition', 'attachment', filename=email_request.pdf_filename)
        msg.attach(part)
        
        # Email gönder
        use_ssl = smtp_port == 465
        
        if use_ssl:
            # Port 465: Direkt SSL
            async with aiosmtplib.SMTP(hostname=smtp_host, port=smtp_port, use_tls=True) as server:
                await server.login(smtp_email, smtp_password)
                await server.send_message(msg)
        else:
            # Port 587: STARTTLS
            async with aiosmtplib.SMTP(hostname=smtp_host, port=smtp_port) as server:
                if smtp_use_tls:
                    await server.starttls()
                await server.login(smtp_email, smtp_password)
                await server.send_message(msg)
        
        logger.info(f"Email sent successfully to {email_request.to_emails}")
        return {"message": "Email başarıyla gönderildi"}
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Email sending failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Email gönderilemedi: {str(e)}")

# Include router
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    # İlk admin kullanıcısını oluştur
    admin = await db.users.find_one({"username": "lenex"})
    if not admin:
        admin_user = User(
            username="lenex",
            password_hash=get_password_hash("NTAG424DNA.3423"),
            role="admin"
        )
        await db.users.insert_one(admin_user.dict())
        logger.info("Admin user created: username='lenex', password='NTAG424DNA.3423'")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

# Run server
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
