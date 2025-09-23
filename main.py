from fastapi import FastAPI, Depends, HTTPException, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from datetime import datetime, timedelta
import bcrypt
import os
import re
from jose import JWTError, jwt

# Database setup
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    password_history = Column(Text, default="")
    posts = relationship("Post", back_populates="author")

class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True, index=True)
    content = Column(Text)
    is_public = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")

Base.metadata.create_all(bind=engine)

# FastAPI app
app = FastAPI()
templates = Jinja2Templates(directory="templates")

SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def validate_password(password: str) -> str:
    """Validate password meets requirements. Returns error message or empty string if valid."""
    if len(password) < 8:
        return "Password must be at least 8 characters long"
    if not any(c.isupper() for c in password):
        return "Password must contain at least one uppercase letter"
    if not any(c.isdigit() for c in password):
        return "Password must contain at least one number"
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        return "Password must contain at least one special character"
    return ""

def is_valid_email(email: str) -> bool:
    pattern = r'^[^@]+@[^@]+\.[^@]+$'
    return re.match(pattern, email) is not None

def create_token(username: str) -> str:
    expire = datetime.utcnow() + timedelta(hours=24)
    return jwt.encode({"sub": username, "exp": expire}, SECRET_KEY, algorithm="HS256")

def get_current_user(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = payload.get("sub")
        user = db.query(User).filter(User.username == username).first()
        return user
    except JWTError:
        return None

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not user:
        return RedirectResponse("/login")
    
    posts = db.query(Post).filter(
        (Post.is_public == True) | (Post.user_id == user.id)
    ).order_by(Post.created_at.desc()).all()
    
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user, "posts": posts})

@app.get("/create-post", response_class=HTMLResponse)
def create_post_page(request: Request, user: User = Depends(get_current_user)):
    if not user:
        return RedirectResponse("/login")
    return templates.TemplateResponse("create_post.html", {"request": request, "user": user})

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
def login(request: Request, email: str = Form(), password: str = Form(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})
    
    token = create_token(user.username)
    response = RedirectResponse("/", status_code=302)
    response.set_cookie("access_token", token, httponly=True)
    return response

@app.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request, error: str = None):
    return templates.TemplateResponse("signup.html", {"request": request, "error": error})

@app.post("/signup")
def signup(request: Request, username: str = Form(), email: str = Form(), password: str = Form(), db: Session = Depends(get_db)):
    # Validate password
    password_error = validate_password(password)
    if password_error:
        return templates.TemplateResponse("signup.html", {"request": request, "error": password_error})
    
    if not is_valid_email(email):
        return templates.TemplateResponse("signup.html", {"request": request, "error": "Invalid email format"})
    
    if db.query(User).filter(User.username == username).first():
        return templates.TemplateResponse("signup.html", {"request": request, "error": "Username exists"})
    
    if db.query(User).filter(User.email == email).first():
        return templates.TemplateResponse("signup.html", {"request": request, "error": "Email already registered"})
    
    hashed_pw = hash_password(password)
    user = User(username=username, email=email, password=hashed_pw, password_history=hashed_pw)
    db.add(user)
    db.commit()
    
    token = create_token(username)
    response = RedirectResponse("/", status_code=302)
    response.set_cookie("access_token", token, httponly=True)
    return response

@app.post("/post")
def create_post(content: str = Form(), is_public: bool = Form(False), user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    post = Post(content=content, is_public=is_public, user_id=user.id)
    db.add(post)
    db.commit()
    return RedirectResponse("/", status_code=302)

@app.get("/change-password", response_class=HTMLResponse)
def change_password_page(request: Request, user: User = Depends(get_current_user)):
    if not user:
        return RedirectResponse("/login")
    return templates.TemplateResponse("change_password.html", {"request": request, "user": user})

@app.post("/change-password")
def change_password(request: Request, current_password: str = Form(), new_password: str = Form(), user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not user or not verify_password(current_password, user.password):
        return templates.TemplateResponse("change_password.html", {"request": request, "user": user, "error": "Invalid current password"})
    
    # Validate new password
    password_error = validate_password(new_password)
    if password_error:
        return templates.TemplateResponse("change_password.html", {"request": request, "user": user, "error": password_error})
    
    # Check last 3 passwords
    history = user.password_history.split(",") if user.password_history else []
    for old_hash in history[-3:]:
        if old_hash and verify_password(new_password, old_hash):
            return templates.TemplateResponse("change_password.html", {"request": request, "user": user, "error": "Cannot reuse recent passwords"})
    
    new_hash = hash_password(new_password)
    history.append(user.password)
    user.password = new_hash
    user.password_history = ",".join(history[-3:])
    db.commit()
    
    return RedirectResponse("/", status_code=302)

@app.post("/delete-post/{post_id}")
def delete_post(post_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    post = db.query(Post).filter(Post.id == post_id, Post.user_id == user.id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found or not authorized")
    
    db.delete(post)
    db.commit()
    return RedirectResponse("/", status_code=302)

@app.get("/logout")
def logout():
    response = RedirectResponse("/login", status_code=302)
    response.delete_cookie("access_token")
    return response

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))