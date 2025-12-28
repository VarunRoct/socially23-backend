import secrets
import httpx
from fastapi import HTTPException
from fastapi import FastAPI, APIRouter, HTTPException, Cookie, Response, UploadFile, File, Form
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import httpx
import base64
from groq import Groq
from fastapi.responses import RedirectResponse
from urllib.parse import urlencode
from fastapi.middleware.cors import CORSMiddleware

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]
GOOGLE_CLIENT_ID = os.environ["GOOGLE_CLIENT_ID"]
GOOGLE_CLIENT_SECRET = os.environ["GOOGLE_CLIENT_SECRET"]
GOOGLE_REDIRECT_URI = os.environ["GOOGLE_REDIRECT_URI"]

# Groq client (will be None until API key is provided)
groq_client = None
if os.environ.get('GROQ_API_KEY'):
    groq_client = Groq(api_key=os.environ.get('GROQ_API_KEY'))

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Define Models
class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: str
    name: str
    picture: str
    bio: Optional[str] = ""
    ai_enabled: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserSession(BaseModel):
    model_config = ConfigDict(extra="ignore")
    user_id: str
    session_token: str
    expires_at: datetime
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Post(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    image_data: str  # Base64 encoded image
    caption: str
    likes_count: int = 0
    comments_count: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class PostCreate(BaseModel):
    image_data: str
    caption: str

class Comment(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    post_id: str
    user_id: str
    text: str
    is_ai_reply: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class CommentCreate(BaseModel):
    text: str

class Like(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    post_id: str
    user_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Save(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    post_id: str
    user_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AIConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    user_id: str
    model_name: str = "llama-3.3-70b-versatile"
    training_data: str = ""
    is_active: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SessionRequest(BaseModel):
    session_id: str

class GoogleCallbackRequest(BaseModel):
    code: str

class UserProfile(BaseModel):
    bio: str

class AIToggle(BaseModel):
    enabled: bool

class GoogleAuthCode(BaseModel):
    code: str

# Helper function to get current user
async def get_current_user(session_token: Optional[str]) -> Optional[User]:
    if not session_token:
        return None
    
    session = await db.user_sessions.find_one({
        "session_token": session_token,
        "expires_at": {"$gt": datetime.now(timezone.utc).isoformat()}
    })
    
    if not session:
        return None
    
    user_doc = await db.users.find_one({"id": session["user_id"]}, {"_id": 0})
    if user_doc:
        if isinstance(user_doc.get('created_at'), str):
            user_doc['created_at'] = datetime.fromisoformat(user_doc['created_at'])
        return User(**user_doc)
    return None



# Google OAuth – start login
@api_router.get("/auth/google/login")
async def google_login():
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": "http://localhost:8000/api/auth/google/callback",
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent",
    }

    auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)
    return RedirectResponse(auth_url)


# 🔹 Google OAuth – handle callback (PASTE THIS PART)
@api_router.get("/auth/google/callback")
async def google_callback(code: str, response: Response):

    

    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")

    # 1) Exchange code for tokens
    token_data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }

    async with httpx.AsyncClient() as client_http:
        token_res = await client_http.post(
            "https://oauth2.googleapis.com/token",
            data=token_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    if token_res.status_code != 200:
        print("Token error:", token_res.text)
        raise HTTPException(status_code=400, detail="Failed to exchange code")

    token_json = token_res.json()
    access_token = token_json.get("access_token")

    if not access_token:
        raise HTTPException(status_code=400, detail="No access token returned")

    # 2) Get user info from Google
    async with httpx.AsyncClient() as client_http:
        userinfo_res = await client_http.get(
            "https://openidconnect.googleapis.com/v1/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )

    if userinfo_res.status_code != 200:
        print("Userinfo error:", userinfo_res.text)
        raise HTTPException(status_code=400, detail="Failed to fetch user info")

    info = userinfo_res.json()

    google_id = info["sub"]
    email = info["email"]
    name = info.get("name") or email.split("@")[0]
    picture = info.get("picture") or ""

    # 3) Find or create user in MongoDB
    existing_user = await db.users.find_one({"id": google_id}, {"_id": 0})

    if existing_user:
        user = User(**existing_user)
    else:
        user = User(
            id=google_id,
            email=email,
            name=name,
            picture=picture,
        )
        user_dict = user.model_dump()
        user_dict["created_at"] = user_dict["created_at"].isoformat()
        await db.users.insert_one(user_dict)

    # 4) Create session
    session_token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)

    session = UserSession(
        user_id=user.id,
        session_token=session_token,
        expires_at=expires_at,
    )

    session_dict = session.model_dump()
    session_dict["expires_at"] = session_dict["expires_at"].isoformat()
    session_dict["created_at"] = session_dict["created_at"].isoformat()

    await db.user_sessions.insert_one(session_dict)

    # 5) Set cookie
    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        secure=False,       # for localhost
        samesite="lax",
        path="/",
        max_age=7 * 24 * 60 * 60,
    )

    return RedirectResponse(url="http://localhost:3000")
# 🔹 END OF NEW BLOCK




# Auth endpoints
@api_router.post("/auth/session")
async def create_session(payload: SessionRequest, response: Response):
    # 1) Get session_id from JSON body
    session_id = payload.session_id

    # 2) Use a fixed demo user for now
    demo_user_id = "demo-user"
    demo_email = "demo@example.com"

    # Check if user exists by id
    existing_user = await db.users.find_one({"id": demo_user_id}, {"_id": 0})

    if not existing_user:
        user = User(
            id=demo_user_id,
            email=demo_email,
            name="Demo User",
            picture="https://avatars.githubusercontent.com/u/1?v=4",  # any URL
        )
        user_dict = user.model_dump()
        user_dict["created_at"] = user_dict["created_at"].isoformat()
        await db.users.insert_one(user_dict)
    else:
        user = User(**existing_user)

    # 3) Create session using the session_id we got from frontend
    session_token = session_id  # "demo-session" for now
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)

    session = UserSession(
        user_id=user.id,
        session_token=session_token,
        expires_at=expires_at,
    )

    session_dict = session.model_dump()
    session_dict["expires_at"] = session_dict["expires_at"].isoformat()
    session_dict["created_at"] = session_dict["created_at"].isoformat()

    await db.user_sessions.insert_one(session_dict)

        # 5) Set cookie (CROSS-SITE: Netlify -> Railway)
    response = JSONResponse(
        {
            "user": user.model_dump(),   # or existing_user dict if you prefer
            "session_token": session_token,
        }
    )

    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        secure=False,      # local http
        samesite="lax",    # local, same-site
        path="/",
        max_age=7 * 24 * 60 * 60,
    )

    return response


@api_router.post("/auth/google/exchange")
async def google_exchange(payload: GoogleAuthCode, response: Response):
    """
    Frontend will send { code: "<google_auth_code>" } here.
    We exchange it for tokens, get user info, create session, set cookie.
    """
    code = payload.code

    # 1) Exchange code for tokens
    token_data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }

    async with httpx.AsyncClient() as client_http:
        token_resp = await client_http.post(
            "https://oauth2.googleapis.com/token",
            data=token_data,
            timeout=10.0,
        )

    if token_resp.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to exchange code with Google")

    token_json = token_resp.json()
    id_token = token_json.get("id_token")
    if not id_token:
        raise HTTPException(status_code=400, detail="No ID token returned by Google")

    # 2) Verify ID token and get user info
    async with httpx.AsyncClient() as client_http:
        info_resp = await client_http.get(
            "https://oauth2.googleapis.com/tokeninfo",
            params={"id_token": id_token},
            timeout=10.0,
        )

    if info_resp.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to verify ID token")

    info = info_resp.json()

    email = info.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Google did not return an email")

    name = info.get("name") or email.split("@")[0]
    picture = info.get("picture") or ""

    # 3) Find or create user in MongoDB (keyed by email)
    existing_user_doc = await db.users.find_one({"email": email}, {"_id": 0})

    if not existing_user_doc:
        user = User(
            email=email,
            name=name,
            picture=picture,
        )
        user_dict = user.model_dump()
        user_dict["created_at"] = user_dict["created_at"].isoformat()
        await db.users.insert_one(user_dict)
    else:
        user = User(**existing_user_doc)

    # 4) Create session + cookie (similar to create_session)
    session_token = str(uuid.uuid4())
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)

    session = UserSession(
        user_id=user.id,
        session_token=session_token,
        expires_at=expires_at,
    )

    session_dict = session.model_dump()
    session_dict["expires_at"] = session_dict["expires_at"].isoformat()
    session_dict["created_at"] = session_dict["created_at"].isoformat()

    await db.user_sessions.insert_one(session_dict)

    # Set cookie
    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        secure=False,       # for localhost; change to True when using HTTPS in production
        samesite="lax",
        path="/",
        max_age=7 * 24 * 60 * 60,
    )

    return {"user": user, "session_token": session_token}



@api_router.get("/auth/me")
async def get_me(
    session_token: Optional[str] = Cookie(None),
    authorization: Optional[str] = None
):
    token = session_token
    if not token and authorization:
        token = authorization.replace("Bearer ", "")
    
    user = await get_current_user(token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    return user

@api_router.post("/auth/logout")
async def logout(
    response: Response,
    session_token: Optional[str] = Cookie(None)
):
    if session_token:
        await db.user_sessions.delete_one({"session_token": session_token})
    
    response.delete_cookie(key="session_token", path="/")
    return {"message": "Logged out"}

# User endpoints
@api_router.get("/users/search/{query}")
async def search_users(query: str):
    if not query or len(query) < 2:
        return []
    
    # Search by name or email (case-insensitive)
    users = await db.users.find({
        "$or": [
            {"name": {"$regex": query, "$options": "i"}},
            {"email": {"$regex": query, "$options": "i"}}
        ]
    }, {"_id": 0, "email": 1, "name": 1, "picture": 1, "id": 1}).limit(10).to_list(10)
    
    # Add post count for each user
    for user in users:
        post_count = await db.posts.count_documents({"user_id": user["id"]})
        user["post_count"] = post_count
    
    return users

@api_router.get("/users/{user_id}")
async def get_user_profile(user_id: str):
    user = await db.users.find_one({"id": user_id}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Get post count
    post_count = await db.posts.count_documents({"user_id": user_id})
    
    if isinstance(user.get('created_at'), str):
        user['created_at'] = datetime.fromisoformat(user['created_at'])
    
    return {**user, "post_count": post_count}

@api_router.put("/users/me")
async def update_profile(
    profile: UserProfile,
    session_token: Optional[str] = Cookie(None),
    authorization: Optional[str] = None
):
    token = session_token or (authorization.replace("Bearer ", "") if authorization else None)
    user = await get_current_user(token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    await db.users.update_one(
        {"id": user.id},
        {"$set": {"bio": profile.bio}}
    )
    
    return {"message": "Profile updated"}

# Post endpoints
@api_router.post("/posts")
async def create_post(
    post_data: PostCreate,
    session_token: Optional[str] = Cookie(None),
    authorization: Optional[str] = None
):
    token = session_token or (authorization.replace("Bearer ", "") if authorization else None)
    user = await get_current_user(token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    post = Post(
        user_id=user.id,
        image_data=post_data.image_data,
        caption=post_data.caption
    )
    
    post_dict = post.model_dump()
    post_dict['created_at'] = post_dict['created_at'].isoformat()
    
    await db.posts.insert_one(post_dict)
    
    return post

@api_router.get("/posts")
async def get_feed(
    skip: int = 0,
    limit: int = 20
):
    posts = await db.posts.find({}, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    
    # Enrich with user data
    for post in posts:
        if isinstance(post.get('created_at'), str):
            post['created_at'] = datetime.fromisoformat(post['created_at'])
        
        user = await db.users.find_one({"id": post["user_id"]}, {"_id": 0})
        if user:
            post['user'] = {
                "id": user["id"],
                "name": user["name"],
                "picture": user["picture"]
            }
    
    return posts

@api_router.get("/posts/{post_id}")
async def get_post(post_id: str):
    post = await db.posts.find_one({"id": post_id}, {"_id": 0})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    if isinstance(post.get('created_at'), str):
        post['created_at'] = datetime.fromisoformat(post['created_at'])
    
    # Add user data
    user = await db.users.find_one({"id": post["user_id"]}, {"_id": 0})
    if user:
        post['user'] = {
            "id": user["id"],
            "name": user["name"],
            "picture": user["picture"]
        }
    
    return post

@api_router.get("/posts/user/{user_id}")
async def get_user_posts(user_id: str):
    posts = await db.posts.find({"user_id": user_id}, {"_id": 0}).sort("created_at", -1).to_list(100)
    
    for post in posts:
        if isinstance(post.get('created_at'), str):
            post['created_at'] = datetime.fromisoformat(post['created_at'])
    
    return posts

@api_router.delete("/posts/{post_id}")
async def delete_post(
    post_id: str,
    session_token: Optional[str] = Cookie(None),
    authorization: Optional[str] = None
):
    token = session_token or (authorization.replace("Bearer ", "") if authorization else None)
    user = await get_current_user(token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    post = await db.posts.find_one({"id": post_id}, {"_id": 0})
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    if post["user_id"] != user.id:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    await db.posts.delete_one({"id": post_id})
    await db.likes.delete_many({"post_id": post_id})
    await db.saves.delete_many({"post_id": post_id})
    await db.comments.delete_many({"post_id": post_id})
    
    return {"message": "Post deleted"}

# Like endpoints
@api_router.post("/posts/{post_id}/like")
async def toggle_like(
    post_id: str,
    session_token: Optional[str] = Cookie(None),
    authorization: Optional[str] = None
):
    token = session_token or (authorization.replace("Bearer ", "") if authorization else None)
    user = await get_current_user(token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    existing_like = await db.likes.find_one({"post_id": post_id, "user_id": user.id})
    
    if existing_like:
        await db.likes.delete_one({"post_id": post_id, "user_id": user.id})
        await db.posts.update_one({"id": post_id}, {"$inc": {"likes_count": -1}})
        return {"liked": False}
    else:
        like = Like(post_id=post_id, user_id=user.id)
        like_dict = like.model_dump()
        like_dict['created_at'] = like_dict['created_at'].isoformat()
        await db.likes.insert_one(like_dict)
        await db.posts.update_one({"id": post_id}, {"$inc": {"likes_count": 1}})
        return {"liked": True}

@api_router.get("/posts/{post_id}/liked")
async def check_liked(
    post_id: str,
    session_token: Optional[str] = Cookie(None),
    authorization: Optional[str] = None
):
    token = session_token or (authorization.replace("Bearer ", "") if authorization else None)
    user = await get_current_user(token)
    if not user:
        return {"liked": False}
    
    liked = await db.likes.find_one({"post_id": post_id, "user_id": user.id})
    return {"liked": bool(liked)}

# Save endpoints
@api_router.post("/posts/{post_id}/save")
async def toggle_save(
    post_id: str,
    session_token: Optional[str] = Cookie(None),
    authorization: Optional[str] = None
):
    token = session_token or (authorization.replace("Bearer ", "") if authorization else None)
    user = await get_current_user(token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    existing_save = await db.saves.find_one({"post_id": post_id, "user_id": user.id})
    
    if existing_save:
        await db.saves.delete_one({"post_id": post_id, "user_id": user.id})
        return {"saved": False}
    else:
        save = Save(post_id=post_id, user_id=user.id)
        save_dict = save.model_dump()
        save_dict['created_at'] = save_dict['created_at'].isoformat()
        await db.saves.insert_one(save_dict)
        return {"saved": True}

@api_router.get("/posts/{post_id}/saved")
async def check_saved(
    post_id: str,
    session_token: Optional[str] = Cookie(None),
    authorization: Optional[str] = None
):
    token = session_token or (authorization.replace("Bearer ", "") if authorization else None)
    user = await get_current_user(token)
    if not user:
        return {"saved": False}
    
    saved = await db.saves.find_one({"post_id": post_id, "user_id": user.id})
    return {"saved": bool(saved)}

@api_router.get("/saves")
async def get_saved_posts(
    session_token: Optional[str] = Cookie(None),
    authorization: Optional[str] = None
):
    token = session_token or (authorization.replace("Bearer ", "") if authorization else None)
    user = await get_current_user(token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    saves = await db.saves.find({"user_id": user.id}, {"_id": 0}).sort("created_at", -1).to_list(100)
    
    posts = []
    for save in saves:
        post = await db.posts.find_one({"id": save["post_id"]}, {"_id": 0})
        if post:
            if isinstance(post.get('created_at'), str):
                post['created_at'] = datetime.fromisoformat(post['created_at'])
            
            post_user = await db.users.find_one({"id": post["user_id"]}, {"_id": 0})
            if post_user:
                post['user'] = {
                    "id": post_user["id"],
                    "name": post_user["name"],
                    "picture": post_user["picture"]
                }
            posts.append(post)
    
    return posts

# Comment endpoints
@api_router.post("/posts/{post_id}/comments")
async def add_comment(
    post_id: str,
    comment_data: CommentCreate,
    session_token: Optional[str] = Cookie(None),
    authorization: Optional[str] = None
):
    token = session_token or (authorization.replace("Bearer ", "") if authorization else None)
    user = await get_current_user(token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    comment = Comment(
        post_id=post_id,
        user_id=user.id,
        text=comment_data.text
    )
    
    comment_dict = comment.model_dump()
    comment_dict['created_at'] = comment_dict['created_at'].isoformat()
    
    await db.comments.insert_one(comment_dict)
    await db.posts.update_one({"id": post_id}, {"$inc": {"comments_count": 1}})
    
    # Check if post owner has AI enabled and trigger auto-reply
    post = await db.posts.find_one({"id": post_id}, {"_id": 0})
    if post and post["user_id"] != user.id:
        post_owner = await db.users.find_one({"id": post["user_id"]}, {"_id": 0})
        if post_owner and post_owner.get("ai_enabled") and groq_client:
            # Generate AI reply
            await generate_ai_reply(post_id, post["user_id"], comment_data.text)
    
    return comment

@api_router.get("/posts/{post_id}/comments")
async def get_comments(post_id: str):
    comments = await db.comments.find({"post_id": post_id}, {"_id": 0}).sort("created_at", 1).to_list(1000)
    
    for comment in comments:
        if isinstance(comment.get('created_at'), str):
            comment['created_at'] = datetime.fromisoformat(comment['created_at'])
        
        user = await db.users.find_one({"id": comment["user_id"]}, {"_id": 0})
        if user:
            comment['user'] = {
                "id": user["id"],
                "name": user["name"],
                "picture": user["picture"]
            }
    
    return comments

# AI endpoints
async def generate_ai_reply(post_id: str, user_id: str, comment_text: str):
    if not groq_client:
        return
    
    try:
        # Get AI config
        ai_config = await db.ai_configs.find_one({"user_id": user_id}, {"_id": 0})
        if not ai_config or not ai_config.get("is_active"):
            return
        
        # Get user's post and comment history for context
        user_posts = await db.posts.find({"user_id": user_id}, {"_id": 0}).limit(10).to_list(10)
        user_comments = await db.comments.find({"user_id": user_id, "is_ai_reply": False}, {"_id": 0}).limit(20).to_list(20)
        
        # Build context
        context = f"You are replying as this user. Here's their style based on their posts and comments:\n\n"
        context += "Recent posts:\n"
        for post in user_posts:
            context += f"- {post.get('caption', '')}\n"
        
        context += "\nRecent comments:\n"
        for comment in user_comments:
            context += f"- {comment.get('text', '')}\n"
        
        context += f"\n\nSomeone commented: '{comment_text}'\n\nReply in the user's style. Be authentic and match their tone. Keep it brief (1-2 sentences). If the comment is abusive or negative, respond professionally but firmly."
        
        # Generate reply
        chat_completion = groq_client.chat.completions.create(
            messages=[
                {"role": "system", "content": context},
                {"role": "user", "content": comment_text}
            ],
            model=ai_config.get("model_name", "llama-3.3-70b-versatile"),
            temperature=0.8,
            max_tokens=100
        )
        
        ai_reply_text = chat_completion.choices[0].message.content
        
        # Save AI reply
        ai_comment = Comment(
            post_id=post_id,
            user_id=user_id,
            text=ai_reply_text,
            is_ai_reply=True
        )
        
        ai_comment_dict = ai_comment.model_dump()
        ai_comment_dict['created_at'] = ai_comment_dict['created_at'].isoformat()
        
        await db.comments.insert_one(ai_comment_dict)
        await db.posts.update_one({"id": post_id}, {"$inc": {"comments_count": 1}})
        
    except Exception as e:
        logging.error(f"Error generating AI reply: {e}")

@api_router.post("/ai/toggle")
async def toggle_ai(
    toggle_data: AIToggle,
    session_token: Optional[str] = Cookie(None),
    authorization: Optional[str] = None
):
    token = session_token or (authorization.replace("Bearer ", "") if authorization else None)
    user = await get_current_user(token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    if not groq_client:
        raise HTTPException(status_code=400, detail="AI feature not configured. Please provide GROQ_API_KEY.")
    
    # Update user AI status
    await db.users.update_one(
        {"id": user.id},
        {"$set": {"ai_enabled": toggle_data.enabled}}
    )
    
    # Create or update AI config
    ai_config = await db.ai_configs.find_one({"user_id": user.id})
    if not ai_config:
        config = AIConfig(
            user_id=user.id,
            is_active=toggle_data.enabled
        )
        config_dict = config.model_dump()
        config_dict['created_at'] = config_dict['created_at'].isoformat()
        config_dict['updated_at'] = config_dict['updated_at'].isoformat()
        await db.ai_configs.insert_one(config_dict)
    else:
        await db.ai_configs.update_one(
            {"user_id": user.id},
            {"$set": {"is_active": toggle_data.enabled, "updated_at": datetime.now(timezone.utc).isoformat()}}
        )
    
    return {"ai_enabled": toggle_data.enabled}

@api_router.get("/ai/status")
async def get_ai_status(
    session_token: Optional[str] = Cookie(None),
    authorization: Optional[str] = None
):
    token = session_token or (authorization.replace("Bearer ", "") if authorization else None)
    user = await get_current_user(token)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    ai_config = await db.ai_configs.find_one({"user_id": user.id}, {"_id": 0})
    
    return {
        "configured": groq_client is not None,
        "enabled": user.ai_enabled,
        "active": ai_config.get("is_active", False) if ai_config else False
    }

# Include the router in the main app
app.include_router(api_router)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://socially23-backend-production-3473.up.railway.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
