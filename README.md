# Ahangify 🎵

A FastAPI-based music platform with user authentication and artist panel features.

## Project Structure 📂

```
Ahangify/
├── auth/
│   ├── hash.py
│   └── jwt_handler.py
├── routers/
│   ├── auth.py
│   └── core.py
├── schemas/
│   └── models.py
├── utils/
│   ├── code.py
│   └── mail.py
├── core.py
├── database.py
├── main.py
└── requirements.txt
```


## Features ✨

- **User Authentication System**
  - JWT-based authentication
  - Password hashing with bcrypt
  - Email verification
  - Password reset functionality

- **Artist Panel 🎨**
  - Artist-specific endpoints
  - Content management features

- **Security Features 🔒**
  - CORS middleware enabled
  - Token blacklisting
  - Automatic cleanup of expired tokens
  - Disabled account management

## Technical Stack 🛠️

- **Framework**: FastAPI 0.100.0
- **Database**: MongoDB (with motor and beanie ODM)
- **Authentication**: JWT (python-jose, bcrypt)
- **Email**: fastapi-mail
- **Additional Features**:
  - QR code generation
  - File handling with aiofiles
  - Environment variable management with python-decouple

## Getting started 🚀

### Installation 

1. Clone the repository:
```
$ git clone https://github.com/yourusername/ahangify.git
```
2. Install dependencies:
```
$ pip install -r requirements.txt
```
3. Set up environment variables:
```
$ cp .env.example .env
```
4. Run the application:
```
$ uvicorn main:app --reload --port 8000 --log-level info
```

## Automatic Maintenance 🛠️

The system includes automatic maintenance features:
- Cleanup of disabled accounts (after 10 minutes)
- Removal of expired verification codes
- Deletion of expired password reset tokens
- Cleanup of blacklisted tokens

## API Documentation  📄
Once the server is running, access:

- Swagger UI: http://127.0.0.1:8000/docs
- ReDoc: http://127.0.0.1:8000/redoc

## Security Considerations 🔐

- All passwords are hashed using bcrypt
- JWT tokens are used for session management
- CORS is configured to accept requests from all origins (customize as needed)
- Automatic token invalidation system