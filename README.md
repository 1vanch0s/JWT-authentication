# JWT-аутентификация на Node.js

Этот проект реализует простую систему регистрации, входа и защищённых маршрутов с использованием JWT.

## 🚀 Установка и запуск

1. **Клонировать репозиторий:**
   ```sh
   git clone https://github.com/1vanch0s/JWT-authentication
   cd JWT-authentication
   ```

2. **Установить зависимости:**
   ```sh
   npm install
   ```

3. **Создать файл `.env` и добавить секретный ключ:**
   ```sh
   echo "JWT_SECRET=your_secret_key" > .env
   ```
   (в файле .env в репозитории уже имеется ключ)

4. **Запустить сервер:**
   ```sh
   node server.js
   ```
   Сервер запустится на `http://localhost:3000/` или можно просто запустить index.html.

## 📌 Доступные маршруты

| Метод | Маршрут         | Описание                      |
|--------|---------------|------------------------------|
| POST  | `/register`    | Регистрация пользователя    |
| POST  | `/login`       | Вход и получение токена     |
| GET   | `/protected`   | Доступ к защищённым данным |

## 🛠 Тестирование API

### 📥 Регистрация
- **URL:** `http://localhost:3000/register`
- **Метод:** `POST`
- **Тело запроса (JSON):**
  ```json
  {
    "username": "testuser",
    "password": "password123"
  }
  ```
- **Ожидаемый ответ:**
  ```json
  {
    "message": "User registered successfully"
  }
  ```

### 🔑 Логин
- **URL:** `http://localhost:3000/login`
- **Метод:** `POST`
- **Тело запроса (JSON):**
  ```json
  {
    "username": "testuser",
    "password": "password123"
  }
  ```
- **Ожидаемый ответ (если успешно):**
  ```json
  {
    "token": "your_jwt_token"
  }
  ```

### 🔒 Доступ к защищённому маршруту
- **URL:** `http://localhost:3000/protected`
- **Метод:** `GET`
- **Заголовки:**
  ```
  Authorization: Bearer your_jwt_token
  ```
- **Ожидаемый ответ:**
  ```json
  {
    "message": "This is a protected route",
    "user": {
      "userId": 1
    }
  }
  ```

## 📌 Примечания
- Все данные пользователей сохраняются даже после перезапуска сервера
- добавлено хеширование паролей при помощи **bcrypt**
- Можно использовать **Postman** или **cURL** для тестирования API. 
