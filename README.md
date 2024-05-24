# Первоначальная настройка
1.  Cинхронизируем пакетную базу apt и установим нужные зависимости:
```
sudo apt-get update
```
2. Устананавливаем необходимые пакеты
```
sudo apt-get install ca-certificates curl 
```
3. Добавляем ключ GPG Docker
```
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
```
4. Добавляем репозиторий в источник apt (на debian подобных системах)
```
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
```
5. Устанвливаем пакета Docker-a
```
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```
6. Проверяем, что все прошло успешно
```
sudo docker run hello-world
docker compose version
```
## Настройка postgres на хосте
База данных находится не в контейнере, а на хосте, поэтому эти шаги так же проделываем на хостовой машине

1. Cинхронизируем пакетную базу apt и установим нужные зависимости:
```
sudo apt-get update
```
2. Устаналиваем необходимые пакеты
```
sudo apt-get install postgresql postgresql-contrib
```
3. Переходим в /etc/postgresql/XX/main/postgresql.conf
где XX - версия postgresql, на данный момент на ubuntu 14 версия
Добавляем строчку
```
listen_addresses = '*'
```
4. В этом же файле указываем порт, стандартно 5432
```
port = 5432
```
5. Переходим в /etc/postgresql/XX/main/pg_hba.conf
Добавляем вместо 1.1.1.1 необходимо указать адрес, с которого выполняется подключение
```
host all all 1.1.1.1/32 password
```
6. Перезапускам сервис и смотрим статус
В последней команде должен быть везде статус running
```
systemctl restart postgresql
systemctl status postgresql
systemctl status postgresql\*
```
7. Заходим под пользователя postgres
```
su - postgres
```
8. Меняем пароль, который будем указывать в .env файле
```
psql -c "ALTER ROLE postgres PASSWORD '<пароль>';"
```
9. Заходим в psql и создаем базу данных, её так же будем указывать в .env
```
psql
CREATE DATABASE <имя база данных>
\l
```
# Настройка .env
Можно редактировать .env.example, предварительно убрав .example
1. TOKEN получаем в https://t.me/BotFather
2. Данные для БД настроили ранее, их нужно будет добавить в .env
3. USERNAME и PASSWORD, указываем какие хотим, с этими данными будем заходить на сайт
4. Secret_key получаем с помощью
```
python -c 'import secrets; print(secrets.token_hex(32))'
```
Пример .env файла
```
# Токен бота
TOKEN = 

# Данные для подключения к БД
DB_USER = 
DB_PASSWORD = 
DB_HOST = 
DB_PORT = 
DB_DATABASE = 

# С этими данными будет доступен вход через страницу login
# Secret_key получаем с помощью python -c 'import secrets; print(secrets.token_hex(32))'
USERNAME = 
PASSWORD = 
SECRET_KEY = 
```
# Запуск без скрипта
1. Из директории проекта запускаем docker-compose, если сайт и бот не запустились можем запустить их вручную
```
docker compose up --build --no-start
docker compose start site bot
```
2. После этого запускаем контейнеры для парсинга, запускаем в порядке parser_xml -> parser_xlsx -> parser_nvd и parser_opencve
```
docker compose start parser_xml
docker compose start parser_xlsx
```
После завершения их работы запускаем остальные два, статус можно посмотреть с помощью
```
docker compose ps -a
```
3. Запускаем остальные парсеры
```
docker compose start parser_nvd parser_opencve
```
Если необходимо их выключить
```
docker compose stop parser_nvd parser_opencve
```
При необходимости добавляем эти команды в Cron для автоматического запуска
# Запуск с помощью скрипта
Перед запуском убедитесь, что скрипты имеют право на выполнение, сделать это можно с помощью команды
```
chmod +x start_parsers.sh cron_start_parsers.sh
```
Затем запустите скрипт
```
./start_parsers.sh
```
Убедитесь, что все запустилось
```
docker compose ps
```
И добавились cron-задачи
```
crontab -l
```
Скрипты выполняют автоматический запуск и остановку парсеров каждый день в 12 часов ночи, а также выполнение первоначальной настройки и сборки контейнеров.
# Пример изменения конфигурации для использования с NGINX и ssl
1. В docker compose добавляем конфигурацию nginx
```
nginx:
    image: nginx:latest
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./certs/fullchain.crt:/etc/nginx/certs/fullchain.crt
      - ./certs/privkey.key:/etc/nginx/certs/privkey.key
    depends_on:
      - site
    network_mode: host
```
2. nginx.conf должен лежать рядом с docker-compose.yml и содержать следующее
fullchain.crt - содержит полную цепочку сертификатов
privkey.key - содержит приватный ключ для ssl
```
events {}

http {
    server {
        listen 80;
        server_name <domain_name>;

        location / {
            return 301 https://$host$request_uri;
        }
    }

    server {
        listen 443 ssl;
        server_name <domain_name>;

        ssl_certificate /etc/nginx/certs/fullchain.crt;
        ssl_certificate_key /etc/nginx/certs/privkey.key;

        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_prefer_server_ciphers on;
        ssl_ciphers HIGH:!aNULL:!MD5;

        location / {
            proxy_pass http://<ip>:5000;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
        }
    }
}

```
