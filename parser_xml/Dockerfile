# Используем официальный образ Golang для сборки приложения
FROM golang:1.22.3-bookworm AS builder

ARG DB_USER
ARG DB_PASSWORD
ARG DB_HOST
ARG DB_PORT
ARG DB_DATABASE

ENV DB_USER=${DB_USER}
ENV DB_PASSWORD=${DB_PASSWORD}
ENV DB_HOST=${DB_HOST}
ENV DB_PORT=${DB_PORT}
ENV DB_DATABASE=${DB_DATABASE}

# Устанавливаем рабочую директорию внутри контейнера
WORKDIR /app

# Копируем go.mod и go.sum для установки зависимостей
COPY go.mod go.sum ./

# Загружаем и устанавливаем зависимости
RUN go mod download

# Копируем исходный код приложения в контейнер
COPY . .

# Сборка приложения
RUN go build -o /app/bin/app

# Используем минимальный образ для запуска приложения
FROM debian:bookworm-slim

# Устанавливаем зависимости для работы приложения
RUN apt-get update && apt-get install -y ca-certificates

# Устанавливаем переменную окружения для указания пути к исполняемому файлу
ENV PATH="/app/bin:${PATH}"

# Создаем рабочую директорию для приложения
WORKDIR /app

# Копируем скомпилированное приложение из стадии сборки
COPY --from=builder /app/bin/app /app/bin/app

# Копируем файл fstek.pem
COPY fstek.pem /app/fstek.pem

# Создаем файл .env и записываем в него переменные окружения
RUN echo "DB_USER=${DB_USER}" > .env && \
    echo "DB_PASSWORD=${DB_PASSWORD}" >> .env && \
    echo "DB_HOST=${DB_HOST}" >> .env && \
    echo "DB_PORT=${DB_PORT}" >> .env && \
    echo "DB_DATABASE=${DB_DATABASE}" >> .env

# Вывод переменных окружения для отладки
RUN cat .env

# Указываем команду для запуска приложения
CMD ["app"]
