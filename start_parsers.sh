#!/bin/bash

# Получаем текущую директорию
PROJECT_DIR=$(pwd)

# Перейти в директорию проекта
cd "$PROJECT_DIR"

# Сборка и создание контейнеров без запуска
docker compose up --build --no-start

# Запуск сайта и бота
docker compose start site bot

# Запуск парсеров в нужном порядке
docker compose start parser_xml
# Ожидание завершения работы parser_xml
while [[ $(docker inspect -f '{{.State.Status}}' parser_xml) == "running" ]]; do
    sleep 5
done

docker compose start parser_xlsx
# Ожидание завершения работы parser_xlsx
while [[ $(docker inspect -f '{{.State.Status}}' parser_xlsx) == "running" ]]; do
    sleep 5
done

# Добавление задания в Crontab для ежедневного запуска парсеров в 12 часов ночи
(crontab -l ; echo "0 0 * * * $PROJECT_DIR/cron_start_parsers.sh >> $PROJECT_DIR/cron.log 2>&1") | crontab -

docker compose start parser_nvd 
docker compose start parser_opencve
END=$((SECONDS+1800))
while [[ $SECONDS -lt $END ]]; do
    if [[ $(docker inspect --format '{{.State.Running}}' test_vkr-parser_nvd-1) != "true" ]] && [[ $(docker inspect --format '{{.State.Running}}' test_vkr-parser_opencve-1) != "true" ]]; then
        break
    fi
    sleep 5
done

# Остановка контейнеров, если они все еще запущены после 30 минут
if [[ $(docker inspect --format '{{.State.Running}}' test_vkr-parser_nvd-1) == "true" ]] || [[ $(docker inspect --format '{{.State.Running}}' test_vkr-parser_opencve-1) == "true" ]]; then
    docker compose stop parser_nvd parser_opencve
fi