package main

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/joho/godotenv"
)

func main() {
	// Загрузка переменных окружения из .env файла, который находится в поддиректории
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Ошибка загрузки .env файла: %v", err)
	}

	// Получение параметров подключения из переменных окружения
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_DATABASE")

	if dbUser == "" || dbPassword == "" || dbHost == "" || dbPort == "" || dbName == "" {
		log.Fatalf("Параметры подключения к базе данных не заданы в .env файле")
	}

	// Формирование строки подключения
	databaseURL := fmt.Sprintf("postgres://%s:%s@%s:%s/%s", dbUser, dbPassword, dbHost, dbPort, dbName)

	// Открытие файла для логирования
	logFile, err := os.OpenFile("output_parser_opencve.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Println("Ошибка при открытии файла логов:", err)
		return
	}
	defer logFile.Close()

	// Настройка логгера
	logger := log.New(logFile, "", log.LstdFlags)

	// Подключение к базе данных
	dbpool, err := pgxpool.Connect(context.Background(), databaseURL)
	if err != nil {
		logger.Fatalf("Не удалось подключиться к базе данных: %v\n", err)
	}
	defer dbpool.Close()

	// Создание таблицы cve_opencve
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS cve_opencve (
		id SERIAL PRIMARY KEY,
		vulnerability_id INTEGER,
		attack_vector TEXT,
		attack_complexity TEXT,
		privileges_required TEXT,
		user_interaction TEXT,
		confidentiality_impact TEXT,
		integrity_impact TEXT,
		availability_impact TEXT,
		scope TEXT,
		FOREIGN KEY(vulnerability_id) REFERENCES vulnerability(id)
	);`
	_, err = dbpool.Exec(context.Background(), createTableSQL)
	if err != nil {
		logger.Fatalf("Не удалось создать таблицу: %v\n", err)
	}

	logger.Println("Успешное подключение и создание таблицы!")

	// Получение всех уязвимостей
	rows, err := dbpool.Query(context.Background(), `SELECT id, identifier FROM vulnerability ORDER BY identifier DESC`)
	if err != nil {
		logger.Fatalf("Не удалось выполнить запрос: %v\n", err)
	}
	defer rows.Close()

	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // Ограничиваем количество параллельных запросов

	// Обработка каждой уязвимости
	for rows.Next() {
		var id int
		var identifier string
		if err := rows.Scan(&id, &identifier); err != nil {
			logger.Fatalf("Не удалось прочитать строку: %v\n", err)
		}

		// Проверка, есть ли уже запись о данной уязвимости
		var exists bool
		err := dbpool.QueryRow(context.Background(), `SELECT EXISTS(SELECT 1 FROM cve_opencve WHERE vulnerability_id=$1)`, id).Scan(&exists)
		if err != nil {
			logger.Printf("Не удалось выполнить запрос на проверку существования записи для уязвимости %d: %v\n", id, err)
			continue
		}

		if exists {
			logger.Printf("Запись для уязвимости %d уже существует, пропускаем\n", id)
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(id int, identifier string) {
			defer wg.Done()
			defer func() { <-sem }()

			// Получение CVE из таблицы cve_identifier
			var cveLink string
			err = dbpool.QueryRow(context.Background(), `SELECT link FROM cve_identifier WHERE vulnerability_id = $1 LIMIT 1`, id).Scan(&cveLink)
			if err != nil {
				logger.Printf("Не удалось выполнить запрос для уязвимости %d: %v\n", id, err)
				return
			}

			// Формирование полного URL
			fullURL := fmt.Sprintf("https://www.opencve.io/cve/%s", strings.TrimSpace(cveLink))

			// Веб-скрапинг для получения CVE данных
			cveData, err := scrapeCveData(fullURL, logger)
			if err != nil {
				logger.Printf("Ошибка при скрапинге CVE данных для уязвимости %d: %v\n", id, err)
				return
			}

			// Сохранение данных в таблицу cve_opencve
			_, err = dbpool.Exec(
				context.Background(),
				`INSERT INTO cve_opencve (
					vulnerability_id, attack_vector, attack_complexity, privileges_required, user_interaction,
					confidentiality_impact, integrity_impact, availability_impact, scope
				) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
				id, cveData.AttackVector, cveData.AttackComplexity, cveData.PrivilegesRequired, cveData.UserInteraction,
				cveData.ConfidentialityImpact, cveData.IntegrityImpact, cveData.AvailabilityImpact, cveData.Scope)
			if err != nil {
				logger.Printf("Ошибка при вставке CVE данных для уязвимости %d: %v\n", id, err)
				return
			}

			logger.Printf("Данные для уязвимости %d успешно вставлены\n", id)

			// Случайная задержка между запросами от 1 миллисекунды до 2 секунд
			randomDelay := time.Duration(rand.Intn(2000-1)+1) * time.Millisecond
			time.Sleep(randomDelay)
		}(id, identifier)
	}

	wg.Wait()

	if err := rows.Err(); err != nil {
		logger.Fatalf("Ошибка при чтении строк: %v\n", err)
	}

	logger.Println("Скрапинг и сохранение данных CVE успешно завершены!")
}

type CveData struct {
	AttackVector          string
	AttackComplexity      string
	PrivilegesRequired    string
	UserInteraction       string
	ConfidentialityImpact string
	IntegrityImpact       string
	AvailabilityImpact    string
	Scope                 string
}

// scrapeCveData выполняет веб-скрапинг данных CVE с указанного URL с повторными попытками
func scrapeCveData(cveURL string, logger *log.Logger) (CveData, error) {
	var cveData CveData
	const maxRetries = 5

	for i := 0; i < maxRetries; i++ {
		// Выполнение запроса к странице
		res, err := http.Get(cveURL)
		if err != nil {
			logger.Printf("Попытка %d: ошибка при получении URL: %v\n", i+1, err)
			time.Sleep(time.Duration(rand.Intn(2000-1)+1) * time.Millisecond)
			continue
		}

		if res.StatusCode != 200 {
			logger.Printf("Попытка %d: ошибка: получен ненормативный код ответа %d\n", i+1, res.StatusCode)
			res.Body.Close()
			time.Sleep(time.Duration(rand.Intn(2000-1)+1) * time.Millisecond)
			continue
		}

		// Парсинг HTML
		doc, err := goquery.NewDocumentFromReader(res.Body)
		res.Body.Close()
		if err != nil {
			logger.Printf("Попытка %d: ошибка при парсинге HTML: %v\n", i+1, err)
			time.Sleep(time.Duration(rand.Intn(2000-1)+1) * time.Millisecond)
			continue
		}

		// Извлечение данных из HTML
		cveData.AttackVector = doc.Find("h4:contains('Attack Vector') .pull-right").Text()
		cveData.AttackComplexity = doc.Find("h4:contains('Attack Complexity') .pull-right").Text()
		cveData.PrivilegesRequired = doc.Find("h4:contains('Privileges Required') .pull-right").Text()
		cveData.UserInteraction = doc.Find("h4:contains('User Interaction') .pull-right").Text()
		cveData.ConfidentialityImpact = doc.Find("h4:contains('Confidentiality Impact') .pull-right").Text()
		cveData.IntegrityImpact = doc.Find("h4:contains('Integrity Impact') .pull-right").Text()
		cveData.AvailabilityImpact = doc.Find("h4:contains('Availability Impact') .pull-right").Text()
		cveData.Scope = doc.Find("h4:contains('Scope') .pull-right").Text()

		return cveData, nil
	}

	return cveData, fmt.Errorf("превышено максимальное количество попыток для URL: %s", cveURL)
}
