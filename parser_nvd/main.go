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
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s", dbUser, dbPassword, dbHost, dbPort, dbName)
	ctx := context.Background()

	// Открытие файла для логирования
	logFile, err := os.OpenFile("output_parser_nvd.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Println("Ошибка при открытии файла логов:", err)
		return
	}
	defer logFile.Close()

	// Настройка логгера
	logger := log.New(logFile, "", log.LstdFlags)

	// Создание пула подключений
	config, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		logger.Fatalf("Не удалось разобрать строку подключения: %v\n", err)
	}

	dbpool, err := pgxpool.ConnectConfig(ctx, config)
	if err != nil {
		logger.Fatalf("Не удалось создать пул подключений: %v\n", err)
	}
	defer dbpool.Close()

	// Убедитесь, что таблица cve_nvd существует
	err = createCveNvdTable(ctx, dbpool, logger)
	if err != nil {
		logger.Fatalf("Ошибка создания таблицы cve_nvd: %v\n", err)
	}

	// Получить последние уязвимости
	vulnerabilities, err := fetchLatestVulnerabilities(ctx, dbpool, logger)
	if err != nil {
		logger.Fatalf("Ошибка при получении уязвимостей: %v\n", err)
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // Ограничиваем количество параллельных запросов

	// Обработка каждой уязвимости
	for _, vul := range vulnerabilities {
		logger.Printf("Обработка уязвимости ID: %d, Identifier: %s\n", vul.ID, vul.Identifier)

		// Получение идентификаторов CVE для уязвимости
		cves, err := fetchCVEIdentifiers(ctx, dbpool, vul.ID, logger)
		if err != nil {
			logger.Printf("Ошибка при получении идентификаторов CVE для уязвимости ID %d: %v\n", vul.ID, err)
			continue
		}

		for _, cve := range cves {
			wg.Add(1)
			sem <- struct{}{}
			go func(cve CVEIdentifier) {
				defer wg.Done()
				defer func() { <-sem }()

				cveLink := formatCVELink(cve.Link)

				// Проверка, существует ли запись в таблице cve_nvd
				exists, err := cveExists(ctx, dbpool, cveLink, logger)
				if err != nil {
					logger.Printf("Ошибка при проверке существования CVE %s: %v\n", cveLink, err)
					return
				}

				if exists {
					logger.Printf("CVE %s уже существует в базе данных. Пропускаем.\n", cveLink)
					return
				}

				description, hyperlinks, err := fetchCVEDetails(cveLink, logger)
				if err != nil {
					logger.Printf("Ошибка при получении данных CVE для %s: %v\n", cveLink, err)
					return
				}

				logger.Printf("CVE: %s, Описание: %s\n", cveLink, description)
				err = saveCVEDetails(ctx, dbpool, cveLink, description, hyperlinks, vul.ID, logger)
				if err != nil {
					logger.Printf("Ошибка при сохранении данных CVE для %s: %v\n", cveLink, err)
				}
			}(cve)
		}
	}

	wg.Wait()
	logger.Println("Скрапинг и сохранение данных CVE успешно завершены!")
}

func createCveNvdTable(ctx context.Context, dbpool *pgxpool.Pool, logger *log.Logger) error {
	query := `
		CREATE TABLE IF NOT EXISTS cve_nvd (
			id SERIAL PRIMARY KEY,
			cve_link TEXT UNIQUE,
			description TEXT,
			last_fetched TIMESTAMP,
			vulnerability_id INTEGER,
			hyperlinks TEXT,
			FOREIGN KEY(vulnerability_id) REFERENCES vulnerability(id)
		);
	`
	_, err := dbpool.Exec(ctx, query)
	if err != nil {
		logger.Printf("Ошибка при создании таблицы cve_nvd: %v\n", err)
	}
	return err
}

type Vulnerability struct {
	ID         int
	Identifier string
}

type CVEIdentifier struct {
	ID              int
	Type            string
	Link            string
	VulnerabilityID int
}

func fetchLatestVulnerabilities(ctx context.Context, dbpool *pgxpool.Pool, logger *log.Logger) ([]Vulnerability, error) {
	query := `
		SELECT id, identifier 
		FROM vulnerability 
		ORDER BY identifier DESC
	`

	rows, err := dbpool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vulnerabilities []Vulnerability
	for rows.Next() {
		var vul Vulnerability
		if err := rows.Scan(&vul.ID, &vul.Identifier); err != nil {
			return nil, err
		}
		vulnerabilities = append(vulnerabilities, vul)
	}

	return vulnerabilities, nil
}

func fetchCVEIdentifiers(ctx context.Context, dbpool *pgxpool.Pool, vulnerabilityID int, logger *log.Logger) ([]CVEIdentifier, error) {
	query := `
		SELECT id, type, link, vulnerability_id 
		FROM cve_identifier 
		WHERE vulnerability_id = $1
	`

	rows, err := dbpool.Query(ctx, query, vulnerabilityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cveIdentifiers []CVEIdentifier
	for rows.Next() {
		var cve CVEIdentifier
		if err := rows.Scan(&cve.ID, &cve.Type, &cve.Link, &cve.VulnerabilityID); err != nil {
			return nil, err
		}
		cveIdentifiers = append(cveIdentifiers, cve)
	}

	return cveIdentifiers, nil
}

func formatCVELink(link string) string {
	if !strings.HasPrefix(link, "http://") && !strings.HasPrefix(link, "https://") {
		return "https://nvd.nist.gov/vuln/detail/" + link
	}
	return link
}

func fetchCVEDetails(cveLink string, logger *log.Logger) (string, []string, error) {
	var description string
	var hyperlinks []string

	const maxRetries = 5
	for i := 0; i < maxRetries; i++ {
		// Выполнение HTTP запроса
		res, err := http.Get(cveLink)
		if err != nil {
			logger.Printf("Попытка %d: ошибка при получении URL %s: %v\n", i+1, cveLink, err)
			time.Sleep(time.Duration(rand.Intn(2000-1)+1) * time.Millisecond)
			continue
		}

		if res.StatusCode != 200 {
			logger.Printf("Попытка %d: ошибка: получен ненормативный код ответа %d для URL %s\n", i+1, res.StatusCode, cveLink)
			res.Body.Close()
			time.Sleep(time.Duration(rand.Intn(2000-1)+1) * time.Millisecond)
			continue
		}

		// Парсинг HTML ответа
		doc, err := goquery.NewDocumentFromReader(res.Body)
		res.Body.Close()
		if err != nil {
			logger.Printf("Попытка %d: ошибка при парсинге HTML для URL %s: %v\n", i+1, cveLink, err)
			time.Sleep(time.Duration(rand.Intn(2000-1)+1) * time.Millisecond)
			continue
		}

		// Найти описание CVE
		description = doc.Find("p[data-testid='vuln-description']").Text()
		description = strings.TrimSpace(description)

		// Найти гиперссылки
		doc.Find("table[data-testid='vuln-hyperlinks-table'] tbody tr").Each(func(i int, s *goquery.Selection) {
			hyperlink := s.Find("td[data-testid^='vuln-hyperlinks-link-'] a").AttrOr("href", "")
			hyperlinks = append(hyperlinks, hyperlink)
		})

		return description, hyperlinks, nil
	}

	return "", nil, fmt.Errorf("превышено максимальное количество попыток для URL: %s", cveLink)
}

func saveCVEDetails(ctx context.Context, dbpool *pgxpool.Pool, cveLink, description string, hyperlinks []string, vulnerabilityID int, logger *log.Logger) error {
	hyperlinksStr := strings.Join(hyperlinks, "; ")

	query := `
		INSERT INTO cve_nvd (cve_link, description, last_fetched, vulnerability_id, hyperlinks)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (cve_link) DO UPDATE
		SET description = EXCLUDED.description, last_fetched = EXCLUDED.last_fetched, hyperlinks = EXCLUDED.hyperlinks;
	`
	_, err := dbpool.Exec(ctx, query, cveLink, description, time.Now(), vulnerabilityID, hyperlinksStr)
	if err != nil {
		logger.Printf("Ошибка при сохранении данных CVE для %s: %v\n", cveLink, err)
	}
	return err
}

func cveExists(ctx context.Context, dbpool *pgxpool.Pool, cveLink string, logger *log.Logger) (bool, error) {
	var exists bool
	query := `SELECT EXISTS (SELECT 1 FROM cve_nvd WHERE cve_link = $1)`
	err := dbpool.QueryRow(ctx, query, cveLink).Scan(&exists)
	if err != nil {
		logger.Printf("Ошибка при проверке существования CVE %s: %v\n", cveLink, err)
	}
	return exists, err
}
