package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/joho/godotenv"
	"github.com/xuri/excelize/v2"
)

type Threat struct {
	Name                     string
	Description              string
	Source                   string
	Object                   string
	ConfidentialityViolation string
	IntegrityViolation       string
	AvailabilityViolation    string
}

func main() {

	log.Println("Старт")

	// Загрузка переменных окружения из .env файла
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Ошибка загрузки .env файла: %v", err)
	}

	log.Println("Переменные окружения загружены")

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
	log.Println("Строка подключения сформирована")

	// Открытие файла логов
	logFile, err := os.OpenFile("output_parser_xlsx.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Println("Ошибка при открытии файла логов:", err)
		return
	}
	defer logFile.Close()
	log.Println("Файл логов открыт")

	// Настройка логгера
	logger := log.New(logFile, "", log.LstdFlags)

	// Чтение CA сертификата
	caCert, err := os.ReadFile("fstek.pem")
	if err != nil {
		logger.Println("Ошибка при чтении CA сертификата:", err)
		return
	}
	logger.Println("CA сертификат прочитан")

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: caCertPool,
		},
	}

	client := &http.Client{Transport: tr}
	logger.Println("HTTP клиент настроен")

	// Загрузка XLSX файла
	xlsxURL := "https://bdu.fstec.ru/files/documents/thrlist.xlsx"
	xlsxPath := "thrlist.xlsx"
	maxRetries := 5
	for i := 0; i < maxRetries; i++ {
		err = downloadFile(client, xlsxURL, xlsxPath, logger)
		if err == nil {
			break
		}
		logger.Printf("Ошибка при загрузке файла (попытка %d/%d): %v\n", i+1, maxRetries, err)
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		logger.Println("Не удалось загрузить файл после нескольких попыток:", err)
		return
	}

	// Открытие загруженного XLSX файла
	f, err := excelize.OpenFile(xlsxPath)
	if err != nil {
		logger.Fatalf("Ошибка при открытии файла: %s", err)
	}

	// Подключение к базе данных
	pool, err := pgxpool.Connect(context.Background(), connStr)
	if err != nil {
		logger.Fatalf("Не удалось подключиться к базе данных: %v", err)
	}
	defer pool.Close()

	// Создание таблицы в базе данных
	createTable(pool, logger)

	// Вставка данных из Excel файла в базу данных
	insertDataFromExcel(f, pool, logger)

	// Удаление загруженного XLSX файла
	err = os.Remove(xlsxPath)
	if err != nil {
		logger.Println("Ошибка при удалении XLSX файла:", err)
		return
	}

	logger.Println("Данные успешно вставлены, файл удален")
}

// Функция для загрузки файла с указанного URL
func downloadFile(client *http.Client, url string, filepath string, log *log.Logger) error {
	const maxRetries = 5

	for attempt := 1; attempt <= maxRetries; attempt++ {
		err := attemptDownload(client, url, filepath, log)
		if err == nil {
			log.Println("Файл успешно загружен")
			return nil
		}
		log.Printf("Попытка загрузки %d/%d не удалась: %v\n", attempt, maxRetries, err)
		time.Sleep(2 * time.Second) // Ожидание перед повторной попыткой
	}

	return fmt.Errorf("не удалось загрузить файл после %d попыток", maxRetries)
}

// Функция для выполнения одной попытки загрузки файла
func attemptDownload(client *http.Client, url string, filepath string, log *log.Logger) error {
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows; U; Windows NT 6.1; WOW64) Gecko/20130401 Firefox/63.8")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("неправильный статус: %s", resp.Status)
	}

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	if err := out.Sync(); err != nil {
		return err
	}

	log.Println("Файл загружен:", filepath)
	return nil
}

// Функция для создания таблицы в базе данных
func createTable(pool *pgxpool.Pool, log *log.Logger) {
	createTableQuery := `
    CREATE TABLE IF NOT EXISTS ubi (
        id SERIAL PRIMARY KEY,
        name TEXT,
        description TEXT,
        source TEXT,
        object TEXT,
        confidentiality_violation TEXT,
        integrity_violation TEXT,
        availability_violation TEXT,
        UNIQUE(name, description, source, object, confidentiality_violation, integrity_violation, availability_violation)
    );`
	_, err := pool.Exec(context.Background(), createTableQuery)
	if err != nil {
		log.Fatalf("Ошибка при создании таблицы: %v", err)
	}
}

// Функция для вставки данных из Excel файла в базу данных
func insertDataFromExcel(f *excelize.File, pool *pgxpool.Pool, log *log.Logger) {
	rows, err := f.GetRows("Sheet")
	if err != nil {
		log.Fatalf("Ошибка при получении строк: %s", err)
	}

	ctx := context.Background()
	for _, row := range rows[2:] { // Пропускаем заголовок
		if len(row) < 7 {
			continue
		}

		threat := Threat{
			Name:                     row[1],
			Description:              row[2],
			Source:                   row[3],
			Object:                   row[4],
			ConfidentialityViolation: row[5],
			IntegrityViolation:       row[6],
			AvailabilityViolation:    row[7],
		}

		_, err := pool.Exec(ctx, `
            INSERT INTO ubi (name, description, source, object, confidentiality_violation, integrity_violation, availability_violation)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (name, description, source, object, confidentiality_violation, integrity_violation, availability_violation) DO NOTHING;`,
			threat.Name, threat.Description, threat.Source, threat.Object, threat.ConfidentialityViolation, threat.IntegrityViolation, threat.AvailabilityViolation)
		if err != nil {
			log.Printf("Ошибка при вставке данных: %v", err)
		}
	}
}
