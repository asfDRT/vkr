package main

import (
	"archive/zip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/joho/godotenv"
)

// Определение структуры для хранения уязвимостей
type Vulnerabilities struct {
	XMLName         xml.Name        `xml:"vulnerabilities"`
	Vulnerabilities []Vulnerability `xml:"vul"`
}

type Vulnerability struct {
	Identifier         string             `xml:"identifier"`
	Name               string             `xml:"name"`
	Description        string             `xml:"description"`
	VulnerableSoftware VulnerableSoftware `xml:"vulnerable_software"`
	Environment        Environment        `xml:"environment"`
	CWE                CWE                `xml:"cwe"`
	IdentifyDate       string             `xml:"identify_date"`
	CVSS               CVSS               `xml:"cvss"`
	CVSS3              CVSS3              `xml:"cvss3"`
	Severity           string             `xml:"severity"`
	Solution           string             `xml:"solution"`
	VulStatus          string             `xml:"vul_status"`
	ExploitStatus      string             `xml:"exploit_status"`
	FixStatus          string             `xml:"fix_status"`
	Sources            string             `xml:"sources"`
	Other              string             `xml:"other"`
	VulIncident        string             `xml:"vul_incident"`
	VulClass           string             `xml:"vul_class"`
	CVEIdentifiers     []Identifier       `xml:"identifiers>identifier"`
}

type VulnerableSoftware struct {
	Software []Software `xml:"soft"`
}

type Software struct {
	Vendor   string `xml:"vendor"`
	Name     string `xml:"name"`
	Version  string `xml:"version"`
	Platform string `xml:"platform"`
	Types    Types  `xml:"types"`
}

type Types struct {
	Type string `xml:"type"`
}

type Environment struct {
	OS OS `xml:"os"`
}

type OS struct {
	Vendor   string `xml:"vendor"`
	Name     string `xml:"name"`
	Version  string `xml:"version"`
	Platform string `xml:"platform"`
}

type CWE struct {
	Identifier string `xml:"identifier"`
}

type CVSS struct {
	Vector string `xml:"vector"`
	Score  string `xml:"score,attr"`
}

type CVSS3 struct {
	Vector string `xml:"vector"`
	Score  string `xml:"score,attr"`
}

type Identifier struct {
	Type string `xml:"type,attr"`
	Link string `xml:",chardata"`
}

func main() {
	// Загрузка переменных окружения из файла .env
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Ошибка загрузки .env файла: %v", err)
	}

	// Получение параметров подключения к базе данных из переменных окружения
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_DATABASE")

	// Проверка, что все параметры подключения заданы
	if dbUser == "" || dbPassword == "" || dbHost == "" || dbPort == "" || dbName == "" {
		log.Fatalf("Параметры подключения к базе данных не заданы в .env файле")
	}

	// Формирование строки подключения к базе данных
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s", dbUser, dbPassword, dbHost, dbPort, dbName)

	// Открытие файла для логирования
	logFile, err := os.OpenFile("output_parser.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Println("Ошибка при открытии файла логов:", err)
		return
	}
	defer logFile.Close()

	// Настройка логгера
	logger := log.New(logFile, "", log.LstdFlags)

	// Чтение CA сертификата
	caCert, err := os.ReadFile("fstek.pem")
	if err != nil {
		logger.Println("Ошибка при чтении CA сертификата:", err)
		return
	}

	// Добавление сертификата в пул сертификатов
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Настройка клиента HTTP с использованием сертификатов
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: caCertPool,
		},
	}
	client := &http.Client{Transport: tr}

	// Скачивание ZIP файла
	zipURL := "https://bdu.fstec.ru/files/documents/vulxml.zip"
	zipPath := "vulxml.zip"
	maxRetries := 5
	for i := 0; i < maxRetries; i++ {
		err = downloadFile(client, zipURL, zipPath, logger)
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

	// Распаковка ZIP файла
	xmlDir := "./"
	err = unzip(zipPath, xmlDir, logger)
	if err != nil {
		logger.Println("Ошибка при распаковке файла:", err)
		return
	}

	// Удаление ZIP файла после распаковки
	err = os.Remove(zipPath)
	if err != nil {
		logger.Println("Ошибка при удалении ZIP файла:", err)
		return
	}

	// Открытие и чтение XML файла
	xmlPath := filepath.Join(xmlDir, "export/export.xml")
	xmlFile, err := os.Open(xmlPath)
	if err != nil {
		logger.Println("Ошибка при открытии XML файла:", err)
		return
	}
	defer xmlFile.Close()

	byteValue, err := os.ReadFile(xmlPath)
	if err != nil {
		logger.Println("Ошибка при чтении XML файла:", err)
		return
	}

	// Разбор (unmarshal) XML данных в структуры
	var vulnerabilities Vulnerabilities
	err = xml.Unmarshal(byteValue, &vulnerabilities)
	if err != nil {
		logger.Println("Ошибка при разборе XML:", err)
		return
	}

	// Подключение к базе данных
	pool, err := pgxpool.Connect(context.Background(), connStr)
	if err != nil {
		logger.Println("Не удалось подключиться к базе данных:", err)
		return
	}
	defer pool.Close()

	// Создание таблиц в базе данных
	createTables(pool, logger)
	// Вставка данных об уязвимостях в базу данных
	insertVulnerabilities(pool, vulnerabilities.Vulnerabilities, logger)

	logger.Println("Данные успешно вставлены")
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
	// Создание файла
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	// Установка пользовательских заголовков, если необходимо
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

// Функция для распаковки ZIP файла
func unzip(src string, dest string, log *log.Logger) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		fPath := filepath.Join(dest, f.Name)

		// Логируем путь, куда будет извлечен файл
		log.Println("Извлечение файла в:", fPath)

		if f.FileInfo().IsDir() {
			err := os.MkdirAll(fPath, os.ModePerm)
			if err != nil {
				return err
			}
			log.Println("Создана директория:", fPath)
		} else {
			err := os.MkdirAll(filepath.Dir(fPath), os.ModePerm)
			if err != nil {
				return err
			}

			outFile, err := os.OpenFile(fPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				return err
			}

			rc, err := f.Open()
			if err != nil {
				return err
			}

			_, err = io.Copy(outFile, rc)
			if err != nil {
				return err
			}

			outFile.Close()
			rc.Close()

			log.Println("Извлечен файл:", fPath)
		}
	}
	log.Println("Файл распакован:", src)
	return nil
}

// Функция для создания таблиц в базе данных
func createTables(pool *pgxpool.Pool, log *log.Logger) {
	createVulTable := `
	CREATE TABLE IF NOT EXISTS vulnerability (
		id SERIAL PRIMARY KEY,
		identifier TEXT UNIQUE,
		name TEXT,
		description TEXT,
		identify_date TEXT,
		severity TEXT,
		solution TEXT,
		vul_status TEXT,
		exploit_status TEXT,
		fix_status TEXT,
		sources TEXT,
		other TEXT,
		vul_incident TEXT,
		vul_class TEXT
	);`

	createSoftwareTable := `
	CREATE TABLE IF NOT EXISTS software (
		id SERIAL PRIMARY KEY,
		vendor TEXT,
		name TEXT,
		version TEXT,
		platform TEXT,
		type TEXT,
		vulnerability_id INTEGER,
		FOREIGN KEY(vulnerability_id) REFERENCES vulnerability(id)
	);`

	createOSTable := `
	CREATE TABLE IF NOT EXISTS os (
		id SERIAL PRIMARY KEY,
		vendor TEXT,
		name TEXT,
		version TEXT,
		platform TEXT,
		vulnerability_id INTEGER,
		FOREIGN KEY(vulnerability_id) REFERENCES vulnerability(id)
	);`

	createCveTable := `
	CREATE TABLE IF NOT EXISTS cve_identifier (
		id SERIAL PRIMARY KEY,
		type TEXT,
		link TEXT,
		vulnerability_id INTEGER,
		FOREIGN KEY(vulnerability_id) REFERENCES vulnerability(id)
	);`

	// Создание таблицы для уязвимостей
	_, err := pool.Exec(context.Background(), createVulTable)
	if err != nil {
		log.Println("Ошибка при создании таблицы уязвимостей:", err)
	}
	// Создание таблицы для программного обеспечения
	_, err = pool.Exec(context.Background(), createSoftwareTable)
	if err != nil {
		log.Println("Ошибка при создании таблицы программного обеспечения:", err)
	}
	// Создание таблицы для операционных систем
	_, err = pool.Exec(context.Background(), createOSTable)
	if err != nil {
		log.Println("Ошибка при создании таблицы операционных систем:", err)
	}
	// Создание таблицы для идентификаторов CVE
	_, err = pool.Exec(context.Background(), createCveTable)
	if err != nil {
		log.Println("Ошибка при создании таблицы идентификаторов CVE:", err)
	}
}

// Функция для вставки данных об уязвимостях в базу данных
func insertVulnerabilities(pool *pgxpool.Pool, vulnerabilities []Vulnerability, log *log.Logger) {
	ctx := context.Background()

	for _, vul := range vulnerabilities {
		var vulnerabilityID int64
		err := pool.QueryRow(ctx, "SELECT id FROM vulnerability WHERE identifier = $1", vul.Identifier).Scan(&vulnerabilityID)
		if err == pgx.ErrNoRows {
			// Вставка новой уязвимости
			err = pool.QueryRow(ctx, `INSERT INTO vulnerability (identifier, name, description, identify_date, severity, solution, vul_status, exploit_status, fix_status, sources, other, vul_incident, vul_class)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
				RETURNING id`,
				vul.Identifier, vul.Name, vul.Description, vul.IdentifyDate, vul.Severity, vul.Solution, vul.VulStatus, vul.ExploitStatus, vul.FixStatus, vul.Sources, vul.Other, vul.VulIncident, vul.VulClass).Scan(&vulnerabilityID)
			if err != nil {
				log.Println("Ошибка при вставке уязвимости:", err)
				continue
			}
		} else if err != nil {
			log.Println("Ошибка при проверке существования уязвимости:", err)
			continue
		} else {
			log.Println("Уязвимость уже существует:", vul.Identifier)
			continue
		}

		// Вставка данных о программном обеспечении
		for _, soft := range vul.VulnerableSoftware.Software {
			_, err := pool.Exec(ctx, `INSERT INTO software (vendor, name, version, platform, type, vulnerability_id)
				VALUES ($1, $2, $3, $4, $5, $6)`,
				soft.Vendor, soft.Name, soft.Version, soft.Platform, soft.Types.Type, vulnerabilityID)
			if err != nil {
				log.Println("Ошибка при вставке данных о программном обеспечении:", err)
			}
		}

		// Вставка данных об операционных системах
		_, err = pool.Exec(ctx, `INSERT INTO os (vendor, name, version, platform, vulnerability_id)
			VALUES ($1, $2, $3, $4, $5)`,
			vul.Environment.OS.Vendor, vul.Environment.OS.Name, vul.Environment.OS.Version, vul.Environment.OS.Platform, vulnerabilityID)
		if err != nil {
			log.Println("Ошибка при вставке данных об операционных системах:", err)
		}

		// Вставка идентификаторов CVE
		for _, id := range vul.CVEIdentifiers {
			if id.Type == "CVE" {
				_, err := pool.Exec(ctx, `INSERT INTO cve_identifier (type, link, vulnerability_id)
					VALUES ($1, $2, $3)`,
					id.Type, id.Link, vulnerabilityID)
				if err != nil {
					log.Println("Ошибка при вставке идентификатора CVE:", err)
				}
			}
		}
	}
}
