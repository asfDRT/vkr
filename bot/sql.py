import logging
from dotenv import load_dotenv
import asyncpg
import os

# Загрузка переменных окружения из файла .env
load_dotenv()

# Настройка логирования
logging.basicConfig(filename="bot_log.txt", filemode='a', level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Получение параметров подключения из переменных окружения
USER = os.getenv('DB_USER')
PASSWORD = os.getenv('DB_PASSWORD')
HOST = os.getenv('DB_HOST')
PORT = os.getenv('DB_PORT')
DATABASE = os.getenv('DB_DATABASE')


async def fetch_from_db(query, *params):
    """
    Выполняет запрос к базе данных и возвращает результат.
    
    :param query: SQL запрос
    :param params: параметры для SQL запроса
    :return: результат выполнения запроса
    """
    logging.info("Подключение к БД")
    conn = await asyncpg.connect(user=USER, password=PASSWORD, database=DATABASE, host=HOST, port=PORT)
    try:
        if params:
            result = await conn.fetch(query, *params)
        else:
            result = await conn.fetch(query)
        return result
    except Exception as e:
        logging.error(f"Ошибка при выполнении запроса: {e}")
        return None
    finally:
        await conn.close()


async def get_stats():
    """
    Запрашивает статистику из базы данных.
    
    :return: словарь со статистикой или None в случае ошибки
    """
    logging.info("Запрос статистики")
    try:
        total_vulnerabilities = await fetch_from_db("SELECT COUNT(*) FROM vulnerability")
        total_software = await fetch_from_db("SELECT COUNT(*) FROM software")
        total_os = await fetch_from_db("SELECT COUNT(*) FROM os")
        total_cve = await fetch_from_db("SELECT COUNT(*) FROM cve_identifier")
        total_cve_nvd = await fetch_from_db("SELECT COUNT(*) FROM cve_nvd")
        total_cve_opencve = await fetch_from_db("SELECT COUNT(*) FROM cve_opencve")
        total_ubi = await fetch_from_db("SELECT COUNT(*) FROM ubi")
        return {
            "total_vulnerabilities": total_vulnerabilities[0][0],
            "total_software": total_software[0][0],
            "total_os": total_os[0][0],
            "total_cve": total_cve[0][0],
            "total_cve_nvd": total_cve_nvd[0][0],
            "total_cve_opencve": total_cve_opencve[0][0],
            "total_ubi": total_ubi[0][0]
        }
    except Exception as e:
        logging.error(f"Произошла ошибка при извлечении данных: {e}")
        return None
    

async def search_by_bdu(identifier):
    """
    Выполняет поиск уязвимостей по идентификатору BDU.

    :param identifier: идентификатор BDU
    :return: данные уязвимостей или None в случае ошибки
    """
    logging.info(f"Поиск по BDU: {identifier}")
    try:
        vulnerability_data = await fetch_from_db(
            "SELECT * FROM vulnerability WHERE identifier = $1", identifier)
        software_data = await fetch_from_db(
            "SELECT * FROM software WHERE vulnerability_id = (SELECT id FROM vulnerability WHERE identifier = $1)", identifier)
        os_data = await fetch_from_db(
            "SELECT * FROM os WHERE vulnerability_id = (SELECT id FROM vulnerability WHERE identifier = $1)", identifier)
        cve_nvd_data = await fetch_from_db(
            "SELECT * FROM cve_nvd WHERE vulnerability_id = (SELECT id FROM vulnerability WHERE identifier = $1)", identifier)
        cve_opencve_data = await fetch_from_db(
            "SELECT * FROM cve_opencve WHERE vulnerability_id = (SELECT id FROM vulnerability WHERE identifier = $1)", identifier)
        only_cve = await fetch_from_db(
            "SELECT link FROM cve_identifier WHERE vulnerability_id = (SELECT id FROM vulnerability WHERE identifier = $1)", identifier)
        return vulnerability_data, software_data, os_data, cve_nvd_data, cve_opencve_data, only_cve
    except Exception as e:
        logging.error(f"Произошла ошибка при поиске по BDU: {e}")
        return None


async def search_by_cve(identifier):
    """
    Выполняет поиск уязвимостей по идентификатору CVE.

    :param identifier: идентификатор CVE
    :return: данные уязвимостей или None в случае ошибки
    """
    logging.info(f"Поиск по CVE: {identifier}")
    try:
        vulnerability_data = await fetch_from_db(
            "SELECT * FROM vulnerability WHERE id IN (SELECT vulnerability_id FROM cve_identifier WHERE link = $1)", identifier)
        software_data = await fetch_from_db(
            "SELECT * FROM software WHERE vulnerability_id = (SELECT vulnerability_id FROM cve_identifier WHERE link = $1)", identifier)
        os_data = await fetch_from_db(
            "SELECT * FROM os WHERE vulnerability_id = (SELECT vulnerability_id FROM cve_identifier WHERE link = $1)", identifier)
        cve_nvd_data = await fetch_from_db(
            "SELECT * FROM cve_nvd WHERE vulnerability_id = (SELECT vulnerability_id FROM cve_identifier WHERE link = $1)", identifier)
        cve_opencve_data = await fetch_from_db(
            "SELECT * FROM cve_opencve WHERE vulnerability_id = (SELECT vulnerability_id FROM cve_identifier WHERE link = $1)", identifier)
        only_cve = await fetch_from_db(
            "SELECT link FROM cve_identifier WHERE vulnerability_id = (SELECT vulnerability_id FROM cve_identifier WHERE link = $1)", identifier)
        return vulnerability_data, software_data, os_data, cve_nvd_data, cve_opencve_data, only_cve
    except Exception as e:
        logging.error(f"Произошла ошибка при поиске по CVE: {e}")
        return None
    

async def get_last_cve():
    """
    Запрашивает последнюю уязвимость из базы данных.

    :return: данные последней уязвимости или None в случае ошибки
    """
    logging.info("Запрос последней уязвимости")
    try:
        last_vulnerabilities = await fetch_from_db(
            """
            SELECT v.identifier, ci.link
            FROM public.vulnerability v
            LEFT JOIN cve_identifier ci ON v.id = ci.vulnerability_id
            ORDER BY v.identifier DESC LIMIT 1
            """
        )
        return last_vulnerabilities
    except Exception as e:
        logging.error(f"Произошла ошибка при извлечении данных: {e}")
        return None
    

async def get_ubi(id):
    """
    Выполняет поиск информации по УБИ.

    :param id: идентификатор УБИ
    :return: данные по УБИ или None в случае ошибки
    """
    logging.info(f"Поиск УБИ: {id}")
    try:
        ubi_inf = await fetch_from_db(
            "SELECT * FROM ubi WHERE id = $1", id)
        return ubi_inf
    except Exception as e:
        logging.error(f"Произошла ошибка при извлечении данных по УБИ: {e}")
        return None
