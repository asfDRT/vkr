import asyncpg
import logging
from config import Config

# Настройка логирования
logging.basicConfig(filename="app_log.txt", filemode='a', level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

async def get_db_connection():
    """
    Устанавливает и возвращает соединение с базой данных.
    """
    logging.info("Установка соединения с базой данных")
    conn = await asyncpg.connect(
        user=Config.DB_USER,
        password=Config.DB_PASSWORD,
        database=Config.DB_NAME,
        host=Config.DB_HOST,
        port=Config.DB_PORT
    )
    return conn

async def fetch_vulnerabilities(page=1, per_page=15, search=None):
    """
    Извлекает список уязвимостей из базы данных с поддержкой пагинации и поиска.

    :param page: номер страницы
    :param per_page: количество записей на страницу
    :param search: строка поиска
    :return: список уязвимостей
    """
    logging.info(f"Запрос уязвимостей, страница: {page}, поиск: {search}")
    conn = await get_db_connection()
    
    query = """
    SELECT vulnerability.id, vulnerability.identifier, vulnerability.name, vulnerability.severity, cve_identifier.link AS cve
    FROM vulnerability
    LEFT JOIN cve_identifier ON vulnerability.id = cve_identifier.vulnerability_id
    WHERE TRUE
    """
    params = []
    
    if search:
        query += " AND (vulnerability.identifier ILIKE $1 OR cve_identifier.link ILIKE $2)"
        search_param = f"%{search}%"
        params.extend([search_param, search_param])
    
    query += " ORDER BY vulnerability.identifier DESC"
    offset = (page - 1) * per_page
    query += f" OFFSET {offset} LIMIT {per_page}"
    
    results = await conn.fetch(query, *params)
    await conn.close()
    
    return results

async def fetch_vulnerability_details(vul_id):
    """
    Извлекает подробную информацию об уязвимости по ее идентификатору.

    :param vul_id: идентификатор уязвимости
    :return: подробная информация об уязвимости
    """
    logging.info(f"Запрос деталей уязвимости с ID: {vul_id}")
    conn = await get_db_connection()
    query = """
    SELECT vulnerability.*, 
           array_agg(DISTINCT cve_identifier.link) AS cve_links,
           array_agg(DISTINCT software.name || ' ' || software.version || ' ' || software.platform) AS software_details,
           array_agg(DISTINCT os.name || ' ' || os.version || ' ' || os.platform) AS os_details
    FROM vulnerability
    LEFT JOIN cve_identifier ON vulnerability.id = cve_identifier.vulnerability_id
    LEFT JOIN software ON vulnerability.id = software.vulnerability_id
    LEFT JOIN os ON vulnerability.id = os.vulnerability_id
    WHERE vulnerability.id = $1
    GROUP BY vulnerability.id
    """
    result = await conn.fetchrow(query, vul_id)
    await conn.close()
    
    return result

async def fetch_cve_nvd_details(vul_id):
    """
    Извлекает детали CVE из NVD по идентификатору уязвимости.

    :param vul_id: идентификатор уязвимости
    :return: детали CVE из NVD
    """
    logging.info(f"Запрос деталей CVE NVD для уязвимости с ID: {vul_id}")
    conn = await get_db_connection()
    query = """
    SELECT cve_link, description, hyperlinks
    FROM cve_nvd
    WHERE vulnerability_id = $1
    """
    result = await conn.fetchrow(query, vul_id)
    await conn.close()
    
    return result

async def fetch_opencve_details(vul_id):
    """
    Извлекает детали из OpenCVE по идентификатору уязвимости.

    :param vul_id: идентификатор уязвимости
    :return: детали из OpenCVE
    """
    logging.info(f"Запрос деталей OpenCVE для уязвимости с ID: {vul_id}")
    conn = await get_db_connection()
    query = """
    SELECT attack_vector, attack_complexity, privileges_required, user_interaction, 
    confidentiality_impact, integrity_impact, availability_impact, scope
    FROM cve_opencve
    WHERE vulnerability_id = $1
    """
    result = await conn.fetchrow(query, vul_id)
    await conn.close()
    
    return result

async def fetch_ubi(page=1, per_page=15):
    """
    Извлекает список УБИ (угроз безопасности информации) с поддержкой пагинации.

    :param page: номер страницы
    :param per_page: количество записей на страницу
    :return: список УБИ
    """
    logging.info(f"Запрос списка УБИ, страница: {page}")
    conn = await get_db_connection()
    
    query = """
    SELECT id, name, source
    FROM ubi
    ORDER BY id ASC
    OFFSET $1 LIMIT $2
    """
    offset = (page - 1) * per_page
    
    results = await conn.fetch(query, offset, per_page)
    await conn.close()
    
    return results

async def fetch_ubi_details(ubi_id):
    """
    Извлекает подробную информацию по УБИ (угрозе безопасности информации) по ее идентификатору.

    :param ubi_id: идентификатор УБИ
    :return: подробная информация по УБИ
    """
    logging.info(f"Запрос деталей УБИ с ID: {ubi_id}")
    conn = await get_db_connection()
    
    query = """
    SELECT *
    FROM ubi
    WHERE id = $1
    """
    
    result = await conn.fetchrow(query, ubi_id)
    await conn.close()
    
    return result

async def fetch_statistics():
    """
    Извлекает статистику из базы данных.

    :return: статистика базы данных
    """
    logging.info("Запрос статистики базы данных")
    conn = await get_db_connection()
    
    query = """
    SELECT
        (SELECT COUNT(*) FROM vulnerability) AS total_vulnerabilities,
        (SELECT COUNT(*) FROM software) AS total_software,
        (SELECT COUNT(*) FROM os) AS total_os,
        (SELECT COUNT(*) FROM cve_identifier) AS total_cve,
        (SELECT COUNT(*) FROM cve_nvd) AS total_cve_nvd,
        (SELECT COUNT(*) FROM cve_opencve) AS total_cve_opencve,
        (SELECT COUNT(*) FROM ubi) AS total_ubi
    """
    
    result = await conn.fetchrow(query)
    await conn.close()
    
    return result
