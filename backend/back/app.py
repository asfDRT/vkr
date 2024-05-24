import logging
import os
from quart import Quart, render_template, request, redirect, url_for, session
from quart_auth import QuartAuth, login_required, AuthUser, login_user, logout_user, current_user, Unauthorized
from dotenv import load_dotenv
from db import fetch_vulnerabilities, fetch_vulnerability_details, fetch_cve_nvd_details, fetch_opencve_details, fetch_statistics, fetch_ubi, fetch_ubi_details

# Загрузка переменных окружения из файла .env
load_dotenv()

# Настройка логирования
logging.basicConfig(filename="app_log.txt", filemode='a', level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Создание экземпляра Quart приложения
app = Quart(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'supersecretkey')
QuartAuth(app)

# Получение учетных данных из переменных окружения
USERNAME = os.getenv('USERNAME')
PASSWORD = os.getenv('PASSWORD')


@app.route('/')
@app.route('/page/<int:page>')
@login_required
async def index(page=1):
    """
    Главная страница с перечнем уязвимостей. Поддерживает поиск и пагинацию.
    """
    search = request.args.get('search')
    vulnerabilities = await fetch_vulnerabilities(page=page, search=search)
    logging.info(f"Пользователь {current_user.auth_id} запросил главную страницу, страница: {page}, поиск: {search}")
    return await render_template('index.html', vulnerabilities=vulnerabilities, page=page, search=search)


@app.route('/details/<int:vul_id>')
@login_required
async def details(vul_id):
    """
    Страница с подробной информацией об уязвимости.
    """
    vulnerability = await fetch_vulnerability_details(vul_id)
    cve_nvd = await fetch_cve_nvd_details(vul_id)
    opencve = await fetch_opencve_details(vul_id)
    logging.info(f"Пользователь {current_user.auth_id} запросил детали уязвимости с ID: {vul_id}")
    return await render_template('details.html', vulnerability=vulnerability, cve_nvd=cve_nvd, opencve=opencve)


@app.route('/ubi')
@app.route('/ubi/page/<int:page>')
@login_required
async def ubi_list(page=1):
    """
    Страница с перечнем УБИ (угроз безопасности информации). Поддерживает пагинацию.
    """
    ubi_list = await fetch_ubi(page=page)
    logging.info(f"Пользователь {current_user.auth_id} запросил список УБИ, страница: {page}")
    return await render_template('ubi.html', ubi_list=ubi_list, page=page)


@app.route('/ubi/details/<int:ubi_id>')
@login_required
async def ubi_details(ubi_id):
    """
    Страница с подробной информацией по УБИ.
    """
    ubi = await fetch_ubi_details(ubi_id)
    logging.info(f"Пользователь {current_user.auth_id} запросил детали УБИ с ID: {ubi_id}")
    return await render_template('ubi_details.html', ubi=ubi)


@app.route('/login', methods=['GET', 'POST'])
async def login():
    """
    Страница для входа в систему. Обрабатывает GET и POST запросы.
    """
    if request.method == 'POST':
        form = await request.form
        username = form.get('username')
        password = form.get('password')
        
        if username == USERNAME and password == PASSWORD:
            user = AuthUser(username)
            login_user(user)
            logging.info(f"Пользователь {username} успешно вошел в систему")
            return redirect(url_for('index'))
        else:
            logging.warning(f"Неудачная попытка входа с использованием имени пользователя: {username}")
            return "Неверные учетные данные", 401

    return await render_template('login.html')


@app.route('/registration')
async def registration():
    """
    Страница для регистрации пользователей.
    """
    return await render_template('registration.html')

@app.route('/logout')
@login_required
async def logout():
    """
    Обработка выхода пользователя из системы.
    """
    logging.info(f"Пользователь {current_user.auth_id} вышел из системы")
    logout_user()
    return redirect(url_for('login'))


@app.route('/glossary')
@login_required
async def glossary():
    """
    Страница с глоссарием.
    """
    logging.info(f"Пользователь {current_user.auth_id} запросил глоссарий")
    return await render_template('glossary.html')

@app.route('/statistics')
@login_required
async def statistics():
    """
    Страница со статистикой базы данных.
    """
    stats = await fetch_statistics()
    logging.info(f"Пользователь {current_user.auth_id} запросил статистику")
    return await render_template('statistics.html', stats=stats)


# Перенаправление неавторизованных пользователей на страницу входа
@app.before_request
async def before_request():
    """
    Перенаправление неавторизованных пользователей на страницу входа.
    """
    allowed_routes = ['login', 'registration']
    if not current_user.is_authenticated and request.endpoint not in allowed_routes:
        logging.info(f"Неавторизованный доступ к {request.endpoint}, перенаправление на страницу входа")
        return redirect(url_for('login'))
    
    
@app.errorhandler(Unauthorized)
async def handle_unauthorized(_):
    """
    Обработка ошибки Unauthorized.
    """
    logging.warning(f"Пользователь не авторизован, перенаправление на страницу входа")
    return redirect(url_for('login'))

if __name__ == '__main__':
    logging.info("Запуск приложения")
    app.run(debug=True, host='0.0.0.0', port=5000)
