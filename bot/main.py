import os
import sys
import logging
import asyncio
import html

from dotenv import load_dotenv
from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import StatesGroup, State
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup, Message, CallbackQuery
from aiogram import F

from sql import get_stats, search_by_bdu, search_by_cve, get_last_cve, get_ubi

# Загрузка переменных окружения из файла .env
load_dotenv()

# Настройка логирования
logging.basicConfig(filename="bot_log.txt", filemode='a', level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

TOKEN = os.getenv('TOKEN')
if not TOKEN:
    logging.error("Токен бота не задан в файле .env")
    sys.exit(1)

# Инициализация диспетчера
dp = Dispatcher()


class SearchState(StatesGroup):
    """Состояния для FSM поиска"""
    waiting_for_search_type = State()
    waiting_for_identifier = State()


class UbiState(StatesGroup):
    """Состояния для FSM поиска по УБИ"""
    waiting_for_ubi_id = State()


@dp.message(F.text, Command("start"))
async def start_command(message: Message):
    """
    Обработка команды /start.
    """
    await message.answer("Бот выполняет поиск по базе данных, в которой есть данные с ФСТЭК, NVD, OpenCVE\n\n"
                         "Доступные команды:\n"
                         "\- /search \- выполняет поиск по идентификатору CVE или BDU\n"
                         "\- /glossary \- справочная информация\n"
                         "\- /statistic \- статистика базы данных\n"
                         "\- /search\_ubi \- выполняет поиск по идентификатору УБИ", parse_mode=ParseMode.MARKDOWN_V2)


@dp.message(F.text, Command("statistic"))
async def show_statistic(message: Message):
    """
    Обработка команды /statistic для отображения статистики базы данных.
    """
    stats = await get_stats()
    if stats:
        await message.answer(
            f"*Статистика базы данных:* \n\n"
            f"Количество уязвимостей из БДУ ФСТЭК: *{stats['total_vulnerabilities']}* \n"
            f"Количество ПО для которых есть уязвимости: *{stats['total_software']}* \n"
            f"Количество ОС для которых есть уязвимости: *{stats['total_os']}* \n"
            f"Количество CVE связанных с BDU из БДУ ФСТЭК: *{stats['total_cve']}* \n"
            f"Количество уязвимостей из NVD: *{stats['total_cve_nvd']}* \n"
            f"Количество уязвимостей из OpenCVE: *{stats['total_cve_opencve']}* \n"
            f"Количество УБИ: *{stats['total_ubi']}* \n", parse_mode=ParseMode.MARKDOWN_V2)
    else:
        await message.answer("Произошла ошибка при получении статистики.")


@dp.message(Command("glossary"))
async def show_glossary(message: Message):
    """
    Обработка команды /glossary для отображения глоссария.
    """
    keyboard = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Термины", callback_data="terms")],
            [InlineKeyboardButton(text="Ресурсы", callback_data="resources")],
        ]
    )
    await message.answer("Выберите раздел глоссария:", reply_markup=keyboard)


@dp.callback_query(lambda c: c.data in ["terms", "resources"])
async def handle_glossary_choice(call: CallbackQuery):
    """
    Обработка выбора в глоссарии.
    """
    await call.answer()
    file_path = "terms.txt" if call.data == "terms" else "res.txt"

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()
            await send_large_message(call.message, content, parse_mode=ParseMode.MARKDOWN_V2)
    except FileNotFoundError:
        await call.message.answer("Файл глоссария не найден.")
        logging.error(f"Файл глоссария {file_path} не найден.")

async def send_large_message(message: types.Message, content: str, parse_mode: ParseMode):
    """
    Отправка большого сообщения, разбивая его на несколько частей.
    """
    max_message_length = 4096
    messages = split_message(content, max_message_length)

    for msg in messages:
        await message.answer(msg, parse_mode=parse_mode)


def split_message(text: str, max_length: int):
    """
    Разбиение текста на части заданной максимальной длины.
    """
    paragraphs = text.split('\n')
    messages = []
    current_message = ""

    for paragraph in paragraphs:
        if len(current_message) + len(paragraph) + 1 > max_length:
            messages.append(current_message)
            current_message = paragraph
        else:
            if current_message:
                current_message += '\n'
            current_message += paragraph

    if current_message:
        messages.append(current_message)

    return messages


@dp.message(Command("search"))
async def start_search(message: Message, state: FSMContext):
    """
    Обработка команды /search для начала поиска по идентификатору.
    """
    keyboard = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="BDU идентификатор", callback_data="BDU")],
            [InlineKeyboardButton(text="CVE идентификатор", callback_data="CVE")],
        ]
    )
    await message.answer("Выберите тип идентификатора для поиска:", reply_markup=keyboard)
    await state.set_state(SearchState.waiting_for_search_type)


@dp.callback_query(lambda c: c.data in ["BDU", "CVE"])
async def handle_search_type(call: CallbackQuery, state: FSMContext):
    """
    Обработка выбора типа идентификатора для поиска.
    """
    await call.answer()
    await state.update_data(search_type=call.data)
    last_cve = await get_last_cve()
    await call.message.answer(f"Введите год и номер идентификатора: \n"
                              f"Например последние уязвимости:\nBDU: {last_cve[0][0]}\nCVE: {last_cve[0][1]}", parse_mode=ParseMode.HTML)
    await state.set_state(SearchState.waiting_for_identifier)


@dp.message(SearchState.waiting_for_identifier)
async def handle_identifier(message: Message, state: FSMContext):
    """
    Обработка введенного идентификатора для поиска.
    """
    identifier = message.text.strip()

    async def get_search_type():
        data = await state.get_data()
        return data["search_type"]

    search_type = await get_search_type()
    await state.clear()

    if search_type == "BDU":
        result = await search_by_bdu(identifier)
    else:
        result = await search_by_cve(identifier)

    if result:
        vulnerability_data, software_data, os_data, cve_nvd_data, cve_opencve_data, only_cve = result

        message_text = f"<b>Найдено по {search_type}:</b>\n\n"
        message_text += f"<b>Уязвимость по ФСТЭК:</b>\n"
        message_text += f"<b>Идентификатор BDU:</b> {vulnerability_data[0][1]}\n"
        if only_cve:
            for row in only_cve:
                message_text += f"<b>Идентификатор CVE:</b> {row['link']}\n"
        message_text += f"<b>Название:</b> {vulnerability_data[0][2]}\n"
        message_text += f"<b>Описание:</b> {vulnerability_data[0][3]}\n"
        message_text += f"<b>Дата выявления:</b> {vulnerability_data[0][4]}\n"
        message_text += f"<b>Уровень опасности:</b> {vulnerability_data[0][5]}\n"
        message_text += f"<b>Статус уязвимости:</b> {vulnerability_data[0][7]}\n"
        message_text += f"<b>Наличие эксплойта:</b> {vulnerability_data[0][8]}\n"
        message_text += f"<b>Информация об устранении:</b> {vulnerability_data[0][9]}\n"
        message_text += f"<b>Источники:</b> {vulnerability_data[0][10]}\n"
        message_text += f"<b>Другие сведения:</b> {vulnerability_data[0][11]}\n"
        message_text += f"<b>Количество инцидентов:</b> {vulnerability_data[0][12]}\n"
        message_text += f"<b>Класс уязвимости:</b> {vulnerability_data[0][13]}\n"
        message_text += f"<b>Класс уязвимости:</b> {vulnerability_data[0][13]}\n"
        message_text += f"<b>Возможные способы устранения:</b> {vulnerability_data[0][6]}\n"

        if software_data:
            message_text += f"\n<b>Программное обеспечение:</b>\n"
            for row in software_data:
                message_text += f"<b>Производитель:</b> {row['vendor']}\n"
                message_text += f"<b>Название:</b> {row['name']}\n"
                message_text += f"<b>Версия:</b> {row['version']}\n"
                message_text += f"<b>Платформа:</b> {row['platform']}\n"
                message_text += f"<b>Тип:</b> {row['type']}\n\n"

        if os_data:
            message_text += f"\n<b>Операционные системы:</b>\n"
            for row in os_data:
                message_text += f"<b>Производитель:</b> {row['vendor']}\n"
                message_text += f"<b>Название:</b> {row['name']}\n"
                message_text += f"<b>Версия:</b> {row['version']}\n"
                message_text += f"<b>Платформа:</b> {row['platform']}\n"

        if cve_nvd_data:
            message_text += f"\n<b>Информация из NVD:</b>\n"
            for row in cve_nvd_data:
                message_text += f"<b>Ссылка на NVD:</b> {row['cve_link']}\n"
                message_text += f"<b>Описание:</b> {row['description']}\n"
                message_text += f"<b>Ссылки из NVD:</b> {row['hyperlinks']}\n"

        if cve_opencve_data:
            message_text += f"\n<b>Информация из OpenCVE:</b>\n"
            message_text += f"<b>Вектор атаки:</b> {cve_opencve_data[0]['attack_vector']}\n"
            message_text += f"<b>Сложность атаки:</b> {cve_opencve_data[0]['attack_complexity']}\n"
            message_text += f"<b>Необходимые права:</b> {cve_opencve_data[0]['privileges_required']}\n"
            message_text += f"<b>Взаимодействие пользователя:</b> {cve_opencve_data[0]['user_interaction']}\n"
            message_text += f"<b>Воздействие на конфиденциальность:</b> {cve_opencve_data[0]['confidentiality_impact']}\n"
            message_text += f"<b>Воздействие на целостность:</b> {cve_opencve_data[0]['integrity_impact']}\n"
            message_text += f"<b>Воздействие на доступность:</b> {cve_opencve_data[0]['availability_impact']}\n"
            message_text += f"<b>Область:</b> {cve_opencve_data[0]['scope']}\n"

        await message.answer(message_text, parse_mode=ParseMode.HTML)
    else:
        await message.answer(f"Информация по {search_type} {identifier} не найдена.")


@dp.message(Command("search_ubi"))
async def start_search_ubi(message: Message, state: FSMContext):
    """
    Обработка команды /search_ubi для начала поиска по идентификатору УБИ.
    """
    await message.answer("Введите идентификатор УБИ \(от 1 до 222\):")
    await state.set_state(UbiState.waiting_for_ubi_id)


@dp.message(UbiState.waiting_for_ubi_id)
async def handle_ubi_id(message: Message, state: FSMContext):
    """
    Обработка введенного идентификатора УБИ.
    """
    ubi_id_str = message.text.strip()
    await state.clear()

    try:
        ubi_id = int(ubi_id_str)
    except ValueError:
        await message.answer(f"Некорректный идентификатор УБИ: {html.escape(ubi_id_str)}. Пожалуйста, введите числовое значение.", parse_mode=ParseMode.HTML)
        return

    result = await get_ubi(ubi_id)

    if result:
        ubi_data = result[0]
        message_text = (
            f"<b>Информация по УБИ:</b>\n\n"
            f"<b>Идентификатор:</b> {html.escape(str(ubi_data['id']))}\n"
            f"<b>Название:</b> {html.escape(ubi_data['name'])}\n"
            f"<b>Описание:</b> {html.escape(ubi_data['description'])}\n"
            f"<b>Источник:</b> {html.escape(ubi_data['source'])}\n"
            f"<b>Объект:</b> {html.escape(ubi_data['object'])}\n"
            f"<b>Нарушение конфиденциальности:</b> {html.escape(ubi_data['confidentiality_violation'])}\n"
            f"<b>Нарушение целостности:</b> {html.escape(ubi_data['integrity_violation'])}\n"
            f"<b>Нарушение доступности:</b> {html.escape(ubi_data['availability_violation'])}\n"
        )
        await message.answer(message_text, parse_mode=ParseMode.HTML)
    else:
        await message.answer(f"Информация по УБИ с идентификатором {html.escape(ubi_id_str)} не найдена.", parse_mode=ParseMode.HTML)

async def main() -> None:
    """
    Основная функция для запуска бота.
    """
    bot = Bot(token=TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.MARKDOWN_V2))
    await dp.start_polling(bot)

if __name__ == "__main__":
    logging.debug("Бот запущен")
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)
    asyncio.run(main())
