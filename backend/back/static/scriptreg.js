document.addEventListener("DOMContentLoaded", function() {
    // Получаем элемент формы с ID 'login-form'
    const form = document.getElementById("login-form");

    // Добавляем обработчик события 'submit' на форму
    form.addEventListener("submit", function(event) {
        // Предотвращаем отправку формы по умолчанию
        event.preventDefault();

        // Отображаем сообщение
        alert("Регистрация временно приостановлена, запросите данные у администратора.");
    });
});
