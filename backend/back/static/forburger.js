document.addEventListener("DOMContentLoaded", function() {
    // Получаем элемент с классом 'burger-menu'
    const burger = document.querySelector('.burger-menu');
    
    // Получаем элемент с классом 'nav-links'
    const navLinks = document.querySelector('.nav-links');

    // Добавляем обработчик события 'click' на элемент 'burger'
    burger.addEventListener('click', function() {
        // Переключаем класс 'mobile' на элементе 'nav-links'
        navLinks.classList.toggle('mobile');
    });
});
