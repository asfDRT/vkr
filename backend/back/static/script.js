// Получаем элемент canvas по его ID и контекст рисования
const canvas = document.getElementById('background-canvas');
const ctx = canvas.getContext('2d');

// Массив частиц и параметры анимации
let particlesArray = [];
let numberOfParticles;
const speedReductionFactor = 0.2; // Коэффициент уменьшения скорости для более плавной анимации
let particleSizeMultiplier;
let mouse = {
    x: null,
    y: null,
    radius: 100
};

// Обработчик события для движения мыши
window.addEventListener('mousemove', (event) => {
    mouse.x = event.x;
    mouse.y = event.y;
});

// Обработчик события для выхода мыши за пределы окна
window.addEventListener('mouseout', () => {
    mouse.x = null;
    mouse.y = null;
});

// Функция для настройки размеров canvas
function adjustCanvasSize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
}

// Функция для настройки параметров частиц в зависимости от размера экрана
function adjustParticleSettings() {
    const screenWidth = window.innerWidth;
    if (screenWidth >= 2500) {
        numberOfParticles = 170;
        particleSizeMultiplier = 1.5;
    } else if (screenWidth >= 1920) {
        numberOfParticles = 100;
        particleSizeMultiplier = 1.2;
    } else if (screenWidth >= 1280) {
        numberOfParticles = 80;
        particleSizeMultiplier = 1;
    } else {
        numberOfParticles = 60;
        particleSizeMultiplier = 0.8;
    }
}

// Класс для создания частиц
class Particle {
    constructor() {
        this.x = Math.random() * canvas.width;
        this.y = Math.random() * canvas.height;
        this.size = (Math.random() * 5 + 1) * particleSizeMultiplier;
        this.speedX = (Math.random() * 2 - 1) * speedReductionFactor;
        this.speedY = (Math.random() * 2 - 1) * speedReductionFactor;
        this.edgeBias();
    }

    // Метод для размещения частиц ближе к краям экрана
    edgeBias() {
        const edgeMargin = 100; // Расстояние от края, где частицы более вероятны
        if (Math.random() < 0.7) { // 70% вероятность размещения ближе к краям
            if (Math.random() < 0.5) {
                this.x = Math.random() < 0.5 ? Math.random() * edgeMargin : canvas.width - Math.random() * edgeMargin;
            } else {
                this.y = Math.random() < 0.5 ? Math.random() * edgeMargin : canvas.height - Math.random() * edgeMargin;
            }
        }
    }

    // Метод для обновления состояния частиц
    update() {
        this.x += this.speedX;
        this.y += this.speedY;

        // Изменение направления при ударе о край
        if (this.x < 0 || this.x > canvas.width) {
            this.speedX = -this.speedX;
        }
        if (this.y < 0 || this.y > canvas.height) {
            this.speedY = -this.speedY;
        }

        // Взаимодействие с мышью
        let dx = mouse.x - this.x;
        let dy = mouse.y - this.y;
        let distance = Math.sqrt(dx * dx + dy * dy);
        if (distance < mouse.radius) {
            let angle = Math.atan2(dy, dx);
            let force = (mouse.radius - distance) / mouse.radius;
            let moveX = Math.cos(angle) * force * 2; // Регулировка силы для более плавного движения
            let moveY = Math.sin(angle) * force * 2;
            this.x -= moveX;
            this.y -= moveY;
        }
    }

    // Метод для рисования частиц
    draw() {
        ctx.fillStyle = 'black';
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
        ctx.closePath();
        ctx.fill();
    }
}

// Функция для инициализации частиц
function init() {
    particlesArray = [];
    for (let i = 0; i < numberOfParticles; i++) {
        particlesArray.push(new Particle());
    }
}

// Функция для обработки и отрисовки частиц
function handleParticles() {
    for (let i = 0; i < particlesArray.length; i++) {
        particlesArray[i].update();
        particlesArray[i].draw();
        for (let j = i + 1; j < particlesArray.length; j++) {
            const dx = particlesArray[i].x - particlesArray[j].x;
            const dy = particlesArray[i].y - particlesArray[j].y;
            const distance = Math.sqrt(dx * dx + dy * dy);
            if (distance < 200) { // Увеличенное максимальное расстояние
                ctx.strokeStyle = `rgba(0, 0, 0, ${Math.max(0.1, 1 - distance / 200)})`; // Уменьшенная скорость уменьшения непрозрачности
                ctx.lineWidth = 1; // Толщина линий для соединений
                ctx.beginPath();
                ctx.moveTo(particlesArray[i].x, particlesArray[i].y);
                ctx.lineTo(particlesArray[j].x, particlesArray[j].y);
                ctx.stroke();
                ctx.closePath();
            }
        }
    }
}

// Функция для анимации частиц
function animate() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    handleParticles();
    requestAnimationFrame(animate);
}

// Функция для начальной настройки
function setup() {
    adjustCanvasSize();
    adjustParticleSettings();
    init();
    animate();
}

// Обработчик события для изменения размера окна
window.addEventListener('resize', () => {
    adjustCanvasSize();
    adjustParticleSettings();
    init();
});

// Вызов начальной настройки
setup();
