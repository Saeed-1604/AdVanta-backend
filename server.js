const express = require('express');
const cors = require('cors');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const xss = require('xss-clean');
const hpp = require('hpp');
const mongoSanitize = require('express-mongo-sanitize');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// ==================== أمان متقدم ====================

// 1️⃣ Helmet: حماية الرؤوس (Headers)
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
}));

// 2️⃣ منع هجمات XSS
app.use(xss());

// 3️⃣ منع تلوث المعلمات (HPP)
app.use(hpp());

// 4️⃣ تنظيف البيانات من أكواد SQL
app.use(mongoSanitize());

// 5️⃣ CORS مقيد (وليس مفتوح للجميع)
const corsOptions = {
    origin: ['https://advanta-aiti.onrender.com', 'http://localhost:3000'], // المواقع المسموح بها فقط
    methods: ['POST', 'GET'],
    allowedHeaders: ['Content-Type'],
    credentials: true
};
app.use(cors(corsOptions));

// 6️⃣ Rate Limiting (حدود الطلبات)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 دقيقة
    max: 100, // حد أقصى 100 طلب لكل IP
    message: { error: 'لقد تجاوزت الحد المسموح من الطلبات، حاول بعد 15 دقيقة' },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/', limiter);

// 7️⃣ Rate Limiting أشد لعملية التوليد (لأنها مكلفة)
const generateLimiter = rateLimit({
    windowMs: 60 * 1000, // دقيقة واحدة
    max: 5, // حد أقصى 5 طلبات توليد في الدقيقة
    message: { error: 'لقد تجاوزت الحد المسموح من طلبات التوليد، حاول بعد دقيقة' },
});
app.use('/api/generate', generateLimiter);

// 8️⃣ منع عرض معلومات السيرفر
app.disable('x-powered-by');

// 9️⃣ تنظيف المدخلات من أي أكواد ضارة
function sanitizeInput(text) {
    if (!text) return '';
    // إزالة أي أكواد HTML/JavaScript
    return text.replace(/<[^>]*>?/gm, '')
               .replace(/javascript:/gi, '')
               .replace(/on\w+=/gi, '')
               .trim();
}

// 🔟 التحقق من صحة البريد الإلكتروني
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// ==================== Middleware ====================
app.use(express.json({ limit: '10kb' })); // حد حجم الجسم 10KB

// سجل الطلبات (Logging)
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - IP: ${req.ip}`);
    next();
});

// ==================== نقطة النهاية الرئيسية ====================
app.get('/', (req, res) => {
    res.json({ 
        status: '✅ AdVanta Backend is running securely',
        message: 'Use POST /api/generate with a prompt',
        security: {
            rateLimit: '15m / 100 requests',
            cors: 'restricted',
            helmet: 'active',
            xss: 'protected'
        }
    });
});

// ==================== نقطة النهاية لتوليد المحتوى ====================
app.post('/api/generate', async (req, res) => {
    try {
        // تنظيف المدخلات
        let { prompt } = req.body;
        
        if (!prompt) {
            return res.status(400).json({ error: 'Prompt is required' });
        }

        // تنظيف النص من أي أكواد ضارة
        prompt = sanitizeInput(prompt);

        // التحقق من طول النص
        if (prompt.length > 5000) {
            return res.status(400).json({ error: 'النص طويل جداً (الحد الأقصى 5000 حرف)' });
        }

        // التحقق من وجود المفتاح
        if (!process.env.GEMINI_API_KEY) {
            console.error('❌ GEMINI_API_KEY غير موجود في البيئة');
            return res.status(500).json({ error: 'خطأ في إعدادات السيرفر' });
        }

        // إرسال الطلب إلى Gemini
        const response = await axios.post(
            `https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent?key=${process.env.GEMINI_API_KEY}`,
            {
                contents: [{
                    parts: [{ text: prompt }]
                }]
            },
            {
                timeout: 30000, // مهلة 30 ثانية
                maxContentLength: 10000 // حد حجم الرد
            }
        );

        // التحقق من صحة الرد
        if (!response.data?.candidates?.[0]?.content?.parts?.[0]?.text) {
            throw new Error('رد غير صالح من Gemini');
        }

        const text = response.data.candidates[0].content.parts[0].text;
        
        // تنظيف الرد قبل الإرسال
        const cleanText = sanitizeInput(text);

        res.json({ result: cleanText });

    } catch (error) {
        console.error('❌ خطأ:', error.message);
        
        // أخطاء مختلفة بردود مختلفة
        if (error.code === 'ECONNABORTED') {
            return res.status(504).json({ error: 'انتهت مهلة الطلب، حاول مرة أخرى' });
        }
        
        if (error.response) {
            // خطأ من Gemini API
            const status = error.response.status;
            if (status === 429) {
                return res.status(429).json({ error: 'لقد تجاوزت الحد المسموح، حاول بعد قليل' });
            }
            if (status === 403) {
                return res.status(403).json({ error: 'المفتاح غير صالح أو محظور' });
            }
            return res.status(status).json({ 
                error: 'خطأ في Gemini API', 
                details: error.response.data 
            });
        }

        res.status(500).json({ error: 'فشل في توليد المحتوى' });
    }
});

// ==================== نقطة نهاية للتحقق من الصحة (Health Check) ====================
app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// ==================== معالجة الأخطاء العامة ====================
app.use((err, req, res, next) => {
    console.error('❌ خطأ غير متوقع:', err.stack);
    res.status(500).json({ error: 'حدث خطأ غير متوقع' });
});

// ==================== 404 ====================
app.use((req, res) => {
    res.status(404).json({ error: 'المسار غير موجود' });
});

// ==================== تشغيل السيرفر ====================
app.listen(PORT, () => {
    console.log(`✅ Backend running securely on port ${PORT}`);
    console.log(`🔒 Security features: Helmet, Rate Limiting, XSS Protection, CORS restricted`);
    console.log(`⚠️  All inputs sanitized and validated`);
});