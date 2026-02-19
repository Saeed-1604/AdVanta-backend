const express = require('express');
const cors = require('cors');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// CORS مفتوح للجميع (للحل النهائي)
app.use(cors({
    origin: '*',
    methods: ['POST', 'GET'],
    allowedHeaders: ['Content-Type']
}));

app.use(express.json());

app.post('/api/generate', async (req, res) => {
    try {
        const { prompt } = req.body;

        if (!prompt) {
            return res.status(400).json({ error: 'Prompt is required' });
        }

        const response = await axios.post(
            `https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent?key=${process.env.GEMINI_API_KEY}`,
            {
                contents: [{
                    parts: [{ text: prompt }]
                }]
            }
        );

        const text = response.data.candidates[0].content.parts[0].text;
        res.json({ result: text });

    } catch (error) {
        console.error('Error:', error.message);
        if (error.response) {
            return res.status(500).json({ 
                error: 'Gemini API error', 
                details: error.response.data 
            });
        }
        res.status(500).json({ error: 'Failed to generate content' });
    }
});

app.get('/', (req, res) => {
    res.send('✅ Advanta Backend is running. Use POST /api/generate');
});

app.listen(PORT, () => {
    console.log(`✅ Backend running on port ${PORT}`);
});