require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 5173;

const userRoutes = require("./api/user.api");
const companyRoutes = require("./api/company.api");
const projectRoutes = require("./api/project.api");
const productRoutes = require("./api/product.api");
const orderRoutes = require("./api/order.api");

const corsOptions = {
    origin: process.env.CLIENT_ORIGIN, 
    credentials: true, 
    optionsSuccessStatus: 200 
};

app.use(helmet()); 
app.use(express.json()); 
app.use(cookieParser()); 
app.use(cors(corsOptions)); 


const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100, 
    message: 'Za dużo żądań z tego adresu IP, spróbuj ponownie później.'
});
app.use(limiter);

app.use('/', userRoutes);
app.use("/company", companyRoutes);
app.use("/project", projectRoutes);
app.use("/", productRoutes);
app.use("/", orderRoutes);


app.get('/', (req, res) => {
    res.status(200).json({ message: "Task Order API is running" });
});

app.use((req, res, next) => {
    res.status(404).json({ error: 'Trasa nie została znaleziona' });
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Wewnętrzny błąd serwera' });
});

app.listen(PORT, () => {
    console.log(`Server serwisu TaskOrder na porcie ${PORT} działa poprawnie`);
});
