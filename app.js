// Core Modules
const path = require('path')

// External Modules
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const multer = require('multer')

// Local Modules 
const userRouter = require('./routes/userRouter');
const rootDir = require("./utils/pathUtil");
const { mongoConnect } = require('./utils/databaseUtil');
const hostRouter = require('./routes/hostRouter');
const collegeRouter = require('./routes/collegeRouter');


require('dotenv').config()

const app = express();

app.set('view engine', 'ejs');
app.set('views', 'views');


const PORT = process.env.PORT;

//! Publicly accessible public folder
app.use(express.static(path.join(rootDir, 'public')))
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.json({ limit: '10mb' }));
app.use(cors());

app.get('/', (req, res, next) => {
    res.render('welcome', { pageTitle: "Welcome" })
})

app.use('/host', hostRouter)
app.use('/college', collegeRouter)
app.use('/user', userRouter);

app.use((req, res, next) => {
    res.status(404).send('<h1 style="text-align:center; margin-top: 30px;">Sorry, We could not resolve your request</h1>')
})

mongoConnect(() => {
    app.listen(PORT, () => {
        console.log(`The server has deployed successfully http://localhost:${PORT}`)
    })
})