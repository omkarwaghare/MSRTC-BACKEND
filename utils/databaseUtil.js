// External Module
const mongodb = require('mongodb')

// .env File
require('dotenv').config();

const MongoClient = mongodb.MongoClient;
const MongoURI = process.env.MONGOURI;

let _db

const mongoConnect = (callback) => {
    MongoClient.connect(MongoURI).then(client => {
        _db = client.db('msrtc');
        callback();
    }).catch(err => {
        console.error('Error while connecting to the database');
    })
}

const getDb = () => {
    if (!_db) {
        throw new Error('MongoDB not connected');
    }

    return _db;
}

exports.mongoConnect = mongoConnect;
exports.getDb = getDb