var express = require('express');
var app = express();
const Joi = require('@hapi/joi');
var bcrypt = require('bcrypt');
var jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
dotenv.config();

var bodyParser = require('body-parser')
app.use(bodyParser.json());       // to support JSON-encoded bodies
app.use(express.json());       // to support JSON-encoded bodies
app.use(express.urlencoded({ extended: true }))

//creazione client MongoDb
const MongoClient = require('mongodb').MongoClient;
const uri = process.env.DBURI;
const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true });

var userscoll, postscoll
//collegamenti a collezioni di utenti e post
client.connect(err => { userscoll = client.db("users").collection("users"); postscoll = client.db("users").collection("posts") })

const userschema = Joi.object({ //schema utente
    nome: Joi.string().min(6).required(),
    email: Joi.string().email().required(),
    pwd: Joi.string().min(6).required()
});

const usersLoginSchema = Joi.object({   //schema info per login
    email: Joi.string().email().required(),
    pwd: Joi.string().min(6).required()
});

const postschema = Joi.object({ //schema post
    titolo: Joi.string().min(5).required(),
    contenuto: Joi.string().min(10).required(),
});

app.get('/', function (req, res) {
    res.send('Ciao!');
});


app.get('/home', autentica, async function (req, res) {

    try {
        var results = await postscoll.find({ utente : req.user.email }).toArray()   //prendi post dell'utente 

        return res.status(200).send(results)
    } catch (error) {
        res.status(401).send("errore home")
    }
})

app.post('/post', autentica, function (req, res) {

    const { error } = postschema.validate(req.body) //verifica schema del post

    if (error) {
        return res.status(400).send(error.details[0].message)
    }

    let date_ob = new Date();

    var post = {    //crea oggetto post
        utente_id : req.user.id,    //parametri id e email presi dal campo user, riempito dal middleware autentica()
        utente: req.user.email,
        titolo: req.body.titolo,
        contenuto: req.body.contenuto,
        data: date_ob.getHours() + ":" + date_ob.getMinutes()
    }

    try {
        postscoll.insertOne(post, function (err, record) { //inserisci nel db
            if (err) {
                console.log(err)
                return res.status(400).send("errore inserimento")
            }

            res.status(200).send("post inserito")
        })
    } catch (err) {
        return res.status(401).send("errore nel post :" + err)
    }

})

function autentica(req, res, next) {    //funzione middleware per autenticare utente con token
    const authHeader = req.get('authorization') //prendi token dal campo dell'header
    const token = authHeader && authHeader.split(' ')[0]    //prendi primo elemento (se più lungo)

    try {
        const verificata = jwt.verify(token, process.env.TOKENPWD)   //verifica il token
        req.user = verificata   //imposta il campo user con attributi json presenti nel token
        next()  
    } catch{
        return res.status(401).send("non autorizzato")
    }

}

app.post('/login', function (req, res) {

    var { error } = usersLoginSchema.validate(req.body) //valida richiesta con schema login

    if (error) {
        return res.status(400).send(error.details[0].message)
    }

    try {
        userscoll.findOne({ email: req.body.email }).then(function (result) {

            if (!result) {
                return res.status(400).send("utente non presente")
            }

            bcrypt.compare(req.body.pwd, result.pwd, (err, same) => {   //confronta password hashate
                
                if (!same) {
                    return res.status(400).send("password sbagliata")
                }

                const token = jwt.sign({ id: result._id, email: result.email }, process.env.TOKENPWD);   //genera token

                return res.status(200).send(token)     //tutto ok, manda il token come risposta
            })
        });

    } catch (err) {
        console.log(err)
        return res.status(400).send("errore login")
    }

})


app.post('/register', function (req, res) {

    var { error } = userschema.validate(req.body)   //valida richiesta secondo lo schema

    if (error) {
        return res.status(400).send(error.details[0].message)
    }

    var salt = bcrypt.genSaltSync(10);  //genera sale per la password
    var hash = bcrypt.hashSync(req.body.pwd, salt); //hasha la password 

    var user = {    //crea oggetto user da inserire
        nome: req.body.nome,
        email: req.body.email,
        pwd: hash
    }

    try {
        userscoll.findOne({ email: req.body.email }).then(function (result) {

            if (result) {   //se utente già presente
                return res.status(400).send("utente già presente :(")
            }

            userscoll.insertOne(user, function (err, record) {  //inserisci utente nel db
                if (err) {
                    console.log(err)
                    return res.status(400).send("errore inserimento")
                }

                res.status(200).send("registrato")
            })
        });

    } catch (err) {
        console.log(err)
        return res.status(400).send("errore inserimento")
    }

});


app.listen(3000, function () {
    console.log('app listening on port 3000!');
});