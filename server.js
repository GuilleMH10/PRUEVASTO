const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const db = require("./db");
const path = require("path");
const nodemailer = require("nodemailer");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

app.get("/", (req,res)=>{
res.sendFile(path.join(__dirname,"index 2.html"));
});



const SECRET = process.env.SECRET;
const crypto = require("crypto");
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL,
    pass: process.env.PASS
  }
}); 

/* ===== REGISTRO ===== */
app.post("/register", async (req,res)=>{
    const {email,password}=req.body;

    if(!email || !password || password.length<6){
return res.status(400).json({msg:"Datos inválidos"});
}


    const hash = await bcrypt.hash(password,10);

    db.run("INSERT INTO users(email,password) VALUES(?,?)",
    [email,hash],
    function(err){
        if(err) return res.status(500).json({msg:"Usuario existente"});
        res.status(201).json({msg:"Usuario creado"});
    });
});

/*recuperar*/
app.post("/forgot-password", (req,res)=>{

const {email} = req.body;

db.get("SELECT * FROM users WHERE email=?", [email], (err,user)=>{

if(!user){
return res.status(404).json({msg:"Usuario no encontrado"});
}

const token = crypto.randomBytes(32).toString("hex");
const expires = Date.now() + (1000 * 60 * 10);

db.run(
"INSERT INTO password_resets(email,token,expires) VALUES(?,?,?)",
[email,token,expires]
);

const link = `http://localhost:3000/reset.html?token=${token}`;

const mailOptions = {
from: "EcoStock <floreschris0906@gmail.com>",
to: email,
subject: "Recuperación de contraseña - EcoStock",
html: `
<h2>Recuperar contraseña</h2>
<p>Haz clic en el siguiente enlace para restablecer tu contraseña:</p>
<a href="${link}">${link}</a>
<p>Este enlace expira en 10 minutos.</p>
`
};

transporter.sendMail(mailOptions, (error,info)=>{
if(error){
console.log(error);
return res.status(500).json({msg:"Error enviando correo"});
}else{
res.json({msg:"Correo de recuperación enviado"});
}
});

});

});

/*cont*/
app.post("/reset-password", async (req,res)=>{

const {token,password} = req.body;

db.get(
"SELECT * FROM password_resets WHERE token=?",
[token],
async (err,reset)=>{

if(!reset) return res.status(400).json({msg:"Token inválido"});

if(Date.now() > reset.expires){
return res.status(400).json({msg:"Token expirado"});
}

const hash = await bcrypt.hash(password,10);

db.run(
"UPDATE users SET password=? WHERE email=?",
[hash, reset.email]
);

res.json({msg:"Contraseña actualizada"});
});

});

/* ===== LOGIN ===== */
app.post("/login",(req,res)=>{
    const {email,password}=req.body;

    db.get("SELECT * FROM users WHERE email=?",[email], async (err,user)=>{
        if(!user) return res.status(404).json({msg:"Usuario no encontrado"});

        const valid = await bcrypt.compare(password,user.password);
        if(!valid) return res.status(401).json({msg:"Contraseña incorrecta"});

        const token = jwt.sign({id:user.id},SECRET,{expiresIn:"1h"});
        res.json({token});
    });
});

/* ===== RUTA PROTEGIDA ===== */
function verifyToken(req,res,next){
const token=req.headers["authorization"];
if(!token) return res.status(403).json({msg:"Acceso denegado"});

jwt.verify(token,SECRET,(err,data)=>{
if(err) return res.status(401).json({msg:"Token expirado"});
req.user=data;
next();
});
}


app.get("/protected",verifyToken,(req,res)=>{
    res.json({msg:"Ruta protegida OK"});
});

app.listen(3000,()=>console.log("Servidor corriendo en puerto 3000"));

app.post("/products", verifyToken, (req,res)=>{

const {name,date,status}=req.body;
const user_id=req.user.id;

db.run(
"INSERT INTO products(name,date,status,user_id) VALUES(?,?,?,?)",
[name,date,status,user_id],
function(err){
if(err) return res.status(500).json({msg:"Error guardando"});
res.json({msg:"Producto guardado"});
}
);

});

app.get("/products", verifyToken, (req,res)=>{

db.all(
"SELECT * FROM products WHERE user_id=?",
[req.user.id],
(err,rows)=>{
if(err) return res.status(500).json({msg:"Error"});
res.json(rows);
});

});

app.delete("/products/:id", verifyToken, (req,res)=>{

db.run(
"DELETE FROM products WHERE id=?",
[req.params.id],
function(err){
if(err) return res.status(500).json({msg:"Error"});
res.json({msg:"Eliminado"});
});

});
