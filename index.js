import express, { json } from "express";
import cors from "cors";
import dotenv from "dotenv";
import dayjs from "dayjs";
import joi from "joi";
import { stripHtml } from "string-strip-html";
import { MongoClient, ObjectId } from "mongodb";
import bcrypt from "bcrypt";
import { v4 as uuid } from "uuid";

// import userController from "./user/userController.js";

const server = express();

server.use(cors());
server.use(json());
dotenv.config();
const PORT = process.env.PORT;
const DB_HOST = process.env.MONGO_URI;
const mongo = new MongoClient(DB_HOST);
let db;

mongo.connect().then(() => {
  db = mongo.db("MyWallet");
  console.log("Banco de dados conectado com sucesso!");
});

const signUpSchema = joi.object({
  name: joi.string().trim().min(1).max(20).required(),
  email: joi.string().email({ minDomainSegments: 2 }).required(),
  password: joi
    .string()
    .pattern(new RegExp("^[a-zA-Z0-9!@#$%&*]{3,30}$"))
    .required(),
  repeat_password: joi.ref("password"),
});

const loginSchema = joi.object({
  email: joi.string().email({ minDomainSegments: 2 }).required(),
  password: joi
    .string()
    .pattern(new RegExp("^[a-zA-Z0-9!@#$%&*]{3,30}$"))
    .required(),
});

// joi.string.guid();

server.post("/sign-up", async (req, res) => {
  let user = req.body;

  const validation = signUpSchema.validate(user, { abortEarly: false });
  if (validation.error) {
    res.status(422).send(validation.error.details.map((item) => item.message));
    return;
  }

  user = {
    name: stripHtml(validation.value.name).result,
    email: stripHtml(validation.value.email).result,
    password: bcrypt.hashSync(stripHtml(validation.value.password).result, 10),
  };

  try {
    const isThereUser = await db
      .collection("users")
      .findOne({ email: user.email });
    if (!isThereUser) {
      await db.collection("users").insertOne(user);
      res.sendStatus(200);
    } else {
      res.status(409).send("O usuário já existe!");
    }
  } catch (e) {
    res.status(500).send(e.message);
  }
});

server.post("/sign-in", async (req, res) => {
  let body = req.body;

  const validation = loginSchema.validate(body, { abortEarly: false });
  if (validation.error) {
    res.status(422).send(validation.error.details.map((item) => item.message));
    return;
  }

  body = {
    email: stripHtml(validation.value.email).result,
    password: stripHtml(validation.value.password).result,
  };

  const { email, password } = body;
  try {
    const user = await db.collection("users").findOne({ email: email });

    if (user) {
      if (bcrypt.compareSync(password, user.password)) {
        // CRIAR O TOKEN E INSERIR O USUÁRIO EM SESSION

        const session = {
          token: uuid(),
          userID: user._id,
          name: user.name.split(" ")[0],
        };

        try {
          await db.collection("sessions").insertOne(session);
          res.status(200).send({ token: session.token });
        } catch (e) {
          res.status(500).send(e.message);
        }
      } else {
        res.status(403).send("Senha inválida!");
      }
    } else {
      res.status(404).send("Usuário não encontrado!");
    }
  } catch (e) {
    res.status(500).send(e.message);
  }
});

server.put("/", async (req, res) => {
  res.sendStatus(200);
});

server.delete("/", async (req, res) => {
  res.sendStatus(200);
});

server.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});

// server.use("/", userController);
