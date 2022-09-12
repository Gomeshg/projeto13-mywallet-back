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

const walletSchema = joi.object({
  type: joi.string().valid("input", "output").required(),
  value: joi.number().min(0).required(),
  description: joi.string().trim().min(3).required(),
});

const walletSchemaUpdate = joi.object({
  value: joi.number().min(0).required(),
  description: joi.string().trim().min(3).required(),
});

const tokenSchema = joi.object({
  token: joi
    .string()
    .guid({
      version: ["uuidv4", "uuidv5"],
    })
    .required(),
});

server.post("/sign-up", async (req, res) => {
  let user = req.body;

  const validationBody = signUpSchema.validate(user, { abortEarly: false });
  if (validationBody.error) {
    res
      .status(422)
      .send(validationBody.error.details.map((item) => item.message));
    return;
  }

  user = {
    name: stripHtml(validationBody.value.name).result,
    email: stripHtml(validationBody.value.email).result,
    password: bcrypt.hashSync(
      stripHtml(validationBody.value.password).result,
      10
    ),
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
        const session = {
          token: uuid(),
          userID: user._id,
          name: user.name.split(" ")[0],
        };

        try {
          await db.collection("sessions").insertOne(session);
          res.status(200).send(session);
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

server.get("/wallet", async (req, res) => {
  let auth;
  try {
    auth = {
      token: req.headers.authorization.split(" ")[1],
    };
  } catch (e) {
    res.status(400).send("Token não enviado!");
  }

  const validateToken = tokenSchema.validate(auth, { abortEarly: false });
  if (validateToken.error) {
    res
      .status(422)
      .send(validateToken.error.details.map((item) => item.message));
  }

  try {
    const session = await db
      .collection("sessions")
      .findOne({ token: validateToken.value.token });

    if (session) {
      try {
        const wallet = await db
          .collection("wallet")
          .find({ userID: new ObjectId(session.userID) })
          .toArray();
        res.status(200).send(wallet);
      } catch (e) {
        res.status(500).send(e.message);
      }
    } else {
      res.sendStatus(403);
    }
  } catch (e) {
    res.status(500).send(e.message);
  }
});

server.get("/oneWallet/:id", async (req, res) => {
  const { id } = req.params;
  let auth;
  try {
    auth = {
      token: req.headers.authorization.split(" ")[1],
    };
  } catch (e) {
    res.status(400).send("Token não enviado!");
  }

  const validateToken = tokenSchema.validate(auth, { abortEarly: false });
  if (validateToken.error) {
    res
      .status(422)
      .send(validateToken.error.details.map((item) => item.message));
  }

  try {
    const session = await db
      .collection("sessions")
      .findOne({ token: validateToken.value.token });

    if (session) {
      try {
        const oneWallet = await db
          .collection("wallet")
          .findOne({ _id: new ObjectId(id) });

        res.status(200).send(oneWallet);
      } catch (e) {
        res.status(500).send(e.message);
      }
    } else {
      res.sendStatus(403);
    }
  } catch (e) {
    res.status(500).send(e.message);
  }
});

server.post("/wallet", async (req, res) => {
  const body = req.body;
  let auth;
  try {
    auth = {
      token: req.headers.authorization.split(" ")[1],
    };
  } catch (e) {
    res.status(400).send("Token não enviado!");
  }

  const validateToken = tokenSchema.validate(auth, { abortEarly: false });
  if (validateToken.error) {
    res
      .status(422)
      .send(validateToken.error.details.map((item) => item.message));
  }

  const validationBody = walletSchema.validate(body, { abortEarly: false });
  if (validationBody.error) {
    res
      .status(422)
      .send(validationBody.error.details.map((item) => item.message));
    return;
  }

  try {
    const session = await db
      .collection("sessions")
      .findOne({ token: validateToken.value.token });

    if (session) {
      const data = {
        type: stripHtml(validationBody.value.type).result,
        description: stripHtml(validationBody.value.description).result,
        value: Number(stripHtml(validationBody.value.value.toString()).result),
        userID: session.userID,
        date: dayjs().format("D/MM"),
      };

      try {
        await db.collection("wallet").insertOne(data);
        res.sendStatus(201);
      } catch (e) {
        res.status(500).send(e.message);
      }
    } else {
      res.sendStatus(403);
    }
  } catch (e) {
    res.status(500).send(e.message);
  }
});

server.put("/wallet/:id", async (req, res) => {
  const { id } = req.params;
  const body = req.body;
  let auth;
  try {
    auth = {
      token: req.headers.authorization.split(" ")[1],
    };
  } catch (e) {
    res.status(400).send("Token não enviado!");
  }

  const validateToken = tokenSchema.validate(auth, { abortEarly: false });
  if (validateToken.error) {
    res
      .status(422)
      .send(validateToken.error.details.map((item) => item.message));
  }

  const validationBody = walletSchemaUpdate.validate(body, {
    abortEarly: false,
  });
  if (validationBody.error) {
    res
      .status(422)
      .send(validationBody.error.details.map((item) => item.message));
    return;
  }

  try {
    const session = await db
      .collection("sessions")
      .findOne({ token: validateToken.value.token });

    if (session) {
      const walletDataForUpdate = await db
        .collection("wallet")
        .findOne({ _id: new ObjectId(id) });

      if (walletDataForUpdate) {
        try {
          const newData = {
            description: stripHtml(validationBody.value.description).result,
            value: Number(
              stripHtml(validationBody.value.value.toString()).result
            ),
          };

          await db
            .collection("wallet")
            .updateOne(
              { _id: new ObjectId(walletDataForUpdate._id) },
              { $set: newData }
            );
          res.sendStatus(200);
        } catch (e) {
          res.status(500).send(e.message);
        }
      } else {
        res.sendStatus(404);
      }
    } else {
      res.sendStatus(403);
    }
  } catch (e) {
    res.status(500).send(e.message);
  }
});

server.delete("/wallet/:id", async (req, res) => {
  let auth;
  const { id } = req.params;

  try {
    auth = {
      token: req.headers.authorization.split(" ")[1],
    };
  } catch (e) {
    res.status(400).send(e.message);
  }

  const validateToken = tokenSchema.validate(auth, { abortEarly: false });
  if (validateToken.error) {
    res
      .status(422)
      .send(validateToken.error.details.map((item) => item.message));
  }

  try {
    await db.collection("wallet").deleteOne({ _id: new ObjectId(id) });
    res.sendStatus(200);
  } catch (e) {
    res.status(500).send(e.message);
  }
});

server.delete("/logout", async (req, res) => {
  let auth;
  try {
    auth = {
      token: req.headers.authorization.split(" ")[1],
    };
  } catch (e) {
    res.status(400).send(e.message);
  }

  const validateToken = tokenSchema.validate(auth, { abortEarly: false });
  if (validateToken.error) {
    res
      .status(422)
      .send(validateToken.error.details.map((item) => item.message));
  }
  try {
    const session = await db
      .collection("sessions")
      .findOne({ token: validateToken.value.token });

    if (session) {
      try {
        await db
          .collection("sessions")
          .deleteOne({ token: validateToken.value.token });
        res.sendStatus(200);
      } catch (e) {
        res.status(500).send(e);
      }
    } else {
      res.sendStatus(404);
    }
  } catch (e) {
    res.status(500).send(e);
  }
});

server.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});

// server.use("/", userController);
