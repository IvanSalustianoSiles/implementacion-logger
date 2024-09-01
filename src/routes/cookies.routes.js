import { Router } from "express";
import config from "../config.js";

const router = Router();

router.get("/getcookies", async (req, res) => {
  try {
    res.status(200).send({ origin: config.SERVER, payload: req.cookies });
  } catch (error) {
    res.status(200).send({
      origin: config.SERVER,
      payload: null,
      error: "Error de cookies",
    });
  }
});
router.get("/setcookie", async (req, res) => {
  try {
    res.cookie("mi-cookie", "Alta galletita", { maxAge: 28800 });
    res.status(200).send({ origin: config.SERVER, payload: "Cookie" });
  } catch (error) {
    res.status(200).send({
      origin: config.SERVER,
      payload: null,
      error: "Error de cookies",
    });
  }
});
router.get("/deletecookie", async (req, res) => {
  try {
    res.clearCookie("mi-cookie");
    res
      .status(200)
      .send({ origin: config.SERVER, payload: "Cookie eliminada." });
  } catch (error) {
    res.status(200).send({
      origin: config.SERVER,
      payload: null,
      error: "Error de cookies",
    });
  }
});
router.get("/session", async (req, res) => {
  try {
    if (req.session.counter) {
      req.session.counter++;
      res.status(200).send({
        origin: config.SERVER,
        payload: `${req.session.counter} visualizaciones!`,
      });
    } else {
      req.session.counter = 1;
      res.status(200).send({
        origin: config.SERVER,
        payload: `Bienvenido! Eres la primera visualización.`,
      });
    }
  } catch {
    res.send({
      origin: config.SERVER,
      payload: null,
      error: "Error de sessions.",
    });
  }
});
router.get("/login", async (req, res) => {
  try {
    const user = {
      mail: "silesivansalustiano@gmail.com",
      password: "Coki-2011",
    }; // Esto vendría de un req.body
    const dbMail = "silesiansalustiano@gmail.com";
    const dbPassword = "Coki-2011";
    if ((user.mail === dbMail) & (user.password === dbPassword)) {
      req.session.user = { ...user, role: "admin" };
      res.status(200).send("Válido. Ingresando...");
    } else {
      res.status(401).send("Datos no encontrados.");
    }
  } catch {
    res.send("Session error.");
  }
});
router.get("/private", async (req, res) => {
  try {
    console.log(req.session);
    if (req.session.user.role == "admin") {
      res.status(200).send("Bienvenido, admin.");
    } else {
      res.status(200).send("ERROR: No tienes permisos.");
    }
  } catch {
    res.send("Session error.");
  }
});
export default router;
