
const express = require('express');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const app = express.Router();

app.get("/", async (req, res) => {
    const filters = {};
  
    if (req.query.email) {
      filters.email = {
        contains: req.query.email,
      };
    }
  
    if (req.query.firstName) {
      filters.firstName = {
        contains: req.query.firstName,
      };
    }
  
    if (req.query.lastName) {
      filters.lastName = {
        contains: req.query.lastName,
      };
    }
  
    if (req.query.role) {
      filters.role = {
        equals: req.query.role,
      };
    }
  
    if (req.query.createdAt) {
      filters.createdAt = {
        equals: new Date(req.query.createdAt),
      };
    }
  
    if (req.query.updatedAt) {
      filters.updatedAt = {
        equals: new Date(req.query.updatedAt),
      };
    }
  
    const users = await prisma.user.findMany({ where: filters });
    res.json(users);
  });
  
  
  // Create a new user
  app.post("/", async (req, res) => {
    const newUser = await prisma.user.create({
      data: req.body,
    });
    res.json(newUser); });
  
  // Update user by ID
  app.put("/:id", async (req, res) => {
    const updatedUser = await prisma.user.update({
      where: {
        id: parseInt(req.params.id),
      },
      data: req.body,
    });
    res.json(updatedUser);
  });
  
  // Delete user by ID
  app.delete("/:id", async (req, res) => {
    const deletedUser = await prisma.user.delete({
      where: {
        id: parseInt(req.params.id),
      },
    });
    res.json(deletedUser);
  });
  module.exports = app;
