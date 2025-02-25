const express = require('express');
const router = express.Router();
const userController = require('../controller/user.controller');
const isRole = require("../middleware/authMiddleware");
const authenticate = require("../middleware/authenticate");



//sprawdzenie emial czy istnieje w bazie danych 
router.post("/check-email", userController.checkEmailExistence);

//towrzenie konta z rola BigBoss
router.post("/newAccounted", userController.createBigBoss);

//dodawanie nowego uzytkownika
router.post('/users', authenticate, isRole(["Admin", "BigBoss"]), userController.createUser);

//generowanie tokenu do restu hasla
router.post("/reset-password-token", userController.resetPasswordToken);

//resetowanie hasla
router.post("/reset-password", userController.resetPassword);

//dodanie nowego miejsca pracy 
router.post("/newRecords", authenticate, userController.addPlaceWork);

//logowanie
router.post("/login", userController.loginUser);

//sprawdzanie sesji
router.get("/check-session", authenticate, userController.checkSession);

//odswierzanie sesji automatyczne 
router.get("/refresh-token", userController.refreshUser);

// wylogowanie
router.post('/logout', userController.logoutUser);

//zmiana roli uzutkownika
router.post("/change-role/:userId", authenticate, isRole(["Admin", "BigBoss"]), userController.changeUserRole);

//pobieranie i wyswietlanie konkretnego uzytkownika
router.get("/user-info/:userId", authenticate, userController.getUserById);

//wyswietlanie uzytkowników o konkretnej roli np Admin
router.get("/users-role", authenticate, isRole(["Admin", "BigBoss", "Boss"]), userController.getUsersByRole);

//edycja użytkownika
router.put('/users/:userId', authenticate, isRole(["Admin", "BigBoss"]), userController.updateUser);

//banowanie obanowywanie użytkownika
router.patch("/user-toggle-status/:userId", authenticate, isRole(["Admin", "BigBoss"]), userController.toggleUserStatus);

//usuwanie pierwszegoLogowania 
router.patch('/firstLoginRemove/:userId', userController.toggleFirstLogin);

//usuwanie użytkownika
router.delete('/users/:userId', authenticate, isRole(["Admin", "BigBoss"]), userController.deleteUser);

// Trasa do weryfikacji użytkownika
router.get('/verify', userController.verifyUser);

//aktualizacja numeru telefonu 
router.patch("/update-phone/:userId", authenticate, userController.updatePhoneNumber);


module.exports = router;
