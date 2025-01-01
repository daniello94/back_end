const mongoose = require("mongoose");
const User = require("./Users"); 

const adminSchema = new mongoose.Schema({

  globalPermissions: [{ type: String }]
});

const AdminSchema = User.discriminator("Admin", adminSchema);
 
module.exports = AdminSchema;