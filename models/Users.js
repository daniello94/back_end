const mongoose = require('mongoose');
const validator = require('validator');
const uniqueValidator = require('mongoose-unique-validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { calculateMyHours, calculateMyHoursOnUpdate } = require('../middleware/userMiddleware');


mongoose.connect(`mongodb://${process.env.DB_HOST}/${process.env.DB_NAME}`)
  .then(() => {
    console.log('Połączono z bazą danych MongoDB');
  })
  .catch((error) => {
    console.error('Błąd połączenia z MongoDB:', error);
  });
const phoneNumberSchema = new mongoose.Schema({
  country: {
    type: String,
    validate: {
      validator: function (v) {
        // Sprawdzenie, czy kraj jest jednym z dozwolonych 
        const allowedCountries = [
          'pl', 'PL',
          'be', 'BE',
          'de', 'DE',
          'en', 'EN',
          'fr', 'FR',
          'uk', 'UK',
          'ar', 'AR',
          'ro', 'RO',
          'nl', 'NL'
        ];
        return allowedCountries.includes(v);
      },
      message: props => `${props.value} nie jest dozwolonym krajem!`
    }
  },
  code: {
    type: String,
    required: false,

  },
  number: {
    type: String
  }
});
// Dodanie middleware do ustawienia kodu kierunkowego na podstawie kraju 
phoneNumberSchema.pre('save', function (next) {
  const countryCodeMap = {
    'pl': '+48',
    'PL': '+48',
    'be': '+32',
    'BE': '+32',
    'de': '+49',
    'DE': '+49',
    'en': '+44',
    'EN': '+44',
    'nl': '+31',
    "NL": '+31',
    'fr': '+33',
    'FR': '+33',
    'uk': '+380',
    'UK': '+380',
    'ar': '+966',
    "AR": '+966',
    "ro": "+40",
    "RO": '+40'
  };
  if (countryCodeMap[this.country]) {
    this.code = countryCodeMap[this.country];

  }
  next();
});
const userSchema = new mongoose.Schema({
  userName: {
    type: String,
    required: true
  },
  userLastName: {
    type: String,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    validate: [validator.isEmail, 'Nieprawidłowy adres email']
  },
  firstLogin: {
    type: Boolean,
    default: true
  },
  phoneNumber: phoneNumberSchema,
  password: {
    type: String,
    required: true
  },
  price: {
    type: Number
  },
  address: {
    city: {
      type: String
    },
    street: {
      type: String
    },
    number: {
      type: String
    },
    numberBox: {
      type: String
    },
    zipCode: {
      type: String
    },
    placePost: {
      type: String
    }
  },
  myHours: [{
    year: {
      type: Number,
      required: true
    },
    month: {
      type: Number,
      required: true,
      min: 1,
      max: 12
    },
    hours: {
      type: Number,
      default: 0
    }
  }],
  placeWork: [{
    year: {
      type: Number,
      required: true
    },
    month: {
      type: Number,
      required: true,
      min: 1,
      max: 12
    },
    day: {
      type: Number,
      required: true,
      min: 1,
      max: 31
    },
    projects: [{
      nameProject: {
        type: String,
        required: true
      },
      time: {
        type: Number,
        required: true
      },
      date: {
        type: Date,
        default: Date.now
      }
    }]
  }],
  preferredLanguage: {
    type: String,
    enum: ["en", "pl", "nl", "fr", "de", "ar", "ro", "uk"],
    default: "en"
  },
  statusUser: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  tokenResetPassword: String,
  resetPasswordExpires: Date,
  verificationToken: String,
  tokenUsedAt: {
    type: Date,
  },
  isVerified: Boolean,
});
userSchema.plugin(uniqueValidator);
userSchema.pre('save', calculateMyHours);
userSchema.pre('findOneAndUpdate', calculateMyHoursOnUpdate);

userSchema.pre('save', function (next) {
  let user = this;

  if (!user.isModified("password")) return next();

  const saltRounds = Number(process.env.SALT_ROUNDS) || 10;

  bcrypt.genSalt(saltRounds, function (err, salt) {
    if (err) return next(err);
    bcrypt.hash(user.password, salt, function (err, hash) {
      if (err) return next(err);
      user.password = hash;
      next();
    });
  });
});

userSchema.methods.generateAuthToken = function () {
  const token = jwt.sign(
    { _id: this._id, role: this.__t },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
  return token;
};

userSchema.methods.generateResetPasswordToken = function () {
  const payload = {
    userId: this._id
  };
  const options = {
    expiresIn: "1d"
  };
  return jwt.sign(payload, process.env.JWT_SECRET, options);
};
const User = mongoose.model("User", userSchema);
module.exports = User;
