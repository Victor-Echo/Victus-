# Victus-
// Project Structure
/*
victus-payment-app/
├── frontend/
│   ├── public/
│   └── src/
│       ├── components/
│       ├── screens/
│       ├── services/
│       ├── utils/
│       ├── App.js
│       └── index.js
├── backend/
│   ├── config/
│   ├── controllers/
│   ├── middleware/
│   ├── models/
│   ├── routes/
│   └── server.js
└── package.json
*/

// --------------------------------------
// FRONTEND
// --------------------------------------

// frontend/src/App.js
import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';

// Screens
import LoginScreen from './screens/LoginScreen';
import RegisterScreen from './screens/RegisterScreen';
import HomeScreen from './screens/HomeScreen';
import ScanScreen from './screens/ScanScreen';
import HistoryScreen from './screens/HistoryScreen';
import ProfileScreen from './screens/ProfileScreen';

// Protected route component
const ProtectedRoute = ({ children }) => {
  const { isAuthenticated } = useAuth();
  return isAuthenticated ? children : <Navigate to="/login" />;
};

function App() {
  return (
    <AuthProvider>
      <Router>
        <Routes>
          <Route path="/login" element={<LoginScreen />} />
          <Route path="/register" element={<RegisterScreen />} />
          <Route 
            path="/" 
            element={
              <ProtectedRoute>
                <HomeScreen />
              </ProtectedRoute>
            } 
          />
          <Route 
            path="/scan" 
            element={
              <ProtectedRoute>
                <ScanScreen />
              </ProtectedRoute>
            } 
          />
          <Route 
            path="/history" 
            element={
              <ProtectedRoute>
                <HistoryScreen />
              </ProtectedRoute>
            } 
          />
          <Route 
            path="/profile" 
            element={
              <ProtectedRoute>
                <ProfileScreen />
              </ProtectedRoute>
            } 
          />
        </Routes>
      </Router>
    </AuthProvider>
  );
}

export default App;

// frontend/src/context/AuthContext.js
import React, { createContext, useState, useContext, useEffect } from 'react';
import { loginUser, verifyToken } from '../services/authService';

const AuthContext = createContext();

export const useAuth = () => useContext(AuthContext);

export const AuthProvider = ({ children }) => {
  const [currentUser, setCurrentUser] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const checkAuth = async () => {
      const token = localStorage.getItem('token');
      if (token) {
        try {
          const userData = await verifyToken(token);
          setCurrentUser(userData);
          setIsAuthenticated(true);
        } catch (error) {
          localStorage.removeItem('token');
        }
      }
      setLoading(false);
    };
    
    checkAuth();
  }, []);

  const login = async (phone, password) => {
    try {
      const { user, token } = await loginUser(phone, password);
      localStorage.setItem('token', token);
      setCurrentUser(user);
      setIsAuthenticated(true);
      return true;
    } catch (error) {
      return false;
    }
  };

  const logout = () => {
    localStorage.removeItem('token');
    setCurrentUser(null);
    setIsAuthenticated(false);
  };

  const value = {
    currentUser,
    isAuthenticated,
    login,
    logout,
    loading
  };

  return (
    <AuthContext.Provider value={value}>
      {!loading && children}
    </AuthContext.Provider>
  );
};

// frontend/src/services/authService.js
import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

export const loginUser = async (phone, password) => {
  const response = await axios.post(`${API_URL}/auth/login`, { phone, password });
  return response.data;
};

export const registerUser = async (userData) => {
  const response = await axios.post(`${API_URL}/auth/register`, userData);
  return response.data;
};

export const verifyToken = async (token) => {
  const response = await axios.get(`${API_URL}/auth/verify`, {
    headers: {
      Authorization: `Bearer ${token}`
    }
  });
  return response.data;
};

// frontend/src/services/paymentService.js
import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

// Get the auth token
const getToken = () => localStorage.getItem('token');

// Create axios instance with auth header
const createAuthHeader = () => ({
  headers: {
    Authorization: `Bearer ${getToken()}`
  }
});

export const getWalletBalance = async () => {
  const response = await axios.get(`${API_URL}/wallet/balance`, createAuthHeader());
  return response.data;
};

export const getTransactionHistory = async () => {
  const response = await axios.get(`${API_URL}/transactions`, createAuthHeader());
  return response.data;
};

export const sendMoney = async (recipient, amount, description) => {
  const response = await axios.post(
    `${API_URL}/transactions/send`,
    { recipient, amount, description },
    createAuthHeader()
  );
  return response.data;
};

export const requestMoney = async (from, amount, description) => {
  const response = await axios.post(
    `${API_URL}/transactions/request`,
    { from, amount, description },
    createAuthHeader()
  );
  return response.data;
};

export const processQrPayment = async (qrData) => {
  const response = await axios.post(
    `${API_URL}/transactions/qr-payment`,
    { qrData },
    createAuthHeader()
  );
  return response.data;
};

export const generateQrCode = async (amount, description) => {
  const response = await axios.post(
    `${API_URL}/transactions/generate-qr`,
    { amount, description },
    createAuthHeader()
  );
  return response.data;
};

// frontend/src/components/NavBar.js
import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Home, Camera, Clock, User } from 'lucide-react';

const NavBar = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const currentPath = location.pathname;

  const NavButton = ({ icon, label, path }) => {
    const active = currentPath === path;
    return (
      <button 
        className={`flex flex-col items-center justify-center p-2 w-full ${active ? 'text-blue-600' : 'text-gray-500'}`}
        onClick={() => navigate(path)}
      >
        <div>{icon}</div>
        <span className="text-xs mt-1">{label}</span>
      </button>
    );
  };

  return (
    <div className="bg-white border-t border-gray-200 fixed bottom-0 w-full">
      <div className="flex justify-around">
        <NavButton icon={<Home size={20} />} label="Home" path="/" />
        <NavButton icon={<Camera size={20} />} label="Scan" path="/scan" />
        <NavButton icon={<Clock size={20} />} label="History" path="/history" />
        <NavButton icon={<User size={20} />} label="Profile" path="/profile" />
      </div>
    </div>
  );
};

export default NavBar;

// frontend/src/screens/HomeScreen.js
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { CreditCard, Send, Download, ArrowRight } from 'lucide-react';
import NavBar from '../components/NavBar';
import { getWalletBalance, getTransactionHistory } from '../services/paymentService';
import { formatCurrency } from '../utils/formatters';
import SendMoneyModal from '../components/SendMoneyModal';
import ReceiveMoneyModal from '../components/ReceiveMoneyModal';

const HomeScreen = () => {
  const navigate = useNavigate();
  const [balance, setBalance] = useState(0);
  const [recentTransactions, setRecentTransactions] = useState([]);
  const [showSendModal, setShowSendModal] = useState(false);
  const [showReceiveModal, setShowReceiveModal] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const balanceData = await getWalletBalance();
        setBalance(balanceData.balance);
        
        const transactionsData = await getTransactionHistory();
        setRecentTransactions(transactionsData.slice(0, 3)); // Get only 3 most recent
      } catch (error) {
        console.error("Failed to fetch wallet data:", error);
      } finally {
        setLoading(false);
      }
    };
    
    fetchData();
  }, []);

  const QuickAction = ({ icon, label, onClick }) => {
    return (
      <div 
        className="bg-white p-2 rounded-lg shadow-sm flex flex-col items-center justify-center cursor-pointer"
        onClick={onClick}
      >
        <div className="w-10 h-10 rounded-full bg-blue-100 flex items-center justify-center mb-1">
          {icon}
        </div>
        <span className="text-xs">{label}</span>
      </div>
    );
  };

  const Transaction = ({ transaction }) => {
    const { type, amount, recipient, sender, description, createdAt } = transaction;
    const isDebit = type === 'DEBIT';
    
    return (
      <div className="p-3 border-b border-gray-100 flex justify-between items-center">
        <div className="flex items-center">
          <div className={`w-10 h-10 rounded-full ${isDebit ? 'bg-red-100' : 'bg-green-100'} flex items-center justify-center mr-3`}>
            {isDebit ? '-' : '+'}
          </div>
          <div>
            <p className="font-medium">{isDebit ? recipient.name : sender.name}</p>
            <p className="text-xs text-gray-500">{new Date(createdAt).toLocaleDateString()}</p>
          </div>
        </div>
        <p className={isDebit ? 'text-red-600' : 'text-green-600'}>
          {isDebit ? '-' : '+'}{formatCurrency(amount)}
        </p>
      </div>
    );
  };

  if (loading) {
    return <div className="flex items-center justify-center h-screen">Loading...</div>;
  }

  return (
    <div className="flex flex-col h-screen bg-gray-100">
      {/* Header */}
      <div className="bg-blue-600 p-4 text-white">
        <div className="flex items-center justify-between">
          <h1 className="text-xl font-bold">Victus Pay</h1>
          <div className="flex items-center space-x-2">
            <div className="bg-blue-500 p-2 rounded-full">
              <CreditCard size={20} />
            </div>
          </div>
        </div>
      </div>
      
      {/* Main Content */}
      <div className="flex-1 overflow-y-auto pb-16 p-4">
        <div className="bg-white rounded-xl shadow-md p-4 mb-4">
          <h2 className="text-lg font-semibold mb-2">Your Balance</h2>
          <p className="text-3xl font-bold text-blue-600">{formatCurrency(balance)}</p>
          <div className="flex mt-4 space-x-2">
            <button 
              className="bg-blue-600 text-white py-2 px-4 rounded-lg flex-1 text-center"
              onClick={() => setShowSendModal(true)}
            >
              Send Money
            </button>
            <button 
              className="bg-green-600 text-white py-2 px-4 rounded-lg flex-1 text-center"
              onClick={() => setShowReceiveModal(true)}
            >
              Receive
            </button>
          </div>
        </div>
        
        <h3 className="font-medium mb-2">Quick Actions</h3>
        <div className="grid grid-cols-3 gap-2 mb-4">
          <QuickAction 
            icon={<Send size={18} className="text-blue-500" />} 
            label="Send" 
            onClick={() => setShowSendModal(true)} 
          />
          <QuickAction 
            icon={<Download size={18} className="text-green-500" />} 
            label="Receive" 
            onClick={() => setShowReceiveModal(true)} 
          />
          <QuickAction 
            icon={<Clock size={18} className="text-orange-500" />} 
            label="History" 
            onClick={() => navigate('/history')} 
          />
        </div>
        
        <div className="flex justify-between items-center mb-2">
          <h3 className="font-medium">Recent Transactions</h3>
          <button 
            className="text-blue-600 text-sm flex items-center"
            onClick={() => navigate('/history')}
          >
            View All <ArrowRight size={14} className="ml-1" />
          </button>
        </div>
        
        <div className="bg-white rounded-lg shadow-sm">
          {recentTransactions.length > 0 ? (
            recentTransactions.map(transaction => (
              <Transaction key={transaction.id} transaction={transaction} />
            ))
          ) : (
            <p className="p-4 text-center text-gray-500">No recent transactions</p>
          )}
        </div>
      </div>
      
      {/* Navigation Bar */}
      <NavBar />
      
      {/* Modals */}
      {showSendModal && (
        <SendMoneyModal 
          onClose={() => setShowSendModal(false)} 
          onSuccess={() => {
            setShowSendModal(false);
            // Refresh balance and transactions
            getWalletBalance().then(data => setBalance(data.balance));
            getTransactionHistory().then(data => setRecentTransactions(data.slice(0, 3)));
          }}
        />
      )}
      
      {showReceiveModal && (
        <ReceiveMoneyModal 
          onClose={() => setShowReceiveModal(false)} 
        />
      )}
    </div>
  );
};

export default HomeScreen;

// --------------------------------------
// BACKEND
// --------------------------------------

// backend/server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const morgan = require('morgan');

// Load environment variables
dotenv.config();

// Import routes
const authRoutes = require('./routes/authRoutes');
const walletRoutes = require('./routes/walletRoutes');
const transactionRoutes = require('./routes/transactionRoutes');

// Initialize express app
const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/wallet', walletRoutes);
app.use('/api/transactions', transactionRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    message: 'Server error',
    error: process.env.NODE_ENV === 'development' ? err.message : 'An unexpected error occurred'
  });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;

// backend/models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Name is required'],
    trim: true
  },
  phone: {
    type: String,
    required: [true, 'Phone number is required'],
    unique: true,
    trim: true
  },
  email: {
    type: String,
    trim: true,
    lowercase: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters']
  },
  profilePhoto: {
    type: String,
    default: ''
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  verificationCode: String,
  verificationExpires: Date,
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Hash password before saving
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Method to compare password
UserSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', UserSchema);

// backend/models/Wallet.js
const mongoose = require('mongoose');

const WalletSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  balance: {
    type: Number,
    default: 0
  },
  currency: {
    type: String,
    default: 'UGX'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  lastUpdated: {
    type: Date,
    default: Date.now
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('Wallet', WalletSchema);

// backend/models/Transaction.js
const mongoose = require('mongoose');

const TransactionSchema = new mongoose.Schema({
  type: {
    type: String,
    enum: ['CREDIT', 'DEBIT'],
    required: true
  },
  amount: {
    type: Number,
    required: true
  },
  fee: {
    type: Number,
    default: 0
  },
  currency: {
    type: String,
    default: 'UGX'
  },
  status: {
    type: String,
    enum: ['PENDING', 'COMPLETED', 'FAILED', 'CANCELLED'],
    default: 'PENDING'
  },
  description: {
    type: String
  },
  reference: {
    type: String,
    unique: true
  },
  sender: {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    wallet: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Wallet'
    },
    name: String,
    phone: String
  },
  recipient: {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    wallet: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Wallet'
    },
    name: String,
    phone: String
  },
  paymentMethod: {
    type: String,
    enum: ['WALLET', 'MOBILE_MONEY', 'BANK_TRANSFER', 'QR_CODE'],
    default: 'WALLET'
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  completedAt: {
    type: Date
  }
});

// Index for faster queries
TransactionSchema.index({ 'sender.user': 1, createdAt: -1 });
TransactionSchema.index({ 'recipient.user': 1, createdAt: -1 });
TransactionSchema.index({ status: 1 });
TransactionSchema.index({ reference: 1 }, { unique: true });

// Generate reference number
TransactionSchema.pre('save', function(next) {
  if (!this.reference) {
    const timestamp = new Date().getTime();
    const random = Math.floor(Math.random() * 1000);
    this.reference = `TXN${timestamp}${random}`;
  }
  next();
});

module.exports = mongoose.model('Transaction', TransactionSchema);

// backend/controllers/authController.js
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Wallet = require('../models/Wallet');
const { generateOTP, sendSMS } = require('../utils/smsService');

// Register user
exports.register = async (req, res, next) => {
  try {
    const { name, phone, email, password } = req.body;
    
    // Check if user already exists
    const existingUser = await User.findOne({ phone });
    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: 'Phone number already registered'
      });
    }
    
    // Generate verification code
    const verificationCode = generateOTP();
    const verificationExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    
    // Create user
    const user = await User.create({
      name,
      phone,
      email,
      password,
      verificationCode,
      verificationExpires
    });
    
    // Create wallet for user
    await Wallet.create({
      user: user._id,
      balance: 0,
      currency: 'UGX'
    });
    
    // Send verification SMS
    await sendSMS(
      phone,
      `Your Victus Pay verification code is ${verificationCode}. Valid for 10 minutes.`
    );
    
    // Generate token
    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );
    
    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      token,
      user: {
        id: user._id,
        name: user.name,
        phone: user.phone,
        email: user.email,
        isVerified: user.isVerified
      }
    });
  } catch (error) {
    next(error);
  }
};

// Login user
exports.login = async (req, res, next) => {
  try {
    const { phone, password } = req.body;
    
    // Check if user exists
    const user = await User.findOne({ phone });
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }
    
    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }
    
    // Generate token
    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );
    
    res.status(200).json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        phone: user.phone,
        email: user.email,
        isVerified: user.isVerified
      }
    });
  } catch (error) {
    next(error);
  }
};

// Verify OTP
exports.verifyOTP = async (req, res, next) => {
  try {
    const { phone, code } = req.body;
    
    const user = await User.findOne({
      phone,
      verificationCode: code,
      verificationExpires: { $gt: Date.now() }
    });
    
    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired verification code'
      });
    }
    
    // Update user verification status
    user.isVerified = true;
    user.verificationCode = undefined;
    user.verificationExpires = undefined;
    await user.save();
    
    res.status(200).json({
      success: true,
      message: 'Phone number verified successfully'
    });
  } catch (error) {
    next(error);
  }
};

// Verify token
exports.verifyToken = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'No token provided'
      });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select('-password');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    res.status(200).json({
      id: user._id,
      name: user.name,
      phone: user.phone,
      email: user.email,
      isVerified: user.isVerified
    });
  } catch (error) {
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Invalid or expired token'
      });
    }
    next(error);
  }
};

// backend/middleware/auth.js
const jwt = require('jsonwebtoken');
const User = require('../models/User');

exports.protect = async (req, res, next) => {
  try {
    let token;
    
    // Check if token exists in headers
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }
    
    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Not authorized, no token provided'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Check if user exists
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Set user in request object
    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Not authorized, token failed'
      });
    }
    next(error);
  }
};

// backend/controllers/walletController.js
const Wallet = require('../models/Wallet');

// Get wallet balance
exports.getBalance = async (req, res, next) => {
  try {
    const wallet = await Wallet.findOne({ user: req.user._id });
    
    if (!wallet) {
      return res.status(404).json({
        success: false,
        message: 'Wallet not found'
      });
    }
    
    res.status(200).json({
      success: true,
      balance: wallet.balance,
      currency: wallet.currency
    });
  } catch (error) {
    next(error);
  }
};

// backend/controllers/transactionController.js
const Transaction = require('../models/Transaction');
const Wallet = require('../models/Wallet');
const User = require('../models/User');
const { generateQRCode } = require('../utils/qrService');
const { sendSMS } = require('../utils/smsService');

// Get user transactions
exports.getTransactions = async (req, res, next) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    const transactions = await Transaction.find({
      $or: [
        { 'sender.user': req.user._id },
        { 'recipient.user': req.user._id }
      ]
    })
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit);
    
    const total = await Transaction.countDocuments({
      $or: [
        { 'sender.user': req.user._id },
        { 'recipient.user': req.user._id }
      ]
    });
    
    res.status(200).json({
      success: true,
      count: transactions.length,
      total,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      transactions
    });
  } catch (error) {
    next(error);
  }
};

// Send money to another user
exports.sendMoney = async (req, res, next) => {
  try {
    const { recipient, amount, description } = req.body;
    
    // Validate amount
    if (!amount || amount <= 0) {
      return res.status(400
